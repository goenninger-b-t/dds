(in-package #:dds.durability)

;;; Task 6 — DARE-encrypted durable-store decorator (ADR 0021 cap.7).
;;; Seals every payload on put via ML-KEM-1024 + AES-256-GCM; opens on get-range.
;;; Two modes selected at construction:
;;;   v1 (no :epoch-dir): a fresh per-session DEK derived on open, discarded on close
;;;     (the in-memory TRANSIENT tier — prior-run records are intentionally unreadable).
;;;   v2 (:epoch-dir present, WP-DURABILITY-PERSISTENT): a persisted epoch table (epochs.dat)
;;;     re-derives each prior run's DEK on open; a fresh epoch is minted lazily on the first put;
;;;     records seal under the current epoch (envelope v2) and open by their epoch-id. This makes
;;;     the disk-backed store cross-restart-readable while keeping AES-GCM nonce reuse structurally
;;;     impossible: every run mints a distinct epoch ⇒ a distinct DEK with its own counter-from-0
;;;     nonce space (design spec §6 / ADR 0025 §5).
;;; Per-(current-epoch) counter nonce (96-bit LE): starts at 0, incremented before each seal.
;;; On auth failure in get-range: record is DROPPED + *dare-error-hook* fires.
;;; Topics / purge / count delegate to inner store unchanged (metadata cleartext).

(defparameter *dare-error-hook* nil
  "Funcallable (CONDITION CONTEXT COUNT) invoked when open-payload returns NIL (auth/tamper fail).
   CONTEXT is :dare-open-failed; COUNT is the running tally. Default = rate-limited WARN.")

(defun* %default-dare-error-hook (condition context count)
    (function (t t (integer 1)) t)
  "Default *DARE-ERROR-HOOK*: power-of-ten rate-limited WARN (mirrors %default-durability-error-hook)."
  (when (%durability-error-count-p count)
    (warn "dds.durability dare (~a) open-payload failure #~d: ~a" context count condition))   ; NOCOND(WARN): rate-limited diagnostic; returns normally, no control transfer
  t)

(eval-when (:load-toplevel :execute)
  (setf *dare-error-hook* #'%default-dare-error-hook))

(defconstant +max-nonce-counter+ (expt 2 96)
  "Per-epoch 96-bit nonce-counter ceiling. A counter reaching this would wrap the 12-byte nonce
   and reuse a (DEK, nonce) pair — astronomically unreachable (a new epoch is minted every open),
   but guarded so the nonce-reuse-impossible property is total, not merely 'unreachable in practice'.")

(defun* %render-nonce (counter)
    (function ((integer 0)) (simple-array (unsigned-byte 8) (*)))
  "Encode 96-bit COUNTER as 12-byte little-endian nonce vector."
  (let ((v (make-array 12 :element-type '(unsigned-byte 8))))
    (dotimes (i 12 v)
      (setf (aref v i) (ldb (byte 8 (* 8 i)) counter)))))

(defun* %record-aad-v2 (topic writer-guid sn kind key-hash)
    (function (string (simple-array (unsigned-byte 8) (*)) (integer 0)
               (member :data :dispose :unregister)
               (or null (simple-array (unsigned-byte 8) (16))))
              (simple-array (unsigned-byte 8) (*)))
  "v2 AEAD additional data: dds.dare:make-record-aad(topic,guid,sn,kind) ∥ kh-present(1) ∥ key-hash(16).
   Binds the key-hash (which the file store writes to the frame in CLEARTEXT, CRC-only) into the AEAD
   so a disk-write adversary cannot flip an instance's key-hash undetected — a flipped key-hash now
   fails the GCM tag ⇒ fail-closed drop (the on-disk threat model, ADR 0026). Absent key-hash ⇒
   presence byte 0 + 16 zero bytes (unambiguous vs a present all-zero hash). Used SYMMETRICALLY by
   the v2 put (seal) and get-range (open), so the binding holds only when key-hash is unchanged."
  (let* ((base (dds.dare:make-record-aad topic writer-guid sn kind))
         (blen (length base))
         (out  (make-array (+ blen 1 16) :element-type '(unsigned-byte 8) :initial-element 0)))
    (replace out base :end1 blen)
    (when key-hash
      (setf (aref out blen) 1)
      (replace out key-hash :start1 (+ blen 1) :end1 (+ blen 1 16)))
    out))

(defun* %encrypted-store-fresh-dek (public-key)
    (function ((simple-array (unsigned-byte 8) (*))) (simple-array (unsigned-byte 8) (*)))
  "Encapsulate to PUBLIC-KEY, derive a fresh per-session DEK (foreign/static), and zeroize+free
   the transient shared secret even if derivation throws (§6 all-secrets posture)."
  (multiple-value-bind (kem-ct ss) (dds.dare:ml-kem-1024-encapsulate public-key)
    (declare (ignore kem-ct))
    (unwind-protect (dds.dare:derive-dek ss)
      (dds.dare:free-secret-octets ss))))

;;; --- epoch table (epochs.dat) codec (WP-DURABILITY-PERSISTENT, design spec §6) ---
;;; Append-only; entry = epoch-id(4 LE) ∥ kem-ct-len(4 LE) ∥ kem-ct ∥ crc32(4 over the entry
;;; bytes before the crc). Load = replay + tail-truncate-recover (mirrors the topic-log torn-vs-
;;; corrupt rule in store-file.lisp): a short trailing entry → truncate+recover; a full-but-bad-crc
;;; entry → error (a lost epoch makes its records unreadable, so only a torn TAIL is recoverable).
;;; +epochs-entry-fixed+ = epoch-id(4) + kem-ct-len(4) + crc(4) = 12 fixed bytes per entry.

(defconstant +epochs-entry-fixed+ 12 "Fixed bytes per epochs.dat entry (epoch-id 4 + len 4 + crc 4).")

;;; Resource guard (NFR-SEC-POSTURE): the ML-KEM-1024 ciphertext is 1568 bytes; a declared
;;; kem-ct-len above this generous cap is gross corruption ⇒ :corrupt (fail loud), never a torn
;;; tail (mirrors +frame-max-payload+ in store-file.lisp — a corrupt length must not silently
;;; truncate the epoch table, which would brick every record under the lost epochs).
(defconstant +epochs-max-ctlen+ 65536 "Maximum accepted epochs.dat kem-ct length in bytes (sanity cap).")

(defun* %epochs-dat-path (dir)
    (function (pathname) pathname)
  "Return the epochs.dat pathname within the encrypted-store epoch directory DIR."
  (uiop:merge-pathnames* "epochs.dat" (uiop:ensure-directory-pathname dir)))

;;; --- log-MAC anchor (ADR 0045 §3.2/§4.3): a persisted ML-KEM ciphertext whose DETERMINISTIC
;;; decapsulation yields a cross-restart-stable secret for the durability log-MAC key, PLUS an
;;; authenticated grandfather set (the pre-existing legacy topic-ids exempt from the downgrade
;;; check). Format:  version(1)=#x01 ∥ ctlen(4 LE) ∥ kem-ct ∥ gf-count(4 LE) ∥ [idlen(4 LE) ∥ id]*
;;;   ∥ gf-mac(32) ∥ crc32(4).  The gf-mac authenticates the SIGNED region (everything before it)
;;; under the log-MAC key, so a disk adversary cannot forge/extend the exempt set to evade chaining.
;;; Minted ONCE (first v3 put), never updated ⇒ crash-safe; a corrupt/forged anchor SIGNALS.

(defconstant +logmac-anchor-version+ #x01
  "Version byte of the DIR/logmac.anchor file (ADR 0045 §3.2).")
(defconstant +logmac-gf-mac-len+ 32
  "Width of the anchor's grandfather-set MAC (HMAC-SHA-256; ADR 0045 §3.2).")

(defparameter %logmac-gf-label
  (map '(simple-array (unsigned-byte 8) (*)) #'char-code "dds-dare/logmac/gf/v1")
  "ASCII octets of the grandfather-set MAC domain label (ADR 0045 §3.2).")

(defconstant +logmac-tail-version+ #x01
  "Version byte of the DIR/logmac.tail sealed high-water tail-anchor file (ADR 0045 §7.1).")

(defparameter %logmac-tail-label
  (map '(simple-array (unsigned-byte 8) (*)) #'char-code "dds-dare/logmac/tail/v1")
  "ASCII octets of the sealed high-water tail-anchor MAC domain label — a FRESH domain separator,
   distinct from the grandfather-set label, so the tail MAC is cryptographically independent (ADR 0045 §7.1).")

(defconstant +epochs-mac-version+ #x01
  "Version byte of the DIR/epochs.mac sealed epochs.dat MAC file (ADR 0045 §7.2).")

(defparameter %logmac-epochs-label
  (map '(simple-array (unsigned-byte 8) (*)) #'char-code "dds-dare/logmac/epochs/v1")
  "ASCII octets of the sealed epochs.dat MAC domain label — a FRESH domain separator, distinct from the
   grandfather-set and tail-anchor labels, so the epochs MAC is cryptographically independent (ADR 0045 §7.2).")

(defun* %logmac-anchor-path (dir)
    (function (pathname) pathname)
  "Return the logmac.anchor pathname within the encrypted-store epoch directory DIR."
  (uiop:merge-pathnames* "logmac.anchor" (uiop:ensure-directory-pathname dir)))

(defun* %logmac-tail-path (dir)
    (function (pathname) pathname)
  "Return the logmac.tail sealed high-water tail-anchor pathname within the epoch directory DIR. A
   SEPARATE file from the write-once logmac.anchor — the tail anchor is MUTABLE (re-sealed every clean
   close), so it must never share the crash-safe write-once anchor file (ADR 0045 §7.1)."
  (uiop:merge-pathnames* "logmac.tail" (uiop:ensure-directory-pathname dir)))

(defun* %epochs-mac-path (dir)
    (function (pathname) pathname)
  "Return the epochs.mac sealed epochs.dat-MAC pathname within the epoch directory DIR. A SEPARATE,
   MUTABLE file (re-sealed every clean close), never shared with the write-once logmac.anchor; mirrors
   %logmac-tail-path (ADR 0045 §7.2)."
  (uiop:merge-pathnames* "epochs.mac" (uiop:ensure-directory-pathname dir)))

(defun* %topic-id-octets (id)
    (function (string) (simple-array (unsigned-byte 8) (*)))
  "ASCII octets of a topic-id (lowercase hex — always ASCII)."
  (map '(simple-array (unsigned-byte 8) (*)) #'char-code id))

(defun* %enumerate-nonempty-topic-ids (dir)
    (function (pathname) list)
  "Topic-ids (log basenames) of every NON-EMPTY *.log in DIR/topics/ — the pre-existing topics at
   anchor-mint time. Because the anchor is minted on the first v3 put (anchor absent ⇒ no v3 frame
   written yet), these logs are all legacy v1/v2 and form the grandfather set (ADR 0045 §3.2).
   FILE-STORE ONLY (the log filenames ARE the raw tids): the returned ids key IDENTICALLY to the file
   store's downgrade-check grandfather lookup (store-file.lisp, `(gethash tid chain-grandfather)`) in
   ALL cases — including a lost/corrupt topics.map, where a topic NAME falls back to the raw tid and a
   %topic->id(tid) round-trip would DOUBLE-ENCODE and never match (a false-REJECT of a degraded store)."
  (let ((tdir (%topics-dir dir))
        (ids '()))
    (when (uiop:directory-exists-p tdir)
      (dolist (log (uiop:directory-files tdir "*.log"))
        (when (plusp (with-open-file (s log :element-type '(unsigned-byte 8)) (file-length s)))
          (push (pathname-name log) ids))))
    ids))

(defun* %store-grandfather-ids (inner-store dir)
    (function (durable-store pathname) list)
  "Mint-time grandfather set = the pre-existing non-empty topic-IDS of INNER-STORE (ADR 0045 §3.2).
   Backend-dispatched so each backend's gf-ids key IDENTICALLY to its own downgrade-check lookup:
   the FILE store scans its log-dir tids DIRECTLY (raw tids = log filenames — robust to a lost
   topics.map, no %topic->id round-trip); SQLite/memory have no on-disk tid logs, so they map the real
   topic NAMES via %topic->id (matching their %topic->id(name) verify lookup key). DRY: one dispatch,
   each path is the backend's own correct enumeration."
  (if (eq (durable-store-name inner-store) :file)
      (%enumerate-nonempty-topic-ids dir)
      (mapcar #'%topic->id (store-topics inner-store))))

(defun* %assemble-anchor-signed (kem-ct grandfather-ids)
    (function ((simple-array (unsigned-byte 8) (*)) list) (simple-array (unsigned-byte 8) (*)))
  "Build the anchor's SIGNED region: version ∥ ctlen ∥ kem-ct ∥ gf-count ∥ [idlen ∥ id]* — the exact
   byte range the grandfather-set MAC and the CRC cover (ADR 0045 §3.2)."
  (let* ((ctlen  (length kem-ct))
         (id-oct (mapcar #'%topic-id-octets grandfather-ids))
         (gf-len (loop for o in id-oct sum (+ 4 (length o))))
         (buf    (make-array (+ 5 ctlen 4 gf-len) :element-type '(unsigned-byte 8))))
    (setf (aref buf 0) +logmac-anchor-version+)
    (%put-u32-le buf 1 (the (unsigned-byte 32) ctlen))
    (replace buf kem-ct :start1 5 :end1 (+ 5 ctlen))
    (let ((off (+ 5 ctlen)))
      (%put-u32-le buf off (the (unsigned-byte 32) (length id-oct)))
      (incf off 4)
      (dolist (o id-oct)
        (%put-u32-le buf off (the (unsigned-byte 32) (length o)))
        (incf off 4)
        (replace buf o :start1 off :end1 (+ off (length o)))
        (incf off (length o))))
    buf))

(defun* %hmac-labeled (logmac-key label signed)
    (function ((simple-array (unsigned-byte 8) (*)) (simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (*)))
              (simple-array (unsigned-byte 8) (*)))
  "The shared anchor-MAC construction: HMAC-SHA-256(LOGMAC-KEY, LABEL ∥ SIGNED) (ADR 0045 §3.2/§4.6/§7.1).
   A fresh LABEL domain-separates each anchor tier (grandfather set vs sealed high-water tail). NO new
   crypto — reuses dds.dare:hmac-sha256 (the DARE NIST/IETF KATs are unchanged)."
  (let* ((ln    (length label))
         (input (make-array (+ ln (length signed)) :element-type '(unsigned-byte 8))))
    (replace input label :end1 ln)
    (replace input signed :start1 ln)
    (dds.dare:hmac-sha256 logmac-key input)))

(defun* %compute-gf-mac (logmac-key signed)
    (function ((simple-array (unsigned-byte 8) (*)) (simple-array (unsigned-byte 8) (*)))
              (simple-array (unsigned-byte 8) (*)))
  "Authenticate the anchor's SIGNED region (kem-ct + grandfather set) under the log-MAC key so a disk
   adversary cannot forge/extend the exempt set: HMAC-SHA-256(key, label ∥ signed) (ADR 0045 §3.2/§7)."
  (%hmac-labeled logmac-key %logmac-gf-label signed))

(defun* %write-anchor-file (path signed mac)
    (function (pathname (simple-array (unsigned-byte 8) (*)) (simple-array (unsigned-byte 8) (*))) t)
  "Persist a signed anchor image at PATH: SIGNED ∥ MAC(32) ∥ crc32(4), content-fsynced + dir-fsynced on
   first create so it survives power loss. Shared by the write-once grandfather anchor and the mutable
   sealed high-water tail anchor (both :supersede; ADR 0045 §3.2/§7.1). DRY: one serialize+CRC+fsync."
  (let* ((slen  (length signed))
         (entry (make-array (+ slen +frame-mac-len+ 4) :element-type '(unsigned-byte 8))))
    (replace entry signed :end1 slen)
    (replace entry mac :start1 slen :end1 (+ slen +frame-mac-len+))
    (let ((crc-off (+ slen +frame-mac-len+)))
      (%put-u32-le entry crc-off (%crc32 entry 0 crc-off)))
    (let ((existed (probe-file path)))
      (ensure-directories-exist path)
      (with-open-file (s path :direction :output :element-type '(unsigned-byte 8)
                              :if-exists :supersede :if-does-not-exist :create)
        (write-sequence entry s)
        (dds.pal:fsync-stream s))
      (unless existed
        (dds.pal:fsync-directory (uiop:pathname-directory-pathname path)))))
  t)

(defun* %write-logmac-anchor (dir signed gf-mac)
    (function (pathname (simple-array (unsigned-byte 8) (*)) (simple-array (unsigned-byte 8) (*))) t)
  "Persist the write-once grandfather anchor: SIGNED ∥ gf-mac(32) ∥ crc32(4), fsynced (ADR 0045 §3.2)."
  (%write-anchor-file (%logmac-anchor-path dir) signed gf-mac))

(defun* %write-logmac-tail (dir signed tail-mac)
    (function (pathname (simple-array (unsigned-byte 8) (*)) (simple-array (unsigned-byte 8) (*))) t)
  "Persist the MUTABLE sealed high-water tail anchor D/logmac.tail: SIGNED ∥ anchor-mac(32) ∥ crc32(4),
   fsynced (ADR 0045 §7.1). Re-written (:supersede) on every clean close — UNLIKE the write-once
   grandfather anchor."
  (%write-anchor-file (%logmac-tail-path dir) signed tail-mac))

(defun* %read-logmac-anchor (dir)
    (function (pathname)
              (values (or null (simple-array (unsigned-byte 8) (*))) list
                      (or null (simple-array (unsigned-byte 8) (*)))
                      (or null (simple-array (unsigned-byte 8) (*)))))
  "Read DIR/logmac.anchor → (values kem-ct grandfather-ids gf-mac signed-bytes), or (NIL () NIL NIL) if
   absent. A present-but-corrupt anchor (bad version/length/structure/crc) SIGNALS (fail loud — a
   lost/garbled anchor must never silently disable verification; ADR 0045 §3.2). SIGNED-BYTES is the
   region the caller re-MACs to authenticate the grandfather set."
  (let ((path (%logmac-anchor-path dir)))
    (unless (probe-file path)
      (return-from %read-logmac-anchor (values nil '() nil nil)))
    (let* ((size (with-open-file (s path :element-type '(unsigned-byte 8)) (file-length s)))
           (buf  (make-array size :element-type '(unsigned-byte 8))))
      (with-open-file (s path :element-type '(unsigned-byte 8) :direction :input)
        (read-sequence buf s))
      (flet ((bad (why) (error "dds.durability: corrupt log-MAC anchor ~a (~a; ADR 0045 §3.2)" path why)))   ; NOCOND(SECURITY-FAILCLOSED): corrupt log-MAC anchor; fail-closed at store-open, caught at the durability start boundary
        (when (< size 13) (bad "truncated"))
        (unless (= (aref buf 0) +logmac-anchor-version+) (bad "version"))
        (let ((ctlen (%get-u32-le buf 1)))
          (when (> ctlen +epochs-max-ctlen+) (bad "ctlen"))
          (when (> (+ 5 ctlen 4) size) (bad "gf-count-oob"))
          (let* ((gf-off   (+ 5 ctlen))
                 (gf-count (%get-u32-le buf gf-off))
                 (off      (+ gf-off 4))
                 (ids      '()))
            (when (> gf-count 1000000) (bad "gf-count"))
            (dotimes (_ gf-count)
              (when (> (+ off 4) size) (bad "gf-entry-oob"))
              (let ((idlen (%get-u32-le buf off)))
                (incf off 4)
                (when (> (+ off idlen) size) (bad "gf-id-oob"))
                (let ((id (make-array idlen :element-type '(unsigned-byte 8))))
                  (replace id buf :start2 off :end2 (+ off idlen))
                  (push (map 'string #'code-char id) ids))
                (incf off idlen)))
            (let* ((gf-mac-off off)
                   (crc-off    (+ gf-mac-off +logmac-gf-mac-len+)))
              (when (/= size (+ crc-off 4)) (bad "size"))
              (let ((stored (%get-u32-le buf crc-off))
                    (actual (%crc32 buf 0 crc-off)))
                (unless (= stored actual) (bad "crc")))
              (let ((kem-ct (make-array ctlen :element-type '(unsigned-byte 8)))
                    (gf-mac (make-array +logmac-gf-mac-len+ :element-type '(unsigned-byte 8)))
                    (signed (make-array gf-mac-off :element-type '(unsigned-byte 8))))
                (replace kem-ct buf :start2 5 :end2 (+ 5 ctlen))
                (replace gf-mac buf :start2 gf-mac-off :end2 crc-off)
                (replace signed buf :start2 0 :end2 gf-mac-off)
                (values kem-ct (nreverse ids) gf-mac signed)))))))))

(defun* %mint-logmac-anchor (key-provider dir grandfather-ids)
    (function (dds.dare:key-provider pathname list)
              (values (simple-array (unsigned-byte 8) (*)) (simple-array (unsigned-byte 8) (*))
                      (simple-array (unsigned-byte 8) (*))))
  "Mint the log-MAC anchor ONCE (first v3 put): encapsulate to the recipient key, derive the log-MAC
   key, the at-rest metadata key k_meta AND the epochs.dat MAC key k_epochs (THREE siblings from the SAME
   shared secret, distinct info labels; ADR 0045 §4.3 / §7.2 / ADR 0025 §10 3c), authenticate
   GRANDFATHER-IDS (pre-existing legacy topic-ids, exempt from the downgrade check) under the log-MAC key,
   and persist (kem-ct + set + MAC). Returns (values logmac-key meta-key epochs-mac-key) — all three
   foreign secrets the caller frees on close. Written once, never updated ⇒ crash-safe, no migration burst
   (ADR 0045 §3.2). The anchor kem-ct decapsulates deterministically on every restart, so all three keys
   are cross-restart-stable (ADR 0025 §10 3c / ADR 0045 §7.2). k_epochs derives from the anchor secret,
   NOT any per-epoch DEK — the DEKs are the CONTENTS of epochs.dat (circular)."
  (let ((pub (dds.dare:key-provider-recipient-public-key key-provider)))
    (multiple-value-bind (kem-ct ss) (dds.dare:ml-kem-1024-encapsulate pub)
      (multiple-value-bind (key mkey ekey)
          (unwind-protect
               (values (dds.dare:derive-log-mac-key ss) (dds.dare:derive-meta-key ss)
                       (dds.dare:derive-epochs-mac-key ss))
            (dds.dare:free-secret-octets ss))
        (let* ((signed (%assemble-anchor-signed kem-ct grandfather-ids))
               (gf-mac (%compute-gf-mac key signed)))
          (%write-logmac-anchor dir signed gf-mac))
        (values key mkey ekey)))))

(defun* %load-logmac-anchor (key-provider dir)
    (function (dds.dare:key-provider pathname)
              (values (simple-array (unsigned-byte 8) (*)) list (simple-array (unsigned-byte 8) (*))
                      (simple-array (unsigned-byte 8) (*))))
  "Load an EXISTING anchor: decapsulate the kem-ct (deterministic ⇒ cross-restart-stable), derive the
   log-MAC key, the at-rest metadata key k_meta AND the epochs.dat MAC key k_epochs (THREE siblings from
   the SAME shared secret; ADR 0045 §4.3 / §7.2 / ADR 0025 §10 3c), and VERIFY the grandfather-set MAC
   under the log-MAC key — a mismatch SIGNALS (a disk adversary cannot forge/extend the exempt set;
   ADR 0045 §3.2) AND frees all three keys first (no secret leak). Returns
   (values logmac-key grandfather-ids meta-key epochs-mac-key); all three keys are foreign secrets the
   caller frees. k_epochs derives from the anchor secret, NOT any per-epoch DEK (the DEKs are the
   contents of epochs.dat — circular; ADR 0045 §7.2)."
  (multiple-value-bind (kem-ct gf-ids gf-mac signed) (%read-logmac-anchor dir)
    (unless kem-ct
      ;; NOCOND(SECURITY-FAILCLOSED): anchor missing; fail-closed at store-open, caught at the durability start boundary
      (error "dds.durability: log-MAC anchor missing in ~a" dir))
    (let ((ss (dds.dare:key-provider-decapsulate key-provider kem-ct)))
      (multiple-value-bind (key mkey ekey)
          (unwind-protect
               (values (dds.dare:derive-log-mac-key ss) (dds.dare:derive-meta-key ss)
                       (dds.dare:derive-epochs-mac-key ss))
            (dds.dare:free-secret-octets ss))
        (unless (equalp (%compute-gf-mac key signed) gf-mac)
          (dds.dare:free-secret-octets key)
          (dds.dare:free-secret-octets mkey)
          (dds.dare:free-secret-octets ekey)
          ;; NOCOND(SECURITY-FAILCLOSED): grandfather-set MAC mismatch (tamper); fail-closed at store-open, caught at the durability start boundary
          (error "dds.durability: log-MAC anchor grandfather-set MAC mismatch in ~a ~
                  (tamper — refusing to open; ADR 0045 §3.2)" dir))
        (values key gf-ids mkey ekey)))))

(defun* %derive-logmac-key (key-provider dir)
    (function (dds.dare:key-provider pathname) (simple-array (unsigned-byte 8) (*)))
  "Derive the cross-restart-stable log-MAC key from DIR's EXISTING anchor — a thin wrapper over
   %LOAD-LOGMAC-ANCHOR returning just the key (used by tests). %LOAD-LOGMAC-ANCHOR derives THREE sibling
   keys from the same anchor secret (log-MAC key, k_meta, k_epochs; ADR 0045 §4.3 / §7.2 / ADR 0025 §10 3c),
   so the two siblings unused here are zeroized+freed before returning (no secret leak — a value-truncating
   call would derive-then-drop 64 bytes of live key material). Caller frees the returned key (ADR 0045 §4.3)."
  (multiple-value-bind (key gf-ids mkey ekey) (%load-logmac-anchor key-provider dir)
    (declare (ignore gf-ids))
    (dds.dare:free-secret-octets mkey)
    (dds.dare:free-secret-octets ekey)
    key))

(defun* %install-logmac-oracle (inner-store logmac-key grandfather-ids)
    (function (durable-store (simple-array (unsigned-byte 8) (*)) list) t)
  "Install the keyed chain MAC oracle (data)->HMAC-SHA-256(LOGMAC-KEY,data) into INNER-STORE, marking
   the store CHAIN-REQUIRED with GRANDFATHER-IDS exempt (ADR 0045 §3.2). The oracle verifies every v3
   frame; the downgrade check (a non-empty log that replays to zero v3 frames ⇒ fail) applies to every
   topic EXCEPT the grandfathered legacy topic-ids. A fresh store has an EMPTY grandfather set ⇒ every
   topic is chain-required (full protection). The closure captures the key; the file store holds only
   it, never the key bytes."
  (let ((k  logmac-key)
        (gf (make-hash-table :test #'equal)))
    (dolist (id grandfather-ids) (setf (gethash id gf) t))
    (store-set-chain-mac-fn inner-store (lambda (data) (dds.dare:hmac-sha256 k data)) t gf))
  t)

;;; --- sealed high-water tail anchor (ADR 0045 §7.1): the store-level SEALED, authenticated per-topic
;;; tail index that closes the whole-tail-truncation (§7.1), whole-topic-drop (§9) and whole-store-
;;; rollback (§2) residuals for the FILE tier. Committed at CLEAN CLOSE, verified at OPEN by prefix-
;;; containment. SEPARATE, MUTABLE file DIR/logmac.tail (never extends the write-once logmac.anchor).
;;; Format:  version(1)=#x01 ∥ entry-count(4 LE) ∥ [tidlen(4 LE) ∥ tid ∥ N(4 LE) ∥ M_N(32)]*
;;;   ∥ anchor-mac(32) ∥ crc32(4).  anchor-mac = HMAC-SHA-256(logmac-key, tail-label ∥ signed-region),
;;; so a raw-disk adversary who truncates the log AND rewrites logmac.tail cannot re-seal it (no key).

(defparameter *durability-debug-skip-tail-seal* nil
  "Test-only fault injector (ADR 0045 §7.1 crash-append). NIL (default) ⇒ inert; byte-identical behavior.
   When non-NIL, the encrypted-store :close SKIPS re-sealing the tail anchor — simulating a CRASH after
   frames were appended but BEFORE the anchor was re-sealed, leaving logmac.tail STALE (an older N). The
   next open must then accept the longer log as a forward extension (prefix-containment, no false-reject)
   — this flag exercises exactly that no-false-reject path. Never set in production code.")

(defparameter *durability-debug-skip-tail-invalidate* nil
  "Test-only fault injector (ADR 0045 §7.1 reclaim-crash brick). NIL (default) ⇒ inert; byte-identical
   behavior. When non-NIL, the encrypted-store :open SKIPS %invalidate-tail-anchor (verify still runs) —
   reproducing the PRE-invalidate design so a test can prove the invalidate is LOAD-BEARING: with it
   skipped, an authorized reclaim-shrink + a crash (skip-seal) leaves the STALE anchor (an older, larger N)
   over a shrunk log ⇒ the next open FALSE-REJECTS (:truncated, bricks). With it on (default) the same
   sequence reopens clean. Mirrors *durability-debug-skip-tail-seal*. Never set in production code.")

(defparameter *durability-debug-skip-epochs-seal* nil
  "Test-only fault injector (ADR 0045 §7.2 forward crash-append). NIL (default) ⇒ inert; byte-identical
   behavior. When non-NIL, the encrypted-store :close SKIPS re-sealing the epochs.dat MAC (D/epochs.mac) —
   simulating a CRASH after a fresh epoch was appended (fsynced) to epochs.dat but BEFORE epochs.mac was
   re-sealed, leaving epochs.mac STALE at the pre-append count N while epochs.dat holds N+1 entries. The
   next open must then accept the extra entry as a forward extension (prefix-containment, no false-reject)
   — this flag exercises exactly that no-false-reject path; a strict whole-table-equality check would BRICK
   here. Mirrors *durability-debug-skip-tail-seal*. Never set in production code.")

(defun* %assemble-tail-signed (tails)
    (function (hash-table) (simple-array (unsigned-byte 8) (*)))
  "Serialize the per-topic tail set TAILS (tid -> (N . M_N)) into the anchor's SIGNED region:
   version ∥ entry-count ∥ [tidlen ∥ tid ∥ N ∥ M_N]* — entries sorted by tid for a deterministic image
   (the exact byte range the anchor-mac and CRC cover; ADR 0045 §7.1)."
  (let* ((entries (sort (loop for tid being the hash-keys of tails using (hash-value nm)
                              collect (list tid (car nm) (cdr nm)))
                        #'string< :key #'first))
         (body    (loop for e in entries
                        sum (+ 4 (length (%topic-id-octets (first e))) 4 +frame-mac-len+)))
         (buf     (make-array (+ 5 body) :element-type '(unsigned-byte 8))))
    (setf (aref buf 0) +logmac-tail-version+)
    (%put-u32-le buf 1 (the (unsigned-byte 32) (length entries)))
    (let ((off 5))
      (dolist (e entries)
        (destructuring-bind (tid n mac) e
          (let* ((oct (%topic-id-octets tid)) (tl (length oct)))
            (%put-u32-le buf off (the (unsigned-byte 32) tl)) (incf off 4)
            (replace buf oct :start1 off :end1 (+ off tl)) (incf off tl)
            (%put-u32-le buf off (the (unsigned-byte 32) n)) (incf off 4)
            (replace buf mac :start1 off :end1 (+ off +frame-mac-len+)) (incf off +frame-mac-len+)))))
    buf))

(defun* %read-logmac-tail (dir)
    (function (pathname)
              (values list (or null (simple-array (unsigned-byte 8) (*)))
                      (or null (simple-array (unsigned-byte 8) (*)))))
  "Read DIR/logmac.tail → (values entries signed-bytes anchor-mac), or (NIL NIL NIL) if absent. ENTRIES
   is a list of (tid N . M_N) (tid string, N integer, M_N 32 octets). A present-but-corrupt tail (bad
   version/count/length/structure/crc) SIGNALS (fail loud, mirrors %read-logmac-anchor). EVERY length
   and offset is bounds-checked against the buffer BEFORE use (NFR-SEC-POSTURE) so a malformed tail
   fails clean, never OOB. SIGNED-BYTES is the region the caller re-MACs to authenticate the tail set."
  (let ((path (%logmac-tail-path dir)))
    (unless (probe-file path)
      (return-from %read-logmac-tail (values nil nil nil)))
    (let* ((size (with-open-file (s path :element-type '(unsigned-byte 8)) (file-length s)))
           (buf  (make-array size :element-type '(unsigned-byte 8))))
      (with-open-file (s path :element-type '(unsigned-byte 8) :direction :input)
        (read-sequence buf s))
      (flet ((bad (why) (error "dds.durability: corrupt tail anchor ~a (~a; ADR 0045 §7.1)" path why)))   ; NOCOND(SECURITY-FAILCLOSED): corrupt tail anchor; fail-closed at store-open, caught at the durability start boundary
        (when (< size (+ 5 +frame-mac-len+ 4)) (bad "truncated"))
        (unless (= (aref buf 0) +logmac-tail-version+) (bad "version"))
        (let ((count (%get-u32-le buf 1))
              (off   5)
              (entries '()))
          (when (> count 1000000) (bad "entry-count"))
          (dotimes (_ count)
            (when (> (+ off 4) size) (bad "tidlen-oob"))
            (let ((tidlen (%get-u32-le buf off)))
              (incf off 4)
              (when (> tidlen 65536) (bad "tidlen"))
              (when (> (+ off tidlen 4 +frame-mac-len+) size) (bad "entry-oob"))
              (let ((tid (make-array tidlen :element-type '(unsigned-byte 8))))
                (replace tid buf :start2 off :end2 (+ off tidlen))
                (incf off tidlen)
                (let ((n (%get-u32-le buf off)))
                  (incf off 4)
                  (let ((mac (make-array +frame-mac-len+ :element-type '(unsigned-byte 8))))
                    (replace mac buf :start2 off :end2 (+ off +frame-mac-len+))
                    (incf off +frame-mac-len+)
                    (push (list* (map 'string #'code-char tid) n mac) entries))))))
          (let* ((mac-off off) (crc-off (+ mac-off +frame-mac-len+)))
            (when (/= size (+ crc-off 4)) (bad "size"))
            (let ((stored (%get-u32-le buf crc-off))
                  (actual (%crc32 buf 0 crc-off)))
              (unless (= stored actual) (bad "crc")))
            (let ((anchor-mac (make-array +frame-mac-len+ :element-type '(unsigned-byte 8)))
                  (signed     (make-array mac-off :element-type '(unsigned-byte 8))))
              (replace anchor-mac buf :start2 mac-off :end2 crc-off)
              (replace signed buf :start2 0 :end2 mac-off)
              (values (nreverse entries) signed anchor-mac))))))))

(defun* %seal-tail-anchor (inner-store dir logmac-key)
    (function (durable-store pathname (simple-array (unsigned-byte 8) (*))) t)
  "Seal the store-level high-water tail anchor at CLEAN CLOSE (ADR 0045 §7.1): gather each chained
   topic's (v3-count N . tail-MAC M_N) via the read-only chain-tails seam, HMAC the per-topic tail set
   under the log-MAC key (label ∥ region, mirroring %compute-gf-mac), and persist DIR/logmac.tail
   (serialized set ∥ anchor-mac ∥ CRC, fsynced). store-sync FIRST so the seam re-walk reads the durable
   bytes. A backend without the chain-tails seam (SQLite/microservice — the tail anchor is a FILE-tier
   feature this slice) writes NO anchor. Committing the PREFIX (N, M_N) makes rolling the log back to a
   shorter valid prefix — whole-tail truncation, whole-topic drop, whole-store rollback — contradict the
   anchor at the next open (prefix-containment), while a forward crash-append stays clean."
  (when (durable-store-chain-tails-fn inner-store)
    (store-sync inner-store)
    (let ((tails (store-chain-tails inner-store)))
      (let* ((signed (%assemble-tail-signed tails))
             (mac    (%hmac-labeled logmac-key %logmac-tail-label signed)))
        (%write-logmac-tail dir signed mac))))
  t)

(defun* %verify-tail-anchor (inner-store dir logmac-key)
    (function (durable-store pathname (simple-array (unsigned-byte 8) (*))) t)
  "Verify the sealed high-water tail anchor at store-open, BEFORE the inner replay compacts the logs
   (ADR 0045 §7.1). Reads DIR/logmac.tail (absent ⇒ nothing sealed ⇒ open CLEAN — a never-cleanly-closed
   store has only running-chain protection); re-MACs it under the log-MAC key and fail-LOUD on the
   anchor's own MAC mismatch (tamper of logmac.tail itself); then per sealed topic runs prefix-
   containment via the read-only verify seam: t ⇒ the committed prefix (N, M_N) is present + intact (may
   extend forward = crash-append → CLEAN); :truncated ⇒ the chain no longer reaches the sealed high-water
   (whole-tail truncation / whole-topic drop / whole-store rollback); :diverged ⇒ the prefix MAC differs
   (rollback / substitution). Either non-t ⇒ fail-CLOSED (a loud error at open, exactly like
   %load-logmac-anchor's gf-mac mismatch)."
  (multiple-value-bind (entries signed anchor-mac) (%read-logmac-tail dir)
    (unless signed
      (return-from %verify-tail-anchor t))
    (unless (equalp (%hmac-labeled logmac-key %logmac-tail-label signed) anchor-mac)
      ;; NOCOND(SECURITY-FAILCLOSED): tail-anchor MAC mismatch (tamper); fail-closed at store-open, caught at the durability start boundary
      (error "dds.durability: tail anchor MAC mismatch in ~a (tamper — refusing to open; ADR 0045 §7.1)"
             dir))
    (dolist (e entries)
      (destructuring-bind (tid n . macv) e
        (let ((r (store-verify-chain-prefix inner-store tid n macv)))
          (unless (eq r t)
            ;; NOCOND(SECURITY-FAILCLOSED): tail-anchor prefix-containment (truncation/rollback); fail-closed at store-open, caught at the durability start boundary
            (error "dds.durability: tail anchor prefix-containment FAILED for topic-id ~a (~a — whole-tail ~
                    truncation / whole-topic drop / whole-store rollback; refusing to open; ADR 0045 §7.1)"
                   tid r)))))
    t))

(defun* %invalidate-tail-anchor (dir)
    (function (pathname) t)
  "Delete DIR/logmac.tail, fsyncing the dirent removal so a crash cannot resurrect a stale anchor
   (ADR 0045 §7.1). Called at OPEN, AFTER %verify-tail-anchor has checked the at-rest sealed state and
   BEFORE store-open's compaction sweep / the session's puts mutate the log. The tail anchor commits the
   PHYSICAL v3-frame chain, but the KEEP_LAST physical-reclaim path (%reclaim-deleted-topic ⇒
   %rewrite-topic-log) and settled-instance compaction AUTHORIZED-SHRINK it mid-session; two files (the
   log + logmac.tail) can't be updated atomically, so a re-seal-on-shrink would just move the crash
   window. Invalidating BEFORE any shrink means an authorized shrink + a crash (no clean re-seal) leaves
   NO stale anchor to FALSE-REJECT — the store reopens clean (the never-cleanly-closed path), while an
   OFFLINE truncation of the clean-closed state is still detected (verify ran first). The anchor is
   RE-SEALED at the next clean close over the final state — so it protects only the at-rest (clean-closed)
   state, never the mutating in-session log."
  (let ((path (%logmac-tail-path dir)))
    (when (probe-file path)
      (delete-file path)
      (dds.pal:fsync-directory (uiop:pathname-directory-pathname path))))
  t)

(defun* %frame-epoch-entry (epoch-id kem-ct)
    (function ((unsigned-byte 32) (simple-array (unsigned-byte 8) (*)))
              (simple-array (unsigned-byte 8) (*)))
  "Serialize one epochs.dat entry: epoch-id(4 LE) ∥ kem-ct-len(4 LE) ∥ kem-ct ∥ crc32(4)."
  (let* ((ctlen (length kem-ct))
         (entry (make-array (+ +epochs-entry-fixed+ ctlen) :element-type '(unsigned-byte 8))))
    (%put-u32-le entry 0 (the (unsigned-byte 32) epoch-id))
    (%put-u32-le entry 4 (the (unsigned-byte 32) ctlen))
    (replace entry kem-ct :start1 8 :end1 (+ 8 ctlen))
    (let ((crc-off (+ 8 ctlen)))
      (%put-u32-le entry crc-off (%crc32 entry 0 crc-off)))
    entry))

(defun* %parse-epoch-entry (buf start end)
    (function ((simple-array (unsigned-byte 8) (*)) (integer 0) (integer 0))
              (values (or null (unsigned-byte 32))
                      (or null (simple-array (unsigned-byte 8) (*)))
                      (integer 0)
                      (member :ok :short :corrupt)))
  "Parse one epochs.dat entry from BUF[START..END).
   Returns (values epoch-id kem-ct next-pos :ok) on success;
   (values nil nil START :short) when fewer than the full declared entry bytes are present (torn tail);
   (values nil nil START :corrupt) when the full entry is present but the crc32 mismatches."
  (let ((avail (- end start)))
    (when (< avail +epochs-entry-fixed+)
      (return-from %parse-epoch-entry (values nil nil start :short)))
    (let* ((epoch-id (%get-u32-le buf start))
           (ctlen    (%get-u32-le buf (+ start 4)))
           (crc-off  (+ start 8 ctlen))
           (entry-end (+ crc-off 4)))
      ;; gross length corruption ⇒ :corrupt (loud), checked before the short test
      (when (> ctlen +epochs-max-ctlen+)
        (return-from %parse-epoch-entry (values nil nil start :corrupt)))
      (when (> entry-end end)
        (return-from %parse-epoch-entry (values nil nil start :short)))
      (let ((stored (%get-u32-le buf crc-off))
            (actual (%crc32 buf start crc-off)))
        (unless (= stored actual)
          (return-from %parse-epoch-entry (values nil nil start :corrupt)))
        (let ((ct (make-array ctlen :element-type '(unsigned-byte 8))))
          (replace ct buf :start2 (+ start 8) :end2 crc-off)
          (values epoch-id ct entry-end :ok))))))

(defun* %load-epoch-table (dir)
    (function (pathname) hash-table)
  "Load epochs.dat from DIR into an epoch-id -> kem-ct hash-table (empty if absent).
   Replay + tail-truncate-recover: a short trailing entry is truncated and recovery proceeds;
   a full-but-bad-crc (mid-file) entry signals an error (a lost epoch is unrecoverable; only a
   torn TAIL is recoverable). Mirrors %replay-log's torn-vs-corrupt discipline (store-file.lisp)."
  (let ((tbl  (make-hash-table :test #'eql))
        (path (%epochs-dat-path dir)))
    (unless (probe-file path)
      (return-from %load-epoch-table tbl))
    (let* ((size (with-open-file (s path :element-type '(unsigned-byte 8)) (file-length s)))
           (buf  (make-array size :element-type '(unsigned-byte 8)))
           (pos  0)
           (last-valid 0))
      (with-open-file (s path :element-type '(unsigned-byte 8) :direction :input)
        (read-sequence buf s))
      (loop
        (when (>= pos size) (return))
        (multiple-value-bind (epoch-id ct next reason) (%parse-epoch-entry buf pos size)
          (cond
            (epoch-id
             (setf (gethash epoch-id tbl) ct)
             (setf last-valid next)
             (setf pos next))
            ((eq reason :short)
             (when (< last-valid size)
               (%truncate-file path last-valid))
             (return))
            (t
             ;; NOCOND(SECURITY-FAILCLOSED): mid-file corruption; fail-closed at store-open, caught at the durability start boundary
             (error "dds.durability: mid-file corruption in ~a at offset ~d (last valid ~d; reason ~s)"
                    path pos last-valid reason)))))
      (when (and (zerop last-valid) (plusp size))
        (%truncate-file path 0))
      tbl)))

(defun* %append-epoch (dir epoch-id kem-ct)
    (function (pathname (unsigned-byte 32) (simple-array (unsigned-byte 8) (*))) t)
  "Append one {epoch-id -> kem-ct} entry to epochs.dat in DIR and fsync it to the OS before
   returning (open→write→dds.pal:fsync-stream→close — SBCL fdatasync(2), Clasp finish-output per
   the NFR-PORT split; same group-commit primitive the file store uses, no #+sbcl/#+clasp here).
   Caller MUST call this BEFORE writing any record that references EPOCH-ID, so the ordering
   invariant holds — every record's epoch-id resolves after a crash (spec §9, ADR 0026)."
  (let ((entry (%frame-epoch-entry epoch-id kem-ct))
        (path  (%epochs-dat-path dir)))
    (let ((existed (probe-file path)))
      (ensure-directories-exist path)
      (with-open-file (s path :direction :output :element-type '(unsigned-byte 8)
                              :if-exists :append :if-does-not-exist :create)
        (write-sequence entry s)
        (dds.pal:fsync-stream s))
      ;; a NEW epochs.dat's dirent must be fsynced into its dir to survive power loss (ADR 0026 §10.10);
      ;; without this the first epoch's record could reference an epoch whose dirent never persisted
      (unless existed
        (dds.pal:fsync-directory (uiop:pathname-directory-pathname path)))))
  t)

(defun* %free-epoch-dek-map (dek-map)
    (function (hash-table) t)
  "Zeroize + free EVERY DEK held in DEK-MAP (foreign secret buffers) and empty the map (§6).
   The current epoch's DEK is held in this map, so this frees it exactly once — callers must NOT
   separately free the current DEK after calling this."
  (maphash (lambda (epoch-id dek) (declare (ignore epoch-id)) (dds.dare:free-secret-octets dek))
           dek-map)
  (clrhash dek-map)
  t)

(defun* %load-epoch-deks (key-provider dir dek-map)
    (function (dds.dare:key-provider pathname hash-table) (integer 0))
  "Decapsulate each persisted epoch's kem-ct via KEY-PROVIDER and derive its DEK into DEK-MAP
   (epoch-id -> foreign DEK). Each transient shared secret is freed once its DEK is derived;
   each DEK is a foreign secret the map owns for the store lifetime. Returns the max epoch-id
   loaded (0 if none) so the next mint can pick max+1."
  (let ((table   (%load-epoch-table dir))
        (max-id  0)
        (ok      nil))
    ;; free any DEKs already derived if a later decapsulate/derive throws (no secret leak on a
    ;; partial load that escapes :open and abandons the store before the next-open reclamation).
    (unwind-protect
         (progn
           (maphash
            (lambda (epoch-id kem-ct)
              (let ((ss (dds.dare:key-provider-decapsulate key-provider kem-ct)))
                (unwind-protect
                     (setf (gethash epoch-id dek-map) (dds.dare:derive-dek ss))
                  (dds.dare:free-secret-octets ss))
                (when (> epoch-id max-id) (setf max-id epoch-id))))
            table)
           (setf ok t)
           max-id)
      (unless ok (%free-epoch-dek-map dek-map)))))

;;; --- sealed epochs.dat MAC (ADR 0045 §7.2): a keyed MAC over the DARE per-epoch KEM-ciphertext table
;;; that closes the epochs.dat tamper/rollback/reorder hole (an offline disk adversary can flip a stored
;;; kem-ct AND recompute its per-entry CRC — CRC is unkeyed — so the entry-CRC-only path misses it). The
;;; MAC key (k_epochs) is the THIRD anchor sibling (derive-epochs-mac-key), NOT any per-epoch DEK (the
;;; DEKs ARE the contents of epochs.dat — circular). Committed at CLEAN CLOSE to a SEPARATE, MUTABLE file
;;; DIR/epochs.mac, verified at OPEN by prefix-containment (forward-tolerant — a 1-ahead crash-append
;;; reopens CLEAN). UNLIKE the tail anchor there is NO invalidate-at-open: epochs.dat is append-only and
;;; NEVER authorized-shrinks, so the only at-open divergence is a forward crash-append (accepted CLEAN).
;;; Format:  version(1)=#x01 ∥ count(4 LE) ∥ [%frame-epoch-entry]* ∥ mac(32) ∥ crc32(4).
;;;   mac = HMAC-SHA-256(k_epochs, epochs-label ∥ signed-region), so a raw-disk adversary who tampers
;;; epochs.dat AND rewrites epochs.mac cannot re-seal it (no key).

(defun* %assemble-epochs-signed (sorted-entries)
    (function (list) (simple-array (unsigned-byte 8) (*)))
  "Serialize the epoch table SORTED-ENTRIES (a list of (epoch-id . kem-ct) sorted by epoch-id ASCENDING)
   into the epochs.mac SIGNED region: version(1)=+epochs-mac-version+ ∥ count(4 LE) ∥ [%frame-epoch-entry]*
   — each entry byte-IDENTICAL to its on-disk epochs.dat image (epoch-id ∥ ctlen ∥ ct ∥ crc), reusing
   %frame-epoch-entry so seal and verify produce the SAME canonical bytes (ADR 0045 §7.2). Deterministic:
   sorting by epoch-id makes the image independent of physical append order."
  (let* ((framed (mapcar (lambda (e)
                           (%frame-epoch-entry (the (unsigned-byte 32) (car e))
                                               (the (simple-array (unsigned-byte 8) (*)) (cdr e))))
                         sorted-entries))
         (body   (loop for f in framed sum (length f)))
         (buf    (make-array (+ 5 body) :element-type '(unsigned-byte 8))))
    (setf (aref buf 0) +epochs-mac-version+)
    (%put-u32-le buf 1 (the (unsigned-byte 32) (length sorted-entries)))
    (let ((off 5))
      (dolist (f framed)
        (replace buf f :start1 off :end1 (+ off (length f)))
        (incf off (length f))))
    buf))

(defun* %read-epochs-mac (dir)
    (function (pathname)
              (values (or null (simple-array (unsigned-byte 8) (*)))
                      (or null (simple-array (unsigned-byte 8) (*)))))
  "Read DIR/epochs.mac → (values signed-bytes anchor-mac), or (NIL NIL) if absent. A present-but-corrupt
   file (bad version/count/length/crc) SIGNALS (fail loud, mirrors %read-logmac-tail). EVERY length and
   offset is bounds-checked against the buffer BEFORE use (NFR-SEC-POSTURE) — mandatory even at (safety 0)
   — so a malformed file fails clean, never OOB. The committed count N is %get-u32-le(signed, 1);
   SIGNED-BYTES is the region the caller re-MACs (ADR 0045 §7.2)."
  (let ((path (%epochs-mac-path dir)))
    (unless (probe-file path)
      (return-from %read-epochs-mac (values nil nil)))
    (let* ((size (with-open-file (s path :element-type '(unsigned-byte 8)) (file-length s)))
           (buf  (make-array size :element-type '(unsigned-byte 8))))
      (with-open-file (s path :element-type '(unsigned-byte 8) :direction :input)
        (read-sequence buf s))
      (flet ((bad (why) (error "dds.durability: corrupt epochs MAC ~a (~a; ADR 0045 §7.2)" path why)))   ; NOCOND(SECURITY-FAILCLOSED): corrupt epochs MAC; fail-closed at store-open, caught at the durability start boundary
        ;; minimum = version(1) + count(4) + mac(32) + crc(4) = 41 (count may be 0)
        (when (< size (+ 5 +frame-mac-len+ 4)) (bad "truncated"))
        (unless (= (aref buf 0) +epochs-mac-version+) (bad "version"))
        (let ((count (%get-u32-le buf 1))
              (off   5))
          (when (> count 1000000) (bad "count"))
          (dotimes (_ count)
            ;; need epoch-id(4)+ctlen(4) before reading ctlen; then the full entry
            (when (> (+ off 8) size) (bad "entry-hdr-oob"))
            (let ((ctlen (%get-u32-le buf (+ off 4))))
              (when (> ctlen +epochs-max-ctlen+) (bad "ctlen"))
              (let ((entry-end (+ off 8 ctlen 4)))
                (when (> entry-end size) (bad "entry-oob"))
                (setf off entry-end))))
          (let* ((mac-off off) (crc-off (+ mac-off +frame-mac-len+)))
            (when (/= size (+ crc-off 4)) (bad "size"))
            (let ((stored (%get-u32-le buf crc-off))
                  (actual (%crc32 buf 0 crc-off)))
              (unless (= stored actual) (bad "crc")))
            (let ((anchor-mac (make-array +frame-mac-len+ :element-type '(unsigned-byte 8)))
                  (signed     (make-array mac-off :element-type '(unsigned-byte 8))))
              (replace anchor-mac buf :start2 mac-off :end2 crc-off)
              (replace signed buf :start2 0 :end2 mac-off)
              (values signed anchor-mac))))))))

(defun* %epoch-table->sorted (table)
    (function (hash-table) list)
  "Collect epoch TABLE (epoch-id -> kem-ct) into a fresh list of (epoch-id . kem-ct) sorted by epoch-id
   ASCENDING — the canonical order both %seal-epochs-mac and %verify-epochs-mac feed to
   %assemble-epochs-signed (ADR 0045 §7.2)."
  (sort (loop for id being the hash-keys of table using (hash-value ct)
              collect (cons id ct))
        #'< :key #'car))

(defun* %seal-epochs-mac (dir epochs-mac-key)
    (function (pathname (simple-array (unsigned-byte 8) (*))) t)
  "Seal DIR/epochs.mac at CLEAN CLOSE (ADR 0045 §7.2): re-read the epoch table (close is not hot-path),
   assemble the canonical signed image over ALL present entries (sorted ascending), HMAC it under
   EPOCHS-MAC-KEY (epochs-label ∥ region, mirroring %seal-tail-anchor), and persist (signed ∥ mac ∥ CRC,
   fsynced) via the shared %write-anchor-file. An empty table seals nothing (returns t). Committing the
   full present count makes an offline ct-tamper / rollback / reorder contradict the sealed image at the
   next open (prefix-containment)."
  (let ((table (%load-epoch-table dir)))
    (when (zerop (hash-table-count table))
      (return-from %seal-epochs-mac t))
    (let* ((sorted (%epoch-table->sorted table))
           (signed (%assemble-epochs-signed sorted))
           (mac    (%hmac-labeled epochs-mac-key %logmac-epochs-label signed)))
      (%write-anchor-file (%epochs-mac-path dir) signed mac)))
  t)

(defun* %verify-epochs-mac (dir epochs-mac-key)
    (function (pathname (simple-array (unsigned-byte 8) (*))) t)
  "Verify DIR/epochs.mac at store-open by PREFIX-CONTAINMENT (ADR 0045 §7.2), forward-tolerant. Absent ⇒
   nothing sealed ⇒ CLEAN (a never-cleanly-closed / legacy-pre-v3 store; mirrors %verify-tail-anchor's
   absent case). Else re-MAC the stored signed region under EPOCHS-MAC-KEY and fail-LOUD on the .mac's own
   MAC mismatch (forgery of epochs.mac itself). Then with N = the committed count: a table with FEWER than
   N entries ⇒ :truncated (rollback / truncation); the first-N entries (ascending) whose canonical image
   /= the stored signed region ⇒ :diverged (ct-tamper / reorder within the committed prefix); a table with
   ≥ N whose first-N MATCH ⇒ CLEAN (the extra count-N entries are a forward 1-ahead crash-append — accepted,
   NOT bricked; a strict whole-table-equality check is REJECTED). Any non-t ⇒ fail-CLOSED (a loud error at
   open, exactly like %verify-tail-anchor). NO invalidate-at-open: epochs.dat is append-only and never
   authorized-shrinks, so the only at-open divergence is the forward crash-append."
  (multiple-value-bind (signed-stored mac-stored) (%read-epochs-mac dir)
    (unless signed-stored
      (return-from %verify-epochs-mac t))
    (unless (equalp (%hmac-labeled epochs-mac-key %logmac-epochs-label signed-stored) mac-stored)
      ;; NOCOND(SECURITY-FAILCLOSED): epochs.mac MAC mismatch (tamper); fail-closed at store-open, caught at the durability start boundary
      (error "dds.durability: epochs.mac MAC mismatch in ~a (tamper — refusing to open; ADR 0045 §7.2)" dir))
    (let* ((n     (%get-u32-le signed-stored 1))
           (table (%load-epoch-table dir)))
      (when (< (hash-table-count table) n)
        ;; FORWARD REQUIREMENT, named in the error itself (ADR 0045 §7.2 / ADR 0059): the no-invalidate seal
        ;; design rests on epochs.dat never AUTHORIZED-shrinking. Epoch-table RETIREMENT is exactly such a
        ;; shrink, and would land here looking like an attack. Whoever hits this while implementing retirement
        ;; must rework the seal lifecycle (invalidate-before-shrink + re-seal at clean close, tail-anchor style)
        ;; — not weaken this check.
        ;; NOCOND(SECURITY-FAILCLOSED): epochs.mac prefix-containment (:truncated rollback); fail-closed at store-open, caught at the durability start boundary
        (error "dds.durability: epochs.mac prefix-containment FAILED in ~a (:truncated — the table has ~d ~
                epochs but ~d were sealed; refusing to open; ADR 0045 §7.2). This is rollback/truncation ~
                tampering UNLESS you are implementing the epoch-table-RETIREMENT follow-on: retirement is an ~
                AUTHORIZED shrink, which this seal deliberately cannot distinguish from an attack, so that WP ~
                MUST rework the seal lifecycle (invalidate-before-shrink + re-seal at clean close) as part of ~
                its scope — do NOT relax this check to make retirement pass."
               dir (hash-table-count table) n))
      (let* ((sorted     (%epoch-table->sorted table))
             (prefix     (subseq sorted 0 n))
             (recomputed (%assemble-epochs-signed prefix)))
        (unless (equalp recomputed signed-stored)
          ;; NOCOND(SECURITY-FAILCLOSED): epochs.mac prefix-containment (:diverged ct-tamper); fail-closed at store-open, caught at the durability start boundary
          (error "dds.durability: epochs.mac prefix-containment FAILED in ~a (:diverged — ct-tamper/reorder ~
                  within the committed prefix; refusing to open; ADR 0045 §7.2)" dir))))
    t))

;;; --- WP-DURABILITY-METADATA-CONF-3c (ADR 0025 §10 item 3): at-rest metadata sealing ---
;;; The v2/epoch decorator seals the record METADATA (topic/GUID/SN/kind/key-hash), not just the
;;; payload, so no cleartext topic name, writer-GUID, or sequence number touches disk. Mechanism:
;;;  (1) k_meta — a cross-restart-stable HMAC/AES key derived (derive-meta-key) as a SIBLING of the
;;;      ADR-0045 log-MAC key from the SAME deterministic ML-KEM anchor secret; a fresh process
;;;      re-derives it identically and re-locates + decrypts the sealed metadata.
;;;  (2) topic-hash = HMAC-SHA-256(k_meta, #x01 ∥ UTF-8(topic)) — deterministic, equality-preserving.
;;;      Used (hex-encoded) as the inner store's TOPIC identifier (file log basename / topics.map key /
;;;      SQLite topic column), so store-get-range(topic) still locates records by topic equality while
;;;      the topic NAME never touches disk. Residual: same-topic⇒same-hash equality-linkability
;;;      (value-confidentiality is met; unlinkability is NOT claimed — see ADR 0025 §10).
;;;  (3) The real guid(16) ∥ sn(8 LE) ∥ kind(1) ∥ key-hash(0|16) ride SEALED INSIDE the per-epoch DEK
;;;      blob (self-describing framing, %seal-meta-frame), recovered on get-range; the AEAD AAD is the
;;;      topic-hash bytes so a blob cannot be moved to another topic. guid/sn/kind/key-hash are thus
;;;      GCM-authenticated inside the ciphertext (the %record-aad-v2 key-hash AAD binding is subsumed).
;;;  (4) The inner store receives ONLY deterministic surrogates: topic-hash, a 16-byte guid-surrogate
;;;      = HMAC(k_meta,#x02∥guid∥sn)[0..16) (unique per (guid,sn) ⇒ preserves idempotent dedup), sn'=0,
;;;      NIL key-hash, kind=:data. It never sees plaintext guid/sn/key-hash/kind.
;;;  (5) KEEP_LAST / settled-instance compaction is DECORATOR-OWNED: the inner store is opened KEEP_ALL
;;;      (it cannot order by the hashed surrogate, and it has no real kind/key-hash), and get-range
;;;      decrypts every blob, sorts by the REAL (guid,sn) (%record-guid-sn<), then applies the effective
;;;      history policy via %compact-topic-records. This keeps get-range results byte-exact and
;;;      correctly superseded; the residual is that superseded/settled blobs are not PHYSICALLY reclaimed
;;;      on the encrypted tier until purge (a space, not a correctness, tradeoff — ADR 0025 §10).
;;;  (6) The v3 log-MAC chain (ADR 0045) covers the sealed-metadata frame unchanged: the chain seed is
;;;      keyed on the topic-hash (still per-topic-distinct), so per-topic chain-head binding survives.

(defparameter %meta-hex-digits "0123456789abcdef"
  "Lowercase hex alphabet for the metadata topic-hash string encoding (3c).")

(defun* %meta-hex (octets)
    (function ((simple-array (unsigned-byte 8) (*))) string)
  "Lowercase-hex-encode OCTETS into a filesystem/SQL-safe string (the on-disk topic-hash id; 3c)."
  (let ((hex (make-array (* 2 (length octets)) :element-type 'character)))
    (loop for b across octets
          for i from 0 by 2
          do (setf (aref hex i)      (char %meta-hex-digits (ldb (byte 4 4) b))
                   (aref hex (1+ i)) (char %meta-hex-digits (ldb (byte 4 0) b))))
    (coerce hex 'string)))

(defun* %meta-unhex (hex)
    (function (string) (simple-array (unsigned-byte 8) (*)))
  "Inverse of %META-HEX: decode a lowercase-hex string back to octets. The cross-restart open-sweep (3c)
   recovers each topic-hash BYTES (the AEAD AAD) from the inner store's on-disk topic-hash id — all it has,
   since the plaintext topic name is off-disk (ADR 0025 §10 3c). Bounds-safe (the operating contract §4):
   an odd-length or non-hex input yields a best-effort vector; a wrong AAD then fails the GCM tag ⇒
   fail-closed drop, never an out-of-bounds access."
  (let* ((n   (floor (length hex) 2))
         (out (make-array n :element-type '(unsigned-byte 8) :initial-element 0)))
    (dotimes (i n out)
      (let ((hi (digit-char-p (char hex (* 2 i)) 16))
            (lo (digit-char-p (char hex (1+ (* 2 i))) 16)))
        (setf (aref out i) (logior (ash (or hi 0) 4) (or lo 0)))))))

(defun* %meta-topic-hash-bytes (meta-key topic)
    (function ((simple-array (unsigned-byte 8) (*)) string) (simple-array (unsigned-byte 8) (*)))
  "Deterministic keyed topic-hash BYTES: HMAC-SHA-256(k_meta, #x01 ∥ UTF-8(TOPIC)) (ADR 0025 §10 3c).
   Equality-preserving (same topic ⇒ same hash) so store-get-range still locates a topic's records
   while the topic NAME never touches disk. Doubles as the AEAD AAD binding a blob to its topic."
  (let* ((tb (%string->utf8 topic))
         (in (make-array (1+ (length tb)) :element-type '(unsigned-byte 8))))
    (setf (aref in 0) #x01)
    (replace in tb :start1 1)
    (dds.dare:hmac-sha256 meta-key in)))

(defun* %meta-guid-surrogate (meta-key writer-guid sn)
    (function ((simple-array (unsigned-byte 8) (*)) (simple-array (unsigned-byte 8) (16)) (integer 0))
              (simple-array (unsigned-byte 8) (16)))
  "Deterministic 16-byte inner-index surrogate for (WRITER-GUID, SN): first 16 bytes of
   HMAC-SHA-256(k_meta, #x02 ∥ writer-guid(16) ∥ sn(8 LE)) (ADR 0025 §10 3c). Unique per (guid,sn) ⇒
   preserves the inner store's idempotent (guid,sn) dedup WITHOUT exposing the real guid or sn — both
   ride sealed inside the blob. The inner store never sees the plaintext writer-guid or sn."
  (let ((in (make-array 25 :element-type '(unsigned-byte 8))))
    (setf (aref in 0) #x02)
    (replace in writer-guid :start1 1 :end1 17)
    (%put-u64-le in 17 sn)
    (let ((mac (dds.dare:hmac-sha256 meta-key in))
          (out (make-array 16 :element-type '(unsigned-byte 8))))
      (replace out mac :end2 16)
      out)))

(defconstant +meta-frame-fixed+ 26
  "Fixed prefix bytes of a sealed metadata frame: guid(16) + sn(8) + kind(1) + kh-present(1) (3c).")

(defun* %seal-meta-frame (writer-guid sn kind key-hash payload)
    (function ((simple-array (unsigned-byte 8) (16)) (integer 0)
               (member :data :dispose :unregister)
               (or null (simple-array (unsigned-byte 8) (16)))
               (simple-array (unsigned-byte 8) (*)))
              (simple-array (unsigned-byte 8) (*)))
  "Build the self-describing plaintext sealed under the per-epoch DEK (ADR 0025 §10 3c):
   guid(16) ∥ sn(8 LE) ∥ kind(1) ∥ kh-present(1) ∥ [key-hash(16)] ∥ payload(N). All the real record
   metadata rides here, so on decrypt %OPEN-META-FRAME recovers each field byte-exact."
  (let* ((kh-p    (not (null key-hash)))
         (plen    (length payload))
         (out-len (+ +meta-frame-fixed+ (if kh-p 16 0) plen))
         (out     (make-array out-len :element-type '(unsigned-byte 8) :initial-element 0)))
    (replace out writer-guid :end1 16)
    (%put-u64-le out 16 sn)
    (setf (aref out 24) (%kind->int kind))
    (setf (aref out 25) (if kh-p 1 0))
    (let ((off +meta-frame-fixed+))
      (when kh-p
        (replace out key-hash :start1 +meta-frame-fixed+ :end1 (+ +meta-frame-fixed+ 16))
        (setf off (+ +meta-frame-fixed+ 16)))
      (replace out payload :start1 off :end1 (+ off plen)))
    out))

(defun* %open-meta-frame (pt)
    (function ((simple-array (unsigned-byte 8) (*)))
              (values (or null (simple-array (unsigned-byte 8) (16))) (integer 0)
                      (or null (member :data :dispose :unregister))
                      (or null (simple-array (unsigned-byte 8) (16)))
                      (or null (simple-array (unsigned-byte 8) (*)))))
  "Decode a sealed metadata frame (produced by %SEAL-META-FRAME) back to
   (values guid sn kind key-hash payload). Bounds-checked, fail-closed — returns (values NIL 0 NIL NIL
   NIL) on any malformed framing (a decode never trusts a length past the buffer, even though the GCM
   tag already authenticated PT; the operating contract §4)."
  (let ((n (length pt)))
    (when (< n +meta-frame-fixed+)
      (return-from %open-meta-frame (values nil 0 nil nil nil)))
    (let ((kind (%int->kind (aref pt 24)))
          (kh-p (= 1 (aref pt 25)))
          (guid (make-array 16 :element-type '(unsigned-byte 8))))
      (unless kind
        (return-from %open-meta-frame (values nil 0 nil nil nil)))
      (replace guid pt :end1 16 :end2 16)
      (let ((sn (%get-u64-le pt 16)))
        (if kh-p
            (progn
              (when (< n (+ +meta-frame-fixed+ 16))
                (return-from %open-meta-frame (values nil 0 nil nil nil)))
              (let ((kh (make-array 16 :element-type '(unsigned-byte 8)))
                    (pl (make-array (- n +meta-frame-fixed+ 16) :element-type '(unsigned-byte 8))))
                (replace kh pt :start2 +meta-frame-fixed+ :end2 (+ +meta-frame-fixed+ 16))
                (replace pl pt :start2 (+ +meta-frame-fixed+ 16))
                (values guid sn kind kh pl)))
            (let ((pl (make-array (- n +meta-frame-fixed+) :element-type '(unsigned-byte 8))))
              (replace pl pt :start2 +meta-frame-fixed+)
              (values guid sn kind nil pl)))))))

(defun* make-encrypted-store (inner-store key-provider &key epoch-dir)
    (function (durable-store dds.dare:key-provider &key (:epoch-dir (or null pathname string)))
              durable-store)
  "Construct a durable-store decorator that DARE-seals payloads on put and opens them on get-range.

   WITHOUT :EPOCH-DIR (the in-memory TRANSIENT tier, envelope v1 — unchanged 3a behavior):
   key-provider-open; ML-KEM-1024-encapsulate(recipient-public-key) -> (kem-ct ss);
   DEK = derive-dek(ss) discarding kem-ct; a per-store 96-bit counter nonce starts at 0; put seals
   + delegates to inner-store; get-range opens each record (NIL -> drop + *dare-error-hook*);
   close zeroizes+frees the DEK; a re-open re-derives a fresh DEK (prior-run records unreadable).

   WITH :EPOCH-DIR (the disk-backed PERSISTENT tier, envelope v2 — WP-DURABILITY-PERSISTENT):
   on open, key-provider-open then load epochs.dat (EPOCH-DIR/epochs.dat) and for EACH stored epoch
   key-provider-decapsulate(kem-ct) -> derive-dek -> a foreign DEK held in an epoch-id->DEK map
   (the map owns every DEK for the store lifetime); the current epoch is NIL until the first put
   (open never mints — a read-only/replay restart adds no epoch). The first put lazily MINTS a fresh
   epoch: ml-kem-1024-encapsulate(recipient-public-key) -> (kem-ct ss); new-epoch-id = max(existing)+1
   (or 1); %append-epoch + fsync epochs.dat BEFORE writing the referencing record; derive-dek(ss)
   becomes the current DEK (added to the map); the counter resets to 0. put seals under the current
   epoch via seal-payload-v2 (AAD-bound epoch-id); get-range opens each record by its epoch-id
   (unknown/NIL -> fail-closed drop + hook); close frees every DEK in the map. Because every run
   mints a distinct epoch (a distinct DEK + counter-from-0), no two runs share a (DEK, nonce) pair —
   nonce reuse is structurally impossible (there is no counter to resume). Spec §6 / ADR 0025 §5.

   All secret material (DEKs, shared secrets) lives in foreign-backed buffers via the PAL
   (static-vector, Clasp-deterministic per clasp#1793); the transient shared secret is freed once
   each DEK is derived. Topics/purge/count delegate to inner-store unchanged (metadata cleartext)."
  (if epoch-dir
      (%make-epoch-encrypted-store inner-store key-provider
                                   (uiop:ensure-directory-pathname epoch-dir))
      (%make-v1-encrypted-store inner-store key-provider)))

(defun* %make-v1-encrypted-store (inner-store key-provider)
    (function (durable-store dds.dare:key-provider) durable-store)
  "Build the v1 (no-epoch, in-memory tier) encrypted-store — the unchanged 3a fresh-DEK behavior."
  (dds.dare:key-provider-open key-provider)
  (let* ((pub-key  (dds.dare:key-provider-recipient-public-key key-provider))
         (dek      (%encrypted-store-fresh-dek pub-key))
         (counter  0)
         (err-count 0))
    (%make-durable-store
     :name :encrypted
     :put
     (lambda (topic writer-guid sn key-hash kind payload)
       (let* ((nonce  (progn (incf counter) (%render-nonce counter)))
              (aad    (dds.dare:make-record-aad topic writer-guid sn kind))
              (sealed (dds.dare:seal-payload dek nonce aad payload)))
         (store-put inner-store topic writer-guid sn key-hash kind sealed)))
     :get-range
     (lambda (topic)
       (let ((result '()))
         (dolist (r (store-get-range inner-store topic))
           (let* ((aad    (dds.dare:make-record-aad
                           (durable-record-topic r)
                           (durable-record-writer-guid r)
                           (durable-record-sn r)
                           (durable-record-kind r)))
                  (opened (dds.dare:open-payload dek (durable-record-payload r) aad)))
             (if opened
                 (push (make-durable-record
                        :topic      (durable-record-topic r)
                        :writer-guid (durable-record-writer-guid r)
                        :sn         (durable-record-sn r)
                        :key-hash   (durable-record-key-hash r)
                        :kind       (durable-record-kind r)
                        :payload    opened)
                       result)
                 (let ((n (incf err-count)))
                   (ignore-errors
                    (funcall *dare-error-hook*
                             (format nil "open-payload NIL (topic ~a, ~d sealed bytes)"
                                     (durable-record-topic r) (length (durable-record-payload r)))
                             :dare-open-failed n))))))
         (nreverse result)))
     :topics
     (lambda () (store-topics inner-store))
     :purge
     (lambda (topic) (store-purge inner-store topic))
     :open
     (lambda (history-kind history-depth)
       ;; v1 has no inner file-store to forward policy to; accept+ignore (decorator contract)
       (declare (ignore history-kind history-depth))
       (unless dek
         (dds.dare:key-provider-open key-provider)
         ;; defensive: never double-hold a DEK; free any stale one before re-deriving (§6)
         (setf dek (dds.dare:free-secret-octets dek))
         (setf dek (%encrypted-store-fresh-dek
                    (dds.dare:key-provider-recipient-public-key key-provider))))
       t)
     :close
     (lambda ()
       ;; zeroize + free the foreign secret DEK (idempotent on NIL); §6
       (setf dek (dds.dare:free-secret-octets dek))
       (dds.dare:key-provider-close key-provider)
       t)
     :count-fn
     (lambda (topic) (store-count inner-store topic))
     :sync
     (lambda () (store-sync inner-store)))))

(defun* %win-entry< (a b)
    (function (list list) boolean)
  "Order two Sliver-3a prior-surrogate window entries (real-guid-list, real-sn, inner-surrogate) by the
   SAME rule as %record-guid-sn< / %keep-last-latest — writer-guid bytes ascending, THEN sn ascending —
   NOT pure sn. This makes the decorator's physical min-drop keep EXACTLY the records the logical newest-D
   get-range view keeps, for ALL cases including a single instance fed by multiple writer GUIDs (a pure-sn
   drop would keep the wrong survivor when the min-sn sample is on the higher writer-guid). DRY with the
   backends' order (%guid-list<)."
  (let ((ga (first a)) (gb (first b)))
    (if (equal ga gb)
        (< (the (integer 0) (second a)) (the (integer 0) (second b)))
        (%guid-list< ga gb))))

(defparameter *durability-debug-disable-open-sweep* nil
  "Test-only switch for the Sliver-3c cross-restart compaction-on-open sweep (ADR 0025 §10.3). NIL
   (default) = inert; the decorator :open runs the sweep. When non-NIL the sweep is skipped, reproducing
   the pre-3c behavior (a prior session's <=D survivors leak across restarts + the fresh window is not
   seeded) so a test can prove the cross-restart-bound RED. Never set in production code.")

(defparameter *durability-debug-window-count-hook* nil
  "Test-only introspection hook (ADR 0025 §10.3 — encrypted decorator instance-windows bound). NIL
   (default) ⇒ inert. When bound to a function of one arg, the encrypted decorator's :put FUNCALLs it
   with the live instance-windows entry count AFTER each put, so a test can assert the window stays
   bounded under settling-instance churn (the put-time settle-hook remhashes a settled instance's
   window). Never set in production code.")

(defun* %make-epoch-encrypted-store (inner-store key-provider epoch-dir)
    (function (durable-store dds.dare:key-provider pathname) durable-store)
  "Build the v2 (epoch-aware, disk-backed PERSISTENT tier) encrypted-store over EPOCH-DIR.
   Holds an epoch-id -> foreign DEK map (owned for the store lifetime), a lazily-minted current
   epoch (NIL until the first put of a run), a per-current-epoch counter, and the max epoch-id
   seen (for the next mint = max+1). Constructed CLOSED — store-open loads the persisted epochs.
   WP-DURABILITY-METADATA-CONF-3c: also seals the record METADATA (topic/GUID/SN/kind/key-hash) —
   see the module header before make-encrypted-store. k_meta (cross-restart-stable) is derived from
   the same anchor secret as the log-MAC key; the inner store sees only deterministic surrogates."
  (let* ((dek-map       (make-hash-table :test #'eql))
         (lock          (dds.pal:make-lock "dds-epoch-encrypted-store"))
         (current-epoch nil)
         (current-dek   nil)
         (max-epoch-id  0)
         (counter       0)
         (err-count     0)
         ;; cross-restart-stable durability log-MAC key (foreign secret, ADR 0045); freed on close
         (logmac-key    nil)
         ;; cross-restart-stable at-rest metadata key k_meta (foreign secret, ADR 0025 §10 3c); freed on close
         (meta-key      nil)
         ;; cross-restart-stable epochs.dat MAC key k_epochs (foreign secret, ADR 0045 §7.2); freed on close
         (epochs-mac-key nil)
         ;; reverse map topic-hash-string -> real topic name, so store-topics can name this session's
         ;; topics (the plaintext name is off-disk; cross-restart it is unrecoverable — ADR 0025 §10 3c)
         (topic-names   (make-hash-table :test #'equal))
         ;; decorator-owned effective compaction policy (the inner store runs KEEP_ALL; 3c item 5)
         (eff-hk        :keep-all)
         (eff-hd        1)
         ;; Sliver 3a online prior-surrogate window (ADR 0025 §10.3): (topic-hash . real-key-hash-list)
         ;; -> list of (real-sn . inner-surrogate). The surrogate is per-SAMPLE, so the decorator must
         ;; REMEMBER each instance's live surrogates to physically evict the superseded ones on put.
         (instance-windows (make-hash-table :test #'equal))
         ;; settled-instance-churn window reclaim (ADR 0025 §10.3): (topic-hash . real-key-hash-list) ->
         ;; settle-tally. The decorator sees the REAL kind/key-hash (the inner store sees only :data
         ;; surrogates), so it detects a settle at put-time (the pass-1 predicate, shared %settle-tally-fold)
         ;; and remhashes the settled instance's window entry — else a settling instance's window entry (and
         ;; this tally) persist until purge/close, so decorator RAM grows with the settled-instance count.
         (settle-tallies (make-hash-table :test #'equal))
         ;; whether the inner store implements the additive :delete slot (SQLite = Sliver 3a, file = 3b).
         ;; NIL => the decorator SKIPS physical reclaim and stays logical-only (byte-identical to pre-3a).
         (del-supported    (and (durable-store-delete inner-store) t)))
    (labels ((%th-bytes (topic) (%meta-topic-hash-bytes meta-key topic))
             (%th (topic) (%meta-hex (%th-bytes topic)))
             (%trim-window-to-depth (th wk win)
               ;; Shared window trim (DRY): reused by the online single-put evict (%evict-prior-surrogates,
               ;; Sliver 3a/3b) AND the cross-restart compaction-on-open sweep (%open-sweep, Sliver 3c). WIN
               ;; is the instance's live entries (real-guid-list real-sn inner-surrogate) under WK (topic-hash
               ;; . real-key-hash-list). Set the window to WIN FIRST, then — if it exceeds eff-hd — physically
               ;; store-delete the entries SMALLEST by %win-entry< (writer-guid bytes ascending, THEN sn:
               ;; IDENTICAL to %keep-last-latest / %record-guid-sn<, so the physical set == the logical
               ;; newest-D get-range view EXACTLY, even for one instance fed by multiple writer GUIDs) and
               ;; overwrite the window with the survivors. The window is rewritten only AFTER the deletes
               ;; succeed, so a delete fault (crash-lower-bar) leaves the untrimmed WIN in the window and
               ;; self-heals on the next put. The store-delete is del-supported-gated so a backend without
               ;; the :delete slot still SEEDS the window (the seed helps even where physical reclaim can't).
               (setf (gethash wk instance-windows) win)
               (when (> (length win) eff-hd)
                 (let* ((sorted  (sort (copy-list win) #'%win-entry<))
                        (drop-n  (- (length sorted) eff-hd))
                        (to-drop (subseq sorted 0 drop-n))
                        (keep    (subseq sorted drop-n)))
                   (when del-supported
                     (dolist (e to-drop)
                       (store-delete inner-store th (third e) 0)))
                   (setf (gethash wk instance-windows) keep))))
             (%evict-prior-surrogates (th writer-guid key-hash sn guid*)
               ;; Sliver 3a/3b online physical reclaim (caller holds LOCK + del-supported + :keep-last +
               ;; :data + non-NIL key-hash). Append this put's entry to the instance window and trim to
               ;; newest-D via the shared %trim-window-to-depth. The append is DEDUP'd on the deterministic
               ;; surrogate so an idempotent re-put of an already-tracked (guid,sn) — which store-put no-ops
               ;; physically (INSERT OR IGNORE) — never double-counts (which would evict a LIVE newest-D
               ;; row = data loss).
               (let* ((wk  (cons th (coerce key-hash 'list)))
                      (cur (gethash wk instance-windows)))
                 (unless (member guid* cur :key #'third :test #'equalp)
                   (%trim-window-to-depth th wk (cons (list (coerce writer-guid 'list) sn guid*) cur)))))
             (%purge-topic-windows (th)
               ;; drop every instance window (and its settle tally) under this topic-hash (its inner rows are
               ;; being purged) so the decorator RAM stays bounded and a stale window can never mis-evict a
               ;; later same-instance write (ADR 0025 §10.3).
               (let ((to-remove '()))
                 (maphash (lambda (k v) (declare (ignore v))
                            (when (equal (car k) th) (push k to-remove)))
                          instance-windows)
                 (dolist (k to-remove) (remhash k instance-windows)))
               (let ((to-remove '()))
                 (maphash (lambda (k v) (declare (ignore v))
                            (when (equal (car k) th) (push k to-remove)))
                          settle-tallies)
                 (dolist (k to-remove) (remhash k settle-tallies))))
             (%settle-window-reclaim (th key-hash kind)
               ;; settled-instance-churn window reclaim (ADR 0025 §10.3): fold this put into the instance's
               ;; settle tally (the pass-1 predicate, shared %settle-tally-fold); on the SETTLE transition
               ;; remhash its eviction window + tally (mirrors %purge-topic-windows' per-key removal) so a
               ;; settling instance leaves no decorator RAM. Clearing the window on settle is exactly the
               ;; :purge FIX-3 discipline (a later re-registration seeds a fresh window — never mis-evicted).
               (let* ((wk    (cons th (coerce key-hash 'list)))
                      (tally (or (gethash wk settle-tallies)
                                 (setf (gethash wk settle-tallies) (%make-settle-tally)))))
                 (when (%settle-tally-fold tally kind)
                   (remhash wk instance-windows)
                   (remhash wk settle-tallies))))
             (%drop-hook (r)
               (let ((n (incf err-count)))
                 (ignore-errors
                  (funcall *dare-error-hook*
                           (format nil "open-payload-v2/meta NIL (~d sealed bytes)"
                                   (length (durable-record-payload r)))
                           :dare-open-failed n))))
             (%open-inner-blob (r th-bytes)
               ;; Shared decrypt (DRY get-range + open-sweep): open one inner record's blob under any known
               ;; epoch DEK, recover the REAL metadata frame; (values guid sn kind key-hash payload) on
               ;; success, (values NIL 0 NIL NIL NIL) on auth/tamper/malformed-frame. TH-BYTES is the AEAD
               ;; AAD (topic-hash bytes). The caller decides the fail-closed policy for a NIL result.
               (let ((opened (dds.dare:open-payload-v2
                              (lambda (e) (gethash e dek-map))
                              (durable-record-payload r) th-bytes)))
                 (if opened (%open-meta-frame opened) (values nil 0 nil nil nil))))
             (%locked-get-range (topic)
               ;; caller holds LOCK + has verified meta-key: locate by topic-hash, decrypt each blob,
               ;; recover the REAL metadata, sort by real (guid,sn), then apply eff-hk/eff-hd (3c item 5).
               (let* ((th-bytes (%th-bytes topic))
                      (th       (%meta-hex th-bytes))
                      (result   '()))
                 (setf (gethash th topic-names) topic)
                 (dolist (r (store-get-range inner-store th))
                   (multiple-value-bind (g s knd kh pl) (%open-inner-blob r th-bytes)
                     (if g
                         (push (make-durable-record
                                :topic topic :writer-guid g :sn s
                                :key-hash kh :kind knd :payload pl)
                               result)
                         (%drop-hook r))))
                 (%compact-topic-records (sort result #'%record-guid-sn<) eff-hk eff-hd)))
             (%open-sweep ()
               ;; Sliver 3c cross-restart physical reclaim (ADR 0025 §10.3): once per open, off the hot path
               ;; (control-plane). After a restart the freshly-clrhash'd window (3a FIX3) does not know a
               ;; prior session's <=D newest survivors per instance, so post-restart online eviction never
               ;; evicts them and they leak until the next restart (across K restarts a hammered instance
               ;; accumulates ~K*D physical rows). For :keep-last only, enumerate each inner topic-hash,
               ;; decrypt its surrogate rows (reuse %open-inner-blob), group the :data records by their REAL
               ;; key-hash, and via %trim-window-to-depth store-delete the leftovers beyond newest-D AND SEED
               ;; the window with the survivors (same entry shape the online path uses). The seed is the crux:
               ;; without it the window stays empty and the next same-instance put cannot evict the prior
               ;; survivors; WITH it the next higher-SN put pushes the seeded window to D+1 and evicts the
               ;; oldest survivor, so cross-restart physical converges to D exactly like the continuously-open
               ;; case. A backend without :delete skips the reclaim (del-supported gate) but still seeds.
               (when (and meta-key (eq :keep-last eff-hk)
                          (not *durability-debug-disable-open-sweep*))
                 (dolist (th (store-topics inner-store))
                   (let ((th-bytes    (%meta-unhex th))
                         (by-instance (make-hash-table :test #'equal)))
                     (dolist (r (store-get-range inner-store th))
                       (let ((guid* (durable-record-writer-guid r)))
                         (multiple-value-bind (g s knd kh pl) (%open-inner-blob r th-bytes)
                           (declare (ignore pl))
                           ;; only keyed :data are depth-swept (disposes/unregisters/keyless retained)
                           (when (and g (eq :data knd) kh)
                             (push (list (coerce g 'list) s guid*)
                                   (gethash (coerce kh 'list) by-instance))))))
                     (maphash (lambda (kh-list entries)
                                (%trim-window-to-depth th (cons th kh-list) entries))
                              by-instance)))))
             (%mint-current-epoch ()
             ;; lazily mint a fresh epoch on the first put of this run (caller holds LOCK).
             (let* ((pub    (dds.dare:key-provider-recipient-public-key key-provider))
                    (new-id (1+ max-epoch-id)))
               (unless (<= new-id #xFFFFFFFF)
                 (warn "dds.durability: epoch-id space exhausted (2^32 opens) — put rejected (:resource-limits)")   ; NOCOND(WARN): terminal resource limit; prints + returns, no control transfer
                 (return-from %mint-current-epoch :resource-limits))
               (multiple-value-bind (kem-ct ss) (dds.dare:ml-kem-1024-encapsulate pub)
                 ;; derive-dek inside unwind-protect so ss is freed even if derivation throws.
                 (let ((dek (unwind-protect (dds.dare:derive-dek ss)
                              (dds.dare:free-secret-octets ss))))
                   ;; fsync epochs.dat ONLY after derive-dek succeeds (no duplicate-id on throw).
                   (%append-epoch epoch-dir new-id kem-ct)
                   (setf (gethash new-id dek-map) dek)
                   (setf current-epoch new-id)
                   (setf current-dek   dek)
                   (setf max-epoch-id  new-id)
                   (setf counter       0))))
             t)
           (%ensure-logmac ()
             ;; lazily mint the log-MAC anchor + derive the key + install the oracle on the FIRST v3
             ;; put of a not-yet-chained store (caller holds LOCK), so the first record is written v3
             ;; and "anchor present" == "a v3 frame exists". The pre-existing NON-EMPTY topic logs at
             ;; this moment (all legacy v1/v2, since anchor absent ⇒ no v3 written yet) are recorded as
             ;; the authenticated GRANDFATHER SET — exempt from the downgrade check — so a legacy
             ;; multi-topic v2 store migrates topic-by-topic WITHOUT a false-REJECT of its dormant
             ;; legacy topics, while every born-chained (non-grandfathered) topic still fails a full
             ;; v3->v2 downgrade. A fresh store has no such logs ⇒ empty set ⇒ full protection (§3.2).
             (unless logmac-key
               (let ((gf-ids (%store-grandfather-ids inner-store epoch-dir)))
                 (multiple-value-bind (lk mk ek) (%mint-logmac-anchor key-provider epoch-dir gf-ids)
                   (setf logmac-key     lk)
                   (setf meta-key       mk)
                   (setf epochs-mac-key ek))
                 (%install-logmac-oracle inner-store logmac-key gf-ids)))
             t))
      (%make-durable-store
       :name :encrypted-persistent
       :put
       ;; 3c: seal topic/GUID/SN/kind/key-hash INTO the blob; hand the inner store only surrogates.
       (lambda (topic writer-guid sn key-hash kind payload)
         (block put
         (dds.pal:with-lock (lock)
           (%ensure-logmac)                     ; also derives k_meta on the first put of a fresh store
           (unless current-epoch
             ;; ADR 0064: an epoch-id-exhausted mint returns :resource-limits — propagate it, never unwind
             (let ((s (%mint-current-epoch)))
               (unless (eq s t) (return-from put s))))
           (incf counter)
           (when (>= counter +max-nonce-counter+)
             (warn "dds.durability: per-epoch nonce counter exhausted (2^96) — put rejected (:resource-limits); restart to mint a fresh epoch")   ; NOCOND(WARN): terminal resource limit; prints + returns, no control transfer
             (return-from put :resource-limits))
           (let* ((th-bytes (%th-bytes topic))
                  (th       (%meta-hex th-bytes))
                  (guid*    (%meta-guid-surrogate meta-key writer-guid sn))
                  (frame    (%seal-meta-frame writer-guid sn kind key-hash payload))
                  (nonce    (%render-nonce counter))
                  ;; AAD = topic-hash bytes: binds the blob to its topic (guid/sn/kind/key-hash are now
                  ;; GCM-authenticated INSIDE the ciphertext, so %record-aad-v2's field binding is subsumed)
                  (sealed   (dds.dare:seal-payload-v2 current-dek current-epoch nonce th-bytes frame)))
             (setf (gethash th topic-names) topic)
             (let ((r (store-put inner-store th guid* 0 nil :data sealed)))
               ;; Sliver 3a/3b: physically evict the superseded prior surrogates so the inner physical row
               ;; count converges to eff-hd (closes the ADR 0025 §10.3 residual for the continuously-open
               ;; case). Runs for ANY del-supported inner store — SQLite (Sliver 3a) AND the file store
               ;; (Sliver 3b: it HAS a :delete slot ⇒ del-supported is T, so the file tier physically
               ;; reclaims too; this on-disk shrink is exactly why the tail anchor is invalidated at open,
               ;; ADR 0045 §7.1). A backend without :delete (del-supported NIL) stays logical-only.
               (when (and del-supported (eq :keep-last eff-hk) (eq :data kind) key-hash)
                 (%evict-prior-surrogates th writer-guid key-hash sn guid*))
               ;; settled-instance-churn window reclaim (ADR 0025 §10.3): the decorator sees the REAL kind,
               ;; so a settle here remhashes the instance's window (the inner store only saw :data surrogates
               ;; and cannot). Same del-supported/:keep-last gate the window itself lives under.
               (when (and del-supported (eq :keep-last eff-hk) key-hash
                          (not *durability-debug-disable-settle-trigger*))
                 (%settle-window-reclaim th key-hash kind))
               (when *durability-debug-window-count-hook*
                 (funcall *durability-debug-window-count-hook* (hash-table-count instance-windows)))
               r)))))
       :get-range
       (lambda (topic)
         (dds.pal:with-lock (lock)
           (if (null meta-key) '() (%locked-get-range topic))))
       :topics
       ;; 3c: the inner store holds topic-HASHES; name only this session's known topics (plaintext
       ;; names are off-disk, so cross-restart enumeration by name is unavailable — ADR 0025 §10).
       (lambda ()
         (dds.pal:with-lock (lock)
           (let ((result '()))
             (dolist (h (store-topics inner-store))
               (let ((real (gethash h topic-names)))
                 (when real (push real result))))
             result)))
       :purge
       (lambda (topic)
         (dds.pal:with-lock (lock)
           (if (null meta-key)
               t
               (let* ((th-bytes (%th-bytes topic))
                      (th       (%meta-hex th-bytes)))
                 (remhash th topic-names)
                 (%purge-topic-windows th)
                 (store-purge inner-store th)))))
       :open
       (lambda (history-kind history-depth)
         (dds.pal:with-lock (lock)
           ;; defensive: a re-open must not leak prior-run secrets (idempotent on empty/NIL); §6
           (%free-epoch-dek-map dek-map)
           (setf current-epoch nil)
           (setf current-dek   nil)
           (setf counter       0)
           (setf logmac-key    (dds.dare:free-secret-octets logmac-key))
           ;; ADR 0045 §7.2: free k_epochs (idempotent on NIL/foreign); re-derived below if the anchor is present
           (setf epochs-mac-key (dds.dare:free-secret-octets epochs-mac-key))
           ;; 3c: free k_meta + drop the session name map; capture the effective compaction policy
           ;; (the decorator owns compaction — the inner store is opened KEEP_ALL below).
           (setf meta-key (dds.dare:free-secret-octets meta-key))
           (clrhash topic-names)
           ;; Sliver 3a: a re-open starts a fresh prior-surrogate window (bounds decorator RAM across
           ;; reopens + prevents a stale window from mis-evicting; cross-restart ≤D leftovers = 3c).
           (clrhash instance-windows)
           (clrhash settle-tallies)      ; settled-instance-churn tallies are per-session (ADR 0025 §10.3)
           (when history-kind  (setf eff-hk history-kind))
           (when history-depth (setf eff-hd history-depth))
           ;; drop any prior-open oracle (it closes over the just-freed key); reinstalled below. This
           ;; also makes a pathological "v3 frames but missing anchor" fail closed (no key) at replay,
           ;; never a use-after-free (ADR 0045 fail-closed posture).
           (store-set-chain-mac-fn inner-store nil)
           ;; keyed log-MAC chain (ADR 0045). Ordering is perms-sensitive (the key-provider's key-dir
           ;; may nest UNDER the store dir, so opening it before the file store enforces 0700 would
           ;; create the store dir at a loose umask) AND downgrade-sensitive (§3.2):
           ;;  - ANCHOR PRESENT ⇒ this store has already committed to the chain (a v3 frame was
           ;;    written): dir is already 0700, so open the key-provider, derive the key + install the
           ;;    oracle (CHAIN-REQUIRED) BEFORE store-open — its replay then verifies the v3 chain AND
           ;;    rejects a full v3->v2 downgrade, fail-closed.
           ;;  - ANCHOR ABSENT ⇒ fresh store OR a legacy Batch-B v2 store (no v3 frames yet): store-open
           ;;    FIRST creates + enforces the 0700 dir and replays v1/v2 in MIGRATION mode (no oracle,
           ;;    not chain-required — a legacy v2 log must never be false-rejected). The anchor is
           ;;    minted lazily on the first v3 put (%ensure-logmac), keeping "anchor present" == "a v3
           ;;    frame exists". (A store whose anchor was DELETED but still holds v3 frames fails here
           ;;    at replay via key-absent, never opening as bogus migration.)
           ;; 3c: the inner store is ALWAYS opened KEEP_ALL (it cannot order/interpret the hashed
           ;; surrogates); the decorator applies eff-hk/eff-hd at get-range post-decrypt.
           (if (probe-file (%logmac-anchor-path epoch-dir))
               (multiple-value-bind (key gf-ids mkey ekey)
                   (progn
                     (dds.dare:key-provider-open key-provider)
                     (%load-logmac-anchor key-provider epoch-dir))
                 (setf logmac-key     key)
                 (setf meta-key       mkey)
                 (setf epochs-mac-key ekey)   ; ADR 0045 §7.2: k_epochs for the epochs.dat MAC verify below
                 (%install-logmac-oracle inner-store key gf-ids)
                 ;; sealed high-water tail anchor (ADR 0045 §7.1): VERIFY the at-rest sealed state (detect
                 ;; an OFFLINE truncation / whole-topic drop / rollback) BEFORE store-open, then INVALIDATE
                 ;; the anchor BEFORE store-open's compaction sweep + this session's puts AUTHORIZED-SHRINK
                 ;; the log — so an authorized shrink + a crash (no clean re-seal) leaves NO stale anchor to
                 ;; FALSE-REJECT (the store reopens clean; re-sealed at the next clean close over the final
                 ;; state). Verify FIRST keeps detection; invalidate SECOND kills the reclaim-crash brick.
                 (%verify-tail-anchor inner-store epoch-dir key)
                 (unless *durability-debug-skip-tail-invalidate*
                   (%invalidate-tail-anchor epoch-dir))
                 (store-open inner-store :keep-all nil))
               (progn
                 (store-open inner-store :keep-all nil)
                 (dds.dare:key-provider-open key-provider)))
           ;; re-derive every persisted epoch's DEK; current stays NIL until the first put
           (setf max-epoch-id (%load-epoch-deks key-provider epoch-dir dek-map))
           ;; sealed epochs.dat MAC (ADR 0045 §7.2): VERIFY the DARE per-epoch kem-ct table by prefix-
           ;; containment, AFTER %load-epoch-deks has run epochs.dat's torn-tail truncate-recovery so verify
           ;; composes with it. GUARDED on epochs-mac-key non-NIL: a legacy pre-0045 store (epochs.dat but no
           ;; anchor) has NIL here ⇒ verify skipped until it goes v3 (mirrors the grandfather exemption).
           ;; Forward-tolerant (a 1-ahead crash-append reopens CLEAN); NO invalidate (epochs.dat never
           ;; authorized-shrinks, so there is no reclaim-crash window to cover — simpler than the tail anchor).
           (when epochs-mac-key
             (%verify-epochs-mac epoch-dir epochs-mac-key))
           ;; Sliver 3c: after the DEKs + k_meta are resident and the window is fresh, sweep the inner
           ;; store — physically reclaim a prior session's beyond-D leftovers AND seed the window with the
           ;; surviving newest-D so post-restart online eviction is correct (cross-restart == continuously-
           ;; open). No-op for :keep-all or a not-yet-chained (meta-key NIL) store; ADR 0025 §10.3.
           (%open-sweep)
           t))
       :close
       (lambda ()
         (dds.pal:with-lock (lock)
           ;; sealed high-water tail anchor (ADR 0045 §7.1): seal the per-topic (N, M_N) BEFORE freeing
           ;; the log-MAC key + dropping the oracle (both needed to MAC the anchor + re-walk the chain).
           ;; SEAL-ON-CLOSE only (prefix-containment makes a stale anchor safe on crash — a forward
           ;; extension is CLEAN); a store that never chained (logmac-key NIL) has no tail to seal.
           (when (and logmac-key (not *durability-debug-skip-tail-seal*))
             (%seal-tail-anchor inner-store epoch-dir logmac-key))
           ;; sealed epochs.dat MAC (ADR 0045 §7.2): re-seal D/epochs.mac over ALL present epochs BEFORE
           ;; freeing k_epochs. SEAL-ON-CLOSE only (prefix-containment makes a stale epochs.mac safe on a
           ;; forward crash-append — CLEAN). A store that never chained (epochs-mac-key NIL) has nothing to seal.
           (when (and epochs-mac-key (not *durability-debug-skip-epochs-seal*))
             (%seal-epochs-mac epoch-dir epochs-mac-key))
           ;; free every DEK in the map (the current DEK is held in the map ⇒ freed once); §6
           (%free-epoch-dek-map dek-map)
           (setf current-epoch nil)
           (setf current-dek   nil)
           ;; Sliver 3a: drop the prior-surrogate window (bounds decorator RAM across reopens); §6 parity
           (clrhash instance-windows)
           (clrhash settle-tallies)      ; settled-instance-churn tallies (ADR 0025 §10.3)
           ;; zeroize + free the foreign log-MAC key + k_meta + k_epochs and drop the oracle (points at freed bytes); §6
           (setf logmac-key     (dds.dare:free-secret-octets logmac-key))
           (setf meta-key       (dds.dare:free-secret-octets meta-key))
           (setf epochs-mac-key (dds.dare:free-secret-octets epochs-mac-key))
           (store-set-chain-mac-fn inner-store nil)
           (dds.dare:key-provider-close key-provider)
           ;; close the inner store last: flush + persist its streams/topics.map (spec §5)
           (store-close inner-store)
           t))
       :count-fn
       ;; 3c: per-topic count is LOGICAL (post-compaction, matching get-range), since the inner store
       ;; retains superseded blobs physically (KEEP_ALL); total count (NIL) is the inner physical count.
       (lambda (topic)
         (dds.pal:with-lock (lock)
           (if topic
               (if (null meta-key) 0 (length (%locked-get-range topic)))
               (store-count inner-store nil))))
       :sync
       (lambda () (store-sync inner-store))))))
