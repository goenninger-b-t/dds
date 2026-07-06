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
    (warn "dds.durability dare (~a) open-payload failure #~d: ~a" context count condition))
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

(defun* %logmac-anchor-path (dir)
    (function (pathname) pathname)
  "Return the logmac.anchor pathname within the encrypted-store epoch directory DIR."
  (uiop:merge-pathnames* "logmac.anchor" (uiop:ensure-directory-pathname dir)))

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

(defun* %compute-gf-mac (logmac-key signed)
    (function ((simple-array (unsigned-byte 8) (*)) (simple-array (unsigned-byte 8) (*)))
              (simple-array (unsigned-byte 8) (*)))
  "Authenticate the anchor's SIGNED region (kem-ct + grandfather set) under the log-MAC key so a disk
   adversary cannot forge/extend the exempt set: HMAC-SHA-256(key, label ∥ signed) (ADR 0045 §3.2/§7)."
  (let* ((ln    (length %logmac-gf-label))
         (input (make-array (+ ln (length signed)) :element-type '(unsigned-byte 8))))
    (replace input %logmac-gf-label :end1 ln)
    (replace input signed :start1 ln)
    (dds.dare:hmac-sha256 logmac-key input)))

(defun* %write-logmac-anchor (dir signed gf-mac)
    (function (pathname (simple-array (unsigned-byte 8) (*)) (simple-array (unsigned-byte 8) (*))) t)
  "Persist the anchor: SIGNED ∥ gf-mac(32) ∥ crc32(4), fsynced (open→write→fsync-stream, + dir fsync
   when new) so it survives power loss (ADR 0045 §3.2)."
  (let* ((slen  (length signed))
         (entry (make-array (+ slen +logmac-gf-mac-len+ 4) :element-type '(unsigned-byte 8))))
    (replace entry signed :end1 slen)
    (replace entry gf-mac :start1 slen :end1 (+ slen +logmac-gf-mac-len+))
    (let ((crc-off (+ slen +logmac-gf-mac-len+)))
      (%put-u32-le entry crc-off (%crc32 entry 0 crc-off)))
    (let* ((path (%logmac-anchor-path dir))
           (existed (probe-file path)))
      (ensure-directories-exist path)
      (with-open-file (s path :direction :output :element-type '(unsigned-byte 8)
                              :if-exists :supersede :if-does-not-exist :create)
        (write-sequence entry s)
        (dds.pal:fsync-stream s))
      (unless existed
        (dds.pal:fsync-directory (uiop:pathname-directory-pathname path)))))
  t)

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
      (flet ((bad (why) (error "dds.durability: corrupt log-MAC anchor ~a (~a; ADR 0045 §3.2)" path why)))
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
              (values (simple-array (unsigned-byte 8) (*)) (simple-array (unsigned-byte 8) (*))))
  "Mint the log-MAC anchor ONCE (first v3 put): encapsulate to the recipient key, derive the log-MAC
   key AND the at-rest metadata key k_meta (siblings from the SAME shared secret, distinct info labels;
   ADR 0045 §4.3 / ADR 0025 §10 3c), authenticate GRANDFATHER-IDS (pre-existing legacy topic-ids,
   exempt from the downgrade check) under the log-MAC key, and persist (kem-ct + set + MAC). Returns
   (values logmac-key meta-key) — both foreign secrets the caller frees on close. Written once, never
   updated ⇒ crash-safe, no migration burst (ADR 0045 §3.2). The anchor kem-ct decapsulates
   deterministically on every restart, so k_meta is cross-restart-stable (ADR 0025 §10 3c)."
  (let ((pub (dds.dare:key-provider-recipient-public-key key-provider)))
    (multiple-value-bind (kem-ct ss) (dds.dare:ml-kem-1024-encapsulate pub)
      (multiple-value-bind (key mkey)
          (unwind-protect
               (values (dds.dare:derive-log-mac-key ss) (dds.dare:derive-meta-key ss))
            (dds.dare:free-secret-octets ss))
        (let* ((signed (%assemble-anchor-signed kem-ct grandfather-ids))
               (gf-mac (%compute-gf-mac key signed)))
          (%write-logmac-anchor dir signed gf-mac))
        (values key mkey)))))

(defun* %load-logmac-anchor (key-provider dir)
    (function (dds.dare:key-provider pathname)
              (values (simple-array (unsigned-byte 8) (*)) list (simple-array (unsigned-byte 8) (*))))
  "Load an EXISTING anchor: decapsulate the kem-ct (deterministic ⇒ cross-restart-stable), derive the
   log-MAC key AND the at-rest metadata key k_meta (siblings from the SAME shared secret; ADR 0045
   §4.3 / ADR 0025 §10 3c), and VERIFY the grandfather-set MAC under the log-MAC key — a mismatch
   SIGNALS (a disk adversary cannot forge/extend the exempt set; ADR 0045 §3.2). Returns
   (values logmac-key grandfather-ids meta-key); both keys are foreign secrets the caller frees."
  (multiple-value-bind (kem-ct gf-ids gf-mac signed) (%read-logmac-anchor dir)
    (unless kem-ct
      (error "dds.durability: log-MAC anchor missing in ~a" dir))
    (let ((ss (dds.dare:key-provider-decapsulate key-provider kem-ct)))
      (multiple-value-bind (key mkey)
          (unwind-protect
               (values (dds.dare:derive-log-mac-key ss) (dds.dare:derive-meta-key ss))
            (dds.dare:free-secret-octets ss))
        (unless (equalp (%compute-gf-mac key signed) gf-mac)
          (dds.dare:free-secret-octets key)
          (dds.dare:free-secret-octets mkey)
          (error "dds.durability: log-MAC anchor grandfather-set MAC mismatch in ~a ~
                  (tamper — refusing to open; ADR 0045 §3.2)" dir))
        (values key gf-ids mkey)))))

(defun* %derive-logmac-key (key-provider dir)
    (function (dds.dare:key-provider pathname) (simple-array (unsigned-byte 8) (*)))
  "Derive the cross-restart-stable log-MAC key from DIR's EXISTING anchor — a thin wrapper over
   %LOAD-LOGMAC-ANCHOR returning just the key (used by tests). Caller frees it (ADR 0045 §4.3)."
  (values (%load-logmac-anchor key-provider dir)))

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
         ;; reverse map topic-hash-string -> real topic name, so store-topics can name this session's
         ;; topics (the plaintext name is off-disk; cross-restart it is unrecoverable — ADR 0025 §10 3c)
         (topic-names   (make-hash-table :test #'equal))
         ;; decorator-owned effective compaction policy (the inner store runs KEEP_ALL; 3c item 5)
         (eff-hk        :keep-all)
         (eff-hd        1))
    (labels ((%th-bytes (topic) (%meta-topic-hash-bytes meta-key topic))
             (%th (topic) (%meta-hex (%th-bytes topic)))
             (%drop-hook (r)
               (let ((n (incf err-count)))
                 (ignore-errors
                  (funcall *dare-error-hook*
                           (format nil "open-payload-v2/meta NIL (~d sealed bytes)"
                                   (length (durable-record-payload r)))
                           :dare-open-failed n))))
             (%locked-get-range (topic)
               ;; caller holds LOCK + has verified meta-key: locate by topic-hash, decrypt each blob,
               ;; recover the REAL metadata, sort by real (guid,sn), then apply eff-hk/eff-hd (3c item 5).
               (let* ((th-bytes (%th-bytes topic))
                      (th       (%meta-hex th-bytes))
                      (result   '()))
                 (setf (gethash th topic-names) topic)
                 (dolist (r (store-get-range inner-store th))
                   (let ((opened (dds.dare:open-payload-v2
                                  (lambda (e) (gethash e dek-map))
                                  (durable-record-payload r) th-bytes)))
                     (if opened
                         (multiple-value-bind (g s knd kh pl) (%open-meta-frame opened)
                           (if g
                               (push (make-durable-record
                                      :topic topic :writer-guid g :sn s
                                      :key-hash kh :kind knd :payload pl)
                                     result)
                               (%drop-hook r)))
                         (%drop-hook r))))
                 (%compact-topic-records (sort result #'%record-guid-sn<) eff-hk eff-hd)))
             (%mint-current-epoch ()
             ;; lazily mint a fresh epoch on the first put of this run (caller holds LOCK).
             (let* ((pub    (dds.dare:key-provider-recipient-public-key key-provider))
                    (new-id (1+ max-epoch-id)))
               (unless (<= new-id #xFFFFFFFF)
                 (error "dds.durability: epoch-id space exhausted (2^32 opens)"))
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
                 (multiple-value-bind (lk mk) (%mint-logmac-anchor key-provider epoch-dir gf-ids)
                   (setf logmac-key lk)
                   (setf meta-key   mk))
                 (%install-logmac-oracle inner-store logmac-key gf-ids)))
             t))
      (%make-durable-store
       :name :encrypted-persistent
       :put
       ;; 3c: seal topic/GUID/SN/kind/key-hash INTO the blob; hand the inner store only surrogates.
       (lambda (topic writer-guid sn key-hash kind payload)
         (dds.pal:with-lock (lock)
           (%ensure-logmac)                     ; also derives k_meta on the first put of a fresh store
           (unless current-epoch
             (%mint-current-epoch))
           (incf counter)
           (when (>= counter +max-nonce-counter+)
             (error "dds.durability: per-epoch nonce counter exhausted (2^96) — restart to mint a fresh epoch"))
           (let* ((th-bytes (%th-bytes topic))
                  (th       (%meta-hex th-bytes))
                  (guid*    (%meta-guid-surrogate meta-key writer-guid sn))
                  (frame    (%seal-meta-frame writer-guid sn kind key-hash payload))
                  (nonce    (%render-nonce counter))
                  ;; AAD = topic-hash bytes: binds the blob to its topic (guid/sn/kind/key-hash are now
                  ;; GCM-authenticated INSIDE the ciphertext, so %record-aad-v2's field binding is subsumed)
                  (sealed   (dds.dare:seal-payload-v2 current-dek current-epoch nonce th-bytes frame)))
             (setf (gethash th topic-names) topic)
             (store-put inner-store th guid* 0 nil :data sealed))))
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
           ;; 3c: free k_meta + drop the session name map; capture the effective compaction policy
           ;; (the decorator owns compaction — the inner store is opened KEEP_ALL below).
           (setf meta-key (dds.dare:free-secret-octets meta-key))
           (clrhash topic-names)
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
               (multiple-value-bind (key gf-ids mkey)
                   (progn
                     (dds.dare:key-provider-open key-provider)
                     (%load-logmac-anchor key-provider epoch-dir))
                 (setf logmac-key key)
                 (setf meta-key   mkey)
                 (%install-logmac-oracle inner-store key gf-ids)
                 (store-open inner-store :keep-all nil))
               (progn
                 (store-open inner-store :keep-all nil)
                 (dds.dare:key-provider-open key-provider)))
           ;; re-derive every persisted epoch's DEK; current stays NIL until the first put
           (setf max-epoch-id (%load-epoch-deks key-provider epoch-dir dek-map))
           t))
       :close
       (lambda ()
         (dds.pal:with-lock (lock)
           ;; free every DEK in the map (the current DEK is held in the map ⇒ freed once); §6
           (%free-epoch-dek-map dek-map)
           (setf current-epoch nil)
           (setf current-dek   nil)
           ;; zeroize + free the foreign log-MAC key + k_meta and drop the oracle (points at freed bytes); §6
           (setf logmac-key (dds.dare:free-secret-octets logmac-key))
           (setf meta-key   (dds.dare:free-secret-octets meta-key))
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
