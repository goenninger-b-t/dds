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
    (ensure-directories-exist path)
    (with-open-file (s path :direction :output :element-type '(unsigned-byte 8)
                            :if-exists :append :if-does-not-exist :create)
      (write-sequence entry s)
      (dds.pal:fsync-stream s)))
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
     (lambda ()
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
   seen (for the next mint = max+1). Constructed CLOSED — store-open loads the persisted epochs."
  (let* ((dek-map       (make-hash-table :test #'eql))
         (lock          (dds.pal:make-lock "dds-epoch-encrypted-store"))
         (current-epoch nil)
         (current-dek   nil)
         (max-epoch-id  0)
         (counter       0)
         (err-count     0))
    (flet ((%mint-current-epoch ()
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
             t))
      (%make-durable-store
       :name :encrypted-persistent
       :put
       (lambda (topic writer-guid sn key-hash kind payload)
         (dds.pal:with-lock (lock)
           (unless current-epoch
             (%mint-current-epoch))
           (incf counter)
           (when (>= counter +max-nonce-counter+)
             (error "dds.durability: per-epoch nonce counter exhausted (2^96) — restart to mint a fresh epoch"))
           (let* ((nonce  (%render-nonce counter))
                  (aad    (%record-aad-v2 topic writer-guid sn kind key-hash))
                  (sealed (dds.dare:seal-payload-v2 current-dek current-epoch nonce aad payload)))
             (store-put inner-store topic writer-guid sn key-hash kind sealed))))
       :get-range
       (lambda (topic)
         (dds.pal:with-lock (lock)
           (let ((result '()))
             (dolist (r (store-get-range inner-store topic))
               (let* ((aad    (%record-aad-v2
                               (durable-record-topic r)
                               (durable-record-writer-guid r)
                               (durable-record-sn r)
                               (durable-record-kind r)
                               (durable-record-key-hash r)))
                      (opened (dds.dare:open-payload-v2
                               (lambda (e) (gethash e dek-map))
                               (durable-record-payload r) aad)))
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
                                 (format nil "open-payload-v2 NIL (topic ~a, ~d sealed bytes)"
                                         (durable-record-topic r) (length (durable-record-payload r)))
                                 :dare-open-failed n))))))
             (nreverse result))))
       :topics
       (lambda () (store-topics inner-store))
       :purge
       (lambda (topic) (store-purge inner-store topic))
       :open
       (lambda ()
         (dds.pal:with-lock (lock)
           ;; open the inner store first: it creates topics/ + replays the sealed logs (spec §5)
           (store-open inner-store)
           ;; defensive: a re-open must not leak prior-run DEKs (idempotent on empty); §6
           (%free-epoch-dek-map dek-map)
           (setf current-epoch nil)
           (setf current-dek   nil)
           (setf counter       0)
           (dds.dare:key-provider-open key-provider)
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
           (dds.dare:key-provider-close key-provider)
           ;; close the inner store last: flush + persist its streams/topics.map (spec §5)
           (store-close inner-store)
           t))
       :count-fn
       (lambda (topic) (store-count inner-store topic))
       :sync
       (lambda () (store-sync inner-store))))))
