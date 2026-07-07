(in-package #:dds.durability)

;;; durable-record: one retained sample from a writer, keyed by (topic, writer-guid, sn).

(defstruct* (durable-record (:constructor make-durable-record))
  "One retained sample in the durable store: topic name, 16-byte writer GUID, sequence number,
   optional 16-byte key hash, change kind, and raw CDR payload."
  (topic   ""  :type string)
  (writer-guid (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)
               :type (simple-array (unsigned-byte 8) (16)))
  (sn      0   :type (integer 0))
  (key-hash nil :type (or null (simple-array (unsigned-byte 8) (16))))
  (kind    :data :type (member :data :dispose :unregister))
  (payload (make-array 0 :element-type '(unsigned-byte 8)) :type (simple-array (unsigned-byte 8) (*))))

;;; durable-store vtable: function slots mirror the transport pattern (FR-XPORT-5 analogue).

(defstruct* (durable-store (:constructor %make-durable-store))
  "Pluggable persistence vtable (ADR 0021): every operation is a function slot so the
   caller is decoupled from the backing implementation (memory, file, or db)."
  (name       :memory :type keyword)
  (put        nil     :type (or null function))
  (get-range  nil     :type (or null function))
  (topics     nil     :type (or null function))
  (purge      nil     :type (or null function))
  (open       nil     :type (or null function))
  (close      nil     :type (or null function))
  (count-fn   nil     :type (or null function))
  ;; group-commit sync: called after each drain tick; NIL = no-op (memory store)
  (sync       nil     :type (or null function))
  ;; keyed log-MAC chain seam (ADR 0045): install a MAC oracle (data)->HMAC; NIL = feature absent
  (set-chain-mac-fn nil :type (or null function))
  ;; sealed high-water tail-anchor seam (ADR 0045 §7.1): read-only, additive NIL-fallback (like sync).
  ;; chain-tails-fn ()->hash topic-id->(N . M_N) gathers the per-topic (v3-count . tail-MAC) for the
  ;; seal; verify-chain-prefix-fn (topic-id N M_N)->t|:truncated|:diverged re-walks a topic's on-disk
  ;; chain for the open-time prefix-containment check. NIL on a backend without the seam (memory /
  ;; SQLite / microservice) ⇒ the tail anchor is absent for that tier (FILE tier only this slice).
  (chain-tails-fn nil :type (or null function))
  (verify-chain-prefix-fn nil :type (or null function))
  ;; per-record physical delete-by-(topic,writer-guid,sn) (ADR 0025 §10.3 / ADR 0029 §10); NIL = the
  ;; backend has no physical reclaim (byte-identical to pre-slot) — same NIL-fallback as sync above
  (delete nil :type (or null function))
  ;; atomic whole-topic REPLACE (ADR 0050 §4.4): (topic records)->t swaps ALL of a topic's records for
  ;; RECORDS in one all-or-nothing step (a partial topic bricks a re-MAC'd chain). NIL = the same additive
  ;; NIL-fallback as delete/sync — store-replace-topic then does purge+bulk-put (crash-atomic ONLY for the
  ;; in-process memory store; a persistent backend SUPPLIES this slot for tmp+rename / transaction atomicity).
  (replace-topic-fn nil :type (or null function)))

;;; Public dispatch functions — one slot read + funcall (no CLOS dispatch on the hot path).

(defun* store-put (store topic writer-guid sn key-hash kind payload)
    (function (durable-store string (simple-array (unsigned-byte 8) (16)) (integer 0)
               (or null (simple-array (unsigned-byte 8) (16)))
               (member :data :dispose :unregister)
               (simple-array (unsigned-byte 8) (*)))
              (or (eql t) (eql :rejected)))
  "Persist a sample: returns T on success or :REJECTED when a bounded store is full.
   Idempotent on (topic, writer-guid, sn) — a re-put of the same key is a no-op returning T."
  (funcall (durable-store-put store) topic writer-guid sn key-hash kind payload))

(defun* store-get-range (store topic)
    (function (durable-store string) list)
  "Return all retained records for TOPIC as a list of DURABLE-RECORD, ordered by (writer-guid, sn)."
  (funcall (durable-store-get-range store) topic))

(defun* store-topics (store)
    (function (durable-store) list)
  "Return a list of topic strings that have at least one retained record."
  (funcall (durable-store-topics store)))

(defun* store-purge (store topic)
    (function (durable-store string) (eql t))
  "Remove all retained records for TOPIC. Returns T."
  (funcall (durable-store-purge store) topic))

(declaim (ftype (function (durable-store &optional
                                          (or null (member :keep-all :keep-last))
                                          (or null (integer 1)))
                          t)
                store-open))
(defun* store-open (store &optional history-kind history-depth)
    (function (durable-store &optional
               (or null (member :keep-all :keep-last)) (or null (integer 1)))
              t)
  "Open STORE; HISTORY-KIND and HISTORY-DEPTH override the factory default when non-NIL.
   A non-NIL HISTORY-DEPTH must be a positive integer (>= 1); NIL defers to the store factory default.
   The in-memory backend stashes the overrides for future per-instance eviction.
   The file backend applies the effective policy at compaction-on-open (DDS 1.4 §2.2.3.5).
   The encrypted backend delegates to the inner store. Returns T."
  (declare (type durable-store store)
           (type (or null (member :keep-all :keep-last)) history-kind)
           (type (or null (integer 1)) history-depth))
  (funcall (durable-store-open store) history-kind history-depth))

(defun* store-close (store)
    (function (durable-store) (eql t))
  "Close the backing store and release resources. No-op for the in-memory implementation. Returns T."
  (funcall (durable-store-close store)))

(defun* store-count (store &optional topic)
    (function (durable-store &optional (or null string)) (integer 0))
  "Return the total record count across all topics, or the per-TOPIC count if TOPIC is supplied."
  (funcall (durable-store-count-fn store) topic))

(defun* store-sync (store)
    (function (durable-store) (eql t))
  "Flush+fsync any buffered writes; no-op when the backing store has no :sync slot."
  (let ((f (durable-store-sync store)))
    (when f (funcall f)))
  t)

(defun* store-set-chain-mac-fn (store fn &optional required grandfather-set)
    (function (durable-store (or null function) &optional t (or null hash-table)) (eql t))
  "Install the keyed log-MAC chain oracle FN (data-octets)->HMAC-SHA-256 into STORE (ADR 0045),
   or clear it with NIL. No-op when the backing store has no chain seam (memory / v1 encrypted).
   The encrypted-store decorator calls this with a closure over its log-MAC key BEFORE it drives
   store-open, so the inner file store's replay verifies and its puts write the chain — the file
   store holds only the closure, never the key bytes (keyed-store-only, no key in make-file-store).
   REQUIRED (ADR 0045 §3.2, downgrade defense): when true the store EXPECTS an active chain — a
   non-empty topic log that replays to ZERO v3 frames (i.e. a full v3->v2 keyless downgrade) fails
   the open loudly, BEFORE compaction. GRANDFATHER-SET (a hash-set of topic-ids, or NIL) names the
   pre-existing legacy topics EXEMPT from that per-topic downgrade check (the authenticated set from
   the anchor) — so a legacy multi-topic v2 store migrates without a false-REJECT of its dormant
   topics; a fresh store's set is empty ⇒ every topic is chain-required. REQUIRED=NIL ⇒ no check
   (fresh/pre-chain store)."
  (let ((f (durable-store-set-chain-mac-fn store)))
    (when f (funcall f fn required grandfather-set)))
  t)

(defun* store-chain-tails (store)
    (function (durable-store) hash-table)
  "Read-only SEAL seam for the sealed high-water tail anchor (ADR 0045 §7.1): return a FRESH hash-table
   topic-id -> (N . M_N) — the current per-topic (v3-frame count . tail chain-MAC) of the backing store.
   The encrypted-store decorator seals this set at clean close so that rolling the log back to a shorter
   valid prefix later contradicts the anchor. An EMPTY table when the backing store has no chain-tails
   seam (memory / SQLite / microservice — the tail anchor is a FILE-tier feature this slice; those tiers
   are follow-on WPs). The NIL-fallback mirrors store-sync / store-set-chain-mac-fn — an additive
   read-only vtable slot, not a fork."
  (let ((f (durable-store-chain-tails-fn store)))
    (if f (funcall f) (make-hash-table :test #'equal))))

(defun* store-verify-chain-prefix (store topic-id n mac)
    (function (durable-store string (integer 0) (simple-array (unsigned-byte 8) (*)))
              (member t :truncated :diverged))
  "Read-only VERIFY seam for the tail anchor's prefix-containment (ADR 0045 §7.1). Re-walk TOPIC-ID's
   on-disk v3 chain and compare against the sealed prefix (N, MAC):
     T          — the chain reaches AT LEAST N v3 frames AND its running MAC at ordinal N == MAC (the
                  committed prefix is present + intact; it MAY extend past N = a legitimate crash-append
                  / forward extension → CLEAN, never a false-reject);
     :truncated — the chain no longer reaches N complete frames on a clean boundary (whole-tail
                  truncation / whole-topic drop [topic absent] / whole-store rollback);
     :diverged  — the chain reaches N but its running MAC differs (prefix rollback / substitution).
   An honest torn TRAILING frame (a crash mid-append) is tolerated (T) — parity with the truncate-recover
   path — so a real crash is never a false-reject. T when the backing store has no verify seam (NIL-
   fallback: the tail anchor is absent for that tier)."
  (let ((f (durable-store-verify-chain-prefix-fn store)))
    (if f (funcall f topic-id n mac) t)))

(defun* store-delete (store topic writer-guid sn)
    (function (durable-store string (simple-array (unsigned-byte 8) (16)) (integer 0))
              (or (eql t) (eql :unsupported)))
  "Physically remove the single record keyed by (TOPIC, WRITER-GUID, SN); return T on delete or
   :UNSUPPORTED when the backing store has no :delete slot (the same NIL-fallback binding as store-sync
   / store-set-chain-mac-fn — an additive vtable slot, not a fork). Per-record delete-by-PRIMARY-KEY,
   NOT evict-instance: the encrypted decorator opens its inner store keyless with a per-sample surrogate
   and knows the EXACT prior surrogate to reclaim (ADR 0025 §10.3 physical reclaim / ADR 0029 §10). A
   backend that omits the slot is byte-identical to pre-slot behavior; the decorator then falls back to
   today's logical-only compaction (superseded blobs retained until purge)."
  (let ((f (durable-store-delete store)))
    (if f (funcall f topic writer-guid sn) :unsupported)))

(defun* store-replace-topic (store topic records)
    (function (durable-store string list) (eql t))
  "Atomically REPLACE every record of TOPIC with RECORDS (a list of DURABLE-RECORD), all-or-nothing.
   The microservice server's +ms-op-topic-rewrite+ replaces a topic's opaque frames after a KEEP_LAST
   reclaim re-MACs the survivors client-side (ADR 0050 §4.4) — a partial topic would brick the re-MAC'd
   chain, so the swap must be atomic. NIL-fallback (the same additive binding as store-delete): store-purge
   then store-put each record — trivially atomic for the in-process memory store (one serialized request,
   no crash-persistence), and correct for a persistent inner too EXCEPT across a mid-swap crash (a file /
   SQLite inner SUPPLIES the :replace-topic slot for tmp+rename / transaction crash-atomicity). Returns T."
  (let ((f (durable-store-replace-topic-fn store)))
    (if f
        (funcall f topic records)
        (progn
          (store-purge store topic)
          (dolist (r records)
            (store-put store topic (durable-record-writer-guid r) (durable-record-sn r)
                       (durable-record-key-hash r) (durable-record-kind r) (durable-record-payload r)))
          t))))

;;; In-memory backing implementation.
;;; Outer table: topic (string) -> inner table.
;;; Inner table: (writer-guid-as-list . sn) -> durable-record, keyed :test #'equal.

(defun* %mem-total-count (outer)
    (function (hash-table) (integer 0))
  "Sum record counts across all topic tables in OUTER."
  (let ((n 0))
    (maphash (lambda (k v) (declare (ignore k)) (incf n (hash-table-count v))) outer)
    n))

(defun* %mem-inner (outer topic)
    (function (hash-table string) hash-table)
  "Return (or create) the per-topic inner hash table in OUTER.
   Side-effect: creates the topic table on miss — call only from a write path under the lock."
  (or (gethash topic outer)
      (setf (gethash topic outer) (make-hash-table :test #'equal))))

(defun* %mem-evict-instance (inn key-hash depth)
    (function (hash-table (simple-array (unsigned-byte 8) (16)) (integer 1)) (eql t))
  "Remove lowest-SN :data records for KEY-HASH in INN until at most DEPTH remain.
   Lifecycle (:dispose/:unregister) records are never evicted (DDS 1.4 §2.2.3.5)."
  (loop
    (let ((data-keys '()))
      (maphash (lambda (k v)
                 (when (and (eq :data (durable-record-kind v))
                            (equalp key-hash (durable-record-key-hash v)))
                   (push k data-keys)))
               inn)
      (when (<= (length data-keys) depth)
        (return t))
      ;; remove the entry with the minimum sn (cdr of the key cons is the sn)
      (let ((min-k (reduce (lambda (a b) (if (< (cdr a) (cdr b)) a b)) data-keys)))
        (remhash min-k inn))))
  t)

(defun* %mem-put (outer lock max-samples hk-cell depth-cell topic writer-guid sn key-hash kind payload)
    (function (hash-table t (integer 0) cons cons string
               (simple-array (unsigned-byte 8) (16)) (integer 0)
               (or null (simple-array (unsigned-byte 8) (16)))
               (member :data :dispose :unregister)
               (simple-array (unsigned-byte 8) (*)))
              (or (eql t) (eql :rejected)))
  "Insert or idempotently no-op a record; return :REJECTED when bounded store is full.
   When the stashed policy (HK-CELL car) is :keep-last, evicts the lowest-SN :data
   records for the inserted instance until DEPTH-CELL car records remain (DDS 1.4 §2.2.3.5)."
  (dds.pal:with-lock (lock)
    (let* ((inn (%mem-inner outer topic))
           (k   (cons (coerce writer-guid 'list) sn)))
      (cond
        ((gethash k inn) t)
        ((and (plusp max-samples) (>= (%mem-total-count outer) max-samples)) :rejected)
        (t (setf (gethash k inn)
                 (make-durable-record :topic topic :writer-guid writer-guid :sn sn
                                      :key-hash key-hash :kind kind :payload payload))
           (when (and (eq :keep-last (car hk-cell))
                      (eq :data kind)
                      key-hash)
             (%mem-evict-instance inn key-hash (car depth-cell)))
           t)))))

(defun* %guid-list< (ga gb)
    (function (list list) boolean)
  "Compare two 16-byte writer GUIDs represented as lists of (unsigned-byte 8), byte-by-byte ascending.
   Returns T iff GA is strictly less than GB in byte-sequence order."
  (loop for ba in ga
        for bb in gb
        when (/= ba bb) do (return (< ba bb))
        finally (return nil)))

(defun* %record-guid-sn< (a b)
    (function (durable-record durable-record) boolean)
  "Canonical get-range order on records: (writer-guid bytes ascending, then sn ascending).
   Shared by every backend (memory + file) so the ordering is defined once (DRY)."
  (let ((ga (coerce (durable-record-writer-guid a) 'list))
        (gb (coerce (durable-record-writer-guid b) 'list)))
    (if (equal ga gb)
        (< (durable-record-sn a) (durable-record-sn b))
        (%guid-list< ga gb))))

(defun* %mem-get-range (outer lock topic)
    (function (hash-table t string) list)
  "Collect and sort all records for TOPIC by (writer-guid bytes ascending, sn ascending)."
  (dds.pal:with-lock (lock)
    (let ((inn (gethash topic outer)))
      (if (null inn)
          '()
          (let ((recs '()))
            (maphash (lambda (k v) (declare (ignore k)) (push v recs)) inn)
            (sort recs #'%record-guid-sn<))))))

(defun* %mem-topics (outer lock)
    (function (hash-table t) list)
  "Return list of topics with at least one record."
  (dds.pal:with-lock (lock)
    (let ((ts '()))
      (maphash (lambda (topic inn)
                 (when (plusp (hash-table-count inn))
                   (push topic ts)))
               outer)
      ts)))

(defun* %mem-purge (outer lock topic)
    (function (hash-table t string) (eql t))
  "Remove all records for TOPIC."
  (dds.pal:with-lock (lock)
    (remhash topic outer)
    t))

(defun* %mem-count (outer lock topic)
    (function (hash-table t (or null string)) (integer 0))
  "Return total count or per-TOPIC count."
  (dds.pal:with-lock (lock)
    (if topic
        (let ((inn (gethash topic outer)))
          (if inn (hash-table-count inn) 0))
        (%mem-total-count outer))))

(defun* make-memory-store (&key (max-samples 0))
    (function (&key (:max-samples (integer 0))) durable-store)
  "Construct an in-memory durable-store. MAX-SAMPLES 0 means unbounded; a positive value
   caps the TOTAL record count across all topics — store-put returns :REJECTED when full.
   The effective KEEP_LAST policy is driven by store-open (the service-start channel,
   ADR 0029, DDS 1.4 §2.2.3.5); the factory default is :keep-all (no eviction)."
  (let ((outer     (make-hash-table :test #'equal))
        (lock      (dds.pal:make-lock "dds-durability-store"))
        ;; mutable stash cells: car is the live value; store-open overwrites car in-place
        (hk-cell   (cons :keep-all nil))
        (depth-cell (cons 1 nil)))
    (%make-durable-store
     :name :memory
     :put        (lambda (topic writer-guid sn key-hash kind payload)
                   (%mem-put outer lock max-samples hk-cell depth-cell
                              topic writer-guid sn key-hash kind payload))
     :get-range  (lambda (topic) (%mem-get-range outer lock topic))
     :topics     (lambda () (%mem-topics outer lock))
     :purge      (lambda (topic) (%mem-purge outer lock topic))
     :open       (lambda (history-kind history-depth)
                   ;; stash the effective policy; non-NIL args override the factory default
                   (when history-kind  (setf (car hk-cell)    history-kind))
                   (when history-depth (setf (car depth-cell) history-depth))
                   t)
     :close      (lambda () t)
     :count-fn   (lambda (topic) (%mem-count outer lock topic))
     ;; per-record physical delete (vtable uniformity): remhash the (guid-list . sn) inner key
     :delete     (lambda (topic writer-guid sn)
                   (dds.pal:with-lock (lock)
                     (let ((inn (gethash topic outer)))
                       (when inn (remhash (cons (coerce writer-guid 'list) sn) inn)))
                     t)))))
