(in-package #:dds.rtps.history)

(define-condition history-not-implemented (error)
  ((what :initarg :what :reader history-not-implemented-what))
  (:report (lambda (c s) (format s "HistoryCache: ~a" (history-not-implemented-what c)))))

(defstruct* (cache-change (:constructor make-cache-change))
  "An RTPS CacheChange (IMPLEMENTATION-PLAN §7.4): the pooled per-sample record held
   in a HistoryCache — change KIND (:data/:dispose/:unregister), writer GUID,
   sequence number, instance key hash, serialized payload, STATUS-INFO flags
   (StatusInfo_t for a dispose/unregister, RTPS 2.5 §9.6.4.9), source timestamp,
   and inline QoS."
  (kind :data :type (member :data :dispose :unregister))
  (writer-guid nil :type (or null (array (unsigned-byte 8) (*))))
  (sn 0 :type (integer 0))
  (instance-key-hash nil :type (or null (array (unsigned-byte 8) (*))))
  (serialized-payload nil :type (or null (array (unsigned-byte 8) (*))))  ; SerializedPayload octets
  (status-info 0 :type (unsigned-byte 8))                                 ; StatusInfo_t flags (RTPS 2.5 §9.6.4.9)
  (source-timestamp 0 :type integer)
  (inline-qos nil :type (or null (array (unsigned-byte 8) (*)))))         ; serialized inline-QoS ParameterList

;;;; HistoryCache (FR-RTPS-5): a change store honouring HISTORY (KEEP_LAST depth /
;;;; KEEP_ALL) and RESOURCE_LIMITS (max_samples). v1 keys changes by sequence
;;;; number in a hash-table; a secondary keyhash->SN index applies KEEP_LAST depth
;;;; PER INSTANCE (DDS 1.4 §2.2.3.18). A pooled, zero-alloc store + non-consing
;;;; iteration and LIFESPAN expiry are tracked follow-ups.

(defstruct* (history-cache (:constructor %make-history-cache))
  "A HistoryCache (FR-RTPS-5): a change store honouring HISTORY (KIND :keep-last with
   DEPTH / :keep-all) and RESOURCE_LIMITS (MAX-SAMPLES; nil = unlimited). CHANGES keys
   changes by sequence number; INSTANCES is the per-instance KEEP_LAST index — instance
   keyhash (EQUALP) -> that instance's stored SNs oldest-first (DDS 1.4 §2.2.3.18: KEEP_LAST
   keeps the last DEPTH values per instance). A NIL / HANDLE_NIL keyhash collapses to one
   shared bucket (global KEEP_LAST). The index is maintained for KEEP_LAST ONLY (its sole
   consumer is per-instance eviction); a KEEP_ALL cache keeps it empty (an O(1) change-table
   insert, never evicted per-instance). Build via MAKE-HISTORY-CACHE."
  (kind :keep-last :type (member :keep-last :keep-all))
  (depth 1 :type (integer 1))
  (max-samples nil :type (or null (integer 0)))                                  ; resource limit; nil = unlimited
  (type-support nil :type (or null dds.types:type-support))
  (changes (make-hash-table :test 'eql) :type hash-table)
  (instances (make-hash-table :test 'equalp) :type hash-table)                   ; keyhash -> SNs oldest-first (per-instance KEEP_LAST, §2.2.3.18)
  (count 0 :type (integer 0)))

(defun* %resolve-max-samples (resource-limits)
    (function (t) t)
  "Extract a max_samples integer from RESOURCE-LIMITS (an integer, a plist with
   :max-samples, or NIL = unlimited)."
  (cond ((integerp resource-limits) resource-limits)
        ((consp resource-limits) (getf resource-limits :max-samples))
        (t nil)))

(defun* make-history-cache (kind depth resource-limits type-support)
    (function ((member :keep-last :keep-all) (integer 1) t t) history-cache)
  "Create a HistoryCache with HISTORY (KIND/DEPTH) and RESOURCE_LIMITS."
  (%make-history-cache :kind kind :depth depth
                       :max-samples (%resolve-max-samples resource-limits)
                       :type-support type-support))

(defun* hc-change-count (hc)
    (function (history-cache) (integer 0))
  "The number of changes currently stored in the HistoryCache HC."
  (history-cache-count hc))

(defun* hc-kind (hc)
    (function (history-cache) (member :keep-last :keep-all))
  "The HISTORY kind of the HistoryCache HC (:keep-last or :keep-all). Read by the reliable writer's
   backpressure path to decide whether the cache is bound by max_samples (KEEP_ALL, ADR 0016 §Backpressure)."
  (history-cache-kind hc))

(defun* hc-max-samples (hc)
    (function (history-cache) (or null (integer 0)))
  "The RESOURCE_LIMITS max_samples bound of the HistoryCache HC (NIL = unlimited). Read by the reliable
   writer's block-up-to-max_blocking_time backpressure path (ADR 0016 §Backpressure)."
  (history-cache-max-samples hc))

(defun* hc-get-change (hc seqnum)
    (function (history-cache integer) t)
  "Return the CacheChange with SEQNUM, or NIL."
  (values (gethash seqnum (history-cache-changes hc))))

(defun* %hc-bucket-key (key-hash)
    (function (t) t)
  "The per-instance index bucket key for a change's INSTANCE-KEY-HASH. A NIL or all-zero
   HANDLE_NIL collapses to one canonical :UNKEYED bucket (the single-instance/global KEEP_LAST
   case, DDS 1.4 §2.2.3.18); any other 16-octet handle is its own bucket (EQUALP-compared)."
  (if (or (null key-hash) (every #'zerop key-hash)) :unkeyed key-hash))

(defun* %hc-index-append (hc sn change)
    (function (history-cache integer cache-change) t)
  "Append SN to its instance bucket tail (SNs arrive monotonically per writer, so the bucket
   stays oldest-first) in the per-instance KEEP_LAST index (DDS 1.4 §2.2.3.18). KEEP_LAST-ONLY:
   the index serves per-instance eviction, which only KEEP_LAST performs; a KEEP_ALL cache never
   evicts per-instance, so it keeps NO index — an O(1) change-table insert, unchanged from pre-WP
   (a KEEP_ALL bucket would otherwise grow unbounded and the tail-append would be O(N) = O(N²) total).
   The append walks the bucket tail, which under KEEP_LAST is bounded by DEPTH (O(depth))."
  (when (eq (history-cache-kind hc) :keep-last)
    (let ((key (%hc-bucket-key (cache-change-instance-key-hash change))))
      (setf (gethash key (history-cache-instances hc))
            (nconc (gethash key (history-cache-instances hc)) (list sn)))))
  t)

(defun* %hc-index-drop (hc sn change)
    (function (history-cache integer cache-change) t)
  "Drop SN from its instance bucket in the per-instance index; remove the bucket when it empties
   so a re-created instance starts fresh (no orphaned SN inflating a later depth check). KEEP_LAST-ONLY
   (mirrors %hc-index-append): a KEEP_ALL cache keeps no index, so its purge/dispose removals never
   touch it (an O(1) change-table-only removal, unchanged from pre-WP)."
  (when (eq (history-cache-kind hc) :keep-last)
    (let* ((key (%hc-bucket-key (cache-change-instance-key-hash change)))
           (rest (delete sn (gethash key (history-cache-instances hc)))))
      (if rest
          (setf (gethash key (history-cache-instances hc)) rest)
          (remhash key (history-cache-instances hc)))))
  t)

(defun* %hc-remove-change (hc seqnum)
    (function (history-cache integer) t)
  "The single change-removal path: drop SEQNUM from BOTH the change table and its per-instance
   index bucket, decrementing the count, so the two never drift (ADR 0019). Return T if one was
   present. Used by KEEP_LAST eviction, the full-ACK purge (writer-purge-acked), and dispose."
  (let ((change (gethash seqnum (history-cache-changes hc))))
    (when change
      (remhash seqnum (history-cache-changes hc))
      (%hc-index-drop hc seqnum change)
      (decf (history-cache-count hc))
      t)))

(defun* hc-remove-change (hc seqnum)
    (function (history-cache integer) t)
  "Remove the change with SEQNUM; return T if one was present. Routes through %HC-REMOVE-CHANGE so
   the per-instance index stays consistent with the change table (ADR 0019)."
  (%hc-remove-change hc seqnum))

(defun* hc-purge-below (hc base)
    (function (history-cache integer) (integer 0))
  "Remove every change with SN < BASE (fully acknowledged + done); return the number removed. O(stored),
   no sort — bounds a KEEP_ALL writer history once all matched readers have ACKed past BASE (RTPS 2.5
   §8.4.1). Routes each removal through %HC-REMOVE-CHANGE so the per-instance index stays consistent (ADR
   0019). The HEARTBEAT firstSN (hc-min-seq) then advances past the purged range."
  (let ((removed '()))
    (maphash (lambda (sn ch) (declare (ignore ch)) (when (< sn base) (push sn removed)))
             (history-cache-changes hc))
    (dolist (sn removed (length removed))
      (%hc-remove-change hc sn))))

(defun* hc-min-seq (hc)
    (function (history-cache) t)
  "Lowest sequence number present, or NIL if empty."
  (let ((min nil))
    (maphash (lambda (sn ch) (declare (ignore ch))
               (when (or (null min) (< sn min)) (setf min sn)))
             (history-cache-changes hc))
    min))

(defun* hc-max-seq (hc)
    (function (history-cache) t)
  "Highest sequence number present, or NIL if empty."
  (let ((max nil))
    (maphash (lambda (sn ch) (declare (ignore ch))
               (when (or (null max) (> sn max)) (setf max sn)))
             (history-cache-changes hc))
    max))

(defun* %hc-store (hc sn change)
    (function (history-cache integer cache-change) (integer 0))
  "Insert CHANGE under sequence number SN into the change table, bumping the count, and append SN to
   its per-instance index bucket (KEEP_LAST only — %hc-index-append no-ops for KEEP_ALL); returns
   the new count."
  (setf (gethash sn (history-cache-changes hc)) change)
  (%hc-index-append hc sn change)
  (incf (history-cache-count hc)))

(defun* hc-add-change (hc change)
    (function (history-cache cache-change) symbol)
  "Add CHANGE, enforcing HISTORY + RESOURCE_LIMITS (FR-RTPS-5). Returns :OK,
   :DUPLICATE (SN already present), or :REJECTED-RESOURCE-LIMITS (KEEP_ALL at
   max_samples). KEEP_LAST keeps the last DEPTH values PER INSTANCE (DDS 1.4 §2.2.3.18):
   when CHANGE's instance is at depth, its OWN oldest SN is evicted (a NIL/HANDLE_NIL
   keyhash collapses to one bucket = global KEEP_LAST)."
  (let ((sn (cache-change-sn change)))
    (cond
      ((nth-value 1 (gethash sn (history-cache-changes hc))) :duplicate)
      ((eq (history-cache-kind hc) :keep-last)
       (%hc-store hc sn change)
       (let ((bucket (gethash (%hc-bucket-key (cache-change-instance-key-hash change))
                              (history-cache-instances hc))))
         (when (> (length bucket) (history-cache-depth hc))
           (%hc-remove-change hc (first bucket))))               ; evict this instance's oldest, not the global oldest
       :ok)
      (t
       (if (and (history-cache-max-samples hc)
                (>= (history-cache-count hc) (history-cache-max-samples hc)))
           :rejected-resource-limits
           (progn (%hc-store hc sn change) :ok))))))

(defun* hc-changes-for-reader (hc reader-proxy)
    (function (history-cache t) list)
  "Return the cache changes in ascending SN order. v1 ignores READER-PROXY; the
   per-reader changes-for-reader filtering lives in the reliable writer."
  (declare (ignore reader-proxy))
  (let ((changes '()))
    (maphash (lambda (sn ch) (declare (ignore sn)) (push ch changes))
             (history-cache-changes hc))
    (sort changes #'< :key #'cache-change-sn)))
