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
;;;; number in a hash-table; a pooled, zero-alloc store + non-consing iteration,
;;;; per-instance KEEP_LAST, and LIFESPAN expiry are tracked follow-ups.

(defstruct* (history-cache (:constructor %make-history-cache))
  "A HistoryCache (FR-RTPS-5): a change store honouring HISTORY (KIND :keep-last with
   DEPTH / :keep-all) and RESOURCE_LIMITS (MAX-SAMPLES; nil = unlimited). v1 keys
   changes by sequence number in a hash-table. Build via MAKE-HISTORY-CACHE."
  (kind :keep-last :type (member :keep-last :keep-all))
  (depth 1 :type (integer 1))
  (max-samples nil :type (or null (integer 0)))                                  ; resource limit; nil = unlimited
  (type-support nil :type (or null dds.types:type-support))
  (changes (make-hash-table :test 'eql) :type hash-table)
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

(defun* hc-get-change (hc seqnum)
    (function (history-cache integer) t)
  "Return the CacheChange with SEQNUM, or NIL."
  (values (gethash seqnum (history-cache-changes hc))))

(defun* hc-remove-change (hc seqnum)
    (function (history-cache integer) t)
  "Remove the change with SEQNUM; return T if one was present."
  (when (remhash seqnum (history-cache-changes hc))
    (decf (history-cache-count hc))
    t))

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
  "Insert CHANGE under sequence number SN into the history cache's change table, bumping its count; returns the new count."
  (setf (gethash sn (history-cache-changes hc)) change)
  (incf (history-cache-count hc)))

(defun* %hc-evict-oldest (hc)
    (function (history-cache) t)
  "Remove the lowest-sequence-number change from the history cache (KEEP_LAST eviction); no-op if empty."
  (let ((min (hc-min-seq hc)))
    (when min (hc-remove-change hc min))))

(defun* hc-add-change (hc change)
    (function (history-cache cache-change) symbol)
  "Add CHANGE, enforcing HISTORY + RESOURCE_LIMITS (FR-RTPS-5). Returns :OK,
   :DUPLICATE (SN already present), or :REJECTED-RESOURCE-LIMITS (KEEP_ALL at
   max_samples). KEEP_LAST evicts the lowest SN when at depth."
  (let ((sn (cache-change-sn change)))
    (cond
      ((nth-value 1 (gethash sn (history-cache-changes hc))) :duplicate)
      ((eq (history-cache-kind hc) :keep-last)
       (when (>= (history-cache-count hc) (history-cache-depth hc))
         (%hc-evict-oldest hc))
       (%hc-store hc sn change)
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
