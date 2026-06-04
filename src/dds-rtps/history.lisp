(in-package #:dds.rtps.history)

(define-condition history-not-implemented (error)
  ((what :initarg :what :reader history-not-implemented-what))
  (:report (lambda (c s) (format s "HistoryCache: ~a" (history-not-implemented-what c)))))

(defstruct (cache-change (:constructor make-cache-change))
  (kind :data :type (member :data :dispose :unregister))
  (writer-guid nil)
  (sn 0 :type (integer 0))
  (instance-key-hash nil)
  (serialized-payload nil)
  (source-timestamp 0 :type integer)
  (inline-qos nil))

;;;; HistoryCache (FR-RTPS-5): a change store honouring HISTORY (KEEP_LAST depth /
;;;; KEEP_ALL) and RESOURCE_LIMITS (max_samples). v1 keys changes by sequence
;;;; number in a hash-table; a pooled, zero-alloc store + non-consing iteration,
;;;; per-instance KEEP_LAST, and LIFESPAN expiry are tracked follow-ups.

(defstruct (history-cache (:constructor %make-history-cache))
  (kind :keep-last :type (member :keep-last :keep-all))
  (depth 1 :type (integer 1))
  (max-samples nil)                                  ; resource limit; nil = unlimited
  (type-support nil)
  (changes (make-hash-table :test 'eql) :type hash-table)
  (count 0 :type (integer 0)))

(declaim (ftype (function (t) t) %resolve-max-samples))
(defun %resolve-max-samples (resource-limits)
  "Extract a max_samples integer from RESOURCE-LIMITS (an integer, a plist with
   :max-samples, or NIL = unlimited)."
  (cond ((integerp resource-limits) resource-limits)
        ((consp resource-limits) (getf resource-limits :max-samples))
        (t nil)))

(declaim (ftype (function ((member :keep-last :keep-all) (integer 1) t t) history-cache) make-history-cache))
(defun make-history-cache (kind depth resource-limits type-support)
  "Create a HistoryCache with HISTORY (KIND/DEPTH) and RESOURCE_LIMITS."
  (%make-history-cache :kind kind :depth depth
                       :max-samples (%resolve-max-samples resource-limits)
                       :type-support type-support))

(declaim (ftype (function (history-cache) (integer 0)) hc-change-count))
(defun hc-change-count (hc) (history-cache-count hc))

(declaim (ftype (function (history-cache integer) t) hc-get-change))
(defun hc-get-change (hc seqnum)
  "Return the CacheChange with SEQNUM, or NIL."
  (values (gethash seqnum (history-cache-changes hc))))

(declaim (ftype (function (history-cache integer) t) hc-remove-change))
(defun hc-remove-change (hc seqnum)
  "Remove the change with SEQNUM; return T if one was present."
  (when (remhash seqnum (history-cache-changes hc))
    (decf (history-cache-count hc))
    t))

(declaim (ftype (function (history-cache) t) hc-min-seq))
(defun hc-min-seq (hc)
  "Lowest sequence number present, or NIL if empty."
  (let ((min nil))
    (maphash (lambda (sn ch) (declare (ignore ch))
               (when (or (null min) (< sn min)) (setf min sn)))
             (history-cache-changes hc))
    min))

(declaim (ftype (function (history-cache) t) hc-max-seq))
(defun hc-max-seq (hc)
  "Highest sequence number present, or NIL if empty."
  (let ((max nil))
    (maphash (lambda (sn ch) (declare (ignore ch))
               (when (or (null max) (> sn max)) (setf max sn)))
             (history-cache-changes hc))
    max))

(declaim (ftype (function (history-cache integer cache-change) (integer 0)) %hc-store))
(defun %hc-store (hc sn change)
  (setf (gethash sn (history-cache-changes hc)) change)
  (incf (history-cache-count hc)))

(declaim (ftype (function (history-cache) t) %hc-evict-oldest))
(defun %hc-evict-oldest (hc)
  (let ((min (hc-min-seq hc)))
    (when min (hc-remove-change hc min))))

(declaim (ftype (function (history-cache cache-change) symbol) hc-add-change))
(defun hc-add-change (hc change)
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

(declaim (ftype (function (history-cache t) list) hc-changes-for-reader))
(defun hc-changes-for-reader (hc reader-proxy)
  "Return the cache changes in ascending SN order. v1 ignores READER-PROXY; the
   per-reader changes-for-reader filtering lives in the reliable writer."
  (declare (ignore reader-proxy))
  (let ((changes '()))
    (maphash (lambda (sn ch) (declare (ignore sn)) (push ch changes))
             (history-cache-changes hc))
    (sort changes #'< :key #'cache-change-sn)))
