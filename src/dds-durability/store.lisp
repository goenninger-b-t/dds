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
  (count-fn   nil     :type (or null function)))

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

(defun* store-open (store)
    (function (durable-store) (eql t))
  "Open (initialise) the backing store. No-op for the in-memory implementation. Returns T."
  (funcall (durable-store-open store)))

(defun* store-close (store)
    (function (durable-store) (eql t))
  "Close the backing store and release resources. No-op for the in-memory implementation. Returns T."
  (funcall (durable-store-close store)))

(defun* store-count (store &optional topic)
    (function (durable-store &optional (or null string)) (integer 0))
  "Return the total record count across all topics, or the per-TOPIC count if TOPIC is supplied."
  (funcall (durable-store-count-fn store) topic))

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

(defun* %mem-put (outer lock max-samples topic writer-guid sn key-hash kind payload)
    (function (hash-table t (integer 0) string
               (simple-array (unsigned-byte 8) (16)) (integer 0)
               (or null (simple-array (unsigned-byte 8) (16)))
               (member :data :dispose :unregister)
               (simple-array (unsigned-byte 8) (*)))
              (or (eql t) (eql :rejected)))
  "Insert or idempotently no-op a record; return :REJECTED when bounded store is full."
  (dds.pal:with-lock (lock)
    (let* ((inn (%mem-inner outer topic))
           (k   (cons (coerce writer-guid 'list) sn)))
      (cond
        ((gethash k inn) t)
        ((and (plusp max-samples) (>= (%mem-total-count outer) max-samples)) :rejected)
        (t (setf (gethash k inn)
                 (make-durable-record :topic topic :writer-guid writer-guid :sn sn
                                      :key-hash key-hash :kind kind :payload payload))
           t)))))

(defun* %guid-list< (ga gb)
    (function (list list) boolean)
  "Compare two 16-byte writer GUIDs represented as lists of (unsigned-byte 8), byte-by-byte ascending.
   Returns T iff GA is strictly less than GB in byte-sequence order."
  (loop for ba in ga
        for bb in gb
        when (/= ba bb) do (return (< ba bb))
        finally (return nil)))

(defun* %mem-get-range (outer lock topic)
    (function (hash-table t string) list)
  "Collect and sort all records for TOPIC by (writer-guid bytes ascending, sn ascending)."
  (dds.pal:with-lock (lock)
    (let ((inn (gethash topic outer)))
      (if (null inn)
          '()
          (let ((recs '()))
            (maphash (lambda (k v) (declare (ignore k)) (push v recs)) inn)
            (sort recs (lambda (a b)
                         (let ((ga (coerce (durable-record-writer-guid a) 'list))
                               (gb (coerce (durable-record-writer-guid b) 'list)))
                           (if (equal ga gb)
                               (< (durable-record-sn a) (durable-record-sn b))
                               (%guid-list< ga gb))))))))))

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
   caps the TOTAL record count across all topics — store-put returns :REJECTED when full."
  (let ((outer (make-hash-table :test #'equal))
        (lock  (dds.pal:make-lock "dds-durability-store")))
    (%make-durable-store
     :name :memory
     :put        (lambda (topic writer-guid sn key-hash kind payload)
                   (%mem-put outer lock max-samples topic writer-guid sn key-hash kind payload))
     :get-range  (lambda (topic) (%mem-get-range outer lock topic))
     :topics     (lambda () (%mem-topics outer lock))
     :purge      (lambda (topic) (%mem-purge outer lock topic))
     :open       (lambda () t)
     :close      (lambda () t)
     :count-fn   (lambda (topic) (%mem-count outer lock topic)))))
