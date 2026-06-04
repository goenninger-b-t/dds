(in-package #:dds.rtps.history)

(define-condition history-not-implemented (error)
  ((what :initarg :what :reader history-not-implemented-what))
  (:report (lambda (c s) (format s "HistoryCache not implemented (M0 stub): ~a"
                                 (history-not-implemented-what c)))))

(defstruct (cache-change (:constructor make-cache-change))
  (kind :data :type (member :data :dispose :unregister))
  (writer-guid nil)
  (sn 0 :type (integer 0))
  (instance-key-hash nil)
  (serialized-payload nil)
  (source-timestamp 0 :type integer)
  (inline-qos nil))

(defstruct (history-cache (:constructor %make-history-cache))
  (kind :keep-last :type (member :keep-last :keep-all))
  (depth 1 :type (integer 1))
  (resource-limits nil)
  (type-support nil))

(declaim (ftype (function ((member :keep-last :keep-all) (integer 1) t t) history-cache) make-history-cache))
(declaim (ftype (function (t t) t) hc-add-change))
(declaim (ftype (function (t t) t) hc-remove-change))
(declaim (ftype (function (t t) t) hc-get-change))
(declaim (ftype (function (t) t) hc-min-seq))
(declaim (ftype (function (t) t) hc-max-seq))
(declaim (ftype (function (t t) t) hc-changes-for-reader))

(defun make-history-cache (kind depth resource-limits type-support)
  "Create a HistoryCache. M0 stores the policy; M2 adds the change store + state."
  (%make-history-cache :kind kind :depth depth
                       :resource-limits resource-limits
                       :type-support type-support))

(defun hc-add-change (hc change)
  (declare (ignore hc change))
  (error 'history-not-implemented :what "hc-add-change (awaiting M2)"))
(defun hc-remove-change (hc seqnum)
  (declare (ignore hc seqnum))
  (error 'history-not-implemented :what "hc-remove-change (awaiting M2)"))
(defun hc-get-change (hc seqnum)
  (declare (ignore hc seqnum))
  (error 'history-not-implemented :what "hc-get-change (awaiting M2)"))
(defun hc-min-seq (hc) (declare (ignore hc))
  (error 'history-not-implemented :what "hc-min-seq (awaiting M2)"))
(defun hc-max-seq (hc) (declare (ignore hc))
  (error 'history-not-implemented :what "hc-max-seq (awaiting M2)"))
(defun hc-changes-for-reader (hc reader-proxy)
  (declare (ignore hc reader-proxy))
  (error 'history-not-implemented :what "hc-changes-for-reader (awaiting M2)"))
