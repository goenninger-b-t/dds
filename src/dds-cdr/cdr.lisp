(in-package #:dds.cdr)

(define-condition cdr-not-implemented (error)
  ((what :initarg :what :reader cdr-not-implemented-what))
  (:report (lambda (c s) (format s "CDR codec error: ~a"
                                 (cdr-not-implemented-what c)))))

(deftype extensibility-kind () '(member :final :appendable :mutable))

(defparameter +representation-ids+
  '((:plain-cdr-be     . #x0000)
    (:plain-cdr-le     . #x0001)
    (:pl-cdr-be        . #x0002)
    (:pl-cdr-le        . #x0003)
    (:plain-cdr2-be    . #x0010)
    (:plain-cdr2-le    . #x0011)
    (:pl-cdr2-be       . #x0012)
    (:pl-cdr2-le       . #x0013)
    (:delimited-cdr-be . #x0014)
    (:delimited-cdr-le . #x0015)
    (:xml              . #x0100))
  "Encapsulation representation identifiers (name . 16-bit value). Source: XTypes
   1.3 §7.4.3.4 Table 39 (ENC_HEADER); cross-checked vs RTPS 2.5 §10.3 Table 10.1.
   Pinned from the in-repo normative specs (docs/specs), never from memory.")

(declaim (ftype (function (symbol) t) representation-id-value))
(declaim (ftype (function (integer) t) representation-id-name))
(declaim (ftype (function (dds.core.buffer:cursor symbol &optional integer) dds.core.buffer:cursor) make-encapsulation-header))
(declaim (ftype (function (dds.core.buffer:cursor) (values t integer)) parse-encapsulation-header))

(defun representation-id-value (name)
  "16-bit wire value for representation NAME (XTypes 1.3 §7.4.3.4 Table 39)."
  (or (cdr (assoc name +representation-ids+))
      (error 'cdr-not-implemented :what (format nil "unknown representation ~s" name))))

(defun representation-id-name (value)
  "Inverse of representation-id-value, or NIL if VALUE is unrecognised."
  (car (rassoc value +representation-ids+)))

(defun make-encapsulation-header (cursor representation &optional (options 0))
  "Write the 4-octet SerializedPayloadHeader: 2-octet representation_identifier in
   network order + 2-octet representation_options (RTPS 2.5 §10.2; sender sets
   options to 0 per §10.2/§10.3), then reset the CDR alignment origin to the byte
   after it (RTPS 2.5 §10.2). REPRESENTATION is a key of +representation-ids+."
  (let ((id (representation-id-value representation)))
    (dds.core.buffer:put-u8 cursor (ldb (byte 8 8) id))
    (dds.core.buffer:put-u8 cursor (ldb (byte 8 0) id))
    (dds.core.buffer:put-u8 cursor (ldb (byte 8 8) options))
    (dds.core.buffer:put-u8 cursor (ldb (byte 8 0) options))
    (dds.core.buffer:cursor-set-origin cursor)
    cursor))

(defun parse-encapsulation-header (cursor)
  "Read and validate the 4-octet SerializedPayloadHeader; reset the CDR alignment
   origin past it (RTPS 2.5 §10.2). Return (values representation-keyword options).
   Bounds-checked at the boundary (NFR-SEC-POSTURE)."
  (let* ((id-hi (dds.core.buffer:get-u8 cursor))
         (id-lo (dds.core.buffer:get-u8 cursor))
         (opt-hi (dds.core.buffer:get-u8 cursor))
         (opt-lo (dds.core.buffer:get-u8 cursor))
         (id (logior (ash id-hi 8) id-lo))
         (options (logior (ash opt-hi 8) opt-lo))
         (name (representation-id-name id)))
    (unless name
      (error 'cdr-not-implemented
             :what (format nil "unknown representation id #x~4,'0x" id)))
    (dds.core.buffer:cursor-set-origin cursor)
    (values name options)))
