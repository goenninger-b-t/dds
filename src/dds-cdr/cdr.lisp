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
    (:xml              . #x0004)
    (:plain-cdr2-be    . #x0006)
    (:plain-cdr2-le    . #x0007)
    (:delimited-cdr-be . #x0008)
    (:delimited-cdr-le . #x0009)
    (:pl-cdr2-be       . #x000a)
    (:pl-cdr2-le       . #x000b))
  "Encapsulation representation identifiers (name . 16-bit value). Source: the
   NORMATIVE DDS-XTypes 1.3 Table 60 'RTPS encapsulation identifier' (§7.6), the
   on-the-wire values. The §7.4 ENC_HEADER illustration lists the XCDR2 kinds as
   0x10-0x15; that is a non-normative INCONSISTENCY in the spec — Table 60 (CDR2
   0x06/0x07, D_CDR2 0x08/0x09, PL_CDR2 0x0a/0x0b, XML 0x04) is what every DDS wire
   uses, confirmed against the Wireshark RTPS dissector. See docs/provenance.md.")


(defun* representation-id-value (name)
    (function (symbol) t)
  "16-bit wire value for representation NAME (XTypes 1.3 §7.6 Table 60)."
  (or (cdr (assoc name +representation-ids+))
      (error 'cdr-not-implemented :what (format nil "unknown representation ~s" name))))

(defun* representation-id-name (value)
    (function (integer) t)
  "Inverse of representation-id-value, or NIL if VALUE is unrecognised."
  (car (rassoc value +representation-ids+)))

(defun* make-encapsulation-header (cursor representation &optional (options 0))
    (function (dds.core.buffer:cursor symbol &optional integer) dds.core.buffer:cursor)
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

(defun* parse-encapsulation-header (cursor)
    (function (dds.core.buffer:cursor) (values t integer))
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
