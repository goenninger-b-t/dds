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
   network order + 2-octet representation_options, then reset the CDR alignment origin
   to the byte after it (RTPS 2.5 §10.2). OPTIONS defaults to 0; for an XCDR2 payload
   the low 2 bits of the second options byte are BACKPATCHED by
   finalize-encapsulation-options once the body length is known (DDS-XTypes 1.3
   §7.6.3.1.2). REPRESENTATION is a key of +representation-ids+."
  (let ((id (representation-id-value representation)))
    (dds.core.buffer:put-u8 cursor (ldb (byte 8 8) id))
    (dds.core.buffer:put-u8 cursor (ldb (byte 8 0) id))
    (dds.core.buffer:put-u8 cursor (ldb (byte 8 8) options))
    (dds.core.buffer:put-u8 cursor (ldb (byte 8 0) options))
    (dds.core.buffer:cursor-set-origin cursor)
    cursor))

(defun* finalize-encapsulation-options (cursor representation)
    (function (dds.core.buffer:cursor symbol) dds.core.buffer:cursor)
  "Backpatch the encapsulation options pad bits after the body is serialized: set the
   low 2 bits of the second options byte (buffer offset 3) to the number of pad bytes
   (0..3) the serialized payload needs to reach the next 4-byte boundary, so the receiver
   can find the exact payload end (DDS-XTypes 1.3 §7.6.3.1.2: 'shall set the least
   significant two bits in the second byte of the options field to ... the number of
   padding bytes needed'). The clause is universal — its normative example sets the bits
   on PLAIN_CDR (XCDR1) — so this applies to ALL CDR representations, not only XCDR2; only
   the non-CDR XML representation is skipped. Assumes the header occupies buffer offsets
   0..3 and the body starts at offset 4. Hot path: allocation-free one-octet in-place patch."
  (unless (eq representation :xml)
    (let* ((body-len (- (dds.core.buffer:cursor-position cursor) 4))
           (pad (mod (- 4 (mod body-len 4)) 4))
           (vec (dds.core.buffer:octet-buffer-vec (dds.core.buffer:cursor-buffer cursor))))
      (setf (aref vec 3) (logior (logandc2 (aref vec 3) 3) pad))))
  cursor)

(defun* parse-encapsulation-header (cursor)
    (function (dds.core.buffer:cursor) (values t integer (integer 0 3)))
  "Read and validate the 4-octet SerializedPayloadHeader; reset the CDR alignment
   origin past it (RTPS 2.5 §10.2). Return (values representation-keyword options pad),
   where PAD is the trailing-padding count carried in the low 2 bits of the second
   options byte (DDS-XTypes 1.3 §7.6.3.1.2 — the receiver SHALL interpret these bits to
   determine where the serialized data exactly ended). A non-zero options value from a
   conformant peer is tolerated, never rejected. Bounds-checked at the boundary
   (NFR-SEC-POSTURE)."
  (let* ((id-hi (dds.core.buffer:get-u8 cursor))
         (id-lo (dds.core.buffer:get-u8 cursor))
         (opt-hi (dds.core.buffer:get-u8 cursor))
         (opt-lo (dds.core.buffer:get-u8 cursor))
         (id (logior (ash id-hi 8) id-lo))
         (options (logior (ash opt-hi 8) opt-lo))
         (pad (logand opt-lo 3))
         (name (representation-id-name id)))
    (unless name
      (error 'cdr-not-implemented
             :what (format nil "unknown representation id #x~4,'0x" id)))
    (dds.core.buffer:cursor-set-origin cursor)
    (values name options pad)))
