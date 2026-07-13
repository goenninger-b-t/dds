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
      (error 'cdr-not-implemented :what (format nil "unknown representation ~s" name))))   ; HOTPATH-ALLOC(ERROR-PATH): only on the way to signalling

(defun* representation-id-name (value)
    (function (integer) t)
  "Inverse of representation-id-value, or NIL if VALUE is unrecognised."
  (car (rassoc value +representation-ids+)))

;;;; NOT cleared for ship — pending counsel (R6); see ADR 0015.
(defun* flatdata-rx-rep-plan (id)
    (function ((unsigned-byte 16)) (values (member :native :transcode :reject)
                                           (or null cdr-mode) (or null (member :little :big))))
  "Classify a 16-bit SerializedPayload representation ID (NBO, as read from vec[0..1]) for a FINAL fixed-size
   FlatData reader's RX (WP-FLATDATA-XCDR-TRANSCODE, FR-PF-4). Returns (values KIND MODE ENDIANNESS) where the
   IDs are PINNED from +representation-ids+ (DDS-XTypes 1.3 §7.6.3.1.2 Table 60), NOT hardcoded from memory:
   PLAIN_CDR2_LE -> (:native nil nil) = read-in-place (0-copy, the canonical buffer); PLAIN_CDR2_BE ->
   (:transcode :xcdr2 :big), PLAIN_CDR_BE -> (:transcode :xcdr1 :big), PLAIN_CDR_LE -> (:transcode :xcdr1
   :little) = decode-via-struct-codec then re-write canonical XCDR2-LE; anything else (PL_CDR(2)/DELIMITED/XML)
   -> (:reject nil nil) — a FINAL fixed-size FlatData type is PLAIN-encapsulated, so these are unexpected.
   NOT cleared for ship — pending counsel (R6)."
  (cond
    ((= id (representation-id-value :plain-cdr2-le)) (values :native    nil    nil))
    ((= id (representation-id-value :plain-cdr2-be)) (values :transcode :xcdr2 :big))
    ((= id (representation-id-value :plain-cdr-be))  (values :transcode :xcdr1 :big))
    ((= id (representation-id-value :plain-cdr-le))  (values :transcode :xcdr1 :little))
    (t (values :reject nil nil))))

;;;; NOT cleared for ship — pending counsel (R6); see ADR 0014.
(defconstant +zc-encapsulation-id+ #x4B43
  "Vendor SerializedPayload encapsulation id for a WP-ZEROCOPY 16-byte reference (ADR 0014; ours, NOT a
   spec clause). A reader without ZC sees an unknown representation id and ignores the sample (fail-open).
   NOT cleared for ship — pending counsel (R6).")

(defconstant +zc-ref-overlay-secured+ 1
  "WP-SECURITY-ZC-SHMEM-OVERLAY (ADR 0051): the value placed in the WP-ZEROCOPY reference datagram's
   reserved u32 (encode-zc-reference / parse-zc-reference) when the referenced SHMEM slot holds a
   data_protection SecuredPayload (ENCRYPT-tier overlay) rather than a raw serialized payload. 0 = raw
   (the default, byte-identical to the pre-overlay reference). This is a LOCAL transport discriminator in
   our own ZC reference format (+zc-encapsulation-id+, ADR 0014 — ours, not an OMG clause); it rides INSIDE
   the rtps/metadata wrap so a co-resident SHMEM attacker cannot flip it.")

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
   0..3 and the body starts at offset 4. Hot path: allocation-free.

   THE PADDING BYTES ARE PART OF THE SERIALIZED PAYLOAD AND MUST BE EMITTED. This wrote the pad COUNT into
   the options bits but never appended the pad BYTES, so we advertised 'N bytes of trailing padding' and then
   sent a payload that did not contain them. A conformant receiver derives the data end as
   (payload_length - pad) — RTI Connext does — and therefore read SHORT by exactly N octets, so EVERY sample
   whose body length was not a multiple of 4 was malformed on the wire. Our own reader ignores the bits and
   is driven by the members, so the defect was invisible in-process: unit tests and ours<->ours echo passed
   at every length. It surfaced only against a foreign vendor — live Connext interop failed for EVERY payload
   length not a multiple of 4 (len mod 4 in {1,2,3}) and passed for every multiple of 4. THE WIRE IS THE
   ORACLE (operating contract §4)."
  (unless (eq representation :xml)
    (let* ((body-len (- (dds.core.buffer:cursor-position cursor) 4))
           (pad (mod (- 4 (mod body-len 4)) 4))
           (vec (dds.core.buffer:octet-buffer-vec (dds.core.buffer:cursor-buffer cursor))))
      (setf (aref vec 3) (logior (logandc2 (aref vec 3) 3) pad))
      (dotimes (i pad) (dds.core.buffer:put-u8 cursor 0))))   ; emit the pad octets the options bits promise
  cursor)

(defun* encode-zc-reference (cursor slot-index generation slot-bytes &optional (overlay 0))
    (function (dds.core.buffer:cursor (unsigned-byte 32) (unsigned-byte 32) (unsigned-byte 32)
              &optional (unsigned-byte 32)) t)
  "Write a 20-octet WP-ZEROCOPY SerializedPayload: +zc-encapsulation-id+ in NBO (hi, lo), options=0 (hi, lo),
   then slot-index, generation, slot-bytes, OVERLAY as LE u32s (ADR 0014). OVERLAY (default 0) is the reserved
   field: 0 = raw payload, +zc-ref-overlay-secured+ = the slot holds a data_protection SecuredPayload overlay
   (ADR 0051)."
  ;; encap id in NBO byte-by-byte, matching make-encapsulation-header convention
  (dds.core.buffer:put-u8 cursor (ldb (byte 8 8) +zc-encapsulation-id+))
  (dds.core.buffer:put-u8 cursor (ldb (byte 8 0) +zc-encapsulation-id+))
  (dds.core.buffer:put-u8 cursor 0)
  (dds.core.buffer:put-u8 cursor 0)
  ;; 16-byte body: four u32 fields in LE (ours-to-ours, ADR 0014)
  (dds.core.buffer:put-u32 cursor slot-index)
  (dds.core.buffer:put-u32 cursor generation)
  (dds.core.buffer:put-u32 cursor slot-bytes)
  (dds.core.buffer:put-u32 cursor overlay)
  cursor)

(defun* parse-zc-reference (buf off len)
    (function ((simple-array (unsigned-byte 8) (*)) (integer 0) (integer 0))
              (values (or null (unsigned-byte 32)) (unsigned-byte 32) (unsigned-byte 32) (unsigned-byte 32)))
  "If BUF[off, off+len) is a WP-ZEROCOPY 16-byte reference (len>=20, leading u16==+zc-encapsulation-id+),
   return (values slot-index generation slot-bytes overlay); else (values NIL 0 0 0). OVERLAY is the reserved
   u32: 0 = raw, +zc-ref-overlay-secured+ = data_protection SecuredPayload overlay (ADR 0051). Bounds-checked
   (NFR-SEC-POSTURE)."
  (unless (and (>= len 20)
               (>= (length buf) (+ off 20)))
    (return-from parse-zc-reference (values nil 0 0 0)))
  ;; encap id in NBO: hi byte at off+0, lo at off+1 (matches encode-zc-reference write convention)
  (let ((id (logior (ash (aref buf off) 8) (aref buf (+ off 1)))))
    (unless (= id +zc-encapsulation-id+)
      (return-from parse-zc-reference (values nil 0 0 0)))
    ;; body at off+4: four LE u32s (slot-index, generation, slot-bytes, overlay/reserved)
    (flet ((le-u32 (base)
             (logior (aref buf base)
                     (ash (aref buf (+ base 1)) 8)
                     (ash (aref buf (+ base 2)) 16)
                     (ash (aref buf (+ base 3)) 24))))
      (values (le-u32 (+ off 4))
              (le-u32 (+ off 8))
              (le-u32 (+ off 12))
              (le-u32 (+ off 16))))))

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
             :what (format nil "unknown representation id #x~4,'0x" id)))   ; HOTPATH-ALLOC(ERROR-PATH): only on the way to signalling
    (dds.core.buffer:cursor-set-origin cursor)
    (values name options pad)))
