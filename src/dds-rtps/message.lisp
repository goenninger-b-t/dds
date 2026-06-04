(in-package #:dds.rtps.message)

;;;; RTPS 2.5 wire constants — read from docs/specs/rtps-2_5.pdf (clause cited),
;;;; never memorized. HOT PATH: monomorphic functions; parsers bounds-checked.

;; PROTOCOL_RTPS: ProtocolId_t[4] = 'R','T','P','S' (RTPS 2.5 §8 / §9.4.4).
(defparameter +protocol-id+
  (make-array 4 :element-type '(unsigned-byte 8)
                :initial-contents (list (char-code #\R) (char-code #\T)
                                        (char-code #\P) (char-code #\S)))
  "The 4-octet RTPS message magic 'R','T','P','S' (RTPS 2.5 §9.4.4).")

;; ProtocolVersion 2.5: major = 2, minor = 5 (RTPS 2.5 §9.4.4).
(defconstant +protocol-version-major+ 2)
(defconstant +protocol-version-minor+ 5)

;; VENDORID_UNKNOWN = {0,0} (RTPS 2.5 §8.3.5.2). A compliant id is OMG-assigned.
(defconstant +vendor-id-unknown+ #x0000)
(defparameter *vendor-id* +vendor-id-unknown+
  "16-bit VendorId written in the header. Provisional VENDORID_UNKNOWN until an
   OMG-assigned id is obtained (FR-RTPS-2, owner action).")

;; SubmessageKind ids (RTPS 2.5 §9.4.5.1.1, enum SubmessageKind).
(defconstant +submsg-pad+            #x01)
(defconstant +submsg-acknack+        #x06)
(defconstant +submsg-heartbeat+      #x07)
(defconstant +submsg-gap+            #x08)
(defconstant +submsg-info-ts+        #x09)
(defconstant +submsg-info-src+       #x0c)
(defconstant +submsg-info-reply-ip4+ #x0d)
(defconstant +submsg-info-dst+       #x0e)
(defconstant +submsg-info-reply+     #x0f)
(defconstant +submsg-nack-frag+      #x12)
(defconstant +submsg-heartbeat-frag+ #x13)
(defconstant +submsg-data+           #x15)
(defconstant +submsg-data-frag+      #x16)

;; Submessage flags: bit 0 = E (EndiannessFlag), 1 = little-endian (§9.4.5.1.2).
(defconstant +flag-endianness+ #x01)

;; EntityId (RTPS 2.5 §9.3.1.2): entityKey[3] + entityKind, 4 octets MSB-first.
(defconstant +entityid-unknown+     #x00000000)
(defconstant +entityid-participant+ #x000001c1)

(declaim (inline %remaining))
(declaim (ftype (function (dds.core.buffer:cursor) fixnum) %remaining))
(defun %remaining (cursor)
  (- (dds.core.buffer:octet-buffer-capacity (dds.core.buffer:cursor-buffer cursor))
     (dds.core.buffer:cursor-position cursor)))

;;; ---- RTPS Message Header (§9.4.4): magic + version + vendorId + guidPrefix ----

(declaim (ftype (function (dds.core.buffer:cursor (simple-array (unsigned-byte 8) (*)) &key (:vendor (unsigned-byte 16))) fixnum) write-header))
(defun write-header (cursor guid-prefix &key (vendor *vendor-id*))
  "Write the 20-octet RTPS Header (RTPS 2.5 §9.4.4). GUID-PREFIX is 12 octets; all
   header fields are octet arrays, so there is no endianness."
  (assert (= 12 (length guid-prefix)))
  (dds.core.buffer:put-octets cursor +protocol-id+ 0 4)
  (dds.core.buffer:put-u8 cursor +protocol-version-major+)
  (dds.core.buffer:put-u8 cursor +protocol-version-minor+)
  (dds.core.buffer:put-u8 cursor (ldb (byte 8 8) vendor))
  (dds.core.buffer:put-u8 cursor (ldb (byte 8 0) vendor))
  (dds.core.buffer:put-octets cursor guid-prefix 0 12)
  (dds.core.buffer:cursor-position cursor))

(declaim (ftype (function (dds.core.buffer:cursor) t) parse-header))
(defun parse-header (cursor)
  "Parse a 20-octet RTPS Header. Returns (values major minor vendor guid-prefix),
   or NIL if fewer than 20 octets remain or the magic is wrong. Bounds-checked;
   never reads OOB (NFR-SEC-POSTURE)."
  (when (< (%remaining cursor) 20)
    (return-from parse-header nil))
  (let ((m0 (dds.core.buffer:get-u8 cursor)) (m1 (dds.core.buffer:get-u8 cursor))
        (m2 (dds.core.buffer:get-u8 cursor)) (m3 (dds.core.buffer:get-u8 cursor)))
    (unless (and (= m0 (aref +protocol-id+ 0)) (= m1 (aref +protocol-id+ 1))
                 (= m2 (aref +protocol-id+ 2)) (= m3 (aref +protocol-id+ 3)))
      (return-from parse-header nil))
    (let* ((major (dds.core.buffer:get-u8 cursor))
           (minor (dds.core.buffer:get-u8 cursor))
           (vh (dds.core.buffer:get-u8 cursor))
           (vl (dds.core.buffer:get-u8 cursor))
           (prefix (make-array 12 :element-type '(unsigned-byte 8))))
      (dds.core.buffer:get-octets cursor prefix 0 12)
      (values major minor (logior (ash vh 8) vl) prefix))))

;;; ---- SubmessageHeader (§9.4.5.1): submessageId, flags, octetsToNextHeader ----

(declaim (ftype (function (dds.core.buffer:cursor (unsigned-byte 8) (unsigned-byte 8) (unsigned-byte 16)) fixnum) write-submessage-header))
(defun write-submessage-header (cursor submessage-id flags octets-to-next)
  "Write a 4-octet SubmessageHeader (RTPS 2.5 §9.4.5.1). octetsToNextHeader is a
   u16 in the cursor's endianness, which the caller MUST keep consistent with the
   E flag (bit 0 of FLAGS)."
  (dds.core.buffer:put-u8 cursor submessage-id)
  (dds.core.buffer:put-u8 cursor flags)
  (dds.core.buffer:put-u16 cursor octets-to-next)
  (dds.core.buffer:cursor-position cursor))

(declaim (ftype (function (dds.core.buffer:cursor) t) parse-submessage-header))
(defun parse-submessage-header (cursor)
  "Parse a 4-octet SubmessageHeader. Returns (values submessage-id flags
   octets-to-next little-endian-p), or NIL if fewer than 4 octets remain.
   octetsToNextHeader is read with the endianness from the E flag (§9.4.5.1.2),
   independent of the cursor. Bounds-checked."
  (when (< (%remaining cursor) 4)
    (return-from parse-submessage-header nil))
  (let* ((id (dds.core.buffer:get-u8 cursor))
         (flags (dds.core.buffer:get-u8 cursor))
         (le (logbitp 0 flags))
         (o0 (dds.core.buffer:get-u8 cursor))
         (o1 (dds.core.buffer:get-u8 cursor)))
    (values id flags (if le (logior o0 (ash o1 8)) (logior (ash o0 8) o1)) le)))

;;; ---- EntityId (§9.3.1.2): 4 octets entityKey[3]+entityKind, MSB-first ----

(declaim (ftype (function (dds.core.buffer:cursor (unsigned-byte 32)) fixnum) write-entity-id))
(defun write-entity-id (cursor entity-id)
  "Write a 4-octet EntityId MSB-first (RTPS 2.5 §9.3.1.2)."
  (dds.core.buffer:put-u8 cursor (ldb (byte 8 24) entity-id))
  (dds.core.buffer:put-u8 cursor (ldb (byte 8 16) entity-id))
  (dds.core.buffer:put-u8 cursor (ldb (byte 8 8) entity-id))
  (dds.core.buffer:put-u8 cursor (ldb (byte 8 0) entity-id))
  (dds.core.buffer:cursor-position cursor))

(declaim (ftype (function (dds.core.buffer:cursor) (unsigned-byte 32)) read-entity-id))
(defun read-entity-id (cursor)
  "Read a 4-octet EntityId as a u32 (MSB-first) (RTPS 2.5 §9.3.1.2)."
  (let ((b0 (dds.core.buffer:get-u8 cursor)) (b1 (dds.core.buffer:get-u8 cursor))
        (b2 (dds.core.buffer:get-u8 cursor)) (b3 (dds.core.buffer:get-u8 cursor)))
    (logior (ash b0 24) (ash b1 16) (ash b2 8) b3)))

;;; ---- SequenceNumber (§9.3.2.10): high (i32) + low (u32); value = low+high*2^32 ----

(defconstant +sequence-number-unknown+ (- (ash 1 32))
  "SEQUENCENUMBER_UNKNOWN = {high=-1, low=0} (RTPS 2.5 §8.3.5.4).")

(declaim (ftype (function (dds.core.buffer:cursor integer) fixnum) write-sequence-number))
(defun write-sequence-number (cursor seqnum)
  "Write an 8-octet SequenceNumber: high (i32) then low (u32), cursor endianness."
  (dds.core.buffer:put-u32 cursor (logand (ash seqnum -32) #xFFFFFFFF))
  (dds.core.buffer:put-u32 cursor (logand seqnum #xFFFFFFFF))
  (dds.core.buffer:cursor-position cursor))

(declaim (ftype (function (dds.core.buffer:cursor) integer) read-sequence-number))
(defun read-sequence-number (cursor)
  "Read an 8-octet SequenceNumber as a signed 64-bit value (RTPS 2.5 §9.3.2.10)."
  (let* ((hu (dds.core.buffer:get-u32 cursor))
         (low (dds.core.buffer:get-u32 cursor))
         (high (if (>= hu #x80000000) (- hu #x100000000) hu)))
    (+ low (* high #x100000000))))

;;; ---- SequenceNumberSet (§9.4.2.6): bitmapBase + numBits + M=(numBits+31)/32 longs.
;;; Offset deltaN maps to bitmap[deltaN/32], bit (31 - deltaN%32) — MSB-first. ----

(defconstant +seqnum-set-max-bits+ 256)

(declaim (ftype (function ((unsigned-byte 32)) fixnum) %seqnum-set-words))
(defun %seqnum-set-words (numbits)
  "M = (numBits+31)/32 longs (RTPS 2.5 §9.4.2.6)."
  (ceiling numbits 32))

(declaim (ftype (function ((simple-array (unsigned-byte 32) (*)) (integer 0)) (unsigned-byte 32)) seqnum-set-bit))
(defun seqnum-set-bit (bitmap delta)
  "Set the bit for offset DELTA: word DELTA/32, bit (31 - DELTA%32) (§9.4.2.6)."
  (let ((w (floor delta 32)))
    (setf (aref bitmap w) (logior (aref bitmap w) (ash 1 (- 31 (mod delta 32)))))))

(declaim (ftype (function (integer (unsigned-byte 32) (simple-array (unsigned-byte 32) (*)) integer) t) seqnum-set-member-p))
(defun seqnum-set-member-p (base numbits bitmap seqnum)
  "T iff SEQNUM is in the SequenceNumberSet, per the §9.4.2.6 membership rule."
  (let ((delta (- seqnum base)))
    (and (<= base seqnum) (< delta numbits)
         (logbitp (- 31 (mod delta 32)) (aref bitmap (floor delta 32))))))

(declaim (ftype (function (dds.core.buffer:cursor integer (unsigned-byte 32) (simple-array (unsigned-byte 32) (*))) fixnum) write-sequence-number-set))
(defun write-sequence-number-set (cursor base numbits bitmap)
  "Write a SequenceNumberSet: bitmapBase + numBits + M longs (RTPS 2.5 §9.4.2.6)."
  (assert (<= numbits +seqnum-set-max-bits+))
  (write-sequence-number cursor base)
  (dds.core.buffer:put-u32 cursor numbits)
  (dotimes (i (%seqnum-set-words numbits))
    (dds.core.buffer:put-u32 cursor (aref bitmap i)))
  (dds.core.buffer:cursor-position cursor))

(declaim (ftype (function (dds.core.buffer:cursor) t) read-sequence-number-set))
(defun read-sequence-number-set (cursor)
  "Parse a SequenceNumberSet. Returns (values base numBits bitmap-words) or NIL on
   short buffer / numBits>256 (§9.4.2.6). Bounds-checked; never reads OOB."
  (when (< (%remaining cursor) 12)
    (return-from read-sequence-number-set nil))
  (let* ((base (read-sequence-number cursor))
         (numbits (dds.core.buffer:get-u32 cursor)))
    (when (> numbits +seqnum-set-max-bits+)
      (return-from read-sequence-number-set nil))
    (let ((m (%seqnum-set-words numbits)))
      (when (< (%remaining cursor) (* m 4))
        (return-from read-sequence-number-set nil))
      (let ((bitmap (make-array (max 1 m) :element-type '(unsigned-byte 32) :initial-element 0)))
        (dotimes (i m) (setf (aref bitmap i) (dds.core.buffer:get-u32 cursor)))
        (values base numbits bitmap)))))
