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

(declaim (ftype (function ((simple-array (unsigned-byte 32) (*)) (integer 0)) t) seqnum-set-bit-p))
(defun seqnum-set-bit-p (bitmap delta)
  "T iff the bit for offset DELTA is set: word DELTA/32, bit (31-DELTA%32) (§9.4.2.6)."
  (logbitp (- 31 (mod delta 32)) (aref bitmap (floor delta 32))))

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

;;; ---- Reliability submessages (base forms): HEARTBEAT §9.4.5.7, ACKNACK
;;; §9.4.5.3, GAP §9.4.5.6. Count is a 32-bit value (§9.4.2.13). The E flag
;;; derives from the cursor endianness so the two stay consistent. The GroupInfo
;;; (G) and FilteredCount (F) extensions are not emitted/parsed in v1.

(defconstant +heartbeat-flag-final+      #x02)
(defconstant +heartbeat-flag-liveliness+ #x04)
(defconstant +heartbeat-flag-group-info+ #x08)
(defconstant +acknack-flag-final+        #x02)
(defconstant +gap-flag-group-info+       #x02)
(defconstant +gap-flag-filtered+         #x04)

(declaim (inline %e-flag))
(declaim (ftype (function (dds.core.buffer:cursor) (unsigned-byte 8)) %e-flag))
(defun %e-flag (cursor)
  (if (eq (dds.core.buffer:cursor-endianness cursor) :little) +flag-endianness+ 0))

(declaim (ftype (function (dds.core.buffer:cursor (unsigned-byte 32) (unsigned-byte 32) integer integer (unsigned-byte 32) &key (:final t) (:liveliness t)) fixnum) write-heartbeat))
(defun write-heartbeat (cursor reader-id writer-id first-sn last-sn count &key final liveliness)
  "Write a complete HEARTBEAT submessage (base form). RTPS 2.5 §9.4.5.7; body=28."
  (write-submessage-header cursor +submsg-heartbeat+
                           (logior (%e-flag cursor)
                                   (if final +heartbeat-flag-final+ 0)
                                   (if liveliness +heartbeat-flag-liveliness+ 0))
                           28)
  (write-entity-id cursor reader-id)
  (write-entity-id cursor writer-id)
  (write-sequence-number cursor first-sn)
  (write-sequence-number cursor last-sn)
  (dds.core.buffer:put-u32 cursor (logand count #xFFFFFFFF))
  (dds.core.buffer:cursor-position cursor))

(declaim (ftype (function (dds.core.buffer:cursor (unsigned-byte 8)) t) parse-heartbeat-body))
(defun parse-heartbeat-body (cursor flags)
  "Parse a HEARTBEAT body after its header (base form). Returns (values reader-id
   writer-id first-sn last-sn count final-p liveliness-p) or NIL. Cursor endianness
   must match the E flag. RTPS 2.5 §9.4.5.7."
  (when (< (%remaining cursor) 28) (return-from parse-heartbeat-body nil))
  (let ((reader-id (read-entity-id cursor))
        (writer-id (read-entity-id cursor))
        (first-sn (read-sequence-number cursor))
        (last-sn (read-sequence-number cursor))
        (count (dds.core.buffer:get-u32 cursor)))
    (values reader-id writer-id first-sn last-sn count
            (logtest flags +heartbeat-flag-final+)
            (logtest flags +heartbeat-flag-liveliness+))))

(declaim (ftype (function (dds.core.buffer:cursor (unsigned-byte 32) (unsigned-byte 32) integer (unsigned-byte 32) (simple-array (unsigned-byte 32) (*)) (unsigned-byte 32) &key (:final t)) fixnum) write-acknack))
(defun write-acknack (cursor reader-id writer-id base numbits bitmap count &key final)
  "Write a complete ACKNACK submessage. RTPS 2.5 §9.4.5.3; body=24+4*M."
  (write-submessage-header cursor +submsg-acknack+
                           (logior (%e-flag cursor) (if final +acknack-flag-final+ 0))
                           (+ 24 (* 4 (%seqnum-set-words numbits))))
  (write-entity-id cursor reader-id)
  (write-entity-id cursor writer-id)
  (write-sequence-number-set cursor base numbits bitmap)
  (dds.core.buffer:put-u32 cursor (logand count #xFFFFFFFF))
  (dds.core.buffer:cursor-position cursor))

(declaim (ftype (function (dds.core.buffer:cursor (unsigned-byte 8)) t) parse-acknack-body))
(defun parse-acknack-body (cursor flags)
  "Parse an ACKNACK body. Returns (values reader-id writer-id base numbits bitmap
   count final-p) or NIL on short/invalid buffer. RTPS 2.5 §9.4.5.3."
  (when (< (%remaining cursor) 8) (return-from parse-acknack-body nil))
  (let ((reader-id (read-entity-id cursor))
        (writer-id (read-entity-id cursor)))
    (multiple-value-bind (base numbits bitmap) (read-sequence-number-set cursor)
      (when (null base) (return-from parse-acknack-body nil))
      (when (< (%remaining cursor) 4) (return-from parse-acknack-body nil))
      (values reader-id writer-id base numbits bitmap
              (dds.core.buffer:get-u32 cursor)
              (logtest flags +acknack-flag-final+)))))

(declaim (ftype (function (dds.core.buffer:cursor (unsigned-byte 32) (unsigned-byte 32) integer integer (unsigned-byte 32) (simple-array (unsigned-byte 32) (*))) fixnum) write-gap))
(defun write-gap (cursor reader-id writer-id gap-start base numbits bitmap)
  "Write a complete GAP submessage (base form). RTPS 2.5 §9.4.5.6; body=28+4*M."
  (write-submessage-header cursor +submsg-gap+ (%e-flag cursor)
                           (+ 28 (* 4 (%seqnum-set-words numbits))))
  (write-entity-id cursor reader-id)
  (write-entity-id cursor writer-id)
  (write-sequence-number cursor gap-start)
  (write-sequence-number-set cursor base numbits bitmap)
  (dds.core.buffer:cursor-position cursor))

(declaim (ftype (function (dds.core.buffer:cursor (unsigned-byte 8)) t) parse-gap-body))
(defun parse-gap-body (cursor flags)
  "Parse a GAP body (base form). Returns (values reader-id writer-id gap-start base
   numbits bitmap) or NIL. RTPS 2.5 §9.4.5.6."
  (declare (ignore flags))
  (when (< (%remaining cursor) 16) (return-from parse-gap-body nil))
  (let ((reader-id (read-entity-id cursor))
        (writer-id (read-entity-id cursor))
        (gap-start (read-sequence-number cursor)))
    (multiple-value-bind (base numbits bitmap) (read-sequence-number-set cursor)
      (when (null base) (return-from parse-gap-body nil))
      (values reader-id writer-id gap-start base numbits bitmap))))

;;; ---- DATA submessage (§9.4.5.4): extraFlags + octetsToInlineQos + readerId +
;;; writerId + writerSN + [inlineQos if Q] + serializedPayload [if D||K]. v1 emits
;;; and parses the base form (Q=0; inlineQos parsing lands with the ParameterList
;;; / discovery increment). serializedPayload is passed/returned as a byte region.

(defconstant +data-flag-inline-qos+    #x02)
(defconstant +data-flag-data+          #x04)
(defconstant +data-flag-key+           #x08)
(defconstant +data-flag-non-standard+  #x10)

(declaim (ftype (function (dds.core.buffer:cursor (unsigned-byte 32) (unsigned-byte 32) integer (simple-array (unsigned-byte 8) (*)) (integer 0) (integer 0) &key (:key t)) fixnum) write-data))
(defun write-data (cursor reader-id writer-id writer-sn payload payload-off payload-len &key key)
  "Write a complete DATA submessage with a serializedPayload, no inlineQos. KEY t
   emits a key payload (K=1,D=0); else data (D=1,K=0). RTPS 2.5 §9.4.5.4."
  (write-submessage-header cursor +submsg-data+
                           (logior (%e-flag cursor)
                                   (if key +data-flag-key+ +data-flag-data+))
                           (+ 20 payload-len))
  (dds.core.buffer:put-u16 cursor 0)             ; extraFlags = 0 (this version)
  (dds.core.buffer:put-u16 cursor 16)            ; octetsToInlineQos = 16
  (write-entity-id cursor reader-id)
  (write-entity-id cursor writer-id)
  (write-sequence-number cursor writer-sn)
  (dds.core.buffer:put-octets cursor payload payload-off payload-len)
  (dds.core.buffer:cursor-position cursor))

(declaim (ftype (function (dds.core.buffer:cursor (unsigned-byte 8) (unsigned-byte 16)) t) parse-data-body))
(defun parse-data-body (cursor flags octets-to-next)
  "Parse a DATA body (base form, Q=0). Returns (values reader-id writer-id writer-sn
   has-payload payload-offset payload-len key-p), or NIL if Q is set (inlineQos
   deferred) or the buffer is short. The serializedPayload is left in place (the
   caller reads it from PAYLOAD-OFFSET). RTPS 2.5 §9.4.5.4."
  (when (logtest flags +data-flag-inline-qos+) (return-from parse-data-body nil))
  (when (< (%remaining cursor) 20) (return-from parse-data-body nil))
  (dds.core.buffer:get-u16 cursor)               ; extraFlags (reserved)
  (dds.core.buffer:get-u16 cursor)               ; octetsToInlineQos
  (let* ((reader (read-entity-id cursor))
         (writer (read-entity-id cursor))
         (sn (read-sequence-number cursor))
         (has-payload (logtest flags (logior +data-flag-data+ +data-flag-key+)))
         (len (if (plusp octets-to-next) (- octets-to-next 20) (%remaining cursor))))
    (values reader writer sn has-payload (dds.core.buffer:cursor-position cursor)
            (if has-payload len 0) (logtest flags +data-flag-key+))))

;;; ---- ParameterList (§9.4.2.11, FR-RTPS-9): a list of (parameterId, length,
;;; value) Parameters, each 4-byte aligned, terminated by PID_SENTINEL. PID
;;; constants from the RTPS 2.5 §9.6.2.2 table, never memorized. ----

(defconstant +pid-pad+                        #x0000)
(defconstant +pid-sentinel+                   #x0001)
(defconstant +pid-participant-lease-duration+ #x0002)
(defconstant +pid-topic-name+                 #x0005)
(defconstant +pid-type-name+                  #x0007)
(defconstant +pid-protocol-version+           #x0015)
(defconstant +pid-vendorid+                   #x0016)
(defconstant +pid-reliability+                #x001a)
(defconstant +pid-default-unicast-locator+    #x0031)
(defconstant +pid-metatraffic-unicast-locator+ #x0032)
(defconstant +pid-participant-guid+           #x0050)
(defconstant +pid-builtin-endpoint-set+       #x0058)
(defconstant +pid-endpoint-guid+              #x005a)
(defconstant +pid-key-hash+                   #x0070)

(declaim (ftype (function (dds.core.buffer:cursor (unsigned-byte 16) (simple-array (unsigned-byte 8) (*)) (integer 0) (integer 0)) fixnum) write-parameter))
(defun write-parameter (cursor pid value off len)
  "Write one Parameter: pid + length (padded to a multiple of 4) + value +
   padding. RTPS 2.5 §9.4.2.11; the ParameterList must start 4-byte aligned."
  (let ((padded (* 4 (ceiling len 4))))
    (dds.core.buffer:put-u16 cursor pid)
    (dds.core.buffer:put-u16 cursor padded)
    (dds.core.buffer:put-octets cursor value off len)
    (dotimes (i (- padded len)) (dds.core.buffer:put-u8 cursor 0))
    (dds.core.buffer:cursor-position cursor)))

(declaim (ftype (function (dds.core.buffer:cursor) fixnum) write-parameter-sentinel))
(defun write-parameter-sentinel (cursor)
  "Write PID_SENTINEL, terminating a ParameterList (RTPS 2.5 §9.4.2.11)."
  (dds.core.buffer:put-u16 cursor +pid-sentinel+)
  (dds.core.buffer:put-u16 cursor 0)
  (dds.core.buffer:cursor-position cursor))

(declaim (ftype (function (dds.core.buffer:cursor function) t) parse-parameter-list))
(defun parse-parameter-list (cursor handler)
  "Iterate Parameters until PID_SENTINEL, calling (HANDLER pid cursor len) with the
   cursor at the value. Returns T on clean termination, NIL on a truncated list.
   Bounds-checked; never reads OOB (NFR-SEC-POSTURE). RTPS 2.5 §9.4.2.11."
  (loop
    (when (< (%remaining cursor) 4) (return nil))
    (let ((pid (dds.core.buffer:get-u16 cursor))
          (len (dds.core.buffer:get-u16 cursor)))
      (when (= pid +pid-sentinel+) (return t))
      (when (> len (%remaining cursor)) (return nil))
      (let ((off (dds.core.buffer:cursor-position cursor)))
        (funcall handler pid cursor len)
        (dds.core.buffer:cursor-set-position cursor (+ off len))))))

;;; ---- RTPS port mapping (§9.6.1.1): PB=7400 DG=250 PG=2 d0=0 d1=10 d2=1 d3=11 ----

(defconstant +port-base+ 7400)
(defconstant +port-domain-gain+ 250)
(defconstant +port-participant-gain+ 2)
(defconstant +port-d0+ 0)
(defconstant +port-d1+ 10)
(defconstant +port-d2+ 1)
(defconstant +port-d3+ 11)

(declaim (ftype (function ((integer 0)) (integer 0)) spdp-multicast-port))
(defun spdp-multicast-port (domain)
  "Discovery (SPDP) multicast port: PB + DG*domain + d0 (RTPS 2.5 §9.6.1.1)."
  (+ +port-base+ (* +port-domain-gain+ domain) +port-d0+))

(declaim (ftype (function ((integer 0) (integer 0)) (integer 0)) spdp-unicast-port))
(defun spdp-unicast-port (domain participant-id)
  "Discovery (SPDP) unicast port: PB + DG*domain + d1 + PG*participantId."
  (+ +port-base+ (* +port-domain-gain+ domain) +port-d1+ (* +port-participant-gain+ participant-id)))

(declaim (ftype (function ((integer 0)) (integer 0)) user-multicast-port))
(defun user-multicast-port (domain)
  "User-traffic multicast port: PB + DG*domain + d2 (RTPS 2.5 §9.6.1.1)."
  (+ +port-base+ (* +port-domain-gain+ domain) +port-d2+))

(declaim (ftype (function ((integer 0) (integer 0)) (integer 0)) user-unicast-port))
(defun user-unicast-port (domain participant-id)
  "User-traffic unicast port: PB + DG*domain + d3 + PG*participantId."
  (+ +port-base+ (* +port-domain-gain+ domain) +port-d3+ (* +port-participant-gain+ participant-id)))

;;; ---- RTPS Message receive loop (§8.3.4 / §9.4.5): parse the Header then walk
;;; the submessages, dispatching each to a handler. Each submessage's endianness
;;; comes from its E flag; octetsToNextHeader (0 = extends to the end) frames the
;;; next one. Bounds-checked throughout (NFR-SEC-POSTURE). ----

(declaim (ftype (function (dds.core.buffer:cursor function) t) dispatch-message))
(defun dispatch-message (cursor handler)
  "Parse an RTPS message; for each submessage call (HANDLER id flags cursor
   body-len) with the cursor at the body and its endianness set per the E flag.
   Returns T on a well-formed message, NIL on bad magic / truncation."
  (unless (parse-header cursor) (return-from dispatch-message nil))
  (loop
    (when (< (%remaining cursor) 4) (return t))
    (multiple-value-bind (id flags octets le) (parse-submessage-header cursor)
      (when (null id) (return nil))
      (dds.core.buffer:cursor-set-endianness cursor (if le :little :big))
      (let* ((body-start (dds.core.buffer:cursor-position cursor))
             (body-len (if (plusp octets) octets (%remaining cursor))))
        (when (> body-len (%remaining cursor)) (return nil))
        (funcall handler id flags cursor body-len)
        (dds.core.buffer:cursor-set-position cursor (+ body-start body-len))))))
