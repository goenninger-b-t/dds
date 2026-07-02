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
(defconstant +protocol-version-major+ 2
  "ProtocolVersion major = 2 (RTPS 2.5 §9.4.4).")
(defconstant +protocol-version-minor+ 5
  "ProtocolVersion minor = 5 (RTPS 2.5 §9.4.4).")

(defconstant +vendor-id-unknown+ #x0000
  "VENDORID_UNKNOWN = {0,0} (RTPS 2.5 §8.3.5.2); a compliant id is OMG-assigned.")
(defconstant +vendor-id-dev-provisional+ #x01ff
  "Provisional development VendorId for this stack (FR-RTPS-2). Non-conflicting with the
   OMG DDS-RTPS vendor-id registry, whose sequential assignments reach 0x0119 as of
   2026-06-09 (dds-foundation.org/dds-rtps-vendor-and-product-ids); 0x01FF sits at the top
   of the conventional 0x01xx block, far clear of the active range. Replace with an
   OMG-assigned id once obtained.")
(defparameter *vendor-id* +vendor-id-dev-provisional+
  "16-bit VendorId written in the RTPS message header (write-header) and the SPDP
   PID_VENDORID (dds-disc). A NON-ZERO id is required for conformant peers (notably RTI
   Connext) to accept this participant — VENDORID_UNKNOWN (0,0) is ignored. Currently the
   provisional +vendor-id-dev-provisional+ (0x01FF) pending an OMG allocation (FR-RTPS-2).")

;; SubmessageKind ids (RTPS 2.5 §9.4.5.1.1, enum SubmessageKind).
(defconstant +submsg-pad+            #x01
  "SubmessageKind PAD (RTPS 2.5 §9.4.5.1.1).")
(defconstant +submsg-acknack+        #x06
  "SubmessageKind ACKNACK (RTPS 2.5 §9.4.5.1.1).")
(defconstant +submsg-heartbeat+      #x07
  "SubmessageKind HEARTBEAT (RTPS 2.5 §9.4.5.1.1).")
(defconstant +submsg-gap+            #x08
  "SubmessageKind GAP (RTPS 2.5 §9.4.5.1.1).")
(defconstant +submsg-info-ts+        #x09
  "SubmessageKind INFO_TS / InfoTimestamp (RTPS 2.5 §9.4.5.1.1).")
(defconstant +submsg-info-src+       #x0c
  "SubmessageKind INFO_SRC / InfoSource (RTPS 2.5 §9.4.5.1.1).")
(defconstant +submsg-info-reply-ip4+ #x0d
  "SubmessageKind INFO_REPLY_IP4 (RTPS 2.5 §9.4.5.1.1).")
(defconstant +submsg-info-dst+       #x0e
  "SubmessageKind INFO_DST / InfoDestination (RTPS 2.5 §9.4.5.1.1).")
(defconstant +submsg-info-reply+     #x0f
  "SubmessageKind INFO_REPLY (RTPS 2.5 §9.4.5.1.1).")
(defconstant +submsg-nack-frag+      #x12
  "SubmessageKind NACK_FRAG (RTPS 2.5 §9.4.5.1.1).")
(defconstant +submsg-heartbeat-frag+ #x13
  "SubmessageKind HEARTBEAT_FRAG (RTPS 2.5 §9.4.5.1.1).")
(defconstant +submsg-data+           #x15
  "SubmessageKind DATA (RTPS 2.5 §9.4.5.1.1).")
(defconstant +submsg-data-frag+      #x16
  "SubmessageKind DATA_FRAG (RTPS 2.5 §9.4.5.1.1).")

(defconstant +flag-endianness+ #x01
  "Submessage E (EndiannessFlag), bit 0; 1 = little-endian (RTPS 2.5 §9.4.5.1.2).")

;; EntityId (RTPS 2.5 §9.3.1.2): entityKey[3] + entityKind, 4 octets MSB-first.
(defconstant +entityid-unknown+     #x00000000
  "ENTITYID_UNKNOWN (RTPS 2.5 §9.3.1.2): entityKey[3]+entityKind, MSB-first u32.")
(defconstant +entityid-participant+ #x000001c1
  "ENTITYID_PARTICIPANT (RTPS 2.5 §9.3.1.2): entityKey[3]+entityKind, MSB-first u32.")

(declaim (inline %remaining))
(defun* %remaining (cursor)
    (function (dds.core.buffer:cursor) fixnum)
  "Octets between CURSOR's current position and its buffer capacity (bytes still available)."
  (- (dds.core.buffer:octet-buffer-capacity (dds.core.buffer:cursor-buffer cursor))
     (dds.core.buffer:cursor-position cursor)))

;;; ---- RTPS Message Header (§9.4.4): magic + version + vendorId + guidPrefix ----

(defun* write-header (cursor guid-prefix &key (vendor *vendor-id*))
    (function (dds.core.buffer:cursor (simple-array (unsigned-byte 8) (*)) &key (:vendor (unsigned-byte 16))) fixnum)
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

(defun* put-info-src-into (vec off guid-prefix)
    (function ((simple-array (unsigned-byte 8) (*)) fixnum (simple-array (unsigned-byte 8) (*))) (integer 24 24))
  "Write a 24-octet INFO_SRC submessage (RTPS 2.5 §9.4.5.9 / §8.3.7.9) into VEC at raw offset OFF declaring
   GUID-PREFIX (12 octets) as the source of the subsequent submessages, little-endian (E flag set). Layout:
   SubmessageHeader[INFO_SRC=0x0c, flags=E, octetsToNextHeader=20] ‖ unused(4)=0 ‖ ProtocolVersion(2) ‖
   VendorId(2) ‖ GuidPrefix(12) = 24 octets. Zero-alloc raw-offset writer (no cursor) for the whole-RTPS-message
   (SRTPS) send path %MAYBE-WRAP-SRTPS. Its purpose is to bind the protected submessages to their source so an
   RTPS message can be relayed / whole-RTPS-protected: DDS-Security 1.1 §9.5.3.3.5 has the encoded RTPS payload
   begin with this source-declaring INFO_SRC, and a strict rtps_protection peer (live RTI Connext) rejects a
   protected payload whose first recovered submessage is not it (decode_rtps_message 'wrong INFO_SRC'). Returns 24
   (octets written); the CALLER ensures OFF+24 <= (length VEC)."
  (assert (= 12 (length guid-prefix)))
  (setf (aref vec off)        +submsg-info-src+
        (aref vec (+ off 1))  +flag-endianness+            ; E=1 little-endian
        (aref vec (+ off 2))  20                            ; octetsToNextHeader = 20 (LE low)
        (aref vec (+ off 3))  0                             ; octetsToNextHeader (LE high)
        (aref vec (+ off 4))  0 (aref vec (+ off 5)) 0      ; unused (reserved, ignored)
        (aref vec (+ off 6))  0 (aref vec (+ off 7)) 0
        (aref vec (+ off 8))  +protocol-version-major+
        (aref vec (+ off 9))  +protocol-version-minor+
        (aref vec (+ off 10)) (ldb (byte 8 8) *vendor-id*)
        (aref vec (+ off 11)) (ldb (byte 8 0) *vendor-id*))
  (replace vec guid-prefix :start1 (+ off 12) :end1 (+ off 24) :start2 0 :end2 12)
  24)

(defun* parse-header (cursor)
    (function (dds.core.buffer:cursor) t)
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

(defun* write-submessage-header (cursor submessage-id flags octets-to-next)
    (function (dds.core.buffer:cursor (unsigned-byte 8) (unsigned-byte 8) (unsigned-byte 16)) fixnum)
  "Write a 4-octet SubmessageHeader (RTPS 2.5 §9.4.5.1). octetsToNextHeader is a
   u16 in the cursor's endianness, which the caller MUST keep consistent with the
   E flag (bit 0 of FLAGS)."
  (dds.core.buffer:put-u8 cursor submessage-id)
  (dds.core.buffer:put-u8 cursor flags)
  (dds.core.buffer:put-u16 cursor octets-to-next)
  (dds.core.buffer:cursor-position cursor))

(defun* parse-submessage-header (cursor)
    (function (dds.core.buffer:cursor) t)
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

(defun* write-entity-id (cursor entity-id)
    (function (dds.core.buffer:cursor (unsigned-byte 32)) fixnum)
  "Write a 4-octet EntityId MSB-first (RTPS 2.5 §9.3.1.2)."
  (dds.core.buffer:put-u8 cursor (ldb (byte 8 24) entity-id))
  (dds.core.buffer:put-u8 cursor (ldb (byte 8 16) entity-id))
  (dds.core.buffer:put-u8 cursor (ldb (byte 8 8) entity-id))
  (dds.core.buffer:put-u8 cursor (ldb (byte 8 0) entity-id))
  (dds.core.buffer:cursor-position cursor))

(defun* read-entity-id (cursor)
    (function (dds.core.buffer:cursor) (unsigned-byte 32))
  "Read a 4-octet EntityId as a u32 (MSB-first) (RTPS 2.5 §9.3.1.2)."
  (let ((b0 (dds.core.buffer:get-u8 cursor)) (b1 (dds.core.buffer:get-u8 cursor))
        (b2 (dds.core.buffer:get-u8 cursor)) (b3 (dds.core.buffer:get-u8 cursor)))
    (logior (ash b0 24) (ash b1 16) (ash b2 8) b3)))

;;; ---- SequenceNumber (§9.3.2.10): high (i32) + low (u32); value = low+high*2^32 ----

(defconstant +sequence-number-unknown+ (- (ash 1 32))
  "SEQUENCENUMBER_UNKNOWN = {high=-1, low=0} (RTPS 2.5 §8.3.5.4).")

(defun* write-sequence-number (cursor seqnum)
    (function (dds.core.buffer:cursor integer) fixnum)
  "Write an 8-octet SequenceNumber: high (i32) then low (u32), cursor endianness."
  (dds.core.buffer:put-u32 cursor (logand (ash seqnum -32) #xFFFFFFFF))
  (dds.core.buffer:put-u32 cursor (logand seqnum #xFFFFFFFF))
  (dds.core.buffer:cursor-position cursor))

(defun* read-sequence-number (cursor)
    (function (dds.core.buffer:cursor) integer)
  "Read an 8-octet SequenceNumber as a signed 64-bit value (RTPS 2.5 §9.3.2.10)."
  (let* ((hu (dds.core.buffer:get-u32 cursor))
         (low (dds.core.buffer:get-u32 cursor))
         (high (if (>= hu #x80000000) (- hu #x100000000) hu)))
    (+ low (* high #x100000000))))

;;; ---- SequenceNumberSet (§9.4.2.6): bitmapBase + numBits + M=(numBits+31)/32 longs.
;;; Offset deltaN maps to bitmap[deltaN/32], bit (31 - deltaN%32) — MSB-first. ----

(defconstant +seqnum-set-max-bits+ 256
  "Maximum numBits in a SequenceNumberSet (RTPS 2.5 §9.4.2.6).")

(defun* %seqnum-set-words (numbits)
    (function ((unsigned-byte 32)) fixnum)
  "M = (numBits+31)/32 longs (RTPS 2.5 §9.4.2.6)."
  (ceiling numbits 32))

(defun* seqnum-set-bit (bitmap delta)
    (function ((simple-array (unsigned-byte 32) (*)) (integer 0)) (unsigned-byte 32))
  "Set the bit for offset DELTA: word DELTA/32, bit (31 - DELTA%32) (§9.4.2.6)."
  (let ((w (floor delta 32)))
    (setf (aref bitmap w) (logior (aref bitmap w) (ash 1 (- 31 (mod delta 32)))))))

(defun* seqnum-set-member-p (base numbits bitmap seqnum)
    (function (integer (unsigned-byte 32) (simple-array (unsigned-byte 32) (*)) integer) t)
  "T iff SEQNUM is in the SequenceNumberSet, per the §9.4.2.6 membership rule."
  (let ((delta (- seqnum base)))
    (and (<= base seqnum) (< delta numbits)
         (logbitp (- 31 (mod delta 32)) (aref bitmap (floor delta 32))))))

(defun* seqnum-set-bit-p (bitmap delta)
    (function ((simple-array (unsigned-byte 32) (*)) (integer 0)) t)
  "T iff the bit for offset DELTA is set: word DELTA/32, bit (31-DELTA%32) (§9.4.2.6)."
  (logbitp (- 31 (mod delta 32)) (aref bitmap (floor delta 32))))

(defun* seqnum-set-from-sns (sns)
    (function (cons) (values integer (unsigned-byte 32) (simple-array (unsigned-byte 32) (*))))
  "Build a SequenceNumberSet (RTPS 2.5 §9.4.2.6) covering the non-empty SN list SNS: (values base numBits
   bitmap), base = min SN, numBits = (max−min+1), one bit set per SN via the shared seqnum-set-bit (so the
   MSB-first word layout is never re-derived). SNS must fit one 256-SN window (max−min < 256), as it does for
   the SNs of a single inbound ACKNACK's SequenceNumberSet; ASSERTed."
  (let* ((lo (reduce #'min sns))
         (hi (reduce #'max sns))
         (numbits (1+ (- hi lo))))
    (assert (<= numbits +seqnum-set-max-bits+))
    (let ((bitmap (make-array (max 1 (%seqnum-set-words numbits))
                              :element-type '(unsigned-byte 32) :initial-element 0)))
      (dolist (sn sns) (seqnum-set-bit bitmap (- sn lo)))
      (values lo numbits bitmap))))

(defun* write-sequence-number-set (cursor base numbits bitmap)
    (function (dds.core.buffer:cursor integer (unsigned-byte 32) (simple-array (unsigned-byte 32) (*))) fixnum)
  "Write a SequenceNumberSet: bitmapBase + numBits + M longs (RTPS 2.5 §9.4.2.6)."
  (assert (<= numbits +seqnum-set-max-bits+))
  (write-sequence-number cursor base)
  (dds.core.buffer:put-u32 cursor numbits)
  (dotimes (i (%seqnum-set-words numbits))
    (dds.core.buffer:put-u32 cursor (aref bitmap i)))
  (dds.core.buffer:cursor-position cursor))

(defun* read-sequence-number-set (cursor)
    (function (dds.core.buffer:cursor) t)
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

;;; ---- FragmentNumberSet (§9.4.2.8): bitmapBase (FragmentNumber, u32) + numBits
;;; + M=ceil(numBits/32) longs; same MSB-first delta bitmap as SequenceNumberSet.

(defun* fragnum-set-bit (bitmap delta)
    (function ((simple-array (unsigned-byte 32) (*)) (integer 0)) (unsigned-byte 32))
  "Set the bit for fragment-offset DELTA: word DELTA/32, bit (31 - DELTA%32) (§9.4.2.8)."
  (let ((w (floor delta 32)))
    (setf (aref bitmap w) (logior (aref bitmap w) (ash 1 (- 31 (mod delta 32)))))))

(defun* fragnum-set-member-p (base numbits bitmap fragnum)
    (function ((unsigned-byte 32) (unsigned-byte 32) (simple-array (unsigned-byte 32) (*)) (unsigned-byte 32)) t)
  "T iff FRAGNUM is in the FragmentNumberSet (§9.4.2.8 membership rule)."
  (let ((delta (- fragnum base)))
    (and (<= base fragnum) (< delta numbits)
         (logbitp (- 31 (mod delta 32)) (aref bitmap (floor delta 32))))))

(defun* write-fragment-number-set (cursor base numbits bitmap)
    (function (dds.core.buffer:cursor (unsigned-byte 32) (unsigned-byte 32) (simple-array (unsigned-byte 32) (*))) fixnum)
  "Write a FragmentNumberSet: bitmapBase (u32) + numBits + M longs (RTPS 2.5 §9.4.2.8)."
  (assert (<= numbits +seqnum-set-max-bits+))
  (dds.core.buffer:put-u32 cursor base)
  (dds.core.buffer:put-u32 cursor numbits)
  (dotimes (i (%seqnum-set-words numbits))
    (dds.core.buffer:put-u32 cursor (aref bitmap i)))
  (dds.core.buffer:cursor-position cursor))

(defun* read-fragment-number-set (cursor)
    (function (dds.core.buffer:cursor) t)
  "Parse a FragmentNumberSet. (values base numBits bitmap) or NIL on short buffer /
   numBits>256 (§9.4.2.8). Bounds-checked; never reads OOB."
  (when (< (%remaining cursor) 8) (return-from read-fragment-number-set nil))
  (let* ((base (dds.core.buffer:get-u32 cursor))
         (numbits (dds.core.buffer:get-u32 cursor)))
    (when (> numbits +seqnum-set-max-bits+) (return-from read-fragment-number-set nil))
    (let ((m (%seqnum-set-words numbits)))
      (when (< (%remaining cursor) (* m 4)) (return-from read-fragment-number-set nil))
      (let ((bitmap (make-array (max 1 m) :element-type '(unsigned-byte 32) :initial-element 0)))
        (dotimes (i m) (setf (aref bitmap i) (dds.core.buffer:get-u32 cursor)))
        (values base numbits bitmap)))))

;;; ---- Reliability submessages (base forms): HEARTBEAT §9.4.5.7, ACKNACK
;;; §9.4.5.3, GAP §9.4.5.6. Count is a 32-bit value (§9.4.2.13). The E flag
;;; derives from the cursor endianness so the two stay consistent. The GroupInfo
;;; (G) and FilteredCount (F) extensions are not emitted/parsed in v1.

(defconstant +heartbeat-flag-final+      #x02
  "HEARTBEAT FinalFlag (F) (RTPS 2.5 §9.4.5.7).")
(defconstant +heartbeat-flag-liveliness+ #x04
  "HEARTBEAT LivelinessFlag (L) (RTPS 2.5 §9.4.5.7).")
(defconstant +heartbeat-flag-group-info+ #x08
  "HEARTBEAT GroupInfoFlag (G); not emitted/parsed in v1 (RTPS 2.5 §9.4.5.7).")
(defconstant +acknack-flag-final+        #x02
  "ACKNACK FinalFlag (F) (RTPS 2.5 §9.4.5.3).")
(defconstant +gap-flag-group-info+       #x02
  "GAP GroupInfoFlag (G) (RTPS 2.5 §9.4.5.6).")
(defconstant +gap-flag-filtered+         #x04
  "GAP FilteredCount/Filtered extension flag (F); not parsed in v1 (RTPS 2.5 §9.4.5.6).")

(declaim (inline %e-flag))
(defun* %e-flag (cursor)
    (function (dds.core.buffer:cursor) (unsigned-byte 8))
  "The submessage EndiannessFlag (E) value for CURSOR: +flag-endianness+ when little-endian, else 0 (RTPS 2.5 §9.4.5.1.1)."
  (if (eq (dds.core.buffer:cursor-endianness cursor) :little) +flag-endianness+ 0))

(defun* write-heartbeat (cursor reader-id writer-id first-sn last-sn count &key final liveliness)
    (function (dds.core.buffer:cursor (unsigned-byte 32) (unsigned-byte 32) integer integer (unsigned-byte 32) &key (:final t) (:liveliness t)) fixnum)
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

(defun* parse-heartbeat-body (cursor flags)
    (function (dds.core.buffer:cursor (unsigned-byte 8)) t)
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

(defun* write-acknack (cursor reader-id writer-id base numbits bitmap count &key final)
    (function (dds.core.buffer:cursor (unsigned-byte 32) (unsigned-byte 32) integer (unsigned-byte 32) (simple-array (unsigned-byte 32) (*)) (unsigned-byte 32) &key (:final t)) fixnum)
  "Write a complete ACKNACK submessage. RTPS 2.5 §9.4.5.3; body=24+4*M."
  (write-submessage-header cursor +submsg-acknack+
                           (logior (%e-flag cursor) (if final +acknack-flag-final+ 0))
                           (+ 24 (* 4 (%seqnum-set-words numbits))))
  (write-entity-id cursor reader-id)
  (write-entity-id cursor writer-id)
  (write-sequence-number-set cursor base numbits bitmap)
  (dds.core.buffer:put-u32 cursor (logand count #xFFFFFFFF))
  (dds.core.buffer:cursor-position cursor))

(defun* parse-acknack-body (cursor flags)
    (function (dds.core.buffer:cursor (unsigned-byte 8)) t)
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

(defun* write-gap (cursor reader-id writer-id gap-start base numbits bitmap)
    (function (dds.core.buffer:cursor (unsigned-byte 32) (unsigned-byte 32) integer integer (unsigned-byte 32) (simple-array (unsigned-byte 32) (*))) fixnum)
  "Write a complete GAP submessage (base form). RTPS 2.5 §9.4.5.6; body=28+4*M."
  (write-submessage-header cursor +submsg-gap+ (%e-flag cursor)
                           (+ 28 (* 4 (%seqnum-set-words numbits))))
  (write-entity-id cursor reader-id)
  (write-entity-id cursor writer-id)
  (write-sequence-number cursor gap-start)
  (write-sequence-number-set cursor base numbits bitmap)
  (dds.core.buffer:cursor-position cursor))

(defun* parse-gap-body (cursor flags)
    (function (dds.core.buffer:cursor (unsigned-byte 8)) t)
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

;;; ---- HEARTBEAT_FRAG submessage (§9.4.5.8): readerId(4) + writerId(4) + writerSN(8) +
;;; lastFragmentNum(4) + count(4) = 24 octets; only the E flag (§9.4.5.8). ----

(defun* write-heartbeat-frag (cursor reader-id writer-id writer-sn last-fragment-num count)
    (function (dds.core.buffer:cursor (unsigned-byte 32) (unsigned-byte 32) integer (unsigned-byte 32) (unsigned-byte 32)) fixnum)
  "Write a HEARTBEAT_FRAG submessage. RTPS 2.5 §9.4.5.8; body=24."
  ;; §9.4.5.8: readerId(4)+writerId(4)+writerSN(8)+lastFragmentNum(4)+count(4)=24
  (write-submessage-header cursor +submsg-heartbeat-frag+ (%e-flag cursor) 24)
  (write-entity-id cursor reader-id)
  (write-entity-id cursor writer-id)
  (write-sequence-number cursor writer-sn)
  (dds.core.buffer:put-u32 cursor last-fragment-num)
  (dds.core.buffer:put-u32 cursor (logand count #xFFFFFFFF))
  (dds.core.buffer:cursor-position cursor))

(defun* parse-heartbeat-frag-body (cursor flags)
    (function (dds.core.buffer:cursor (unsigned-byte 8)) t)
  "Parse a HEARTBEAT_FRAG body. Returns (values reader-id writer-id writer-sn
   last-fragment-num count) or NIL on short buffer. RTPS 2.5 §9.4.5.8."
  (declare (ignore flags))
  ;; §9.4.5.8: body must be exactly 24 octets
  (when (< (%remaining cursor) 24) (return-from parse-heartbeat-frag-body nil))
  (let ((reader-id (read-entity-id cursor))
        (writer-id (read-entity-id cursor))
        (writer-sn (read-sequence-number cursor))
        (last-fragment-num (dds.core.buffer:get-u32 cursor))
        (count (dds.core.buffer:get-u32 cursor)))
    (values reader-id writer-id writer-sn last-fragment-num count)))

;;; ---- NACK_FRAG submessage (§9.4.5.14): readerId(4)+writerId(4)+writerSN(8)+
;;; fragmentNumberState(8+4*M)+count(4) = 28+4*M octets; only the E flag.

(defun* write-nack-frag (cursor reader-id writer-id writer-sn base numbits bitmap count)
    (function (dds.core.buffer:cursor (unsigned-byte 32) (unsigned-byte 32) integer (unsigned-byte 32) (unsigned-byte 32) (simple-array (unsigned-byte 32) (*)) (unsigned-byte 32)) fixnum)
  "Write a NACK_FRAG submessage. RTPS 2.5 §9.4.5.14; body=28+4*M."
  ;; §9.4.5.14 + §9.4.2.8: 4+4+8 + (8+4*M) + 4 = 28+4*M (Connext emits 32 for M=1)
  (write-submessage-header cursor +submsg-nack-frag+ (%e-flag cursor)
                           (+ 28 (* 4 (%seqnum-set-words numbits))))
  (write-entity-id cursor reader-id)
  (write-entity-id cursor writer-id)
  (write-sequence-number cursor writer-sn)
  (write-fragment-number-set cursor base numbits bitmap)
  (dds.core.buffer:put-u32 cursor (logand count #xFFFFFFFF))
  (dds.core.buffer:cursor-position cursor))

(defun* parse-nack-frag-body (cursor flags)
    (function (dds.core.buffer:cursor (unsigned-byte 8)) t)
  "Parse a NACK_FRAG body. Returns (values reader-id writer-id writer-sn base numbits
   bitmap count) or NIL on short/invalid buffer. RTPS 2.5 §9.4.5.14."
  (declare (ignore flags))
  (when (< (%remaining cursor) 16) (return-from parse-nack-frag-body nil))
  (let ((reader-id (read-entity-id cursor))
        (writer-id (read-entity-id cursor))
        (writer-sn (read-sequence-number cursor)))
    (multiple-value-bind (base numbits bitmap) (read-fragment-number-set cursor)
      (when (null base) (return-from parse-nack-frag-body nil))
      (when (< (%remaining cursor) 4) (return-from parse-nack-frag-body nil))
      (values reader-id writer-id writer-sn base numbits bitmap
              (dds.core.buffer:get-u32 cursor)))))

;;; ---- DATA submessage (§9.4.5.4): extraFlags + octetsToInlineQos + readerId +
;;; writerId + writerSN + [inlineQos if Q] + serializedPayload [if D||K]. v1 emits
;;; and parses the base form (Q=0; inlineQos parsing lands with the ParameterList
;;; / discovery increment). serializedPayload is passed/returned as a byte region.

(defconstant +data-flag-inline-qos+    #x02
  "DATA InlineQosFlag (Q): inlineQos present (RTPS 2.5 §9.4.5.4).")
(defconstant +data-flag-data+          #x04
  "DATA DataFlag (D): serializedPayload carries data (RTPS 2.5 §9.4.5.4).")
(defconstant +data-flag-key+           #x08
  "DATA KeyFlag (K): serializedPayload carries a key (RTPS 2.5 §9.4.5.4).")
(defconstant +data-flag-non-standard+  #x10
  "DATA NonStandardPayloadFlag (N) (RTPS 2.5 §9.4.5.4).")

;; StatusInfo_t (RTPS 2.5 §9.6.4.9): octet[4]; the last octet holds the flags ...F|U|D
;; (D=bit0, U=bit1, F=bit2). Big-endian octet array, so the flags live in byte index 3.
(defconstant +statusinfo-disposed+     #x01
  "StatusInfo_t DisposedFlag (D): the instance was disposed (RTPS 2.5 §9.6.4.9).")
(defconstant +statusinfo-unregistered+ #x02
  "StatusInfo_t UnregisteredFlag (U): the instance was unregistered (RTPS 2.5 §9.6.4.9).")
(defconstant +statusinfo-filtered+     #x04
  "StatusInfo_t FilteredFlag (F): the sample did not pass the reader filter (RTPS 2.5 §9.6.4.9).")

(defun* status-info->kind (status-flags)
    (function ((unsigned-byte 8)) (member :data :dispose :unregister))
  "Derive the CacheChange kind from StatusInfo_t flags (RTPS 2.5 §9.6.4.9): U=1 ->
   :unregister (dominates), else D=1 -> :dispose, else :data. FilteredFlag does not
   change the kind (it qualifies an ALIVE write)."
  (cond ((logtest status-flags +statusinfo-unregistered+) :unregister)
        ((logtest status-flags +statusinfo-disposed+) :dispose)
        (t :data)))

(defun* write-status-info-inline-qos (cursor key-hash status-flags)
    (function (dds.core.buffer:cursor (simple-array (unsigned-byte 8) (*)) (unsigned-byte 8)) fixnum)
  "Write a dispose/unregister inlineQos ParameterList into CURSOR: PID_KEY_HASH (the
   16-octet KEY-HASH, RTPS 2.5 §9.6.4.8) + PID_STATUS_INFO (StatusInfo_t octet[4], the
   STATUS-FLAGS in the last octet, §9.6.4.9) + PID_SENTINEL. Reuses write-parameter so the
   4-byte alignment + sentinel rules stay in one place (§9.4.2.11). Returns the new position."
  (let ((si (make-array 4 :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref si 3) status-flags)                ; StatusInfo_t flags occupy the last octet
    (write-parameter cursor +pid-key-hash+ key-hash 0 16)
    (write-parameter cursor +pid-status-info+ si 0 4)
    (write-parameter-sentinel cursor)))

(defun* parse-inline-qos-key-status (cursor body-end &optional (capture-key-hash t))
    (function (dds.core.buffer:cursor fixnum &optional t) t)
  "Walk an inlineQos ParameterList (RTPS 2.5 §9.4.2.11) bounded by BODY-END, extracting
   PID_KEY_HASH (KeyHash_t octet[16], §9.6.4.8), PID_STATUS_INFO (StatusInfo_t octet[4],
   §9.6.4.9), and PID_ORIGINAL_WRITER_INFO (GuidPrefix_t[12]+EntityId_t[4]+SequenceNumber_t[8],
   §8.3.5.4). Returns (values key-hash status-flags walk-ok original-guid original-sn).
   KEY-HASH is a fresh 16-octet array or NIL; STATUS-FLAGS is the last StatusInfo octet (0 if
   absent); WALK-OK is NIL when the list ran off BODY-END without a sentinel; ORIGINAL-GUID is
   a fresh 16-octet array (GuidPrefix+EntityId) or NIL; ORIGINAL-SN is an integer or NIL.
   When CAPTURE-KEY-HASH is NIL the key-hash is NOT materialized (zero per-sample allocation
   on the hot keyed-DATA path). Unknown PIDs are skipped. Every read is bounds-checked against
   BODY-END FIRST (NFR-SEC-POSTURE); a KEY_HASH not exactly 16 / STATUS_INFO not exactly 4 /
   ORIGINAL_WRITER_INFO not exactly 24 octets is ignored, never trusted."
  (let ((key-hash nil) (status-flags 0) (original-guid nil) (original-sn nil))
    (loop
      (when (> (+ (dds.core.buffer:cursor-position cursor) 4) body-end)
        (return (values key-hash status-flags nil original-guid original-sn)))
      (let ((pid (dds.core.buffer:get-u16 cursor))
            (plen (dds.core.buffer:get-u16 cursor)))
        (when (= pid +pid-sentinel+)
          (return (values key-hash status-flags t original-guid original-sn)))
        (let ((value-start (dds.core.buffer:cursor-position cursor)))
          (when (> (+ value-start plen) body-end)
            (return (values key-hash status-flags nil original-guid original-sn)))
          (cond
            ((and capture-key-hash (= pid +pid-key-hash+) (= plen 16))
             (let ((kh (make-array 16 :element-type '(unsigned-byte 8))))
               (dds.core.buffer:get-octets cursor kh 0 16)
               (setf key-hash kh)))
            ((and (= pid +pid-status-info+) (= plen 4))
             (dds.core.buffer:get-u8 cursor) (dds.core.buffer:get-u8 cursor)
             (dds.core.buffer:get-u8 cursor)
             (setf status-flags (dds.core.buffer:get-u8 cursor)))
            ((= pid +pid-original-writer-info+)
             ;; PID_ORIGINAL_WRITER_INFO body: 24 octets (RTPS 2.5 §8.3.5.4):
             ;;   GuidPrefix_t[12] + EntityId_t[4] + SequenceNumber_t high(i32)[4] + low(u32)[4]
             (multiple-value-bind (g s) (parse-original-writer-info
                                         (dds.core.buffer:octet-buffer-vec
                                          (dds.core.buffer:cursor-buffer cursor))
                                         value-start plen)
               (when g (setf original-guid g original-sn s)))))
          (dds.core.buffer:cursor-set-position cursor (+ value-start plen)))))))

(defun* write-data-dispose (cursor reader-id writer-id writer-sn key-hash status-flags)
    (function (dds.core.buffer:cursor (unsigned-byte 32) (unsigned-byte 32) integer (simple-array (unsigned-byte 8) (*)) (unsigned-byte 8)) fixnum)
  "Write a complete dispose/unregister DATA submessage (RTPS 2.5 §9.4.5.4 + §9.6.4.9):
   flags E+Q only — D clear, K clear, NO serializedPayload; the instance is named by
   PID_KEY_HASH and the lifecycle transition by PID_STATUS_INFO (STATUS-FLAGS). Wire form
   resolved from the conformant Fast DDS oracle. octetsToInlineQos=16; the body is the
   20-octet fixed prefix + a 32-octet inlineQos (KEY_HASH 4+16, STATUS_INFO 4+4, SENTINEL 4)."
  (write-submessage-header cursor +submsg-data+
                           (logior (%e-flag cursor) +data-flag-inline-qos+)
                           52)
  (dds.core.buffer:put-u16 cursor 0)               ; extraFlags = 0 (this version)
  (dds.core.buffer:put-u16 cursor 16)              ; octetsToInlineQos = 16
  (write-entity-id cursor reader-id)
  (write-entity-id cursor writer-id)
  (write-sequence-number cursor writer-sn)
  (write-status-info-inline-qos cursor key-hash status-flags)
  (dds.core.buffer:cursor-position cursor))

(defun* write-data (cursor reader-id writer-id writer-sn payload payload-off payload-len
                   &key key inline-qos)
    (function (dds.core.buffer:cursor (unsigned-byte 32) (unsigned-byte 32) integer
               (simple-array (unsigned-byte 8) (*)) (integer 0) (integer 0)
               &key (:key t) (:inline-qos (or null (simple-array (unsigned-byte 8) (*))))) fixnum)
  "Write a complete DATA submessage (RTPS 2.5 §9.4.5.4). KEY t → K=1,D=0; else D=1,K=0.
   INLINE-QOS (or nil): when non-nil the caller supplies a COMPLETE, PID_SENTINEL-terminated
   ParameterList octet vector; write-data ORs +data-flag-inline-qos+ into the flags, adds the
   (length inline-qos) to octetsToNextHeader, and writes the bytes verbatim between the 20-octet
   fixed body prefix and the serializedPayload (caller is responsible for 4-octet alignment,
   which holds as long as inline-qos bytes are a multiple of 4 — true for all standard parameters).
   When nil: byte-identical to the prior no-inline-qos form (Q-bit clear, octetsToNextHeader
   unchanged). Design choice: the caller passes the FULL pre-framed block (simplest — write-data
   just length-accounts and copies). §9.4.5.4 / §9.4.2.11."
  (let ((iq-len (if inline-qos (length inline-qos) 0)))
    (write-submessage-header cursor +submsg-data+
                             (logior (%e-flag cursor)
                                     (if key +data-flag-key+ +data-flag-data+)
                                     (if inline-qos +data-flag-inline-qos+ 0))
                             (+ 20 iq-len payload-len))
    (dds.core.buffer:put-u16 cursor 0)           ; extraFlags = 0 (this version)
    (dds.core.buffer:put-u16 cursor 16)          ; octetsToInlineQos = 16
    (write-entity-id cursor reader-id)
    (write-entity-id cursor writer-id)
    (write-sequence-number cursor writer-sn)
    (when inline-qos (dds.core.buffer:put-octets cursor inline-qos 0 iq-len))
    (dds.core.buffer:put-octets cursor payload payload-off payload-len)
    (dds.core.buffer:cursor-position cursor)))

(defun* %skip-inline-qos (cursor body-end)
    (function (dds.core.buffer:cursor fixnum) t)
  "Advance CURSOR past an inlineQos ParameterList (each Parameter = id+len header then len
   value octets, already 4-aligned) up to PID_SENTINEL. Every read is bounds-checked
   against BODY-END FIRST (NFR-SEC-POSTURE). Returns T on success, NIL if it would read
   past BODY-END or runs off the end without a sentinel. RTPS 2.5 §9.4.2.11."
  (loop
    (when (> (+ (dds.core.buffer:cursor-position cursor) 4) body-end) (return nil))
    (let ((pid (dds.core.buffer:get-u16 cursor))
          (plen (dds.core.buffer:get-u16 cursor)))
      (when (= pid +pid-sentinel+) (return t))
      (let ((next (+ (dds.core.buffer:cursor-position cursor) plen)))
        (when (> next body-end) (return nil))
        (dds.core.buffer:cursor-set-position cursor next)))))

(defun* parse-data-body (cursor flags octets-to-next &optional capture-data-key-hash)
    (function (dds.core.buffer:cursor (unsigned-byte 8) (unsigned-byte 16) &optional t) t)
  "Parse a DATA body. Returns (values reader-id writer-id writer-sn has-payload
   payload-offset payload-len key-p change-kind key-hash status-flags original-guid original-sn),
   or NIL if the buffer is short / malformed. When the InlineQos flag (Q) is set the inlineQos
   ParameterList is walked (bounds-checked, parse-inline-qos-key-status) — PID_STATUS_INFO
   yields STATUS-FLAGS (§9.6.4.9) and the derived CHANGE-KIND (:data/:dispose/:unregister);
   the 16-octet KEY-HASH is materialized for a no-payload lifecycle change OR when
   CAPTURE-DATA-KEY-HASH is non-NIL (durability collect node opts in; default NIL = zero per-sample
   allocation on the hot keyed-DATA path); PID_ORIGINAL_WRITER_INFO yields ORIGINAL-GUID (16
   octets) and ORIGINAL-SN or nil/nil when absent (§8.3.5.4). RTPS 2.5 §9.4.5.4 + §9.6.4.9."
  (let* ((body-start (dds.core.buffer:cursor-position cursor))
         (cap (dds.core.buffer:octet-buffer-capacity (dds.core.buffer:cursor-buffer cursor)))
         (body-end (if (plusp octets-to-next) (min (+ body-start octets-to-next) cap) cap)))
    (when (< (- body-end body-start) 20) (return-from parse-data-body nil))
    (dds.core.buffer:get-u16 cursor)             ; extraFlags (reserved)
    (dds.core.buffer:get-u16 cursor)             ; octetsToInlineQos
    (let ((reader (read-entity-id cursor))
          (writer (read-entity-id cursor))
          (sn (read-sequence-number cursor))
          (has-payload (logtest flags (logior +data-flag-data+ +data-flag-key+)))
          (key-hash nil) (status-flags 0) (original-guid nil) (original-sn nil))
      (when (logtest flags +data-flag-inline-qos+)
        (multiple-value-bind (kh sf ok og os)
            (parse-inline-qos-key-status cursor body-end (or (not has-payload) capture-data-key-hash))
          (unless ok (return-from parse-data-body nil))
          (setf key-hash kh status-flags sf original-guid og original-sn os)))
      (let* ((poff (dds.core.buffer:cursor-position cursor))
             (len (- body-end poff)))
        (when (< len 0) (return-from parse-data-body nil))
        (values reader writer sn has-payload poff
                (if has-payload len 0) (logtest flags +data-flag-key+)
                (status-info->kind status-flags) key-hash status-flags
                original-guid original-sn)))))

;;; ---- DATA_FRAG submessage (§9.4.5.5): extraFlags + octetsToInlineQos + readerId +
;;; writerId + writerSN + fragmentStartingNum(u32) + fragmentsInSubmessage(u16) +
;;; fragmentSize(u16) + sampleSize(u32) + [inlineQos if Q] + serializedPayload. Flags
;;; pinned from §9.4.5.5: E=0x01, Q=0x02, K=0x04, N=0x08. One fragment series per
;;; submessage; reassembly + resource guards live in the data plane. ----

(defconstant +data-frag-flag-inline-qos+ #x02
  "DATA_FRAG InlineQosFlag (Q) (RTPS 2.5 §9.4.5.5).")
(defconstant +data-frag-flag-key+        #x04
  "DATA_FRAG KeyFlag (K): the fragments carry the key, not the data (RTPS 2.5 §9.4.5.5).")

(defun* write-data-frag (cursor reader-id writer-id sn sample-size frag-start frags-in-submsg frag-size
                        payload payload-off payload-len &key key)
    (function (dds.core.buffer:cursor (unsigned-byte 32) (unsigned-byte 32) integer (unsigned-byte 32) (unsigned-byte 32) (unsigned-byte 16) (unsigned-byte 16) (simple-array (unsigned-byte 8) (*)) (integer 0) (integer 0) &key (:key t)) fixnum)
  "Write one DATA_FRAG submessage (RTPS 2.5 §9.4.5.5), no inlineQos. Carries the bytes
   [PAYLOAD-OFF, PAYLOAD-OFF+PAYLOAD-LEN) — FRAGS-IN-SUBMSG consecutive fragments of size
   FRAG-SIZE starting at the 1-based FRAG-START — of the SAMPLE-SIZE-byte serialized sample.
   KEY t sets the K flag (key fragments). Body = 32 + PAYLOAD-LEN."
  (write-submessage-header cursor +submsg-data-frag+
                           (logior (%e-flag cursor) (if key +data-frag-flag-key+ 0))
                           (+ 32 payload-len))
  (dds.core.buffer:put-u16 cursor 0)             ; extraFlags
  (dds.core.buffer:put-u16 cursor 28)            ; octetsToInlineQos (to inlineQos start)
  (write-entity-id cursor reader-id)
  (write-entity-id cursor writer-id)
  (write-sequence-number cursor sn)
  (dds.core.buffer:put-u32 cursor frag-start)
  (dds.core.buffer:put-u16 cursor frags-in-submsg)
  (dds.core.buffer:put-u16 cursor frag-size)
  (dds.core.buffer:put-u32 cursor sample-size)
  (dds.core.buffer:put-octets cursor payload payload-off payload-len)
  (dds.core.buffer:cursor-position cursor))

(defun* parse-data-frag-body (cursor flags octets-to-next)
    (function (dds.core.buffer:cursor (unsigned-byte 8) (unsigned-byte 16)) t)
  "Parse a DATA_FRAG body (RTPS 2.5 §9.4.5.5). Returns (values reader-id writer-id writer-sn
   sample-size frag-start frags-in-submsg frag-size payload-offset payload-len key-p), or NIL
   if short / malformed / spec-invalid (frag-start not strictly positive, frag-size > sample-
   size, frags-in-submsg 0). inlineQos (Q) is skipped, bounds-checked (NFR-SEC-POSTURE). The
   payload (the fragment bytes) is left in place at PAYLOAD-OFFSET."
  (let* ((body-start (dds.core.buffer:cursor-position cursor))
         (cap (dds.core.buffer:octet-buffer-capacity (dds.core.buffer:cursor-buffer cursor)))
         (body-end (if (plusp octets-to-next) (min (+ body-start octets-to-next) cap) cap)))
    (when (< (- body-end body-start) 32) (return-from parse-data-frag-body nil))
    (dds.core.buffer:get-u16 cursor)             ; extraFlags
    (dds.core.buffer:get-u16 cursor)             ; octetsToInlineQos
    (let ((reader (read-entity-id cursor))
          (writer (read-entity-id cursor))
          (sn (read-sequence-number cursor))
          (frag-start (dds.core.buffer:get-u32 cursor))
          (frags (dds.core.buffer:get-u16 cursor))
          (frag-size (dds.core.buffer:get-u16 cursor))
          (sample-size (dds.core.buffer:get-u32 cursor)))
      (when (or (zerop frag-start) (zerop frags) (> frag-size sample-size))
        (return-from parse-data-frag-body nil))
      (when (logtest flags +data-frag-flag-inline-qos+)
        (unless (%skip-inline-qos cursor body-end) (return-from parse-data-frag-body nil)))
      (let* ((poff (dds.core.buffer:cursor-position cursor))
             (len (- body-end poff)))
        (when (< len 0) (return-from parse-data-frag-body nil))
        (values reader writer sn sample-size frag-start frags frag-size poff len
                (logtest flags +data-frag-flag-key+))))))

;;; ---- ParameterList (§9.4.2.11, FR-RTPS-9): a list of (parameterId, length,
;;; value) Parameters, each 4-byte aligned, terminated by PID_SENTINEL. PID
;;; constants from the RTPS 2.5 §9.6.2.2 table, never memorized. ----

(defconstant +pid-pad+                        #x0000
  "PID_PAD (RTPS 2.5 §9.6.2.2 table).")
(defconstant +pid-sentinel+                   #x0001
  "PID_SENTINEL, terminates a ParameterList (RTPS 2.5 §9.6.2.2 / §9.4.2.11).")
(defconstant +pid-participant-lease-duration+ #x0002
  "PID_PARTICIPANT_LEASE_DURATION (RTPS 2.5 §9.6.2.2 table).")
(defconstant +pid-topic-name+                 #x0005
  "PID_TOPIC_NAME (RTPS 2.5 §9.6.2.2 table).")
(defconstant +pid-type-name+                  #x0007
  "PID_TYPE_NAME (RTPS 2.5 §9.6.2.2 table).")
(defconstant +pid-ownership-strength+         #x0006
  "PID_OWNERSHIP_STRENGTH -> OwnershipStrengthQosPolicy {long value} (RTPS 2.5 Table 9.18
   §9.6.2.2; DDS 1.4 dds_rtf2_dcps.idl §2.2.3.10). Carried in DataWriterQos only (writer-only).")
(defconstant +pid-protocol-version+           #x0015
  "PID_PROTOCOL_VERSION (RTPS 2.5 §9.6.2.2 table).")
(defconstant +pid-vendorid+                   #x0016
  "PID_VENDORID (RTPS 2.5 §9.6.2.2 table).")
(defconstant +pid-reliability+                #x001a
  "PID_RELIABILITY (RTPS 2.5 §9.6.2.2 table).")
(defconstant +pid-liveliness+                 #x001b
  "PID_LIVELINESS -> LivelinessQosPolicy (RTPS 2.5 Table 9.18, §9.6.2.2).")
(defconstant +pid-durability+                 #x001d
  "PID_DURABILITY (RTPS 2.5 §9.6.3.2).")
(defconstant +pid-ownership+                   #x001f
  "PID_OWNERSHIP -> OwnershipQosPolicy {OwnershipQosPolicyKind kind} (RTPS 2.5 Table 9.18
   §9.6.2.2; DDS 1.4 dds_rtf2_dcps.idl §2.2.3.9). kind u32: SHARED_OWNERSHIP_QOS=0,
   EXCLUSIVE_OWNERSHIP_QOS=1.")
(defconstant +pid-default-unicast-locator+    #x0031
  "PID_DEFAULT_UNICAST_LOCATOR (RTPS 2.5 §9.6.2.2 table).")
(defconstant +pid-metatraffic-unicast-locator+ #x0032
  "PID_METATRAFFIC_UNICAST_LOCATOR (RTPS 2.5 §9.6.2.2 table).")
(defconstant +pid-participant-guid+           #x0050
  "PID_PARTICIPANT_GUID (RTPS 2.5 §9.6.2.2 table).")
(defconstant +pid-builtin-endpoint-set+       #x0058
  "PID_BUILTIN_ENDPOINT_SET (RTPS 2.5 §9.6.2.2 table).")
(defconstant +pid-endpoint-guid+              #x005a
  "PID_ENDPOINT_GUID (RTPS 2.5 §9.6.2.2 table).")
(defconstant +pid-key-hash+                   #x0070
  "PID_KEY_HASH (RTPS 2.5 §9.6.2.2 table).")
(defconstant +pid-status-info+                #x0071
  "PID_STATUS_INFO -> StatusInfo_t (RTPS 2.5 Table 9.23, §9.6.4.9).")
(defconstant +pid-data-representation+        #x0073
  "PID_DATA_REPRESENTATION -> DataRepresentationQosPolicy {sequence<DataRepresentationId_t> value}
   (DDS-XTypes 1.3 §7.6.3.1.1; @id(0x0073) in the discovery-builtin-topic IDL). The value is a
   CDR sequence<short>: u32 count + count*short (XCDR_DATA_REPRESENTATION=0/XML=1/XCDR2=2), padded to 4.
   The policy struct is APPENDABLE, so a peer (e.g. RTI) may append trailing members the reader ignores.")
(defconstant +pid-type-information+           #x0075
  "PID_TYPE_INFORMATION (DDS-XTypes 1.3 BuiltinTopicData @id(0x0075)).")
(defconstant +pid-entity-virtual-guid+        #x8002
  "PID_ENTITY_VIRTUAL_GUID — RTI vendor SEDP PID (0x8002; eProsima names it PID_PERSISTENCE_GUID).
   16-byte GUID of the original writer this relay endpoint represents. Emitted by a Persistence Service
   relay writer in its SEDP announcement; triggers Connext receiver-side PID_ORIGINAL_WRITER_INFO dedup.
   Observed in live Connext 7.3.1 PS capture (spike 2026-06-18). Vendor range, fail-open for receivers
   that ignore it (RTPS 2.5 §8.3.5.10).")
(defconstant +pid-service-kind+               #x8003
  "PID_SERVICE_KIND — RTI vendor SEDP PID (0x8003), u32 LE. Value 1 = PERSISTENCE_SERVICE_QOS.
   Emitted by a Persistence Service relay writer in its SEDP announcement; gates Connext receiver-side
   PID_ORIGINAL_WRITER_INFO dedup (Connext only applies inline-QoS dedup when the relay announces
   SERVICE_KIND=PERSISTENCE_SERVICE). Observed in live Connext 7.3.1 PS capture (spike 2026-06-18).
   Vendor range, fail-open for receivers that ignore it (RTPS 2.5 §8.3.5.10).")
(defconstant +service-kind-persistence+       #x00000001
  "PERSISTENCE_SERVICE_QOS wire value for PID_SERVICE_KIND (0x8003, RTI vendor). u32 LE = 1.
   Connext activation gate for receiver-side PID_ORIGINAL_WRITER_INFO dedup (spike 2026-06-18).")
(defconstant +pid-type-object-lb+             #x8021
  "PID_TYPE_OBJECT_LB — RTI Connext VENDOR parameter (high-bit 0x8000 vendor range) carrying
   a ZLIB-compressed complete TypeObject. NOT an OMG-spec PID; value observed on the live
   Connext 7.3.1 wire (ADR 0009). Parsed inbound only; never emitted (clean-room).")
(defconstant +pid-shmem-host-uuid+            #x8040
  "PID_SHMEM_HOST_UUID — OUR vendor parameter (high-bit 0x8000 vendor range) carrying an
   8-octet same-host UUID (u64 LE) for SHMEM peer selection. NOT an OMG-spec PID; value
   pinned in ADR 0013, not from any spec clause. Cross-vendor peers ignore an unknown PID
   (fail-open), so it is purely additive to SPDP.")
;;;; NOT cleared for ship — pending counsel (R6); see ADR 0014.
(defconstant +pid-zerocopy-capable+           #x8041
  "Vendor PID (1 octet, 1 = endpoint understands WP-ZEROCOPY references). ADR 0014; ours, NOT a spec clause.")
(defconstant +pid-original-writer-info+       #x0061
  "PID_ORIGINAL_WRITER_INFO — GUID + SequenceNumber of the original writer (RTPS 2.5 §8.3.5.4, Table 9.12).
   Carried in inline-QoS of DATA/DATA_FRAG sent by a Persistence Service replaying retained samples to late
   joiners; lets receivers deduplicate against samples already received from the live writer.")

(defun* encode-original-writer-info (guid sn)
    (function ((simple-array (unsigned-byte 8) (16)) (integer 0)) (simple-array (unsigned-byte 8) (24)))
  "Encode a 24-octet OriginalWriterInfo body LE: bytes 0-15 = GUID verbatim; bytes 16-19 = SN.high (i32 LE);
   bytes 20-23 = SN.low (u32 LE). RTPS 2.5 §8.3.5.4 / Table 9.12."
  (let ((body (make-array 24 :element-type '(unsigned-byte 8) :initial-element 0))
        (high (logand (ash sn -32) #xFFFFFFFF))
        (low  (logand sn #xFFFFFFFF)))
    (replace body guid :start1 0 :end1 16)
    (setf (aref body 16) (ldb (byte 8  0) high)
          (aref body 17) (ldb (byte 8  8) high)
          (aref body 18) (ldb (byte 8 16) high)
          (aref body 19) (ldb (byte 8 24) high)
          (aref body 20) (ldb (byte 8  0) low)
          (aref body 21) (ldb (byte 8  8) low)
          (aref body 22) (ldb (byte 8 16) low)
          (aref body 23) (ldb (byte 8 24) low))
    body))

(defun* parse-original-writer-info (octets off len)
    (function ((simple-array (unsigned-byte 8) (*)) (integer 0) (integer 0)) t)
  "Parse a 24-octet OriginalWriterInfo body from OCTETS at offset OFF with wire length LEN.
   Returns (values guid sn) or (values nil nil) if LEN /= 24 or body overruns OCTETS.
   Bounds-checked; never reads OOB (NFR-SEC-POSTURE). RTPS 2.5 §8.3.5.4 / Table 9.12."
  (when (or (/= len 24) (> (+ off 24) (length octets)))
    (return-from parse-original-writer-info (values nil nil)))
  (let ((guid (make-array 16 :element-type '(unsigned-byte 8)))
        (high 0)
        (low  0))
    (replace guid octets :start1 0 :end1 16 :start2 off :end2 (+ off 16))
    (setf high (logior (aref octets (+ off 16))
                       (ash (aref octets (+ off 17)) 8)
                       (ash (aref octets (+ off 18)) 16)
                       (ash (aref octets (+ off 19)) 24)))
    (setf low  (logior (aref octets (+ off 20))
                       (ash (aref octets (+ off 21)) 8)
                       (ash (aref octets (+ off 22)) 16)
                       (ash (aref octets (+ off 23)) 24)))
    (when (>= high #x80000000) (setf high (- high #x100000000)))
    (values guid (+ low (* high #x100000000)))))

(defun* write-original-writer-info-parameter (cursor guid sn)
    (function (dds.core.buffer:cursor (simple-array (unsigned-byte 8) (16)) (integer 0)) fixnum)
  "Write a complete PID_ORIGINAL_WRITER_INFO parameter (pid + len=24 + body) via WRITE-PARAMETER.
   RTPS 2.5 §8.3.5.4 / Table 9.12; 24-octet body is always a multiple of 4, no padding needed."
  (write-parameter cursor +pid-original-writer-info+ (encode-original-writer-info guid sn) 0 24))

(defun* write-parameter (cursor pid value off len)
    (function (dds.core.buffer:cursor (unsigned-byte 16) (simple-array (unsigned-byte 8) (*)) (integer 0) (integer 0)) fixnum)
  "Write one Parameter: pid + length (padded to a multiple of 4) + value +
   padding. RTPS 2.5 §9.4.2.11; the ParameterList must start 4-byte aligned."
  (let ((padded (* 4 (ceiling len 4))))
    (dds.core.buffer:put-u16 cursor pid)
    (dds.core.buffer:put-u16 cursor padded)
    (dds.core.buffer:put-octets cursor value off len)
    (dotimes (i (- padded len)) (dds.core.buffer:put-u8 cursor 0))
    (dds.core.buffer:cursor-position cursor)))

(defun* write-parameter-sentinel (cursor)
    (function (dds.core.buffer:cursor) fixnum)
  "Write PID_SENTINEL, terminating a ParameterList (RTPS 2.5 §9.4.2.11)."
  (dds.core.buffer:put-u16 cursor +pid-sentinel+)
  (dds.core.buffer:put-u16 cursor 0)
  (dds.core.buffer:cursor-position cursor))

(defun* parse-parameter-list (cursor handler)
    (function (dds.core.buffer:cursor function) t)
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

(defun* spdp-multicast-port (domain)
    (function ((integer 0)) (integer 0))
  "Discovery (SPDP) multicast port: PB + DG*domain + d0 (RTPS 2.5 §9.6.1.1)."
  (+ +port-base+ (* +port-domain-gain+ domain) +port-d0+))

(defun* spdp-unicast-port (domain participant-id)
    (function ((integer 0) (integer 0)) (integer 0))
  "Discovery (SPDP) unicast port: PB + DG*domain + d1 + PG*participantId."
  (+ +port-base+ (* +port-domain-gain+ domain) +port-d1+ (* +port-participant-gain+ participant-id)))

(defun* user-multicast-port (domain)
    (function ((integer 0)) (integer 0))
  "User-traffic multicast port: PB + DG*domain + d2 (RTPS 2.5 §9.6.1.1)."
  (+ +port-base+ (* +port-domain-gain+ domain) +port-d2+))

(defun* user-unicast-port (domain participant-id)
    (function ((integer 0) (integer 0)) (integer 0))
  "User-traffic unicast port: PB + DG*domain + d3 + PG*participantId."
  (+ +port-base+ (* +port-domain-gain+ domain) +port-d3+ (* +port-participant-gain+ participant-id)))

;;; ---- RTPS Message receive loop (§8.3.4 / §9.4.5): parse the Header then walk
;;; the submessages, dispatching each to a handler. Each submessage's endianness
;;; comes from its E flag; octetsToNextHeader (0 = extends to the end) frames the
;;; next one. Bounds-checked throughout (NFR-SEC-POSTURE). ----

(defun* dispatch-message (cursor handler &optional msg-end)
    (function (dds.core.buffer:cursor function &optional (integer 0)) t)
  "Parse an RTPS message; for each submessage call (HANDLER id flags cursor
   body-len) with the cursor at the body and its endianness set per the E flag.
   MSG-END bounds the message (e.g. a UDP datagram size); defaults to the buffer
   capacity. Returns T on a well-formed message, NIL on bad magic / truncation."
  (let ((end (or msg-end
                 (dds.core.buffer:octet-buffer-capacity (dds.core.buffer:cursor-buffer cursor)))))
    (unless (parse-header cursor) (return-from dispatch-message nil))
    (loop
      (when (< (- end (dds.core.buffer:cursor-position cursor)) 4) (return t))
      (multiple-value-bind (id flags octets le) (parse-submessage-header cursor)
        (when (null id) (return nil))
        (dds.core.buffer:cursor-set-endianness cursor (if le :little :big))
        (let* ((body-start (dds.core.buffer:cursor-position cursor))
               (avail (- end body-start))
               (body-len (if (plusp octets) octets avail)))
          (when (> body-len avail) (return nil))
          (funcall handler id flags cursor body-len)
          (dds.core.buffer:cursor-set-position cursor (+ body-start body-len)))))))
