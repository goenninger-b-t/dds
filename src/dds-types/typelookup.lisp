;;;; TypeLookup_Request XCDR2 codec (M4, FR-TYPE-3). XTypes 1.3 §7.6.3.3: the built-in
;;;; TypeLookup service request type, TypeLookup_Request { dds::rpc::RequestHeader header;
;;;; TypeLookup_Call data; } (§7.6.3.3.3), with the DDS-RPC header types copied in
;;;; §7.6.3.3.2 (GUID_t = 12-octet prefix + 4-octet entityId; SequenceNumber_t = long high
;;;; + unsigned long low; RequestHeader = SampleIdentity requestId + string<255> instanceName).
;;;;
;;;; NO Connext oracle exists for this protocol (ADR 0010: RTI does not implement the
;;;; builtin TypeLookup service); the framing follows the de-facto interop convention of
;;;; the designated FR-IO-2 oracle, Fast DDS (whose rpc_types.idl/TypeLookupTypes.idl pin
;;;; every RPC header struct and the top-level Request/Reply @final), which the
;;;; Wireshark/tshark RTPS dissector implements verbatim. The framing choices are now
;;;; PEER-CONFIRMED against live Fast DDS 3.6.1 (FR-IO-2 S4, 2026-06-12: leg A
;;;; s4-ourclient-lo0.pcap frs 85-87, our client vs their server; leg B-patched
;;;; s4-theirclient-patched-lo0.pcap frs 2494-2498, their client vs our server — see
;;;; interop/fastdds/README.md "CONFIRM-VS-PEER walk"): (1) the spec IDL (§7.6.3.3.3)
;;;; leaves TypeLookup_Request/Reply unannotated — the §7.3.1.2.1.8 default would be
;;;; appendable — but the implemented convention is FINAL => PLAIN_CDR2, encapsulation
;;;; CDR2_LE {0x00,0x07} (Table 60, §7.6.3.1.2), NO top-level DHEADER [PEER-CONFIRMED:
;;;; every live frame both directions]. (2) The DDS-RPC header structs are FINAL => flat;
;;;; the TypeLookup_Call/Return/Result unions are unannotated => default appendable =>
;;;; each carries a DHEADER before its discriminator (§7.4.3.4.1 + §7.4.3.5.3 rule (30))
;;;; [PEER-CONFIRMED: their fr 2496 Call DHEADER; their fr 86 Return+Result DHEADERs;
;;;; ours consumed both directions]. (3) The MUTABLE *_In/*_Out members use EMHEADER1
;;;; LC=5: NEXTINT doubles as the member value's leading UInt32 (DHEADER / element count)
;;;; per serialization rule (22) (§7.4.3.5.3), matching the Fast CDR encoder
;;;; [PEER-CONFIRMED: their frs 86/2496 emit LC=5; our LC=5 frames consumed]. (4) type_ids
;;;; elements are EK_MINIMAL/EK_COMPLETE hash-defined TypeIdentifiers only (the only kinds
;;;; a request for a TypeObject can name that we serve); other TypeIdentifier kinds reject
;;;; on parse. CONFIRM-VS-PEER stays open only for: a live non-OK reply (Return-arm
;;;; omission — self-pinned, tshark-validated) and non-CDR2_LE encapsulations (both peers
;;;; only ever emitted CDR2_LE).

(in-package #:dds.types)

(defconstant +tl-gettypes-hash+ #x018252d3
  "TypeLookup_getTypes_HashId: the TypeLookup_Call discriminator selecting getTypes
   (XTypes 1.3 §7.6.3.3.3, 'computed from @hashid(\"getTypes\")').")

(defconstant +tl-getdeps-hash+ #x05aafb31
  "TypeLookup_getDependencies_HashId: the TypeLookup_Call discriminator selecting
   getTypeDependencies (XTypes 1.3 §7.6.3.3.3, 'computed from @hashid(\"getDependencies\")').")

;; @hashid("type_ids") §7.3.1.2.1.1: MD5[0:4]={65 60 53 6c} LE=#x6C536065 AND #x0FFFFFFF (test re-derives)
(defconstant +tl-member-type-ids+ #x0C536065
  "Member id of the @hashid type_ids member of TypeLookup_getTypes_In /
   TypeLookup_getTypeDependencies_In (XTypes 1.3 §7.6.3.3.3 + §7.3.1.2.1.1).")

;; @hashid("continuation_point") §7.3.1.2.1.1: MD5[0:4]={d2 e3 08 35} LE=#x3508E3D2 AND #x0FFFFFFF
(defconstant +tl-member-continuation-point+ #x0508E3D2
  "Member id of the @hashid continuation_point member of TypeLookup_getTypeDependencies_In
   (XTypes 1.3 §7.6.3.3.3 + §7.3.1.2.1.1).")

;; FINAL top level (Fast DDS @final convention; spec IDL unannotated). PEER-CONFIRMED.
(defconstant +tl-encap-cdr2-le+ #x0007
  "RTPS encapsulation identifier CDR2_LE {0x00,0x07}: PLAIN_CDR2, XCDR2, little endian
   (XTypes 1.3 §7.6.3.1.2 Table 60). TypeLookup_Request/Reply's encapsulation — the
   top-level types are FINAL per the implemented convention (Fast DDS pins them @final;
   the tshark RTPS dissector expects exactly this), so no top-level DHEADER follows.
   PEER-CONFIRMED live vs Fast DDS 3.6.1 (FR-IO-2 S4, 2026-06-12): every TypeLookup frame
   both directions carries 0x0007 with the flat header directly after the options.")

(defconstant +tl-max-instance-name+ 255
  "InstanceName bound: typedef string<255> InstanceName (XTypes 1.3 §7.6.3.3.2).")

(defconstant +tl-max-continuation-octets+ 32
  "continuation_point bound: sequence<octet,32> (XTypes 1.3 §7.6.3.3.3).")

;;; ---- serialize (MUTABLE framing via %mutable-member-begin/-end, typeobject-cdr.lisp) ----

(defun* %put-tl-request-header (c writer-guid sn instance-name)
    (function (dds.core.buffer:cursor (simple-array (unsigned-byte 8) (*)) integer string) t)
  "dds::rpc::RequestHeader, flat (§7.6.3.3.2): 16 GUID octets + SequenceNumber_t
   (long high, unsigned long low) + InstanceName string. PEER-CONFIRMED (flat nesting):
   Fast DDS 3.6.1 emits the identical layout (s4-theirclient-patched-lo0.pcap frs
   2494/2496) and its server consumed ours (s4-ourclient-lo0.pcap fr 85 -> REMOTE_EX_OK)."
  (dds.core.buffer:put-octets c writer-guid 0 16)
  (dds.cdr:cdr-put-u32 c (logand (ash sn -32) #xFFFFFFFF) :xcdr2)
  (dds.cdr:cdr-put-u32 c (logand sn #xFFFFFFFF) :xcdr2)
  (dds.cdr:cdr-put-string c instance-name :xcdr2)
  t)

(defun* %put-tl-type-ids-member (c type-ids)
    (function (dds.core.buffer:cursor list) t)
  "The @hashid type_ids member: sequence<TypeIdentifier> = DHEADER + UInt32 count +
   elements (§7.4.3.5.3 rule 12, non-primitive elements); each element an EK_MINIMAL
   TypeIdentifier = discriminator octet + 14-octet EquivalenceHash (§7.3.4.9.1).
   EMHEADER1 LC=5: the backpatched NEXTINT doubles as the DHEADER (rule (22))."
  (let ((np (%mutable-member-begin c +tl-member-type-ids+ nil 5)))
    (dds.cdr:cdr-put-u32 c (length type-ids) :xcdr2)
    (dolist (h type-ids)
      (dds.core.buffer:put-u8 c +ek-minimal+)
      (dds.core.buffer:put-octets c h 0 14))
    (%mutable-member-end c np))
  t)

(defun* %put-tl-continuation-member (c continuation)
    (function (dds.core.buffer:cursor (simple-array (unsigned-byte 8) (*))) t)
  "The @hashid continuation_point member: sequence<octet,32> = UInt32 length + octets
   (§7.4.3.5.3 rule 11, primitive elements: no DHEADER). EMHEADER1 LC=5: the backpatched
   NEXTINT doubles as the element count (octet elements: count = byte length, rule (22))."
  (let ((np (%mutable-member-begin c +tl-member-continuation-point+ nil 5)))
    (dds.core.buffer:put-octets c continuation 0 (length continuation))
    (%mutable-member-end c np))
  t)

(defun* serialize-type-lookup-request (&key writer-guid sn instance-name operation
                                            type-ids continuation)
    (function (&key (:writer-guid (simple-array (unsigned-byte 8) (*)))
                    (:sn integer)
                    (:instance-name string)
                    (:operation (member :get-types :get-deps))
                    (:type-ids list)
                    (:continuation (or null (simple-array (unsigned-byte 8) (*)))))
              (values (or null (simple-array (unsigned-byte 8) (*))) (or null keyword)))
  "Serialize a TypeLookup_Request (XTypes 1.3 §7.6.3.3.3) as XCDR2-LE octets, including
   the 4-octet CDR2_LE encapsulation header. WRITER-GUID is the 16-octet requester GUID,
   SN the request SequenceNumber, INSTANCE-NAME the bounded<255> service instance name,
   OPERATION :get-types or :get-deps, TYPE-IDS a list of 14-octet EquivalenceHashes
   (serialized as EK_MINIMAL TypeIdentifiers), CONTINUATION an optional continuation_point
   (<=32 octets, :get-deps only; omitted when NIL or empty).

   Returns (values octets NIL) — a fresh octet vector — or (values NIL status) if an argument violates the
   XTypes bound it is checked against: :BAD-WRITER-GUID / :INSTANCE-NAME-TOO-LONG / :BAD-TYPE-ID /
   :CONTINUATION-TOO-LONG. These are SPEC BOUNDS on what may go on the wire, so they must be enforced
   before a single octet is emitted; they are now returned rather than signalled (ADR 0064)."
  (unless (= 16 (length writer-guid))
    (bail :bad-writer-guid))            ; GUID_t is 16 octets — XTypes §7.6.3.3.2
  (unless (<= (length instance-name) +tl-max-instance-name+)
    (bail :instance-name-too-long))     ; instanceName is string<255> — XTypes §7.6.3.3.2
  (dolist (h type-ids)
    (unless (= 14 (length h))
      (bail :bad-type-id)))             ; each type_id is a 14-octet EquivalenceHash — XTypes §7.3.4.9.1
  (when (and continuation (> (length continuation) +tl-max-continuation-octets+))
    (bail :continuation-too-long))      ; continuation_point is sequence<octet,32> — XTypes §7.6.3.3.3
  ;; 1024 = fixed-part slack: encapsulation+DHEADERs+EMHEADERs+header+continuation+padding
  (let* ((buf (dds.core.buffer:make-octet-buffer
               (+ 1024 (* 16 (length type-ids)) (length instance-name))))
         (c (dds.core.buffer:cursor buf :endianness :little)))
    (unwind-protect
         (progn
           (dds.core.buffer:put-u8 c (ldb (byte 8 8) +tl-encap-cdr2-le+))
           (dds.core.buffer:put-u8 c (ldb (byte 8 0) +tl-encap-cdr2-le+))
           (dds.core.buffer:put-u16 c 0)
           (dds.core.buffer:cursor-set-origin c)
           ;; FINAL top level: no DHEADER; header flat (Fast DDS @final convention)
           (%put-tl-request-header c writer-guid sn instance-name)
           ;; TypeLookup_Call: default-appendable union => DHEADER + discriminator
           (let ((up (%dheader-begin c)))
             (dds.cdr:cdr-put-u32 c (ecase operation
                                      (:get-types +tl-gettypes-hash+)
                                      (:get-deps +tl-getdeps-hash+))
                                  :xcdr2)
             (let ((ip (%dheader-begin c)))
               (%put-tl-type-ids-member c type-ids)
               (when (and (eq operation :get-deps) continuation (plusp (length continuation)))
                 (%put-tl-continuation-member c continuation))
               (%dheader-end c ip))
             (%dheader-end c up))
           (let* ((e (dds.core.buffer:cursor-position c))
                  (out (make-array e :element-type '(unsigned-byte 8))))
             (replace out (dds.core.buffer:octet-buffer-vec buf) :end2 e)
             (values out nil)))
      (dds.pal:free-static (dds.core.buffer:octet-buffer-vec buf)))))

;;; ---- parse (network-facing: every read bounds-checked, NFR-SEC-POSTURE) ----

(defun* %tl-member-extent (c lc limit)
    (function (dds.core.buffer:cursor (integer 0 7) (integer 0))
              (values (or null (integer 0)) (or null (integer 0))))
  "Decode an EMHEADER's LC into (values member-value-start member-end) per §7.4.3.4.2 +
   serialization rule (22) (§7.4.3.5.3). LC 0-3: no NEXTINT, the value is the next
   1/2/4/8 bytes. LC 4-7: NEXTINT present, and the bytes following it number
   NEXTINT/NEXTINT/4*NEXTINT/8*NEXTINT. For LC 5-7 rule (22) rewinds the stream 4 bytes
   ('XCDR.offset = XCDR.offset-4') so NEXTINT doubles as the value's leading UInt32
   (string length incl. NUL / element count / DHEADER): the value STARTS at the NEXTINT,
   but the extent beyond it is unchanged — end = nextint-pos + 4 + length in all LC 4-7
   cases (the only reading consistent with the rule-(22) reuse). NIL NIL if the member
   would extend past LIMIT."
  (let* ((nextint (when (>= lc 4) (dds.core.buffer:get-u32 c)))
         (start (if (and nextint (>= lc 5))
                    (- (dds.core.buffer:cursor-position c) 4)
                    (dds.core.buffer:cursor-position c)))
         (len (ecase lc
                (0 1) (1 2) (2 4) (3 8)
                ((4 5) nextint)
                (6 (* 4 nextint))
                (7 (* 8 nextint))))
         (end (+ (dds.core.buffer:cursor-position c) len)))
    (if (> end limit) (values nil nil) (values start end))))

(defun* %tl-walk-mutable-struct (c tend member-fn)
    (function (dds.core.buffer:cursor (integer 0) function) t)
  "Walk a MUTABLE struct (PL_CDR2: DHEADER + EMHEADER1[/NEXTINT] members, §7.4.3.4.2)
   inside an enclosing extent ending at TEND. For each member, MEMBER-FN is called as
   (id vstart vend) and must return :HANDLED (member consumed), :UNKNOWN (member not
   recognized; skipped by its encoded length), or NIL (malformed member content). Returns
   T on a complete walk; NIL on malformed framing, a member extent past its bound, a NIL
   from MEMBER-FN, or an unknown member with M_FLAG set (§7.2.2.4.4.4.6)."
  (let* ((isize (dds.cdr:cdr-get-dheader c :xcdr2))
         (iend (+ (dds.core.buffer:cursor-position c) isize)))
    (when (> iend tend) (return-from %tl-walk-mutable-struct nil))
    (loop while (< (dds.core.buffer:cursor-position c) iend)
          do (dds.cdr:cdr-align c 4 :xcdr2)
             (when (>= (dds.core.buffer:cursor-position c) iend) (return))
             (multiple-value-bind (mu lc id)
                 (dds.cdr:emheader1-decode (dds.core.buffer:get-u32 c))
               (multiple-value-bind (vstart vend) (%tl-member-extent c lc iend)
                 (unless vstart (return-from %tl-walk-mutable-struct nil))
                 (let ((r (funcall member-fn id vstart vend)))
                   (cond ((eq r :handled))
                         ;; unknown must-understand member: discard the sample (§7.2.2.4.4.4.6)
                         ((and (eq r :unknown) (not mu)))
                         (t (return-from %tl-walk-mutable-struct nil))))
                 (dds.core.buffer:cursor-set-position c vend))))
    t))

(defun* %tl-parse-type-ids (c limit)
    (function (dds.core.buffer:cursor (integer 0)) (values list t))
  "Parse a sequence<TypeIdentifier> member value ending at most at LIMIT: DHEADER +
   UInt32 count + per element a hash-kind discriminator octet + 14-octet hash. Returns
   (values ids ok); ok NIL on any malformed/overlong content."
  (let* ((dsize (dds.cdr:cdr-get-dheader c :xcdr2))
         (dend (+ (dds.core.buffer:cursor-position c) dsize)))
    (if (> dend limit)
        (values nil nil)
        (let ((count (dds.cdr:cdr-get-u32 c :xcdr2))
              (ids '()))
          ;; each element is >= 15 octets; an absurd count cannot fit before LIMIT
          (if (> (* count 15) (- dend (dds.core.buffer:cursor-position c)))
              (values nil nil)
              (progn
                (dotimes (i count)
                  (let ((disc (dds.core.buffer:get-u8 c)))
                    (unless (or (= disc +ek-minimal+) (= disc +ek-complete+))
                      (return-from %tl-parse-type-ids (values nil nil)))
                    (let ((h (make-array 14 :element-type '(unsigned-byte 8))))
                      (dds.core.buffer:get-octets c h 0 14)
                      (push h ids))))
                (values (nreverse ids) t)))))))

(defun* %tl-parse-continuation (c limit)
    (function (dds.core.buffer:cursor (integer 0))
              (values (or null (simple-array (unsigned-byte 8) (*))) t))
  "Parse a sequence<octet,32> member value ending at most at LIMIT: UInt32 length +
   octets. Returns (values continuation ok); empty parses as NIL, ok NIL on a length
   over the §7.6.3.3.3 bound or past LIMIT."
  (let ((n (dds.cdr:cdr-get-u32 c :xcdr2)))
    (cond ((or (> n +tl-max-continuation-octets+)
               (> (+ (dds.core.buffer:cursor-position c) n) limit))
           (values nil nil))
          ((zerop n) (values nil t))
          (t (let ((v (make-array n :element-type '(unsigned-byte 8))))
               (dds.core.buffer:get-octets c v 0 n)
               (values v t))))))

(defun* %tl-parse-in-struct (c len op)
    (function (dds.core.buffer:cursor (integer 0) (member :get-types :get-deps))
              (values list t t))
  "Parse a MUTABLE TypeLookup_get*_In struct via %tl-walk-mutable-struct: (values
   type-ids continuation ok). continuation_point is a member of the getTypeDependencies_In
   struct only (§7.6.3.3.3), so for OP :get-types it is an unknown member: skipped, or
   rejecting the sample if M_FLAG is set. ok NIL on any malformed framing."
  (let ((ids '()) (continuation nil))
    (if (%tl-walk-mutable-struct
         c len
         (lambda (id vstart vend)
           (cond ((= id +tl-member-type-ids+)
                  (dds.core.buffer:cursor-set-position c vstart)
                  (multiple-value-bind (v ok) (%tl-parse-type-ids c vend)
                    (when ok (setf ids v) :handled)))
                 ((and (eq op :get-deps) (= id +tl-member-continuation-point+))
                  (dds.core.buffer:cursor-set-position c vstart)
                  (multiple-value-bind (v ok) (%tl-parse-continuation c vend)
                    (when ok (setf continuation v) :handled)))
                 (t :unknown))))
        (values ids continuation t)
        (values nil nil nil))))

(defun* parse-type-lookup-request (octets)
    (function ((simple-array (unsigned-byte 8) (*)))
              (values (or null (member :get-types :get-deps :unknown)) list
                      (or null (simple-array (unsigned-byte 8) (*))) (or null integer)
                      (or null string) (or null (simple-array (unsigned-byte 8) (*)))))
  "Parse a serialized TypeLookup_Request (XTypes 1.3 §7.6.3.3.3, CDR2_LE) and return
   (values operation type-ids writer-guid sn instance-name continuation) where OPERATION
   is :get-types or :get-deps and TYPE-IDS a list of 14-octet EquivalenceHashes; (values
   :unknown NIL writer-guid sn instance-name NIL) for an unrecognized union discriminator;
   NIL on any malformed, truncated, or out-of-bounds input (network-facing: every read is
   bounds-checked against the input extent, NFR-SEC-POSTURE)."
  (let ((len (length octets)))
    (when (< len 8) (return-from parse-type-lookup-request nil))
    ;; encapsulation: CDR2_LE only (what we and live Fast DDS 3.6.1 emit, FR-IO-2 S4;
    ;; other encodings CONFIRM-VS-PEER -- no peer has ever sent one)
    (unless (and (= (aref octets 0) (ldb (byte 8 8) +tl-encap-cdr2-le+))
                 (= (aref octets 1) (ldb (byte 8 0) +tl-encap-cdr2-le+)))
      (return-from parse-type-lookup-request nil))
    (let* ((buf (dds.core.buffer:make-octet-buffer len))
           (c (dds.core.buffer:cursor buf :endianness :little)))
      (replace (dds.core.buffer:octet-buffer-vec buf) octets)
      (unwind-protect
           ;; the cursor signals BUFFER-OVERFLOW on any read past LEN -> NIL
           (handler-case
               (progn
                 (dds.core.buffer:cursor-set-position c 4)
                 (dds.core.buffer:cursor-set-origin c)
                 ;; FINAL top level: the input extent is the bound (no top DHEADER)
                 (let ((guid (make-array 16 :element-type '(unsigned-byte 8))))
                   (dds.core.buffer:get-octets c guid 0 16)
                   (let* ((high (dds.cdr:cdr-get-i32 c :xcdr2))
                          (low (dds.cdr:cdr-get-u32 c :xcdr2))
                          (sn (+ low (* high #x100000000)))
                          (slen (dds.cdr:cdr-get-u32 c :xcdr2))
                          (spos (dds.core.buffer:cursor-position c)))
                     ;; string<255>: length includes the NUL, so 1..256 (§7.6.3.3.2),
                     ;; NUL-terminated, and inside the input extent
                     (when (or (zerop slen) (> slen (1+ +tl-max-instance-name+))
                               (> (+ spos slen) len)
                               (plusp (aref octets (+ spos slen -1))))
                       (return-from parse-type-lookup-request nil))
                     ;; rewind to the length and re-read via the cdr-put-string inverse
                     (dds.core.buffer:cursor-set-position c (- spos 4))
                     (let* ((iname (dds.cdr:cdr-get-string c :xcdr2))
                            ;; TypeLookup_Call: appendable union DHEADER bounds disc + arm
                            (usize (dds.cdr:cdr-get-dheader c :xcdr2))
                            (uend (+ (dds.core.buffer:cursor-position c) usize)))
                       (when (> uend len) (return-from parse-type-lookup-request nil))
                       (let ((disc (dds.cdr:cdr-get-u32 c :xcdr2)))
                         (cond
                           ((or (= disc +tl-gettypes-hash+) (= disc +tl-getdeps-hash+))
                            (let ((op (if (= disc +tl-gettypes-hash+) :get-types :get-deps)))
                              (multiple-value-bind (ids continuation ok)
                                  (%tl-parse-in-struct c uend op)
                                (if ok
                                    (values op ids guid sn iname continuation)
                                    nil))))
                           (t (values :unknown nil guid sn iname nil))))))))
             (dds.core.buffer:buffer-overflow () nil))
        (dds.pal:free-static (dds.core.buffer:octet-buffer-vec buf))))))

;;;; TypeLookup_Reply codec. §7.6.3.3.3's IDL declares the reply header as
;;;; dds::rpc::RequestHeader — an editorial defect: §7.6.3.3.2 copies ReplyHeader
;;;; { dds::SampleIdentity relatedRequestId; RemoteExceptionCode_t remoteEx; } from
;;;; DDS-RPC precisely for the @RPCReplyType, and only ReplyHeader can carry remoteEx.
;;;; We serialize the §7.6.3.3.2 ReplyHeader. PEER-CONFIRMED: Fast DDS 3.6.1's reply
;;;; carries remoteEx directly after relatedRequestId (s4-ourclient-lo0.pcap fr 86, the
;;;; locked fastdds-typelookup-reply-vector), and its client consumed OUR replies with
;;;; this placement and resolved the type from them (s4-theirclient-patched-lo0.pcap
;;;; frs 2495/2497 -> 2498). The nested Return/Result unions are default-appendable: each
;;;; carries a DHEADER before its discriminator (§7.4.3.4.1 + §7.4.3.5.3 rule (30)), like
;;;; the request's TypeLookup_Call (the Fast DDS / dissector layout; their fr 86 hex shows
;;;; both DHEADERs).

;; @hashid("types") §7.3.1.2.1.1: MD5[0:4]={d1 4a 80 22} LE=#x22804AD1 AND #x0FFFFFFF (test re-derives)
(defconstant +tl-member-types+ #x02804AD1
  "Member id of the @hashid types member of TypeLookup_getTypes_Out
   (XTypes 1.3 §7.6.3.3.3 + §7.3.1.2.1.1).")

;; @hashid("complete_to_minimal") §7.3.1.2.1.1: MD5[0:4]={77 65 8e fb} LE=#xFB8E6577 AND #x0FFFFFFF
(defconstant +tl-member-complete-to-minimal+ #x0B8E6577
  "Member id of the @hashid complete_to_minimal member of TypeLookup_getTypes_Out
   (XTypes 1.3 §7.6.3.3.3 + §7.3.1.2.1.1).")

;; @hashid("dependent_typeids") §7.3.1.2.1.1: MD5[0:4]={c9 df a4 2b} LE=#x2BA4DFC9 AND #x0FFFFFFF
(defconstant +tl-member-dependent-typeids+ #x0BA4DFC9
  "Member id of the @hashid dependent_typeids member of TypeLookup_getTypeDependencies_Out
   (XTypes 1.3 §7.6.3.3.3 + §7.3.1.2.1.1).")

;; The Out continuation_point shares +tl-member-continuation-point+ (same name => same @hashid)

(defconstant +tl-retcode-ok+ 0
  "DDS_RETCODE_OK, the only TypeLookup_get*_Result union case (XTypes 1.3 §7.6.3.3.3);
   pinned from the DDS 1.4 PSM IDL (docs/specs/dds_rtf2_dcps.idl: const ReturnCode_t
   RETCODE_OK = 0).")

(defun* %tl-remote-ex-code (kw)
    (function ((member :ok :unsupported :invalid-argument :out-of-resources
                       :unknown-operation :unknown-exception))
              (unsigned-byte 32))
  "RemoteExceptionCode_t enumerator for KW: §7.6.3.3.2 declaration order REMOTE_EX_OK,
   _UNSUPPORTED, _INVALID_ARGUMENT, _OUT_OF_RESOURCES, _UNKNOWN_OPERATION,
   _UNKNOWN_EXCEPTION = 0..5 (default IDL enumerator values)."
  (ecase kw
    (:ok 0) (:unsupported 1) (:invalid-argument 2)
    (:out-of-resources 3) (:unknown-operation 4) (:unknown-exception 5)))

(defun* %tl-remote-ex-keyword (code)
    (function ((unsigned-byte 32)) (or null keyword))
  "Inverse of %tl-remote-ex-code; NIL for a value outside the §7.6.3.3.2 enum."
  (case code
    (0 :ok) (1 :unsupported) (2 :invalid-argument)
    (3 :out-of-resources) (4 :unknown-operation) (5 :unknown-exception)
    (t nil)))

(defun* %put-tl-reply-header (c related-guid related-sn remote-ex)
    (function (dds.core.buffer:cursor (simple-array (unsigned-byte 8) (*)) integer symbol) t)
  "dds::rpc::ReplyHeader, flat (§7.6.3.3.2): relatedRequestId SampleIdentity (16 GUID
   octets + SequenceNumber_t long high / unsigned long low) + remoteEx enum as a 32-bit
   value (default enum bit-bound). PEER-CONFIRMED (flat nesting, like the request):
   byte-identical layout in Fast DDS 3.6.1's own reply (fr 86) and ours consumed by
   their client (patched frs 2495/2497)."
  (dds.core.buffer:put-octets c related-guid 0 16)
  (dds.cdr:cdr-put-u32 c (logand (ash related-sn -32) #xFFFFFFFF) :xcdr2)
  (dds.cdr:cdr-put-u32 c (logand related-sn #xFFFFFFFF) :xcdr2)
  (dds.cdr:cdr-put-u32 c (%tl-remote-ex-code remote-ex) :xcdr2)
  t)

(defun* %put-tl-pairs-member (c pairs)
    (function (dds.core.buffer:cursor list) t)
  "The @hashid types member: sequence<TypeIdentifierTypeObjectPair> = DHEADER + UInt32
   count + elements (§7.4.3.5.3 rule 12). Each pair is FINAL (xtypes-1_3_typeobject.idl)
   so no struct DHEADER (rule 17): the TypeIdentifier (FINAL union, rule 26: EK_MINIMAL
   octet + 14-octet hash) then the TypeObject (APPENDABLE union, rule 30) as the raw
   minimal-type-object-octets, which begin with that rule-30 DHEADER — spliced 4-aligned
   so the embedded XCDR2 alignment phase (max 4, §7.4.3.3) is preserved. EMHEADER1 LC=5:
   the backpatched NEXTINT doubles as the sequence DHEADER (rule (22))."
  (let ((np (%mutable-member-begin c +tl-member-types+ nil 5)))
    (dds.cdr:cdr-put-u32 c (length pairs) :xcdr2)
    (dolist (p pairs)
      (dds.core.buffer:put-u8 c +ek-minimal+)
      (dds.core.buffer:put-octets c (car p) 0 14)
      (dds.cdr:cdr-align c 4 :xcdr2)
      (dds.core.buffer:put-octets c (cdr p) 0 (length (cdr p))))
    (%mutable-member-end c np))
  t)

(defun* %put-tl-c2m-member (c)
    (function (dds.core.buffer:cursor) t)
  "The @hashid complete_to_minimal member, emitted empty (v1 serves EK_MINIMAL TypeObjects
   only, so no complete-to-minimal mapping exists, §7.6.3.3.4.2): DHEADER + count 0
   (sequence of non-primitive elements, §7.4.3.5.3 rule 12). EMHEADER1 LC=5: the
   backpatched NEXTINT doubles as the sequence DHEADER (rule (22))."
  (let ((np (%mutable-member-begin c +tl-member-complete-to-minimal+ nil 5)))
    (dds.cdr:cdr-put-u32 c 0 :xcdr2)
    (%mutable-member-end c np))
  t)

(defun* %put-tl-deps-member (c dependencies)
    (function (dds.core.buffer:cursor list) t)
  "The @hashid dependent_typeids member: sequence<TypeIdentfierWithSize> [sic] = DHEADER +
   UInt32 count + elements (§7.4.3.5.3 rule 12); each element via
   %put-type-id-with-size-octets (APPENDABLE framing, typeobject-cdr.lisp). EMHEADER1
   LC=5: the backpatched NEXTINT doubles as the sequence DHEADER (rule (22))."
  (let ((np (%mutable-member-begin c +tl-member-dependent-typeids+ nil 5)))
    (dds.cdr:cdr-put-u32 c (length dependencies) :xcdr2)
    (dolist (d dependencies)
      (%put-type-id-with-size-octets c (car d) (cdr d)))
    (%mutable-member-end c np))
  t)

(defun* serialize-type-lookup-reply (&key writer-guid related-guid related-sn operation
                                          (remote-ex :ok) pairs dependencies continuation)
    (function (&key (:writer-guid (or null (simple-array (unsigned-byte 8) (*))))
                    (:related-guid (simple-array (unsigned-byte 8) (*)))
                    (:related-sn integer)
                    (:operation (or null (member :get-types :get-deps)))
                    (:remote-ex (member :ok :unsupported :invalid-argument :out-of-resources
                                        :unknown-operation :unknown-exception))
                    (:pairs list)
                    (:dependencies list)
                    (:continuation (or null (simple-array (unsigned-byte 8) (*)))))
              (values (or null (simple-array (unsigned-byte 8) (*))) (or null keyword)))
  "Serialize a TypeLookup_Reply (XTypes 1.3 §7.6.3.3.3) as XCDR2-LE octets, including the
   4-octet CDR2_LE encapsulation header. The header is the §7.6.3.3.2 ReplyHeader —
   relatedRequestId (RELATED-GUID, 16 octets + RELATED-SN, the request's SampleIdentity)
   + REMOTE-EX — not the RequestHeader the §7.6.3.3.3 IDL names (spec editorial defect;
   see the section comment). WRITER-GUID is accepted for request/reply call-site symmetry
   and validated, but is NOT serialized: ReplyHeader carries no replier identity. For
   REMOTE-EX :ok, OPERATION selects the TypeLookup_Return arm: :get-types serializes
   PAIRS, a list of (14-octet-hash . typeobject-octets) TypeIdentifierTypeObjectPairs,
   plus an empty complete_to_minimal; :get-deps serializes DEPENDENCIES, a list of
   (14-octet-hash . typeobject-serialized-size), plus CONTINUATION (<=32 octets, omitted
   when NIL or empty, §7.6.3.3.4.1). For any non-:ok REMOTE-EX the TypeLookup_Return is
   omitted entirely: DDS-RPC (referenced by §7.6.3.3.2/.4) signals failure via remoteEx,
   the Return union has no default arm to select (§7.6.3.3.3), and the reply then ends at
   the input extent (FINAL top level: absence = nothing after the header). The
   REMOTE_EX_OK framing is PEER-CONFIRMED (Fast DDS 3.6.1's client consumed our getTypes
   and getTypeDependencies replies and built the type from them, FR-IO-2 S4 leg
   B-patched); the non-OK Return-arm omission stays CONFIRM-VS-PEER (never provoked live;
   self-pinned + tshark-validated only).

   Returns (values octets NIL) — a fresh vector — or (values NIL status) if an argument violates an XTypes
   bound: :BAD-WRITER-GUID / :BAD-RELATED-GUID / :BAD-OPERATION / :BAD-PAIR / :BAD-DEPENDENCY /
   :CONTINUATION-TOO-LONG. Returned, never signalled (ADR 0064)."
  (when writer-guid
    (unless (= 16 (length writer-guid))
      (bail :bad-writer-guid)))         ; GUID_t is 16 octets — XTypes §7.6.3.3.2
  (unless (= 16 (length related-guid))
    (bail :bad-related-guid))           ; GUID_t is 16 octets — XTypes §7.6.3.3.2
  (when (eq remote-ex :ok)
    (unless (member operation '(:get-types :get-deps))
      (bail :bad-operation)))           ; a REMOTE_EX_OK reply must select a Return arm — §7.6.3.3.3
  (dolist (p pairs)
    (unless (and (= 14 (length (car p))) (plusp (length (cdr p))))
      (bail :bad-pair)))                ; (14-octet hash . TypeObject octets) — XTypes §7.3.4.9.1
  (dolist (d dependencies)
    (unless (and (= 14 (length (car d))) (typep (cdr d) '(unsigned-byte 32)))
      (bail :bad-dependency)))          ; (14-octet hash . UInt32 size) — XTypes §7.6.3.3.3
  (when (and continuation (> (length continuation) +tl-max-continuation-octets+))
    (bail :continuation-too-long))      ; continuation_point is sequence<octet,32> — XTypes §7.6.3.3.3
  ;; 1024 = fixed-part slack; +32/pair and +32/dependency cover framing + padding
  (let* ((buf (dds.core.buffer:make-octet-buffer
               (+ 1024 (* 32 (length dependencies))
                  (loop for p in pairs sum (+ 32 (length (cdr p)))))))
         (c (dds.core.buffer:cursor buf :endianness :little)))
    (unwind-protect
         (progn
           (dds.core.buffer:put-u8 c (ldb (byte 8 8) +tl-encap-cdr2-le+))
           (dds.core.buffer:put-u8 c (ldb (byte 8 0) +tl-encap-cdr2-le+))
           (dds.core.buffer:put-u16 c 0)
           (dds.core.buffer:cursor-set-origin c)
           ;; FINAL top level: no DHEADER; header flat (Fast DDS @final convention)
           (%put-tl-reply-header c related-guid related-sn remote-ex)
           (when (eq remote-ex :ok)
             ;; TypeLookup_Return then TypeLookup_get*_Result: appendable unions,
             ;; each = DHEADER + discriminator (§7.4.3.4.1 + §7.4.3.5.3 rule (30))
             (let ((up (%dheader-begin c)))
               (dds.cdr:cdr-put-u32 c (ecase operation
                                        (:get-types +tl-gettypes-hash+)
                                        (:get-deps +tl-getdeps-hash+))
                                    :xcdr2)
               (let ((rp (%dheader-begin c)))
                 (dds.cdr:cdr-put-u32 c +tl-retcode-ok+ :xcdr2)
                 (let ((op (%dheader-begin c)))
                   (ecase operation
                     (:get-types
                      (%put-tl-pairs-member c pairs)
                      (%put-tl-c2m-member c))
                     (:get-deps
                      (%put-tl-deps-member c dependencies)
                      (when (and continuation (plusp (length continuation)))
                        (%put-tl-continuation-member c continuation))))
                   (%dheader-end c op))
                 (%dheader-end c rp))
               (%dheader-end c up)))
           (let* ((e (dds.core.buffer:cursor-position c))
                  (out (make-array e :element-type '(unsigned-byte 8))))
             (replace out (dds.core.buffer:octet-buffer-vec buf) :end2 e)
             (values out nil)))
      (dds.pal:free-static (dds.core.buffer:octet-buffer-vec buf)))))

;;; ---- reply parse (network-facing: every read bounds-checked, NFR-SEC-POSTURE) ----

(defun* %tl-parse-pairs (c limit)
    (function (dds.core.buffer:cursor (integer 0)) (values list t))
  "Parse the types member value ending at most at LIMIT: DHEADER + UInt32 count + per
   pair an EK_* discriminator octet + 14-octet hash + (4-aligned) the TypeObject's
   DHEADER-prefixed octets, returned verbatim as (hash . octets). The count is pre-checked
   against the DHEADER extent (>= 20 octets/element: 15 TypeIdentifier + 4 DHEADER +
   1 discriminator) before any allocation; each TypeObject extent is bounded by
   *max-type-object-bytes* (resource guard). (values pairs ok)."
  (let* ((dsize (dds.cdr:cdr-get-dheader c :xcdr2))
         (dend (+ (dds.core.buffer:cursor-position c) dsize)))
    (if (> dend limit)
        (values nil nil)
        (let ((count (dds.cdr:cdr-get-u32 c :xcdr2))
              (pairs '()))
          (if (> (* count 20) (- dend (dds.core.buffer:cursor-position c)))
              (values nil nil)
              (progn
                (dotimes (i count)
                  ;; variable-size elements: re-check the 20-octet minimum per iteration
                  (when (> (+ (dds.core.buffer:cursor-position c) 20) dend)
                    (return-from %tl-parse-pairs (values nil nil)))
                  (let ((disc (dds.core.buffer:get-u8 c)))
                    (unless (or (= disc +ek-minimal+) (= disc +ek-complete+))
                      (return-from %tl-parse-pairs (values nil nil)))
                    (let ((h (make-array 14 :element-type '(unsigned-byte 8))))
                      (dds.core.buffer:get-octets c h 0 14)
                      (dds.cdr:cdr-align c 4 :xcdr2)
                      (let* ((p0 (dds.core.buffer:cursor-position c))
                             (tsz (dds.cdr:cdr-get-u32 c :xcdr2)))
                        (when (or (zerop tsz) (> tsz *max-type-object-bytes*)
                                  (> (+ p0 4 tsz) dend))
                          (return-from %tl-parse-pairs (values nil nil)))
                        (let ((to (make-array (+ 4 tsz) :element-type '(unsigned-byte 8))))
                          (dds.core.buffer:cursor-set-position c p0)
                          (dds.core.buffer:get-octets c to 0 (+ 4 tsz))
                          (push (cons h to) pairs))))))
                (values (nreverse pairs) t)))))))

(defun* %tl-parse-c2m (c limit)
    (function (dds.core.buffer:cursor (integer 0)) (values list t))
  "Parse the complete_to_minimal member value ending at most at LIMIT: DHEADER + UInt32
   count + count TypeIdentifierPairs, each two hash-form TypeIdentifiers —
   type_identifier1 EK_COMPLETE + 14-octet hash, type_identifier2 EK_MINIMAL + 14-octet
   hash (the COMPLETE-to-MINIMAL mapping a server sends when it answers a query for a
   MINIMAL TypeIdentifier with the COMPLETE TypeObject, XTypes 1.3 §7.6.3.3.4.2; observed
   live from Fast DDS 3.6.1). 30 octets/pair, pre-checked against the extent before any
   allocation. (values alist ok), each entry (complete-hash . minimal-hash)."
  (let* ((dsize (dds.cdr:cdr-get-dheader c :xcdr2))
         (dend (+ (dds.core.buffer:cursor-position c) dsize)))
    (if (> dend limit)
        (values nil nil)
        (let ((count (dds.cdr:cdr-get-u32 c :xcdr2))
              (acc '()))
          (if (> (* count 30) (- dend (dds.core.buffer:cursor-position c)))
              (values nil nil)
              (progn
                (dotimes (i count)
                  (unless (= (dds.core.buffer:get-u8 c) +ek-complete+)
                    (return-from %tl-parse-c2m (values nil nil)))
                  (let ((ch (make-array 14 :element-type '(unsigned-byte 8))))
                    (dds.core.buffer:get-octets c ch 0 14)
                    (unless (= (dds.core.buffer:get-u8 c) +ek-minimal+)
                      (return-from %tl-parse-c2m (values nil nil)))
                    (let ((mh (make-array 14 :element-type '(unsigned-byte 8))))
                      (dds.core.buffer:get-octets c mh 0 14)
                      (push (cons ch mh) acc))))
                (values (nreverse acc) t)))))))

(defun* %tl-parse-deps (c limit)
    (function (dds.core.buffer:cursor (integer 0)) (values list t))
  "Parse the dependent_typeids member value ending at most at LIMIT: DHEADER + UInt32
   count + per element a TypeIdentfierWithSize [sic] (APPENDABLE: DHEADER + EK_* octet +
   14-octet hash + pad + UInt32 size; skipped to its own DHEADER extent for appendable
   growth). The count is pre-checked against the extent (>= 24 octets/element: 4 DHEADER
   + 20 content) before any allocation. (values deps ok), each dep (hash . size)."
  (let* ((dsize (dds.cdr:cdr-get-dheader c :xcdr2))
         (dend (+ (dds.core.buffer:cursor-position c) dsize)))
    (if (> dend limit)
        (values nil nil)
        (let ((count (dds.cdr:cdr-get-u32 c :xcdr2))
              (deps '()))
          (if (> (* count 24) (- dend (dds.core.buffer:cursor-position c)))
              (values nil nil)
              (progn
                (dotimes (i count)
                  (let* ((esz (dds.cdr:cdr-get-dheader c :xcdr2))
                         (eend (+ (dds.core.buffer:cursor-position c) esz)))
                    (when (or (< esz 20) (> eend dend))
                      (return-from %tl-parse-deps (values nil nil)))
                    (let ((disc (dds.core.buffer:get-u8 c)))
                      (unless (or (= disc +ek-minimal+) (= disc +ek-complete+))
                        (return-from %tl-parse-deps (values nil nil)))
                      (let ((h (make-array 14 :element-type '(unsigned-byte 8))))
                        (dds.core.buffer:get-octets c h 0 14)
                        (dds.cdr:cdr-align c 4 :xcdr2)
                        (push (cons h (dds.cdr:cdr-get-u32 c :xcdr2)) deps)))
                    (dds.core.buffer:cursor-set-position c eend)))
                (values (nreverse deps) t)))))))

(defun* %tl-parse-out-struct (c len op)
    (function (dds.core.buffer:cursor (integer 0) (member :get-types :get-deps))
              (values list t list t))
  "Parse a MUTABLE TypeLookup_get*_Out struct via %tl-walk-mutable-struct: (values
   result continuation c2m ok), RESULT the pairs for :get-types or the (hash . size)
   deps for :get-deps, C2M the parsed complete_to_minimal mapping for :get-types
   (XTypes 1.3 §7.6.3.3.4.2). Members not in OP's Out struct are unknown (skipped, or
   rejecting on M_FLAG). ok NIL on any malformed framing."
  (let ((result '()) (continuation nil) (c2m '()))
    (if (%tl-walk-mutable-struct
         c len
         (lambda (id vstart vend)
           (cond ((and (eq op :get-types) (= id +tl-member-types+))
                  (dds.core.buffer:cursor-set-position c vstart)
                  (multiple-value-bind (v ok) (%tl-parse-pairs c vend)
                    (when ok (setf result v) :handled)))
                 ((and (eq op :get-deps) (= id +tl-member-dependent-typeids+))
                  (dds.core.buffer:cursor-set-position c vstart)
                  (multiple-value-bind (v ok) (%tl-parse-deps c vend)
                    (when ok (setf result v) :handled)))
                 ((and (eq op :get-deps) (= id +tl-member-continuation-point+))
                  (dds.core.buffer:cursor-set-position c vstart)
                  (multiple-value-bind (v ok) (%tl-parse-continuation c vend)
                    (when ok (setf continuation v) :handled)))
                 ((and (eq op :get-types) (= id +tl-member-complete-to-minimal+))
                  (dds.core.buffer:cursor-set-position c vstart)
                  (multiple-value-bind (v ok) (%tl-parse-c2m c vend)
                    (when ok (setf c2m v) :handled)))
                 (t :unknown))))
        (values result continuation c2m t)
        (values nil nil nil nil))))

(defun* parse-type-lookup-reply (octets)
    (function ((simple-array (unsigned-byte 8) (*)))
              (values (or null (member :get-types :get-deps :unknown)) list
                      (or null (simple-array (unsigned-byte 8) (*))) (or null integer)
                      (or null keyword) (or null (simple-array (unsigned-byte 8) (*)))
                      list))
  "Parse a serialized TypeLookup_Reply (XTypes 1.3 §7.6.3.3.3, CDR2_LE) and return
   (values operation result related-guid related-sn remote-ex continuation c2m):
   OPERATION :get-types with RESULT a list of (14-octet-hash . typeobject-octets) pairs
   and C2M the complete_to_minimal alist ((complete-hash . minimal-hash) ...) a server
   sends when it answers a MINIMAL query with COMPLETE TypeObjects (§7.6.3.3.4.2), or
   :get-deps with RESULT a list of (14-octet-hash . size) and an optional CONTINUATION;
   :unknown for an unrecognized TypeLookup_Return discriminator; OPERATION NIL with
   RELATED-GUID/RELATED-SN/REMOTE-EX still returned when the Return union is absent (a
   non-OK reply, see serialize-type-lookup-reply; an :ok reply without a Return is
   malformed); plain NIL on any malformed, truncated, or out-of-bounds input
   (network-facing: every read is bounds-checked, NFR-SEC-POSTURE). A Result union
   discriminator other than DDS_RETCODE_OK selects no arm (the union has only that case,
   §7.6.3.3.3) and yields an empty RESULT."
  (let ((len (length octets)))
    (when (< len 8) (return-from parse-type-lookup-reply nil))
    ;; encapsulation: CDR2_LE only (what we and live Fast DDS 3.6.1 emit, FR-IO-2 S4;
    ;; other encodings CONFIRM-VS-PEER -- no peer has ever sent one)
    (unless (and (= (aref octets 0) (ldb (byte 8 8) +tl-encap-cdr2-le+))
                 (= (aref octets 1) (ldb (byte 8 0) +tl-encap-cdr2-le+)))
      (return-from parse-type-lookup-reply nil))
    (let* ((buf (dds.core.buffer:make-octet-buffer len))
           (c (dds.core.buffer:cursor buf :endianness :little)))
      (replace (dds.core.buffer:octet-buffer-vec buf) octets)
      (unwind-protect
           ;; the cursor signals BUFFER-OVERFLOW on any read past LEN -> NIL
           (handler-case
               (progn
                 (dds.core.buffer:cursor-set-position c 4)
                 (dds.core.buffer:cursor-set-origin c)
                 ;; FINAL top level: the input extent is the bound (no top DHEADER)
                 (let ((guid (make-array 16 :element-type '(unsigned-byte 8))))
                   (dds.core.buffer:get-octets c guid 0 16)
                   (let* ((high (dds.cdr:cdr-get-i32 c :xcdr2))
                          (low (dds.cdr:cdr-get-u32 c :xcdr2))
                          (sn (+ low (* high #x100000000)))
                          (rex (%tl-remote-ex-keyword (dds.cdr:cdr-get-u32 c :xcdr2))))
                     (unless rex (return-from parse-type-lookup-reply nil))
                     (cond
                       ;; Return omitted: valid only for a non-OK reply (header-only)
                       ((>= (dds.core.buffer:cursor-position c) len)
                        (if (eq rex :ok) nil (values nil nil guid sn rex nil nil)))
                       (t
                        ;; TypeLookup_Return: appendable union DHEADER bounds disc + arm
                        (let* ((usize (dds.cdr:cdr-get-dheader c :xcdr2))
                               (uend (+ (dds.core.buffer:cursor-position c) usize)))
                          (when (> uend len) (return-from parse-type-lookup-reply nil))
                          (let ((disc (dds.cdr:cdr-get-u32 c :xcdr2)))
                            (cond
                              ((or (= disc +tl-gettypes-hash+) (= disc +tl-getdeps-hash+))
                               (let* ((op (if (= disc +tl-gettypes-hash+) :get-types :get-deps))
                                      ;; TypeLookup_get*_Result: appendable union DHEADER
                                      (rsize (dds.cdr:cdr-get-dheader c :xcdr2))
                                      (rend (+ (dds.core.buffer:cursor-position c) rsize)))
                                 (when (> rend uend)
                                   (return-from parse-type-lookup-reply nil))
                                 (let ((ret (dds.cdr:cdr-get-i32 c :xcdr2)))
                                   (if (/= ret +tl-retcode-ok+)
                                       ;; no DDS_RETCODE_OK arm: bare Result discriminator
                                       (values op nil guid sn rex nil nil)
                                       (multiple-value-bind (result continuation c2m ok)
                                           (%tl-parse-out-struct c rend op)
                                         (if ok
                                             (values op result guid sn rex continuation c2m)
                                             nil))))))
                              (t (values :unknown nil guid sn rex nil nil))))))))))
             (dds.core.buffer:buffer-overflow () nil))
        (dds.pal:free-static (dds.core.buffer:octet-buffer-vec buf))))))

;;;; TypeLookup server core (Task 3.1, FR-TYPE-3): a memoized EquivalenceHash index over
;;;; *type-registry* plus the pure request->reply function the builtin service endpoints
;;;; will call (XTypes 1.3 §7.6.3.3.4: a participant SHALL answer getTypes /
;;;; getTypeDependencies for any TypeIdentifier it announced). No transport here.

(defparameter *max-typelookup-request-ids* 32
  "Max type_ids accepted in one inbound TypeLookup request before the request is
   dropped unanswered (resource-exhaustion guard, NFR-SEC-POSTURE).")

(defvar *tl-hash-index* (cons -1 '())
  "Memoized EquivalenceHash index: (registry-generation . ((hash14 . type-name) ...)),
   rebuilt by %TL-HASH-INDEX whenever *TYPE-REGISTRY-GENERATION* changes (re-registering
   an existing name bumps the generation though the registry count is unchanged).")

(defun* %tl-hash-index ()
    (function () list)
  "The ((hash14 . type-name) ...) alist over *TYPE-REGISTRY*, memoized in
   *TL-HASH-INDEX* and invalidated when *TYPE-REGISTRY-GENERATION* changes.
   Types without a serializable minimal TypeObject (EQUIVALENCE-HASH errors, e.g.
   sequence member TypeIdentifiers pending oracle confirmation) are skipped."
  (let ((n *type-registry-generation*))
    (unless (= n (car *tl-hash-index*))
      (let ((acc '()))
        (loop for name being the hash-keys of *type-registry* using (hash-value ts)
              do (let ((to (type-support-typeobject ts)))
                   (when (minimal-struct-type-p to)
                     ;; unserializable TypeObject: the type is not served by hash
                     (handler-case (push (cons (equivalence-hash to) name) acc)
                       (error () nil)))))
        (setf *tl-hash-index* (cons n (nreverse acc)))))
    (cdr *tl-hash-index*)))

(defun* find-type-support-by-hash (hash)
    (function ((simple-array (unsigned-byte 8) (*))) t)
  "The registered type-support whose minimal EquivalenceHash equals HASH (first 14
   octets compared), or NIL. Types whose TypeObject cannot serialize are skipped."
  (when (>= (length hash) 14)
    (let* ((h (if (= 14 (length hash)) hash (subseq hash 0 14)))
           (entry (assoc h (%tl-hash-index) :test #'equalp)))
      (and entry (find-type-support (cdr entry))))))

(defun* type-lookup-respond (request-octets)
    (function ((simple-array (unsigned-byte 8) (*)))
              (values (or null (simple-array (unsigned-byte 8) (*))) (or null keyword)))
  "Answer one inbound TypeLookup request: getTypes/getTypeDependencies over the local
   type registry (XTypes 1.3 §7.6.3.3.4: a participant SHALL answer for any
   TypeIdentifier it announced).

   Returns (values reply-octets NIL) to send; (values NIL NIL) = DROP the request (malformed or
   guard-rejected — the ordinary hostile-input outcome, NOT an error); (values NIL status) if the reply
   we assembled would itself violate an XTypes bound, which is OUR bug, not the peer's, and is therefore
   distinguishable from a drop rather than folded into it (ADR 0064). The reply's
   relatedRequestId echoes the request's writer GUID + SN (§7.6.3.3.2); hashes not
   found locally are silently omitted (zero pairs/deps still answers REMOTE_EX_OK);
   an unrecognized TypeLookup_Call discriminator answers REMOTE_EX_UNKNOWN_OPERATION
   with no TypeLookup_Return arm. getTypeDependencies dependencies are the
   %COLLECT-DEPENDENCIES closure of each found type, deduped by hash, as
   (hash . typeobject-serialized-size) TypeIdentfierWithSize entries; the
   continuation_point is always empty (v1 serves the full set in one reply)."
  (multiple-value-bind (op ids guid sn) (parse-type-lookup-request request-octets)
    (cond
      ((null op) nil)
      ((> (length ids) *max-typelookup-request-ids*) nil)
      ((eq op :unknown)
       (serialize-type-lookup-reply :related-guid guid :related-sn sn
                                    :remote-ex :unknown-operation))
      ((eq op :get-types)
       (let ((pairs (loop for h in ids
                          for ts = (find-type-support-by-hash h)
                          when ts
                            collect (cons h (minimal-type-object-octets
                                             (type-support-typeobject ts))))))
         (serialize-type-lookup-reply :related-guid guid :related-sn sn
                                      :operation :get-types :remote-ex :ok
                                      :pairs pairs)))
      (t
       (let ((deps '()))
         (dolist (h ids)
           (let ((ts (find-type-support-by-hash h)))
             (when ts
               (dolist (d (%collect-dependencies (type-support-typeobject ts)))
                 (let ((dh (equivalence-hash d)))
                   (unless (assoc dh deps :test #'equalp)
                     (push (cons dh (length (minimal-type-object-octets d))) deps)))))))
         (serialize-type-lookup-reply :related-guid guid :related-sn sn
                                      :operation :get-deps :remote-ex :ok
                                      :dependencies (nreverse deps)))))))
