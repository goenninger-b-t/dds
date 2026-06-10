;;;; TypeLookup_Request XCDR2 codec (M4, FR-TYPE-3). XTypes 1.3 §7.6.3.3: the built-in
;;;; TypeLookup service request type, TypeLookup_Request { dds::rpc::RequestHeader header;
;;;; TypeLookup_Call data; } (§7.6.3.3.3), with the DDS-RPC header types copied in
;;;; §7.6.3.3.2 (GUID_t = 12-octet prefix + 4-octet entityId; SequenceNumber_t = long high
;;;; + unsigned long low; RequestHeader = SampleIdentity requestId + string<255> instanceName).
;;;;
;;;; NO Connext oracle exists for this protocol (ADR 0010: RTI does not implement the
;;;; builtin TypeLookup service); everything here is pinned from the spec text and marked
;;;; CONFIRM-VS-PEER where a byte-level choice awaits a compliant peer (Fast DDS, FR-IO-2):
;;;; (1) TypeLookup_Request is unannotated, so it takes the §7.3.1.2.1.8 default ("the type
;;;; shall be considered appendable") => DELIMITED_CDR, encapsulation D_CDR2_LE {0x00,0x09}
;;;; (Table 60, §7.6.3.1.2), one top-level DHEADER. (2) The nested DDS-RPC header types and
;;;; the TypeLookup_Call union are serialized FLAT (no per-struct DHEADERs, union = bare
;;;; discriminator + arm), matching Fast DDS practice for these RPC types rather than the
;;;; strict default-appendable recursion. (3) The MUTABLE *_In members use EMHEADER1 LC=4
;;;; + explicit NEXTINT, M_FLAG=0 (the §7.2.2.4.4.4.6 default), mirroring
;;;; serialize-type-information. (4) type_ids elements are EK_MINIMAL/EK_COMPLETE
;;;; hash-defined TypeIdentifiers only (the only kinds a request for a TypeObject can name
;;;; that we serve); other TypeIdentifier kinds reject on parse.

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

;; Default extensibility (§7.3.1.2.1.8) => APPENDABLE => DELIMITED_CDR. CONFIRM-VS-PEER.
(defconstant +tl-encap-d-cdr2-le+ #x0009
  "RTPS encapsulation identifier D_CDR2_LE {0x00,0x09}: DELIMITED_CDR, XCDR2, little
   endian (XTypes 1.3 §7.6.3.1.2 Table 60). TypeLookup_Request's encapsulation.")

(defconstant +tl-max-instance-name+ 255
  "InstanceName bound: typedef string<255> InstanceName (XTypes 1.3 §7.6.3.3.2).")

(defconstant +tl-max-continuation-octets+ 32
  "continuation_point bound: sequence<octet,32> (XTypes 1.3 §7.6.3.3.3).")

;;; ---- serialize (MUTABLE framing via %mutable-member-begin/-end, typeobject-cdr.lisp) ----

(defun* %put-tl-request-header (c writer-guid sn instance-name)
    (function (dds.core.buffer:cursor (simple-array (unsigned-byte 8) (*)) integer string) t)
  "dds::rpc::RequestHeader, flat (§7.6.3.3.2): 16 GUID octets + SequenceNumber_t
   (long high, unsigned long low) + InstanceName string. CONFIRM-VS-PEER (flat nesting)."
  (dds.core.buffer:put-octets c writer-guid 0 16)
  (dds.cdr:cdr-put-u32 c (logand (ash sn -32) #xFFFFFFFF) :xcdr2)
  (dds.cdr:cdr-put-u32 c (logand sn #xFFFFFFFF) :xcdr2)
  (dds.cdr:cdr-put-string c instance-name :xcdr2)
  t)

(defun* %put-tl-type-ids-member (c type-ids)
    (function (dds.core.buffer:cursor list) t)
  "The @hashid type_ids member: sequence<TypeIdentifier> = DHEADER + UInt32 count +
   elements (§7.4.3.5.3 rule 12, non-primitive elements); each element an EK_MINIMAL
   TypeIdentifier = discriminator octet + 14-octet EquivalenceHash (§7.3.4.9.1)."
  (let ((np (%mutable-member-begin c +tl-member-type-ids+)))
    (let ((sp (%dheader-begin c)))
      (dds.cdr:cdr-put-u32 c (length type-ids) :xcdr2)
      (dolist (h type-ids)
        (dds.core.buffer:put-u8 c +ek-minimal+)
        (dds.core.buffer:put-octets c h 0 14))
      (%dheader-end c sp))
    (%mutable-member-end c np))
  t)

(defun* %put-tl-continuation-member (c continuation)
    (function (dds.core.buffer:cursor (simple-array (unsigned-byte 8) (*))) t)
  "The @hashid continuation_point member: sequence<octet,32> = UInt32 length + octets
   (§7.4.3.5.3 rule 11, primitive elements: no DHEADER)."
  (let ((np (%mutable-member-begin c +tl-member-continuation-point+)))
    (dds.cdr:cdr-put-u32 c (length continuation) :xcdr2)
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
              (simple-array (unsigned-byte 8) (*)))
  "Serialize a TypeLookup_Request (XTypes 1.3 §7.6.3.3.3) as XCDR2-LE octets, including
   the 4-octet D_CDR2_LE encapsulation header. WRITER-GUID is the 16-octet requester GUID,
   SN the request SequenceNumber, INSTANCE-NAME the bounded<255> service instance name,
   OPERATION :get-types or :get-deps, TYPE-IDS a list of 14-octet EquivalenceHashes
   (serialized as EK_MINIMAL TypeIdentifiers), CONTINUATION an optional continuation_point
   (<=32 octets, :get-deps only; omitted when NIL or empty). Returns a fresh octet vector."
  (unless (= 16 (length writer-guid))
    (error "TypeLookup_Request: writer-guid must be 16 octets (GUID_t, XTypes §7.6.3.3.2)"))
  (unless (<= (length instance-name) +tl-max-instance-name+)
    (error "TypeLookup_Request: instanceName exceeds the string<255> bound (XTypes §7.6.3.3.2)"))
  (dolist (h type-ids)
    (unless (= 14 (length h))
      (error "TypeLookup_Request: each type_id must be a 14-octet EquivalenceHash (XTypes §7.3.4.9.1)")))
  (when (and continuation (> (length continuation) +tl-max-continuation-octets+))
    (error "TypeLookup_Request: continuation_point exceeds sequence<octet,32> (XTypes §7.6.3.3.3)"))
  ;; 1024 = fixed-part slack: encapsulation+DHEADERs+EMHEADERs+header+continuation+padding
  (let* ((buf (dds.core.buffer:make-octet-buffer
               (+ 1024 (* 16 (length type-ids)) (length instance-name))))
         (c (dds.core.buffer:cursor buf :endianness :little)))
    (unwind-protect
         (progn
           (dds.core.buffer:put-u8 c (ldb (byte 8 8) +tl-encap-d-cdr2-le+))
           (dds.core.buffer:put-u8 c (ldb (byte 8 0) +tl-encap-d-cdr2-le+))
           (dds.core.buffer:put-u16 c 0)
           (dds.core.buffer:cursor-set-origin c)
           (let ((tp (%dheader-begin c)))
             (%put-tl-request-header c writer-guid sn instance-name)
             (dds.cdr:cdr-put-u32 c (ecase operation
                                      (:get-types +tl-gettypes-hash+)
                                      (:get-deps +tl-getdeps-hash+))
                                  :xcdr2)
             (let ((ip (%dheader-begin c)))
               (%put-tl-type-ids-member c type-ids)
               (when (and (eq operation :get-deps) continuation (plusp (length continuation)))
                 (%put-tl-continuation-member c continuation))
               (%dheader-end c ip))
             (%dheader-end c tp))
           (let* ((e (dds.core.buffer:cursor-position c))
                  (out (make-array e :element-type '(unsigned-byte 8))))
             (replace out (dds.core.buffer:octet-buffer-vec buf) :end2 e)
             out))
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
  "Parse a serialized TypeLookup_Request (XTypes 1.3 §7.6.3.3.3, D_CDR2_LE) and return
   (values operation type-ids writer-guid sn instance-name continuation) where OPERATION
   is :get-types or :get-deps and TYPE-IDS a list of 14-octet EquivalenceHashes; (values
   :unknown NIL writer-guid sn instance-name NIL) for an unrecognized union discriminator;
   NIL on any malformed, truncated, or out-of-bounds input (network-facing: every read is
   bounds-checked against the input extent, NFR-SEC-POSTURE)."
  (let ((len (length octets)))
    (when (< len 8) (return-from parse-type-lookup-request nil))
    ;; encapsulation: D_CDR2_LE only (what we emit; other encodings CONFIRM-VS-PEER)
    (unless (and (= (aref octets 0) (ldb (byte 8 8) +tl-encap-d-cdr2-le+))
                 (= (aref octets 1) (ldb (byte 8 0) +tl-encap-d-cdr2-le+)))
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
                 (let* ((tsize (dds.cdr:cdr-get-dheader c :xcdr2))
                        (tend (+ (dds.core.buffer:cursor-position c) tsize)))
                   (when (> tend len) (return-from parse-type-lookup-request nil))
                   (let ((guid (make-array 16 :element-type '(unsigned-byte 8))))
                     (dds.core.buffer:get-octets c guid 0 16)
                     (let* ((high (dds.cdr:cdr-get-i32 c :xcdr2))
                            (low (dds.cdr:cdr-get-u32 c :xcdr2))
                            (sn (+ low (* high #x100000000)))
                            (slen (dds.cdr:cdr-get-u32 c :xcdr2))
                            (spos (dds.core.buffer:cursor-position c)))
                       ;; string<255>: length includes the NUL, so 1..256 (§7.6.3.3.2),
                       ;; NUL-terminated, and inside the top-level DHEADER extent
                       (when (or (zerop slen) (> slen (1+ +tl-max-instance-name+))
                                 (> (+ spos slen) tend)
                                 (plusp (aref octets (+ spos slen -1))))
                         (return-from parse-type-lookup-request nil))
                       ;; rewind to the length and re-read via the cdr-put-string inverse
                       (dds.core.buffer:cursor-set-position c (- spos 4))
                       (let ((iname (dds.cdr:cdr-get-string c :xcdr2))
                             (disc (dds.cdr:cdr-get-u32 c :xcdr2)))
                         (cond
                           ((or (= disc +tl-gettypes-hash+) (= disc +tl-getdeps-hash+))
                            (let ((op (if (= disc +tl-gettypes-hash+) :get-types :get-deps)))
                              (multiple-value-bind (ids continuation ok)
                                  (%tl-parse-in-struct c tend op)
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
;;;; We serialize the §7.6.3.3.2 ReplyHeader. CONFIRM-VS-PEER. The nested Return/Result
;;;; unions are FLAT (bare discriminator + arm) like the request's TypeLookup_Call.

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
   value (default enum bit-bound). CONFIRM-VS-PEER (flat nesting, like the request)."
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
   so the embedded XCDR2 alignment phase (max 4, §7.4.3.3) is preserved."
  (let ((np (%mutable-member-begin c +tl-member-types+)))
    (let ((sp (%dheader-begin c)))
      (dds.cdr:cdr-put-u32 c (length pairs) :xcdr2)
      (dolist (p pairs)
        (dds.core.buffer:put-u8 c +ek-minimal+)
        (dds.core.buffer:put-octets c (car p) 0 14)
        (dds.cdr:cdr-align c 4 :xcdr2)
        (dds.core.buffer:put-octets c (cdr p) 0 (length (cdr p))))
      (%dheader-end c sp))
    (%mutable-member-end c np))
  t)

(defun* %put-tl-c2m-member (c)
    (function (dds.core.buffer:cursor) t)
  "The @hashid complete_to_minimal member, emitted empty (v1 serves EK_MINIMAL TypeObjects
   only, so no complete-to-minimal mapping exists, §7.6.3.3.4.2): DHEADER + count 0
   (sequence of non-primitive elements, §7.4.3.5.3 rule 12)."
  (let ((np (%mutable-member-begin c +tl-member-complete-to-minimal+)))
    (let ((sp (%dheader-begin c)))
      (dds.cdr:cdr-put-u32 c 0 :xcdr2)
      (%dheader-end c sp))
    (%mutable-member-end c np))
  t)

(defun* %put-tl-deps-member (c dependencies)
    (function (dds.core.buffer:cursor list) t)
  "The @hashid dependent_typeids member: sequence<TypeIdentfierWithSize> [sic] = DHEADER +
   UInt32 count + elements (§7.4.3.5.3 rule 12); each element via
   %put-type-id-with-size-octets (APPENDABLE framing, typeobject-cdr.lisp)."
  (let ((np (%mutable-member-begin c +tl-member-dependent-typeids+)))
    (let ((sp (%dheader-begin c)))
      (dds.cdr:cdr-put-u32 c (length dependencies) :xcdr2)
      (dolist (d dependencies)
        (%put-type-id-with-size-octets c (car d) (cdr d)))
      (%dheader-end c sp))
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
              (simple-array (unsigned-byte 8) (*)))
  "Serialize a TypeLookup_Reply (XTypes 1.3 §7.6.3.3.3) as XCDR2-LE octets, including the
   4-octet D_CDR2_LE encapsulation header. The header is the §7.6.3.3.2 ReplyHeader —
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
   the Return union has no default arm to select (§7.6.3.3.3), and the reply struct's
   default-APPENDABLE DHEADER extent (§7.3.1.2.1.8 + §7.4.3.4.1) lets absent trailing
   members take default values (§7.2.2.4.4.4.7). CONFIRM-VS-PEER. Returns a fresh vector."
  (when writer-guid
    (unless (= 16 (length writer-guid))
      (error "TypeLookup_Reply: writer-guid must be 16 octets (GUID_t, XTypes §7.6.3.3.2)")))
  (unless (= 16 (length related-guid))
    (error "TypeLookup_Reply: related-guid must be 16 octets (GUID_t, XTypes §7.6.3.3.2)"))
  (when (eq remote-ex :ok)
    (unless (member operation '(:get-types :get-deps))
      (error "TypeLookup_Reply: a REMOTE_EX_OK reply needs :operation :get-types or :get-deps")))
  (dolist (p pairs)
    (unless (and (= 14 (length (car p))) (plusp (length (cdr p))))
      (error "TypeLookup_Reply: each pair must be (14-octet hash . TypeObject octets) (XTypes §7.3.4.9.1)")))
  (dolist (d dependencies)
    (unless (and (= 14 (length (car d))) (typep (cdr d) '(unsigned-byte 32)))
      (error "TypeLookup_Reply: each dependency must be (14-octet hash . UInt32 size) (XTypes §7.6.3.3.3)")))
  (when (and continuation (> (length continuation) +tl-max-continuation-octets+))
    (error "TypeLookup_Reply: continuation_point exceeds sequence<octet,32> (XTypes §7.6.3.3.3)"))
  ;; 1024 = fixed-part slack; +32/pair and +32/dependency cover framing + padding
  (let* ((buf (dds.core.buffer:make-octet-buffer
               (+ 1024 (* 32 (length dependencies))
                  (loop for p in pairs sum (+ 32 (length (cdr p)))))))
         (c (dds.core.buffer:cursor buf :endianness :little)))
    (unwind-protect
         (progn
           (dds.core.buffer:put-u8 c (ldb (byte 8 8) +tl-encap-d-cdr2-le+))
           (dds.core.buffer:put-u8 c (ldb (byte 8 0) +tl-encap-d-cdr2-le+))
           (dds.core.buffer:put-u16 c 0)
           (dds.core.buffer:cursor-set-origin c)
           (let ((tp (%dheader-begin c)))
             (%put-tl-reply-header c related-guid related-sn remote-ex)
             (when (eq remote-ex :ok)
               (dds.cdr:cdr-put-u32 c (ecase operation
                                        (:get-types +tl-gettypes-hash+)
                                        (:get-deps +tl-getdeps-hash+))
                                    :xcdr2)
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
                 (%dheader-end c op)))
             (%dheader-end c tp))
           (let* ((e (dds.core.buffer:cursor-position c))
                  (out (make-array e :element-type '(unsigned-byte 8))))
             (replace out (dds.core.buffer:octet-buffer-vec buf) :end2 e)
             out))
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
              (values list t t))
  "Parse a MUTABLE TypeLookup_get*_Out struct via %tl-walk-mutable-struct: (values
   result continuation ok), RESULT the pairs for :get-types or the (hash . size) deps
   for :get-deps. Members not in OP's Out struct are unknown (skipped, or rejecting on
   M_FLAG); the complete_to_minimal member is skipped by extent (v1 consumes minimal
   TypeObjects only). ok NIL on any malformed framing."
  (let ((result '()) (continuation nil))
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
                  :handled)
                 (t :unknown))))
        (values result continuation t)
        (values nil nil nil))))

(defun* parse-type-lookup-reply (octets)
    (function ((simple-array (unsigned-byte 8) (*)))
              (values (or null (member :get-types :get-deps :unknown)) list
                      (or null (simple-array (unsigned-byte 8) (*))) (or null integer)
                      (or null keyword) (or null (simple-array (unsigned-byte 8) (*)))))
  "Parse a serialized TypeLookup_Reply (XTypes 1.3 §7.6.3.3.3, D_CDR2_LE) and return
   (values operation result related-guid related-sn remote-ex continuation): OPERATION
   :get-types with RESULT a list of (14-octet-hash . typeobject-octets) pairs, or
   :get-deps with RESULT a list of (14-octet-hash . size) and an optional CONTINUATION;
   :unknown for an unrecognized TypeLookup_Return discriminator; OPERATION NIL with
   RELATED-GUID/RELATED-SN/REMOTE-EX still returned when the Return union is absent (a
   non-OK reply, see serialize-type-lookup-reply); plain NIL on any malformed, truncated,
   or out-of-bounds input (network-facing: every read is bounds-checked, NFR-SEC-POSTURE).
   A Result union discriminator other than DDS_RETCODE_OK selects no arm (the union has
   only that case, §7.6.3.3.3) and yields an empty RESULT."
  (let ((len (length octets)))
    (when (< len 8) (return-from parse-type-lookup-reply nil))
    ;; encapsulation: D_CDR2_LE only (what we emit; other encodings CONFIRM-VS-PEER)
    (unless (and (= (aref octets 0) (ldb (byte 8 8) +tl-encap-d-cdr2-le+))
                 (= (aref octets 1) (ldb (byte 8 0) +tl-encap-d-cdr2-le+)))
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
                 (let* ((tsize (dds.cdr:cdr-get-dheader c :xcdr2))
                        (tend (+ (dds.core.buffer:cursor-position c) tsize)))
                   (when (or (> tend len) (< tsize 28))
                     (return-from parse-type-lookup-reply nil))
                   (let ((guid (make-array 16 :element-type '(unsigned-byte 8))))
                     (dds.core.buffer:get-octets c guid 0 16)
                     (let* ((high (dds.cdr:cdr-get-i32 c :xcdr2))
                            (low (dds.cdr:cdr-get-u32 c :xcdr2))
                            (sn (+ low (* high #x100000000)))
                            (rex (%tl-remote-ex-keyword (dds.cdr:cdr-get-u32 c :xcdr2))))
                       (unless rex (return-from parse-type-lookup-reply nil))
                       (cond
                         ;; Return omitted (non-OK reply): header only inside the extent
                         ((>= (dds.core.buffer:cursor-position c) tend)
                          (values nil nil guid sn rex nil))
                         (t
                          (let ((disc (dds.cdr:cdr-get-u32 c :xcdr2)))
                            (cond
                              ((or (= disc +tl-gettypes-hash+) (= disc +tl-getdeps-hash+))
                               (let ((op (if (= disc +tl-gettypes-hash+) :get-types :get-deps))
                                     (ret (dds.cdr:cdr-get-i32 c :xcdr2)))
                                 (if (/= ret +tl-retcode-ok+)
                                     ;; no DDS_RETCODE_OK arm: bare Result discriminator
                                     (values op nil guid sn rex nil)
                                     (multiple-value-bind (result continuation ok)
                                         (%tl-parse-out-struct c tend op)
                                       (if ok
                                           (values op result guid sn rex continuation)
                                           nil)))))
                              (t (values :unknown nil guid sn rex nil))))))))))
             (dds.core.buffer:buffer-overflow () nil))
        (dds.pal:free-static (dds.core.buffer:octet-buffer-vec buf))))))
