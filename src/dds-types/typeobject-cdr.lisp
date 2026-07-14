;;;; XCDR2 MinimalTypeObject serializer + EquivalenceHash (M4, FR-TYPE-2/5).
;;;; Serializes the in-memory Minimal struct TypeObject (xtypes.lisp) to the canonical
;;;; XCDR2 little-endian bytes and computes EquivalenceHash = MD5(serialized
;;;; TypeObject)[0:14] (XTypes 1.3 §7.3.4.9.1). Framing pinned from the §7.4.3.5.3
;;;; serialization VM: APPENDABLE -> DHEADER + content (rule 30); FINAL struct -> members
;;;; in order, no DHEADER (rule 17); FINAL union -> discriminator + arm (rule 26);
;;;; sequence of non-primitive -> DHEADER + length + elements (rule 12). Struct/header/
;;;; member extensibility pinned from xtypes-1_3_typeobject.idl (TypeObject APPENDABLE;
;;;; MinimalTypeObject + MinimalStructType + CommonStructMember + MinimalMemberDetail +
;;;; MinimalTypeDetail FINAL; MinimalStructHeader + MinimalStructMember APPENDABLE).
;;;;
;;;; EXTERNALLY CONFIRMED vs live Fast DDS 3.6.1 for the exercised path (FR-IO-2 S3,
;;;; 2026-06-12; Connext never emits the minimal hash, ADR 0009): for the identical
;;;; ShapeType IDL (FINAL struct + i32 + unbounded string8) Fast DDS announces the SAME
;;;; EK_MINIMAL hash + typeobject_serialized_size 87 (test fastdds-type-information-vector,
;;;; locked from interop/fastdds/captures/s1-forward-lo0.pcap frame 236) — MD5 equality
;;;; pins the whole 87-octet serialization, confirming the three formerly-provisional
;;;; byte-level choices for that path: (1) the hash is over the raw TypeObject XCDR2-LE
;;;; bytes with NO 4-byte encapsulation header; (2) struct_flags = the extensibility bit
;;;; only (minimal-masked, XTypes TypeFlagMinimalMask 0x0007); (3) member_flags =
;;;; TRY_CONSTRUCT=DISCARD (0x01) OR'd with @optional/@must_understand/@key (minimal-masked
;;;; 0x003f). Still PROVISIONAL: the unexercised serialization-VM edges (unions, MUTABLE
;;;; structs, TK_NONE base under the hash, nested-dependency hashes). Sequence-member
;;;; TypeIdentifiers (plain-collection element_flags / EK_BOTH / @external framing) are
;;;; the most oracle-sensitive and error cleanly until confirmed. SCC/cyclic types
;;;; (§7.3.4.9.2) are out of scope: the DSL is acyclic (define-before-use).

(in-package #:dds.types)

(defconstant +tk-none+ #x00)                ; TypeKind TK_NONE (idl §16)

;;; ---- XTypes minimal flag masks (idl §139/§163) ----
(defconstant +member-flag-try-construct-discard+ #x0001)  ; T1=1,T2=0 (idl §118-119)
(defconstant +member-flag-is-optional+ #x0008)            ; @position(3)
(defconstant +member-flag-is-must-understand+ #x0010)     ; @position(4)
(defconstant +member-flag-is-key+ #x0020)                 ; @position(5)
(defconstant +type-flag-is-final+ #x0001)                 ; @position(0)
(defconstant +type-flag-is-appendable+ #x0002)            ; @position(1)
(defconstant +type-flag-is-mutable+ #x0004)               ; @position(2)


(defun* %struct-type-flag (extensibility)
    (function (symbol) (unsigned-byte 16))
  "Minimal-masked StructTypeFlag (idl §163, TypeFlagMinimalMask 0x0007): the
   extensibility bit only (no IS_NESTED/IS_AUTOID_HASH, which do not affect assignability)."
  (ecase extensibility
    (:final +type-flag-is-final+)
    (:appendable +type-flag-is-appendable+)
    (:mutable +type-flag-is-mutable+)))

(defun* %member-flag (m)
    (function (minimal-struct-member) (unsigned-byte 16))
  "Minimal-masked StructMemberFlag (idl §139, MemberFlagMinimalMask 0x003f): TRY_CONSTRUCT
   DISCARD OR'd with @optional/@must_understand/@key. The TRY_CONSTRUCT-DISCARD default and
   the bare non-optional flags are externally confirmed for key + plain members via the Fast
   DDS hash lock (test fastdds-type-information-vector); @optional/@must_understand
   combinations remain peer-unexercised."
  (logior +member-flag-try-construct-discard+
          (if (minimal-struct-member-optional-p m) +member-flag-is-optional+ 0)
          (if (minimal-struct-member-must-understand-p m) +member-flag-is-must-understand+ 0)
          (if (minimal-struct-member-key-p m) +member-flag-is-key+ 0)))

;;; ---- DHEADER backpatching: write a placeholder, fill the size after the content ----

(defun* %dheader-begin (cursor)
    (function (dds.core.buffer:cursor) (integer 0))
  "Align to 4 and write a placeholder DHEADER UInt32; return its byte position."
  (dds.cdr:cdr-align cursor 4 :xcdr2)
  (let ((p (dds.core.buffer:cursor-position cursor)))
    (dds.core.buffer:put-u32 cursor 0)
    p))

(defun* %dheader-end (cursor start)
    (function (dds.core.buffer:cursor (integer 0)) (integer 0))
  "Backpatch the DHEADER at START with the serialized size of the content that follows it
   (XTypes §7.4.3.4.1: the size excludes the DHEADER itself)."
  (let ((e (dds.core.buffer:cursor-position cursor)))
    (dds.core.buffer:cursor-set-position cursor start)
    (dds.core.buffer:put-u32 cursor (- e start 4))
    (dds.core.buffer:cursor-set-position cursor e)
    e))

;;; ---- MUTABLE member framing: EMHEADER1 + backpatched NEXTINT (§7.4.3.4.2) ----

(defun* %mutable-member-begin (c id &optional mu (lc 4))
    (function (dds.core.buffer:cursor (unsigned-byte 28) &optional t (integer 4 5))
              (integer 0))
  "Write EMHEADER1 (M_FLAG=MU, length code LC) for member ID plus a placeholder NEXTINT;
   return the NEXTINT's byte position for %mutable-member-end. LC 4: NEXTINT is the
   member byte length and the value follows it. LC 5: NEXTINT doubles as the value's own
   leading UInt32 (DHEADER / element count, serialization rule (22), XTypes 1.3
   §7.4.3.5.3) — the caller writes the value WITHOUT that leading UInt32. MU defaults
   to NIL: the member must_understand attribute defaults to false (§7.2.2.4.4.4 /
   §7.2.2.4.4.4.6) absent an @must_understand annotation; pass T only for annotated members."
  (dds.cdr:cdr-align c 4 :xcdr2)
  (dds.core.buffer:put-u32 c (dds.cdr:emheader1-encode mu lc id))
  (let ((np (dds.core.buffer:cursor-position c)))
    (dds.core.buffer:put-u32 c 0)
    np))

(defun* %mutable-member-end (c np)
    (function (dds.core.buffer:cursor (integer 0)) (integer 0))
  "Backpatch the NEXTINT at NP with the byte length of the content that follows it
   (LC=4: the member length, §7.4.3.4.2; LC=5: the same value doubling as the value's
   own leading UInt32 — DHEADER or element count — per rule (22), §7.4.3.5.3)."
  (let ((e (dds.core.buffer:cursor-position c)))
    (dds.core.buffer:cursor-set-position c np)
    (dds.core.buffer:put-u32 c (- e np 4))
    (dds.core.buffer:cursor-set-position c e)
    e))

;;; ---- TypeIdentifier (FINAL union, rule 26): discriminator octet + arm ----

(defun* %put-type-identifier (cursor ti)
    (function (dds.core.buffer:cursor type-identifier) t)
  "Serialize a TypeIdentifier: primitives are the bare discriminator octet; a narrow
   string is disc + bound (SBound octet for SMALL, LBound UInt32 for LARGE); a hash-defined
   (EK_MINIMAL/EK_COMPLETE) type is disc + the 14-octet EquivalenceHash (computed from the
   referenced struct when not cached). Sequence/other kinds error pending oracle confirmation."
  (let ((kind (type-identifier-kind ti)))
    (cond
      ((ti-primitive-p ti) (dds.core.buffer:put-u8 cursor kind))
      ((= kind +ti-string8-small+)
       (dds.core.buffer:put-u8 cursor kind)
       (dds.core.buffer:put-u8 cursor (min 255 (type-identifier-bound ti))))
      ((= kind +ti-string8-large+)
       (dds.core.buffer:put-u8 cursor kind)
       (dds.cdr:cdr-put-u32 cursor (type-identifier-bound ti) :xcdr2))
      ((or (= kind +ek-minimal+) (= kind +ek-complete+))
       (dds.core.buffer:put-u8 cursor kind)
       (let* ((cached (type-identifier-hash ti))
              (ref (type-identifier-referenced ti))
              (h (or cached (and (minimal-struct-type-p ref) (equivalence-hash ref)))))
         (unless (and h (>= (length h) 14))
           (error "TypeObject serialize: no EquivalenceHash for an EK_* member TypeIdentifier"))
         (dds.core.buffer:put-octets cursor h 0 14)))
      ((ti-sequence-p ti)
       (error "TypeObject serialize: sequence member TypeIdentifiers are pending Connext-oracle confirmation"))
      (t (error "TypeObject serialize: unsupported TypeIdentifier kind #x~2,'0x" kind))))
  t)

;;; ---- CommonStructMember (FINAL, rule 17) + MinimalMemberDetail (FINAL) ----

(defun* %put-common-struct-member (cursor m)
    (function (dds.core.buffer:cursor minimal-struct-member) t)
  "CommonStructMember: member_id (UInt32) + member_flags (UInt16) + member_type_id."
  (dds.cdr:cdr-put-u32 cursor (minimal-struct-member-id m) :xcdr2)
  (dds.cdr:cdr-put-u16 cursor (%member-flag m) :xcdr2)
  (%put-type-identifier cursor (minimal-struct-member-type-identifier m))
  t)

(defun* %put-minimal-member-detail (cursor m)
    (function (dds.core.buffer:cursor minimal-struct-member) t)
  "MinimalMemberDetail: the 4-octet NameHash."
  (dds.core.buffer:put-octets cursor (minimal-struct-member-name-hash m) 0 4)
  t)

;;; ---- MinimalStructType (FINAL, rule 17): struct_flags + header + member_seq ----

(defun* %put-minimal-struct-type (cursor s)
    (function (dds.core.buffer:cursor minimal-struct-type) t)
  "MinimalStructType: StructTypeFlag (UInt16) + MinimalStructHeader (APPENDABLE: DHEADER +
   TK_NONE base_type + empty MinimalTypeDetail) + MinimalStructMemberSeq (sequence of
   APPENDABLE members: DHEADER + UInt32 length + each member as DHEADER + common + detail).
   Members are ordered by member_id (idl §458 / §7.3.4.5)."
  (dds.cdr:cdr-put-u16 cursor (%struct-type-flag (minimal-struct-type-extensibility s)) :xcdr2)
  (let ((hp (%dheader-begin cursor)))
    (dds.core.buffer:put-u8 cursor +tk-none+)
    (%dheader-end cursor hp))
  (let ((sp (%dheader-begin cursor))
        (members (sort (copy-list (minimal-struct-type-members s)) #'<
                       :key #'minimal-struct-member-id)))
    (dds.cdr:cdr-put-u32 cursor (length members) :xcdr2)
    (dolist (m members)
      (let ((mp (%dheader-begin cursor)))
        (%put-common-struct-member cursor m)
        (%put-minimal-member-detail cursor m)
        (%dheader-end cursor mp)))
    (%dheader-end cursor sp))
  t)

;;; ---- MinimalTypeObject (FINAL union, rule 26) + TypeObject (APPENDABLE, rule 30) ----

(defun* %put-minimal-type-object (cursor s)
    (function (dds.core.buffer:cursor minimal-struct-type) t)
  "MinimalTypeObject FINAL union: TK_STRUCTURE discriminator + MinimalStructType arm."
  (dds.core.buffer:put-u8 cursor +tk-structure+)
  (%put-minimal-struct-type cursor s)
  t)

(defun* %put-type-object (cursor s)
    (function (dds.core.buffer:cursor minimal-struct-type) t)
  "TypeObject APPENDABLE union: DHEADER + EK_MINIMAL discriminator + MinimalTypeObject."
  (let ((p (%dheader-begin cursor)))
    (dds.core.buffer:put-u8 cursor +ek-minimal+)
    (%put-minimal-type-object cursor s)
    (%dheader-end cursor p))
  t)

(defun* minimal-type-object-octets (s)
    (function (minimal-struct-type) (simple-array (unsigned-byte 8) (*)))
  "The canonical XCDR2 little-endian serialization of the EK_MINIMAL TypeObject for struct
   S (XTypes §7.3.4.5), with NO encapsulation header. The buffer the EquivalenceHash is
   computed over."
  (let* ((buf (dds.core.buffer:make-octet-buffer 16384))
         (c (dds.core.buffer:cursor buf :endianness :little)))
    (%put-type-object c s)
    (let* ((e (dds.core.buffer:cursor-position c))
           (out (make-array e :element-type '(unsigned-byte 8))))
      (replace out (dds.core.buffer:octet-buffer-vec buf) :end2 e)
      (dds.pal:free-static (dds.core.buffer:octet-buffer-vec buf))
      out)))

(defun* equivalence-hash (s)
    (function (minimal-struct-type) (simple-array (unsigned-byte 8) (*)))
  "EquivalenceHash(S) = first 14 octets of MD5 of the serialized MinimalTypeObject
   (XTypes §7.3.4.9.1). Nested struct members recurse to the referenced struct's hash.
   Externally confirmed vs live Fast DDS 3.6.1 for the exercised path (FR-IO-2 S3;
   test fastdds-type-information-vector)."
  (subseq (dds.core.md5:md5 (minimal-type-object-octets s)) 0 14))

;;;; MinimalTypeObject deserializer (TypeLookup Task 2.1, FR-TYPE-2/3): the exact inverse
;;;; of MINIMAL-TYPE-OBJECT-OCTETS for the modeled subset, so a TypeObject received via
;;;; TypeLookup can feed assignability (FR-TYPE-4; the service logic wiring the two
;;;; together is a subsequent task). Additionally parses the plain-sequence
;;;; member TypeIdentifiers the serializer cannot emit yet, pinned from the idl:
;;;; PlainSequenceSElemDefn (FINAL, rule 17) = PlainCollectionHeader { EquivalenceKind
;;;; equiv_kind (octet); CollectionElementFlag element_flags (UInt16) } + SBound bound
;;;; (octet) + @external TypeIdentifier element_identifier; the LARGE form carries an
;;;; LBound (UInt32) instead (xtypes-1_3_typeobject.idl §181-197). Network-facing: every
;;;; read is bounds-checked (NFR-SEC-POSTURE) — DHEADER extents explicitly, the buffer
;;;; extent via the cursor's BUFFER-OVERFLOW signal.

(defconstant +max-plain-collection-nesting+ 32
  "Resource guard (NFR-SEC-POSTURE): the maximum plain-collection element nesting
   PARSE-MINIMAL-TYPE-OBJECT recurses into before deeming the type :UNSUPPORTED.")

(defun* %struct-flag-extensibility (flags)
    (function ((unsigned-byte 16)) (or null (member :final :appendable :mutable)))
  "Inverse of %STRUCT-TYPE-FLAG: the extensibility encoded in StructTypeFlag FLAGS, or
   NIL unless exactly one extensibility bit is set (idl §163); other bits are ignored."
  (let ((e (logand flags (logior +type-flag-is-final+ +type-flag-is-appendable+
                                 +type-flag-is-mutable+))))
    (cond ((= e +type-flag-is-final+) :final)
          ((= e +type-flag-is-appendable+) :appendable)
          ((= e +type-flag-is-mutable+) :mutable)
          (t nil))))

(defun* %get-type-identifier (c depth)
    (function (dds.core.buffer:cursor (integer 0)) (or type-identifier (member :unsupported)))
  "Parse one TypeIdentifier at cursor C: the inverse of %PUT-TYPE-IDENTIFIER plus the
   plain-sequence forms (idl §187-197). DEPTH bounds collection-element recursion;
   :UNSUPPORTED for any unmodeled kind; reads past the buffer signal BUFFER-OVERFLOW."
  (let* ((k (dds.core.buffer:get-u8 c))
         (ti (%make-type-identifier :kind k)))
    (cond
      ((ti-primitive-p ti) ti)
      ((= k +ti-string8-small+)
       (setf (type-identifier-bound ti) (dds.core.buffer:get-u8 c))
       ti)
      ((= k +ti-string8-large+)
       (setf (type-identifier-bound ti) (dds.cdr:cdr-get-u32 c :xcdr2))
       ti)
      ((or (= k +ek-minimal+) (= k +ek-complete+))
       (let ((h (make-array 14 :element-type '(unsigned-byte 8))))
         (dds.core.buffer:get-octets c h 0 14)
         (hash-type-identifier k :hash h)))
      ((ti-sequence-p ti)
       (if (zerop depth)
           :unsupported
           (let ((ek (dds.core.buffer:get-u8 c)))
             (dds.cdr:cdr-get-u16 c :xcdr2)   ; element_flags: beyond the minimal model, ignored
             (if (not (or (= ek +ek-minimal+) (= ek +ek-complete+) (= ek +ek-both+)))
                 :unsupported
                 (let* ((bound (if (= k +ti-plain-sequence-small+)
                                   (dds.core.buffer:get-u8 c)
                                   (dds.cdr:cdr-get-u32 c :xcdr2)))
                        (el (%get-type-identifier c (1- depth))))
                   (if (type-identifier-p el)
                       (let ((sti (sequence-type-identifier el bound)))
                         (setf (type-identifier-kind sti) k)   ; preserve SMALL vs LARGE
                         sti)
                       el))))))
      (t :unsupported))))

(defun* %get-struct-member (c send detail-fn)
    (function (dds.core.buffer:cursor (integer 0) function)
              (or null minimal-struct-member (member :unsupported)))
  "Shared APPENDABLE struct-member scaffold for the MINIMAL/COMPLETE member readers:
   member DHEADER + extent check vs SEND, CommonStructMember (member_id UInt32 +
   member_flags UInt16 + member TypeIdentifier), then DETAIL-FN (cursor ti) ->
   (values name name-hash ti) — or :UNSUPPORTED as the first value — for the
   variant-specific detail, then skip to the member extent (APPENDABLE tolerance for
   future extra fields) and wire the flags into the slots. NIL on framing past SEND or
   past the member extent; :UNSUPPORTED on an unmodeled member TypeIdentifier or a
   degraded detail."
  (let* ((msize (dds.cdr:cdr-get-dheader c :xcdr2))
         (mend (+ (dds.core.buffer:cursor-position c) msize)))
    (when (> mend send) (return-from %get-struct-member nil))
    (let* ((id (dds.cdr:cdr-get-u32 c :xcdr2))
           (flags (dds.cdr:cdr-get-u16 c :xcdr2))
           (ti (%get-type-identifier c +max-plain-collection-nesting+)))
      (unless (type-identifier-p ti) (return-from %get-struct-member ti))
      (multiple-value-bind (name nh dti) (funcall detail-fn c ti)
        (when (eq name :unsupported) (return-from %get-struct-member :unsupported))
        (when (> (dds.core.buffer:cursor-position c) mend)
          (return-from %get-struct-member nil))
        (dds.core.buffer:cursor-set-position c mend)
        (%make-minimal-struct-member
         :name name :id id :type-identifier dti
         :key-p (logtest flags +member-flag-is-key+)
         :optional-p (logtest flags +member-flag-is-optional+)
         :must-understand-p (logtest flags +member-flag-is-must-understand+)
         :name-hash nh)))))

(defun* %parse-struct-type-object (octets expected-ek min-member-octets header-fn detail-fn)
    (function ((simple-array (unsigned-byte 8) (*)) (unsigned-byte 8) (integer 1)
               function function)
              (or null minimal-struct-type (member :unsupported)))
  "Shared TypeObject -> struct-model driver for PARSE-MINIMAL-TYPE-OBJECT and
   COMPLETE-TO-MINIMAL-TYPE-OBJECT (the framing is identical, XTypes 1.3 §7.3.4.5 per the
   §7.4.3.5.3 rules cited on the serializer; only the EK and the detail fields differ):
   *MAX-TYPE-OBJECT-BYTES* guard, bounds-checked cursor (BUFFER-OVERFLOW -> NIL,
   NFR-SEC-POSTURE), top DHEADER, EK discrimination (the MIRROR EK degrades to
   :UNSUPPORTED, any other octet is NIL), TK_STRUCTURE + extensibility struct_flags,
   struct header (TK_NONE base + HEADER-FN (cursor) -> type name or :UNSUPPORTED, extras
   skipped by extent), then the member sequence (count lower-bounded by MIN-MEMBER-OCTETS
   per member) read via %GET-STRUCT-MEMBER with DETAIL-FN."
  (let ((len (length octets)))
    (when (> len *max-type-object-bytes*)
      (return-from %parse-struct-type-object :unsupported))
    ;; absolute minimum onset: DHEADER 4 + EK 1 + TK 1 + struct_flags 2
    (when (< len 8) (return-from %parse-struct-type-object nil))
    (let* ((buf (dds.core.buffer:make-octet-buffer len))
           (c (dds.core.buffer:cursor buf :endianness :little)))
      (replace (dds.core.buffer:octet-buffer-vec buf) octets)
      (unwind-protect
           ;; the cursor signals BUFFER-OVERFLOW on any read past LEN -> NIL
           (handler-case
               (let* ((tsize (dds.cdr:cdr-get-dheader c :xcdr2))
                      (tend (+ (dds.core.buffer:cursor-position c) tsize)))
                 (when (> tend len) (return-from %parse-struct-type-object nil))
                 (let ((ek (dds.core.buffer:get-u8 c)))
                   (unless (= ek expected-ek)
                     ;; the mirror EK is well-formed but out of scope; anything else is malformed
                     (return-from %parse-struct-type-object
                       (if (or (= ek +ek-minimal+) (= ek +ek-complete+)) :unsupported nil))))
                 (unless (= (dds.core.buffer:get-u8 c) +tk-structure+)
                   (return-from %parse-struct-type-object :unsupported))
                 (let ((ext (%struct-flag-extensibility (dds.cdr:cdr-get-u16 c :xcdr2))))
                   (unless ext (return-from %parse-struct-type-object nil))
                   ;; struct header (APPENDABLE): TK_NONE base + variant detail, extras skipped
                   (let* ((hsize (dds.cdr:cdr-get-dheader c :xcdr2))
                          (hend (+ (dds.core.buffer:cursor-position c) hsize)))
                     (when (or (zerop hsize) (> hend tend))
                       (return-from %parse-struct-type-object nil))
                     (unless (= (dds.core.buffer:get-u8 c) +tk-none+)
                       (return-from %parse-struct-type-object :unsupported))
                     (let ((tname (funcall header-fn c)))
                       (unless (stringp tname)
                         (return-from %parse-struct-type-object tname))
                       (when (> (dds.core.buffer:cursor-position c) hend)
                         (return-from %parse-struct-type-object nil))
                       (dds.core.buffer:cursor-set-position c hend)
                       (let* ((ssize (dds.cdr:cdr-get-dheader c :xcdr2))
                              (send (+ (dds.core.buffer:cursor-position c) ssize)))
                         (when (> send tend) (return-from %parse-struct-type-object nil))
                         (let ((count (dds.cdr:cdr-get-u32 c :xcdr2))
                               (members '()))
                           (when (> (* count min-member-octets)
                                    (- send (dds.core.buffer:cursor-position c)))
                             (return-from %parse-struct-type-object nil))
                           (dotimes (i count)
                             (let ((m (%get-struct-member c send detail-fn)))
                               (unless (minimal-struct-member-p m)
                                 (return-from %parse-struct-type-object m))
                               (push m members)))
                           (make-minimal-struct-type :name tname :extensibility ext
                                                     :members (nreverse members))))))))
             (dds.core.buffer:buffer-overflow () nil))
        (dds.pal:free-static (dds.core.buffer:octet-buffer-vec buf))))))

(defun* %minimal-header-detail (c)
    (function (dds.core.buffer:cursor) string)
  "MinimalTypeDetail is empty (idl, MinimalTypeDetail): nothing to read; Minimal erases
   the type name, so the model carries NAME \"\"."
  (declare (ignorable c))
  "")

(defun* %minimal-member-detail (c ti)
    (function (dds.core.buffer:cursor type-identifier)
              (values (or string (member :unsupported)) t t))
  "MinimalMemberDetail: the 4-octet NameHash. The name is unknown in Minimal, so the
   member is built with NAME \"\" and the PARSED NameHash (never recomputed); TI passes
   through unchanged."
  (let ((nh (make-array 4 :element-type '(unsigned-byte 8))))
    (dds.core.buffer:get-octets c nh 0 4)
    (values "" nh ti)))

(defun* parse-minimal-type-object (octets)
    (function ((simple-array (unsigned-byte 8) (*)))
              (or null minimal-struct-type (member :unsupported)))
  "Parse a serialized EK_MINIMAL TypeObject into a minimal-struct-type; :UNSUPPORTED for
   any kind outside the modeled subset (EK_COMPLETE, non-struct TK, a non-TK_NONE base,
   an unmodeled member TypeIdentifier) and for input over *MAX-TYPE-OBJECT-BYTES*;
   NIL on malformed/truncated input. Inverse of MINIMAL-TYPE-OBJECT-OCTETS (XTypes 1.3
   §7.3.4.5; framing per the §7.4.3.5.3 rules cited on the serializer). The parsed model
   carries NAME \"\" (Minimal erases names), the wire NameHashes, and member EK_* hashes
   with REFERENCED=NIL, so it re-serializes byte-identically."
  ;; min member 15 = DHEADER 4 + id 4 + flags 2 + TI 1 + NameHash 4
  (%parse-struct-type-object octets +ek-minimal+ 15
                             #'%minimal-header-detail #'%minimal-member-detail))

;;;; CompleteTypeObject -> MINIMAL reconstruction (FR-IO-2 S4, FR-TYPE-3): a getTypes
;;;; server queried for a MINIMAL TypeIdentifier may answer with the COMPLETE TypeObject
;;;; plus a complete_to_minimal mapping, and "the receiver [reconstructs] the MINIMAL
;;;; TypeObject" (XTypes 1.3 §7.6.3.3.4.2 — Fast DDS 3.6.1 does exactly this, locked
;;;; vector test fastdds-typelookup-reply-vector). Complete differs from Minimal only in
;;;; the details: CompleteTypeDetail carries optional annotations + the type name where
;;;; MinimalTypeDetail is empty, and CompleteMemberDetail carries the member name +
;;;; optional annotations where MinimalMemberDetail is the 4-octet NameHash
;;;; (xtypes-1_3_typeobject.idl §431-495); @optional members ride as <is_present>
;;;; booleans in PLAIN_CDR2 (§7.4.3.5.2).

(defun* %remap-complete-ti (ti c2m)
    (function (type-identifier list) (or type-identifier (member :unsupported)))
  "Remap any EK_COMPLETE hash carried by TI — directly, or as a plain-collection ELEMENT,
   recursively — to its EK_MINIMAL counterpart via the C2M alist
   ((complete-hash . minimal-hash) ..., §7.6.3.3.4.2); :UNSUPPORTED when a carried
   EK_COMPLETE hash has no mapping (fail-open: never emit a model the assignability gate
   could mis-handle). TIs carrying no EK_COMPLETE pass through unchanged."
  (cond
    ((= (type-identifier-kind ti) +ek-complete+)
     (let ((mh (cdr (assoc (type-identifier-hash ti) c2m :test #'equalp))))
       (if mh (hash-type-identifier +ek-minimal+ :hash mh) :unsupported)))
    ((type-identifier-element ti)
     (let ((el (%remap-complete-ti (type-identifier-element ti) c2m)))
       (cond ((eq el (type-identifier-element ti)) ti)
             ((not (type-identifier-p el)) :unsupported)
             ;; rebuild, preserving the SMALL/LARGE collection kind + bound
             (t (let ((sti (sequence-type-identifier el (type-identifier-bound ti))))
                  (setf (type-identifier-kind sti) (type-identifier-kind ti))
                  sti)))))
    (t ti)))

(defun* %complete-header-detail (c)
    (function (dds.core.buffer:cursor) (or string (member :unsupported)))
  "CompleteTypeDetail: 2 optional <is_present> booleans (§7.4.3.5.2) + the type_name;
   a PRESENT type-level annotation is beyond the modeled subset (:UNSUPPORTED)."
  (if (and (zerop (dds.core.buffer:get-u8 c))
           (zerop (dds.core.buffer:get-u8 c)))
      (dds.cdr:cdr-get-string c :xcdr2)
      :unsupported))

(defun* %complete-member-detail (c ti c2m)
    (function (dds.core.buffer:cursor type-identifier list)
              (values (or string (member :unsupported)) t t))
  "CompleteMemberDetail: the member name (the trailing optional annotations are skipped
   by extent — Minimal erases them). The NameHash is recomputed from the wire name
   (member-name-hash, §7.3.4.5) and the member TypeIdentifier is remapped EK_COMPLETE ->
   EK_MINIMAL via %REMAP-COMPLETE-TI, degrading to :UNSUPPORTED when unmapped (fail-open)."
  (let ((rti (%remap-complete-ti ti c2m)))
    (if (not (type-identifier-p rti))
        (values :unsupported nil nil)
        (let ((name (dds.cdr:cdr-get-string c :xcdr2)))
          (values name (member-name-hash name) rti)))))

(defun* complete-to-minimal-type-object (octets c2m)
    (function ((simple-array (unsigned-byte 8) (*)) list)
              (or null minimal-struct-type (member :unsupported)))
  "Reconstruct the MINIMAL struct model from a serialized EK_COMPLETE TypeObject, per
   the XTypes 1.3 §7.6.3.3.4.2 latitude (a getTypes server asked for a MINIMAL
   TypeIdentifier may send the COMPLETE TypeObject; the receiver reconstructs). C2M is
   the reply's complete_to_minimal alist ((complete-hash . minimal-hash) ...) used to
   remap EK_COMPLETE TypeIdentifiers — member-level AND plain-collection elements;
   an EK_COMPLETE the alist cannot remap degrades the whole parse (never a model the
   assignability gate could mis-handle; the EquivalenceHash re-check downstream remains
   the backstop). Returns a minimal-struct-type carrying the real type + member names
   (Minimal serialization includes neither, §7.3.4.5, so EQUIVALENCE-HASH and
   MINIMAL-TYPE-OBJECT-OCTETS are unaffected; member NameHashes are recomputed from the
   names); :UNSUPPORTED outside the modeled subset (EK_MINIMAL or non-struct input, a
   non-TK_NONE base, a PRESENT type-level annotation, an unmodeled or unmappable
   member/element TypeIdentifier, input over *MAX-TYPE-OBJECT-BYTES*); NIL on
   malformed/truncated input (network-facing: every read bounds-checked,
   NFR-SEC-POSTURE)."
  ;; min member 16 = DHEADER 4 + id 4 + flags 2 + TI 1 + name 4+1
  (%parse-struct-type-object octets +ek-complete+ 16 #'%complete-header-detail
                             (lambda (c ti) (%complete-member-detail c ti c2m))))

;;;; TypeInformation codec (M4 step b1, FR-TYPE-3 foundation). The TypeInformation carried
;;;; in PublicationBuiltinTopicData/SubscriptionBuiltinTopicData (PID_TYPE_INFORMATION,
;;;; idl @id(0x0075)) so peers learn a type's EquivalenceHash-based TypeIdentifier without
;;;; the full TypeObject (XTypes §7.6.3.4 / §7.3.4.9.1). Structure (xtypes-1_3_typeobject.idl):
;;;; TypeInformation (MUTABLE) { @id(0x1001) minimal; @id(0x1002) complete; }; each member is
;;;; a TypeIdentifierWithDependencies (APPENDABLE) { TypeIdentfierWithSize [sic] typeid_with_size;
;;;; long dependent_typeid_count; sequence<TypeIdentfierWithSize> dependent_typeids; };
;;;; TypeIdentfierWithSize (APPENDABLE) { TypeIdentifier type_id; unsigned long
;;;; typeobject_serialized_size; }. Emission: minimal-only (the complete member is omitted,
;;;; MUTABLE permits it); the mutable member uses LC=4 (explicit NEXTINT length) with
;;;; M_FLAG=0 (the §7.2.2.4.4.4.6 must_understand default; the IDL has no @must_understand);
;;;; dependent ordering is insertion order. Spec-legal and consumed by live Fast DDS 3.6.1
;;;; (FR-IO-2 S1/S2). Parsing accepts BOTH LC=4 and the LC>=5 NEXTINT-reuse framing
;;;; (§7.4.3.4.2) that Fast DDS emits — its live 92-octet value (minimal+complete members,
;;;; dependent_typeid_count -1) is locked in test fastdds-type-information-vector.


(defun* %put-type-id-with-size-octets (c hash size)
    (function (dds.core.buffer:cursor (simple-array (unsigned-byte 8) (*)) (unsigned-byte 32)) t)
  "TypeIdentfierWithSize [sic] (APPENDABLE): DHEADER + EK_MINIMAL TypeIdentifier (disc + 14-octet
   HASH) + typeobject_serialized_size SIZE (UInt32)."
  (let ((p (%dheader-begin c)))
    (dds.core.buffer:put-u8 c +ek-minimal+)
    (dds.core.buffer:put-octets c hash 0 14)
    (dds.cdr:cdr-put-u32 c size :xcdr2)
    (%dheader-end c p))
  t)

(defun* %put-type-id-with-size (c s)
    (function (dds.core.buffer:cursor minimal-struct-type) t)
  "TypeIdentfierWithSize [sic] for struct S: hash + size computed from its MinimalTypeObject."
  (let ((bytes (minimal-type-object-octets s)))
    (%put-type-id-with-size-octets c (subseq (dds.core.md5:md5 bytes) 0 14) (length bytes)))
  t)

(defun* %collect-dependencies (s)
    (function (minimal-struct-type) list)
  "The dependent struct TypeObjects reachable from S (nested-struct members), deduped by
   EquivalenceHash, in stable insertion order. Excludes S itself; the DSL is acyclic."
  (let ((acc '()) (seen '()))
    (labels ((visit (st)
               (dolist (m (minimal-struct-type-members st))
                 (let* ((ti (minimal-struct-member-type-identifier m))
                        (ref (and ti (ti-aggregated-p ti) (type-identifier-referenced ti))))
                   (when (minimal-struct-type-p ref)
                     (let ((h (equivalence-hash ref)))
                       (unless (member h seen :test #'equalp)
                         (push h seen)
                         (push ref acc)
                         (visit ref))))))))
      (visit s))
    (nreverse acc)))

(defun* %put-type-id-with-deps (c s)
    (function (dds.core.buffer:cursor minimal-struct-type) t)
  "TypeIdentifierWithDependencies (APPENDABLE): DHEADER + TypeIdentfierWithSize [sic] (S) +
   dependent_typeid_count (Int32) + sequence<TypeIdentfierWithSize> (DHEADER + length +
   each dependency's TypeIdentfierWithSize)."
  (let ((deps (%collect-dependencies s))
        (p (%dheader-begin c)))
    (%put-type-id-with-size c s)
    (dds.cdr:cdr-put-u32 c (length deps) :xcdr2)
    (let ((sp (%dheader-begin c)))
      (dds.cdr:cdr-put-u32 c (length deps) :xcdr2)
      (dolist (d deps) (%put-type-id-with-size c d))
      (%dheader-end c sp))
    (%dheader-end c p))
  t)

(defun* serialize-type-information (s)
    (function (minimal-struct-type) (simple-array (unsigned-byte 8) (*)))
  "Serialize the TypeInformation for struct S (minimal only) as the octets carried in
   PID_TYPE_INFORMATION: a MUTABLE struct DHEADER + the @id(0x1001) minimal member
   (EMHEADER1 M_FLAG=0 LC=4 + NEXTINT length + TypeIdentifierWithDependencies).
   M_FLAG=0 is the must_understand default (§7.2.2.4.4.4.6; the TypeInformation IDL
   carries no @must_understand on its members). LC=4 is spec-legal alongside the LC=5
   NEXTINT-reuse framing Fast DDS emits (§7.4.3.4.2); live Fast DDS 3.6.1 consumed this
   emission (FR-IO-2 S1/S2)."
  (let* ((buf (dds.core.buffer:make-octet-buffer 16384))
         (c (dds.core.buffer:cursor buf :endianness :little)))
    (let ((p (%dheader-begin c)))
      (let ((np (%mutable-member-begin c #x1001)))
        (%put-type-id-with-deps c s)
        (%mutable-member-end c np))
      (%dheader-end c p))
    (let* ((e (dds.core.buffer:cursor-position c))
           (out (make-array e :element-type '(unsigned-byte 8))))
      (replace out (dds.core.buffer:octet-buffer-vec buf) :end2 e)
      (dds.pal:free-static (dds.core.buffer:octet-buffer-vec buf))
      out)))

(defun* deserialize-type-information-hash (octets)
    (function ((simple-array (unsigned-byte 8) (*)))
              (values (or null (simple-array (unsigned-byte 8) (*))) (or null keyword)))
  "Parse a serialized TypeInformation and return its minimal EK_MINIMAL TypeIdentifier's
   14-octet EquivalenceHash (the value endpoint matching needs). Lenient: walks the top
   DHEADER, the @id(0x1001) member EMHEADER1 (+NEXTINT), and the two APPENDABLE DHEADERs.
   Accepts both mutable-member framings (XTypes 1.3 §7.4.3.4.2): LC=4 (NEXTINT is the
   member length; the member's own DHEADER follows — our emission) and LC>=5 (NEXTINT is
   REUSED as the member's leading UInt32, i.e. its DHEADER — Fast DDS 3.6.1 emission).

   NETWORK-FACING: OCTETS come from a peer's SPDP/SEDP announcement, so a malformed value is an ORDINARY
   outcome, not an error. Returns (values hash NIL), or (values NIL status) — :NOT-MINIMAL-MEMBER (the
   @id member is not 0x1001) / :NOT-EK-MINIMAL (the type_id discriminator is not EK_MINIMAL). Returned,
   never signalled (ADR 0064). A TRUNCATED buffer still surfaces as the CDR layer's BUFFER-OVERFLOW signal
   (the hand-written CDR primitives are a later slice), so a caller wanting total robustness against a
   hostile peer must BOTH check the status AND keep a handler for that — which both callers do."
  (let* ((buf (dds.core.buffer:make-octet-buffer (max 16 (length octets))))
         (c (dds.core.buffer:cursor buf :endianness :little)))
    (replace (dds.core.buffer:octet-buffer-vec buf) octets)
    (unwind-protect
         (progn
           (dds.cdr:cdr-get-dheader c :xcdr2)
           (dds.cdr:cdr-align c 4 :xcdr2)
           (multiple-value-bind (mu lc id) (dds.cdr:emheader1-decode (dds.core.buffer:get-u32 c))
             (declare (ignore mu))
             (unless (= id #x1001)
               (bail :not-minimal-member))
             ;; LC>=4: NEXTINT carries the member length (§7.4.3.4.2)
             (when (>= lc 4) (dds.core.buffer:get-u32 c))
             ;; LC=4: a separate member DHEADER follows; LC>=5: NEXTINT was the DHEADER
             (when (= lc 4) (dds.cdr:cdr-get-dheader c :xcdr2))
             (dds.cdr:cdr-get-dheader c :xcdr2)
             (let ((disc (dds.core.buffer:get-u8 c)))
               (unless (= disc +ek-minimal+)
                 (bail :not-ek-minimal))
               (let ((h (make-array 14 :element-type '(unsigned-byte 8))))
                 (dds.core.buffer:get-octets c h 0 14)
                 (values h nil)))))
      (dds.pal:free-static (dds.core.buffer:octet-buffer-vec buf)))))
