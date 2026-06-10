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
;;;; PROVISIONAL pending a Connext oracle (owner decision 2026-06-06 "build now, confirm
;;;; vs Connext"). Three byte-level choices are spec-faithful but unconfirmed against a
;;;; conformant peer, and are the single points to flip when Connext reference vectors
;;;; arrive: (1) the hash is over the raw TypeObject XCDR2-LE bytes with NO 4-byte
;;;; encapsulation header; (2) struct_flags = the extensibility bit only (minimal-masked,
;;;; XTypes TypeFlagMinimalMask 0x0007); (3) member_flags = TRY_CONSTRUCT=DISCARD (0x01)
;;;; OR'd with @optional/@must_understand/@key (minimal-masked 0x003f). Sequence-member
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
   DISCARD OR'd with @optional/@must_understand/@key. PROVISIONAL: the TRY_CONSTRUCT default
   and whether non-optional members carry @must_understand are Connext-confirmable."
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

;;; ---- MUTABLE member framing: EMHEADER1 LC=4 + backpatched NEXTINT (§7.4.3.4.2) ----

(defun* %mutable-member-begin (c id &optional mu)
    (function (dds.core.buffer:cursor (unsigned-byte 28) &optional t) (integer 0))
  "Write EMHEADER1 (M_FLAG=MU, LC=4) for member ID plus a placeholder NEXTINT; return
   the NEXTINT's byte position for %mutable-member-end. MU defaults to NIL: the member
   must_understand attribute defaults to false (XTypes 1.3 §7.2.2.4.4.4 / §7.2.2.4.4.4.6)
   absent an @must_understand annotation; pass T only for annotated members."
  (dds.cdr:cdr-align c 4 :xcdr2)
  (dds.core.buffer:put-u32 c (dds.cdr:emheader1-encode mu 4 id))
  (let ((np (dds.core.buffer:cursor-position c)))
    (dds.core.buffer:put-u32 c 0)
    np))

(defun* %mutable-member-end (c np)
    (function (dds.core.buffer:cursor (integer 0)) (integer 0))
  "Backpatch the NEXTINT at NP with the member's serialized length (LC=4: NEXTINT is
   the byte length of the member that follows it, §7.4.3.4.2)."
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
   (XTypes §7.3.4.9.1). Nested struct members recurse to the referenced struct's hash."
  (subseq (dds.core.md5:md5 (minimal-type-object-octets s)) 0 14))

;;;; TypeInformation codec (M4 step b1, FR-TYPE-3 foundation). The TypeInformation carried
;;;; in PublicationBuiltinTopicData/SubscriptionBuiltinTopicData (PID_TYPE_INFORMATION,
;;;; idl @id(0x0075)) so peers learn a type's EquivalenceHash-based TypeIdentifier without
;;;; the full TypeObject (XTypes §7.6.3.4 / §7.3.4.9.1). Structure (xtypes-1_3_typeobject.idl):
;;;; TypeInformation (MUTABLE) { @id(0x1001) minimal; @id(0x1002) complete; }; each member is
;;;; a TypeIdentifierWithDependencies (APPENDABLE) { TypeIdentfierWithSize [sic] typeid_with_size;
;;;; long dependent_typeid_count; sequence<TypeIdentfierWithSize> dependent_typeids; };
;;;; TypeIdentfierWithSize (APPENDABLE) { TypeIdentifier type_id; unsigned long
;;;; typeobject_serialized_size; }. PROVISIONAL like the TypeObject serializer: minimal-only
;;;; (the complete member is omitted, MUTABLE permits it); the mutable member uses LC=4
;;;; (explicit NEXTINT length) with M_FLAG=0 (the §7.2.2.4.4.4.6 must_understand default;
;;;; the IDL has no @must_understand); dependent ordering is insertion order. Confirm vs
;;;; Connext.


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
   carries no @must_understand on its members). CONFIRM-VS-PEER."
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
    (function ((simple-array (unsigned-byte 8) (*))) (simple-array (unsigned-byte 8) (*)))
  "Parse a serialized TypeInformation and return its minimal EK_MINIMAL TypeIdentifier's
   14-octet EquivalenceHash (the value endpoint matching needs). Lenient: walks the top
   DHEADER, the @id(0x1001) member EMHEADER1 (+NEXTINT), and the two APPENDABLE DHEADERs."
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
               (error "TypeInformation parse: expected minimal member 0x1001, got #x~x" id))
             (when (>= lc 4) (dds.core.buffer:get-u32 c))
             (dds.cdr:cdr-get-dheader c :xcdr2)
             (dds.cdr:cdr-get-dheader c :xcdr2)
             (let ((disc (dds.core.buffer:get-u8 c)))
               (unless (= disc +ek-minimal+)
                 (error "TypeInformation parse: expected EK_MINIMAL type_id, got #x~x" disc))
               (let ((h (make-array 14 :element-type '(unsigned-byte 8))))
                 (dds.core.buffer:get-octets c h 0 14)
                 h))))
      (dds.pal:free-static (dds.core.buffer:octet-buffer-vec buf)))))
