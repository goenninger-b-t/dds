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

(declaim (ftype (function (symbol) (unsigned-byte 16)) %struct-type-flag))
(declaim (ftype (function (minimal-struct-member) (unsigned-byte 16)) %member-flag))
(declaim (ftype (function (dds.core.buffer:cursor) (integer 0)) %dheader-begin))
(declaim (ftype (function (dds.core.buffer:cursor (integer 0)) (integer 0)) %dheader-end))
(declaim (ftype (function (dds.core.buffer:cursor type-identifier) t) %put-type-identifier))
(declaim (ftype (function (dds.core.buffer:cursor minimal-struct-member) t) %put-common-struct-member))
(declaim (ftype (function (dds.core.buffer:cursor minimal-struct-member) t) %put-minimal-member-detail))
(declaim (ftype (function (dds.core.buffer:cursor minimal-struct-type) t) %put-minimal-struct-type))
(declaim (ftype (function (dds.core.buffer:cursor minimal-struct-type) t) %put-minimal-type-object))
(declaim (ftype (function (dds.core.buffer:cursor minimal-struct-type) t) %put-type-object))
(declaim (ftype (function (minimal-struct-type) (simple-array (unsigned-byte 8) (*))) minimal-type-object-octets))
(declaim (ftype (function (minimal-struct-type) (simple-array (unsigned-byte 8) (*))) equivalence-hash))

(defun %struct-type-flag (extensibility)
  "Minimal-masked StructTypeFlag (idl §163, TypeFlagMinimalMask 0x0007): the
   extensibility bit only (no IS_NESTED/IS_AUTOID_HASH, which do not affect assignability)."
  (ecase extensibility
    (:final +type-flag-is-final+)
    (:appendable +type-flag-is-appendable+)
    (:mutable +type-flag-is-mutable+)))

(defun %member-flag (m)
  "Minimal-masked StructMemberFlag (idl §139, MemberFlagMinimalMask 0x003f): TRY_CONSTRUCT
   DISCARD OR'd with @optional/@must_understand/@key. PROVISIONAL: the TRY_CONSTRUCT default
   and whether non-optional members carry @must_understand are Connext-confirmable."
  (logior +member-flag-try-construct-discard+
          (if (minimal-struct-member-optional-p m) +member-flag-is-optional+ 0)
          (if (minimal-struct-member-must-understand-p m) +member-flag-is-must-understand+ 0)
          (if (minimal-struct-member-key-p m) +member-flag-is-key+ 0)))

;;; ---- DHEADER backpatching: write a placeholder, fill the size after the content ----

(defun %dheader-begin (cursor)
  "Align to 4 and write a placeholder DHEADER UInt32; return its byte position."
  (dds.cdr:cdr-align cursor 4 :xcdr2)
  (let ((p (dds.core.buffer:cursor-position cursor)))
    (dds.core.buffer:put-u32 cursor 0)
    p))

(defun %dheader-end (cursor start)
  "Backpatch the DHEADER at START with the serialized size of the content that follows it
   (XTypes §7.4.3.4.1: the size excludes the DHEADER itself)."
  (let ((e (dds.core.buffer:cursor-position cursor)))
    (dds.core.buffer:cursor-set-position cursor start)
    (dds.core.buffer:put-u32 cursor (- e start 4))
    (dds.core.buffer:cursor-set-position cursor e)
    e))

;;; ---- TypeIdentifier (FINAL union, rule 26): discriminator octet + arm ----

(defun %put-type-identifier (cursor ti)
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

(defun %put-common-struct-member (cursor m)
  "CommonStructMember: member_id (UInt32) + member_flags (UInt16) + member_type_id."
  (dds.cdr:cdr-put-u32 cursor (minimal-struct-member-id m) :xcdr2)
  (dds.cdr:cdr-put-u16 cursor (%member-flag m) :xcdr2)
  (%put-type-identifier cursor (minimal-struct-member-type-identifier m))
  t)

(defun %put-minimal-member-detail (cursor m)
  "MinimalMemberDetail: the 4-octet NameHash."
  (dds.core.buffer:put-octets cursor (minimal-struct-member-name-hash m) 0 4)
  t)

;;; ---- MinimalStructType (FINAL, rule 17): struct_flags + header + member_seq ----

(defun %put-minimal-struct-type (cursor s)
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

(defun %put-minimal-type-object (cursor s)
  "MinimalTypeObject FINAL union: TK_STRUCTURE discriminator + MinimalStructType arm."
  (dds.core.buffer:put-u8 cursor +tk-structure+)
  (%put-minimal-struct-type cursor s)
  t)

(defun %put-type-object (cursor s)
  "TypeObject APPENDABLE union: DHEADER + EK_MINIMAL discriminator + MinimalTypeObject."
  (let ((p (%dheader-begin cursor)))
    (dds.core.buffer:put-u8 cursor +ek-minimal+)
    (%put-minimal-type-object cursor s)
    (%dheader-end cursor p))
  t)

(defun minimal-type-object-octets (s)
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

(defun equivalence-hash (s)
  "EquivalenceHash(S) = first 14 octets of MD5 of the serialized MinimalTypeObject
   (XTypes §7.3.4.9.1). Nested struct members recurse to the referenced struct's hash."
  (subseq (dds.core.md5:md5 (minimal-type-object-octets s)) 0 14))
