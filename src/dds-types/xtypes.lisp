;;;; XTypes TypeIdentifier + structural (Minimal) TypeObject model (M4, FR-TYPE-2).
;;;; Control-plane CLOS-free value structs. Octet constants pinned from
;;;; docs/specs/xtypes-1_3_typeobject.idl (§8-70). This is the IN-MEMORY structural
;;;; type description: TypeIdentifiers for primitives/strings/plain-sequences (the
;;;; "explicit description" kinds), plus a struct's member list with NameHashes. It is
;;;; the foundation for type assignability (FR-TYPE-4) and feeds the (deferred,
;;;; Connext-oracle-gated) XCDR2 TypeObject serializer + EquivalenceHash. A struct's
;;;; OWN TypeIdentifier (EK_MINIMAL + hash) needs that serializer, so it is left
;;;; pending here; member references to nested structs likewise carry a pending hash.

(in-package #:dds.types)

;;; ---- TypeKind octets (idl §13-51) ----
(defconstant +tk-boolean+ #x01)
(defconstant +tk-byte+    #x02)            ; XTypes 1.3 8-bit kind (no distinct INT8/UINT8)
(defconstant +tk-int16+   #x03)
(defconstant +tk-int32+   #x04)
(defconstant +tk-int64+   #x05)
(defconstant +tk-uint16+  #x06)
(defconstant +tk-uint32+  #x07)
(defconstant +tk-uint64+  #x08)
(defconstant +tk-float32+ #x09)
(defconstant +tk-float64+ #x0a)
(defconstant +tk-float128+ #x0b)
(defconstant +tk-char8+   #x10)
(defconstant +tk-char16+  #x11)
(defconstant +tk-string8+ #x20)
(defconstant +tk-string16+ #x21)
(defconstant +tk-structure+ #x51)
(defconstant +tk-sequence+ #x60)
(defconstant +tk-array+   #x61)
;;; ---- EquivalenceKind (idl §8-10) ----
(defconstant +ek-minimal+ #xf1)
(defconstant +ek-complete+ #xf2)
;;; ---- TypeIdentifierKind (idl §56-70) ----
(defconstant +ti-string8-small+ #x70)
(defconstant +ti-string8-large+ #x71)
(defconstant +ti-plain-sequence-small+ #x80)
(defconstant +ti-plain-sequence-large+ #x81)

;;; ---- TypeIdentifier (idl §269 union, structural in-memory form) ----

(defstruct (type-identifier (:constructor %make-type-identifier) (:copier nil))
  "Structural XTypes TypeIdentifier. KIND is the discriminant octet (a TK_* primitive,
   a TI_STRING8_*/TI_PLAIN_SEQUENCE_*, or an EK_* for a hash-defined type). BOUND is the
   string/collection bound (0 = unbounded). ELEMENT is the collection element TI. HASH is
   the 14-octet EquivalenceHash for an EK_* kind, or NIL when the hash is pending (the
   serializer that computes it is deferred to a Connext oracle). REFERENCED is the in-memory
   minimal-struct-type an EK_* kind resolves to, so type assignability (FR-TYPE-4) can
   recurse into nested structs ahead of that deferred hash; NIL for non-aggregated kinds."
  (kind 0 :type (unsigned-byte 8))
  (bound 0 :type (integer 0))
  (element nil :type (or null type-identifier))
  (hash nil)
  (referenced nil))

(declaim (ftype (function (keyword) type-identifier) primitive-type-identifier))
(defun primitive-type-identifier (keyword)
  "The TypeIdentifier for a primitive / string DSL member KEYWORD. :u8/:i8 map to
   TK_BYTE (XTypes 1.3 has no distinct 8-bit int kind). :string is an unbounded STRING8."
  (let ((tk (ecase keyword
              (:bool +tk-boolean+) (:u8 +tk-byte+) (:i8 +tk-byte+)
              (:i16 +tk-int16+) (:u16 +tk-uint16+)
              (:i32 +tk-int32+) (:u32 +tk-uint32+)
              (:i64 +tk-int64+) (:u64 +tk-uint64+)
              (:string +tk-string8+))))
    (if (= tk +tk-string8+)
        (%make-type-identifier :kind +ti-string8-small+ :bound 0)   ; 0 = unbounded
        (%make-type-identifier :kind tk))))

(declaim (ftype (function (type-identifier &optional (integer 0)) type-identifier) sequence-type-identifier))
(defun sequence-type-identifier (element &optional (bound 0))
  "A plain-sequence TypeIdentifier with ELEMENT element TI and BOUND (0 = unbounded)."
  (%make-type-identifier :kind +ti-plain-sequence-small+ :bound bound :element element))

(declaim (ftype (function ((unsigned-byte 8) &key (:hash t) (:referenced t)) type-identifier) hash-type-identifier))
(defun hash-type-identifier (ek &key hash referenced)
  "A hash-defined TypeIdentifier (EK_MINIMAL/EK_COMPLETE). HASH is the 14-octet
   EquivalenceHash, or NIL when pending (the serializer is deferred). REFERENCED is the
   in-memory minimal-struct-type the identifier resolves to, letting assignability recurse
   ahead of the deferred hash."
  (%make-type-identifier :kind ek :hash hash :referenced referenced))

(declaim (ftype (function (type-identifier type-identifier) t) type-identifier=))
(defun type-identifier= (a b)
  "Structural equality of two TypeIdentifiers (FR-TYPE-2): same kind + bound, equal
   element (recursively), equal EquivalenceHash (both NIL or both equal), and the same
   referenced struct (compared by identity — distinct instances of the same nested type
   are EQ in this stack)."
  (and (= (type-identifier-kind a) (type-identifier-kind b))
       (= (type-identifier-bound a) (type-identifier-bound b))
       (eq (null (type-identifier-element a)) (null (type-identifier-element b)))
       (or (null (type-identifier-element a))
           (type-identifier= (type-identifier-element a) (type-identifier-element b)))
       (equalp (type-identifier-hash a) (type-identifier-hash b))
       (eq (type-identifier-referenced a) (type-identifier-referenced b))
       t))

;;; ---- Member name hash + the Minimal struct-type structural model ----

(declaim (ftype (function (string) (simple-array (unsigned-byte 8) (4))) member-name-hash))
(defun member-name-hash (name)
  "NameHash = first 4 octets of MD5(UTF-8 NAME without NUL) (idl §90-93). IDL member
   names are ASCII, so UTF-8 = the char codes. Example: \"color\" -> 70 dd a5 df."
  (let* ((bytes (map '(simple-array (unsigned-byte 8) (*)) #'char-code name))
         (out (make-array 4 :element-type '(unsigned-byte 8))))
    (replace out (dds.core.md5:md5 bytes) :end2 4)
    out))

(defstruct (minimal-struct-member (:constructor %make-minimal-struct-member))
  "A member of a Minimal struct type (idl §454): the IDL name + member id + member
   TypeIdentifier + key/optional/must-understand flags + the NameHash (the MINIMAL detail)."
  (name "" :type string)
  (id 0 :type (unsigned-byte 32))
  (type-identifier nil :type (or null type-identifier))
  (key-p nil)
  (optional-p nil)
  (must-understand-p nil)
  (name-hash nil))

(declaim (ftype (function (string (unsigned-byte 32) type-identifier &key (:key-p t) (:optional-p t) (:must-understand-p t)) minimal-struct-member) make-struct-member))
(defun make-struct-member (name id type-identifier &key key-p optional-p must-understand-p)
  "Build a Minimal struct member, computing its NameHash from NAME."
  (%make-minimal-struct-member :name name :id id :type-identifier type-identifier
                               :key-p key-p :optional-p optional-p
                               :must-understand-p must-understand-p
                               :name-hash (member-name-hash name)))

(defstruct (minimal-struct-type (:constructor make-minimal-struct-type))
  "A Minimal struct TypeObject (idl §499), structural form: the qualified type name,
   extensibility (:final/:appendable/:mutable), and the member list in member order."
  (name "" :type string)
  (extensibility :final)
  (members '() :type list))
