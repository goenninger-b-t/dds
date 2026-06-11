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
(defconstant +tk-boolean+ #x01 "XTypes TypeKind octet TK_BOOLEAN (idl §13-51).")
(defconstant +tk-byte+    #x02
  "XTypes TypeKind octet TK_BYTE (idl §13-51): the 1.3 8-bit kind (no distinct INT8/UINT8).")
(defconstant +tk-int16+   #x03 "XTypes TypeKind octet TK_INT16 (idl §13-51).")
(defconstant +tk-int32+   #x04 "XTypes TypeKind octet TK_INT32 (idl §13-51).")
(defconstant +tk-int64+   #x05 "XTypes TypeKind octet TK_INT64 (idl §13-51).")
(defconstant +tk-uint16+  #x06 "XTypes TypeKind octet TK_UINT16 (idl §13-51).")
(defconstant +tk-uint32+  #x07 "XTypes TypeKind octet TK_UINT32 (idl §13-51).")
(defconstant +tk-uint64+  #x08 "XTypes TypeKind octet TK_UINT64 (idl §13-51).")
(defconstant +tk-float32+ #x09 "XTypes TypeKind octet TK_FLOAT32 (idl §13-51).")
(defconstant +tk-float64+ #x0a "XTypes TypeKind octet TK_FLOAT64 (idl §13-51).")
(defconstant +tk-float128+ #x0b)
(defconstant +tk-char8+   #x10 "XTypes TypeKind octet TK_CHAR8 (idl §13-51).")
(defconstant +tk-char16+  #x11)
(defconstant +tk-string8+ #x20 "XTypes TypeKind octet TK_STRING8 (idl §13-51): narrow string.")
(defconstant +tk-string16+ #x21)
(defconstant +tk-structure+ #x51 "XTypes TypeKind octet TK_STRUCTURE (idl §13-51).")
(defconstant +tk-sequence+ #x60 "XTypes TypeKind octet TK_SEQUENCE (idl §13-51).")
(defconstant +tk-array+   #x61)
;;; ---- EquivalenceKind (idl §8-10) ----
(defconstant +ek-minimal+ #xf1 "XTypes EquivalenceKind octet EK_MINIMAL (idl §8-10).")
(defconstant +ek-complete+ #xf2 "XTypes EquivalenceKind octet EK_COMPLETE (idl §8-10).")
(defconstant +ek-both+ #xf3
  "XTypes EquivalenceKind octet EK_BOTH (idl §8-10): carried as the PlainCollectionHeader
   equiv_kind of fully-descriptive plain-collection elements (idl §181-183).")
;;; ---- TypeIdentifierKind (idl §56-70) ----
(defconstant +ti-string8-small+ #x70
  "XTypes TypeIdentifierKind octet TI_STRING8_SMALL (idl §56-70): narrow string, SBound.")
(defconstant +ti-string8-large+ #x71)
(defconstant +ti-plain-sequence-small+ #x80
  "XTypes TypeIdentifierKind octet TI_PLAIN_SEQUENCE_SMALL (idl §56-70): plain sequence, SBound.")
(defconstant +ti-plain-sequence-large+ #x81)

;;; ---- TypeIdentifier (idl §269 union, structural in-memory form) ----

(defstruct* (type-identifier (:constructor %make-type-identifier) (:copier nil))
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
  (hash nil :type (or null (array (unsigned-byte 8) (*))))
  (referenced nil :type t))

(defun* string8-type-identifier (&optional (bound 0))
    (function (&optional (integer 0)) type-identifier)
  "A narrow-string (STRING8) TypeIdentifier with BOUND (0 = unbounded). KIND is
   TI_STRING8_SMALL when BOUND <= 255 (the SBound form), TI_STRING8_LARGE when BOUND
   > 255 (the LBound form) — the 255 small/large threshold of idl §56-70, mirroring
   the %get-type-identifier/%put-type-identifier wire model (typeobject-cdr.lisp)."
  (%make-type-identifier :kind (if (> bound 255) +ti-string8-large+ +ti-string8-small+)
                         :bound bound))

(defun* primitive-type-identifier (keyword)
    (function (keyword) type-identifier)
  "The TypeIdentifier for a primitive / string DSL member KEYWORD. :u8/:i8 map to
   TK_BYTE (XTypes 1.3 has no distinct 8-bit int kind). :f32/:f64 are FLOAT32/FLOAT64,
   :char is CHAR8. :string is an unbounded STRING8."
  (if (eq keyword :string)
      (string8-type-identifier 0)
      (%make-type-identifier
       :kind (ecase keyword
               (:bool +tk-boolean+) (:u8 +tk-byte+) (:i8 +tk-byte+)
               (:i16 +tk-int16+) (:u16 +tk-uint16+)
               (:i32 +tk-int32+) (:u32 +tk-uint32+)
               (:i64 +tk-int64+) (:u64 +tk-uint64+)
               (:f32 +tk-float32+) (:f64 +tk-float64+) (:char +tk-char8+)))))

(defun* sequence-type-identifier (element &optional (bound 0))
    (function (type-identifier &optional (integer 0)) type-identifier)
  "A plain-sequence TypeIdentifier with ELEMENT element TI and BOUND (0 = unbounded)."
  (%make-type-identifier :kind +ti-plain-sequence-small+ :bound bound :element element))

(defun* hash-type-identifier (ek &key hash referenced)
    (function ((unsigned-byte 8) &key (:hash t) (:referenced t)) type-identifier)
  "A hash-defined TypeIdentifier (EK_MINIMAL/EK_COMPLETE). HASH is the 14-octet
   EquivalenceHash, or NIL when pending (the serializer is deferred). REFERENCED is the
   in-memory minimal-struct-type the identifier resolves to, letting assignability recurse
   ahead of the deferred hash."
  (%make-type-identifier :kind ek :hash hash :referenced referenced))

(defun* type-identifier= (a b)
    (function (type-identifier type-identifier) t)
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

(defun* member-name-hash (name)
    (function (string) (simple-array (unsigned-byte 8) (4)))
  "NameHash = first 4 octets of MD5(UTF-8 NAME without NUL) (idl §90-93). IDL member
   names are ASCII, so UTF-8 = the char codes. Example: \"color\" -> 70 dd a5 df."
  (let* ((bytes (map '(simple-array (unsigned-byte 8) (*)) #'char-code name))
         (out (make-array 4 :element-type '(unsigned-byte 8))))
    (replace out (dds.core.md5:md5 bytes) :end2 4)
    out))

(defstruct* (minimal-struct-member (:constructor %make-minimal-struct-member))
  "A member of a Minimal struct type (idl §454): the IDL name + member id + member
   TypeIdentifier + key/optional/must-understand flags + the NameHash (the MINIMAL detail)."
  (name "" :type string)
  (id 0 :type (unsigned-byte 32))
  (type-identifier nil :type (or null type-identifier))
  (key-p nil :type boolean)
  (optional-p nil :type boolean)
  (must-understand-p nil :type boolean)
  (name-hash nil :type (or null (simple-array (unsigned-byte 8) (4)))))

(defun* make-struct-member (name id type-identifier &key key-p optional-p must-understand-p)
    (function (string (unsigned-byte 32) type-identifier &key (:key-p t) (:optional-p t) (:must-understand-p t)) minimal-struct-member)
  "Build a Minimal struct member, computing its NameHash from NAME."
  (%make-minimal-struct-member :name name :id id :type-identifier type-identifier
                               :key-p key-p :optional-p optional-p
                               :must-understand-p must-understand-p
                               :name-hash (member-name-hash name)))

(defstruct* (minimal-struct-type (:constructor make-minimal-struct-type))
  "A Minimal struct TypeObject (idl §499), structural form: the qualified type name,
   extensibility (:final/:appendable/:mutable), and the member list in member order."
  (name "" :type string)
  (extensibility :final :type (member :final :appendable :mutable))
  (members '() :type list))
