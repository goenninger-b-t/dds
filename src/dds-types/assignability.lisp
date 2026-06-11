;;;; XTypes type assignability (is-assignable-from) + TYPE_CONSISTENCY_ENFORCEMENT
;;;; (M4, FR-TYPE-4). A pure structural relation over the in-memory (Minimal) TypeObject
;;;; model in xtypes.lisp; control-plane, CLOS-free (defstruct + monomorphic functions).
;;;; Rules pinned from XTypes 1.3 §7.2.4.4 (Tables 14-19), the delimited/strong-assignability
;;;; concepts (§7.2.4.2/3), and the enforcement Step-1 decision (§7.6.3.4.2). Verifiable-
;;;; first: the relation is logic, not wire bytes, so it is checked against the spec's own
;;;; worked examples (Coordinate2D/3D truncation, Vehicle/LandVehicle) with no Connext oracle.
;;;; Modeled kinds are exactly those the generator can construct and therefore test:
;;;; primitives, narrow strings, plain sequences, and (nested) structs. Union/enum/bitmask/
;;;; array/map/alias assignability awaits their type model (no generable instance to verify
;;;; today) and is conservatively non-assignable.

(in-package #:dds.types)

(defstruct* (assignability-options (:constructor make-assignability-options))
  "The four TypeConsistencyEnforcement fields that modulate is-assignable-from under
   ALLOW_TYPE_COERCION (XTypes §7.6.3.4.1). Spec defaults: bounds ignored, member names
   enforced, type widening permitted."
  (ignore-sequence-bounds t :type boolean)
  (ignore-string-bounds t :type boolean)
  (ignore-member-names nil :type boolean)
  (prevent-type-widening nil :type boolean))


(defun* default-assignability-options ()
    (function () assignability-options)
  "A fresh options struct carrying the XTypes §7.6.3.4.1 defaults."
  (make-assignability-options))

;;; ---- TypeIdentifier kind predicates (octets defined in xtypes.lisp) ----

(defun* ti-primitive-p (ti)
    (function (type-identifier) t)
  "True if TI is a primitive TypeKind (boolean..float128, char8/char16)."
  (let ((k (type-identifier-kind ti)))
    (or (<= +tk-boolean+ k +tk-float128+) (= k +tk-char8+) (= k +tk-char16+))))

(defun* ti-string-p (ti)
    (function (type-identifier) t)
  "True if TI is a narrow string (TI_STRING8_SMALL/LARGE)."
  (let ((k (type-identifier-kind ti)))
    (or (= k +ti-string8-small+) (= k +ti-string8-large+))))

(defun* ti-sequence-p (ti)
    (function (type-identifier) t)
  "True if TI is a plain sequence (TI_PLAIN_SEQUENCE_SMALL/LARGE)."
  (let ((k (type-identifier-kind ti)))
    (or (= k +ti-plain-sequence-small+) (= k +ti-plain-sequence-large+))))

(defun* ti-aggregated-p (ti)
    (function (type-identifier) t)
  "True if TI is a hash-defined aggregated type (EK_MINIMAL/EK_COMPLETE) carrying a
   resolved in-memory referenced struct."
  (let ((k (type-identifier-kind ti)))
    (and (or (= k +ek-minimal+) (= k +ek-complete+))
         (minimal-struct-type-p (type-identifier-referenced ti)))))

;;; ---- Bound comparison (0 = unbounded = the maximum) ----

(defun* bound>= (b1 b2)
    (function ((integer 0) (integer 0)) t)
  "T1.bound >= T2.bound, with 0 meaning unbounded (the maximum): an unbounded T1 always
   satisfies it; a bounded T1 never satisfies an unbounded T2."
  (cond ((zerop b1) t) ((zerop b2) nil) (t (>= b1 b2))))

;;; ---- Delimited types (XTypes §7.2.4.2), assuming XCDR2 (the stack default) ----

(defun* ti-delimited-p (ti)
    (function (type-identifier) t)
  "Whether an object of type TI is self-delimiting under XCDR2 (§7.2.4.2): primitives and
   strings are; a sequence is iff its element is; an aggregated type is iff its
   extensibility is APPENDABLE or MUTABLE (FINAL aggregated types are not delimited)."
  (cond ((ti-primitive-p ti) t)
        ((ti-string-p ti) t)
        ((ti-sequence-p ti)
         (let ((e (type-identifier-element ti))) (and e (ti-delimited-p e) t)))
        ((ti-aggregated-p ti)
         (and (member (minimal-struct-type-extensibility (type-identifier-referenced ti))
                      '(:appendable :mutable))
              t))
        (t nil)))

;;; ---- is-assignable-from at the TypeIdentifier level (Tables 15-17 + nested 19) ----

(defun* ti-assignable-from (t1 t2 opts)
    (function (type-identifier type-identifier assignability-options) t)
  "T1 is-assignable-from T2 at the TypeIdentifier level (XTypes §7.2.4.4): primitives are
   assignable from the same primitive kind (Table 15); narrow strings from narrow strings
   under the bound rule gated by ignore_string_bounds (Table 16); plain sequences when the
   element is strongly-assignable and the bound rule (gated by ignore_sequence_bounds)
   holds (Table 17); nested structs by recursing on the referenced struct (Table 19).
   Unmodeled or mismatched kinds are not assignable."
  (cond
    ((and (ti-primitive-p t1) (ti-primitive-p t2))
     (= (type-identifier-kind t1) (type-identifier-kind t2)))
    ((and (ti-string-p t1) (ti-string-p t2))
     (or (assignability-options-ignore-string-bounds opts)
         (bound>= (type-identifier-bound t1) (type-identifier-bound t2))))
    ((and (ti-sequence-p t1) (ti-sequence-p t2))
     (let ((e1 (type-identifier-element t1)) (e2 (type-identifier-element t2)))
       (and e1 e2
            (strongly-assignable-from e1 e2 opts)
            (or (assignability-options-ignore-sequence-bounds opts)
                (bound>= (type-identifier-bound t1) (type-identifier-bound t2)))
            t)))
    ((and (ti-aggregated-p t1) (ti-aggregated-p t2))
     (struct-assignable-from (type-identifier-referenced t1)
                             (type-identifier-referenced t2) opts))
    (t nil)))

(defun* strongly-assignable-from (t1 t2 opts)
    (function (type-identifier type-identifier assignability-options) t)
  "T1 is strongly-assignable-from T2 (§7.2.4.3): assignable-from AND T2 is a delimited
   type. Required for collection elements and aggregated key members."
  (and (ti-assignable-from t1 t2 opts) (ti-delimited-p t2) t))

;;; ---- Struct (aggregated) assignability (XTypes §7.2.4.4.8, Table 19) ----

(defun* member-by-id (id members)
    (function ((unsigned-byte 32) list) (or null minimal-struct-member) )
  "The member in MEMBERS whose id = ID, or NIL."
  (find id members :key #'minimal-struct-member-id :test #'=))

(defun* key-erase-struct (s)
    (function (minimal-struct-type) minimal-struct-type)
  "A copy of struct S with @key cleared on every immediate member (XTypes KeyErased;
   deeper levels are erased as the relation recurses through them)."
  (make-minimal-struct-type
   :name (minimal-struct-type-name s)
   :extensibility (minimal-struct-type-extensibility s)
   :members (mapcar (lambda (m)
                      (let ((c (copy-minimal-struct-member m)))
                        (setf (minimal-struct-member-key-p c) nil)
                        c))
                    (minimal-struct-type-members s))))

(defun* key-erase-ti (ti)
    (function (type-identifier) type-identifier)
  "KeyErased(TI): for an aggregated type, the same kind referencing a key-erased struct;
   for any other type, TI unchanged (no keys to erase)."
  (if (ti-aggregated-p ti)
      (hash-type-identifier (type-identifier-kind ti)
                            :referenced (key-erase-struct (type-identifier-referenced ti)))
      ti))

(defun* member-names-agree-p (a b)
    (function (minimal-struct-member minimal-struct-member) t)
  "Whether members A and B count as having 'the same name' for the §7.2.4.4.8 Table 19
   name<->id correspondence. A Minimal TypeObject erases member names, carrying only the
   4-octet MinimalMemberDetail.name_hash (xtypes-1_3_typeobject.idl MinimalMemberDetail;
   hash rule XTypes 1.3 §7.2.2.4.4.4.5: first 4 octets of MD5(UTF-8 name)), so when BOTH
   sides carry a NameHash that hash IS the member-name identity (EQUALP); the string
   names are compared only when either side's hash is absent. Keeps a wire-parsed model
   (name \"\" + wire NameHash) comparable against a locally-built one."
  (let ((ha (minimal-struct-member-name-hash a))
        (hb (minimal-struct-member-name-hash b)))
    (if (and ha hb)
        (equalp ha hb)
        (string= (minimal-struct-member-name a) (minimal-struct-member-name b)))))

(defun* member-names-ids-consistent-p (members1 members2 ignore-names)
    (function (list list t) t)
  "Member name<->id correspondence (§7.2.4.4.8): across the two lists, members with the
   same name have the same id and members with the same id have the same name — name
   identity per MEMBER-NAMES-AGREE-P (NameHash when both sides carry one; Minimal erases
   names). When IGNORE-NAMES is true, names/hashes are not consulted at all (only ids
   matter, §7.6.3.4.2)."
  (if ignore-names
      t
      (dolist (a members1 t)
        (dolist (b members2)
          (when (and (= (minimal-struct-member-id a) (minimal-struct-member-id b))
                     (not (member-names-agree-p a b)))
            (return-from member-names-ids-consistent-p nil))
          (when (and (member-names-agree-p a b)
                     (not (= (minimal-struct-member-id a) (minimal-struct-member-id b))))
            (return-from member-names-ids-consistent-p nil))))))

(defun* key-member-bound-ok-p (m1 m2)
    (function (minimal-struct-member minimal-struct-member) t)
  "Key sub-bound rule (§7.2.4.4.8): for a string or sequence key member, the T1 member's
   bound must be >= the T2 member's bound (0 = unbounded). Scalar key members carry no
   bound and pass. (The DSL restricts @key to scalar/string, so struct/union/enum key
   sub-rules are unreachable today and conservatively pass.)"
  (let ((ti1 (minimal-struct-member-type-identifier m1))
        (ti2 (minimal-struct-member-type-identifier m2)))
    (if (and ti1 ti2 (or (and (ti-string-p ti1) (ti-string-p ti2))
                         (and (ti-sequence-p ti1) (ti-sequence-p ti2))))
        (bound>= (type-identifier-bound ti1) (type-identifier-bound ti2))
        t)))

(defun* struct-assignable-from (s1 s2 opts)
    (function (minimal-struct-type minimal-struct-type assignability-options) t)
  "STRUCTURE_TYPE is-assignable-from (XTypes §7.2.4.4.8, Table 19): T1=S1 is-assignable-from
   T2=S2. Checks the common conditions (same extensibility; name/id correspondence; >=1
   corresponding member; KeyErased member-type assignability; must_understand and key
   members present in both; key sub-bounds) then the FINAL/APPENDABLE/MUTABLE member-
   matching rules, plus prevent_type_widening. Members are matched by id; base-type members
   are assumed already flattened (the spec's evaluation model)."
  (let ((m1s (minimal-struct-type-members s1))
        (m2s (minimal-struct-type-members s2))
        (ext (minimal-struct-type-extensibility s1)))
    (block result
      (unless (eq ext (minimal-struct-type-extensibility s2)) (return-from result nil))
      (unless (member-names-ids-consistent-p m1s m2s (assignability-options-ignore-member-names opts))
        (return-from result nil))
      (unless (some (lambda (b) (member-by-id (minimal-struct-member-id b) m1s)) m2s)
        (return-from result nil))
      (dolist (b m2s)
        (let ((a (member-by-id (minimal-struct-member-id b) m1s)))
          (when a
            (let ((ta (minimal-struct-member-type-identifier a))
                  (tb (minimal-struct-member-type-identifier b)))
              (when (and ta tb
                         (not (ti-assignable-from (key-erase-ti ta) (key-erase-ti tb) opts)))
                (return-from result nil))))))
      (dolist (m (append m1s m2s))
        (when (and (minimal-struct-member-must-understand-p m)
                   (not (minimal-struct-member-optional-p m)))
          (unless (and (member-by-id (minimal-struct-member-id m) m1s)
                       (member-by-id (minimal-struct-member-id m) m2s))
            (return-from result nil))))
      (dolist (m (append m1s m2s))
        (when (minimal-struct-member-key-p m)
          (unless (and (member-by-id (minimal-struct-member-id m) m1s)
                       (member-by-id (minimal-struct-member-id m) m2s))
            (return-from result nil))))
      (dolist (b m2s)
        (when (minimal-struct-member-key-p b)
          (let ((a (member-by-id (minimal-struct-member-id b) m1s)))
            (when (and a (not (key-member-bound-ok-p a b))) (return-from result nil)))))
      (when (assignability-options-prevent-type-widening opts)
        (dolist (b m2s)
          (when (and (not (minimal-struct-member-optional-p b))
                     (not (member-by-id (minimal-struct-member-id b) m1s)))
            (return-from result nil))))
      (ecase ext
        (:mutable nil)
        ((:appendable :final)
         (let ((n (min (length m1s) (length m2s))))
           (dotimes (i n)
             (let ((a (nth i m1s)) (b (nth i m2s)))
               (let ((ta (minimal-struct-member-type-identifier a))
                     (tb (minimal-struct-member-type-identifier b)))
                 (unless (and (= (minimal-struct-member-id a) (minimal-struct-member-id b))
                              (eq (and (minimal-struct-member-optional-p a) t)
                                  (and (minimal-struct-member-optional-p b) t))
                              ta tb (strongly-assignable-from ta tb opts))
                   (return-from result nil)))))
           (when (eq ext :final)
             (unless (and (= (length m1s) (length m2s))
                          (every (lambda (a) (member-by-id (minimal-struct-member-id a) m2s)) m1s)
                          (every (lambda (b) (member-by-id (minimal-struct-member-id b) m1s)) m2s))
               (return-from result nil))))))
      (return-from result t))))

;;; ---- Structural MINIMAL-equivalence (a verifiable stand-in for EquivalenceHash) ----

(defun* ti-equivalent-p (t1 t2)
    (function (type-identifier type-identifier) t)
  "Structural MINIMAL-equivalence of two TypeIdentifiers (§7.3.4.7 stand-in for the
   deferred EquivalenceHash): same kind + bound, recursively-equivalent element, and an
   equivalent referenced struct (both NIL or both equivalent structs)."
  (and (= (type-identifier-kind t1) (type-identifier-kind t2))
       (= (type-identifier-bound t1) (type-identifier-bound t2))
       (eq (null (type-identifier-element t1)) (null (type-identifier-element t2)))
       (or (null (type-identifier-element t1))
           (ti-equivalent-p (type-identifier-element t1) (type-identifier-element t2)))
       (let ((r1 (type-identifier-referenced t1)) (r2 (type-identifier-referenced t2)))
         (cond ((and (null r1) (null r2)) t)
               ((and (minimal-struct-type-p r1) (minimal-struct-type-p r2))
                (struct-equivalent-p r1 r2))
               (t nil)))))

(defun* struct-equivalent-p (s1 s2)
    (function (minimal-struct-type minimal-struct-type) t)
  "Structural MINIMAL-equivalence of two struct TypeObjects (§7.3.4.7 stand-in): same
   extensibility, same member count, and pairwise (in member order) same id, same @key,
   same @optional, and equivalent member type. Member NAMES are not compared (MINIMAL
   erases them). True EquivalenceHash equality awaits the deferred XCDR2 serializer."
  (and (eq (minimal-struct-type-extensibility s1) (minimal-struct-type-extensibility s2))
       (= (length (minimal-struct-type-members s1)) (length (minimal-struct-type-members s2)))
       (every (lambda (a b)
                (and (= (minimal-struct-member-id a) (minimal-struct-member-id b))
                     (eq (and (minimal-struct-member-key-p a) t)
                         (and (minimal-struct-member-key-p b) t))
                     (eq (and (minimal-struct-member-optional-p a) t)
                         (and (minimal-struct-member-optional-p b) t))
                     (let ((ta (minimal-struct-member-type-identifier a))
                           (tb (minimal-struct-member-type-identifier b)))
                       (and ta tb (ti-equivalent-p ta tb) t))))
              (minimal-struct-type-members s1) (minimal-struct-type-members s2))
       t))

;;; ---- TYPE_CONSISTENCY_ENFORCEMENT Step-1 decision (XTypes §7.6.3.4.2) ----

(defun* enforce-type-consistency (reader-type writer-type
                                 &key (kind :allow-type-coercion)
                                      (ignore-sequence-bounds t)
                                      (ignore-string-bounds t)
                                      (ignore-member-names nil)
                                      (prevent-type-widening nil))
    (function (minimal-struct-type minimal-struct-type &key (:kind symbol) (:ignore-sequence-bounds t) (:ignore-string-bounds t) (:ignore-member-names t) (:prevent-type-widening t)) t)
  "TypeConsistencyEnforcement Step-1 decision (XTypes §7.6.3.4.2) for the TypeObject-present
   case: under ALLOW_TYPE_COERCION the READER-TYPE must be is-assignable-from the
   WRITER-TYPE, taking the four options into account; under DISALLOW_TYPE_COERCION the two
   types must be (MINIMAL-)equivalent. Returns T iff the types are consistent. (Step 2 — the
   type-name fallback and force_type_validation when no TypeObject is on the wire — is a
   DCPS match-time concern, deferred until SEDP carries PID_TYPE_INFORMATION.)"
  (ecase kind
    (:allow-type-coercion
     (struct-assignable-from
      reader-type writer-type
      (make-assignability-options :ignore-sequence-bounds ignore-sequence-bounds
                                  :ignore-string-bounds ignore-string-bounds
                                  :ignore-member-names ignore-member-names
                                  :prevent-type-widening prevent-type-widening)))
    (:disallow-type-coercion
     (struct-equivalent-p reader-type writer-type))))
