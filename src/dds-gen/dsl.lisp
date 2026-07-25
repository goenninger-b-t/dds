(in-package #:dds.gen)

(defparameter *dds-type-map*
  ;; dds-type -> (lisp-type default put-fn get-fn align size|:var)
  '((:bool   t                  nil dds.cdr:cdr-put-bool   dds.cdr:cdr-get-bool   1 1)
    (:u8     (unsigned-byte 8)  0   dds.cdr:cdr-put-u8     dds.cdr:cdr-get-u8     1 1)
    (:byte   (unsigned-byte 8)  0   dds.cdr:cdr-put-u8     dds.cdr:cdr-get-u8     1 1)
    (:octet  (unsigned-byte 8)  0   dds.cdr:cdr-put-u8     dds.cdr:cdr-get-u8     1 1)
    (:u16    (unsigned-byte 16) 0   dds.cdr:cdr-put-u16    dds.cdr:cdr-get-u16    2 2)
    (:u32    (unsigned-byte 32) 0   dds.cdr:cdr-put-u32    dds.cdr:cdr-get-u32    4 4)
    (:u64    (unsigned-byte 64) 0   dds.cdr:cdr-put-u64    dds.cdr:cdr-get-u64    8 8)
    (:i8     (signed-byte 8)    0   dds.cdr:cdr-put-i8     dds.cdr:cdr-get-i8     1 1)
    (:i16    (signed-byte 16)   0   dds.cdr:cdr-put-i16    dds.cdr:cdr-get-i16    2 2)
    (:i32    (signed-byte 32)   0   dds.cdr:cdr-put-i32    dds.cdr:cdr-get-i32    4 4)
    (:i64    (signed-byte 64)   0   dds.cdr:cdr-put-i64    dds.cdr:cdr-get-i64    8 8)
    (:string string             ""  dds.cdr:cdr-put-string dds.cdr:cdr-get-string 4 :var))
  "Maps an s-expr DSL member type to its Lisp slot type, default, codec ops, CDR
   alignment, and serialized size (:var = data-dependent). Sizes/alignment follow
   REQUIREMENTS FR-CDR-1/2; string size = 4 (length) + octets + 1 (NUL). :u8/:i8 are the
   numeric 8-bit integers (TK_UINT8/TK_INT8); :byte (alias :octet) is the opaque octet
   (TK_BYTE, IDL `octet`) — all three share the one-octet wire codec but carry distinct
   XTypes kinds (D1).")

(defparameter *sample-pool-capacity* 64
  "Per-type sample-pool size, pre-allocated at registration (NFR-MEM). A later
   ADR derives this from the RESOURCE_LIMITS QoS.")

(defun* %sym (package &rest parts)
    (function (package &rest t) symbol)
  "Intern the concatenation of PARTS (string designators) as a symbol in PACKAGE."
  (intern (apply #'concatenate 'string (mapcar #'string parts)) package))

(defparameter *dds-enum-literals* (make-hash-table :test 'eq)
  "Enum name symbol -> the list of its declared keywords, in declaration order. Populated at
   COMPILE time by define-dds-enum so a later define-dds-type can give an (:enum name) member an
   exact slot type. Define-before-use, exactly as nested struct members require.")

(defmacro define-dds-enum (name &rest literals)
  "Define the DDS enumerated type NAME from LITERALS, each `(keyword value)`.

   The wire representation is int32: DDS-XTypes 1.3 §7.3.1.2.1 gives an enumeration a default bit
   bound of 32, and the value on the wire is the DECLARED constant, never the literal's ordinal
   position — which is why the values are written out rather than inferred.

   Emits `NAME-TO-I32` and `NAME-FROM-I32`, each returning `(values result status)` where status is
   `:unknown-enum-value` for an input this build does not declare. A newer revision of a type will
   send values we have never heard of; reporting one is honest, inventing a keyword for it is not.
   Emits the codec pair the type compiler wires into a member, and registers the literal list so
   `(:enum NAME)` members get an exact slot type."
  (let* ((pkg (or (symbol-package name) *package*))
         (to (%sym pkg (string name) "-TO-I32"))
         (from (%sym pkg (string name) "-FROM-I32"))
         (put (%sym pkg "%PUT-" (string name)))
         (get (%sym pkg "%GET-" (string name)))
         (kws (mapcar #'first literals))
         (vals (mapcar #'second literals)))
    (unless literals   ; NOCOND(MACRO): macroexpansion-time — compile-time rejection
      (error "define-dds-enum: ~s declares no literals" name))
    (unless (every (lambda (l) (and (consp l) (= 2 (length l)) (keywordp (first l))
                                    (typep (second l) '(signed-byte 32))))
                   literals)   ; NOCOND(MACRO): macroexpansion-time — compile-time rejection
      (error "define-dds-enum: each literal must be (keyword (signed-byte 32)); got ~s" literals))
    (unless (= (length kws) (length (remove-duplicates kws)))   ; NOCOND(MACRO): macroexpansion-time
      (error "define-dds-enum: duplicate keyword in ~s" name))
    ;; Two literals sharing a value make FROM-I32 ambiguous — the wire could not say which was meant.
    (unless (= (length vals) (length (remove-duplicates vals)))   ; NOCOND(MACRO): macroexpansion-time
      (error "define-dds-enum: duplicate value in ~s — a wire value must decode to ONE literal" name))
    `(progn
       (eval-when (:compile-toplevel :load-toplevel :execute)
         (setf (gethash ',name dds.gen::*dds-enum-literals*) ',kws))
       (declaim (ftype (function (t) (values (or null (signed-byte 32)) (or null keyword))) ,to))
       (defun ,to (keyword)
         ,(format nil "The declared int32 value of KEYWORD in ~(~a~), or ~
                       (values NIL :UNKNOWN-ENUM-VALUE) if it declares no such literal." name)
         (case keyword
           ,@(loop for l in literals collect `(,(first l) (values ,(second l) nil)))
           (t (values nil :unknown-enum-value))))
       (declaim (ftype (function ((signed-byte 32)) (values (or null keyword) (or null keyword))) ,from))
       (defun ,from (value)
         ,(format nil "The ~(~a~) literal with int32 VALUE, or (values NIL :UNKNOWN-ENUM-VALUE) if ~
                       this build declares none — a peer built from a newer revision of the type ~
                       will send values this one does not know, and the only honest answers are to ~
                       report it or drop it, never to invent a literal." name)
         (case value
           ,@(loop for l in literals collect `(,(second l) (values ,(first l) nil)))
           (t (values nil :unknown-enum-value))))
       (declaim (ftype (function (dds.core.buffer:cursor t &optional symbol) t) ,put))
       (defun ,put (cursor value &optional (mode :xcdr2))
         ,(format nil "Write ~(~a~) VALUE as int32 (XTypes 1.3 §7.3.1.2.1). A declared keyword is ~
                       written as its declared constant; an int32 (what an undecodable wire value ~
                       decodes to) is written back UNCHANGED, so relaying a sample cannot ~
                       fabricate a value the sender never sent." name)
         (dds.cdr:cdr-put-i32 cursor (if (keywordp value) (,to value) value) mode))
       (declaim (ftype (function (dds.core.buffer:cursor &optional symbol) t) ,get))
       (defun ,get (cursor &optional (mode :xcdr2))
         ,(format nil "Read an int32 and map it to its ~(~a~) literal, or return the RAW INT32 when ~
                       this build declares no literal for it. Never a wrong keyword." name)
         (let ((v (dds.cdr:cdr-get-i32 cursor mode)))
           (or (,from v) v)))
       ',name)))

(defun* %parse-member (spec)
    (function (list) list)
  "Parse a member spec into a codegen plist. Member type is a primitive keyword,
   (:sequence ELEMENT-KEYWORD) for a sequence of fixed-size primitives, or the
   symbol of a previously-defined dds type for a nested struct."
  (destructuring-bind (slot dds-type &rest opts) spec
    (cond
      ((and (consp dds-type) (eq (car dds-type) :sequence))
       (let* ((elt (second dds-type))
              (row (cdr (assoc elt *dds-type-map*))))
         (unless row   ; NOCOND(MACRO): macroexpansion-time — rejects a malformed type spec at COMPILE time
           (error "define-dds-type: unsupported sequence element ~s in ~s" elt spec))
         (destructuring-bind (eltype default eput eget ealign esize) row
           (declare (ignore default))
           (when (eq esize :var)   ; NOCOND(MACRO): macroexpansion-time — compile-time rejection
             (error "define-dds-type: sequence of variable-size element ~s not supported in v1"
                    elt))
           ;; WP-PERF: :elt-ltype is the element's LISP type — it makes the decoded sequence a
           ;; SPECIALIZED vector instead of a simple-vector (8 B/element regardless of element type).
           (list :slot slot :kind :sequence :ltype 'vector :default '(vector)
                 :elt-put eput :elt-get eget :elt-align ealign :elt-size esize
                 :elt-type elt :elt-ltype eltype :key (getf opts :key)))))
      ((keywordp dds-type)
       (let ((row (cdr (assoc dds-type *dds-type-map*))))
         (unless row   ; NOCOND(MACRO): macroexpansion-time — compile-time rejection
           (error "define-dds-type: unsupported member type ~s in ~s" dds-type spec))
         (destructuring-bind (ltype default put get align size) row
           (list :slot slot :kind :scalar :ltype ltype :default default :put put :get get
                 :align align :var (eq size :var) :size (if (eq size :var) 0 size)
                 :dds-type dds-type :key (getf opts :key)))))
      ;; (:string N) — a BOUNDED string. Same wire codec as :string; the bound is part of the TYPE
      ;; (XTypes 1.3 §7.3.1.2.1), so it must reach the TypeObject or a peer's `string<N>` and our
      ;; unbounded string are structurally different types that do not match (ADR 0009).
      ((and (consp dds-type) (eq (car dds-type) :string))
       (let ((bound (second dds-type)))
         (unless (and (integerp bound) (plusp bound))   ; NOCOND(MACRO): macroexpansion-time — compile-time rejection
           (error "define-dds-type: string bound must be a positive integer, got ~s in ~s" bound spec))
         (destructuring-bind (ltype default put get align size) (cdr (assoc :string *dds-type-map*))
           (declare (ignore size))
           (list :slot slot :kind :scalar :ltype ltype :default default :put put :get get
                 :align align :var t :size 0
                 :dds-type :string :bound bound :key (getf opts :key)))))
      ;; (:enum NAME) — a previously-defined define-dds-enum. Wire is int32 (XTypes 1.3 §7.3.1.2.1
      ;; default bit bound 32), so it reuses the :i32 row's width/alignment; only the codec pair
      ;; differs, mapping keyword <-> declared constant.
      ((and (consp dds-type) (eq (car dds-type) :enum))
       (let* ((ename (second dds-type))
              (epkg (or (and (symbolp ename) (symbol-package ename)) *package*))
              (kws (and (symbolp ename) (gethash ename *dds-enum-literals*))))
         (unless kws   ; NOCOND(MACRO): macroexpansion-time — compile-time rejection
           (error "define-dds-type: unknown enum ~s in ~s — define-dds-enum it first (define-before-use)"
                  ename spec))
         (destructuring-bind (ltype default put get align size) (cdr (assoc :i32 *dds-type-map*))
           (declare (ignore ltype default put get))
           ;; The slot admits the declared literals OR a raw int32: an undecodable wire value is
           ;; kept verbatim rather than flattened to a wrong literal, and the type declaration is
           ;; what stops an undeclared keyword ever reaching the wire.
           (list :slot slot :kind :scalar
                 :ltype `(or (member ,@kws) (signed-byte 32))
                 :default (first kws)
                 :put (%sym epkg "%PUT-" (string ename))
                 :get (%sym epkg "%GET-" (string ename))
                 :align align :var nil :size size
                 :dds-type :enum :enum ename :key (getf opts :key)))))
      ((symbolp dds-type)            ; nested, previously-defined dds type
       (let ((tpkg (or (symbol-package dds-type) *package*)))
         (list :slot slot :kind :nested :ltype dds-type
               :type-name (string-downcase (string dds-type))
               :default (list (%sym tpkg "MAKE-" (string dds-type)))
               :ser (%sym tpkg "SERIALIZE-" (string dds-type))
               :des (%sym tpkg "DESERIALIZE-" (string dds-type))
               :des-into (%sym tpkg "DESERIALIZE-INTO-" (string dds-type))
               :ssize (%sym tpkg "%SSIZE-" (string dds-type))
               :key (getf opts :key))))
      ;; NOCOND(MACRO): macroexpansion-time — compile-time rejection
      (t (error "define-dds-type: unsupported member type ~s in ~s" dds-type spec)))))

(defun* %octet-sequence-p (m)
    (function (list) t)
  "T iff sequence member M's element is an OCTET type (:u8 / :byte / :octet — the three one-octet UNSIGNED
   kinds, which share the (unsigned-byte 8) Lisp representation and so can be bulk-copied to/from the wire).
   NOT :i8: its (signed-byte 8) elements need two's-complement conversion per element, so it keeps the
   generic path."
  (member (getf m :elt-type) '(:u8 :byte :octet)))

(defun* %seq-put-form (m acc-form)
    (function (list t) t)
  "Macro-time: the serialize form for sequence member M reading its value from ACC-FORM. An octet sequence
   gets the BULK memcpy codec; anything else keeps the generic per-element closure loop.

   WP-PERF: the per-element path costs ~12 ns PER OCTET (measured, perfectly linear: 3166 ns for a 256 B
   payload, 204 802 ns for 16 KB) because it funcalls a closure for every single octet. The bulk path is one
   REPLACE. Byte-identical on the wire — an octet has alignment 1, so there is no inter-element padding to
   reproduce."
  (if (%octet-sequence-p m)
      `(dds.cdr:cdr-put-octet-sequence cursor ,acc-form mode)
      `(dds.cdr:cdr-put-sequence cursor ,acc-form (function ,(getf m :elt-put)) mode)))

(defun* %seq-get-form (m)
    (function (list) t)
  "Macro-time: the deserialize form for sequence member M — the bulk octet codec when eligible
   (%octet-sequence-p), else the generic per-element loop into a vector specialized to the element's Lisp
   type. See %seq-put-form for the measured cost of the per-element path."
  (if (%octet-sequence-p m)
      `(dds.cdr:cdr-get-octet-sequence cursor mode)
      `(dds.cdr:cdr-get-sequence-typed cursor (function ,(getf m :elt-get)) mode ',(getf m :elt-ltype))))

;;;; ---- MUTABLE extensibility framing (ADR 0086) ----
;;;; XCDR2 = PL_CDR2: DHEADER + one EMHEADER1-framed member each (XTypes 1.3 §7.4.3.5 rules
;;;; (21)-(22), header layout §7.4.3.4.2). XCDR1 = PL_CDR: a parameter list terminated by
;;;; PID_LIST_END, each member 4-aligned with its alignment origin reset (rules (23)-(25),
;;;; parameter-id bitmask §7.4.1.2.1). Both are emitted; MODE selects at runtime, because the same
;;;; generated function serves a writer offering either representation.

(defun* %mutable-lc (m)
    (function (list) (or null (integer 0 3)))
  "The EMHEADER1 length code for member M when its width is STATICALLY KNOWN, else NIL meaning
   \"LC=4 with a backpatched NEXTINT\" (XTypes 1.3 §7.4.3.4.2; ADR 0086).

   LC 0/1/2/3 encode a serialized member length of 1/2/4/8 octets directly in the 4-octet header, so a
   fixed-width scalar carries no length field at all. A string, sequence or nested struct has no
   compile-time width and takes LC=4, whose NEXTINT is backpatched once the member has been written.

   DELIBERATELY DOES NOT RETURN 5-7, and that is an open empirical question, not a settled one.
   Those codes rewind the stream so NEXTINT doubles as the member's own leading length — a 4-octet
   saving the spec OFFERS (\"the use of length codes 5 to 7 saves 4 bytes\"), never requires. LC=4 is
   unambiguously conformant for every member, and emitting only 0-4 keeps our bytes a function of the
   declared member widths alone. We nevertheless DECODE 0-7 (lc-member-extent), because a peer may
   well emit them.

   ADR 0086 Decision 4 adopts the opposite rule (smallest correct LC, i.e. 5-7 for length-prefixed
   members) and says in the same breath that the choice \"must be confirmed against a captured Connext
   payload before it is called byte-exact; if Connext differs, the vector wins and this rule changes\".
   Until that vector exists, the unambiguous encoding is the honest default: flipping this one function
   is the whole change if the capture says otherwise."
  (if (getf m :var)
      nil
      (case (getf m :size) (1 0) (2 1) (4 2) (8 3) (t nil))))

(defun* %member-size-step-forms (m value-form pos mode)
    (function (list t symbol symbol) list)
  "Macro-time: forms advancing the size accumulator POS by the serialized size of member M holding
   VALUE-FORM, under codec mode MODE.

   Extracted from serialized-size-<name> so the XCDR1 MUTABLE encoder can reuse it: rules (24)/(25)
   need M.value.ssize BEFORE the member is written, to choose the short or the long parameter form.
   One definition of a member's serialized size, not two — a second copy is how an encoder and its
   size function drift until a buffer is undersized."
  (ecase (getf m :kind)
    (:scalar
     (if (getf m :var)
         ;; 4 (length prefix) + the UTF-8 OCTETS + 1 (NUL) — never (LENGTH s): a character occupies
         ;; up to four octets (RFC 3629 §3), and this number sizes the buffer, so under-estimating
         ;; it is a buffer overflow.
         `((setf ,pos (dds.cdr:cdr-size-align ,pos 4 ,mode))
           (incf ,pos (+ 5 (dds.cdr:utf8-octet-length ,value-form))))
         `((setf ,pos (dds.cdr:cdr-size-align ,pos ,(getf m :align) ,mode))
           (incf ,pos ,(getf m :size)))))
    (:sequence
     ;; Closed form, not a per-element loop: every supported element type has
     ;; (size MOD effective-align) = 0, so once the first element is aligned every later one starts
     ;; aligned. Align once, then add n*size.
     `((setf ,pos (dds.cdr:cdr-size-align ,pos 4 ,mode))
       (incf ,pos 4)
       (let ((n (length ,value-form)))
         (when (plusp n)
           (setf ,pos (dds.cdr:cdr-size-align ,pos ,(getf m :elt-align) ,mode))
           (incf ,pos (* n ,(getf m :elt-size)))))))
    (:nested
     `((setf ,pos (,(getf m :ssize) ,value-form ,pos ,mode))))))

(defun* %member-ssize-form (m value-form mode)
    (function (list t symbol) t)
  "Macro-time: a form evaluating to member M's serialized size measured from a FRESH origin — what
   rules (24)/(25) call M.value.ssize. XCDR1 MUTABLE resets the alignment origin per member
   (PUSH(ORIGIN=0)), so a member's size does not depend on where in the stream it lands and can be
   computed before it is written."
  (let ((p (gensym "MPOS")))
    `(let ((,p 0))
       (declare (type (integer 0) ,p))
       ,@(%member-size-step-forms m value-form p mode)
       ,p)))

(defun* %mutable-xcdr2-member-forms (m put-form)
    (function (list t) list)
  "Macro-time: rule (22) — one EMHEADER1-framed member under PL_CDR2.

   A fixed-width member needs only the 4-octet header (its LC states the length). A variable member
   takes LC=4 and an 8-octet header whose NEXTINT is written as a placeholder and backpatched with the
   octets the member actually occupied — the same mechanism the APPENDABLE DHEADER uses."
  (let ((id (getf m :id))
        (mu (getf m :must-understand))
        (lc (%mutable-lc m)))
    (if lc
        `((dds.cdr:cdr-align cursor 4 mode)
          (dds.core.buffer:put-u32 cursor (dds.cdr:emheader1-encode ,mu ,lc ,id))
          ,put-form)
        (let ((np (gensym "NEXTINT")) (ms (gensym "MSTART")) (me (gensym "MEND")))
          `((dds.cdr:cdr-align cursor 4 mode)
            (dds.core.buffer:put-u32 cursor (dds.cdr:emheader1-encode ,mu 4 ,id))
            (let ((,np (dds.core.buffer:cursor-position cursor)))
              (dds.core.buffer:put-u32 cursor 0)
              (let ((,ms (dds.core.buffer:cursor-position cursor)))
                ,put-form
                (let ((,me (dds.core.buffer:cursor-position cursor)))
                  (dds.core.buffer:cursor-set-position cursor ,np)
                  (dds.core.buffer:put-u32 cursor (- ,me ,ms))
                  (dds.core.buffer:cursor-set-position cursor ,me)))))))))

(defun* %mutable-xcdr1-member-forms (m put-form value-form)
    (function (list t t) list)
  "Macro-time: rules (24)/(25) — one PL_CDR parameter under XCDR1.

   The short form (24) carries a 16-bit parameter id and a 16-bit length; it applies when both fit,
   and the LONG form (25) is used otherwise. The id bound is taken as < PID_EXTENDED (0x3F01) rather
   than the rule's literal 2^14, because DDS-XTypes 1.3 Table 34 reserves 0x3F01-0x3FFF for the OMG:
   a member id in that window would be read back as a reserved parameter, not as the member.

   PUSH(ORIGIN=0) is the per-member alignment reset both rules specify — a member's internal
   alignment is relative to its own start, not to the stream origin. It is pushed and popped around
   the member so the parameter list itself keeps aligning against the stream origin.

   THE DECLARED LENGTH IS ROUNDED UP TO A MULTIPLE OF 4, and the pad octets are emitted. Rules (24)/(25)
   say `M.value.ssize`, which reads as the exact size — but a PL_CDR parameter list IS the RTPS
   ParameterList structure (RTPS 2.5 §9.4.2.11), where every parameter carries a 4-multiple length; this
   repo's own dds.rtps.message:write-parameter has always done exactly this for discovery. Confirmed
   against the live RTI Connext vector, which declares length 4 for a 2-octet short and length 12 for a
   10-octet string (corpus/xcdr2/mutabledata-connext.bin)."
  (let ((id (getf m :id))
        (mu (getf m :must-understand))
        (sz (gensym "SSIZE")) (pad (gensym "PADDED")) (o (gensym "ORIGIN")))
    `((dds.cdr:cdr-align cursor 4 mode)
      (let* ((,sz ,(%member-ssize-form m value-form 'mode))
             (,pad (* 4 (ceiling ,sz 4))))
        (if (and ,(< id #x3f01) (<= ,pad #xffff))
            (progn                                   ; rule (24), short form
              (dds.core.buffer:put-u16 cursor (dds.cdr:pl-pid-encode ,mu ,id))
              (dds.core.buffer:put-u16 cursor ,pad))
            (progn                                   ; rule (25), long form
              (dds.core.buffer:put-u16 cursor dds.cdr:+pid-extended-mu+)
              (dds.core.buffer:put-u16 cursor 8)
              (dds.core.buffer:put-u32 cursor (logior ,(if mu 'dds.cdr:+emheader-mu-flag+ 0) ,id))
              (dds.core.buffer:put-u32 cursor ,pad)))
        (let ((,o (dds.core.buffer:cursor-origin cursor)))
          (dds.core.buffer:cursor-set-origin cursor)   ; PUSH(ORIGIN=0)
          ,put-form
          (dotimes (i (- ,pad ,sz)) (dds.core.buffer:put-u8 cursor 0))
          (setf (dds.core.buffer:cursor-origin cursor) ,o))))))

(defun* %mutable-ser-form (parsed put-forms value-forms)
    (function (list list list) t)
  "Macro-time: the whole MUTABLE serialize body — rules (21)-(22) under XCDR2, rules (23)-(25) under
   XCDR1, selected at runtime by MODE because one generated function serves both offered
   representations. PUT-FORMS and VALUE-FORMS run parallel to PARSED."
  (let ((dh (gensym "DH")) (e (gensym "END")))
    `(if (eq mode :xcdr2)
         ;; (21): DHEADER over the member sequence. Backpatched — the size is not known yet.
         (let ((,dh (progn (dds.cdr:cdr-align cursor 4 mode)
                           (let ((p (dds.core.buffer:cursor-position cursor)))
                             (dds.core.buffer:put-u32 cursor 0)
                             p))))
           ,@(loop for m in parsed for f in put-forms
                   append (%mutable-xcdr2-member-forms m f))
           (let ((,e (dds.core.buffer:cursor-position cursor)))
             (dds.core.buffer:cursor-set-position cursor ,dh)
             ;; §7.4.3.4.1: the size EXCLUDES the DHEADER itself.
             (dds.core.buffer:put-u32 cursor (- ,e ,dh 4))
             (dds.core.buffer:cursor-set-position cursor ,e)))
         ;; (23): no DHEADER — a parameter list closed by PID_LIST_END with a zero length.
         (progn
           ,@(loop for m in parsed for f in put-forms for v in value-forms
                   append (%mutable-xcdr1-member-forms m f v))
           (dds.cdr:cdr-align cursor 4 mode)
           ;; Table 34 marks PID_LIST_END must-understand, so the terminator on the wire is 0x7F02.
           (dds.core.buffer:put-u16 cursor dds.cdr:+pid-list-end-mu+)
           (dds.core.buffer:put-u16 cursor 0)))))

(defun* %mutable-ssize-forms (parsed value-forms)
    (function (list list) list)
  "Macro-time: forms advancing POS by the serialized size of a MUTABLE struct's framing AND members.

   THE FRAMING IS PART OF THE SIZE. %serialize-sample sizes the payload buffer from this number, so
   omitting the DHEADER or a member header is a buffer overflow, not a cosmetic mismatch — which is
   exactly what a MUTABLE type would have hit, since every member here carries its own header.

   Both encodings are EXACT, and they get there differently because the two rules differ in one
   respect that matters here: whether a member's internal alignment is measured from the stream or
   from the member.

   XCDR2 (rules (21)-(22)) has NO origin reset, so a member's padding depends on where in the stream
   it lands and the size accumulator must thread through it exactly as the encoder does: 4 (DHEADER)
   + per member 4 (EMHEADER1), plus 4 more for a variable-width member (LC=4's NEXTINT), each
   4-aligned, then the member's own stepped size.

   XCDR1 (rules (24)/(25)) resets the origin per member (PUSH(ORIGIN=0)), which makes a member's size
   independent of its position — so it is computed once from a fresh origin and simply ADDED. That is
   both exact and simpler than threading the accumulator, which would measure the member's internal
   padding from the wrong base and could undersize the buffer for, say, a sequence of 8-byte elements
   landing at the wrong stream parity. The header is 4 octets short-form or 12 long-form, chosen by
   the same test the encoder uses so the two cannot disagree, plus 4 for the terminating sentinel."
  `((if (eq mode :xcdr2)
        (progn
          (setf pos (dds.cdr:cdr-size-align pos 4 mode))
          (incf pos 4)
          ,@(loop for m in parsed for v in value-forms
                  append `((setf pos (dds.cdr:cdr-size-align pos 4 mode))
                           (incf pos ,(if (%mutable-lc m) 4 8))
                           ,@(%member-size-step-forms m v 'pos 'mode))))
        (progn
          ,@(loop for m in parsed for v in value-forms
                  append (let ((sz (gensym "SZ")))
                           `((setf pos (dds.cdr:cdr-size-align pos 4 mode))
                             (let* ((,sz ,(%member-ssize-form m v 'mode))
                                    (,sz (* 4 (ceiling ,sz 4))))   ; the DECLARED length is 4-padded
                               ;; Same short-vs-long test as %mutable-xcdr1-member-forms.
                               (incf pos (if (and ,(< (getf m :id) #x3f01) (<= ,sz #xffff)) 4 12))
                               (incf pos ,sz)))))
          ;; Rule (23): the list is closed by PID_LIST_END + a zero length.
          (setf pos (dds.cdr:cdr-size-align pos 4 mode))
          (incf pos 4)))))

(defun* %mutable-assign-form (m get-form dest-form bad)
    (function (list t t symbol) t)
  "Macro-time: assign one decoded MUTABLE member to DEST-FORM.

   A NESTED member is the reason this is not simply a SETF: a nested MUTABLE type's deserializer
   returns (values sample status), and dropping that status would deliver a sample whose nested
   member silently failed to decode. A FINAL or APPENDABLE nested type returns a single value, so its
   status reads as NIL and the same shape covers both."
  (if (eq (getf m :kind) :nested)
      (let ((v (gensym "V")) (st (gensym "ST")))
        `(multiple-value-bind (,v ,st) ,get-form
           (if ,st (setf ,bad ,st) (setf ,dest-form ,v))))
      `(setf ,dest-form ,get-form)))

(defun* %mutable-decode-loop-form (parsed assign-forms bad)
    (function (list list symbol) t)
  "Macro-time: the MUTABLE decode walk, shared by deserialize-<name> and deserialize-into-<name>.
   ASSIGN-FORMS runs parallel to PARSED; BAD is the caller's status variable, and a non-NIL BAD stops
   the walk and makes the caller return (values NIL BAD).

   Members arrive BY ID, in any order, and a peer may send ids we do not know — that is what the kind
   is FOR. So the caller starts every slot at its default, this walks the extent header by header,
   dispatches on the id, and SKIPS anything unrecognised using the header's own length, never the
   member's type (which we do not have).

   UNLESS the must-understand flag is set. §7.4.1.2.1: that bit decides whether an unrecognised
   member \"may be simply ignored or whether it causes the entire data sample to be discarded\". A
   discard is reported as a STATUS, never signalled (ADR 0064).

   WIRE DATA (NFR-SEC-POSTURE): every length here is peer-controlled. Each member's end is checked
   against the enclosing extent, which is itself checked against the buffer, so a forged length can
   neither walk us past the payload nor loop forever — every iteration consumes at least the 4 octets
   of a member header, so the walk always makes progress. The position is FORCED to each member's
   declared end, which also means a member a peer sized differently from us costs exactly that member
   instead of desynchronising the rest of the sample."
  (let ((n (gensym "N")) (end (gensym "END")) (emh (gensym "EMH")) (mu (gensym "MU"))
        (lc (gensym "LC")) (mid (gensym "ID")) (nx (gensym "NX")) (mlen (gensym "LEN"))
        (ms (gensym "MSTART")) (o (gensym "ORIGIN")) (done (gensym "DONE"))
        (pid (gensym "PID")) (slen (gensym "SLEN")) (m0 (gensym "MU0")) (id0 (gensym "ID0"))
        (stop (gensym "STOP")) (hp (gensym "HDRPOS")))
    (flet ((next-header-form (end-var)
             ;; Advance to where the next member header would start, and stop if it does not fit in
             ;; END. The alignment is computed and ASSIGNED rather than done with cdr-align, for two
             ;; reasons. It must not run before the bound is known: a struct whose extent ends on an
             ;; unaligned octet — the common case, since the last member need not be 4-wide — would
             ;; have cdr-align try to pad past the end of the payload and raise buffer-overflow on a
             ;; PERFECTLY VALID sample. And cdr-align ZERO-FILLS the padding it skips, which is right
             ;; when writing and wrong here: this is a receive buffer, and a decoder has no business
             ;; writing into the octets a peer sent.
             `(let ((,hp (+ (dds.core.buffer:cursor-origin cursor)
                            (dds.cdr:cdr-size-align
                             (- (dds.core.buffer:cursor-position cursor)
                                (dds.core.buffer:cursor-origin cursor))
                             4 mode))))
                (when (> (+ ,hp 4) ,end-var) (return))
                (dds.core.buffer:cursor-set-position cursor ,hp)))
           (dispatch (mid-var mu-var extra)
             ;; Shared id dispatch: a known id decodes, PID_IGNORE is dropped unconditionally
             ;; (Table 34: "All consumers ... shall ignore parameters with this ID"), and anything
             ;; else is skipped unless it is flagged must-understand.
             `(case ,mid-var
                ,@(loop for m in parsed for a in assign-forms
                        collect `((,(getf m :id)) ,a))
                (t (cond ,@extra
                         ((= ,mid-var dds.cdr:+pid-ignore+) nil)
                         (,mu-var (setf ,bad :unknown-must-understand-member)))))))
      `(if (eq mode :xcdr2)
           ;; ---- rules (21)-(22): DHEADER extent, EMHEADER1 per member ----
           (let* ((,n (dds.cdr:cdr-get-dheader cursor mode))
                  (,end (progn
                          ;; A DHEADER claiming more than the buffer holds is refused, never
                          ;; followed (NFR-SEC-POSTURE).
                          (dds.core.buffer:check-room cursor ,n)
                          (+ (dds.core.buffer:cursor-position cursor) ,n))))
             (loop while (null ,bad)
                   ;; Fewer than 4 octets left in the extent is trailing padding, not a member.
                   do ,(next-header-form end)
                      (let ((,emh (dds.core.buffer:get-u32 cursor)))
                        (multiple-value-bind (,mu ,lc ,mid) (dds.cdr:emheader1-decode ,emh)
                          (if (and (>= ,lc 4)
                                   (> (+ (dds.core.buffer:cursor-position cursor) 4) ,end))
                              (setf ,bad :truncated-member-header)
                              (let* ((,nx (if (>= ,lc 4) (dds.core.buffer:get-u32 cursor) 0))
                                     (,mlen (dds.cdr:lc-member-extent ,lc ,nx)))
                                ;; LC 5-7 reuse NEXTINT as the member's own leading length: rewind so
                                ;; the member starts AT it (rule (22): XCDR.offset = XCDR.offset-4).
                                (when (>= ,lc 5)
                                  (dds.core.buffer:cursor-set-position
                                   cursor (- (dds.core.buffer:cursor-position cursor) 4)))
                                (let ((,ms (dds.core.buffer:cursor-position cursor)))
                                  (if (> (+ ,ms ,mlen) ,end)
                                      (setf ,bad :malformed-member-extent)
                                      (progn
                                        ,(dispatch mid mu '())
                                        (when (null ,bad)
                                          (dds.core.buffer:cursor-set-position
                                           cursor (+ ,ms ,mlen)))))))))))
             ;; Consume the declared extent whatever the members did with it, so the caller's
             ;; cursor is left where the next object starts.
             (when (null ,bad) (dds.core.buffer:cursor-set-position cursor ,end)))
           ;; ---- rules (23)-(25): a parameter list closed by PID_LIST_END ----
           (let ((,end (dds.core.buffer:octet-buffer-capacity (dds.core.buffer:cursor-buffer cursor)))
                 (,done nil))
             (loop while (and (null ,bad) (null ,done))
                   ;; Same compute-then-check as the XCDR2 walk, but running out here is an ERROR
                   ;; rather than a clean stop: a parameter list ends at PID_LIST_END, and guessing
                   ;; that it ended where the payload did would accept a truncated sample.
                   do (let ((,hp (+ (dds.core.buffer:cursor-origin cursor)
                                    (dds.cdr:cdr-size-align
                                     (- (dds.core.buffer:cursor-position cursor)
                                        (dds.core.buffer:cursor-origin cursor))
                                     4 mode))))
                        (if (> (+ ,hp 4) ,end)
                            (setf ,bad :missing-parameter-list-end)
                            (progn
                              (dds.core.buffer:cursor-set-position cursor ,hp)
                          (let ((,pid (dds.core.buffer:get-u16 cursor))
                                (,slen (dds.core.buffer:get-u16 cursor))
                                (,mu nil) (,mid 0) (,mlen 0) (,stop nil))
                            (multiple-value-bind (,m0 ,id0) (dds.cdr:pl-pid-decode ,pid)
                              (cond
                                ((dds.cdr:pl-end-of-list-p ,id0) (setf ,done t ,stop t))
                                ;; Long form (§7.4.1.2.1): slength is 8, then eMemberHeader (flags +
                                ;; 28-bit id) and llength, then the member.
                                ((= ,id0 dds.cdr:+pid-extended+)
                                 (if (or (/= ,slen 8)
                                         (> (+ (dds.core.buffer:cursor-position cursor) 8) ,end))
                                     (setf ,bad :malformed-extended-parameter ,stop t)
                                     (let ((,emh (dds.core.buffer:get-u32 cursor)))
                                       (setf ,mlen (dds.core.buffer:get-u32 cursor)
                                             ,mu (logtest ,emh dds.cdr:+emheader-mu-flag+)
                                             ,mid (logand ,emh #x0fffffff)))))
                                (t (setf ,mu ,m0 ,mid ,id0 ,mlen ,slen))))
                            (unless ,stop
                              (let ((,ms (dds.core.buffer:cursor-position cursor))
                                    (,o (dds.core.buffer:cursor-origin cursor)))
                                (if (> (+ ,ms ,mlen) ,end)
                                    (setf ,bad :malformed-member-extent)
                                    (progn
                                      ;; PUSH(ORIGIN=0): a member's internal alignment is relative to
                                      ;; its own start (rules (24)/(25)).
                                      (dds.core.buffer:cursor-set-origin cursor)
                                      ,(dispatch mid mu '())
                                      (setf (dds.core.buffer:cursor-origin cursor) ,o)
                                      (when (null ,bad)
                                        (dds.core.buffer:cursor-set-position
                                         cursor (+ ,ms ,mlen)))))))))))))))))

(defun* %key-max-size (keys)
    (function (list) t)
  "Maximum PLAIN_CDR2 (XCDR2, max alignment 4) serialized size of the key holder built
   from the scalar @key members KEYS, or :UNBOUNDED if any key is variable-size (a
   string). Drives the RTPS 2.5 §9.6.4.8 <=16-direct vs >16-MD5 keyhash decision, which
   is a per-TYPE property (the max size), not a per-sample one."
  (let ((pos 0))
    (dolist (m keys pos)
      (when (getf m :var) (return :unbounded))
      (let ((a (min (getf m :align) 4)))
        (setf pos (* (ceiling pos a) a))
        (incf pos (getf m :size))))))

(defun* %key-hash-defun (fn in-type input acc-fn doc keys key-direct-p)
    (function (symbol t symbol function string list t) list)
  "Emit (declaim + defun) for a generated 16-octet key-hash / instance-handle function FN (RTPS 2.5 §9.6.4.8):
   serialize the KEYS from INPUT (accessed via ACC-FN, PLAIN_CDR2/XCDR2 big-endian, origin-0) and copy them into
   OUT (<=16 direct/zero-padded when KEY-DIRECT-P, else the MD5). Shared by the struct (KEY-HASH-<name>) and the
   FlatData (KEY-HASH-<name>-FD) emitters (DRY) — they differ only in IN-TYPE, INPUT, and ACC-FN. RX-POOLING
   (ADR 0075/0076, NFR-MEM): two trailing &optionals, both defaulting NIL (every TX / register / test caller
   allocates fresh, byte-identical). SER-SCRATCH — a reusable :big cursor over a >=256-octet buffer — serializes
   the key IN PLACE (no per-call make-octet-buffer/cursor/free-static). OUT-SCRATCH — a reusable 16-octet array —
   is the RESULT buffer, zero-filled then written in place (no per-call make-array); the caller (the drain) uses
   it ONLY transiently for the instance-rec lookup, then reads the STABLE handle off the rec (ADR 0076), so it is
   NOT retained. With OUT-SCRATCH the steady-state keyed take/write allocates ZERO here."
  `((declaim (ftype (function (,in-type &optional t t) (simple-array (unsigned-byte 8) (16))) ,fn))
    (defun ,fn (,input &optional ser-scratch out-scratch)
      ,doc
      (let* ((out (the (simple-array (unsigned-byte 8) (16))
                       (or out-scratch (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0))))
             (fresh (unless ser-scratch (dds.core.buffer:make-octet-buffer 256)))
             (wc (if ser-scratch
                     (progn (dds.core.buffer:cursor-reset ser-scratch) ser-scratch)
                     (dds.core.buffer:cursor fresh :endianness :big))))
        (when out-scratch (fill out 0))   ; reused result: clear stale bytes so the <=16-direct zero-pad is correct
        ,@(loop for m in keys
                collect `(,(getf m :put) wc (,(funcall acc-fn m) ,input) :xcdr2))
        (let ((len (dds.core.buffer:cursor-position wc))
              (vec (dds.core.buffer:octet-buffer-vec (dds.core.buffer:cursor-buffer wc))))
          ,(if key-direct-p
               `(replace out vec :end2 len)
               `(replace out (dds.core.md5:md5 (subseq vec 0 len)))))
        (when fresh (dds.pal:free-static (dds.core.buffer:octet-buffer-vec fresh)))
        out))))

;;;; NOT cleared for ship — pending counsel (R6); see ADR 0015.
(defun* %flatdata-offsets (parsed)
    (function (list) (values list (integer 0)))
  "(values ((slot . body-offset) ...) total-body-size) for FINAL fixed-size scalar members, using the same
   XCDR2 alignment rule as %ssize (cdr-size-align, max-align 4 per FR-CDR-2) constant-folded. The body is NOT
   tail-padded: the engine's serialize-<name> writes an unpadded FINAL struct and records the trailing pad to
   the next 4-byte boundary in the encapsulation OPTIONS field (finalize-encapsulation-options), so the true
   SerializedPayload body length is the last member's end, not the next 4-multiple. The byte-exact test
   (in-memory == classic serialize) is the oracle. NOT cleared for ship — pending counsel (R6)."
  (let ((pos 0) (out '()))
    (dolist (m parsed)
      (let ((a (min (getf m :align) 4)))
        (setf pos (* (ceiling pos a) a))
        (push (cons (getf m :slot) pos) out)
        (incf pos (getf m :size))))
    (values (nreverse out) pos)))

;;;; NOT cleared for ship — pending counsel (R6); see ADR 0015.
(defun* %flatdata-field-kind (m)
    (function (list) (values (integer 1 8) t t))
  "(values nbytes signed-p bool-p) for a fixed-size scalar member plist M, so the FlatData accessor mirrors
   the exact cdr-put-/cdr-get- XCDR2-LE encoding (two's-complement for signed, 1/0 for bool). NBYTES is read
   from (getf M :size) — the one width table in *dds-type-map* via %parse-member (DRY) — so only the bool-p /
   signed-p distinction is decided here. The byte-exact test is the oracle. NOT cleared for ship (R6)."
  (let ((nbytes (getf m :size)))
    (ecase (getf m :dds-type)
      (:bool (values nbytes nil t))
      ((:u8 :byte :octet :u16 :u32 :u64) (values nbytes nil nil))
      ((:i8 :i16 :i32 :i64) (values nbytes t nil)))))

(defun* %flatdata-getter-form (vec base nbytes signed-p bool-p)
    (function (symbol (integer 0) (integer 1 8) t t) t)
  "Macro-time: a 0-alloc form reading an NBYTES XCDR2-LE field at VEC[BASE..], two's-complement if SIGNED-P,
   /=0 boolean if BOOL-P. Direct (aref VEC ...) — no cursor, no consing. NOT cleared for ship (R6)."
  (let ((raw `(logior ,@(loop for i below nbytes
                              collect `(ash (aref ,vec ,(+ base i)) ,(* 8 i))))))
    (cond (bool-p `(/= 0 ,raw))
          (signed-p `(let ((u ,raw)) (if (>= u ,(ash 1 (1- (* 8 nbytes)))) (- u ,(ash 1 (* 8 nbytes))) u)))
          (t raw))))

;;;; NOT cleared for ship — pending counsel (R6); see ADR 0017.
(defun* %flatdata-sap-getter-form (sap base nbytes signed-p bool-p)
    (function (symbol t (integer 1 8) t t) t)
  "Macro-time: the SAP twin of %flatdata-getter-form for WP-FLATDATA-ZC-LOAN — a 0-alloc form reading an NBYTES
   XCDR2-LE field straight off a live SHMEM-slot SAP at SAP+BASE.., byte-exact to the aref form. Composes from
   per-byte (dds.pal:load-sap-u8 SAP (+ BASE i)) reads with the SAME logior/ash + two's-complement (SIGNED-P) +
   /=0 boolean (BOOL-P) logic (BASE may be a runtime form). Per-byte u8 compose guarantees LE byte-exactness
   matching the aref accessor exactly — NOT load-sap-u16/u32, to avoid any native-order divergence. NOT cleared
   for ship — pending counsel (R6); see ADR 0017."
  (let ((raw `(logior ,@(loop for i below nbytes
                              collect `(ash (dds.pal:load-sap-u8 ,sap (+ ,base ,i)) ,(* 8 i))))))
    (cond (bool-p `(/= 0 ,raw))
          (signed-p `(let ((u ,raw)) (if (>= u ,(ash 1 (1- (* 8 nbytes)))) (- u ,(ash 1 (* 8 nbytes))) u)))
          (t raw))))

(defun* %flatdata-setter-form (vec base nbytes bool-p val)
    (function (symbol (integer 0) (integer 1 8) t symbol) t)
  "Macro-time: a 0-alloc form writing VAL as an NBYTES XCDR2-LE field at VEC[BASE..] (two's-complement reduced
   via LDB; bool 1/0). Direct (setf (aref VEC ...)) — no cursor, no consing. NOT cleared for ship (R6)."
  (let ((u (if bool-p `(if ,val 1 0) val)))
    `(let ((u ,u))
       ,@(loop for i below nbytes
               collect `(setf (aref ,vec ,(+ base i)) (ldb (byte 8 ,(* 8 i)) u)))
       ,val)))

;;;; NOT cleared for ship — pending counsel (R6); see ADR 0042.
(defun* %flatdata-sap-setter-form (sap base nbytes bool-p val)
    (function (symbol t (integer 1 8) t symbol) t)
  "Macro-time: the SAP twin of %flatdata-setter-form for WP-FLATDATA-LOAN-WRITE — a 0-alloc form writing VAL as
   an NBYTES XCDR2-LE field STRAIGHT INTO a live SHMEM-slot SAP at SAP+BASE.., byte-exact to the aref form.
   Composes from per-byte (dds.pal:store-sap-u8 SAP (+ BASE i) byte) writes with the SAME LDB byte split + bool
   1/0 (BASE may be a runtime form). Per-byte u8 stores guarantee LE byte-exactness matching the aref setter
   exactly — NOT store-sap-u16/u32, mirroring the SAP getter's per-byte load compose. NOT cleared for ship —
   pending counsel (R6); see ADR 0042."
  (let ((u (if bool-p `(if ,val 1 0) val)))
    `(let ((u ,u))
       ,@(loop for i below nbytes
               collect `(dds.pal:store-sap-u8 ,sap (+ ,base ,i) (ldb (byte 8 ,(* 8 i)) u)))
       ,val)))

(defmacro define-dds-type (name options &body members)
  "Define a DDS topic type NAME from an s-expr spec. OPTIONS is a plist; :extensibility is
   :final (default), :appendable or :mutable, and :flatdata requires :final. Each MEMBER is
   (slot-name member-type &key key id must-understand), where member-type is a primitive keyword,
   (:sequence element), (:string bound), (:enum name), or the name of a previously-defined dds type
   (nested struct). Emits a defstruct, ftype-declared serialize/deserialize/serialized-size
   monomorphic functions (plus an internal %ssize position-threading helper), and a type-support.

   :ID is the member's wire identity (@id, FR-TYPE-1), defaulting to declaration order from 0. It is
   what MUTABLE matches on, it goes into the TypeObject, and it must stay stable across revisions of a
   type — reordering members of a mutable type is safe, renumbering them is not. Duplicates are
   rejected at macroexpansion.

   :MUST-UNDERSTAND (@must_understand) marks a member a peer may not silently ignore: if it does not
   recognise the id, it must discard the whole sample rather than deliver a partial one
   (XTypes 1.3 §7.4.1.2.1). It is a per-member wire flag in both encodings.

   :NAME is the member's WIRE name, defaulting to the downcased slot name. It exists because the two
   are not always the same string: IDL spells identifiers with '_' where Lisp uses '-', so a slot
   named T-NS renders \"t-ns\" while the IDL member is \"t_ns\". Type assignability matches members by
   NameHash, so that difference makes an otherwise identical type INCONSISTENT with the peer's — and
   the symptom is not an error but a silent non-match (matched=0), the ADR 0057 failure shape. Give
   the IDL spelling here whenever it differs. Duplicates are rejected at macroexpansion.

   EXTENSIBILITY decides the framing and the encapsulation id together (Table 60, §7.6.3.1.2):
   :final is plain CDR; :appendable prepends a DHEADER under XCDR2 and is AsFinal under XCDR1
   (rules 29/30); :mutable frames every member with its own header — EMHEADER1 under XCDR2
   (rules 21-22) and a PL_CDR parameter list under XCDR1 (rules 23-25) — which is what lets a peer
   add, remove or reorder members without breaking either side. It costs a header per member on the
   wire and an id dispatch per member on decode; that is inherent to the kind and is the user's choice
   per type (ADR 0086)."
  (let* ((pkg (or (symbol-package name) *package*))
         (ext (getf options :extensibility :final))
         (parsed (let ((i -1))
                   (mapcar (lambda (spec)
                             (incf i)
                             ;; Member id (@id, FR-TYPE-1; ADR 0086 Decision 2, XTypes 1.3 §7.4.3.4.2):
                             ;; declaration order by default, overridable with :id. Ids are what MUTABLE
                             ;; MEANS — a member is found by id, not by position — so they are explicit in
                             ;; the codegen plist rather than positional-by-accident. :must-understand
                             ;; (@must_understand) rides along: it is a per-member wire flag in both
                             ;; encodings, and it is what decides whether a peer that does not know this
                             ;; member may ignore it or must discard the whole sample.
                             (append (%parse-member spec)
                                     (list :id (or (getf (cddr spec) :id) i)
                                           :must-understand
                                           (and (getf (cddr spec) :must-understand) t)
                                           ;; The member's WIRE name, which is not always derivable
                                           ;; from the Lisp slot: IDL spells identifiers with '_'
                                           ;; and Lisp with '-', so a slot T-NS renders "t-ns" while
                                           ;; the IDL member is "t_ns". Those hash to different
                                           ;; NameHashes, the assignability check finds the members
                                           ;; inconsistent, and the type gate REFUSES a peer using
                                           ;; the very same type — silently, as matched=0 with no
                                           ;; error (the ADR 0057 failure shape). :name overrides it.
                                           :name (or (getf (cddr spec) :name)
                                                     (string-downcase (string (first spec)))))))
                           members)))
         (ctor (%sym pkg "MAKE-" (string name)))
         (ser  (%sym pkg "SERIALIZE-" (string name)))
         (des  (%sym pkg "DESERIALIZE-" (string name)))
         (ssz  (%sym pkg "SERIALIZED-SIZE-" (string name)))
         (sszi (%sym pkg "%SSIZE-" (string name)))
         (dnto (%sym pkg "DESERIALIZE-INTO-" (string name)))
         (khf  (%sym pkg "KEY-HASH-" (string name)))
         (khf-fd (%sym pkg "KEY-HASH-" (string name) "-FD"))
         (keys (remove-if-not (lambda (m) (getf m :key)) parsed))
         (keymax (%key-max-size keys))
         (key-direct-p (and (integerp keymax) (<= keymax 16)))
         (flatp (and (getf options :flatdata) t))
         (fd-size-sym (%sym pkg "+" (string name) "-FLATDATA-SIZE+"))
         (fd-ctor (%sym pkg "MAKE-" (string name) "-FLATDATA"))
         (fd-ser (%sym pkg "SERIALIZE-" (string name) "-FD"))
         (fd-des (%sym pkg "DESERIALIZE-" (string name) "-FD"))
         (fd-dnto (%sym pkg "DESERIALIZE-INTO-" (string name) "-FD"))
         (fd-ssz (%sym pkg "SERIALIZED-SIZE-" (string name) "-FD"))
         (fd-tx (%sym pkg "TX-TRANSCODE-" (string name) "-FD"))
         (tname (string-downcase (string name))))
    (unless (member ext '(:final :appendable :mutable))   ; NOCOND(MACRO): macroexpansion-time — compile-time rejection
      (error "define-dds-type: extensibility must be :final, :appendable or :mutable (got ~s)" ext))
    ;; FlatData's in-memory layout IS the wire (ADR 0015); a DHEADER, or a per-member EMHEADER, in front
    ;; of it breaks the identity block-copy the whole mechanism rests on.
    (when (and (getf options :flatdata) (member ext '(:appendable :mutable)))
      ;; NOCOND(MACRO): macroexpansion-time — compile-time rejection
      (error "define-dds-type: :flatdata requires :final extensibility (got ~s)" ext))
    ;; FlatData v1 gate: :flatdata t requires every member to be a fixed-size scalar (FR-PF-4, ADR 0015).
    ;; This already constrains @key members to fixed-size scalars (WP-KEYED-FLATDATA): a string/sequence/
    ;; variable-size @key still errors here; the keyhash is read from the buffer via key-hash-<name>-fd below.
    ;; An enum member is excluded too: its slot holds a keyword, but a FlatData Offset accessor
    ;; reads/writes the raw XCDR2 field, so the two would disagree about what the member IS.
    (when (getf options :flatdata)
      (when (some (lambda (m) (or (getf m :var) (getf m :enum) (not (eq (getf m :kind) :scalar)))) parsed)
        ;; NOCOND(MACRO): macroexpansion-time — compile-time rejection
        (error "define-dds-type: :flatdata v1 requires FINAL + fixed-size scalar members (no string/sequence/nested/variable/enum); got ~s"
               (find-if (lambda (m) (or (getf m :var) (getf m :enum) (not (eq (getf m :kind) :scalar)))) parsed))))
    (when (some (lambda (m) (not (eq (getf m :kind) :scalar))) keys)   ; NOCOND(MACRO): macroexpansion-time
      (error "define-dds-type: only scalar/string @key members are supported in v1"))
    ;; Member ids address members on the wire, so a duplicate is not a style problem: two members would
    ;; share one EMHEADER id and the second would silently overwrite the first on decode. The range is
    ;; EMHEADER1's 28-bit id field (XTypes 1.3 §7.4.3.4.2); an id at or above PID_EXTENDED simply takes
    ;; the XCDR1 long parameter form (%mutable-xcdr1-member-forms), so it is permitted, not rejected.
    (let ((ids (mapcar (lambda (m) (getf m :id)) parsed)))
      (unless (every (lambda (id) (typep id '(integer 0 #x0fffffff))) ids)   ; NOCOND(MACRO): macroexpansion-time
        (error "define-dds-type: member :id must be an integer in [0, #x0fffffff]; got ~s" ids))
      (unless (= (length ids) (length (remove-duplicates ids)))   ; NOCOND(MACRO): macroexpansion-time
        (error "define-dds-type: duplicate member :id in ~s — an id addresses a member on the wire" name)))
    ;; Wire names are matched by NameHash during type assignability, so two members sharing one name
    ;; make the type ambiguous to a peer exactly as two members sharing an id do.
    (let ((names (mapcar (lambda (m) (getf m :name)) parsed)))
      (unless (= (length names) (length (remove-duplicates names :test #'string=)))   ; NOCOND(MACRO): macroexpansion-time
        (error "define-dds-type: duplicate member :name in ~s — a name is matched by NameHash" name)))
    (multiple-value-bind (fd-offs fd-body) (when flatp (%flatdata-offsets parsed))
      (declare (ignorable fd-offs fd-body))
    (flet ((acc (m) (%sym pkg (string name) "-" (string (getf m :slot))))
           (fd-acc (m) (%sym pkg (string name) "-" (string (getf m :slot)) "-FD")))
      (declare (ignorable #'fd-acc))
      `(progn
         (defstruct (,name (:constructor ,ctor))
           ,@(loop for m in parsed
                   collect `(,(getf m :slot) ,(getf m :default) :type ,(getf m :ltype))))
         ;; A bounded string member gains its bound as a constant and a CHECKED setter. The plain
         ;; defstruct accessor stays — existing types are untouched and the hot path keeps direct slot
         ;; access — so this is purely additive. The bound counts OCTETS (ADR 0083): a character can
         ;; occupy four, and CL:LENGTH here would let a multi-byte string past a bound it exceeds.
         ,@(loop for m in parsed
                 when (getf m :bound)
                   append (let ((bsym (%sym pkg "+" (string name) "-" (string (getf m :slot)) "-BOUND+"))
                                (ssym (%sym pkg "SET-" (string name) "-" (string (getf m :slot)))))
                            `((defconstant ,bsym ,(getf m :bound)
                                ,(format nil "Declared octet bound of ~(~a~).~(~a~) (IDL string<~d>, ~
                                              XTypes 1.3 §7.3.1.2.1). Octets, not characters."
                                         name (getf m :slot) (getf m :bound)))
                              (declaim (ftype (function (,name string)
                                                        (values (or null (eql t)) (or null keyword)))
                                              ,ssym))
                              (defun ,ssym (sample value)
                                ,(format nil "Set ~(~a~).~(~a~) to VALUE, or refuse it. Returns ~
                                              (values T NIL), or (values NIL :STRING-BOUND-EXCEEDED) ~
                                              when VALUE exceeds the declared ~d-octet bound — measured ~
                                              in UTF-8 octets (ADR 0083), never characters."
                                         name (getf m :slot) (getf m :bound))
                                (if (> (dds.cdr:utf8-octet-length value) ,bsym)
                                    (values nil :string-bound-exceeded)
                                    (progn (setf (,(acc m) sample) value) (values t nil)))))))
         (declaim (ftype (function (,name dds.core.buffer:cursor &optional symbol) ,name) ,ser))
         (defun ,ser (sample cursor &optional (mode :xcdr2))
           ;; APPENDABLE + XCDR2 = DHEADER then the members AS IF FINAL (XTypes 1.3 §7.4.3.5 rule
           ;; 30). Under XCDR1 rule (29) says AsFinal — no DHEADER — so :final emits exactly what it
           ;; always did and stays byte-identical (make corpus is the guard on that).
           ,@(let ((forms (loop for m in parsed collect
                                (ecase (getf m :kind)
                                  (:scalar `(,(getf m :put) cursor (,(acc m) sample) mode))
                                  (:sequence (%seq-put-form m `(,(acc m) sample)))
                                  (:nested `(,(getf m :ser) (,(acc m) sample) cursor mode)))))
                   (dh (gensym "DH")) (e (gensym "END")))
               (if (eq ext :mutable)
                   ;; MUTABLE: rules (21)-(22) under XCDR2, rules (23)-(25) under XCDR1. Both are
                   ;; emitted and MODE picks at runtime — a stock foreign reader may request either
                   ;; representation, and emitting XCDR2 framing under an XCDR1 encapsulation id would
                   ;; be silently wrong bytes rather than a visible failure (ADR 0086 Decision 1).
                   (list (%mutable-ser-form parsed forms
                                            (loop for m in parsed collect `(,(acc m) sample))))
               (if (eq ext :appendable)
                   `((let ((,dh (when (eq mode :xcdr2)
                                  ;; Placeholder, backpatched below — the size is not known yet.
                                  ;; Same mechanism as %dheader-begin/%dheader-end; not a second one.
                                  (dds.cdr:cdr-align cursor 4 mode)
                                  (let ((p (dds.core.buffer:cursor-position cursor)))
                                    (dds.core.buffer:put-u32 cursor 0)
                                    p))))
                       ,@forms
                       (when ,dh
                         (let ((,e (dds.core.buffer:cursor-position cursor)))
                           (dds.core.buffer:cursor-set-position cursor ,dh)
                           ;; §7.4.3.4.1: the size EXCLUDES the DHEADER itself.
                           (dds.core.buffer:put-u32 cursor (- ,e ,dh 4))
                           (dds.core.buffer:cursor-set-position cursor ,e)))))
                   forms)))
           sample)
         ;; A MUTABLE decode can REFUSE a sample — an unrecognised must-understand member, or a forged
         ;; length — and reports it as (values NIL status) per ADR 0064. That has to be in the declared
         ;; type: hot-path code compiles at (safety 0), where the compiler simply believes this, and a
         ;; declaration promising a struct from a function that returns NIL is undefined behaviour, not
         ;; a lint. FINAL and APPENDABLE cannot fail this way and keep the single-value declaration.
         (declaim (ftype (function (dds.core.buffer:cursor &optional symbol)
                                   ,(if (eq ext :mutable)
                                        `(values (or null ,name) (or null keyword))
                                        name))
                         ,des))
         (defun ,des (cursor &optional (mode :xcdr2))
           ;; An APPENDABLE reader must stop at the DHEADER's extent: a peer built from an OLDER
           ;; revision sent fewer members, and reading past the extent would decode the next
           ;; sample's octets as this one's trailing members. Members not covered keep their
           ;; defaults, and whatever a NEWER peer appended is skipped. That is the property
           ;; extensibility exists for (XTypes 1.3 §7.4.3.5 rules 29/30).
           ,(let* ((binds (loop for m in parsed collect
                                (ecase (getf m :kind)
                                  (:scalar `(,(getf m :slot) (,(getf m :get) cursor mode)))
                                  (:sequence `(,(getf m :slot) ,(%seq-get-form m)))
                                  (:nested `(,(getf m :slot) (,(getf m :des) cursor mode))))))
                   (end (gensym "END"))
                   (ctor-call `(,ctor ,@(loop for m in parsed
                                              append (list (intern (string (getf m :slot)) :keyword)
                                                           (getf m :slot))))))
              (if (eq ext :mutable)
                  ;; MUTABLE decode (ADR 0086). Every slot starts at its DEFAULT because a member may
                  ;; simply be absent — an older or newer peer sends the ids it has — and the walk
                  ;; itself lives in %mutable-decode-loop-form, shared with deserialize-into-<name> so
                  ;; the two cannot drift apart on the one path where wire data drives the control flow.
                  (let ((bad (gensym "BAD")))
                    `(let (,@(loop for m in parsed collect `(,(getf m :slot) ,(getf m :default)))
                           (,bad nil))
                       ,(%mutable-decode-loop-form
                         parsed
                         (loop for m in parsed
                               collect (%mutable-assign-form
                                        m
                                        (ecase (getf m :kind)
                                          (:scalar `(,(getf m :get) cursor mode))
                                          (:sequence (%seq-get-form m))
                                          (:nested `(,(getf m :des) cursor mode)))
                                        (getf m :slot) bad))
                         bad)
                       (if ,bad (values nil ,bad) (values ,ctor-call nil))))
                  (if (eq ext :appendable)
                  `(let* ((,end (when (eq mode :xcdr2)
                                  (let ((n (dds.cdr:cdr-get-dheader cursor mode)))
                                    ;; WIRE DATA — a DHEADER claiming more than the buffer holds is
                                    ;; refused, never followed (NFR-SEC-POSTURE). DEFENSE IN DEPTH,
                                    ;; not the sole guard: every member read is independently
                                    ;; bounds-checked, so removing this does NOT turn the suite red.
                                    ;; It fails FAST, before any attacker-controlled member is parsed
                                    ;; against a bogus extent. Treat it as a contract assertion.
                                    (dds.core.buffer:check-room cursor n)
                                    (+ (dds.core.buffer:cursor-position cursor) n))))
                          ,@(loop for b in binds for m in parsed
                                  collect `(,(first b)
                                            (if (or (null ,end)
                                                    (< (dds.core.buffer:cursor-position cursor) ,end))
                                                ,(second b)
                                                ,(getf m :default)))))
                     (when ,end (dds.core.buffer:cursor-set-position cursor ,end))
                     ,ctor-call)
                  `(let ,binds ,ctor-call)))))
         (declaim (ftype (function (,name dds.core.buffer:cursor &optional symbol)
                                   ,(if (eq ext :mutable)
                                        `(values (or null ,name) (or null keyword))
                                        name))
                         ,dnto))
         (defun ,dnto (sample cursor &optional (mode :xcdr2))
           ;; Same extent rule as ,des. An uncovered member is reset to its DEFAULT rather than
           ;; left alone: this fills a POOLED sample in place, so keeping the previous occupant's
           ;; value would leak one sample's data into the next.
           ,@(let ((forms (loop for m in parsed collect
                                (ecase (getf m :kind)
                                  (:scalar `(setf (,(acc m) sample) (,(getf m :get) cursor mode)))
                                  (:sequence `(setf (,(acc m) sample) ,(%seq-get-form m)))
                                  (:nested `(,(getf m :des-into) (,(acc m) sample) cursor mode)))))
                   (end (gensym "END")))
               (if (eq ext :mutable)
                   ;; MUTABLE fills a POOLED sample, so every slot is reset to its default BEFORE the
                   ;; walk — a member absent from this sample must not keep the previous occupant's
                   ;; value. Same walk as ,des; only the destinations differ.
                   (let ((bad (gensym "BAD")))
                     `((let ((,bad nil))
                         ,@(loop for m in parsed
                                 collect `(setf (,(acc m) sample) ,(getf m :default)))
                         ,(%mutable-decode-loop-form
                           parsed
                           (loop for m in parsed
                                 collect (%mutable-assign-form
                                          m
                                          (ecase (getf m :kind)
                                            (:scalar `(,(getf m :get) cursor mode))
                                            (:sequence (%seq-get-form m))
                                            ;; The nested type fills the EXISTING sub-struct in place
                                            ;; (the pooling point), so it yields the sub-struct itself.
                                            (:nested `(progn (,(getf m :des-into)
                                                              (,(acc m) sample) cursor mode)
                                                             (,(acc m) sample))))
                                          `(,(acc m) sample) bad))
                           bad)
                         (when ,bad (return-from ,dnto (values nil ,bad))))))
               (if (eq ext :appendable)
                   `((let ((,end (when (eq mode :xcdr2)
                                   (let ((n (dds.cdr:cdr-get-dheader cursor mode)))
                                     (dds.core.buffer:check-room cursor n)   ; wire data (NFR-SEC-POSTURE)
                                     (+ (dds.core.buffer:cursor-position cursor) n)))))
                       ,@(loop for f in forms for m in parsed
                               collect `(if (or (null ,end)
                                                (< (dds.core.buffer:cursor-position cursor) ,end))
                                            ,f
                                            (setf (,(acc m) sample) ,(getf m :default))))
                       (when ,end (dds.core.buffer:cursor-set-position cursor ,end))))
                   forms)))
           ,(if (eq ext :mutable) '(values sample nil) 'sample))
         (declaim (ftype (function (,name (integer 0) &optional symbol) (integer 0)) ,sszi))
         (defun ,sszi (sample pos &optional (mode :xcdr2))
           (declare (type (integer 0) pos) (ignorable sample))
           ;; The DHEADER is part of the serialized size. %serialize-sample sizes the payload buffer
           ;; from this number, so omitting it here is a buffer overflow, not a cosmetic mismatch.
           ,@(when (eq ext :appendable)
               `((when (eq mode :xcdr2)
                   (setf pos (dds.cdr:cdr-size-align pos 4 mode))
                   (incf pos 4))))
           ,@(if (eq ext :mutable)
                 ;; MUTABLE carries a header per MEMBER, not one per struct, so the framing dominates
                 ;; the size rather than decorating it — see %mutable-ssize-forms.
                 (%mutable-ssize-forms parsed (loop for m in parsed collect `(,(acc m) sample)))
                 (loop for m in parsed append
                   (ecase (getf m :kind)
                     (:scalar
                      (if (getf m :var)
                          ;; 4 (length prefix) + the UTF-8 OCTETS + 1 (NUL). It must be the octet
                          ;; count, never (LENGTH s): a character occupies up to four octets
                          ;; (RFC 3629 §3), and this number sizes the buffer the sample is
                          ;; serialized into, so under-estimating it is a buffer overflow.
                          `((setf pos (dds.cdr:cdr-size-align pos 4 mode))
                            (incf pos (+ 5 (dds.cdr:utf8-octet-length (,(acc m) sample)))))
                          `((setf pos (dds.cdr:cdr-size-align pos ,(getf m :align) mode))
                            (incf pos ,(getf m :size)))))
                     (:sequence
                      ;; WP-PERF: CLOSED FORM, not a per-element loop. This runs on EVERY write, and it was
                      ;; iterating once per ELEMENT — 16384 cdr-size-align calls (generic arithmetic) to
                      ;; compute a NUMBER for a 16 KB octet sequence: measured ~107 us per write, the single
                      ;; largest cost on the send path and ~90% of %serialize-sample.
                      ;; Byte-exact: every supported element type has (size MOD effective-align) = 0 — u8 1/1,
                      ;; u16 2/2, u32 4/4, u64 8/8 (and 8 MOD 4 = 0 under XCDR2's 4-byte alignment cap,
                      ;; FR-CDR-2) — so once the FIRST element is aligned, every later element starts already
                      ;; aligned and the loop can only add size each time. Align once, then add n*size.
                      `((setf pos (dds.cdr:cdr-size-align pos 4 mode))
                        (incf pos 4)
                        (let ((n (length (,(acc m) sample))))
                          (when (plusp n)
                            (setf pos (dds.cdr:cdr-size-align pos ,(getf m :elt-align) mode))
                            (incf pos (* n ,(getf m :elt-size)))))))
                     (:nested
                      `((setf pos (,(getf m :ssize) (,(acc m) sample) pos mode)))))))
           pos)
         (declaim (ftype (function (,name &optional symbol) (integer 0)) ,ssz))
         (defun ,ssz (sample &optional (mode :xcdr2))
           (,sszi sample 0 mode))
         ,@(when keys
             (%key-hash-defun
              khf name 'sample #'acc
              (format nil "16-octet DDS keyhash / instance handle (RTPS 2.5 §9.6.4.8, ~
                FR-TYPE-5): the @key members in member order, PLAIN_CDR2 (XCDR2) ~
                big-endian, no encapsulation/type/member headers, origin-0 (4-aligned). ~
                Key holder max serialized size = ~a -> ~a path."
                      (if (integerp keymax) keymax :unbounded)
                      (if key-direct-p "<=16 direct/zero-padded" "MD5"))
              keys key-direct-p))
         ;;;; NOT cleared for ship — pending counsel (R6); see ADR 0015.
         ,@(when flatp
             (let* ((fd-pad (mod (- 4 (mod fd-body 4)) 4))
                    (fd-total (+ 4 fd-body fd-pad)))
               `((defconstant ,fd-size-sym ,fd-total
                   ,(format nil "WP-FLATDATA total SerializedPayload size for ~a = 4 (XCDR2 encap header) ~
                     + ~d (fixed XCDR2-LE body) + ~d (trailing pad to the next 4-byte boundary); equals the ~
                     engine's SerializedPayload length for this type (%serialize-sample / serialize-~a).~%~
                     THE TRAILING PAD OCTETS ARE PART OF THE PAYLOAD AND ARE EMITTED. This constant ~
                     previously excluded them, on the belief that the pad is 'carried in the OPTIONS field, ~
                     not as body octets' — that belief was WRONG and it was a wire-conformance bug: ~
                     DDS-XTypes 1.3 SS7.6.3.1.2 has the OPTIONS bits COUNT padding that is present, so a ~
                     conformant receiver derives the data end as (payload_length - pad). RTI Connext does, ~
                     and rejected every sample whose body was not 4-aligned (FR-PF-4, ADR 0015; R6)."
                            tname fd-body fd-pad tname))
                 ,@(loop for m in parsed
                         for off = (cdr (assoc (getf m :slot) fd-offs))
                         for base = (+ 4 off)
                         append
                         (multiple-value-bind (nbytes signed-p bool-p)
                             (%flatdata-field-kind m)
                           `((declaim (ftype (function ((or dds.core.buffer:octet-buffer dds.types:flatdata-view))
                                                       ,(getf m :ltype))
                                             ,(fd-acc m)))
                             (defun ,(fd-acc m) (x)
                               ,(format nil "WP-FLATDATA Offset getter: read member ~a in place at body offset ~
                                 ~d, XCDR2-LE, 0-alloc raw SAP/vec access (no cursor, no consing). X is EITHER an ~
                                 owned octet-buffer (the shipped aref read at buffer offset ~d) OR a ~
                                 WP-FLATDATA-ZC-LOAN flatdata-view over a live SHMEM slot (the SAP read at ~
                                 base-offset+~d, byte-exact to the aref form), dispatched by a single predicted ~
                                 struct-type branch (no generic dispatch). NOT cleared for ship — pending counsel ~
                                 (R6); see ADR 0017 (view) / ADR 0015 (owned)." (getf m :slot) off base off)
                               (dds.pal:with-hot-optimizations
                                 (if (dds.types:flatdata-view-p x)
                                     (let ((sap (dds.types:flatdata-view-slot-sap x))
                                           (base (+ (dds.types:flatdata-view-base-offset x) ,off)))
                                       ,(%flatdata-sap-getter-form 'sap 'base nbytes signed-p bool-p))
                                     (let ((vec (dds.core.buffer:octet-buffer-vec x)))
                                       (declare (type (simple-array (unsigned-byte 8) (*)) vec))
                                       ,(%flatdata-getter-form 'vec base nbytes signed-p bool-p)))))
                             (declaim (ftype (function (,(getf m :ltype)
                                                        (or dds.core.buffer:octet-buffer dds.types:flatdata-view))
                                                       ,(getf m :ltype)) (setf ,(fd-acc m))))
                             (defun (setf ,(fd-acc m)) (v x)
                               ,(format nil "WP-FLATDATA Offset setter: write member ~a in place at body offset ~
                                 ~d, XCDR2-LE, 0-alloc raw SAP/vec access (no cursor, no consing). X is EITHER an ~
                                 owned octet-buffer (the shipped aref write at buffer offset ~d) OR a ~
                                 WP-FLATDATA-LOAN-WRITE flatdata-view over a live writer-loaned SHMEM slot (the SAP ~
                                 write at base-offset+~d, byte-exact to the aref form), dispatched by a single ~
                                 predicted struct-type branch (no generic dispatch). The view branch is the ~
                                 write-side dual of the read-in-place getter — the app fills a loan-sample slot ~
                                 straight through this setter. NOT cleared for ship — pending counsel (R6); see ~
                                 ADR 0042 (loan-write view) / ADR 0015 (owned)." (getf m :slot) off base off)
                               (dds.pal:with-hot-optimizations
                                 (if (dds.types:flatdata-view-p x)
                                     (let ((sap (dds.types:flatdata-view-slot-sap x))
                                           (base (+ (dds.types:flatdata-view-base-offset x) ,off)))
                                       ,(%flatdata-sap-setter-form 'sap 'base nbytes bool-p 'v))
                                     (let ((vec (dds.core.buffer:octet-buffer-vec x)))
                                       (declare (type (simple-array (unsigned-byte 8) (*)) vec))
                                       ,(%flatdata-setter-form 'vec base nbytes bool-p 'v))))))))
                 ;;;; NOT cleared for ship — pending counsel (R6); see ADR 0015/0017.
                 ,@(when keys
                     (%key-hash-defun
                      khf-fd '(or dds.core.buffer:octet-buffer dds.types:flatdata-view) 'x #'fd-acc
                      (format nil "WP-KEYED-FLATDATA 16-octet DDS keyhash / instance handle (RTPS 2.5 §9.6.4.8, ~
                        FR-TYPE-5) for a KEYED FlatData type — read directly from the FlatData SAMPLE X (an owned ~
                        octet-buffer OR a flatdata-view, via the dual-dispatching <name>-<field>-fd accessors), not ~
                        a struct. The @key members in member order, PLAIN_CDR2 (XCDR2) big-endian, no ~
                        encapsulation/type/member headers, origin-0 (4-aligned); key holder max serialized size = ~
                        ~a -> ~a path. Byte-identical to the struct key-hash-<name> for the same key values (the ~
                        conformance crux: a keyed FlatData instance's identity equals what a non-FlatData peer ~
                        computes). NOT cleared for ship — pending counsel (R6); see ADR 0015/0017."
                              (if (integerp keymax) keymax :unbounded)
                              (if key-direct-p "<=16 direct/zero-padded" "MD5"))
                      keys key-direct-p))
                 (declaim (ftype (function () dds.core.buffer:octet-buffer) ,fd-ctor))
                 (defun ,fd-ctor ()
                   ,(format nil "WP-FLATDATA constructor: allocate a ~a-octet foreign octet-buffer (the sample IS ~
                     the SerializedPayload) and write the 4-octet XCDR2-LE (PLAIN_CDR2_LE) encapsulation header ~
                     the engine uses, with the OPTIONS trailing-pad bits set IDENTICALLY to %serialize-sample ~
                     (via finalize-encapsulation-options at the body end) so a non-4-aligned body matches the ~
                     engine byte-for-byte; return the buffer. NOT cleared for ship — pending counsel (R6)."
                            (symbol-name fd-size-sym))
                   (let* ((buf (dds.core.buffer:make-octet-buffer ,fd-size-sym))
                          (wc (dds.core.buffer:cursor buf :endianness :little)))
                     (dds.cdr:make-encapsulation-header wc :plain-cdr2-le)
                     ;; Position at the UNPADDED body end, then let finalize set the OPTIONS pad bits AND
                     ;; emit the pad octets — byte-identical to %serialize-sample. (The buffer is sized to
                     ;; include the pad; see the FLATDATA-SIZE constant.)
                     (dds.core.buffer:cursor-set-position wc ,(+ 4 fd-body))
                     (dds.cdr:finalize-encapsulation-options wc :plain-cdr2-le)
                     buf))
                 (declaim (ftype (function (dds.core.buffer:octet-buffer dds.core.buffer:cursor &optional symbol)
                                           dds.core.buffer:octet-buffer)
                                 ,fd-ser))
                 (defun ,fd-ser (sample cursor &optional (mode :xcdr2))
                   ,(format nil "WP-FLATDATA serialize=IDENTITY (TX, type-support :serialize, same signature as ~
                     serialize-~a but SAMPLE is the FlatData octet-buffer): block-copy the body bytes [4,~a) of ~
                     the FlatData buffer into the engine's write CURSOR — NO per-field encoding, 0-alloc (put-octets ~
                     = replace). The engine (%serialize-sample) has already written the 4-octet XCDR2-LE encap ~
                     header into CURSOR and reset its origin to 4, then calls this for the body only; the copied ~
                     body is byte-identical to serialize-~a (proven byte-exact, Phase B). MODE is accepted+ignored ~
                     (a FlatData buffer is already XCDR2-LE). NOT cleared for ship — pending counsel (R6); see ADR 0015."
                            tname (symbol-name fd-size-sym) tname)
                   (declare (ignore mode))
                   (dds.pal:with-hot-optimizations
                     (dds.core.buffer:put-octets cursor (dds.core.buffer:octet-buffer-vec sample)
                                                 4 ,fd-body))
                   sample)
                 (declaim (ftype (function (dds.core.buffer:octet-buffer &optional symbol) (integer 0)) ,fd-ssz))
                 (defun ,fd-ssz (sample &optional (mode :xcdr2))
                   ,(format nil "WP-FLATDATA serialized BODY size (type-support :serialized-size): the constant ~
                     unpadded XCDR2-LE body length ~d (= ~a - 4), which the engine adds the 4-octet header to. ~
                     SAMPLE (the FlatData octet-buffer) + MODE are accepted+ignored — the size is a per-TYPE ~
                     constant. NOT cleared for ship — pending counsel (R6); see ADR 0015." fd-body (symbol-name fd-size-sym))
                   (declare (ignore sample mode))
                   ,fd-body)
                 (declaim (ftype (function (dds.core.buffer:octet-buffer dds.core.buffer:cursor &optional symbol)
                                           (values (or null dds.core.buffer:octet-buffer) (or null keyword)))
                                 ,fd-dnto))
                 (defun ,fd-dnto (target cursor &optional (mode :xcdr2))
                   ,(format nil "WP-FLATDATA deserialize into a PRE-LOANED FlatData buffer TARGET, branching on the ~
                     received SerializedPayload representation id (NBO at vec[0..1]) via dds.cdr:flatdata-rx-rep-plan ~
                     (PINNED to +representation-ids+, DDS-XTypes 1.3 §7.6.3.1.2): (1) PLAIN_CDR2_LE (0x0007) = the ~
                     0-ALLOC READ-IN-PLACE path (UNCHANGED, parallel to deserialize-into-~a) — block-copy the body ~
                     into TARGET, NO per-field decode; (2) a FOREIGN transcodable rep (PLAIN_CDR_BE 0x0000, ~
                     PLAIN_CDR_LE 0x0001, PLAIN_CDR2_BE 0x0006) = TRANSCODE (WP-FLATDATA-XCDR-TRANSCODE, FR-PF-4): ~
                     decode the body via the sibling struct codec deserialize-~a (mode + cursor endianness from the ~
                     rep-id — it already handles XCDR1/XCDR2 x BE/LE incl. the 8-vs-4 alignment divergence) then ~
                     write each field into TARGET's canonical XCDR2-LE layout via the ~a-<field>-fd setters; the ~
                     allocating fallback for a conformant non-XCDR2-LE peer (e.g. stock RTI Connext, XCDR1-BE), OFF ~
                     the measured CDR hot path; (3) anything else (PL_CDR(2)/DELIMITED/XML) = a CLEAN reject (a FINAL ~
                     fixed-size FlatData type is PLAIN-encapsulated, so these are unexpected). FALSE-REJECT-SAFE ~
                     BOUNDS (NFR-SEC-POSTURE, even at (safety 0)): the available payload length (cursor-buffer ~
                     capacity) MUST be >= 4 to read the rep-id, then >= ~a for the native copy (NOT == — a LONGER ~
                     trailing-padded peer payload is accepted); the transcode's struct codec bounds-checks every ~
                     field against the payload extent (check-room), so a SHORT/forged foreign body -> a controlled ~
                     signal, never OOB. Returns TARGET. NOT cleared for ship — pending counsel (R6); see ADR 0015."
                            tname tname tname (symbol-name fd-size-sym))
                   (declare (ignore mode))
                   (dds.pal:with-hot-optimizations
                     (let* ((src-buf (dds.core.buffer:cursor-buffer cursor))
                            (src (dds.core.buffer:octet-buffer-vec src-buf))
                            (avail (dds.core.buffer:octet-buffer-capacity src-buf))
                            (dst (dds.core.buffer:octet-buffer-vec target)))
                       (declare (type (simple-array (unsigned-byte 8) (*)) src dst))
                       ;; false-REJECT-safe: need >= 4 octets even to read the representation id (never OOB).
                       (when (< avail 4)
                         (return-from ,fd-dnto (values nil :short-payload)))
                       ;; rep-id NBO at vec[0..1]; classify against +representation-ids+ (§7.6.3.1.2; not from memory).
                       (let ((id (logior (ash (aref src 0) 8) (aref src 1))))
                         (multiple-value-bind (kind tmode tendian) (dds.cdr:flatdata-rx-rep-plan id)
                           (ecase kind
                             (:native
                              ;; PLAIN_CDR2_LE (0x0007): read-in-place (0-copy, UNCHANGED) — header+OPTIONS already in TARGET.
                              (when (< avail ,fd-size-sym)
                                (return-from ,fd-dnto (values nil :short-payload)))
                              (replace dst src :start1 4 :end1 ,fd-size-sym :start2 4 :end2 ,fd-size-sym))
                             (:transcode
                              ;; foreign rep: decode the body (struct codec, foreign mode+endianness) then write canonical.
                              (let ((rc (dds.core.buffer:cursor src-buf :endianness tendian)))
                                (dds.core.buffer:cursor-set-position rc 4)
                                (dds.core.buffer:cursor-set-origin rc)
                                (let ((%st (,des rc tmode)))
                                  ,@(loop for m in parsed
                                          collect `(setf (,(fd-acc m) target) (,(acc m) %st))))))
                             (:reject
                              (return-from ,fd-dnto
                                (values nil :representation-not-supported))))))
                       (values target nil))))
                 (declaim (ftype (function (dds.core.buffer:cursor &optional symbol)
                                           (values (or null dds.core.buffer:octet-buffer) (or null keyword)))
                                 ,fd-des))
                 (defun ,fd-des (cursor &optional (mode :xcdr2))
                   ,(format nil "WP-FLATDATA deserialize=READ-IN-PLACE (RX, type-support :deserialize, same ~
                     signature as deserialize-~a): wrap the received payload as a fresh FlatData ~a-octet sample the ~
                     Offset accessors read at 4+offset, with NO per-field decode. The engine (%deserialize-sample) ~
                     has parsed the encap header and positioned CURSOR at body offset 4. Allocates a fresh FlatData ~
                     buffer (make-~a-flatdata) — matching the classic :deserialize vtable contract, which also ~
                     returns a freshly-allocated sample — then delegates the false-REJECT-safe validation + 0-per- ~
                     field-work body copy to deserialize-into-~a-fd (DRY). PHASE-C/D COPY (engine-contract gap): ~
                     %deserialize-sample frees the RX buffer immediately after this returns, so a true 0-copy view ~
                     would be use-after-free; Phase D confirmed a literal-0-copy SHMEM-slot view is NOT safe in v1 ~
                     either (async store read off-thread with no slot-aware release hook + an octet-buffer cannot ~
                     wrap a raw foreign SAP), so ZC RX is a SINGLE copy into an owned vector (ADR 0015 Phase D ~
                     outcome). The 0-ALLOC steady-state RX path is deserialize-into-~a-fd (copy into a loaned buffer). MODE ignored. ~
                     NOT cleared for ship — pending counsel (R6); see ADR 0015." tname (symbol-name fd-size-sym)
                            tname tname tname)
                   ;; The FlatData buffer is allocated BEFORE the payload is validated, so a rejected payload
                   ;; must FREE it here: the reject used to unwind out as a condition and LEAK this buffer on
                   ;; every malformed/forged datagram (a remote memory-exhaustion vector). ADR 0064.
                   (let ((buf (,fd-ctor)))
                     (multiple-value-bind (out status) (,fd-dnto buf cursor mode)
                       (when status
                         (dds.pal:free-static (dds.core.buffer:octet-buffer-vec buf))
                         (return-from ,fd-des (values nil status)))
                       (values out nil))))
                 ;;;; NOT cleared for ship — pending counsel (R6); see ADR 0015.
                 (declaim (ftype (function (t dds.core.buffer:octet-buffer dds.cdr:cdr-mode symbol)
                                           (simple-array (unsigned-byte 8) (*)))
                                 ,fd-tx))
                 (defun ,fd-tx (ts sample mode encap)
                   ,(format nil "WP-DATA-REPRESENTATION TX-transcode for a FlatData writer offering a non-XCDR2-LE ~
                     representation (DDS-XTypes 1.3 §7.6.3.1.1, FR-PF-4; bound to type-support flatdata-builder, ~
                     invoked by %serialize-sample): the FlatData buffer SAMPLE is canonical XCDR2-LE, so for an ~
                     :xcdr1 offered rep transcode it (symmetric to the RX deserialize-into-~a-fd :transcode arm) — ~
                     decode the XCDR2-LE body via the sibling struct codec deserialize-~a (it already handles the ~
                     8-vs-4 alignment divergence) into a fresh struct, then RE-SERIALIZE that struct via serialize-~a ~
                     in MODE under an ENCAP-derived (representation-id-value, +representation-ids+ §7.6.3.1.2) ~
                     encapsulation header — byte-exact to a non-FlatData XCDR1 writer of the same values. The :xcdr2 ~
                     identity path NEVER reaches here (%serialize-sample short-circuits it to the 0-copy serialize-~a-fd). ~
                     ALLOCATES (the opt-in foreign-rep TX fallback, OFF the measured CDR hot path); the XCDR2 default ~
                     stays 0-alloc. TS is unused (the codec is monomorphic to this type). NOT cleared for ship — ~
                     pending counsel (R6); see ADR 0015." tname tname tname tname)
                   (declare (ignore ts))
                   (let* ((rc (dds.core.buffer:cursor sample :endianness :little)))
                     (dds.core.buffer:cursor-set-position rc 4)   ; past the FlatData buffer's XCDR2-LE encap header
                     (dds.core.buffer:cursor-set-origin rc)
                     (let* ((%st (,des rc :xcdr2))
                            (body-size (,ssz %st mode))
                            (buf (dds.core.buffer:make-octet-buffer (+ 4 body-size 8)))
                            (wc (dds.core.buffer:cursor buf :endianness :little)))
                       (dds.cdr:make-encapsulation-header wc encap)
                       (,ser %st wc mode)
                       (dds.cdr:finalize-encapsulation-options wc encap)
                       (let* ((len (dds.core.buffer:cursor-position wc))
                              (out (make-array len :element-type '(unsigned-byte 8))))
                         (replace out (dds.core.buffer:octet-buffer-vec buf) :end1 len)
                         (dds.pal:free-static (dds.core.buffer:octet-buffer-vec buf))
                         out)))))))
         (let ((%pool (dds.types:make-sample-pool (function ,ctor) ,*sample-pool-capacity*)))
           (dds.types:register-type
            (dds.types:make-type-support
             :name ,tname :type-name ,tname :extensibility ,ext
             :keyed-p ,(and keys t)
             ;; WP-FLATDATA: for a :flatdata type the engine's vtable funcalls the FlatData serialize=identity /
             ;; deserialize=read-in-place / constant serialized-size instead of the classic per-field codecs
             ;; (the engine hot path is unchanged — only these pointers swap); the classic ser/des/ssz stay
             ;; emitted for interop/non-FlatData use. WP-KEYED-FLATDATA: a keyed FlatData type binds :key-hash to
             ;; the buffer-reading key-hash-<name>-fd (the FlatData sample is the octet-buffer/view, not a struct);
             ;; a keyed non-FlatData type keeps the struct key-hash-<name>. (R6, ADR 0015/0017.)
             :serialize (function ,(if flatp fd-ser ser))
             :deserialize (function ,(if flatp fd-des des))
             :serialized-size (function ,(if flatp fd-ssz ssz))
             :key-hash ,(when keys `(function ,(if flatp khf-fd khf)))
             ;; WP-DATA-REPRESENTATION (R6): the FlatData TX-transcode for a non-XCDR2 offered rep
             ;; (decode XCDR2 buffer -> struct -> re-encode XCDR1), invoked by %serialize-sample; NIL
             ;; for a non-FlatData type (its struct serializer already honours the mode). (§7.6.3.1.1.)
             :flatdata-builder ,(when flatp `(function ,fd-tx))
             ;; WP-FLATDATA-LOAN-WRITE (R6, ADR 0042): the 0-arg FlatData constructor for DCPS loan-sample.
             :flatdata-ctor ,(when flatp `(function ,fd-ctor))
             :sample-pool-alloc (lambda () (dds.types:sample-pool-acquire %pool))
             :sample-pool-free (lambda (s) (dds.types:sample-pool-release %pool s))
             ;; WP-FLATDATA fixed-size layout (FR-PF-4, ADR 0015; R6); NIL for non-FlatData types.
             :flatdata-offset
             ,(when flatp
                `(dds.types:make-flatdata-layout
                  :size ,fd-size-sym
                  :fields (list ,@(loop for m in parsed
                                        for off = (cdr (assoc (getf m :slot) fd-offs))
                                        collect `(list ,(getf m :name)
                                                       ,off (function ,(fd-acc m))
                                                       (function (setf ,(fd-acc m))))))))
             ;; (field-name . accessor) per scalar/string member for content filters
             ;; (FR-DCPS-5, ADR 0008); sequence/nested members are not filterable in v1.
             :field-accessors
             (list ,@(loop for m in parsed
                           when (member (getf m :kind) '(:scalar))
                             collect `(cons ,(getf m :name)
                                            (function ,(acc m)))))
             ;; Structural Minimal TypeObject (FR-TYPE-2): member TIs for primitives/
             ;; strings/sequences; a nested-struct member carries a PENDING EK_MINIMAL
             ;; hash (the XCDR2 serializer that computes it is Connext-oracle-deferred).
             :typeobject
             (dds.types:make-minimal-struct-type
              :name ,tname :extensibility ,ext
              :members
              ;; The member id, not the member's POSITION. They coincide for a type that declares no
              ;; :id, which is why a positional index survived here; for a type that does declare one
              ;; they diverge, and the TypeObject would then advertise a different member id from the
              ;; one the codec puts in every EMHEADER — the two things a peer matches on (FR-TYPE-1
              ;; @id, FR-TYPE-2).
              (list ,@(loop for m in parsed
                            collect `(dds.types:make-struct-member
                                      ,(getf m :name)
                                      ,(getf m :id)
                                      ,(ecase (getf m :kind)
                                         ;; A bounded string is STRING8 with its bound, not the
                                         ;; unbounded STRING8 primitive-type-identifier yields.
                                         ;; An enum is TK_INT32 — its wire type. KNOWN GAP: a
                                         ;; conformant peer declares TK_ENUM, so the two TypeObjects
                                         ;; differ (the ADR 0009 class). Emitting a real enum TI
                                         ;; needs MinimalEnumeratedType serialization, whose bytes
                                         ;; are oracle-sensitive — the same reason sequence-member
                                         ;; TypeIdentifiers deliberately error rather than guess.
                                         (:scalar (cond
                                                    ((getf m :bound)
                                                     `(dds.types:string8-type-identifier ,(getf m :bound)))
                                                    ((getf m :enum)
                                                     `(dds.types:primitive-type-identifier :i32))
                                                    (t `(dds.types:primitive-type-identifier
                                                         ,(getf m :dds-type)))))
                                         (:sequence `(dds.types:sequence-type-identifier
                                                      (dds.types:primitive-type-identifier
                                                       ,(getf m :elt-type))))
                                         (:nested `(dds.types:hash-type-identifier
                                                    dds.types:+ek-minimal+
                                                    :referenced
                                                    (dds.types:type-support-typeobject
                                                     (dds.types:find-type-support
                                                      ,(getf m :type-name))))))
                                      ,@(when (getf m :key) '(:key-p t))
                                      ,@(when (getf m :must-understand)
                                          '(:must-understand-p t)))))))))
         ',name)))))
