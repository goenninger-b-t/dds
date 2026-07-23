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
  "Define a DDS topic type NAME from an s-expr spec. OPTIONS is a plist (only
   :extensibility, default :final, in v1). Each MEMBER is (slot-name member-type
   &key key), where member-type is a primitive keyword, (:sequence element), or
   the name of a previously-defined dds type (nested struct). Emits a defstruct,
   ftype-declared serialize/deserialize/serialized-size monomorphic functions
   (plus an internal %ssize position-threading helper), and a type-support."
  (let* ((pkg (or (symbol-package name) *package*))
         (ext (getf options :extensibility :final))
         (parsed (mapcar #'%parse-member members))
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
    (unless (eq ext :final)   ; NOCOND(MACRO): macroexpansion-time — compile-time rejection
      (error "define-dds-type: only :final extensibility is supported in v1 (got ~s)" ext))
    ;; FlatData v1 gate: :flatdata t requires every member to be a fixed-size scalar (FR-PF-4, ADR 0015).
    ;; This already constrains @key members to fixed-size scalars (WP-KEYED-FLATDATA): a string/sequence/
    ;; variable-size @key still errors here; the keyhash is read from the buffer via key-hash-<name>-fd below.
    (when (getf options :flatdata)
      (when (some (lambda (m) (or (getf m :var) (not (eq (getf m :kind) :scalar)))) parsed)
        ;; NOCOND(MACRO): macroexpansion-time — compile-time rejection
        (error "define-dds-type: :flatdata v1 requires FINAL + fixed-size scalar members (no string/sequence/nested/variable); got ~s"
               (find-if (lambda (m) (or (getf m :var) (not (eq (getf m :kind) :scalar)))) parsed))))
    (when (some (lambda (m) (not (eq (getf m :kind) :scalar))) keys)   ; NOCOND(MACRO): macroexpansion-time
      (error "define-dds-type: only scalar/string @key members are supported in v1"))
    (multiple-value-bind (fd-offs fd-body) (when flatp (%flatdata-offsets parsed))
      (declare (ignorable fd-offs fd-body))
    (flet ((acc (m) (%sym pkg (string name) "-" (string (getf m :slot))))
           (fd-acc (m) (%sym pkg (string name) "-" (string (getf m :slot)) "-FD")))
      (declare (ignorable #'fd-acc))
      `(progn
         (defstruct (,name (:constructor ,ctor))
           ,@(loop for m in parsed
                   collect `(,(getf m :slot) ,(getf m :default) :type ,(getf m :ltype))))
         (declaim (ftype (function (,name dds.core.buffer:cursor &optional symbol) ,name) ,ser))
         (defun ,ser (sample cursor &optional (mode :xcdr2))
           ,@(loop for m in parsed collect
                   (ecase (getf m :kind)
                     (:scalar `(,(getf m :put) cursor (,(acc m) sample) mode))
                     (:sequence (%seq-put-form m `(,(acc m) sample)))
                     (:nested `(,(getf m :ser) (,(acc m) sample) cursor mode))))
           sample)
         (declaim (ftype (function (dds.core.buffer:cursor &optional symbol) ,name) ,des))
         (defun ,des (cursor &optional (mode :xcdr2))
           (let ,(loop for m in parsed collect
                       (ecase (getf m :kind)
                         (:scalar `(,(getf m :slot) (,(getf m :get) cursor mode)))
                         (:sequence `(,(getf m :slot) ,(%seq-get-form m)))
                         (:nested `(,(getf m :slot) (,(getf m :des) cursor mode)))))
             (,ctor ,@(loop for m in parsed
                            append (list (intern (string (getf m :slot)) :keyword)
                                         (getf m :slot))))))
         (declaim (ftype (function (,name dds.core.buffer:cursor &optional symbol) ,name) ,dnto))
         (defun ,dnto (sample cursor &optional (mode :xcdr2))
           ,@(loop for m in parsed collect
                   (ecase (getf m :kind)
                     (:scalar `(setf (,(acc m) sample) (,(getf m :get) cursor mode)))
                     (:sequence `(setf (,(acc m) sample) ,(%seq-get-form m)))
                     (:nested `(,(getf m :des-into) (,(acc m) sample) cursor mode))))
           sample)
         (declaim (ftype (function (,name (integer 0) &optional symbol) (integer 0)) ,sszi))
         (defun ,sszi (sample pos &optional (mode :xcdr2))
           (declare (type (integer 0) pos) (ignorable sample))
           ,@(loop for m in parsed append
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
                      `((setf pos (,(getf m :ssize) (,(acc m) sample) pos mode))))))
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
                                        collect `(list ,(string-downcase (string (getf m :slot)))
                                                       ,off (function ,(fd-acc m))
                                                       (function (setf ,(fd-acc m))))))))
             ;; (field-name . accessor) per scalar/string member for content filters
             ;; (FR-DCPS-5, ADR 0008); sequence/nested members are not filterable in v1.
             :field-accessors
             (list ,@(loop for m in parsed
                           when (member (getf m :kind) '(:scalar))
                             collect `(cons ,(string-downcase (string (getf m :slot)))
                                            (function ,(acc m)))))
             ;; Structural Minimal TypeObject (FR-TYPE-2): member TIs for primitives/
             ;; strings/sequences; a nested-struct member carries a PENDING EK_MINIMAL
             ;; hash (the XCDR2 serializer that computes it is Connext-oracle-deferred).
             :typeobject
             (dds.types:make-minimal-struct-type
              :name ,tname :extensibility ,ext
              :members
              (list ,@(loop for m in parsed for idx from 0
                            collect `(dds.types:make-struct-member
                                      ,(string-downcase (string (getf m :slot)))
                                      ,idx
                                      ,(ecase (getf m :kind)
                                         (:scalar `(dds.types:primitive-type-identifier
                                                    ,(getf m :dds-type)))
                                         (:sequence `(dds.types:sequence-type-identifier
                                                      (dds.types:primitive-type-identifier
                                                       ,(getf m :elt-type))))
                                         (:nested `(dds.types:hash-type-identifier
                                                    dds.types:+ek-minimal+
                                                    :referenced
                                                    (dds.types:type-support-typeobject
                                                     (dds.types:find-type-support
                                                      ,(getf m :type-name))))))
                                      ,@(when (getf m :key) '(:key-p t)))))))))
         ',name)))))
