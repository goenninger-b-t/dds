(in-package #:dds.gen)

(defparameter *dds-type-map*
  ;; dds-type -> (lisp-type default put-fn get-fn align size|:var)
  '((:bool   t                  nil dds.cdr:cdr-put-bool   dds.cdr:cdr-get-bool   1 1)
    (:u8     (unsigned-byte 8)  0   dds.cdr:cdr-put-u8     dds.cdr:cdr-get-u8     1 1)
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
   REQUIREMENTS FR-CDR-1/2; string size = 4 (length) + octets + 1 (NUL).")

(defparameter *sample-pool-capacity* 64
  "Per-type sample-pool size, pre-allocated at registration (NFR-MEM). A later
   ADR derives this from the RESOURCE_LIMITS QoS.")

(declaim (ftype (function (package &rest t) symbol) %sym))
(defun %sym (package &rest parts)
  "Intern the concatenation of PARTS (string designators) as a symbol in PACKAGE."
  (intern (apply #'concatenate 'string (mapcar #'string parts)) package))

(declaim (ftype (function (list) list) %parse-member))
(defun %parse-member (spec)
  "Parse a member spec into a codegen plist. Member type is a primitive keyword,
   (:sequence ELEMENT-KEYWORD) for a sequence of fixed-size primitives, or the
   symbol of a previously-defined dds type for a nested struct."
  (destructuring-bind (slot dds-type &rest opts) spec
    (cond
      ((and (consp dds-type) (eq (car dds-type) :sequence))
       (let* ((elt (second dds-type))
              (row (cdr (assoc elt *dds-type-map*))))
         (unless row
           (error "define-dds-type: unsupported sequence element ~s in ~s" elt spec))
         (destructuring-bind (eltype default eput eget ealign esize) row
           (declare (ignore eltype default))
           (when (eq esize :var)
             (error "define-dds-type: sequence of variable-size element ~s not supported in v1"
                    elt))
           (list :slot slot :kind :sequence :ltype 'vector :default '(vector)
                 :elt-put eput :elt-get eget :elt-align ealign :elt-size esize
                 :key (getf opts :key)))))
      ((keywordp dds-type)
       (let ((row (cdr (assoc dds-type *dds-type-map*))))
         (unless row
           (error "define-dds-type: unsupported member type ~s in ~s" dds-type spec))
         (destructuring-bind (ltype default put get align size) row
           (list :slot slot :kind :scalar :ltype ltype :default default :put put :get get
                 :align align :var (eq size :var) :size (if (eq size :var) 0 size)
                 :key (getf opts :key)))))
      ((symbolp dds-type)            ; nested, previously-defined dds type
       (let ((tpkg (or (symbol-package dds-type) *package*)))
         (list :slot slot :kind :nested :ltype dds-type
               :default (list (%sym tpkg "MAKE-" (string dds-type)))
               :ser (%sym tpkg "SERIALIZE-" (string dds-type))
               :des (%sym tpkg "DESERIALIZE-" (string dds-type))
               :des-into (%sym tpkg "DESERIALIZE-INTO-" (string dds-type))
               :ssize (%sym tpkg "%SSIZE-" (string dds-type))
               :key (getf opts :key))))
      (t (error "define-dds-type: unsupported member type ~s in ~s" dds-type spec)))))

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
         (tname (string-downcase (string name))))
    (unless (eq ext :final)
      (error "define-dds-type: only :final extensibility is supported in v1 (got ~s)" ext))
    (flet ((acc (m) (%sym pkg (string name) "-" (string (getf m :slot)))))
      `(progn
         (defstruct (,name (:constructor ,ctor))
           ,@(loop for m in parsed
                   collect `(,(getf m :slot) ,(getf m :default) :type ,(getf m :ltype))))
         (declaim (ftype (function (,name dds.core.buffer:cursor &optional symbol) ,name) ,ser))
         (defun ,ser (sample cursor &optional (mode :xcdr2))
           ,@(loop for m in parsed collect
                   (ecase (getf m :kind)
                     (:scalar `(,(getf m :put) cursor (,(acc m) sample) mode))
                     (:sequence `(dds.cdr:cdr-put-sequence
                                  cursor (,(acc m) sample) (function ,(getf m :elt-put)) mode))
                     (:nested `(,(getf m :ser) (,(acc m) sample) cursor mode))))
           sample)
         (declaim (ftype (function (dds.core.buffer:cursor &optional symbol) ,name) ,des))
         (defun ,des (cursor &optional (mode :xcdr2))
           (let ,(loop for m in parsed collect
                       (ecase (getf m :kind)
                         (:scalar `(,(getf m :slot) (,(getf m :get) cursor mode)))
                         (:sequence `(,(getf m :slot)
                                      (dds.cdr:cdr-get-sequence
                                       cursor (function ,(getf m :elt-get)) mode)))
                         (:nested `(,(getf m :slot) (,(getf m :des) cursor mode)))))
             (,ctor ,@(loop for m in parsed
                            append (list (intern (string (getf m :slot)) :keyword)
                                         (getf m :slot))))))
         (declaim (ftype (function (,name dds.core.buffer:cursor &optional symbol) ,name) ,dnto))
         (defun ,dnto (sample cursor &optional (mode :xcdr2))
           ,@(loop for m in parsed collect
                   (ecase (getf m :kind)
                     (:scalar `(setf (,(acc m) sample) (,(getf m :get) cursor mode)))
                     (:sequence `(setf (,(acc m) sample)
                                       (dds.cdr:cdr-get-sequence
                                        cursor (function ,(getf m :elt-get)) mode)))
                     (:nested `(,(getf m :des-into) (,(acc m) sample) cursor mode))))
           sample)
         (declaim (ftype (function (,name (integer 0) &optional symbol) (integer 0)) ,sszi))
         (defun ,sszi (sample pos &optional (mode :xcdr2))
           (declare (type (integer 0) pos) (ignorable sample))
           ,@(loop for m in parsed append
                   (ecase (getf m :kind)
                     (:scalar
                      (if (getf m :var)
                          `((setf pos (dds.cdr:cdr-size-align pos 4 mode))
                            (incf pos (+ 5 (length (,(acc m) sample)))))
                          `((setf pos (dds.cdr:cdr-size-align pos ,(getf m :align) mode))
                            (incf pos ,(getf m :size)))))
                     (:sequence
                      `((setf pos (dds.cdr:cdr-size-align pos 4 mode))
                        (incf pos 4)
                        (loop repeat (length (,(acc m) sample))
                              do (setf pos (dds.cdr:cdr-size-align pos ,(getf m :elt-align) mode))
                                 (incf pos ,(getf m :elt-size)))))
                     (:nested
                      `((setf pos (,(getf m :ssize) (,(acc m) sample) pos mode))))))
           pos)
         (declaim (ftype (function (,name &optional symbol) (integer 0)) ,ssz))
         (defun ,ssz (sample &optional (mode :xcdr2))
           (,sszi sample 0 mode))
         (let ((%pool (dds.types:make-sample-pool (function ,ctor) ,*sample-pool-capacity*)))
           (dds.types:register-type
            (dds.types:make-type-support
             :name ,tname :type-name ,tname :extensibility ,ext
             :serialize (function ,ser)
             :deserialize (function ,des)
             :serialized-size (function ,ssz)
             :sample-pool-alloc (lambda () (dds.types:sample-pool-acquire %pool))
             :sample-pool-free (lambda (s) (dds.types:sample-pool-release %pool s)))))
         ',name))))
