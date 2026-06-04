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

(declaim (ftype (function (package &rest t) symbol) %sym))
(defun %sym (package &rest parts)
  "Intern the concatenation of PARTS (string designators) as a symbol in PACKAGE."
  (intern (apply #'concatenate 'string (mapcar #'string parts)) package))

(declaim (ftype (function (list) list) %parse-member))
(defun %parse-member (spec)
  "Parse a member spec (SLOT DDS-TYPE &key key) into a plist of codegen facts."
  (destructuring-bind (slot dds-type &rest opts) spec
    (let ((row (cdr (assoc dds-type *dds-type-map*))))
      (unless row
        (error "define-dds-type: unsupported member type ~s in ~s" dds-type spec))
      (destructuring-bind (ltype default put get align size) row
        (list :slot slot :ltype ltype :default default :put put :get get
              :align align :var (eq size :var) :size (if (eq size :var) 0 size)
              :key (getf opts :key))))))

(defmacro define-dds-type (name options &body members)
  "Define a DDS topic type NAME from an s-expr spec. OPTIONS is a plist (only
   :extensibility, default :final, in v1). Each MEMBER is (slot-name dds-type
   &key key). Emits: a defstruct, ftype-declared serialize/deserialize/
   serialized-size monomorphic functions, and a registered type-support."
  (let* ((pkg (or (symbol-package name) *package*))
         (ext (getf options :extensibility :final))
         (parsed (mapcar #'%parse-member members))
         (ctor (%sym pkg "MAKE-" (string name)))
         (ser  (%sym pkg "SERIALIZE-" (string name)))
         (des  (%sym pkg "DESERIALIZE-" (string name)))
         (ssz  (%sym pkg "SERIALIZED-SIZE-" (string name)))
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
           ,@(loop for m in parsed
                   collect `(,(getf m :put) cursor (,(acc m) sample) mode))
           sample)
         (declaim (ftype (function (dds.core.buffer:cursor &optional symbol) ,name) ,des))
         (defun ,des (cursor &optional (mode :xcdr2))
           (let ,(loop for m in parsed
                       collect `(,(getf m :slot) (,(getf m :get) cursor mode)))
             (,ctor ,@(loop for m in parsed
                            append (list (intern (string (getf m :slot)) :keyword)
                                         (getf m :slot))))))
         (declaim (ftype (function (,name &optional symbol) (integer 0)) ,ssz))
         (defun ,ssz (sample &optional (mode :xcdr2))
           (declare (ignorable sample))
           (let ((pos 0))
             (declare (type (integer 0) pos))
             ,@(loop for m in parsed
                     append `((setf pos (dds.cdr:cdr-size-align pos ,(getf m :align) mode))
                              (incf pos ,(if (getf m :var)
                                             `(+ 5 (length (,(acc m) sample)))
                                             (getf m :size)))))
             pos))
         (dds.types:register-type
          (dds.types:make-type-support
           :name ,tname :type-name ,tname :extensibility ,ext
           :serialize (function ,ser)
           :deserialize (function ,des)
           :serialized-size (function ,ssz)))
         ',name))))
