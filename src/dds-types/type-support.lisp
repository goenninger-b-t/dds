(in-package #:dds.types)

(defstruct (type-support (:constructor make-type-support))
  (name nil)
  (type-name nil :type (or null string))
  (extensibility :appendable)
  (serialize nil :type (or null function))
  (deserialize nil :type (or null function))
  (serialized-size nil :type (or null function))
  (key-hash nil :type (or null function))
  (typeobject nil)
  (typeidentifier nil)
  (sample-pool-alloc nil :type (or null function))
  (sample-pool-free nil :type (or null function))
  (flatdata-offset nil :type (or null function))
  (flatdata-builder nil :type (or null function))
  (data-representation-mask 0 :type integer))

(defvar *type-registry* (make-hash-table :test 'equal)
  "Maps a type name to its type-support. Control-plane structure (off hot path).")

(declaim (ftype (function (type-support) type-support) register-type))
(declaim (ftype (function (t) t) find-type-support))
(declaim (ftype (function () list) registered-type-names))

(defun register-type (ts)
  "Register type-support TS under its NAME. Returns TS."
  (setf (gethash (type-support-name ts) *type-registry*) ts)
  ts)

(defun find-type-support (name)
  "Look up the type-support registered under NAME, or NIL."
  (values (gethash name *type-registry*)))

(defun registered-type-names ()
  "List of all registered type names."
  (loop for k being the hash-keys of *type-registry* collect k))

;;; Sample pool: a fixed-capacity freelist of pre-allocated sample structs, so a
;;; reader loans a struct, deserializes into it, and returns it — zero per-sample
;;; allocation in steady state (NFR-MEM / NFR-DET). Carved once at registration.

(defstruct (sample-pool (:constructor %make-sample-pool))
  (slots #() :type simple-vector)
  (top 0 :type fixnum))

(declaim (ftype (function (function (integer 1)) sample-pool) make-sample-pool))
(defun make-sample-pool (ctor capacity)
  "Pre-allocate CAPACITY samples via the thunk CTOR for zero-per-sample reuse."
  (let ((slots (make-array capacity)))
    (dotimes (i capacity) (setf (svref slots i) (funcall ctor)))
    (%make-sample-pool :slots slots :top capacity)))

(declaim (ftype (function (sample-pool) t) sample-pool-acquire))
(defun sample-pool-acquire (pool)
  "Pop a pre-allocated sample; NIL on exhaustion (caller applies RESOURCE_LIMITS)."
  (let ((top (sample-pool-top pool)))
    (if (zerop top)
        nil
        (let ((nt (1- top)))
          (setf (sample-pool-top pool) nt)
          (let ((obj (svref (sample-pool-slots pool) nt)))
            (setf (svref (sample-pool-slots pool) nt) nil)
            obj)))))

(declaim (ftype (function (sample-pool t) (values)) sample-pool-release))
(defun sample-pool-release (pool obj)
  "Return a loaned sample to POOL."
  (let ((top (sample-pool-top pool)))
    (setf (svref (sample-pool-slots pool) top) obj
          (sample-pool-top pool) (1+ top))
    (values)))
