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
