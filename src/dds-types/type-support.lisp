(in-package #:dds.types)

;;;; NOT cleared for ship — pending counsel (R6); see ADR 0015.
(defstruct* (flatdata-layout (:constructor make-flatdata-layout))
  "WP-FLATDATA fixed-size layout (FR-PF-4): total SerializedPayload SIZE (encap header + XCDR2 body),
   ENCAP-OFFSET (4), and per-field (name body-offset getter setter) for in-place access.
   NOT cleared for ship — pending counsel (R6); see ADR 0015."
  (size 0 :type (integer 0)) (encap-offset 4 :type (integer 0)) (fields '() :type list))

(defstruct* (type-support (:constructor make-type-support))
  "Per-type manual vtable the engine funcalls per sample (IMPLEMENTATION-PLAN §7.3): a
   plain defstruct of function objects (serialize/deserialize/serialized-size/key-hash,
   sample-pool alloc+free, FlatData hooks — FLATDATA-OFFSET holds the FlatData-layout for a
   :flatdata type, NIL otherwise — field accessors) plus the type name,
   extensibility, structural TypeObject/TypeIdentifier, and data-representation mask. The
   hot path sees only this struct, never the concrete sample type. KEYED-P records the
   RTPS TopicKind (DDSI-RTPS 2.5 §8.2.4.2): T = WITH_KEY (the type has at least one @key
   member), NIL = NO_KEY; it defaults T for back-compat and lets discovery pick the RTPS
   entity kind."
  (name nil :type (or null string))
  (type-name nil :type (or null string))
  (extensibility :appendable :type (member :final :appendable :mutable))
  (keyed-p t :type boolean)
  (serialize nil :type (or null function))
  (deserialize nil :type (or null function))
  (serialized-size nil :type (or null function))
  (key-hash nil :type (or null function))
  (typeobject nil :type t)
  (typeidentifier nil :type t)
  (sample-pool-alloc nil :type (or null function))
  (sample-pool-free nil :type (or null function))
  (flatdata-offset nil :type (or null function flatdata-layout))
  (flatdata-builder nil :type (or null function))
  (data-representation-mask 0 :type integer)
  ;; (FIELD-NAME-STRING . unary accessor) per scalar/string member, for content
  ;; filters / query conditions (FR-DCPS-5, ADR 0008). Off the hot path; nil otherwise.
  (field-accessors '() :type list))

(defvar *type-registry* (make-hash-table :test 'equal)
  "Maps a type name to its type-support. Control-plane structure (off hot path).")

(defvar *type-registry-generation* 0
  "Monotonic counter bumped by every REGISTER-TYPE call — including re-registration of
   an existing name, which leaves HASH-TABLE-COUNT unchanged — so caches derived from
   *TYPE-REGISTRY* (e.g. the TypeLookup hash index) can detect any mutation.")

(defun* register-type (ts)
    (function (type-support) type-support)
  "Register type-support TS under its NAME, bumping *TYPE-REGISTRY-GENERATION*. Returns TS."
  (setf (gethash (type-support-name ts) *type-registry*) ts)
  (incf *type-registry-generation*)
  ts)

(defun* find-type-support (name)
    (function (t) t)
  "Look up the type-support registered under NAME, or NIL."
  (values (gethash name *type-registry*)))

(defun* registered-type-names ()
    (function () list)
  "List of all registered type names."
  (loop for k being the hash-keys of *type-registry* collect k))

;;; Sample pool: a fixed-capacity freelist of pre-allocated sample structs, so a
;;; reader loans a struct, deserializes into it, and returns it — zero per-sample
;;; allocation in steady state (NFR-MEM / NFR-DET). Carved once at registration.

(defstruct* (sample-pool (:constructor %make-sample-pool))
  "A fixed-capacity freelist of pre-allocated sample structs: a reader loans a struct,
   deserializes into it, and returns it — zero per-sample allocation in steady state
   (NFR-MEM / NFR-DET). SLOTS is the backing vector, TOP the freelist stack pointer.
   Carved once at registration."
  (slots #() :type simple-vector)
  (top 0 :type fixnum))

(defun* make-sample-pool (ctor capacity)
    (function (function (integer 1)) sample-pool)
  "Pre-allocate CAPACITY samples via the thunk CTOR for zero-per-sample reuse."
  (let ((slots (make-array capacity)))
    (dotimes (i capacity) (setf (svref slots i) (funcall ctor)))
    (%make-sample-pool :slots slots :top capacity)))

(defun* sample-pool-acquire (pool)
    (function (sample-pool) t)
  "Pop a pre-allocated sample; NIL on exhaustion (caller applies RESOURCE_LIMITS)."
  (let ((top (sample-pool-top pool)))
    (if (zerop top)
        nil
        (let ((nt (1- top)))
          (setf (sample-pool-top pool) nt)
          (let ((obj (svref (sample-pool-slots pool) nt)))
            (setf (svref (sample-pool-slots pool) nt) nil)
            obj)))))

(defun* sample-pool-release (pool obj)
    (function (sample-pool t) (values))
  "Return a loaned sample to POOL."
  (let ((top (sample-pool-top pool)))
    (setf (svref (sample-pool-slots pool) top) obj
          (sample-pool-top pool) (1+ top))
    (values)))
