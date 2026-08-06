(in-package #:dds.types)

;;;; NOT cleared for ship — pending counsel (R6); see ADR 0015.
(defstruct* (flatdata-layout (:constructor make-flatdata-layout))
  "WP-FLATDATA fixed-size layout (FR-PF-4): total SerializedPayload SIZE (encap header + XCDR2 body),
   ENCAP-OFFSET (4), and per-field (name body-offset getter setter) for in-place access.
   NOT cleared for ship — pending counsel (R6); see ADR 0015."
  (size 0 :type (integer 0)) (encap-offset 4 :type (integer 0)) (fields '() :type list))

;;;; NOT cleared for ship — pending counsel (R6); see ADR 0017.
(defstruct* (flatdata-view (:constructor make-flatdata-view))
  "WP-FLATDATA-ZC-LOAN in-place view over a live ZC SHMEM slot (FR-PF-3/4): SLOT-SAP + BASE-OFFSET (the XCDR2
   body start within the segment, past the 4-octet encap header) for the SAP-mode Offset accessors, LEN
   (validated >= +size+ by the loan path), and the pool handle (POOL-SAP + SLOT-INDEX + GENERATION) for
   return-loan / loan-write commit. Used BOTH ways: RX read-in-place (ADR 0017, the getters) and WP-FLATDATA-
   LOAN-WRITE TX write-in-place (ADR 0042 — the setters write the app's fields straight into a writer-loaned
   slot). NOT cleared for ship — pending counsel (R6); see ADR 0017 / 0042."
  (slot-sap nil :type t) (base-offset 4 :type (integer 0)) (len 0 :type (integer 0))
  (pool-sap nil :type t) (slot-index 0 :type (integer 0)) (generation 0 :type (unsigned-byte 32)))

(defstruct* (type-support (:constructor make-type-support))
  "Per-type manual vtable the engine funcalls per sample (IMPLEMENTATION-PLAN §7.3): a
   plain defstruct of function objects (serialize/deserialize/serialized-size/key-hash,
   sample-pool alloc+free, FlatData hooks — FLATDATA-OFFSET holds the FlatData-layout for a
   :flatdata type, NIL otherwise; FLATDATA-BUILDER holds that type's WP-DATA-REPRESENTATION
   TX-transcode (buf,mode,encap)->octets for a non-XCDR2 offered rep, NIL otherwise — field
   accessors) plus the type name,
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
  ;; ADR 0093 slice 4: (sample cursor &optional mode) -> fills SAMPLE IN PLACE and returns it (mutable
  ;; extensibility returns (values sample-or-nil status)). Every slot is reset to its default first, so a
  ;; recycled sample never keeps the previous occupant's value. NIL for a FlatData type — its own
  ;; deserialize-into-<name>-fd targets a BUFFER, not a struct, so the copy path falls back to allocating.
  (deserialize-into nil :type (or null function))
  (serialized-size nil :type (or null function))
  (key-hash nil :type (or null function))
  (typeobject nil :type t)
  (typeidentifier nil :type t)
  (sample-pool-alloc nil :type (or null function))
  (sample-pool-free nil :type (or null function))
  (flatdata-offset nil :type (or null function flatdata-layout))
  ;; WP-DATA-REPRESENTATION FlatData TX-transcode (buf,mode,encap)->octets; NIL for non-FlatData (R6, §7.6.3.1.1).
  (flatdata-builder nil :type (or null function))
  ;; WP-FLATDATA-LOAN-WRITE (R6, ADR 0042): the 0-arg FlatData constructor make-<name>-flatdata (a fresh
  ;; encap-initialized foreign octet-buffer); NIL for non-FlatData. DCPS loan-sample funcalls it for the
  ;; graceful-degradation (non-slot) loan AND to source the per-type 4-octet encap header for a slot-backed loan.
  (flatdata-ctor nil :type (or null function))
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
    (function (sample-pool t) (values (or null (eql t)) (or null keyword)))
  "Return a loaned sample to POOL. (values T NIL) on success; (values NIL :pool-overflow) when POOL is
   already full, in which case OBJ is DROPPED and the pool is left untouched.

   ⚠️ THE BOUNDS CHECK IS THE POINT, AND IT USED TO BE ABSENT. This wrote (setf (svref slots top) obj) with
   TOP unchecked against the backing vector's length, so releasing more samples than were acquired — a
   double release, or a release of an object this pool never loaned — indexed PAST THE END of SLOTS.

   WHAT THAT ACTUALLY DID, MEASURED RATHER THAN ASSUMED: this repo carries no global OPTIMIZE policy (only
   three tiny local sites), so it compiles at SBCL's default SAFETY 1, where SVREF IS bounds-checked — the
   un-guarded release therefore SIGNALLED (observed: 'Invalid index 3 for (SIMPLE-VECTOR 3)'), it did not
   silently corrupt the heap. That is still a defect, and a double one: a condition escaping a pool release
   violates the no-conditions rule, and the same code at SAFETY 0 — or in any build that lowers safety —
   would be a genuine out-of-bounds write instead. The identical (safety 0) OOB claim was made about
   ADR 0078 and turned out to be false for exactly this reason; do not restate it without measuring.

   It was unreachable in practice only because the engine does not call these hooks: DDS.DCPS deliberately
   uses its own per-reader DR-DATA-POOL instead (see the note at %rx-data-pop's definition — this pool is
   shared across readers AND, until now, unguarded). 'Safe because nothing calls it' stops being true the
   moment something does, which is exactly what the take-into design proposed to do.

   REFUSES rather than signals (the no-conditions rule): an over-release is a CALLER defect, so it is
   reported as a status the caller can test, and the pool's invariant (TOP <= capacity, every slot below TOP
   live) holds unconditionally afterwards. Dropping OBJ is deliberate — the alternative, growing SLOTS, would
   let a buggy or hostile caller drive unbounded allocation through a fixed-capacity pool.

   Mirrors SAMPLE-POOL-ACQUIRE, which already reports exhaustion as NIL rather than signalling."
  (let ((slots (sample-pool-slots pool))
        (top (sample-pool-top pool)))
    (when (>= top (length slots))
      (return-from sample-pool-release (values nil :pool-overflow)))
    (setf (svref slots top) obj
          (sample-pool-top pool) (1+ top))
    (values t nil)))
