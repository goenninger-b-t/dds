(in-package #:dds.core.arena)

(defparameter *static-arena-bytes* (* 64 1024 1024)
  "Master off-heap byte budget for all hot-path memory (REQUIREMENTS NFR-MEM).
   Read ONCE at init-arena; rebinding afterwards has no effect until teardown.")

;; ARENA-EXHAUSTED (the condition) is GONE. Arena exhaustion is the ORDINARY, EXPECTED outcome NFR-MEM
;; demands be handled — RESOURCE_LIMITS or a documented allocating fallback, never a silent GC-heap
;; fill-in — so it is now MAKE-BUFFER-POOL's :ARENA-EXHAUSTED status value, not a stack unwind (ADR 0064).
;; Every one of its eight call sites already degraded to a NIL pool; each now TESTS the status, and — the
;; defect that fell out of the conversion — TEARS THE ARENA DOWN, which the catching versions never did:
;; a failed carve used to leave the just-init'd arena's static allocation orphaned.

(defstruct* (arena (:constructor %make-arena))
  "Static, startup-allocated off-heap memory region with a fixed byte budget;
   pools are carved from it via make-buffer-pool (NFR-MEM)."
  (byte-budget 0 :type fixnum)
  (bytes-used 0 :type fixnum)
  (pools '() :type list)
  (initialized nil :type boolean))

(defstruct* (buffer-pool (:constructor %make-buffer-pool))
  "Fixed-capacity pool of equal-size octet buffers carved from a static arena; pool-acquire/pool-release reuse them with zero per-acquisition allocation (NFR-MEM)."
  (element-bytes 0 :type fixnum)
  (capacity 0 :type fixnum)
  (slots #() :type simple-vector)
  (top 0 :type fixnum)
  (in-use 0 :type fixnum)
  (high-water 0 :type fixnum))


(defun* arena-initialized-p (arena)
    (function (arena) boolean) "True while ARENA is live (between init-arena and teardown-arena)." (arena-initialized arena))
(defun* pool-capacity (pool)
    (function (buffer-pool) fixnum) "Fixed number of buffers POOL was provisioned with." (buffer-pool-capacity pool))
(defun* pool-in-use (pool)
    (function (buffer-pool) fixnum) "Number of buffers currently checked out of POOL." (buffer-pool-in-use pool))
(defun* pool-high-water (pool)
    (function (buffer-pool) fixnum) "Peak in-use count seen for POOL (NFR-OBS / budget tracking)." (buffer-pool-high-water pool))

(defun* init-arena (&key (bytes *static-arena-bytes*))
    (function (&key (:bytes (integer 0))) arena)
  "Create the arena with a fixed BYTE budget (defaults from *static-arena-bytes*,
   read once here). One-shot; pools are carved from it via make-buffer-pool."
  (declare (type (integer 0) bytes))
  (%make-arena :byte-budget bytes :bytes-used 0 :pools '() :initialized t))

(defun* teardown-arena (arena)
    (function (arena) arena)
  "Free every pool's static buffers and mark the arena uninitialized."
  (dolist (pool (arena-pools arena))
    (loop for b across (buffer-pool-slots pool)
          when b do (dds.pal:free-static (dds.core.buffer:octet-buffer-vec b))))
  (setf (arena-pools arena) '()
        (arena-bytes-used arena) 0
        (arena-initialized arena) nil)
  arena)

(defun* make-buffer-pool (arena element-bytes capacity)
    (function (arena (integer 1) (integer 1)) (values (or null buffer-pool) (or null keyword)))
  "Carve a fixed-capacity pool of CAPACITY octet-buffers of ELEMENT-BYTES each,
   pre-allocated once from off-heap static memory. Steady-state acquire/release
   is index manipulation with zero allocation.

   Returns (values pool NIL), or (values NIL :ARENA-EXHAUSTED) when the carve does not fit the arena's
   remaining budget. EXHAUSTION IS AN ORDINARY, EXPECTED OUTCOME — NFR-MEM requires it map to
   RESOURCE_LIMITS or a documented fallback, never a silent GC-heap fill-in — so it is a STATUS VALUE, not
   the ARENA-EXHAUSTED condition it used to signal (ADR 0064). Every caller already degraded to a NIL pool
   plus an allocating fallback; they now do it by TESTING the status rather than by catching."
  (declare (type (integer 1) element-bytes capacity))
  (let* ((want (* element-bytes capacity))
         (remaining (- (arena-byte-budget arena) (arena-bytes-used arena))))
    (when (> want remaining)
      (bail :arena-exhausted))
    (let ((slots (make-array capacity)))
      (dotimes (i capacity)
        (setf (svref slots i) (dds.core.buffer:make-octet-buffer element-bytes)))
      (let ((pool (%make-buffer-pool :element-bytes element-bytes
                                     :capacity capacity
                                     :slots slots
                                     :top capacity)))
        (incf (arena-bytes-used arena) want)
        (push pool (arena-pools arena))
        (values pool nil)))))

(defun* pool-acquire (pool)
    (function (buffer-pool) t)
  "Pop a buffer from POOL. Return NIL on exhaustion — the caller applies
   RESOURCE_LIMITS, never a GC-heap fallback (NFR-MEM)."
  (let ((top (buffer-pool-top pool)))
    (when (zerop top)
      (return-from pool-acquire nil))
    (let ((new-top (1- top)))
      (setf (buffer-pool-top pool) new-top)
      (let ((obj (svref (buffer-pool-slots pool) new-top)))
        (setf (svref (buffer-pool-slots pool) new-top) nil)
        (incf (buffer-pool-in-use pool))
        (when (> (buffer-pool-in-use pool) (buffer-pool-high-water pool))
          (setf (buffer-pool-high-water pool) (buffer-pool-in-use pool)))
        obj))))

(defun* pool-release (pool obj)
    (function (buffer-pool t) (values))
  "Return OBJ to POOL. A release when the free list is already FULL (top = capacity, i.e. nothing is
   checked out) would, at (safety 0), write (svref slots capacity) — one past the vector — a wild heap
   write that a later GC faults on (ADR 0078 §re-landing: this was an unguarded OOB). It is only ever
   reachable through a caller bug (a double release / a release of a buffer never acquired); the bounds
   guard degrades that to a NO-OP (a bounded leaked slot — the pool then falls back to allocating),
   strictly better than corrupting the free list or the heap. Correct callers (top < capacity) are
   byte-identical to before."
  (let ((top (buffer-pool-top pool)))
    (when (< top (buffer-pool-capacity pool))
      (setf (svref (buffer-pool-slots pool) top) obj
            (buffer-pool-top pool) (1+ top))
      (decf (buffer-pool-in-use pool))))
  (values))

(defun* arena-report (arena)
    (function (arena) list)
  "Plist of reserved sizes per pool for startup logging (NFR-OBS)."
  (list :byte-budget (arena-byte-budget arena)
        :bytes-used (arena-bytes-used arena)
        :pools (mapcar (lambda (p)
                         (list :element-bytes (buffer-pool-element-bytes p)
                               :capacity (buffer-pool-capacity p)
                               :high-water (buffer-pool-high-water p)))
                       (arena-pools arena))))
