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
  (initialized nil :type boolean)
  ;; ADR 0095 option (a): a SUB-ARENA is a charge account against PARENT. Every carve here also charges the
  ;; parent — so the ONE process budget (*static-arena-bytes*) is what is really enforced — and adds to
  ;; RESERVED; teardown returns exactly RESERVED to the parent. That is what makes a participant
  ;; create/delete cycle budget-neutral: without it a shared arena is bump-allocated with no way to return
  ;; a carve, and a long-running process that churns participants eventually cannot carve at all.
  (parent nil :type (or null arena))
  (reserved 0 :type fixnum))

(defvar *process-arena* nil
  "THE process-wide static arena (ADR 0095), created on first use from *STATIC-ARENA-BYTES* and shared by
   every participant in the image via its own sub-arena. NIL until PROCESS-ARENA is first called.

   It exists because FR-PF-7's budget was not being enforced anywhere: every production carve used to build
   its OWN arena sized to that one pool, so *STATIC-ARENA-BYTES* was never read outside tests and no
   component could answer 'has this process exceeded its static-memory budget?'. Rebinding this to NIL
   between runs is how a test gets a fresh budget; rebinding *STATIC-ARENA-BYTES* after the first carve has
   no effect, exactly as its own docstring says.")

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

(defun* process-arena ()
    (function () arena)
  "THE process-wide static arena (ADR 0095), created on first call with the *STATIC-ARENA-BYTES* budget and
   returned unchanged thereafter. Every participant sub-carves from it (MAKE-SUB-ARENA), so this one budget
   is what bounds all hot-path static memory in the image — the property FR-PF-7 asserts and that ten
   independent per-pool arenas could not provide."
  (or *process-arena*
      (setf *process-arena* (init-arena))))

(defun* make-sub-arena (parent)
    (function (arena) arena)
  "A sub-arena of PARENT: a charge account, not a pre-sized slab (ADR 0095 option (a)). It starts with no
   reservation and grows on demand — every carve charges PARENT (so PARENT's budget is the real ceiling)
   and is remembered in RESERVED, which TEARDOWN-ARENA returns to PARENT in full.

   Demand-grown rather than fixed on purpose: a fixed per-participant slab has to be guessed, and both
   errors are bad — too small and the participant cannot carve its pools, too large and it silently shrinks
   the process budget for everyone else. Nothing has to be guessed here.

   Its own BYTE-BUDGET is PARENT's, so a sub-carve is bounded by exactly the same ceiling; the sub-arena
   adds ownership and teardown, never a second limit."
  (%make-arena :byte-budget (arena-byte-budget parent) :bytes-used 0 :pools '()
               :initialized t :parent parent :reserved 0))

(defun* teardown-arena (arena)
    (function (arena) arena)
  "Free every pool's static buffers, return any parent reservation, and mark the arena uninitialized.
   ADR 0095: a sub-arena returns exactly what it charged (RESERVED) to its parent, which is what keeps a
   participant create/delete cycle budget-neutral."
  (dolist (pool (arena-pools arena))
    (loop for b across (buffer-pool-slots pool)
          when b do (dds.pal:free-static (dds.core.buffer:octet-buffer-vec b))))
  (let ((parent (arena-parent arena)))
    (when parent
      (decf (arena-bytes-used parent) (arena-reserved arena))))
  (setf (arena-pools arena) '()
        (arena-bytes-used arena) 0
        (arena-reserved arena) 0
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
         ;; ADR 0095: a sub-arena's ceiling is its PARENT's remaining budget, not its own bookkeeping — the
         ;; whole point is that ONE process budget bounds everything. A root arena charges only itself.
         (charge-to (or (arena-parent arena) arena))
         (remaining (- (arena-byte-budget charge-to) (arena-bytes-used charge-to))))
    (when (> want remaining)
      (bail :arena-exhausted))
    (let ((slots (make-array capacity)))
      (dotimes (i capacity)
        (setf (svref slots i) (dds.core.buffer:make-octet-buffer element-bytes)))
      (let ((pool (%make-buffer-pool :element-bytes element-bytes
                                     :capacity capacity
                                     :slots slots
                                     :top capacity)))
        ;; Charge the budget-holder (the parent for a sub-arena) and remember the reservation locally, so
        ;; teardown can return exactly this much. A root arena's CHARGE-TO is itself, so both INCFs land on
        ;; the same counter and RESERVED simply mirrors BYTES-USED — byte-identical to the pre-ADR-0095
        ;; behaviour for every caller that still builds its own arena (the tests).
        (incf (arena-bytes-used charge-to) want)
        (incf (arena-reserved arena) want)
        (unless (eq charge-to arena) (incf (arena-bytes-used arena) want))
        (push pool (arena-pools arena))
        (values pool nil)))))

(defun* carve-buffer (arena bytes)
    (function (arena (integer 1)) (values t (or null keyword)))
  "One dedicated BYTES-octet buffer carved from ARENA — for a LONG-LIVED scratch buffer that belongs to one
   owner for its whole life (a node's TX message buffer, a receiver thread's datagram buffer) rather than
   being borrowed per operation from a pool.

   ADR 0095 slice 3: these were THE BYPASS. They came from bare dds.pal:alloc-static, so the ~192 KiB of
   receive/TX scratch per node sat OUTSIDE the *static-arena-bytes* budget, and FR-PF-7's \"all hot-path
   memory comes from the static arena\" was false for the single largest consumer — the process could not
   answer what it had reserved, and a budget that does not see the biggest allocation bounds nothing.

   IMPLEMENTED AS A CAPACITY-1 BUFFER-POOL, deliberately: the pool already carries the budget charge, the
   RESERVED accounting and the teardown-arena return, so a dedicated buffer needs no second mechanism and
   cannot drift from the pool path as either evolves.

   Returns (values buffer NIL), or (values NIL :ARENA-EXHAUSTED) — a STATUS, never a condition (ADR 0064).
   Every caller keeps its unpooled fallback, so a tight budget degrades rather than failing to start."
  (multiple-value-bind (pool status) (make-buffer-pool arena bytes 1)
    (if pool (values (pool-acquire pool) nil) (values nil status))))

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
