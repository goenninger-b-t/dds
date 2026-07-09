;;;; L5 — WP-ASYNC-FLOW (FR-PF-2, flow-control half). The metering primitive a paced async
;;;; sender uses: a bytes/period token bucket with lazy on-acquire refill and an injectable
;;;; clock (a thunk returning ns) for deterministic tests. Hot-path-pure — the scheduler will
;;;; call %fb-acquire/%fb-refill per datagram, so they are 0-alloc, CLOS-free, overflow-safe
;;;; integer arithmetic. Flow control is wire-invisible / additive on conforming RTPS (it
;;;; changes only WHEN a datagram is sent, never its bytes) — not patent-gated (ADR 0016).

(in-package #:dds.disc)

(defstruct* (flow-token-bucket (:constructor %make-flow-token-bucket))
  "WP-ASYNC-FLOW token bucket (FR-PF-2): TOKENS bytes available, refilled TOKENS-PER-PERIOD every PERIOD ns,
   capped at MAX-BURST; CLOCK-FN returns current ns (injectable for deterministic tests). Hot-path-pure."
  (tokens-per-period 0 :type (integer 1)) (period 1 :type (integer 1)) (max-burst 1 :type (integer 1))
  (tokens 0 :type (integer 0)) (last-refill 0 :type (integer 0)) (clock-fn nil :type function))

(defun* make-flow-token-bucket (&key tokens-per-period period max-burst (clock-fn #'dds.pal:monotonic-ns))
    (function (&key (:tokens-per-period (integer 1)) (:period (integer 1))
                    (:max-burst (integer 1)) (:clock-fn function))
              flow-token-bucket)
  "Construct a token bucket pacing TOKENS-PER-PERIOD bytes every PERIOD ns, capacity MAX-BURST bytes, clocked
   by CLOCK-FN (a thunk returning current ns; defaults to DDS.PAL:MONOTONIC-NS). Each of TOKENS-PER-PERIOD,
   PERIOD, MAX-BURST MUST be >= 1 (signals SIMPLE-ERROR otherwise). Starts full (TOKENS = MAX-BURST) with
   LAST-REFILL = (FUNCALL CLOCK-FN). Flow control is wire-invisible / additive on conforming RTPS (ADR 0016)."
  (unless (and (integerp tokens-per-period) (>= tokens-per-period 1))
    (error "make-flow-token-bucket: :tokens-per-period must be a positive integer, got ~S." tokens-per-period))
  (unless (and (integerp period) (>= period 1))
    (error "make-flow-token-bucket: :period must be a positive integer (ns), got ~S." period))
  (unless (and (integerp max-burst) (>= max-burst 1))
    (error "make-flow-token-bucket: :max-burst must be a positive integer (bytes), got ~S." max-burst))
  (%make-flow-token-bucket :tokens-per-period tokens-per-period :period period :max-burst max-burst
                           :tokens max-burst :last-refill (funcall clock-fn) :clock-fn clock-fn))

(defun* %fb-refill (b)
    (function (flow-token-bucket) (integer 0))
  "Lazily refill bucket B for the time elapsed since LAST-REFILL and return the resulting TOKENS. Adds
   floor(elapsed * TOKENS-PER-PERIOD / PERIOD) tokens (multiply-before-divide for integer precision), capped
   at MAX-BURST. When tokens are added, LAST-REFILL advances by exactly the time those tokens represent
   (floor(added * PERIOD / TOKENS-PER-PERIOD)), NOT to NOW; when none are added it is left untouched — so the
   sub-quantum elapsed remainder accumulates across calls rather than being dropped (advancing to NOW would
   systematically under-deliver at low rates). Hot path: 0-alloc, CLOS-free, overflow-safe (CL integers never
   wrap; a long-idle product transiently widens to a bignum then is clamped by MAX-BURST)."
  (let* ((now (funcall (flow-token-bucket-clock-fn b)))
         (elapsed (max 0 (- now (flow-token-bucket-last-refill b))))
         (added (floor (* elapsed (flow-token-bucket-tokens-per-period b))
                       (flow-token-bucket-period b))))
    (declare (type (integer 0) elapsed added))
    (when (plusp added)
      (setf (flow-token-bucket-tokens b)
            (min (flow-token-bucket-max-burst b) (+ (flow-token-bucket-tokens b) added))
            (flow-token-bucket-last-refill b)
            (+ (flow-token-bucket-last-refill b)
               (floor (* added (flow-token-bucket-period b))
                      (flow-token-bucket-tokens-per-period b)))))
    (flow-token-bucket-tokens b)))

(defun* %fb-acquire (b cost)
    (function (flow-token-bucket (integer 0)) (integer 0))
  "Try to acquire COST bytes from bucket B (refilling first). If enough tokens, consume them and return 0
   (proceed). Otherwise consume NOTHING and return a strictly positive deficit-wait in ns —
   max(1, ceil((min(COST, MAX-BURST) - tokens) * PERIOD / TOKENS-PER-PERIOD)) — the time the scheduler should
   sleep before retrying. Clamping the need to MAX-BURST lets a datagram larger than the bucket through after a
   full-bucket wait (never a deadlock); the max-1 floor guarantees forward progress without a busy-spin. An
   over-MAX-BURST datagram drains the bucket on a FULL bucket (it pays at most MAX-BURST tokens, clamped to a
   floor of 0 — there is no debt accounting in v1) and proceeds, so configure MAX-BURST >= the largest datagram.
   Hot path: 0-alloc, CLOS-free, overflow-safe integer arithmetic."
  (%fb-refill b)
  (let ((tokens (flow-token-bucket-tokens b)))
    (declare (type (integer 0) tokens))
    (cond ((or (>= tokens cost)
               (and (> cost (flow-token-bucket-max-burst b)) (>= tokens (flow-token-bucket-max-burst b))))
           (setf (flow-token-bucket-tokens b) (max 0 (- tokens cost)))
           0)
          (t (let ((need (min cost (flow-token-bucket-max-burst b))))
               (declare (type (integer 0) need))
               (max 1 (ceiling (* (- need tokens) (flow-token-bucket-period b))
                               (flow-token-bucket-tokens-per-period b))))))))

;;;; ---- WP-ASYNC-FLOW Phase C: the shared flow-controller + its scheduler thread (FR-PF-2, ADR 0016) ----
;;;; A standalone, shareable object that paces the user-data byte rate of its associated writers via the
;;;; token bucket above. Its OWN scheduler thread round-robins one datagram per associated writer per turn,
;;;; acquiring tokens for each datagram's exact length before sending — so multiple writers' datagrams
;;;; interleave at the shaped aggregate rate. Flow control is wire-invisible / additive on conforming RTPS:
;;;; it changes only WHEN a datagram is sent, never its bytes — not patent-gated (ADR 0016). NOT a hot path
;;;; (the per-sample CDR hot path is untouched; only the once-per-datagram token math, %fb-acquire above, is
;;;; hot, and it stays 0-alloc + CLOS-free).

(defstruct* (flow-controller (:constructor %make-flow-controller))
  "WP-ASYNC-FLOW shared flow-controller (FR-PF-2, ADR 0016): paces the aggregate user-data byte rate of its
   associated WRITERS (per-writer flow-writer-states — one per local DataWriter, WP-N-ENDPOINT-S1B) via BUCKET,
   a SCHEDULER thread round-robining one datagram per writer per turn. POLICY-FN is the PLUGGABLE next-writer selector (default %FLOW-POLICY-ROUND-ROBIN; EDF/priority
   follow-ups replace it without touching the loop). LOCK guards {BUCKET token math, WRITERS, RR-CURSOR,
   each node's FLOW-PENDING flag, STOP, CURRENT-EMIT-NODE} and is NEVER held across a build/send/deficit-sleep
   (see %FLOW-SCHEDULER-LOOP). CV wakes the scheduler on a publish signal or STOP. CURRENT-EMIT-NODE +
   EMIT-DONE-CV are the PER-NODE EMIT BARRIER (FR-PF-2, ADR 0016 §Teardown): the scheduler sets
   CURRENT-EMIT-NODE under LOCK before the lock-free emit and clears+signals it after, so
   FLOW-CONTROLLER-UNREGISTER can block until the scheduler is provably not mid-emit on a node before its
   resources are freed (the controller is SHARED across nodes, so a per-node barrier — not a whole-scheduler
   join — is what stop-node needs). SCRATCH is the controller's
   OWN octet send-buffer (the scheduler thread owns it, like the WP-ASYNC sender's async-tx-msg — no buffer
   shared across threads). Off by default; opt-in (make-flow-controller / flow-controller-associate)."
  (bucket nil :type flow-token-bucket)
  (writers '() :type list)           ; registered per-writer flow-writer-states — the SELECTION ENTRIES (WP-N-ENDPOINT-S1B; one per associated local user writer, guarded by LOCK)
  (rr-cursor 0 :type (integer 0))    ; round-robin index into WRITERS (guarded by LOCK)
  (policy-fn nil :type function)     ; pluggable next-writer selector (default round-robin)
  (scheduling :round-robin :type symbol) ; the policy KIND (:round-robin | :edf | :priority): gates the QoS-key stamping in %flow-signal / the scheduler so the RR/off path is untouched (WP-FLOW-EDF-PRIORITY)
  (lock (dds.pal:make-lock "flow-controller") :type t)
  (cv (dds.pal:make-condvar) :type t)
  (thread nil :type t)
  (stop nil :type t)                 ; shutdown requested (guarded by LOCK)
  (current-emit-node nil :type t)    ; per-node emit barrier: the node the scheduler is mid-emit on, else NIL (guarded by LOCK)
  (emit-done-cv (dds.pal:make-condvar) :type t)   ; signalled (under LOCK) when an emit on CURRENT-EMIT-NODE completes — unregister waits on it
  (scratch nil :type (or null dds.core.buffer:octet-buffer))   ; scheduler thread's OWN scratch send-buffer
  (emit-errors 0 :type fixnum))   ; WP-SENDER-ERROR-RESILIENCE: count of emit errors the scheduler thread caught + survived (FR-PF-2)

(defun* %flow-writer-pending-p (ws)
    (function (dds.disc::flow-writer-state) t)
  "T iff writer-state WS has work the scheduler can advance: either an in-progress per-datagram plan
   (FLOW-WRITER-STATE-STEP-STATE non-NIL, still draining) OR a fresh PENDING signal awaiting a plan
   snapshot. CALLER HOLDS the controller LOCK (PENDING + the writers list are LOCK-guarded). Pure
   predicate — no send. STEP-STATE is read here under the lock as a plain slot value; only the
   scheduler thread MUTATES it for an associated writer, so this read races nothing that matters
   (WP-N-ENDPOINT-S1B: the pre-S1B per-node predicate, now keyed on the per-writer selection entry)."
  (or (dds.disc::flow-writer-state-pending ws)
      (dds.disc::flow-writer-state-step-state ws)))

(defun* %flow-policy-round-robin (controller)
    (function (flow-controller) t)
  "The v1 PLUGGABLE scheduling policy (ADR 0016): return the next registered writer-state WITH pending work
   strictly after RR-CURSOR, wrapping around, and advance RR-CURSOR past it; NIL when NO registered writer
   has pending work. Pure SELECTION (no send, no token math) — the scheduler emits exactly one datagram for
   the returned writer, so one datagram per writer per turn interleaves multiple writers at the shaped
   aggregate rate. CALLER HOLDS the controller LOCK. The standard-QoS-anchored follow-ups (TRANSPORT_PRIORITY
   -> priority; LATENCY_BUDGET/DEADLINE -> EDF) drop in here without touching %FLOW-SCHEDULER-LOOP."
  (let ((writers (flow-controller-writers controller)))
    (when writers
      (let ((n (length writers)))
        (declare (type (integer 1) n))
        (dotimes (i n)
          (let* ((idx (mod (+ (flow-controller-rr-cursor controller) i) n))
                 (ws (nth idx writers)))
            (when (%flow-writer-pending-p ws)
              (setf (flow-controller-rr-cursor controller) (mod (1+ idx) n))
              (return-from %flow-policy-round-robin ws))))
        nil))))

(defparameter *flow-priority-aging-quantum-ns* 10000000
  "WP-FLOW-EDF-PRIORITY (ADR 0016 deferred scheduling policies): the :PRIORITY scheduler's
   starvation-avoidance aging quantum in NANOSECONDS. Each full quantum a pending writer waits UNSERVED
   raises its EFFECTIVE priority by 1 — effective = base TRANSPORT_PRIORITY + floor((now - last-served)/
   quantum). Bounds low-priority starvation: behind a permanently-saturating writer of base P_high, a writer
   of base P_low waits at most ~(P_high - P_low) quanta (≈ (P_high - P_low)·quantum ns) before its effective
   priority ties then exceeds P_high and it is selected — finite for any finite priority gap. Read via the
   controller's injected clock-fn, so tests advance it deterministically. Default 10 ms.")

(defun* %flow-controller-now (controller)
    (function (flow-controller) integer)
  "Current time in ns from CONTROLLER's injected clock-fn (the token bucket's, reused DRY — the same seam the
   deterministic pacing tests inject). The :edf/:priority policies + %flow-signal read wall time ONLY through
   this so scheduling stays deterministic under a test clock (WP-FLOW-EDF-PRIORITY, ADR 0016)."
  (funcall (flow-token-bucket-clock-fn (flow-controller-bucket controller))))

(defun* %flow-policy-select (controller key-fn)
    (function (flow-controller function) t)
  "Shared min-KEY selector for the QoS-anchored policies (WP-FLOW-EDF-PRIORITY, ADR 0016): among the
   registered writer-states WITH pending work (%flow-writer-pending-p), return the one whose (FUNCALL KEY-FN
   CONTROLLER WS) integer key is SMALLEST, breaking ties by round-robin rank (the candidate nearest AFTER
   RR-CURSOR, wrapping) so equal-key writers rotate and never starve each other, and advance RR-CURSOR past
   the winner exactly as %FLOW-POLICY-ROUND-ROBIN does. NIL when NO registered writer has pending work. Pure
   SELECTION (no send, no token math); CALLER HOLDS the controller LOCK; 0-alloc (KEY-FN is a top-level
   function, never a per-call closure) + CLOS-free. This is the pending/barrier discipline of
   %FLOW-POLICY-ROUND-ROBIN with the selection order factored out (DRY). WP-N-ENDPOINT-S1B: because the entry
   is a WRITER (not a node), this ALREADY-node-global min-key selector orders samples ACROSS the participant's
   writers with NO cross-writer merge — the whole point of S1b."
  (let ((writers (flow-controller-writers controller)))
    (when writers
      (let ((n (length writers))
            (cursor (flow-controller-rr-cursor controller))
            (best nil) (best-key 0) (best-rank 0) (best-idx 0))
        (declare (type (integer 1) n) (type (integer 0) cursor best-rank best-idx)
                 (type integer best-key))
        (dotimes (i n)
          (let ((ws (nth i writers)))
            (when (%flow-writer-pending-p ws)
              (let ((key (funcall key-fn controller ws))
                    (rank (mod (- i cursor) n)))
                (declare (type integer key) (type (integer 0) rank))
                (when (or (null best) (< key best-key)
                          (and (= key best-key) (< rank best-rank)))
                  (setf best ws best-key key best-rank rank best-idx i))))))
        (when best
          (setf (flow-controller-rr-cursor controller) (mod (1+ best-idx) n))
          best)))))

(defun* %flow-edf-key (controller ws)
    (function (flow-controller dds.disc::flow-writer-state) integer)
  "EARLIEST-DEADLINE-FIRST key for writer-state WS (WP-FLOW-EDF-PRIORITY, ADR 0016): the per-sample DEADLINE =
   head-of-unsent write-time + LATENCY_BUDGET (HEAD-NS + LATENCY-BUDGET-NS, both cached under the controller
   lock). Keyed on LATENCY_BUDGET, NOT QoS DEADLINE (which here is the periodicity/liveliness contract driving
   OFFERED/REQUESTED_DEADLINE_MISSED — a different meaning). A budget-0 writer (the DDS default) has deadline =
   write-time, so it sorts EARLIEST (most urgent) — the spec-faithful reading. Smaller key = earlier deadline =
   selected first. WP-N-ENDPOINT-S1B: keyed per WRITER, so EDF orders across the participant's writers."
  (declare (ignore controller))
  (+ (dds.disc::flow-writer-state-head-ns ws) (dds.disc::flow-writer-state-latency-budget-ns ws)))

(defun* %flow-priority-key (controller ws)
    (function (flow-controller dds.disc::flow-writer-state) integer)
  "HIGHEST-TRANSPORT_PRIORITY-FIRST key for writer-state WS WITH starvation-avoidance aging (WP-FLOW-EDF-PRIORITY,
   ADR 0016): effective priority = base TRANSPORT_PRIORITY + floor((now - LAST-SERVED-NS)/
   *FLOW-PRIORITY-AGING-QUANTUM-NS*), where NOW is the controller clock. Returned NEGATED so the shared
   min-key selector picks the HIGHEST effective priority. Aging lets a starved low-priority writer's effective
   priority climb until it overtakes a saturating high-priority writer (whose LAST-SERVED-NS keeps
   refreshing at each selection, holding its aging near 0), bounding starvation. WP-N-ENDPOINT-S1B: keyed per
   WRITER, so priority orders across the participant's writers."
  (let* ((now (%flow-controller-now controller))
         (waited (max 0 (- now (dds.disc::flow-writer-state-last-served-ns ws))))
         (aging (floor waited *flow-priority-aging-quantum-ns*)))
    (declare (type integer now waited aging))
    (- (+ (dds.disc::flow-writer-state-transport-priority ws) aging))))

(defun* %flow-head-advance (controller ws)
    (function (flow-controller dds.disc::flow-writer-state) t)
  "Re-stamp writer-state WS's EDF head write-time (HEAD-NS) to now — called when WS's per-datagram plan
   RE-SNAPSHOTS (its head-of-line batch has drained and a fresh unsent set is captured). Under SUSTAINED
   per-writer backlog (new samples arrive before the plan drains) the writer NEVER goes idle, so the
   idle->pending stamp in %FLOW-SIGNAL never re-fires; without this re-stamp the frozen HEAD-NS would grow
   progressively more urgent vs the wall clock and the backlogged writer would MONOPOLIZE selection against
   newer-but-tighter-budget writers. Re-stamping at each re-snapshot makes the :edf key track the writer's
   CURRENT head batch (now, the lock-safe proxy for the head sample's enqueue time — the HistoryCache cannot be
   read under the controller lock), so a served writer's urgency resets each drain while an UNSERVED writer's
   HEAD-NS correctly stays put and ages toward selection (natural EDF anti-starvation). CALLER HOLDS the
   controller LOCK. Only meaningful for :edf (the scheduler gates the call on it)."
  (setf (dds.disc::flow-writer-state-head-ns ws) (%flow-controller-now controller))
  t)

(defun* %flow-policy-edf (controller)
    (function (flow-controller) t)
  "The :EDF pluggable policy (WP-FLOW-EDF-PRIORITY, ADR 0016): select the pending writer whose head-unsent
   sample has the MIN deadline (write-time + LATENCY_BUDGET, %FLOW-EDF-KEY), RR-tiebroken among equal
   deadlines. Pure SELECTION under the controller LOCK; drops into make-flow-controller's ecase without
   touching %FLOW-SCHEDULER-LOOP."
  (%flow-policy-select controller #'%flow-edf-key))

(defun* %flow-policy-priority (controller)
    (function (flow-controller) t)
  "The :PRIORITY pluggable policy (WP-FLOW-EDF-PRIORITY, ADR 0016): select the pending writer with the
   HIGHEST effective priority (base TRANSPORT_PRIORITY + aging, %FLOW-PRIORITY-KEY), RR-tiebroken, then stamp
   the winner's FLOW-LAST-SERVED-NS = now so its aging resets (a saturating high-priority writer thus stays
   near 0 aging while a starved writer's climbs until it wins — bounded starvation). Pure SELECTION under the
   controller LOCK; drops into make-flow-controller's ecase without touching %FLOW-SCHEDULER-LOOP."
  (let ((ws (%flow-policy-select controller #'%flow-priority-key)))
    (when ws
      (setf (dds.disc::flow-writer-state-last-served-ns ws) (%flow-controller-now controller)))
    ws))

(defun* %flow-acquire-hook (controller)
    (function (flow-controller) function)
  "Return the BEFORE-SEND closure %EMIT-PLAN-ENTRY calls with the just-built datagram's LENGTH, AFTER the
   build but BEFORE the send (the build-then-send seam, ADR 0016): it acquires LENGTH tokens from BUCKET,
   sleeping the deficit, so the controller paces the byte rate. The datagram is already built in SCRATCH and
   is HELD there unchanged across the deficit sleep — never rebuilt (B1 / reliable-completeness). LOCK
   discipline: the controller LOCK is held ONLY for the %FB-ACQUIRE token math and the STOP re-check; the
   deficit wait is a condvar-wait that RELEASES the lock while sleeping (woken early by a new publish signal
   or STOP), and the lock is released before %EMIT-PLAN-ENTRY proceeds to the SEND. On STOP mid-deficit the
   hook returns WITHOUT a wait so the built datagram is sent through immediately (teardown flush) — no
   datagram is dropped."
  (lambda (len)
    (declare (type (integer 0) len))
    (dds.pal:with-lock ((flow-controller-lock controller))
      (loop
        (let ((wait-ns (%fb-acquire (flow-controller-bucket controller) len)))
          (declare (type (integer 0) wait-ns))
          (when (zerop wait-ns) (return))                       ; tokens acquired: %emit-plan-entry sends now
          (when (flow-controller-stop controller) (return))     ; teardown: send through (no wait), loop exits after
          (dds.pal:condvar-wait (flow-controller-cv controller) ; sleep the deficit (LOCK released during wait)
                                (flow-controller-lock controller)
                                (/ wait-ns 1000000000.0d0)))))))

(defun* %flow-flush-all (controller)
    (function (flow-controller) t)
  "Teardown drain (called from %FLOW-SCHEDULER-LOOP on STOP, with the controller LOCK RELEASED and no other
   thread touching the scratch buffer): for EACH registered writer, drain its remaining cached plan + any
   newly-unsent changes to completion via %FLOW-STEP-EMIT, IGNORING the bucket — shutdown must never wait on
   a slow paced drain (ADR 0016), and a partial in-progress plan must NOT be dropped (its unsent watermark is
   already advanced — B1). %FLOW-STEP-EMIT snapshots-if-NIL/steps/clears, so looping it to MORE-REMAIN-P NIL
   flushes both the held plan and a fresh snapshot of any still-unsent data. Uses the controller's own
   SCRATCH (the scheduler thread is the only user and it is exiting). WP-N-ENDPOINT-S1B: drains EVERY registered
   per-writer state (each its OWN plan + refs), so no writer's tail is dropped and no writer's send-refs leak."
  (dolist (ws (flow-controller-writers controller))
    (when (dds.disc::flow-writer-state-writer ws)
      (loop with more = t
            while more
            do (multiple-value-bind (bytes more-remain)
                   (dds.disc::%flow-step-emit ws (flow-controller-scratch controller))
                 (declare (ignore bytes))
                 (setf more (and more-remain t))))))
  t)

(defun* %flow-scheduler-loop (controller)
    (function (flow-controller) t)
  "WP-ASYNC-FLOW scheduler thread (FR-PF-2, ADR 0016): the single thread that paces one datagram per
   associated writer per round-robin turn. Each iteration: (1) under the controller LOCK, condvar-wait
   (bounded) until some registered writer has pending work or STOP, then RR-PICK one pending writer
   (POLICY-FN) and, if it needs a fresh plan, consume its FLOW-PENDING signal; (2) with the LOCK RELEASED,
   build the writer's next single datagram into SCRATCH (%NODE-DATAGRAM-PLAN snapshots the unsent set ONCE
   on the first datagram of a plan — the B1 contract: build the plan once, step to completion, re-snapshot
   only after it drains), acquire tokens for that datagram's exact length (sleeping the deficit), then send
   the already-built datagram and advance the plan cursor (%EMIT-PLAN-ENTRY with the token-acquire BEFORE-SEND
   hook). The emit is wrapped in WITH-SENDER-EMIT-GUARD (:FLOW-SCHEDULER) and the plan cursor is advanced
   UNCONDITIONALLY (Option 1: drop + advance — WP-SENDER-ERROR-RESILIENCE, FR-PF-2): a signalled emit error is
   caught INSIDE the unwind-protect (so the per-node barrier cleanup still disarms and the error never escapes
   the loop), the scheduler counts it (EMIT-ERRORS) + fires *SENDER-EMIT-ERROR-HOOK* and moves on, so the
   scheduler thread never dies from one bad emit and the cursor always progresses (no hot-spin — the unsent
   watermark already advanced at SNAPSHOT time, so a drained faulted plan is never re-snapshotted). A dropped
   reliable DATA stays in the HistoryCache and is recovered via the HEARTBEAT/ACKNACK repair (RTPS 2.5 §8.4).
   On STOP, flush every registered writer's remaining datagrams IGNORING the bucket and return.

   LOCK ORDERING (correctness-critical, BINARY gate). The controller LOCK guards ONLY {condvar-wait,
   RR-pick/cursor, FLOW-PENDING flags, %FB-ACQUIRE token math, the writers list, STOP}. It is NEVER held
   across: the plan BUILD (%NODE-DATAGRAM-PLAN, which takes the writer + node locks internally), the per-
   datagram BUILD (the plan thunk writing SCRATCH), the deficit SLEEP, or the SEND (%SEND-RAW-BUF). The
   deficit wait is a condvar-wait that releases the lock while waiting (and is woken early by a new publish
   signal or STOP). So the controller lock and the writer lock are NEVER held simultaneously — mirroring the
   WP-ASYNC sender's release-async-lock-before-send. The bounded condvar timeout means a missed signal can
   never wedge shutdown. The built datagram is HELD in SCRATCH across the deficit sleep and never rebuilt
   (B1 / ADR 0016 reliable-completeness).

   PER-NODE EMIT BARRIER (UAF-critical, BINARY gate — ADR 0016 §Teardown). The controller is SHARED across
   nodes, so stop-node CANNOT join the scheduler (that would block on the other nodes); it must instead be
   guaranteed the scheduler is not — and never again will be — emitting on the ONE node being torn down. The
   loop sets CURRENT-EMIT-NODE = NODE UNDER THE LOCK in the same critical section that picks it (before the
   lock is released), and an UNWIND-PROTECT clears CURRENT-EMIT-NODE + signals EMIT-DONE-CV under the lock on
   EVERY exit path of the lock-free build/emit (normal, a send error, any non-local exit) — so the barrier
   slot is never left stuck pointing at a node. FLOW-CONTROLLER-UNREGISTER (called by stop-node BEFORE the
   frees) removes the node from WRITERS first (the scheduler can never newly pick it) then waits on
   EMIT-DONE-CV while CURRENT-EMIT-NODE = NODE. Deadlock-free: the emit is LOCK-FREE, so the scheduler never
   needs the controller lock to FINISH the emit unregister is waiting on; unregister's CONDVAR-WAIT releases
   the lock, letting the scheduler re-take it to clear+signal; the emit always completes in bounded time (the
   deficit wait is a finite max(1,...) ns), and unregister's wait is itself bounded + re-checks the predicate
   on each wake, so no logic error can wedge teardown."
  (loop
    (let ((ws nil) (snapshot-needed nil) (stop nil))
      ;; -- PICK phase (controller LOCK held; no build/send/sleep here) --
      (dds.pal:with-lock ((flow-controller-lock controller))
        (loop until (or (flow-controller-stop controller)
                        (some (lambda (w) (%flow-writer-pending-p w))
                              (flow-controller-writers controller)))
              do (dds.pal:condvar-wait (flow-controller-cv controller)
                                       (flow-controller-lock controller) 0.5))
        (setf stop (flow-controller-stop controller))
        (unless stop
          (setf ws (funcall (flow-controller-policy-fn controller) controller))   ; WP-N-ENDPOINT-S1B: selects a WRITER-state
          (when ws
            (setf (flow-controller-current-emit-node controller)   ; arm the per-NODE barrier (node-grained) BEFORE releasing the lock
                  (dds.disc::flow-writer-state-node ws)))
          (when (and ws
                     (null (dds.disc::flow-writer-state-step-state ws))
                     (dds.disc::flow-writer-state-pending ws))
            (setf snapshot-needed t                                 ; consume the signal: the build below snapshots
                  (dds.disc::flow-writer-state-pending ws) nil)
            (when (eq (flow-controller-scheduling controller) :edf)   ; re-stamp the EDF head at plan re-snapshot so a backlogged writer's key tracks its CURRENT head (WP-FLOW-EDF-PRIORITY Finding-1)
              (%flow-head-advance controller ws)))))
      (when stop
        (%flow-flush-all controller)   ; LOCK released: drain every writer ignoring the bucket, then exit
        (return))
      (when ws
        (unwind-protect   ; barrier: clear CURRENT-EMIT-NODE + signal on EVERY exit path (incl. send error / non-local) so unregister never wedges
            ;; -- BUILD + paced EMIT of ONE datagram for THIS writer (controller LOCK RELEASED, *emit-writer* bound) --
            (let ((*emit-writer* (dds.disc::flow-writer-state-writer ws)))   ; WP-N-ENDPOINT-S1B: this writer's own GUID/HC across build+emit
              (when (or snapshot-needed (null (dds.disc::flow-writer-state-step-state ws)))
                (multiple-value-bind (plan refs)
                    (dds.disc::%node-datagram-plan (dds.disc::flow-writer-state-node ws)
                                                   (dds.disc::flow-writer-state-writer ws)
                                                   (flow-controller-scratch controller))
                  (setf (dds.disc::flow-writer-state-step-state ws) plan
                        (dds.disc::flow-writer-state-step-refs ws) refs)))
              (let ((plan (dds.disc::flow-writer-state-step-state ws)))
                (when plan   ; NIL plan = nothing actually unsent (raced); writer drops out of pending until re-signalled
                  (with-sender-emit-guard (:flow-scheduler (flow-controller-emit-errors controller))   ; catch INSIDE the unwind-protect: barrier cleanup still disarms, the error never escapes the loop
                    (dds.disc::%emit-plan-entry (dds.disc::flow-writer-state-node ws)
                                                (flow-controller-scratch controller) (car plan)
                                                (%flow-acquire-hook controller)))
                  (dds.disc::%flow-step-advance ws plan))))   ; advance the cursor whether sent or dropped (Option 1: drop + advance; reliability repairs via NACK/HEARTBEAT) + release the snapshot's send-refs on drain (release-safety)
          (dds.pal:with-lock ((flow-controller-lock controller))   ; disarm the barrier: emit on this writer's NODE is done
            (setf (flow-controller-current-emit-node controller) nil)
            (dds.pal:condvar-signal (flow-controller-emit-done-cv controller)))))))
  t)

(defun* %flow-signal (controller ws)
    (function (flow-controller dds.disc::flow-writer-state) t)
  "WP-ASYNC-FLOW publish hook (FR-PF-2, ADR 0016; WP-N-ENDPOINT-S1B per-writer): mark writer-state WS pending and
   wake the scheduler. Under the controller LOCK set WS's PENDING flag (the scheduler snapshots THAT writer's
   unsent set on the next turn) and condvar-signal the controller CV. The caller (publish-sample /
   %dispose-or-unregister, resolving WS via %flow-writer-state-for on the written writer) does NOT send — the send
   is the scheduler thread's, rate-paced. The reliable unsent-list IS the queue; PENDING just says 'there is new
   unsent work to snapshot'. condvar-SIGNAL (not broadcast) is exact: a controller has exactly ONE scheduler
   thread waiting on the CV. For a QoS-anchored policy this also stamps the writer's idle->pending scheduling key
   (WP-FLOW-EDF-PRIORITY): :edf stamps HEAD-NS (the fresh burst's head write-time; a continuous backlog re-stamps
   at each plan re-snapshot via %FLOW-HEAD-ADVANCE, not here), :priority stamps LAST-SERVED-NS (the aging
   baseline). For :round-robin NEITHER slot is touched — the RR/off path is byte-identical (RR reads no
   scheduling key), so the QoS policies are literally additive behind the ecase."
  (dds.pal:with-lock ((flow-controller-lock controller))
    (unless (%flow-writer-pending-p ws)   ; idle->pending: stamp the QoS-policy key (gated so RR is untouched)
      (case (flow-controller-scheduling controller)
        (:edf (setf (dds.disc::flow-writer-state-head-ns ws) (%flow-controller-now controller)))
        (:priority (setf (dds.disc::flow-writer-state-last-served-ns ws) (%flow-controller-now controller)))))
    (setf (dds.disc::flow-writer-state-pending ws) t)
    (dds.pal:condvar-signal (flow-controller-cv controller)))
  t)

(defun* make-flow-controller (&key tokens-per-period period max-burst (scheduling :round-robin)
                                   (clock-fn #'dds.pal:monotonic-ns))
    (function (&key (:tokens-per-period (integer 1)) (:period (integer 1)) (:max-burst (integer 1))
                    (:scheduling symbol) (:clock-fn function))
              flow-controller)
  "Construct + START a WP-ASYNC-FLOW flow-controller (FR-PF-2, ADR 0016): a token bucket pacing
   TOKENS-PER-PERIOD bytes every PERIOD ns (capacity MAX-BURST bytes, clocked by CLOCK-FN), a SCHEDULING
   policy, an empty registered-writer set, the controller's own SCRATCH send-buffer, and its OWN scheduler
   thread (%FLOW-SCHEDULER-LOOP). Each of TOKENS-PER-PERIOD / PERIOD / MAX-BURST MUST be >= 1 (validated as
   make-flow-token-bucket does). SCHEDULING selects the pluggable next-writer policy (any other value SIGNALS):
   :ROUND-ROBIN (default — fair cursor rotation); :EDF (earliest-deadline-first on LATENCY_BUDGET,
   %FLOW-POLICY-EDF); :PRIORITY (highest TRANSPORT_PRIORITY first with starvation-avoidance aging,
   %FLOW-POLICY-PRIORITY) — WP-FLOW-EDF-PRIORITY, ADR 0016. Selection is ORTHOGONAL to the token-bucket pacing
   (the policy picks WHICH writer drains next; the bucket paces WHEN), so all three shape to the same aggregate
   rate. Configure MAX-BURST >= the largest
   datagram so a single datagram costs at most one full-bucket wait. Associate writers with
   flow-controller-associate; tear down with destroy-flow-controller. Off by default — a node with no
   controller associated is byte-identical to before (the controller only diverts publish-sample when the
   flow-controller slot is set)."
  (let* ((policy-fn (ecase scheduling
                      (:round-robin #'%flow-policy-round-robin)     ; fair cursor rotation (v1 default)
                      (:edf #'%flow-policy-edf)                     ; WP-FLOW-EDF-PRIORITY: LATENCY_BUDGET earliest-deadline-first
                      (:priority #'%flow-policy-priority)))         ; WP-FLOW-EDF-PRIORITY: highest TRANSPORT_PRIORITY + aging
         (controller (%make-flow-controller
                      :bucket (make-flow-token-bucket :tokens-per-period tokens-per-period :period period
                                                      :max-burst max-burst :clock-fn clock-fn)
                      :policy-fn policy-fn :scheduling scheduling
                      :scratch (dds.core.buffer:make-octet-buffer 2048))))
    (setf (flow-controller-thread controller)
          (dds.pal:spawn (lambda () (%flow-scheduler-loop controller)) :name "dds-flow-scheduler"))
    controller))

(defun* %flow-unblock-writer (node)
    (function (dds.disc::disc-node) t)
  "Wake any writer-write blocked on NODE's bounded HistoryCache (WP-ASYNC-FLOW backpressure, ADR 0016
   §Backpressure / §Teardown) by broadcasting the writer's SPACE-CV. Called when NODE leaves a controller
   (flow-controller-unregister) or the controller is destroyed (destroy-flow-controller): the controller is
   no longer associated, so a subsequently-blocked publish (a writer with no controller) is now bounded only
   by its own max_blocking_time deadline. The wake lets a CURRENTLY-blocked publish re-evaluate immediately;
   if the cache is still full (the ACKNACK purge is the only thing that frees a KEEP_ALL cache, and teardown
   does not purge) it re-blocks and reaches its block-up-to-max_blocking_time TIMEOUT at its deadline.
   A no-op when NODE has no user writer or no writer is blocked. NOT a hot path (teardown only); CLOS-free
   (flow-control.lisp is gate-hotpath-listed). WP-N-ENDPOINT-S1B: wakes EVERY local user writer of NODE."
  (dolist (w (dds.disc::%all-user-writers node))
    (dds.rtps.reliable:%writer-signal-space w))
  t)

(defun* %flow-unblock-writer-state (ws)
    (function (dds.disc::flow-writer-state) t)
  "Wake any writer-write blocked on WS's writer's bounded HistoryCache (WP-N-ENDPOINT-S1B teardown): the
   per-writer variant of %FLOW-UNBLOCK-WRITER used when the controller holds writer-STATE entries. A no-op when
   WS has no writer. NOT a hot path (teardown only)."
  (let ((w (dds.disc::flow-writer-state-writer ws)))
    (when w (dds.rtps.reliable:%writer-signal-space w)))
  t)

(defun* %flow-cache-writer-qos (node writer ws)
    (function (dds.disc::disc-node dds.rtps.reliable:rtps-writer dds.disc::flow-writer-state) t)
  "Cache WRITER's LATENCY_BUDGET (as ns) + TRANSPORT_PRIORITY onto its per-writer flow-state WS for the :edf /
   :priority policies (WP-FLOW-EDF-PRIORITY, ADR 0016; WP-N-ENDPOINT-S1B per-writer) — read ONCE here (at
   associate / register-under-controller) from THIS writer's OWN advertised endpoint QoS (matched by EntityId in
   disc-node-local-writers) so the per-datagram policy never re-reads QoS on the hot path and each writer is
   scheduled by its OWN budget/priority. Only the writer-LOCAL values matter for sender-side scheduling (no SEDP
   propagation). A writer with no advertised endpoint keeps the defaults (budget 0 / priority 0). Caller HOLDS
   the controller LOCK."
  (let* ((weid (dds.rtps.reliable:rtps-writer-entityid writer))
         (ep (find weid (dds.disc::disc-node-local-writers node)
                   :key (lambda (e) (dds.disc::%guid-entityid (dds.rtps.discovery:endpoint-data-guid e)))
                   :test #'eql)))
    (when ep
      (let ((q (dds.rtps.discovery:endpoint-data-qos ep)))
        (let ((b (dds.qos:qos-latency-budget q)))
          (setf (dds.disc::flow-writer-state-latency-budget-ns ws)
                (+ (* (dds.qos:qos-duration-sec b) 1000000000) (dds.qos:qos-duration-nanosec b))
                (dds.disc::flow-writer-state-transport-priority ws) (dds.qos:qos-transport-priority q))))))
  t)

(defun* %flow-add-writer-locked (controller node writer)
    (function (flow-controller dds.disc::disc-node dds.rtps.reliable:rtps-writer) dds.disc::flow-writer-state)
  "Register one local user WRITER of NODE with CONTROLLER as a per-writer flow-state (WP-N-ENDPOINT-S1B); the
   locked body of FLOW-CONTROLLER-ADD-WRITER. CALLER HOLDS the controller LOCK. Idempotent per EntityId: a
   re-register REPLACES the writer ref + refreshes the cached QoS, keeping the existing cursor/keys (so a mid-
   drain re-enable never resets an in-flight plan). A NEW EntityId conses a fresh flow-writer-state, caches its
   QoS, and pushes it onto both NODE's flow-writer-states registry AND the controller's WRITERS selection set.
   Returns the flow-writer-state."
  (let* ((weid (dds.rtps.reliable:rtps-writer-entityid writer))
         (cell (assoc weid (dds.disc::disc-node-flow-writer-states node) :test #'eql)))
    (if cell
        (let ((ws (cdr cell)))
          (setf (dds.disc::flow-writer-state-writer ws) writer)
          (%flow-cache-writer-qos node writer ws)
          ws)
        (let ((ws (dds.disc::%make-flow-writer-state :node node :writer writer)))
          (%flow-cache-writer-qos node writer ws)
          (push (cons weid ws) (dds.disc::disc-node-flow-writer-states node))
          (push ws (flow-controller-writers controller))
          ws))))

(defun* flow-controller-add-writer (controller node writer)
    (function (flow-controller dds.disc::disc-node dds.rtps.reliable:rtps-writer) dds.disc::flow-writer-state)
  "Register one local user WRITER of NODE with CONTROLLER as a per-writer flow-state (WP-N-ENDPOINT-S1B), taking
   the controller LOCK. Called by FLOW-CONTROLLER-ASSOCIATE for each existing writer and by %REGISTER-USER-WRITER
   for a writer created UNDER an already-associated controller (the lifted S1 second-writer fail-fast). Returns
   the flow-writer-state."
  (dds.pal:with-lock ((flow-controller-lock controller))
    (%flow-add-writer-locked controller node writer)))

(defun* flow-controller-associate (controller node)
    (function (flow-controller dds.disc::disc-node) t)
  "Associate writer-participant NODE with CONTROLLER (FR-PF-2, ADR 0016; WP-N-ENDPOINT-S1B multi-writer), making
   its publication async-and-paced (the controller's scheduler thread sends, rate-shaped at the shared aggregate).
   Under the controller LOCK: SIGNALS if NODE is already bound to a controller (one controller per participant);
   otherwise sets NODE's FLOW-CONTROLLER slot and registers a per-writer flow-state for EACH local user writer
   (%FLOW-ADD-WRITER-LOCKED — caching each writer's OWN LATENCY_BUDGET/TRANSPORT_PRIORITY for the :edf/:priority
   policies; a no-op key-wise for :round-robin, which ignores those slots). Each registered writer becomes a
   distinct SELECTION ENTRY, so the token bucket paces + the policy orders across ALL the participant's writers.
   Writers created LATER under this controller are registered incrementally by %REGISTER-USER-WRITER. After this,
   publish / dispose / unregister on NODE return immediately after signalling the controller (the per-node async
   sender + batch are superseded). Returns the controller."
  (dds.pal:with-lock ((flow-controller-lock controller))
    (when (dds.disc::disc-node-flow-controller node)
      (error "flow-controller-associate: ~S is already associated with a flow-controller (one per participant)." node))
    (setf (dds.disc::disc-node-flow-controller node) controller)
    (dolist (w (dds.disc::%all-user-writers node))
      (%flow-add-writer-locked controller node w)))
  controller)

(defun* flow-controller-unregister (controller node)
    (function (flow-controller dds.disc::disc-node) t)
  "Remove writer NODE from CONTROLLER and BLOCK until the scheduler is provably not (and never again will be)
   emitting on NODE — the PER-NODE EMIT BARRIER (FR-PF-2, ADR 0016 §Teardown). Under the controller LOCK,
   FIRST drop NODE from WRITERS + clear its FLOW-CONTROLLER + FLOW-PENDING (so the round-robin policy can
   never NEWLY pick it — RR-CURSOR is left as-is: %FLOW-POLICY-ROUND-ROBIN always indexes WRITERS mod its
   length, so a stale cursor is in-range, and not resetting it preserves rotation fairness under churn). THEN
   wait — (LOOP WHILE (EQ (FLOW-CONTROLLER-CURRENT-EMIT-NODE CONTROLLER) NODE) DO bounded CONDVAR-WAIT on
   EMIT-DONE-CV) — until any IN-FLIGHT scheduler emit on NODE finishes (the scheduler clears CURRENT-EMIT-NODE
   + signals EMIT-DONE-CV under this same LOCK on every emit exit path). Returns ONLY when CURRENT-EMIT-NODE
   /= NODE, i.e. the scheduler holds no live reference to NODE's socket / SHMEM ring / tx buffers — so a
   caller (stop-node, called BEFORE the udp-close/shmem-close/free-static, or a direct unregister) may then
   free NODE's resources with NO use-after-free. If NODE was never mid-emit the loop sees /= immediately and
   returns at once. Deadlock-free: the scheduler's emit is LOCK-FREE (it never needs this LOCK to FINISH the
   emit being waited on), the CONDVAR-WAIT releases the LOCK so the scheduler can re-take it to clear+signal,
   and the wait is bounded + re-checked so a logic error cannot wedge teardown forever. The controller is
   SHARED, so this per-node barrier — not a whole-scheduler join — is what makes stop-node safe; the
   controller keeps serving its other writers. After the barrier (under the same lock) it RELEASES each of NODE's
   per-writer MID-DRAIN send-refs (%FLOW-RELEASE-STEP-REFS per writer-state) so a SHARED controller that keeps
   running never leaks NODE's captured CacheChanges until stop-node — the per-writer analogue of the
   destroy-path %FLOW-FLUSH-ALL release, but WITHOUT emitting (unregister must not send on a node about to be
   freed). A no-op (returns at once) if NODE is not registered here. Idempotent (NIL refs release nothing)."
  (dds.pal:with-lock ((flow-controller-lock controller))
    (setf (flow-controller-writers controller)   ; WP-N-ENDPOINT-S1B: drop ALL of NODE's per-writer selection entries
          (remove-if (lambda (ws) (eq (dds.disc::flow-writer-state-node ws) node))
                     (flow-controller-writers controller)))
    (dolist (cell (dds.disc::disc-node-flow-writer-states node))   ; clear each writer's pending so RR/EDF/priority can never newly pick it
      (setf (dds.disc::flow-writer-state-pending (cdr cell)) nil))
    (when (eq (dds.disc::disc-node-flow-controller node) controller)
      (setf (dds.disc::disc-node-flow-controller node) nil))
    (loop while (eq (flow-controller-current-emit-node controller) node)   ; block on any in-flight emit on NODE
          do (dds.pal:condvar-wait (flow-controller-emit-done-cv controller)
                                   (flow-controller-lock controller) 0.5))   ; bounded: re-check on wake, teardown can't wedge
    ;; WP-N-ENDPOINT-S1B (adversarial-review FIX-1): release each unregistered writer's MID-DRAIN send-refs so a
    ;; SHARED controller that keeps running (other nodes still associated, destroy NOT called) never leaks this
    ;; node's captured CacheChanges (they pin a pooled payload) until stop-node. Runs AFTER the barrier (the
    ;; scheduler is provably not — and never again will be — mid-emit on NODE, since NODE is already removed from
    ;; WRITERS, so the single-mutator discipline of step-state/step-refs holds and this release races nothing).
    ;; Idempotent: a writer with no in-progress plan has NIL refs -> %flow-release-step-refs is a no-op. Mirrors the
    ;; "teardown releases all" invariant %flow-flush-all provides on the destroy path, but WITHOUT emitting —
    ;; unregister must not send on a node whose socket/buffers the caller (stop-node) is about to free.
    (dolist (cell (dds.disc::disc-node-flow-writer-states node))
      (dds.disc::%flow-release-step-refs (cdr cell))))
  (%flow-unblock-writer node)   ; wake any publish blocked on a full bounded cache (ADR 0016 §Backpressure / §Teardown): paced drain stops, so it must reach its TIMEOUT
  t)

(defun* flow-controller-remove-writer (controller node writer)
    (function (flow-controller dds.disc::disc-node dds.rtps.reliable:rtps-writer) t)
  "Remove ONE local user WRITER of NODE from CONTROLLER — the PER-WRITER analogue of
   flow-controller-unregister (WP-DCPS-API-COMPLETION S2.T4 delete_datawriter; ADR 0016 §Teardown / ADR 0052).
   Under the controller LOCK: drop WRITER's selection entry from WRITERS and its flow-writer-state from NODE's
   registry (so the scheduler can never NEWLY pick it), clear its pending, then BLOCK on the per-NODE emit
   barrier (LOOP WHILE current-emit-node = NODE, bounded CONDVAR-WAIT on EMIT-DONE-CV) until any in-flight
   scheduler emit on NODE finishes — so no scheduler send references WRITER after this returns (delete is
   SYNCHRONOUS for the deleted writer). Finally release WRITER's mid-drain step-refs (no leaked pinned
   CacheChange). NODE keeps its flow-controller association and its OTHER writers untouched — unlike
   flow-controller-unregister, which detaches the whole node. A no-op if WRITER is not registered (idempotent)."
  (let ((weid (dds.rtps.reliable:rtps-writer-entityid writer)))
    (dds.pal:with-lock ((flow-controller-lock controller))
      (let ((cell (assoc weid (dds.disc::disc-node-flow-writer-states node) :test #'eql)))
        (when cell
          (let ((ws (cdr cell)))
            (setf (flow-controller-writers controller) (remove ws (flow-controller-writers controller))
                  (dds.disc::disc-node-flow-writer-states node)
                  (remove cell (dds.disc::disc-node-flow-writer-states node))
                  (dds.disc::flow-writer-state-pending ws) nil)
            (loop while (eq (flow-controller-current-emit-node controller) node)   ; block on any in-flight emit on NODE
                  do (dds.pal:condvar-wait (flow-controller-emit-done-cv controller)
                                           (flow-controller-lock controller) 0.5))
            (dds.disc::%flow-release-step-refs ws))))))
  t)

(defun* destroy-flow-controller (controller)
    (function (flow-controller) t)
  "Tear down CONTROLLER (FR-PF-2, ADR 0016): under the LOCK set STOP + condvar-signal the scheduler, JOIN
   the scheduler thread (which flushes every registered writer's remaining datagrams IGNORING the bucket on
   the way out — shutdown never waits on a slow paced drain, and no partial plan is dropped: B1), then free
   the SCRATCH buffer. Idempotent (a no-op once the thread is already joined). Unblocks any writer blocked in
   writer-write on a full bounded cache with TIMEOUT (ADR 0016 §Backpressure / §Teardown): the paced drain is
   gone, so each registered writer's SPACE-CV is broadcast so a blocked publish re-evaluates and reaches its
   block-up-to-max_blocking_time TIMEOUT promptly (the writers snapshot is taken under the LOCK BEFORE the
   join — the scheduler will not newly pick them after STOP)."
  (when (flow-controller-thread controller)
    (let ((writers (dds.pal:with-lock ((flow-controller-lock controller))
                     (setf (flow-controller-stop controller) t)
                     (dds.pal:condvar-signal (flow-controller-cv controller))
                     (copy-list (flow-controller-writers controller)))))
      (dds.pal:join (flow-controller-thread controller))
      (setf (flow-controller-thread controller) nil)
      (dolist (ws writers) (%flow-unblock-writer-state ws))   ; WP-N-ENDPOINT-S1B: wake any publish blocked on a full bounded cache -> TIMEOUT (per-writer entries)
      (when (flow-controller-scratch controller)
        (dds.pal:free-static (dds.core.buffer:octet-buffer-vec (flow-controller-scratch controller)))
        (setf (flow-controller-scratch controller) nil))))
  t)
