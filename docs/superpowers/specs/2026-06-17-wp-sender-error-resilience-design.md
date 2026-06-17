# WP-SENDER-ERROR-RESILIENCE — sender-thread emit guard — design

**Goal (FR-PF-2 hardening; the WP-ASYNC-FLOW deferred Should-fix).** Make the two background sender threads
SURVIVE a transient error raised by a per-iteration emit, instead of dying and silently stalling the writers
they serve. A thread-level guard mirroring the RX receiver thread's existing pattern: catch a per-iteration
`error`, observe it (a bindable hook + a counter), continue. Non-R6; SBCL + Clasp.

## Scope / honest framing
The UDP transport send already swallows per-destination socket errors (`udp.lisp:31`, returns 0; reliability
recovers), so a bare `sendto` is NOT the trigger. What can still SIGNAL out of an emit and kill a sender
thread: a SIGNALED `%shmem-send` error (lane-full/claim-fail already returns 0 → UDP fallback, but a hard
segment/pshared/bounds error signals; SHMEM is auto-on same-host), the datagram BUILD / destination
resolution, static-arena exhaustion, or a future transport. This is thread-level defense-in-depth +
observability — the RX receiver thread already has this guard (`udp.lisp:105` `(error () …)`); the two
sender threads are the asymmetric gap (WP-ASYNC-FLOW flagged it as a Should-fix that fails safe).

## Standard conformance (the Option-1 rationale — owner-confirmed)
DDS 1.4 / DDSI-RTPS 2.5 does NOT specify local send-error handling (implementation-defined, not
wire-observable), so no behaviour is literally mandated. The reliability model (RTPS 2.5 §8.4.1–§8.4.2)
makes DROP-AND-ADVANCE the consistent choice: a dropped DATA leaves the sample in the writer HistoryCache;
the periodic HEARTBEAT advertises `[firstSN,lastSN]`; the reader NACKs the gap; the repair path
(`%on-user-acknack`) resends — so a reliable sample is still delivered, and a best-effort drop is conformant
(loss tolerated). It mirrors the UDP transport's existing conformant drop behaviour and preserves pushMode=true
proactive progress (§8.4.2.2). Retry-the-same (rejected) risks WEDGING a writer (no SN ever advances →
no-progress); clear-pending (rejected) defers proactive push.

## Grounded current state (file:line — verified)
- `src/dds-xport/udp.lisp:105` — the RX receiver thread ALREADY guards: `(handler-case (funcall on-datagram
  buf size) (error () nil))` + the recv in `(error () (return))`. The pattern to mirror on the sender side.
- `src/dds-disc/dataplane.lisp:746` `%async-sender-loop` — `(%push-data-buf node (disc-node-async-tx-msg
  node))` at :760 has NO handler → a signaled emit error unwinds out of the loop → the `dds-async-sender`
  thread dies → that node's async writers stall (publish/dispose keep signalling a dead thread).
- `src/dds-disc/flow-control.lisp:186` `%flow-scheduler-loop` — `%emit-plan-entry` at :252 is inside an
  `unwind-protect` whose cleanup only DISARMS the per-node barrier (:255-257); the condition still propagates
  out of the loop → the single `dds-flow-scheduler` thread dies → EVERY writer on that controller stalls.
- `src/dds-disc/dataplane.lisp:32` `%send-raw-buf` — the shared one-datagram send both threads reach (via
  `%send-msg-buf` / `%send-packed` → `%emit-next-datagram` / `%push-data-buf` / `%emit-plan-entry`). Already
  carries the `*datagram-sink*` test hook (:41) and the SHMEM-returns-0 → UDP-fallback (:44-49). The
  fault-injection point.
- `src/dds-xport/udp.lisp:31` — UDP `:send` swallows `(error () 0)`. `src/dds-xport/shmem.lisp:192` — SHMEM
  `:send` calls `%shmem-send` with NO handler (a signaled hard error propagates).

## Design

### 1. The shared guard (DRY, 0-alloc) — `with-sender-emit-guard`
A macro in `dds.disc` (one definition, used by both loops):
```lisp
(defmacro with-sender-emit-guard ((context count-place) &body body)
  "Run BODY (one sender-thread emit); on a caught ERROR observe it via %NOTE-SENDER-EMIT-ERROR and return
   NIL (BODY's value on success). CONTEXT is a keyword tagging the thread; COUNT-PLACE is the error counter."
  `(handler-case (progn ,@body)
     (error (c) (%note-sender-emit-error ,context ,count-place c) nil)))
```
- Catches `error` ONLY — NOT `serious-condition` (storage-condition / control-stack-exhausted): a fatal VM
  state SHOULD still terminate the thread; masking it would hide an unrecoverable condition.
- Returns BODY's value on success, NIL on a caught error. The flow caller advances its cursor UNCONDITIONALLY
  (whether the value is the emit result or NIL) → the scheduler always progresses → no hot-spin.
- A macro (no per-emit closure) → 0-alloc; the sender threads are off the measured CDR hot path regardless,
  but this keeps them allocation-clean (`make mem` unaffected).

### 2. Observability — `*sender-emit-error-hook*` + counters
- `(defparameter *sender-emit-error-hook* #'%default-sender-emit-error-hook)` — exported; a funcallable
  `(condition context count)`; docstring states the contract AND that it runs ON the sender thread (must not
  block; a signaling hook is itself guarded). Bind it (test / app diagnostic) to observe.
- `%note-sender-emit-error (context count-place condition)` → `(incf <count-place>)` then
  `(ignore-errors (funcall *sender-emit-error-hook* condition context <new-count>))` — the `ignore-errors`
  guarantees a signaling HOOK cannot re-kill the thread.
- `%default-sender-emit-error-hook (condition context count)` — clockless rate-limited `warn` to
  `*error-output*`: warn when `count` is 1 or a power of ten (1,10,100,…) so a persistent failure logs
  O(log n) lines, never a flood. (No logging framework exists; this is the minimal observable default.)
- Counters: a `defstruct*` slot on `disc-node` (`async-emit-errors`, fixnum, 0) for the async loop and on
  `flow-controller` (`emit-errors`, fixnum, 0) for the scheduler. `context` is `:async-sender` /
  `:flow-scheduler`.

### 3. The async path (`dataplane.lisp` `%async-sender-loop`)
```lisp
(when (disc-node-user-writer node)
  (with-sender-emit-guard (:async-sender (disc-node-async-emit-errors node))
    (%push-data-buf node (disc-node-async-tx-msg node))))
```
Already cannot hot-spin (async-pending was cleared at :758 before the send; on a caught error the loop
returns to the bounded condvar-wait). Unsent samples stay in the writer HC → repaired via NACK/HEARTBEAT or
re-pushed on the next signal.

### 4. The flow path (`flow-control.lisp` `%flow-scheduler-loop`)
Catch INSIDE the unwind-protect's protected form (the barrier cleanup at :255-257 still runs; the error does
not escape), and advance the cursor UNCONDITIONALLY:
```lisp
(let ((plan (dds.disc::disc-node-flow-step-state node)))
  (when plan
    (with-sender-emit-guard (:flow-scheduler (flow-controller-emit-errors controller))
      (dds.disc::%emit-plan-entry node (flow-controller-scratch controller) (car plan)
                                  (%flow-acquire-hook controller)))
    (setf (dds.disc::disc-node-flow-step-state node) (cdr plan))))   ; advance whether sent or dropped → Option 1
```
The cursor advances on both success and a caught error → the scheduler always makes progress (Option 1). A
dropped reliable datagram is repaired by the existing NACK/HEARTBEAT path; the sample stays in the HC. The
per-node emit barrier is UNAFFECTED (the guard does not propagate, so the unwind-protect cleanup disarms
normally; a serious-condition still propagates AFTER the cleanup, as today).

**Why advancing only the plan cursor is sufficient for no-spin (correctness-critical).** The writer's unsent
WATERMARK is advanced at SNAPSHOT time (`%node-datagram-plan`), NOT per send — see `%flow-step-emit`'s
contract (`dataplane.lisp:702-704`: "snapshots the whole-node datagram plan … capturing the unsent set ONCE —
the watermark is advanced here, not per step"). So once a plan is snapshotted, those samples are already past
the watermark and the node is no longer pending FOR THEM. Draining the faulted plan's cursor therefore exits
the plan; the next PICK does not find the node pending for the dropped samples and does NOT re-snapshot them →
bounded work, no spin. We deliberately do NOT touch the watermark (it already moved at snapshot); the dropped
samples remain in the HistoryCache and are recovered via the HEARTBEAT/ACKNACK repair, not by re-snapshotting.

### 5. Fault injection (test affordance, inert in production)
- `(define-condition sender-emit-test-fault (error) () …)` — a test-only synthetic error.
- `*debug-emit-fault*` (special, default NIL, exported; mirrors `*debug-drop-sample-numbers*`): NIL = inert;
  a positive integer N = signal the fault on the next N `%send-raw-buf` calls (decrementing to 0/NIL);
  `:persistent` = signal on EVERY call (for the no-spin test). Injected at the TOP of `%send-raw-buf` (after
  `*datagram-sink*`, before the actual send) so BOTH sender threads (and the sync path, under test control)
  exercise the guard. Inert (NIL) → zero production effect, byte-identical wire.

## Test scenarios (oracle = thread survival + delivery + the hook record; both impls except the live legs)
1. **Async survives + continues:** enable-async; bind the hook to a recorder; `*debug-emit-fault*` = 3;
   publish ≥5 samples; assert the sender thread is STILL ALIVE, the hook fired 3× with `:async-sender`, the
   counter = 3, and the post-fault samples were delivered to a loopback reader.
2. **Flow survives + NO hot-spin:** a flow-controller + writer; `*debug-emit-fault*` = `:persistent`; publish
   a bounded set; assert the scheduler thread survives, the cursor ADVANCES (a BOUNDED number of hook-fires ≈
   the number of pending datagrams, NOT unbounded — proving no spin), and on clearing the fault the writer
   resumes.
3. **Reliable repair after a transient drop:** a reliable writer + reader; `*debug-emit-fault*` = 1 (drop one
   DATA); assert the reader STILL receives that sample (via NACK/HEARTBEAT repair) — proves Option 1's
   "reliability recovers".
4. **Regression / inert:** `*debug-emit-fault*` NIL → the guard is inert, normal publish byte-identical (the
   `*datagram-sink*` capture unchanged); `make mem` unaffected.
5. **Hook self-error safety:** bind the hook to one that itself signals; assert the sender thread STILL
   survives (the `ignore-errors` around the hook call).
6. **Cross-DDS interop (the per-feature DoD — RTI Connext + Fast DDS, the agent runs BOTH peers live):**
   publish async (and flow-paced) to a live Connext 7.3.1 + Fast DDS 3.6.1 UDP subscriber; mid-stream set
   `*debug-emit-fault*` = a few; assert (a) our sender thread survives, (b) the foreign peer STILL receives
   ALL reliable samples (the guard continued + reliability repaired the dropped ones). Plus a no-fault
   baseline (byte-identical interop). tshark-validated; captures committed. (The UDP send already swallows
   socket errors, so the fault is injected via `*debug-emit-fault*` to exercise the thread-level guard on a
   real wire-interop path.)

## Out of scope (follow-ups)
- Converting a SIGNALED `%shmem-send` hard error into the return-0 → UDP-fallback path (so a hard SHMEM fault
  delivers via UDP instead of dropping) — a transport-layer hardening for ALL callers (sync + threads); the
  thread-level guard already drops-and-recovers it. Its own small follow-up.
- Retry/backoff (Option 2) and clear-pending (Option 3) — rejected (non-progress / weakened pushMode).
- A general logging framework — only the minimal hook here.

## Conformance citations
- RTPS 2.5 §8.4.1–§8.4.2 (reliable-writer HistoryCache retention + HEARTBEAT/ACKNACK repair); §8.4.2.2
  (pushMode=true proactive push). Local send-error handling is implementation-defined (the standard is
  silent — the rationale above derives Option 1 from the reliability model, not from a mandate).
- The operating contract §5.1 (docstrings on the new special var + exported symbols); NFR-PORT (both impls);
  the cross-DDS-interop-per-feature DoD (Connext + Fast DDS, agent runs both peers live).
