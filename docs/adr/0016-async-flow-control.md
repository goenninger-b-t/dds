# ADR 0016 — WP-ASYNC-FLOW: asynchronous flow control (shared FlowController + token bucket)

- **Status:** Accepted (Phases A–F delivered 2026-06-15: A token bucket, B1 per-datagram step, C shared
  FlowController + scheduler, D backpressure, E teardown + off-by-default, F1 rate-shaping bench, F2 docs) —
  created at Phase A; **WP-FLOW-EDF-PRIORITY addendum delivered 2026-07-04** (the deferred `:edf` +
  `:priority` scheduling policies + the TRANSPORT_PRIORITY QoS slot — see §Addendum below)
- **Deciders:** A0 (integrator)
- **Amends:** the `writer-write` / `writer-lifecycle-change` contract (Phase D, **delivered** — they now return
  `(or integer (eql :timeout))`; consumers `publish-sample` / `%dispose-or-unregister` /
  `dispose-instance` / `unregister-instance` and the DCPS `write-sample` / `dispose-instance` /
  `unregister-instance` absorb the `:timeout` / surface `RETCODE_TIMEOUT`). Phase A was purely additive (a
  new `defstruct` + file); the Phase-D contract change was recorded here ahead of time and is finalized below
- **Feature:** FR-PF-2 (asynchronous publication — the **flow-control** half; the async-sender half shipped
  in WP-ASYNC v1, ADR-less, commit `b94d36d`)

## NOT patent-gated (defining non-constraint)

Flow control is **standard DDS**: a sender-side scheduling concept that changes only *when* a datagram is
sent, never the submessage bytes. It is therefore an **additive extension on top of conforming RTPS
sending** (the operating-contract-permitted "extend, never replace" pattern) and carries **no R6 marker, no
"NOT cleared for ship" header**. This is the explicit contrast with WP-ZEROCOPY/WP-FLATDATA (ADR 0014/0015),
which mirror RTI-patented mechanisms and are R6-gated. Nothing in WP-ASYNC-FLOW is patented or wire-visible.

## Context

WP-ASYNC v1 (`enable-async`, commit `b94d36d`) gave each node a sender thread that, on signal, flushes **all**
unsent changes (`%push-data-buf`) **unpaced** — "the reliable unsent-list IS the queue." That delivers
async-without-flow-control. WP-ASYNC-FLOW adds the second half of FR-PF-2: **rate-shaped** asynchronous
publication. A standalone, shareable **FlowController** object with its **own scheduler thread** paces the
user-data byte rate of its associated writers via a **token bucket**, with **fragment-level granularity** (the
FR-PF-2 "DATA_FRAG pacing" use case) and DDS-standard **block-up-to-`max_blocking_time`** backpressure. Off by
default; opt-in.

The authoritative design spec is `docs/superpowers/specs/2026-06-15-wp-async-flow-design.md` (Alt B — shared
FlowController + scheduler thread, owner-chosen).

A writer is in exactly one of three send modes: **sync** (caller pushes), **async-unpaced** (`enable-async`,
per-node thread), **async-paced** (associated with a `flow-controller`, that controller's scheduler thread).
A writer is associated with **at most one** controller; association supersedes the per-node unpaced sender for
that writer. The non-flow paths stay **byte-identical** (regression-gated).

## Decision — phased delivery

### Phase A (this ADR, delivered now) — the token bucket only

A pure, deterministic **token bucket** (`flow-token-bucket`, `src/dds-disc/flow-control.lisp`): the metering
primitive the later scheduler will call once per datagram. No controller, no thread, no `writer-write` change
yet — those are Phases B–E. Phase A is a `defstruct` + two hot functions + the validating constructor + a
deterministic unit test. Token-bucket semantics:

- **Meter = bytes/period.** Fields: `tokens-per-period` (bytes, `(integer 1)`), `period` (ns, `(integer 1)`),
  `max-burst` (bytes, the bucket capacity, `(integer 1)`), `tokens` (current bytes), `last-refill` (ns).
- **Injectable clock.** A thunk `clock-fn` returning current ns (default `dds.pal:monotonic-ns`). Tests inject
  a closure over a settable counter so the math is deterministic and wall-clock-independent.
- **Lazy refill** (`%fb-refill`), no separate refill timer:
  `elapsed = max(0, now − last-refill)`; `added = floor(elapsed · tokens-per-period / period)` (the rate
  `tokens-per-period/period` is applied **multiply-before-divide** to keep integer precision);
  `tokens = min(max-burst, tokens + added)`. When `added > 0`, `last-refill` advances by **exactly the time
  those added tokens represent** — `last-refill += floor(added · period / tokens-per-period)`, **not** to
  `now`; when `added = 0` it is left untouched. Both rules keep the sub-quantum elapsed remainder accumulating
  across calls rather than being silently dropped (advancing to `now` would discard the fractional remainder
  and systematically under-deliver at low rates — e.g. lose ~0.9% over many sub-quantum refills).
- **`%fb-acquire(cost)`:** refill; if `tokens ≥ cost` ⇒ `tokens −= cost`, return `0` (proceed). It **also**
  succeeds when the datagram is larger than the whole bucket and the bucket is full
  (`cost > max-burst ∧ tokens ≥ max-burst`): it consumes `tokens = max(0, tokens − cost)` (clamped to a floor
  of 0 — pays at most `max-burst`, no debt accounting in v1) and returns `0`. This is the
  allowed-after-a-full-bucket-wait case for an over-`max-burst` datagram (**never deadlocks / never
  livelocks** — without it the bare `tokens ≥ cost` test can never hold and the scheduler spins on `wait = 1`
  forever). Otherwise `need = min(cost, max-burst)` and it returns the deficit wait
  `max(1, ceil((need − tokens) · period / tokens-per-period))` ns, **without consuming** — the non-full
  over-large case waits here until the bucket refills to full, then the retry takes the success clause above.
  The `min max-burst` bounds the wait to a full-bucket fill; the `max 1` guarantees a strictly positive wait so
  the scheduler re-evaluates after a refill rather than busy-spinning. Configure **`max-burst ≥ the largest
  datagram`** so a single datagram costs at most one full-bucket wait.
- **Overflow-safe.** All operands are non-negative; CL integer arithmetic is arbitrary-precision, so the
  intermediate products (`elapsed · tokens-per-period`, `(need − tokens) · period`) never wrap — a long-idle
  delta transiently widens to a bignum and is then clamped by `min max-burst`. The steady-state path (small ns
  deltas, fixnum tokens/cost) stays in fixnum arithmetic and is **0-alloc, CLOS-free** (gate-hotpath / mem).
- **Validation.** Zero/negative `tokens-per-period`, `period`, or `max-burst` ⇒ rejected at
  `make-flow-token-bucket` (the slot `(integer 1)` types plus an explicit check). Initial state: `tokens =
  max-burst` (starts full), `last-refill = (funcall clock-fn)`.

`%fb-acquire`/`%fb-refill` are **hot** (the scheduler will call them per datagram): `defun*` + full ftype +
0-alloc fixnum arithmetic + no CLOS dispatch + no per-call allocation. The file is added to the
`gate-hotpath` file list.

### Phases B–E (recorded now, NOT in this ADR's delivery) — the public API to come

The public **`flow-controller`** API (Alt B):
- `make-flow-controller(:tokens-per-period :period :max-burst &optional (:scheduling :round-robin))` — builds
  the controller (a token bucket + scheduling policy + registered-writer set + its own scheduler thread + lock
  + condvar). Validates as the bucket does.
- `flow-controller-associate(controller node/writer)` — registers a writer with the controller, making its
  sending async-and-paced (the controller thread sends). Associating a writer already bound to a controller is
  rejected (one controller per writer).
- `destroy-flow-controller(controller)` — set stop, signal, **join** the scheduler thread; flush the remaining
  unsent **ignoring the bucket** (shutdown never waits on a slow paced drain); unblock any writer blocked in
  `writer-write` with `TIMEOUT`. `stop-node` unregisters its writer(s) from any controller before the frees.
  Because the controller is **shared**, this is **not** a whole-scheduler join — `flow-controller-unregister`
  is a **per-node emit barrier** (see §Teardown): it removes the node from `writers` then blocks until the
  scheduler is provably not (and never again will be) mid-emit on that node, so the subsequent
  socket/SHMEM/buffer frees see no live scheduler reference. A bare unregister that only dropped the node from
  `writers` would **not** prevent a use-after-free of an emit already in flight on the node — the barrier is
  the fix.

**Scheduler thread + round-robin v1 behind a pluggable policy hook.** The scheduler loop, under the controller
lock, lazily refills the bucket and picks the next writer-with-pending-work via a **round-robin cursor**;
**peeks** that writer's next unsent datagram's byte size; `%fb-acquire`s that many tokens (still under the
controller lock); on success **releases the controller lock**, takes the **writer lock**, and emits **exactly
one** datagram (one coalesced `DATA(+HEARTBEAT)` group or one `DATA_FRAG` fragment), advancing the unsent
watermark; on a deficit it releases the lock, sleeps the returned wait, and re-evaluates. **Lock ordering
(correctness-critical):** the controller lock and the writer lock are **never held simultaneously** — the
controller lock is always released before the send, mirroring WP-ASYNC v1's release-async-lock-before-send.
One datagram per writer per RR step ⇒ fragments/samples from multiple writers interleave at the shaped
aggregate rate.

The scheduling policy is a **pluggable hook** (the scheduler calls it to pick the next writer-with-pending-
work). v1 ships **round-robin only**. The OMG-QoS-anchored follow-ups (deferred) drop in without rework:
- **TRANSPORT_PRIORITY** (standard QoS) → a priority / highest-priority-first policy.
- **LATENCY_BUDGET** and/or **DEADLINE** (standard QoS) → an EDF-like policy (per-sample deadline ≈
  write-time + latency-budget; earliest first). LATENCY_BUDGET is a max-delay **hint** — a rate limiter may
  delay beyond it under sustained overload, so the budget informs **ordering**, not a hard cap.

**The per-datagram "step" send (core refactor).** Today `%push-data-buf` flushes **all** unsent for a writer
in one call. Paced RR needs to **build the next single datagram** for a writer into the controller's scratch
buffer (no I/O) — its length is the exact token cost — then `%fb-acquire` that many tokens and only then
`sendto` the built buffer (byte-exact accounting; a built-but-unsent datagram is **held** in the scratch
buffer across a deficit sleep — never rebuilt, never dropped, so reliable completeness holds). The step reuses
the existing coalesce-budget + DATA_FRAG fragmentation, driven stepwise, and reports whether more remain. The
non-flow paths keep flush-all `%push-data-buf` **unchanged**. The step has **no compliance dimension** (wire-
invisible); it exists only because byte-exact token accounting + multi-writer interleaving require it.

### Phase D — `writer-write` contract change (DELIVERED 2026-06-15)

On an associated writer, `publish-sample` is async-and-paced: `writer-write` adds the sample to the
HistoryCache (bounded by RESOURCE_LIMITS `max_samples` under HISTORY **KEEP_ALL** — the cache already supports
both, `src/dds-rtps/history.lisp`), then marks the writer pending in its controller and signals the controller
condvar; it returns **without the caller sending** (async). The contract change, as built:

- **`writer-write` blocks up to `max_blocking_time`** on a per-writer "space-available" condvar (`space-cv`,
  paired with the existing writer lock; new slots `space-cv` + `max-blocking-ns` on `rtps-writer`) when the
  KEEP_ALL cache is full with a finite `max_samples`, then returns a **`:timeout` sentinel** (RETCODE_TIMEOUT)
  with the cache left intact and **no SN consumed** (the SN is bumped only on the add, so the reliable SN
  stream stays hole-free). `max_blocking_time = 0` ⇒ immediate `:timeout` (the non-blocking reject); **no
  finite `max_samples` (the default, unlimited KEEP_ALL or KEEP_LAST) ⇒ never blocks, byte-identical**.
  `writer-write` + `writer-lifecycle-change` share `%writer-add-bounded` (DRY); the bound applies to **all**
  changes (data + dispose/unregister, each occupying a SN — consistent). The deadline-wait loop releases the
  writer lock via `condvar-wait` while blocked. Space is signalled by **`%writer-signal-space`**
  (a `condvar-broadcast` under the writer lock — new `dds.pal:condvar-broadcast`, implemented on the native
  `sb-thread:condition-broadcast` / `mp:condition-variable-broadcast` because bordeaux-threads 0.9.4 has no
  portable broadcast) whenever the cache **shrinks**: `writer-purge-acked` (the existing purge-on-full-ACK)
  signals on a `>0` purge, and `flow-controller-unregister` / `destroy-flow-controller` signal each writer
  (`%flow-unblock-writer`) so a blocked publish reaches its TIMEOUT once the paced drain stops. The bound is
  **per-writer**; the controller paces the **aggregate** rate; together they keep the backlog bounded
  (NFR-MEM) regardless of paced-drain or reader-ACK speed.
- **Consumers** of the new `:timeout` return (audited + updated): **`writer-write`** + **`writer-lifecycle-change`**
  → `(or integer (eql :timeout))`; **`publish-sample`** (surfaces `:timeout`, does NOT push/signal/advance on
  it) + **`%dispose-or-unregister`** + the disc **`dispose-instance`** / **`unregister-instance`** wrappers
  (propagate `:timeout`); the DCPS **`write-sample`** / **`dispose-instance`** / **`unregister-instance`**
  surface `+RETCODE-OK+` / `+RETCODE-TIMEOUT+` (DDS 1.4 ReturnCode_t §2.2.4.4, `:ok` / `:timeout` keywords).
  Wiring: **`enable-publisher`** gains `&key max-samples max-blocking-ns` (both `nil` default ⇒ unlimited
  cache + no blocking, byte-identical). This is the only API-surface change in the WP; it is **additive** for
  the non-flow / non-full case (a writer with no finite `max_samples`, or a cache with room, sees the prior
  behavior). **Lock ordering (verified, binary):** the only lock held across the wait is the writer lock,
  released by `condvar-wait`; the freeing thread (ACKNACK purge on the receiver thread / paced scheduler on
  its own thread — never the app thread) re-takes the same lock to purge + signal, so there is no
  lock-ordering cycle, and the flow scheduler is **send-only** (it never calls `writer-write`), so a blocked
  publish on the app thread cannot wedge it. **Test:** `run-flow-backpressure-test` (`src/dds-tests/echo-test.lisp`,
  SBCL; Clasp pass-skipped — real blocking + the known Clasp condvar SIGSEGV): block→`:timeout` at
  ~`max_blocking_time`; unblock via the real `writer-purge-acked` BEFORE the deadline (proves the CV wakeup);
  `max_blocking_time = 0` immediate `:timeout`; default unlimited / KEEP_LAST never blocks.

### Sender-thread emit resilience (WP-SENDER-ERROR-RESILIENCE — the deferred Should-fix, DELIVERED 2026-06-17)

WP-ASYNC-FLOW flagged a Should-fix: the RX receiver thread already guards each iteration's dispatch
(`src/dds-xport/udp.lisp:105`, `(handler-case … (error () nil))`), but the **two sender threads** —
`%async-sender-loop` (`dataplane.lisp`) and `%flow-scheduler-loop` (`flow-control.lisp`) — did not, so a
signalled emit `error` (a hard `%shmem-send` segment/bounds error, datagram-build / destination resolution,
static-arena exhaustion, or a future transport) unwound out of the loop, **killed the thread**, and silently
stalled every writer it served. This WP closes that asymmetric gap. Non-R6; standard DDS (local send-error
handling is implementation-defined — the standard is silent — so this adds resilience, it does not change the
wire). Delivered:

- **One DRY guard macro** `with-sender-emit-guard ((context count-place) &body body)` in `dds.disc`
  (`dataplane.lisp`), used by **both** loops. It wraps the one per-iteration emit in `handler-case`: a caught
  `error` bumps `count-place`, fires `*sender-emit-error-hook*` (itself `ignore-errors`-guarded so a signalling
  hook cannot re-kill the thread), and returns `NIL`; on success it returns the body value. It catches **`error`
  only, NOT `serious-condition`** — a fatal VM state (`storage-condition` / control-stack-exhausted) SHOULD still
  terminate the thread; masking it would hide an unrecoverable condition. A macro (no per-emit closure) keeps it
  0-alloc, though the sender threads are off the measured CDR hot path regardless (`make mem` 0.0000 unchanged).
- **Observability** — exported `*sender-emit-error-hook*` (a funcallable `(condition context count)`, default
  `%default-sender-emit-error-hook` = a clockless rate-limited WARN: log only when `count` is 1 or a power of
  ten, so a persistent failure logs O(log n) lines, never a flood) + per-thread fixnum counters
  (`disc-node` slot `async-emit-errors`, `flow-controller` slot `emit-errors`); `context` is `:async-sender` /
  `:flow-scheduler`. The hook runs **on the sender thread** (it must not block; it does not inherit the binding
  thread's dynamic environment — a test/app sets the GLOBAL value).
- **The flow path drops + advances unconditionally (Option 1).** The catch is **inside** the scheduler's
  `unwind-protect` (the per-node emit barrier cleanup at `flow-control.lisp:264` still disarms; the error never
  escapes the loop), and the plan cursor advances on both success and a caught error
  (`(setf (disc-node-flow-step-state node) (cdr plan))`). **Why this cannot hot-spin (correctness-critical):**
  the writer's unsent **watermark is advanced at SNAPSHOT time** (`%node-datagram-plan` /
  `%flow-step-emit`'s contract, `dataplane.lisp`), NOT per send — so once a plan is snapshotted those samples
  are already past the watermark and the node is no longer pending *for them*; draining the faulted plan's cursor
  exits the plan, and the next RR-pick does not re-snapshot the dropped samples → bounded work, no spin. We
  deliberately do NOT touch the watermark (it already moved); the dropped samples stay in the HistoryCache and
  are recovered by the writer's proactive re-push on the next flush / the HEARTBEAT-ACKNACK fallback (RTPS 2.5
  §8.4.2.2, §8.4.1). The async path already could not spin (`async-pending` is cleared before the send, so a
  caught error returns to the bounded condvar-wait). Option 2 (retry-the-same) was rejected — it risks
  **wedging** a writer (no SN advances → no-progress); Option 3 (clear-pending) defers proactive push.
- **Fault injection (test-only, inert in production):** condition `sender-emit-test-fault` + the special
  `*debug-emit-fault*` (default `NIL` = inert, byte-identical; a positive integer N faults the next N
  `%send-raw-buf` calls decrementing; `:persistent` faults every call) — injected at the top of the single
  shared send primitive `%send-raw-buf` so both threads exercise the guard. Mirrors `*debug-drop-sample-numbers*`.
- **Tests (6, oracle = thread survival + delivery + the hook record; all green SBCL+Clasp except where noted):**
  `run-async-emit-fault-survives-test` (3 faults caught, thread survives, all 6 samples delivered),
  `run-emit-fault-inert-test` (NIL ⇒ byte-identical wire + counter stays 0),
  `run-flow-emit-fault-no-spin-test` (persistent fault, the K small samples coalesce to 1 plan entry, the
  hook-fire count STABILISES + is BOUNDED, the scheduler resumes — SBCL; Clasp pass-skip, the flow-test timing
  gap), `run-flow-emit-fault-no-spin-multi-test` (the multi-entry strengthening: a 4000-octet sample forces a
  ≥3-entry DATA_FRAG plan — asserted via a deterministic twin-node `%node-datagram-plan` snapshot — so the
  scheduler walks the multi-element cursor under a persistent fault; the plan-size-agnostic stability proof —
  observed a 6-entry plan, 6 fires, stable — SBCL; Clasp pass-skip),
  `run-reliable-repair-after-drop-test` (Option-1: a reliable DATA dropped by the guard is still delivered),
  `run-hook-self-error-test` (a signalling hook does not re-kill the thread).
- **Live cross-DDS interop (the per-feature DoD):** the Shapes publisher gained `FAULT=k@j` / `HISTORY=keep-all`
  / `PORT=` env gates (inert when unset, byte-identical wire); the async sender survived **3/3** injected faults
  while interoperating with a **live RTI Connext 7.3.1** and **live Fast DDS 3.6.1** reliable subscriber, the
  peer kept matching + receiving, and delivery was preserved (the Fast DDS fault run = its no-fault baseline,
  29/30) — `interop/sender-resilience/`, tshark-validated, captures committed. **Honest framing:** a reliable
  writer delivers regardless of the guard (the re-push + HEARTBEAT run on threads that do not die with the
  guarded sender thread), so the interop proves *sender-thread survival + wire validity + delivery preservation*;
  the *guard-vs-no-guard* discrimination is the unit mutation tests, not the interop.

### Addendum — WP-FLOW-EDF-PRIORITY: the two QoS-anchored scheduling policies (DELIVERED 2026-07-04)

This addendum delivers the deferred pluggable policies named above (§Phases B–E, "Scheduler thread"): `:edf`
(earliest-deadline-first, anchored on **LATENCY_BUDGET**) and `:priority` (highest **TRANSPORT_PRIORITY** first,
with starvation-avoidance aging). Both are **pure SELECTION** — they change only *which* registered writer the
scheduler drains next, under the controller lock; the token-bucket pacing (*when*), the per-datagram build/emit,
the per-node emit barrier, and the wire bytes are all **untouched**. They drop into `make-flow-controller`'s
policy `ecase` (`:round-robin` | `:edf` | `:priority`) with **no change to `%flow-scheduler-loop`** — the seam
was designed for exactly this. `:round-robin` and controller-off remain **byte-identical** (the new code is
additive behind the ecase; RR ignores the new slots). Still **NOT R6** — scheduling is wire-invisible.

**LATENCY_BUDGET as the EDF key (NOT DEADLINE).** The per-sample EDF deadline is `write-time + LATENCY_BUDGET`,
earliest first. In this stack QoS **DEADLINE** is the *periodicity/liveliness* contract that drives
OFFERED/REQUESTED_DEADLINE_MISSED (DDS 1.4 §2.2.3.7) — a **different** contract; using it as the EDF key would
conflate two meanings. **LATENCY_BUDGET** (§2.2.3.8) is precisely a *maximum acceptable delay* / urgency hint,
so it is the correct ordering anchor. It is a **hint, not a hard cap**: a saturated token bucket may still delay
a sample beyond its budget — EDF informs **ordering**, it does not guarantee the deadline (the bench measures
miss *reduction* vs round-robin, not zero misses).

**budget-0 semantics.** The DDS default LATENCY_BUDGET is `{0,0}`. Deadline = `write-time + 0 = write-time`, so a
budget-0 writer sorts **earliest / most urgent** relative to positive-budget writers enqueued at the same time —
the spec-faithful reading (`deadline = write-time`), *not* "no preference". Confirmed + tested
(`run-flow-edf-ordering-test`: a budget-0 writer drains before a budget-10ms one).

**Aging policy + starvation bound.** Effective priority = `base TRANSPORT_PRIORITY + floor((now − last-served)/
quantum)`, where `quantum = *flow-priority-aging-quantum-ns*` (default 10 ms) and `now` is read via the
controller's **injected clock-fn** (the token bucket's — reused DRY, so tests advance a settable counter and the
policy is deterministic; **no raw wall-clock** that would break determinism). `last-served` is stamped on the
node **each time the `:priority` policy selects it**; a saturating high-priority writer is served every turn, so
its aging stays ≈ 0, while a starved low-priority writer's aging climbs with elapsed time. **Bound:** behind a
permanently-saturating writer of base `P_high`, a writer of base `P_low` waits at most **≈ `(P_high − P_low)`
quanta** (≈ `(P_high − P_low)·quantum` ns) before its effective priority ties then exceeds `P_high` and it is
selected — **finite for any finite priority gap** (contrast: pure highest-first starves it unboundedly). Ties
(equal EDF deadline or equal effective priority) fall to a **stable round-robin cursor** tiebreak, so equal-key
writers rotate and never starve each other. Verified: `run-flow-priority-aging-test` (deterministic clock) +
the bench's max-consecutive-unserved-gap metric.

**Per-writer-key surfacing path (honours the lock discipline).** The policy runs **under the controller lock**,
which must **never** nest the writer lock (the binary lock-ordering gate). So the policy **cannot** read the
writer's HistoryCache/QoS live. Instead the needed keys are **cached onto controller-lock-guarded `disc-node`
slots**: `flow-latency-budget-ns` + `flow-transport-priority` are read **once at `flow-controller-associate`**
from the writer endpoint's QoS (`%flow-cache-writer-qos`), and the EDF write-time `flow-head-ns` is stamped
**(a)** in **`%flow-signal`** on the idle→pending transition (a fresh burst's head write-time) **and (b)** in
the scheduler at each plan **re-snapshot** (`%flow-head-advance`, when the writer's head-of-line batch has
drained and a fresh unsent set is captured). Both stamps use the controller clock **now** as the lock-safe
proxy for the head sample's enqueue time (the HistoryCache — the true timestamp — cannot be read under the
controller lock). The **(b)** re-stamp is essential under **sustained per-writer backlog**: a continuously-
pending writer never goes idle, so **(a)** never re-fires; without **(b)** its frozen `flow-head-ns` would grow
progressively more urgent vs the wall clock and it would **monopolize** selection against newer-but-tighter-
budget writers. With **(b)**, a *served* writer's key advances each drain (its urgency resets) while an
*unserved* writer's `flow-head-ns` correctly stays put and ages toward selection — natural EDF anti-starvation.
The **granularity is the plan (snapshot) batch, not the individual sample** (the plan snapshots the whole
unsent set at once, so `flow-head-ns` = the current batch's snapshot time, not each sample's exact enqueue):
EDF ordering is thus exact across writers at each re-snapshot, approximate within a multi-datagram plan. Both
stamps are **gated by the scheduling policy** — `:edf` stamps `flow-head-ns`, `:priority` stamps
`flow-last-served-ns` (the aging baseline), **`:round-robin` stamps NEITHER**, so the RR/off path is literally
additive-behind-the-ecase (byte-identical). All slots are written/read only under the controller lock — **zero
writer-lock contact from the policy**, and **no per-sample allocation** on the selection path (the key-fns are
top-level functions, never per-call closures). This is the "cache at associate + stamp at signal/re-snapshot"
path, chosen over live HistoryCache peeking precisely because live peeking would violate the
controller-lock-never-nests-writer-lock invariant.

**TRANSPORT_PRIORITY QoS slot (the plumbing gap).** TRANSPORT_PRIORITY was not yet a QoS slot; this WP adds
`transport-priority` (`(signed-byte 32)`, default **0** per DDS 1.4 §2.2.3.13) to the `qos` struct. It is
**writer-local, NOT an RxO policy** (absent from `qos-rxo-compatible` — a mismatch neither blocks nor is
reported) and **NOT propagated in SEDP**: sender-side scheduling needs only the writer's *local* value, and the
SEDP serializer is explicit per-PID (adding the slot does **not** perturb the wire). Full SEDP propagation is
deliberately **out of scope** (no test needs it). Verified: `run-flow-transport-priority-qos-test`.

**Tests (6 new) + bench.** `run-flow-transport-priority-qos-test` (slot default 0 + not-RxO + associate
caching), `run-flow-edf-ordering-test` (min-deadline-first + budget-0-most-urgent + RR tie-rotation),
`run-flow-edf-backlog-test` (Finding-1: under sustained per-writer backlog WITHOUT the re-snapshot re-stamp the
tight writer monopolizes and the loose writer starves — served 0, the RED; WITH `%flow-head-advance` the loose
writer makes bounded progress while the tight writer stays preferential),
`run-flow-priority-ordering-test` (highest-first), `run-flow-priority-aging-test` (bounded starvation under a
saturating high writer, injected clock) — all five are **deterministic direct policy exercises** (no threads/
sockets), so they run on **both** SBCL and Clasp (they are *not* the real-thread flow kind Clasp pass-skips);
`run-flow-edf-priority-e2e-test` drives a live `:edf` and a live `:priority` controller end-to-end (delivery
completeness, SBCL-only, Clasp pass-skipped exactly like `run-flow-multiwriter-rr-test`). Bench:
`run-bench-flow-edf-priority` (`make bench-flow-edf-priority`, `bench/report/2026-07-04-wp-flow-edf-priority.md`)
— a deterministic discrete-event sim over the **shipped** selectors: EDF deadline-miss count vs round-robin for
mixed-budget streams, and `:priority` service share + the low-priority starvation bound vs round-robin.

## OMG DDS / RTPS spec-compliance (wire-invisible / additive on conforming RTPS / NOT R6)

Flow control is **wire-invisible**: it changes only **when** a datagram is sent, never the submessage bytes.
DDSI-RTPS 2.5 constrains the wire (DATA / DATA_FRAG / HEARTBEAT format, the fragmentation rules, and that a
**reliable** writer must *eventually* deliver every change) — **not** the sender's internal scheduling. So
WP-ASYNC-FLOW is an **additive extension on top of conforming RTPS sending**, the operating-contract-permitted
pattern. The normative obligations it preserves:

- **Conformant DATA_FRAG fragmentation** — the per-datagram step reuses the existing fragmentation path
  unchanged (the step structure is internal and wire-invisible).
- **Reliable completeness** — pacing *delays*, never *drops*: KEEP_ALL retention + the held-(never-rebuilt,
  never-dropped) datagram + the scheduler draining all pending ⇒ every reliable change is eventually sent.
- **Standard backpressure** — block-up-to-`max_blocking_time` over a bounded HISTORY/RESOURCE_LIMITS cache is
  the standard RELIABILITY behavior, not a new wire concept.

The **FlowController, asynchronous PublishMode, and the round-robin / EDF / highest-priority-first policy
names are RTI Connext vendor extensions — none are normative in OMG DDS 1.4 or DDSI-RTPS 2.5** (the standard
QoS set has no PUBLISH_MODE or FLOW_CONTROLLER; asynchronous publication is an implementation freedom). The
spec is **silent on scheduling**, so round-robin is as compliant as any policy; where a future policy should
be grounded in standard QoS rather than proprietary names, the anchors are TRANSPORT_PRIORITY and
LATENCY_BUDGET/DEADLINE (above).

## Memory / hot-path (NFR-MEM, NFR-CLOS)

The token-bucket acquire/refill runs in the scheduler thread per datagram — `defstruct` + fixnum arithmetic,
**0-alloc, CLOS-free** (gate-hotpath / mem cover it; `src/dds-disc/flow-control.lisp` is in the gate-hotpath
file list). The scheduler's per-datagram step (Phase D) reuses the existing foreign tx buffers (the controller
owns its own scratch buffer, like the async sender). No per-sample heap allocation on the paced path.

## Testing / acceptance (oracle = measured rate + deterministic unit math; FR-LANG-7)

- **Phase A (delivered):** `run-flow-token-bucket-test` (`src/dds-tests/echo-test.lisp`, registered in
  `run-all-tests`, SBCL + Clasp) — deterministic with an injected settable-counter clock: starts full;
  acquire-success decrements; deficit-wait positive without consuming; half-period elapsed refills ~rate·Δ
  capped at max-burst; tokens never exceed max-burst after long idle; an over-max-burst acquire **succeeds via
  retry-then-refill within a small bound and drains the bucket to 0** (the no-livelock guarantee — fails the
  pre-fix `wait = 1`-forever code); a low-rate refill stepped in **sub-quantum increments delivers the ideal
  token count with no remainder loss** (fails the pre-fix advance-to-`now` refill); zero/negative
  `tokens-per-period`/`period` signal.
- **Phases B–E (delivered):** `run-flow-pacing-test` (low rate + N bytes ⇒ paced elapsed ≥ ~0.5× ideal AND
  materially slower than the unpaced `enable-async` baseline — rate shaping observed; SBCL, Clasp pass-skipped
  timing); `run-flow-multiwriter-rr-test` (two writers on one controller ⇒ both delivered, ≥ 4 a/b
  interleave-transitions in delivery order proving per-datagram RR, aggregate shaped); `run-flow-backpressure-test`
  (full bounded KEEP_ALL ⇒ `write()` blocks then `:timeout` at `max_blocking_time`, unblocks via the real
  `writer-purge-acked` before the deadline, `max_blocking_time = 0` immediate, default unlimited/KEEP_LAST never
  blocks); hot-path/mem (acquire is 0-alloc + CLOS-free per `gate-hotpath` + `mem`; controller-off ⇒
  byte-identical per `run-flow-off-byte-identical-test` + `flow-step-equivalence`, regression-gated);
  `run-flow-concurrency-stress-test` (SBCL; Clasp pass-skipped — real-thread timing + the known Clasp condvar
  SIGSEGV): the per-node emit barrier closes the use-after-free where `stop-node` frees a node's
  socket/SHMEM/buffers while the **shared** scheduler is mid-emit on it — a deterministic `*datagram-sink*` park
  proves `stop-node` blocks in the barrier until the emit completes (fails the pre-barrier code), plus
  single-writer + shared-controller churn variants (no deadlock, no lost wakeup, clean teardown, the controller
  keeps serving its other writers); `run-flow-teardown-test` (flush-on-destroy + no-wedge of a blocked writer).
- **Phase F1 bench (delivered):** `run-bench-async-flow` (`src/dds-tests/integration-test.lisp`, `make
  bench-async-flow`) → `bench/report/2026-06-15-wp-async-flow.md` — the HONEST rate-shaping report over the real
  data plane (no "0-cost"/"free" claim; pacing adds latency by design): rate-shaping accuracy
  (achieved-vs-configured over several rates/burst sizes — e.g. configured 125 KB/s achieved ~132 KB/s, the
  startup full bucket + per-datagram-granularity overshoot; a smaller `max-burst` tracks ~1.00×), single-writer
  paced vs the `enable-async` UNPACED baseline (the same workload ~0.4 s paced vs ~0.005 s unpaced ⇒ ~86×
  slower — the added latency stated plainly as the *point* of rate control), multi-writer AGGREGATE shaped to
  ~R not 2R (the controller paces the sum) + the per-datagram RR interleaving, and DATA_FRAG fragment cadence
  (one 8000-octet sample → ~8 fragments, the full bucket draining the first few back-to-back then the rest
  spread at the token-refill cadence — the FR-PF-2 headline). SBCL only; Clasp pass-skips (the flow tests'
  NFR-PORT gap). A bench is a `run-bench-*` entry, not a unit test in the suite count (the project convention,
  as `run-bench-flatdata`).

## Consumers (as built / planned)

- `src/dds-disc/flow-control.lisp` — `flow-token-bucket`, `make-flow-token-bucket`, `%fb-refill`,
  `%fb-acquire` (Phase A); `flow-controller`, `make-flow-controller`, `flow-controller-associate`,
  `flow-controller-unregister`, `destroy-flow-controller`, the scheduler thread (`%flow-scheduler-loop`) +
  pluggable policy hook (`%flow-policy-round-robin`) + the per-node emit barrier (Phase C)
- `src/dds-disc/packages.lisp` — exports the token-bucket + `flow-controller` API
- **WP-FLOW-EDF-PRIORITY addendum:** `src/dds-qos/qos.lisp` + `packages.lisp` (`transport-priority` slot +
  `qos-transport-priority` export); `src/dds-disc/disc.lisp` (`flow-latency-budget-ns` / `flow-transport-priority`
  / `flow-head-ns` / `flow-last-served-ns` node slots); `src/dds-disc/flow-control.lisp`
  (`*flow-priority-aging-quantum-ns*`, `%flow-controller-now`, `%flow-policy-select`, `%flow-edf-key`,
  `%flow-priority-key`, `%flow-policy-edf`, `%flow-policy-priority`, `%flow-cache-writer-qos`; `%flow-signal`
  head/aging stamping; `flow-controller-associate` caching; `make-flow-controller` ecase + docstrings);
  `src/dds-tests/integration-test.lisp` + `echo-test.lisp` (5 tests + `run-bench-flow-edf-priority`);
  `Makefile` (`bench-flow-edf-priority`)
- `src/dds-disc/dataplane.lisp` — the per-datagram "build one datagram into the scratch buffer" step
  (`%node-datagram-plan` / `%emit-plan-entry` / `%flow-step-emit`, Phase B1); `writer-write` /
  `writer-lifecycle-change` block-up-to-`max_blocking_time` + `:timeout` sentinel via `%writer-add-bounded`;
  `publish-sample` / `%dispose-or-unregister` divert to `%flow-signal` / absorb `:timeout`; `stop-node`
  unregisters from any controller (Phase D)
- `src/dds-rtps/reliable.lisp` — `rtps-writer` `space-cv` + `max-blocking-ns` slots, `%writer-signal-space`
  (`condvar-broadcast` on purge), `dds.pal:condvar-broadcast` (Phase D)
- `src/dds-tests/echo-test.lisp` — `run-flow-token-bucket-test` (Phase A); `run-flow-backpressure-test` (Phase D)
- `src/dds-tests/integration-test.lisp` — `run-flow-controller-lifecycle-test`, `run-flow-pacing-test`,
  `run-flow-multiwriter-rr-test`, `run-flow-concurrency-stress-test`, `run-flow-teardown-test`,
  `run-flow-off-byte-identical-test` (Phases C–E); `run-bench-async-flow` (Phase F1 bench)

## Provenance

Implemented clean-room from FR-PF-2 + the DDSI-RTPS 2.5 scheduling-is-implementation-freedom reading; **no RTI
source, headers, or `rtiddsgen` output consulted**. The bytes/period lazy-refill token bucket is a textbook
rate-limiter (the standard "leaky/token bucket" algorithm), not an RTI mechanism; the FlowController object
shape is this project's own Alt-B design. Provenance logged in `docs/provenance.md`.

## Consequences

- A new `defstruct` + file in `dds.disc`, exported symbols, and one new test — purely additive; no existing
  behaviour changed, non-flow paths byte-identical.
- The **`writer-write` + `writer-lifecycle-change` contract gained a `:timeout` return** (Phase D, delivered;
  additive: only a writer with a full **bounded** KEEP_ALL cache and `max_blocking_time` elapsed sees it);
  `publish-sample` / `%dispose-or-unregister` / the disc + DCPS `dispose`/`unregister` wrappers and the DCPS
  `write-sample` handle it (the DCPS layer surfaces `+RETCODE-OK+` / `+RETCODE-TIMEOUT+`). Finalized above.
- `docs/verification.csv` FR-PF-2 row: the pacing, multi-writer, backpressure, teardown, off-by-default
  acceptance tests pass and the Phase-F1 rate-shaping bench is delivered (`bench/report/2026-06-15-wp-async-flow.md`).
- **NOT R6-gated** — no patent marker, no "NOT cleared for ship" header; flow control is standard DDS.
