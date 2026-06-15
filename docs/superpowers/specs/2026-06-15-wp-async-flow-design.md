# WP-ASYNC-FLOW — Asynchronous flow control (shared FlowController + token bucket) — design

**Goal (FR-PF-2, second half).** Provide **rate-shaped flow control** for asynchronous publication: a
standalone, shareable **FlowController** object with its **own scheduler thread** paces the user-data byte
rate of its associated writers via a **token bucket**, with **fragment-level granularity** (the FR-PF-2
"DATA_FRAG pacing" use case) and DDS-standard **block-up-to-`max_blocking_time`** backpressure. Off by
default; opt-in. Not patent-gated (standard DDS — no R6 marker).

## Relationship to WP-ASYNC v1
WP-ASYNC v1 (`enable-async`) gave each node a sender thread that, on signal, flushes **all** unsent changes
(`%push-data-buf`) **unpaced** — "the reliable unsent-list IS the queue." WP-ASYNC-FLOW adds a **separate**
`flow-controller` object whose **own** scheduler thread performs **paced** sending for the writers associated
with it. A writer is associated with **at most one** controller; association makes its sending
async-and-paced (the controller thread sends), **superseding** the per-node unpaced sender for that writer.
`enable-async` remains for the async-without-flow-control case. A writer is therefore in exactly one of three
send modes: **sync** (caller pushes), **async-unpaced** (`enable-async`, per-node thread), **async-paced**
(associated with a `flow-controller`, controller thread).

## Architecture (Alt B — shared FlowController + scheduler thread; owner-chosen)
A `flow-controller` is a standalone object holding: a **token bucket**, a **scheduling policy**, the set of
**registered writers** (each with a "pending unsent" mark), its **own scheduler thread**, a **lock**, and a
**condvar**. The RTI model: one controller may pace several writers; the controller schedules their aggregate
output.

### Components

1. **Token bucket** (`defstruct`, hot-path-pure — no CLOS, 0-alloc, fixnum arithmetic):
   - Fields: `tokens-per-period` (bytes), `period` (ns), `max-burst` (bytes, bucket capacity), `tokens`
     (current bytes), `last-refill` (ns).
   - **Lazy refill** on each acquire: `tokens = min(max-burst, tokens + floor((now − last-refill) · rate))`,
     `rate = tokens-per-period / period`, `now = dds.pal:monotonic-ns`. The clock is **injectable** (a thunk)
     so unit tests are deterministic, not wall-clock-dependent. No separate refill timer.
   - `acquire(cost-bytes)`: if `tokens ≥ cost` ⇒ `tokens −= cost`, proceed. Else compute the deficit wait
     `ceil((cost − tokens) / rate)` ns; the scheduler thread sleeps that long (or until signalled-and-
     refilled), then retries. A datagram with `cost > max-burst` is allowed through after a full-bucket wait
     (never deadlocks on an over-large fragment).

2. **Scheduler thread + round-robin dispatch.** Loop:
   - Under the **controller lock**, timed-wait (the `period`, bounded) until some registered writer has
     pending unsent work or `stop`. Lazily refill the bucket.
   - Pick the next writer with pending work via a **round-robin cursor** over the registered-writer list.
     **Peek** that writer's next unsent datagram's byte size (build-cost without sending). Acquire that many
     tokens (still under the controller lock); if insufficient, compute the wait, **release the lock**, sleep,
     and continue the loop (re-evaluating after refill).
   - On a successful token acquire: **release the controller lock**, then take the **writer lock** and **emit
     exactly that one datagram** (one coalesced `DATA(+HEARTBEAT)` group, or one `DATA_FRAG` fragment),
     advancing the writer's unsent watermark. Advance the RR cursor to the next writer. Repeat.
   - When a writer's unsent set is fully drained, clear its pending mark. When no writer has pending work, the
     scheduler sleeps on the condvar until signalled.
   - **Fairness:** one datagram per writer per RR step ⇒ fragments/samples from multiple writers interleave at
     the shaped aggregate rate.

3. **Lock ordering (correctness-critical — ultrathink in the plan).** The **controller lock** guards only the
   scheduling/token/registration state and is **always released before** the **writer lock** (the send).
   **The two locks are never held simultaneously** — mirroring WP-ASYNC v1's release-async-lock-before-send.
   Token accounting happens under the controller lock (by peeking the next datagram's size); the send happens
   outside it. This eliminates the controller×writer lock-ordering deadlock.

4. **The per-datagram "step" send (core refactor).** Today `%push-data-buf` flushes **all** unsent for a
   writer in one call (internal coalescing + fragmentation). Paced RR needs to emit **one datagram at a time**
   so tokens are accounted and writers interleaved per datagram. So a flow-aware send exposes "**build the
   next single datagram** for writer W **into the controller's scratch buffer** (no I/O)" → its **length is
   the exact token cost**; the scheduler then `acquire`s that many tokens and only then `sendto`s the built
   buffer (so accounting is byte-exact and a built-but-not-yet-sent datagram is simply **held** in the scratch
   buffer across the deficit sleep — never rebuilt, never dropped). The step reuses the existing datagram-
   building (coalesce budget, DATA_FRAG fragmentation) driven stepwise, and reports whether more remain. The
   non-flow paths (sync; `enable-async` unpaced) keep using flush-all `%push-data-buf` **unchanged**.

5. **`publish-sample` on an associated writer:** `writer-write` (add to the HistoryCache, applying
   backpressure — §Backpressure), then **mark the writer pending** in its controller + **signal** the
   controller condvar; return (async — the caller does **not** send).

### Backpressure (owner-chosen: block up to `max_blocking_time`)
The writer HistoryCache is bounded by **RESOURCE_LIMITS `max_samples`** (HISTORY **KEEP_ALL**; the cache
already supports both — `src/dds-rtps/history.lisp`). When the cache is full, `writer-write` **blocks** on a
"space-available" condvar up to **`RELIABILITY.max_blocking_time`**, then returns **`RETCODE_TIMEOUT`**
(`publish-sample` surfaces it). The scheduler signals "space-available" as it sends and as ACKNACKs purge
acked changes (the existing purge-on-full-ACK frees space). `max_blocking_time = 0` ⇒ immediate timeout (the
non-blocking degenerate). The bound is **per-writer** (each writer's cache); the controller paces the
**aggregate** send rate; together they keep the backlog bounded (NFR-MEM) regardless of how slow the paced
drain is or how slow a reader ACKs.

### Defaults / opt-in
- **No controller** ⇒ unchanged behavior (sync or `enable-async` unpaced) — **byte-identical**, regression-
  gated.
- **Opt-in:** `make-flow-controller(:tokens-per-period :period :max-burst &optional (:scheduling
  :round-robin))`; `flow-controller-associate(controller node/writer)`; configure the writer's HistoryCache
  `max_samples` (KEEP_ALL) + `max_blocking_time` for backpressure. Same opt-in shape as batch/async.

### Teardown
- `destroy-flow-controller`: set `stop`, signal, **join** the scheduler thread; **flush the remaining unsent
  ignoring the bucket** (do not make shutdown wait on a slow paced drain); unblock any writer blocked in
  `writer-write` with `TIMEOUT`.
- `stop-node` **unregisters** its writer(s) from any controller before tearing down. The controller is
  **shared** across nodes, so this is **NOT** a whole-scheduler join (that would block on the other nodes) —
  `flow-controller-unregister` is a **per-node emit barrier**: under the controller lock it (1) removes the
  node from `writers` + clears its `flow-pending`/`flow-controller` (the round-robin policy can never *newly*
  pick it), then (2) blocks on an `emit-done-cv` while `current-emit-node = node` until any **in-flight**
  scheduler emit on that node finishes. The scheduler sets `current-emit-node = node` under the lock in the
  same critical section that picks it (before releasing the lock for the lock-free build/send) and clears it
  + signals `emit-done-cv` under the lock on **every** emit exit path (`unwind-protect`, so even a send error
  can't leave the slot stuck). Only after unregister returns (`current-emit-node ≠ node`) does `stop-node`
  `udp-close` the socket / `shmem-transport-close` the ring / `free-static` the tx buffers — so the scheduler
  holds **no live reference** to the freed resources (no use-after-free). A bare unregister-*without*-this-
  barrier (only removing the node from `writers`) would **NOT** be safe — an emit already in flight on the
  node would send on a closed socket / freed SHMEM ring. Deadlock-free: the emit is lock-free (the scheduler
  never needs the controller lock to *finish* the emit being waited on), the `condvar-wait` releases the lock
  so the scheduler can re-take it to clear+signal, and the wait is bounded + re-checked. A controller may
  outlive its nodes only until `destroy-flow-controller`.

### Error handling / edges
- Zero/negative `tokens-per-period` or `period` ⇒ rejected at `make-flow-controller`.
- A datagram larger than `max-burst` ⇒ allowed after a full-bucket wait (no deadlock).
- `max_blocking_time` expiry ⇒ `TIMEOUT`, the cache left intact.
- Associating a writer already bound to a controller ⇒ rejected (one controller per writer).
- The scheduler's bounded period-timeout ensures a missed signal cannot wedge shutdown (WP-ASYNC v1 pattern).
- Token/refill arithmetic is overflow-safe (fixnum math on monotonic-ns deltas).

## Memory / hot-path (NFR-MEM, NFR-CLOS)
The token-bucket acquire/refill runs in the scheduler thread per datagram — `defstruct` + fixnum arithmetic,
**0-alloc, CLOS-free** (gate-hotpath / mem cover it). The scheduler's per-datagram step reuses the existing
foreign tx buffers (the controller owns its own scratch buffer, like the async sender). No per-sample heap
allocation on the paced path.

## OMG DDS / RTPS spec-compliance
Flow control is **wire-invisible**: it changes only **when** a datagram is sent, never the submessage bytes.
DDSI-RTPS 2.5 constrains the wire (DATA / DATA_FRAG / HEARTBEAT format, the fragmentation rules, and that a
**reliable** writer must *eventually* deliver every change), **not** the sender's internal scheduling. So
this WP is an **additive extension on top of conforming RTPS sending** — the operating-contract-permitted
pattern (extend, never replace, conforming behavior). The normative obligations it must preserve, and does:
- **Conformant DATA_FRAG fragmentation** — the per-datagram step reuses the existing fragmentation path
  unchanged (the step structure is internal and wire-invisible).
- **Reliable completeness** — pacing *delays*, never *drops*: KEEP_ALL retention + the held-(never-rebuilt,
  never-dropped) datagram + the scheduler draining all pending ⇒ every reliable change is eventually sent.
- **Standard backpressure** — block-up-to-`max_blocking_time` over a bounded HISTORY/RESOURCE_LIMITS cache is
  the standard RELIABILITY behavior, not a new wire concept.

**The FlowController, asynchronous PublishMode, and the round-robin / EDF / highest-priority-first policy
names are RTI Connext vendor extensions — none are normative in OMG DDS 1.4 or DDSI-RTPS 2.5** (the standard
QoS set has no PUBLISH_MODE or FLOW_CONTROLLER; asynchronous publication is an implementation freedom). The
spec is therefore **silent on scheduling**, so round-robin is as compliant as any policy. Where a future
policy should be *grounded in standard QoS* rather than proprietary names, the OMG QoS anchors are:
- **TRANSPORT_PRIORITY** (standard QoS) → a priority / highest-priority-first policy.
- **LATENCY_BUDGET** and/or **DEADLINE** (standard QoS) → an EDF-like policy (per-sample deadline ≈
  write-time + latency-budget; earliest first). Note LATENCY_BUDGET is a max-delay **hint** — a rate limiter
  may delay beyond it under sustained overload, so the budget informs **ordering**, not a hard cap.

v1 therefore keeps the **scheduling policy pluggable** (a policy hook the scheduler calls to pick the next
writer-with-pending-work) so the TRANSPORT_PRIORITY / LATENCY_BUDGET-anchored policies drop in without
rework. The **per-datagram step has no compliance dimension** (wire-invisible) — it is chosen purely because
byte-exact token accounting + multi-writer interleaving require it.

## Testing / acceptance (oracle = measured rate + deterministic unit math; FR-LANG-7)
- **Unit (deterministic, injected clock):** token-bucket refill, acquire, deficit-wait, burst cap, over-large
  cost — no wall-clock dependence.
- **Pacing:** a low rate + N bytes ⇒ assert elapsed ≥ N/rate (bench-measured, with tolerance); a fragmented
  (DATA_FRAG) sample's fragments spread across periods.
- **Multi-writer round-robin:** two writers on one controller ⇒ their datagrams interleave AND the aggregate
  byte rate is shaped to the bucket.
- **Backpressure:** tiny `max_samples` + a stalled drain ⇒ `write()` blocks then returns `TIMEOUT` at
  `max_blocking_time`; it unblocks when the scheduler frees space.
- **Hot-path / mem:** the acquire path is 0-alloc + CLOS-free; **controller-off ⇒ byte-identical** (the
  send paths are unchanged when no controller is associated) — regression-gated.
- **Concurrency / stability (binary gate):** `run-flow-concurrency-stress-test` (SBCL; Clasp pass-skipped —
  real-thread timing + the known Clasp multithread-condvar SIGSEGV). Three variants drive the exact racy path
  the other flow tests avoid (they never stop a node mid-emit): (A) **deterministic** — `*datagram-sink*`
  parks the scheduler mid-emit on a node, a worker calls `stop-node`, and the test asserts `stop-node`
  **blocks** in the per-node barrier until the park releases (and only then frees the node — the regression
  guard for the use-after-free); (B) single-writer churn — publish continuously then `stop-node` races the
  draining scheduler with **no destroy-first**; (C) **shared-controller** churn — two writers on one
  controller, stop one node mid-drain, and assert the **other keeps being delivered** (the scheduler thread
  survived a per-node teardown — a whole-scheduler join could not). Proves no deadlock (lock ordering), no
  lost wakeup, no use-after-free, and clean teardown. Verified to **fail against the pre-barrier code**
  (variant A trips `flow-stress-barrier-blocks`) and pass with the barrier.
- **Bench:** `bench/report/2026-06-15-wp-async-flow.md` — rate-shaping + multi-writer aggregate numbers,
  honest (no "0-cost" claim; pacing adds latency by design).

## Out of scope (v1 — follow-ups)
- **EDF / highest-priority-first / priority scheduling** — v1 is **round-robin only**, behind a **pluggable
  policy hook**; the OMG-QoS-anchored follow-ups are LATENCY_BUDGET/DEADLINE → EDF and TRANSPORT_PRIORITY →
  priority (see §OMG DDS / RTPS spec-compliance).
- Per-sample priority or deadline.
- **Runtime rate re-configuration** — properties are set at `make-flow-controller`; dynamic change is a
  follow-up.
- Pacing of discovery / HEARTBEAT / ACKNACK — only user DATA is paced (as with WP-ASYNC v1).
- Cross-process flow control — a controller is an in-process object (flow control is a sender-side concept).

## Decisions baked in (from brainstorming 2026-06-15 — confirm at spec review)
1. **Alt B** — shared `flow-controller` object + its own scheduler thread (owner-chosen, upgraded from the
   per-node-sender recommendation).
2. **Meter = bytes/period**, lazy-refill token bucket, **fragment-level** pacing (approved).
3. **Backpressure = block up to `max_blocking_time`** over a bounded KEEP_ALL cache (owner-chosen); `=0`
   degenerates to immediate reject.
4. **Scheduling = round-robin** for v1, behind a **pluggable policy hook** (EDF/HPF deferred; their standard-
   QoS anchors are LATENCY_BUDGET/DEADLINE and TRANSPORT_PRIORITY — see §OMG DDS / RTPS spec-compliance). The
   one v1 default introduced by Alt B that was not separately confirmed; flagged here for your review.
5. **Off by default, opt-in**; flush-on-stop teardown (approved).
6. **Not R6-gated** (standard DDS — no patent marker).
