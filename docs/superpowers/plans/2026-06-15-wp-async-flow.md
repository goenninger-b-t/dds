# WP-ASYNC-FLOW Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** The flow-control half of FR-PF-2 — a shared, RTI-style `flow-controller` object with its own scheduler thread that paces the user-data byte rate of its associated writers via a token bucket (bytes/period, fragment-level), with DDS-standard block-up-to-`max_blocking_time` backpressure. Off by default; opt-in; wire-invisible (compliant by construction).

**Architecture:** A `flow-controller` (token bucket + registered writers + round-robin policy hook + scheduler thread + lock/cv) drives a per-datagram "step" send (one datagram at a time, byte-exact token accounting, RR interleaving) refactored out of the existing flush-all path. `writer-write` gains block-up-to-`max_blocking_time` backpressure over the bounded KEEP_ALL HistoryCache. Lock ordering: the controller lock is never held across a send (released before the writer lock).

**Tech Stack:** Common Lisp (SBCL + Clasp); `dds.disc` (sender/dataplane), `dds.rtps.reliable` (writer/HistoryCache), `dds.pal` (threads/locks/condvars/`monotonic-ns`), `dds.core.buffer` (foreign tx buffers).

**Authoritative spec:** `docs/superpowers/specs/2026-06-15-wp-async-flow-design.md`. **Conventions:** `defun*`+full ftype (FR-LANG-8); one-line comments; the token-bucket acquire path is 0-alloc + CLOS-free (NFR-MEM/NFR-CLOS); no reader conditionals outside `dds-pal/`; SBOM auto-staged; FR-LANG-7 bench; **NO R6 marker** (flow control is standard DDS, not patent-gated); commit autonomously with each task's message; **no AI-assistant/Co-Authored-By attribution** anywhere.

## Verified grounding (from the code)
- **Send path** (`src/dds-disc/dataplane.lisp`): `%push-data-buf(node,buf)` (:524) flushes ALL unsent — for each `%reader-push-targets` group it calls `%send-changes-packed` with `(%merge-unsent writer ...)`, coalescing DATA+HEARTBEAT into datagrams via `%send-packed` (:69). The unsent watermark is per-reader; `writer-unsent-list` advances `unsent-base` (send-once, RTPS 2.5 §8.4.2.2).
- **Writer** (`src/dds-rtps/reliable.lisp`): `writer-write` (:56) = `%with-writer-lock` + `hc-add-change` (NO blocking today). `reader-proxy.unsent-base` (:27) is the send watermark. `writer-heartbeat`/`%changes-from`/`writer-unsent-list` (:83–120).
- **HistoryCache** (`src/dds-rtps/history.lisp`): `make-history-cache(kind depth resource-limits type-support)` honours HISTORY (`:keep-last`/`:keep-all`) + RESOURCE_LIMITS (`max-samples`, nil=unlimited); `hc-add-change` enforces them (returns a status symbol); `hc-purge-below` frees acked space.
- **Async pattern to mirror** (`dataplane.lisp` :569–609): `enable-async` spawns `%async-sender-loop`; `%async-signal` sets `async-pending` + `condvar-signal` under `async-lock`; the sender owns `async-tx-msg`; `stop-node` joins it. Reuse this lock/cv/own-buffer shape for the controller.
- **PAL**: `dds.pal:monotonic-ns`, `make-lock`/`with-lock`, `make-condvar`/`condvar-wait`(timeout)/`condvar-signal`/`condvar-broadcast`, `spawn`/`join-thread`. `dds.pal:bytes-consed` (SBCL) for the 0-alloc test.

## File structure
- **Create** `src/dds-disc/flow-control.lisp` — `flow-token-bucket` + `flow-controller` + the scheduler loop + the RR policy hook. Added to `dds-disc.asd` (after `dataplane`) + package exports.
- **Modify** `src/dds-disc/dataplane.lisp` — refactor `%send-changes-packed` into a per-datagram **step** + a flush-all wrapper; `publish-sample`/`%dispose-or-unregister` signal the associated controller.
- **Modify** `src/dds-disc/disc.lisp` (+ `packages.lisp`) — disc-node slot `flow-controller`; `stop-node` unregisters before teardown.
- **Modify** `src/dds-rtps/reliable.lisp` (+ `packages.lisp`) — `writer-write` block-up-to-`max_blocking_time` backpressure (space-available CV); a purge/send hook signals it.
- **Create** `docs/adr/0016-async-flow-control.md` — the `flow-controller` API + the `writer-write` backpressure contract change.
- **Test**: `src/dds-tests/echo-test.lisp` (token-bucket unit, 0-alloc), `src/dds-tests/integration-test.lisp` (step-equivalence, pacing, multi-writer RR, backpressure, concurrency stress). **Bench**: `bench/report/2026-06-15-wp-async-flow.md`. **Docs**: README P4, `docs/wiki/transports.md`, `docs/verification.csv`, `docs/provenance.md`.

---

# Phase A — Token bucket (pure core) + ADR 0016

### Task A1: ADR 0016 + the `flow-token-bucket` (deterministic, injected clock)
**Files:** Create `docs/adr/0016-async-flow-control.md`, `src/dds-disc/flow-control.lisp`; Modify `dds-disc.asd`, `src/dds-disc/packages.lisp`, `src/dds-tests/echo-test.lisp`.
- [ ] **Step 1: ADR 0016** (match ADR 0015 style): WP-ASYNC-FLOW (FR-PF-2); the `flow-controller` public API (`make-flow-controller`/`flow-controller-associate`/`destroy-flow-controller`), the token-bucket semantics, **round-robin v1 behind a pluggable policy hook** (LATENCY_BUDGET/DEADLINE→EDF, TRANSPORT_PRIORITY→priority as standard-QoS-anchored follow-ups), and the **`writer-write` contract change** (may now block up to `max_blocking_time` and return a TIMEOUT sentinel on a full KEEP_ALL cache — list `publish-sample`/`%dispose-or-unregister` as consumers). Note flow control is wire-invisible / additive / not R6.
- [ ] **Step 2: failing unit test** `run-flow-token-bucket-test` (register in `run-all-tests`): with an **injected clock** (a closure returning a settable ns counter), assert: a fresh bucket `(make-flow-token-bucket :tokens-per-period 1000 :period 1000000000 :max-burst 1000)` starts full; `%fb-acquire` of 400 succeeds twice then the 3rd (cost 400, only 200 left) returns a positive deficit-wait ns; after advancing the clock half a period it has ~500 tokens; never exceeds `max-burst`; an over-`max-burst` cost (e.g. 1500) returns a finite wait (no error); zero/negative rate or period signals at `make-flow-token-bucket`.
- [ ] **Step 3:** implement in `flow-control.lisp`:
```lisp
(defstruct* (flow-token-bucket (:constructor %make-flow-token-bucket))
  "WP-ASYNC-FLOW token bucket (FR-PF-2): TOKENS bytes available, refilled TOKENS-PER-PERIOD every PERIOD ns,
   capped at MAX-BURST; CLOCK-FN returns the current ns (injectable for deterministic tests). Hot-path-pure:
   defstruct + fixnum arithmetic, 0-alloc, CLOS-free."
  (tokens-per-period 0 :type (integer 1))
  (period 1 :type (integer 1))
  (max-burst 1 :type (integer 1))
  (tokens 0 :type (integer 0))
  (last-refill 0 :type (integer 0))
  (clock-fn nil :type function))

(defun* make-flow-token-bucket (&key tokens-per-period period max-burst (clock-fn #'dds.pal:monotonic-ns))
    (function (&key (:tokens-per-period (integer 1)) (:period (integer 1)) (:max-burst (integer 1))
                    (:clock-fn function)) flow-token-bucket)
  "Build a token bucket; start full at MAX-BURST. Signals on non-positive rate/period (caller-config error)."
  (let ((now (funcall clock-fn)))
    (%make-flow-token-bucket :tokens-per-period tokens-per-period :period period :max-burst max-burst
                             :tokens max-burst :last-refill now :clock-fn clock-fn)))

(defun* %fb-refill (b)
    (function (flow-token-bucket) (integer 0))
  "Lazily add elapsed*rate tokens (capped at MAX-BURST); advance LAST-REFILL. Returns the new token count."
  (let* ((now (funcall (flow-token-bucket-clock-fn b)))
         (elapsed (max 0 (- now (flow-token-bucket-last-refill b))))
         (added (floor (* elapsed (flow-token-bucket-tokens-per-period b)) (flow-token-bucket-period b))))
    (when (plusp added)
      (setf (flow-token-bucket-tokens b) (min (flow-token-bucket-max-burst b)
                                              (+ (flow-token-bucket-tokens b) added))
            (flow-token-bucket-last-refill b) now))
    (flow-token-bucket-tokens b)))

(defun* %fb-acquire (b cost)
    (function (flow-token-bucket (integer 0)) (integer 0))
  "Try to consume COST bytes. Returns 0 on success (tokens decremented). On shortfall returns the
   deficit-wait in ns (ceil((cost-tokens)/rate)) WITHOUT consuming — caller sleeps then retries. An
   over-MAX-BURST cost waits for a full bucket (never deadlocks)."
  (%fb-refill b)
  (let ((have (flow-token-bucket-tokens b))
        (need (min cost (flow-token-bucket-max-burst b))))
    (cond ((>= have cost) (decf (flow-token-bucket-tokens b) cost) 0)
          (t (max 1 (ceiling (* (- need have) (flow-token-bucket-period b))
                             (flow-token-bucket-tokens-per-period b)))))))
```
- [ ] **Step 4:** wire `flow-control.lisp` into `dds-disc.asd` (after `dataplane`); export `make-flow-token-bucket` etc. as needed (the bucket is internal; export the controller API later). Run `run-flow-token-bucket-test` SBCL+Clasp → pass. `make gate-types` + `make gate-hotpath` (add `flow-control.lisp` to the hot-path file list for the acquire path) PASS.
- [ ] **Step 5: commit** `feat(disc): WP-ASYNC-FLOW token bucket (bytes/period, lazy refill, injectable clock) + ADR 0016 (FR-PF-2)`

---

# Phase B — Per-datagram step send (the refactor)

### Task B1: refactor `%send-changes-packed` into a per-datagram step + flush-all wrapper
**Files:** Modify `src/dds-disc/dataplane.lisp`; Test `src/dds-tests/integration-test.lisp`.
- [ ] **Step 1: failing test** `run-flow-step-equivalence-test` (register): build a node with K small unsent changes; capture the datagram byte-sequence produced by the existing flush-all (`%push-data-buf`) into a recording stub (a fake send capturing each datagram's bytes); then drive the same unsent set through the new per-datagram **step** and capture its datagrams; assert the **two datagram byte-sequences are identical** (the step refactor is wire-equivalent). Repeat with one large (DATA_FRAG) sample → identical fragment sequence.
- [ ] **Step 2:** refactor the inner of `%send-changes-packed` so the datagram-building loop body becomes a reusable step `%emit-next-datagram(node, buf, state)` → `(values bytes-sent more-remain-p new-state)` where `state` threads the remaining items/fragment cursor; the existing `%send-changes-packed` becomes `(loop ... (%emit-next-datagram ...) until done)` — **byte-identical** (it is literally the same body, now stepped). Keep `%push-data-buf` calling the wrapper unchanged (regression). Expose `%emit-next-datagram` (or a node-level `%flow-step-emit(node, buf)` that pulls the next unsent datagram for the node's user writer and emits one) for the scheduler.
- [ ] **Step 3:** run `run-flow-step-equivalence-test` SBCL+Clasp → pass; full suite → no regression (the flush-all path is byte-identical). `make gate-hotpath` PASS.
- [ ] **Step 4: commit** `refactor(disc): WP-ASYNC-FLOW per-datagram step send (build-one-datagram), flush-all = step loop, byte-identical (FR-PF-2)`

---

# Phase C — FlowController object + scheduler thread + round-robin + pacing

### Task C1: the `flow-controller` object + lifecycle + association
**Files:** Modify `src/dds-disc/flow-control.lisp`, `src/dds-disc/disc.lisp` (+ `packages.lisp`).
- [ ] **Step 1: failing test** `run-flow-controller-lifecycle-test` (register): `make-flow-controller` returns an object with its scheduler thread running; `flow-controller-associate` registers a node (a 2nd associate of the same node → error); `destroy-flow-controller` stops+joins the thread (assert the thread is not alive after). No samples needed yet.
- [ ] **Step 2:** add the `flow-controller` defstruct (token bucket; `writers` list of registered nodes; `rr-cursor`; `policy-fn` defaulting to round-robin; `lock`; `cv`; `thread`; `stop`; `scratch` octet-buffer; `pending` set/flags per node) + `make-flow-controller(&key tokens-per-period period max-burst (scheduling :round-robin) (clock-fn ...))` (validates, builds the bucket, allocates scratch, spawns `%flow-scheduler-loop`) + `destroy-flow-controller` (set stop, broadcast cv, join, flush remaining ignoring the bucket, unblock blocked writers) + `flow-controller-associate(controller node)` / `flow-controller-unregister(controller node)` (under the controller lock; reject double-association; set/clear the node's `disc-node-flow-controller` slot). Add the `flow-controller` slot to `disc-node`.
- [ ] **Step 3:** the round-robin policy `%flow-policy-round-robin(controller)` → the next registered node with pending work after `rr-cursor`, advancing the cursor; NIL if none. (Pluggable: `policy-fn` is called by the scheduler; the spec's EDF/priority follow-ups replace this fn.)
- [ ] **Step 4:** run SBCL+Clasp; commit `feat(disc): WP-ASYNC-FLOW flow-controller object — lifecycle, association, round-robin policy hook (FR-PF-2)`

### Task C2: the scheduler loop (pacing) + publish-sample integration
**Files:** Modify `src/dds-disc/flow-control.lisp`, `src/dds-disc/dataplane.lisp`.
- [ ] **Step 1: failing test** `run-flow-pacing-test` (register, SBCL timing): associate a node with a low-rate controller (e.g. 10_000 bytes/100ms, burst 10_000); publish N samples totalling B bytes; assert the elapsed wall time to drain ≈ B/rate within tolerance (rate-shaping observed). Add `run-flow-multiwriter-rr-test`: two nodes on one controller, assert their datagrams interleave (RR) and the aggregate rate is shaped. (Use `monotonic-ns`; tolerant bounds; mark SBCL — Clasp timing may vary, pass-skip if flaky.)
- [ ] **Step 2:** `%flow-scheduler-loop(controller)`:
  - Loop. Under the controller lock: timed `condvar-wait` (period-bounded) until any registered node has pending work or `stop`. If `stop` → flush-all-ignoring-bucket each node, return.
  - Pick the next pending node via `policy-fn`. Release the controller lock.
  - **Build** the node's next datagram into the controller `scratch` (the Phase-B `%flow-step-emit` build-only variant — build, don't send yet); its `length` is the cost. Re-take the controller lock; `%fb-acquire(bucket, cost)`. If a deficit-wait ns > 0 is returned: release the lock, `sleep` the deficit (or `condvar-wait` it, so a new signal can re-evaluate), continue the loop (the built datagram is HELD in scratch — do not rebuild). If 0 (acquired): release the lock, then **send** the held datagram (the actual `sendto`, taking the writer lock as the existing send does), advance the writer's unsent watermark for that one datagram. Clear the node's pending mark when its unsent is drained.
  - **Lock ordering:** the controller lock is released before the build's writer-lock access and before the send — never hold both (mirror `%async-sender-loop`).
- [ ] **Step 3:** in `publish-sample` / `%dispose-or-unregister` (dataplane.lisp): when `(disc-node-flow-controller node)` is set, after `writer-write`, **mark the node pending + signal the controller cv** (a new `%flow-signal(controller, node)`), instead of `%async-signal`/`%push-data`. (Order the cond: flow-controller first, then async-thread, then batch.)
- [ ] **Step 4:** run SBCL (+Clasp where timing allows); full suite no regression; `make gate-hotpath`+`mem` PASS. Commit `feat(disc): WP-ASYNC-FLOW scheduler thread — round-robin paced send, fragment-level token accounting (FR-PF-2)`

---

# Phase D — Backpressure (block up to max_blocking_time)

### Task D1: `writer-write` blocks on a full KEEP_ALL cache up to `max_blocking_time`
**Files:** Modify `src/dds-rtps/reliable.lisp` (+ `packages.lisp`); Test `integration-test.lisp`.
- [ ] **Step 1: failing test** `run-flow-backpressure-test` (register): a writer whose HistoryCache is KEEP_ALL with a tiny `max_samples` (e.g. 3) and a stalled drain (no controller send / no ACKs); `writer-write` (via publish-sample) of the 4th sample BLOCKS then returns the **TIMEOUT** sentinel after ~`max_blocking_time`; then free space (purge/ack) and assert a subsequent `writer-write` succeeds (unblocks). Add a `max_blocking_time = 0` case → immediate timeout (no block).
- [ ] **Step 2:** give `rtps-writer` a `space-cv` (condvar) + the writer lock already exists. In `writer-write`: after taking the writer lock, if the cache is `:keep-all` and `(>= (hc-count) max-samples)`, `condvar-wait` on `space-cv` (releasing the writer lock) until space frees OR `max_blocking_time` elapses (deadline via `monotonic-ns`); on timeout return a `:timeout` sentinel (change `writer-write`'s return to `(or integer (eql :timeout))` — ftype + the ADR contract). On space available, proceed with `hc-add-change`. `max_blocking_time = 0` → no wait, immediate `:timeout` if full.
- [ ] **Step 3:** signal `space-cv` wherever the cache frees space — `hc-purge-below` callers (writer-on-acknack purge) and after a successful paced send that advances acked-base — add a `%writer-signal-space(writer)` (broadcast `space-cv`) on purge. `publish-sample` surfaces `:timeout` as `RETCODE_TIMEOUT` to its caller (return value / condition — match the DCPS write() contract).
- [ ] **Step 4:** run SBCL+Clasp; full suite no regression (default unlimited `max-samples` ⇒ never blocks, unchanged). Commit `feat(rtps): WP-ASYNC-FLOW backpressure — writer-write blocks up to max_blocking_time on a full KEEP_ALL cache, RETCODE_TIMEOUT (FR-PF-2, FR-QOS)`

---

# Phase E — Integration, defaults, teardown, concurrency

### Task E1: off-by-default regression + teardown + concurrency stress
**Files:** Modify `src/dds-disc/disc.lisp` (stop-node), `src/dds-disc/dataplane.lisp`; Test `integration-test.lisp`.
- [ ] **Step 1: failing tests** (register): `run-flow-off-byte-identical-test` — no controller associated ⇒ the send path + wire bytes are byte-identical to pre-WP (capture a publish with/without the WP loaded path; assert identical). `run-flow-teardown-test` — `stop-node` on a node associated with a controller unregisters it (the scheduler no longer touches the freed node) and flushes the backlog; `destroy-flow-controller` with a blocked writer unblocks it (TIMEOUT) and joins the thread. `run-flow-concurrency-stress-test` (SBCL) — 2–3 writer threads publishing into one controller while the scheduler drains for ~1s: assert no deadlock (completes), all samples eventually sent (reliable completeness), clean teardown (thread joined, no error).
- [ ] **Step 2:** `stop-node`: if `(disc-node-flow-controller node)`, `flow-controller-unregister` it BEFORE freeing the node's buffers/threads (no use-after-free by the scheduler). Confirm the cond-order in `publish-sample` (flow-controller > async > batch) and that lifecycle changes also signal the controller.
- [ ] **Step 3:** run SBCL+Clasp; `make gate-hotpath`+`gate-types`+`mem` PASS; full suite green both impls. Commit `feat(disc): WP-ASYNC-FLOW integration — off-by-default byte-identical, teardown unregister, concurrency-safe (FR-PF-2)`

---

# Phase F — bench + docs

### Task F1: rate-shaping + multi-writer bench (FR-LANG-7, honest)
- [ ] `run-bench-async-flow` + `make bench-async-flow` → `bench/report/2026-06-15-wp-async-flow.md`: the achieved byte rate vs the configured rate (shaping accuracy); single vs multi-writer aggregate; the added latency (pacing trades latency for rate control — state it honestly, no "0-cost" claim); the unpaced (`enable-async`) baseline for comparison. Commit `bench(disc): WP-ASYNC-FLOW rate-shaping + multi-writer bench (FR-PF-2, FR-LANG-7)`

### Task F2: docs (ADR 0016 finalize, README, wiki, verification, provenance)
- [ ] ADR 0016 "Final design (as implemented)"; README P4 (async + flow control: the `flow-controller` API, RR v1 + the LATENCY_BUDGET/DEADLINE→EDF + TRANSPORT_PRIORITY→priority follow-ups, block-up-to-`max_blocking_time` backpressure, wire-invisible/standard-DDS); `docs/wiki/transports.md` (a worked flow-controller example + the three send modes sync/async-unpaced/async-paced); `docs/verification.csv` FR-PF-2 row; `docs/provenance.md` (clean-room — generic token-bucket flow control, no external source). Commit `docs(disc): WP-ASYNC-FLOW ADR 0016 final + README + wiki + verification + provenance (FR-PF-2, §5.1)`

---

## Self-review
- **Spec coverage:** token bucket→A1; per-datagram step (fragment-level)→B1; flow-controller object + scheduler + RR + pacing→C1/C2; block-up-to-`max_blocking_time` backpressure→D1; off-by-default + teardown + concurrency→E1; bench→F1; docs/ADR/QoS-anchored-followups→A1/F2; pluggable policy→C1. All covered.
- **Placeholder scan:** the must-confirm-at-impl points carry explicit "confirm vs %send-changes-packed / writer-write contract" notes, not TODOs. The step refactor's byte-identical claim is gated by `run-flow-step-equivalence-test` (the oracle).
- **Type consistency:** `flow-token-bucket` (tokens/period/max-burst/clock-fn), `%fb-acquire`→ns-or-0, `flow-controller` (bucket/writers/rr-cursor/policy-fn/lock/cv/thread/scratch/pending), `%flow-step-emit`/`%emit-next-datagram`→(values bytes more-p), `writer-write`→`(or integer (eql :timeout))` (ADR-recorded contract change). Consistent A→F.
- **Contract changes (ADR 0016):** the new `flow-controller` API + `writer-write`'s return-type/blocking change (consumers: `publish-sample`, `%dispose-or-unregister`, all `writer-write` callers — audit them in D1).
- **Binary gates:** correctness/stability — the concurrency stress test (E1) + the lock-ordering rule (controller lock never held across a send) guard deadlock/UAF; reliable completeness (pacing delays, never drops) is asserted. Wire-invisible ⇒ no interop risk (off-by-default byte-identical, E1).
- **Hot-path:** the token-bucket acquire is 0-alloc/CLOS-free (A1, gate-hotpath/mem). NOT R6 (standard DDS).
