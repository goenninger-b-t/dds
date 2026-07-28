# ADR 0092 — every teardown wait is bounded, and reports where it expired

- **Status:** **Accepted** — implemented, verified and falsified; see §8.
- **Date:** 2026-07-27
- **Requirements:** NFR-SEC-POSTURE (a teardown that never returns is a liveness failure), NFR-PORT (no
  per-OS syscall side-effect may be load-bearing), FR-LANG-8 / the no-conditions rule (a failure is a
  status value threaded to the caller, never a stack unwind)
- **Relates to:** **ADR 0091**, whose §5 and §7 recorded exactly these follow-ons and which this ADR
  closes; ADR 0016 §Teardown (the flow-controller per-node emit barrier); ADR 0050 §4.8 (the durability
  microservice server's accept/serve threads); ADR 0021 (the durability service runner); ADR 0082 §6/§7
  (the log service runner); ADR 0014/0042 (the leak-beats-use-after-free ranking this reuses)
- **Contract touched:** **`DDS.PAL` is widened** — `note-stuck-teardown`, `stuck-teardown-joins`,
  `reset-stuck-teardown-joins` are new exports, and `join-bounded` gains an optional **`SITE`** argument
  ahead of `TIMEOUT`. **Ten teardown functions now return `(values result status)`** where they returned a
  bare `T`. Consumers enumerated in §7.

---

## 1. The defect class

ADR 0091 fixed *one* unbounded wait — the one that had been caught hanging. It recorded the rest as a list
rather than a fix. This ADR is that list, closed.

**Nineteen unbounded waits** existed outside the test suite:

- **15 production `dds.pal:join` call sites** — DCPS (deadline monitor, autodiscovery announcer), dds-log
  (async worker, runner drain threads, supervisor monitor), SHMEM (receive thread), durability (service
  collect threads, discovery poll, process monitor, supervisor watcher, microservice accept + serve
  threads), disc (the WP-ASYNC sender), flow-control (the scheduler thread).
- **2 in-file test-harness joins** (`run-shmem-stress-test`, `run-rtps-protection-zeroalloc-test`).
- **2 copies of the flow-controller per-node emit barrier**.

Every one of them could stop a process forever at 0% CPU, exactly as the UDP receiver did.

### ⚠️ The most instructive one: a wait that *documented itself* as bounded

```lisp
(loop while (eq (flow-controller-current-emit-node controller) node)   ; block on any in-flight emit
      do (dds.pal:condvar-wait (flow-controller-emit-done-cv controller)
                               (flow-controller-lock controller) 0.5))   ; bounded: teardown can't wedge
```

The comment said *"bounded: re-check on wake, teardown can't wedge"*. The docstring went further: *"the wait
is bounded + re-checked so a logic error cannot wedge teardown forever."* **Both were false.** Only the
individual `condvar-wait` was bounded, at 0.5 s. The `loop while` around it retried **forever**, so a
`current-emit-node` that never clears — a scheduler wedged inside a send, or killed between arming the
barrier and reaching its `unwind-protect` — hangs teardown permanently, waking twice a second, at 0% CPU,
indistinguishable from the ADR 0091 hang.

**A wait assembled from bounded waits is not itself bounded.** This is the second time in two ADRs that a
docstring's confident claim was the thing standing between us and the bug (ADR 0091 §2: `udp-close`'s
"TRUE ON DARWIN"). **A docstring is a claim, not evidence.**

## 2. The two questions every site had to answer

Bounding a wait is the easy half. The hard half is what a *timeout* means, and it is **not** "carry on":

1. **Is the wait bounded?** — mechanical, and the same answer everywhere: `dds.pal:join-bounded`.
2. **What does this wait GUARD?** — site-specific, and it decides everything. Nearly every one of these
   joins exists so that a *subsequent* release is safe: a `free-static`, a `shm-detach`, a `store-close`, a
   `delete-participant`, a socket `close`. If the join cannot prove the thread stopped, **that release must
   not happen.**

Answering (1) without (2) converts a hang into a **use-after-free**, which is strictly worse: the hang is at
least loud and local.

## 3. The decision

**No wait in a teardown path is unbounded, and no expired wait is silent or treated as success.**

1. **Bound it** with `dds.pal:join-bounded` (default `*join-timeout-seconds*` = 5). One primitive, reused —
   not a second mechanism. The emit barrier, which is not a join, gets one shared helper
   (`%flow-emit-barrier`) instead of the two divergent copies it had.
2. **Report it where it is DETECTED.** `join-bounded` itself calls `note-stuck-teardown` on `:TIMEOUT`,
   under a `SITE` keyword naming the call site. A caller that ignores the returned status therefore
   *still cannot* make the failure silent — which matters, because most of these callers ignore return
   values (`ignore-errors (dds.pal:join th)` was the prevailing idiom).
3. **Skip exactly what the wait guarded**, and leak instead. Bounded, reported, retryable.

### ⚠️ A timed-out wait is NOT success

The ranking is the one ADR 0091 and the Zero-Copy refcount path already apply: **a bounded leak beats a
use-after-free on a live thread.** `stuck-teardown-joins` MUST read 0 after a healthy run; non-zero means a
resource was deliberately leaked because teardown could not prove it was safe to release.

## 4. The classification — what each timeout skips

| site keyword | what the wait guards | on `:TIMEOUT` |
|---|---|---|
| `:shmem-receiver` | `pshared-destroy` + `shm-detach` + `shm-destroy` | **skip all three.** The receiver parks on a condvar *inside the segment*: destroying it is a SIGSEGV in foreign code, not a leak |
| `:flow-unregister`, `:flow-remove-writer` | `stop-node`'s closes + frees; the writer's mid-drain step-refs | skip the ref release; **`stop-node` returns early and frees nothing** |
| `:flow-scheduler` | `free-static` of the controller SCRATCH | skip the free — the scheduler *builds datagrams into* SCRATCH. `THREAD` stays set so a retry re-joins |
| `:disc-async-sender` | `free-static` of `async-tx-msg`, and the node tail | skip; mark `teardown-leaked` |
| `:disc-unicast-rx`, `:disc-multicast-rx` | the node's buffer/pool/arena frees (ADR 0091) | skip; mark `teardown-leaked` |
| `:dcps-auto-announcer` | `stop-node` — the announcer **sends** through the node's announce buffers | skip the whole delete; participant stays intact + retryable |
| `:dcps-deadline-monitor` | `stop-node` — misses reach an application listener that may write | skip the whole delete |
| `:log-async-worker` | `close-logger`'s `delete-participant` — the worker spins and writes through it | skip the delete; leave the participant alive |
| `:log-runner-drain` | `close-log-collector` (sinks + participant) | **per index.** COLLECTORS and THREADS are parallel vectors, so one wedged drain costs only *its own* collector |
| `:log-supervisor-monitor` | `log-runner-stop` — a live monitor **respawns** drain threads onto collectors being closed | skip the runner stop entirely |
| `:durability-collect` | that pair's `stop-node`, and `store-close` | **per node pair**; store stays open |
| `:durability-discovery-poll` | the discovery node's `stop-node`, and `store-close` | skip both |
| `:microservice-accept-loop` | `tcp-close` of the listener (parked in `accept(2)`) + `store-close` | skip both — a reused fd number would be accepted on by the wrong socket |
| `:microservice-serve` | `store-close` of the inner store | skip the store close |
| `:durability-supervisor-watch` | (restarts) | **report only, proceed** — see §6 |
| `:durability-process-service-monitor`, `:durability-process-monitor` | nothing releasable | **report only, proceed** — polls `process-alive-p`, owns no store, node or buffer |

Two in-file test harnesses are bounded with **deliberately generous, site-specific** deadlines
(`:shmem-stress-tx` = its own `deadline-seconds` + 30, `:za2-concur` = 60). A blanket 5 s there would fail a
**healthy** run — the point of a test-harness bound is only to turn an infinite hang into a failed
assertion.

## 5. Why the report lives inside `join-bounded`

The alternative was a counter per owning struct, as `disc-node-stuck-receiver-teardowns` already is. Adding
that to eight more structs would have duplicated the same field eight times and — worse — made the report
*optional at every call site*, in a codebase whose prevailing idiom for these joins was to discard the
result. Counting at the point of detection makes the report **impossible to forget** and gives every future
teardown wait the same reporting for free.

It is REPORTED, never printed: `stuck-teardown-joins` returns `(values TOTAL ALIST)`, a queryable snapshot
in the same shape as `dds.log:logger-shed-counts` and `disc-node-stuck-receiver-teardowns`. A `format` to
`*error-output*` would be unconsumable by an application, untestable by a caller, and invisible in a
service; a signalled condition is barred outright and could unwind a receiver thread (ADR 0064).

## 6. Why not the alternatives

- **Blanket-replace all 19 with a 5 s bound.** Rejected: it breaks the two test harnesses, whose workers
  legitimately run 30 s, and — far worse — it answers question (1) while ignoring question (2), converting
  every hang into a use-after-free.
- **Propagate the status to the public API** (`delete_participant`, `close-logger`, `service-stop` all
  returning a failure to the application). Rejected as churn without benefit: the status is needed
  *locally*, by the code that performs the guarded release, and the central counter already carries the
  report outward. Where a status is genuinely useful to a caller it is returned (§7); it is not threaded
  through every layer.
- **Skip the runner stop on a `:durability-supervisor-watch` timeout.** Rejected deliberately. A live
  watcher can restart a service during teardown, but refusing to stop the runner would skip every
  `service-stop` and therefore every `store-close`, **losing the fsync of durable state**. Data integrity
  outranks a stranded thread, and the memory-safety argument does not apply: `service-stop` gates its own
  `store-close` on its own collect joins, so nothing is freed under a live thread either way.
- **Leave the emit barrier alone because it has never been observed hanging.** That was ADR 0091's
  position, and it is exactly the reasoning that left the UDP receiver unbounded until it hung in CI.

## 7. Consumers of the widened contract

- **`DDS.PAL`** (`pal-net.lisp`, shared by both impls — no reader conditional): three new exports;
  `join-bounded` gains optional `SITE` **before** `TIMEOUT`. Both pre-existing call sites (ADR 0091, in
  `stop-node`) passed neither, so they are unaffected and now pass site names.
- **Returning `(values … status)` where they returned `T`:** `stop-shmem-receiver`,
  `shmem-transport-close`, `flow-controller-unregister`, `flow-controller-remove-writer`,
  `destroy-flow-controller`, `%stop-auto-announcer`, `%deadline-monitor-stop`, `%logger-stop-worker`,
  `log-runner-stop`, `log-supervisor-stop`, `service-stop`, `supervisor-stop`, `%stop-process-service`,
  `microservice-server-stop`. Every existing caller either ignores the value or uses only the primary
  value, which is unchanged — so the extra value is additive.
- **`stop-node`** now consumes the flow-controller barrier status and the SHMEM close status, folding both
  into the existing `teardown-leaked` / `stuck-receiver-teardowns` reporting.
- **`delete-participant`** and **`close-logger`** now gate their teardown on their stop status. Their
  signatures are unchanged.

### A latent defect found while wiring this

`stop-node`'s ADR 0091 early return was `(return-from stop-node node)` while its declaimed ftype is
`(function (disc-node) (eql t))`. Under `(safety 0)` a caller compiled against that declaration may assume
`T`. Corrected to `t` here.

## 8. Verification

**Falsified, both directions — a green gate proves nothing until it has been seen red:**

- **Remove the bound** (`*join-timeout-seconds*` → `NIL`) and pin `current-emit-node`: the emit barrier is
  **still blocked after 8 s**, and returns *immediately* once the predicate is released — proving it was
  blocked on the predicate rather than dead. This is the pre-fix behaviour, reproduced on demand.
- **Wedge a SHMEM receiver**: `shmem-transport-close` returns `:TIMEOUT`, leaves `rx-thread` set (so the
  close is retryable), and the segment **is still mapped and readable through its SAP** — the
  `pshared-destroy` / `shm-detach` / `shm-destroy` were provably skipped. Reported as `:SHMEM-RECEIVER`.

**Permanent regression test** — `teardown-deadline`, 1.6 s, four legs: a clean join reports **nothing**
(no false positives); a wedged thread yields `:TIMEOUT` and is counted **under its own site keyword**; the
emit barrier **terminates**, asserted on *elapsed time* rather than only on the return value; and a real
participant create+delete moves the report by **zero**. This also closes part of ADR 0091 §7, which had to
record "no permanent regression test" — the *bounded-wait property* is now gated, though the original
intermittent close/park race still needs a soak target.

**Full gate:** **619/619 on SBCL and Clasp** · corpus 13+1, 0 mismatches on both · gate-build clean-cache
PASS on both impls · gate-hotpath / types (3177 defuns) / pal / nocond (0 to go) / drivers PASS · fuzz PASS
· gate-mem 1739 B/sample vs ceiling 1775 (unchanged — every edit is on a cold teardown path).

## 9. Residual

- `*join-timeout-seconds*` is one global deadline for every site. Adequate now (a pathological teardown
  costs at most 5 s per stuck thread), but a site that legitimately needs longer must pass its own, as the
  two test harnesses do.
- A stuck teardown is reported but **not** surfaced as a DDS status bit. The internal services (log runner,
  durability supervisor, SHMEM transport) are not DDS entities and have no status mask; the counter is the
  contract for them. If a participant-visible bit is wanted for the `stop-node` path, that is a follow-on.
- The ADR 0091 soak target for the original intermittent receiver race is still not written.
