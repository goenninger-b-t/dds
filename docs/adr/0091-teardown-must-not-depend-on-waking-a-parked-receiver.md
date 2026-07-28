# ADR 0091 — teardown must not depend on waking a parked receiver

- **Status:** **Accepted** — fixes a reproducible teardown hang. Implemented, verified and falsified; see §6.
- **Date:** 2026-07-27
- **Requirements:** NFR-PORT (no per-OS syscall side-effect may be load-bearing), NFR-SEC-POSTURE (a
  teardown that never returns is a liveness failure), FR-XPORT-5 (the receiver thread contract)
- **Relates to:** the `udp-close` shutdown(2) fix (Linux, found by CI) whose docstring this ADR corrects;
  ADR 0066 (`udp-recv`'s raw-recvfrom arm); ADR 0016 §Teardown (the flow-controller emit barrier, the other
  unbounded wait in `stop-node`)
- **Contract touched:** **`DDS.PAL` is widened** — `join-bounded`, `udp-set-receive-timeout`,
  `*join-timeout-seconds*`, `*udp-receive-timeout-seconds*` are new exports. `DDS.XPORT.UDP`
  `start-udp-receiver` gains an **optional** third argument (existing two-argument callers unaffected).
  `DDS.DISC` gains two counters. Consumers enumerated in §5.

---

## 1. The defect

`stop-node` hung forever, intermittently. Observed in a full-suite run as **61 minutes elapsed for 15
seconds of CPU** — blocked, not spinning — after which the suite reported nothing at all.

Captured live, with an all-thread backtrace watchdog:

```
dds-udp-rx  (alive=T)
  8: (DDS.PAL:UDP-RECV #<INET-SOCKET fd: -1 …> #(…) 65507)      <-- parked on a CLOSED fd
main thread (alive=T)
  10: (SB-THREAD::%CONDITION-WAIT #<WAITQUEUE "dds-udp-rx"> …)  <-- stop-node's join, forever
```

The receiver was inside `recvfrom(2)` when `stop-node` released its file descriptor, and **nothing woke
it**. Everything downstream — `service-stop`, `runner-stop`, `delete-participant`, the test, the suite —
blocked behind that one unbounded join.

**Intermittent** because it requires the receiver to be *inside* the syscall at the moment of close.

## 2. Three wakeup mechanisms, all of which fail here

| mechanism | why it does not save us |
|---|---|
| `close(2)` | Does not unblock a parked `recvfrom` on Linux — already known, which is why `udp-close` shuts down first. |
| `shutdown(2)` | On macOS/BSD, **fails `ENOTCONN` on an UNCONNECTED UDP socket** and wakes nothing. `udp-close` wraps it in `ignore-errors`, so the failure is silent. |
| `SO_RCVTIMEO` | Rescues a **freshly opened** socket (measured: returns in 0.256 s) but **does not rescue one already parked** when the fd is released (measured: still inside `UDP-RECV` on `fd: -1` minutes later). |

**⚠️ This ADR corrects a false claim in `udp-close`'s own docstring**, which stated the receiver "exits when
the socket is closed — which is TRUE ON DARWIN and FALSE ON LINUX". Darwin is **racy**, not correct. That
sentence cost an investigation: it contradicted the right hypothesis (macOS `shutdown`/`ENOTCONN`) and the
hypothesis was abandoned on its authority. **A docstring is a claim, not evidence.**

## 3. The decision

**Teardown must not depend on waking a parked receiver at all.** Signal the thread to leave *while its file
descriptor is still valid*, and never wait for it unboundedly.

Three layers, in order of what actually does the work:

1. **`flag → join → close`** (was `close → join`). `stop-node` sets `disc-node-rx-stopping` FIRST; each
   receiver loop tests it at the top of every iteration and returns. **This is the fix**: the unreachable
   state is never entered rather than merely survived.
2. **`SO_RCVTIMEO` on every UDP socket** (`udp-open` → `udp-set-receive-timeout`, delegating to the
   existing `tcp-set-recv-timeout` — one encoding of `struct timeval`, not two). This bounds how long a
   parked receiver takes to *notice* the flag: ≤ 250 ms. Cost: 4 idle wakeups/second per receiver thread,
   off the data path.
3. **`join-bounded`** at the teardown joins (5 s). A backstop that should never fire now.

### ⚠️ A timed-out join is NOT success

The joins exist to guarantee no receiver is still writing into a buffer `stop-node` is about to free. So on
`:TIMEOUT` the node is marked `teardown-leaked`, **the frees are skipped**, and
`stuck-receiver-teardowns` is incremented. **A bounded leak beats a use-after-free on a live thread** — the
same ranking the Zero-Copy refcount path already applies ("an under-count would be a use-after-free,
strictly worse than the leak"). `stuck-receiver-teardowns` MUST stay 0; non-zero means teardown could not
prove the receiver had stopped.

## 4. Why not the alternatives

- **`connect()` the socket to itself so `shutdown` works** — makes correctness depend on a second per-OS
  behaviour, which is the class of bug being fixed.
- **Self-wakeup datagram before close** — needs a stop flag anyway to close the re-park race, so it is the
  same design with an extra packet.
- **Bounded join alone** — leaves the receiver genuinely stuck ~40% of the time (measured, §6), leaking on
  every occurrence. Contains the symptom, does not remove it.

## 5. Consumers of the widened contract

- `DDS.PAL` (`pal-net.lisp`, shared by SBCL and Clasp — no reader conditional): new exports above.
- `DDS.XPORT.UDP` `start-udp-receiver`: optional `stop-fn`. **Both existing call sites** are in
  `dds-disc/disc.lisp` `start-node` (unicast + multicast) and both pass it.
- `DDS.DISC` `stop-node`: reordered; two new counters exported.
- **19 other `dds.pal:join` call sites remain UNBOUNDED** (dcps/log/xport/durability). They are not changed
  here — only the teardown path that was demonstrably hanging. Converting the rest is a follow-on; the
  `join-bounded` primitive now exists for it. → **CLOSED by ADR 0092.**
- **The other unbounded wait in `stop-node` is untouched**: the flow-controller unregister barrier, which
  "BLOCKS until the SHARED scheduler is not mid-emit on NODE" (ADR 0016 §Teardown). It has not been
  observed hanging, and is recorded here so the next teardown hang starts from a shorter list.
  → **CLOSED by ADR 0092**, which found that barrier's own comment and docstring *claimed* it was bounded
  when the `loop while` around its bounded `condvar-wait` retried forever.

## 6. Verification

**Reproduction** (the tool matters as much as the fix): an all-thread backtrace watchdog that fires on
**lack of progress** — never on elapsed time, which cries hang on a healthy slow run — and dumps every
thread with `:count ≥ 14` (frames 0–7 are interrupt plumbing). It turned an hour of silence into a named
stuck frame in minutes. To tell *blocked* from *spinning*, sample the same thread 4× at 3 s intervals.

**Staged measurement**, 25 iterations of `run-durability-supervisor-test` (a healthy iteration is 0.3 s):

| build | worst iteration | iterations > 3 s |
|---|---|---|
| before | — | **hung at iteration 3, every time** |
| receive timeout + bounded join only | 5.29 s | 10 / 25 — contained, still stuck and leaking |
| **+ the `flag → join → close` reorder** | **1.40 s** | **0 / 25** |

**FALSIFIED**: remove the `rx-stopping` signal *and* make the join unbounded again ⇒ **hangs at iteration
0**. A green gate proves nothing until it has been seen red.

**Full gate**: 618/618 on SBCL and Clasp · corpus 13+1, 0 mismatches on both · gate-hotpath / types / pal /
nocond / drivers PASS · gate-mem 1739.6 vs ceiling 1775 · gate-build clean-cache PASS on both impls.

## 7. Follow-ons, recorded rather than done

- **No permanent regression test.** Reproduction needs ~25 iterations (~35 s), too slow for `make test`; it
  belongs in a soak/nightly target. Until then this defect is guarded by an ADR and a counter, not a gate.
  → **PARTLY CLOSED by ADR 0092**: the `teardown-deadline` test (1.6 s) now gates the *bounded-wait
  property* and its report. The original intermittent close/park race still needs the soak target.
- The 19 unbounded `dds.pal:join` sites (§5). → **CLOSED by ADR 0092.**
- The flow-controller emit barrier (§5). → **CLOSED by ADR 0092.**
