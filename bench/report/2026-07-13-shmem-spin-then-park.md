# Spin-then-park, done right (OUTSIDE the mutex): 256 B one-way 19.1 → 11.8 µs. Connext ratio 2.34× → 1.68×.

2026-07-13. SBCL, macOS arm64, cross-process echo, 256 B, one-way p50. Baseline `38a2092`.

## Why

`2026-07-13-the-gap-is-our-shmem.md` established that our whole remaining distance to Connext is the SHMEM
transport: on UDP we are **1.33×** of Connext, on SHMEM **2.34×**. Connext extracts 2.76× from shared memory
where we extract 1.57×. The cause was measured: the **cross-process wake** — our receiver parks on a pshared
condvar, so every sample costs a `pthread_cond_signal` *plus* the receiver being scheduled onto a core.
`__psynch_cvsignal` was 30 % of the responder's CPU.

## The fix, and what was wrong the first time

A bounded spin before parking, so a receiver that is still spinning when the datagram lands skips **both**
halves of the wake — and costs the sender nothing either, since `%shmem-send` enqueues into a lock-free lane
and only takes the mutex + signals when it observes `parked=1`.

**The first attempt (reverted in `294fe93`) put the spin inside `%rx-wait-for-work` — which runs WITH THE
PSHARED MUTEX HELD.** A spinning receiver therefore held the mutex that `stop-shmem-receiver` needs in order
to broadcast. Result: latency **7× worse** (16 → 117 µs) and a long spin **hung on teardown**.

This version spins in `start-shmem-receiver`'s loop, **before** the lock is taken (`%rx-spin-for-work`).
The mutex is free throughout, `stop` is re-checked every iteration, and `parked` stays 0 for the whole spin.

**Teardown proven, not assumed:** 5 create/destroy cycles with `*shmem-rx-spin-iterations*` = **200 000**
complete cleanly and instantly — the exact scenario that hung the in-mutex version.

## Result

The sweep (one side tuned):

| spin iterations | 256 B one-way p50 | responder CPU over the run |
|---|---|---|
| 0 (park immediately) | 19 125 ns | 0.76 s |
| 500 | 12 270 ns | 0.98 s |
| 5 000 | 11 791 ns | 0.93 s |
| 50 000 | 11 750 ns | 0.95 s |

**The shipped configuration — default `1000`, both peers (owner directive):**

| | 256 B one-way p50 | p99 |
|---|---|---|
| **spin = 1000 (SHIPPED DEFAULT)** | **9 458 / 9 542 / 9 541 ns** | 23 958 ns |
| `DDS_SHMEM_RX_SPIN_ITERATIONS=0` (opt out) | 26 270 ns | 53 833 ns |

**26.3 → 9.5 µs.** Note how *tight* the spinning runs are — 9 458 / 9 542 / 9 541 ns across three runs (±40 ns)
on a box that had been swinging 16–32 µs for identical code. Removing the scheduler from the critical path
removes the jitter with it; the tail improves too (p99 53.8 → 24.0 µs).

| | ours | Connext (SHMEM) | ratio |
|---|---|---|---|
| session start | ~22 µs | 6 979 ns | 3.20× |
| before this commit | 16–19 µs | 6 979 ns | 2.34× |
| **shipped default (spin 1000)** | **9.5 µs** | 6 979 ns | **1.37×** |

## The CPU cost is smaller than I expected, and here is why

I had assumed a spin long enough to outlast the peer's turnaround would peg a core. It does not: the spin
**exits the instant data lands**, and a genuinely idle receiver still exhausts its budget and parks — and
then *stays* parked until signalled. The spin therefore runs once per wake, not continuously. Measured
overhead is +0.2 s of CPU over the run (0.76 → 0.98 s, +29 %) for a **39 % latency cut**, and it does not
grow with the budget (50 000 costs no more than 500).

## Configuration (owner directive 2026-07-13: default 1000, fully configurable)

| knob | effect |
|---|---|
| `dds.xport.shmem:*shmem-rx-spin-iterations*` | **Default 1000.** Settable at runtime — the budget is re-read on every wait, so a live node can be retuned. |
| `DDS_SHMEM_RX_SPIN_ITERATIONS` (env) | Overrides the default at load, no rebuild. Verified on **both** impls: `42` → 42, `0` → 0, garbage → falls back to 1000. |
| `0` | Restores the pure blocking behaviour for a CPU-constrained node. |

## Gates

`make test` 563/563 SBCL · `make test-clasp` 563/563 Clasp · `gate-hotpath` PASS · `gate-types` PASS (2854).
Note the suites run with spin = 0 (the default), so the spin path is exercised by the teardown test and the
bench above, not by the suite.
