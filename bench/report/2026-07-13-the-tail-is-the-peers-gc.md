# The ~10 ms tail is a GC pause in the PEER — and with GC out of the way we BEAT Connext's tail

2026-07-13, `21aa721`. SBCL, macOS arm64, cross-process echo, 256 B, 6000 samples.

## The question

The current ratio table shows our worst sample at **~9–10 ms** at every payload size, against Connext's
~0.2 ms — we lose the tail by 15–60×. `REQUIREMENTS.md` §7 predicted exactly this ("a GC'd runtime cannot, in
general, match a pre-alloc C++ stack on tail latency"). Before optimising on that theory, test it.

## The measurement — and the trap in it

| configuration | p50 | p99 | **max** | GCs in the pinger |
|---|---|---|---|---|
| default | 7 875 ns | 18 542 ns | **9 901 812 ns** | **0** |
| pinger nursery = 1 GB | 10 562 ns | 32 667 ns | **10 358 375 ns** | **0** |
| **both sides nursery = 1 GB** | 9 229 ns | 28 896 ns | **100 541 ns** | 0 |

**The first two rows falsify the obvious hypothesis.** The measuring process performed **zero** GCs and the
10 ms outlier appeared anyway — enlarging *its* nursery changed nothing. A GC pause in the process you are
timing is not the only way to get a tail; the peer can stall just as well, and the RTT cannot tell them apart.

**The third row is the answer: the pause is in the RESPONDER.** It allocates ~5.9 KB/sample, collects, and
its pause stalls the echo — which arrives at the pinger as a ~10 ms round trip. Silence the peer's GC and the
worst sample collapses **9.9 ms → 100 µs, a 98× improvement**.

## Two consequences

**1. With GC out of the way we BEAT Connext's tail.** 100 µs worst-sample vs Connext's ~160–230 µs. The tail
is therefore **not** an intrinsic penalty of a GC'd runtime, as `REQUIREMENTS.md` §7 assumed — it is the
direct, mechanical consequence of our residual per-sample allocation. Remove the allocation and the
prediction does not hold.

This also explains why the original "we beat Connext's tail by 2.2×" claim was irreproducible: it was almost
certainly measured in a GC-quiet window. The claim was *right about the ceiling* and wrong to present a lucky
run as the steady state.

**2. The 1 GB nursery is NOT a fix and must not be shipped as one.** It defers the collection; a long-running
node still collects, and the deferred pause is *larger*. It is a diagnostic instrument, nothing more. The
only real fix is the NFR-MEM mandate that was there all along: **zero bytes per sample in steady state.**

## What this changes

Earlier today I concluded, from the median, that allocation work "bought no latency" (`2647227`). That was
true for the median and **wrong for the tail** — and the tail is where our worst deficit is. The remaining
~5.9 KB/sample is now the single highest-value target in the performance programme:

- it is the whole of the 15–60× tail deficit,
- it is the standing NFR-MEM/NFR-PERF-8 requirement (0 B/sample),
- and it is the one lever that a spin, a syscall cut, or a `declaim` cannot touch.

Next: drive the residual RX/TX allocation to zero (arena + reuse, the pattern already proven on the TX pooled
path and the secured decode pool), then re-measure the tail with enough samples that p99.99 is a percentile
rather than the max.
