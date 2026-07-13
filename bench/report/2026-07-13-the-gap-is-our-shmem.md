# The comparison IS fair — and the gap is almost entirely our SHMEM transport. On UDP we are 1.33× of Connext.

2026-07-13. SBCL, macOS arm64, cross-process echo, 256 B, one-way p50. All four cells measured in ONE
session, same machine, same harness, same QoS (RELIABLE / KEEP_ALL / VOLATILE / XCDR2, single in-flight).

## Why this was measured

Every ratio this project has published is against Connext's 256 B p50 of ~7 µs — but nobody had verified
**which transport that number came from**. Connext enables UDPv4 *and* SHMEM for same-host by default and
prefers SHMEM; so do we (`*shmem-enabled*` is T for same-host). We had already measured that our own
transport choice moves the number by ~10 µs — **larger than several of the optimisations landed this
session** — so an unverified transport assumption could have invalidated the whole comparison.

Connext forced to UDPv4 only via a QoS profile (`transport_builtin/mask = UDPv4`).

## The table

| | ours | Connext | ratio |
|---|---|---|---|
| **UDPv4 only** | 25 375 / 25 750 ns | **19 270 ns** | **1.33×** |
| **SHMEM (both defaults)** | 17 229 / 15 354 ns | **6 979 ns** | **2.34×** |
| *speedup SHMEM buys* | **1.57×** | **2.76×** | |

## What it means

**1. The comparison was fair.** Both stacks defaulted to SHMEM, so the ratios in every earlier report
(2.4×–3.2× at 256 B) are apples-to-apples. That caveat is now closed.

**2. On UDP we are 1.33× of Connext.** Our RTPS engine, codec, history cache and DCPS layer — everything
above the transport — are within a third of Connext's, *on the same transport*. After this session's fixes
there is no large algorithmic defect left in that stack.

**3. THE GAP IS OUR SHMEM TRANSPORT.** Connext extracts **2.76×** from shared memory; we extract **1.57×**.
That difference is the whole story:

```
  if our SHMEM were as effective as Connext's:   25.6 us / 2.76  =  ~9.3 us
  which against Connext's 6.98 us would be:      ~1.3x
```

**4. The cause is already identified and measured.** The cross-process WAKE: our SHMEM receiver parks on a
pshared condvar, so every sample costs a `pthread_cond_signal` from the sender plus the receiver having to
be *scheduled* onto a core before it can look at the data. Measured at ~6 µs of the ~16 µs one-way, and
`__psynch_cvsignal` was the single largest item (30 %) in the responder's CPU profile
(`2026-07-13-syscall-budget-and-a-failed-spin.md`). Connext's shared-memory notification evidently does not
pay this per sample.

## What this changes about the plan

Stop looking for engine-level inefficiency: on UDP, the engine is already at 1.33×. **The remaining work is
the SHMEM notification path** — task #24 (spin-then-park, done correctly this time: OUTSIDE the pshared
mutex, which is what made the first attempt fail).

It also means the `declaim`/constant-factor pass (#17) is still the wrong lever — it cannot touch a
scheduler wake.

## Caveat

Single-in-flight latency only, one machine, one payload size, and this box has been noisy (identical code
measured 16–32 µs at different times through the session). The 1.33× UDP figure should be re-confirmed on a
quiet machine before it is quoted as a headline.
