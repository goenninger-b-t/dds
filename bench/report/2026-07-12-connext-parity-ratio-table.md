# The Connext parity ratio table — the evidence (WP-1 complete)

2026-07-12. macOS arm64, UDPv4 loopback, **both stacks cross-process**, RELIABLE / KEEP_ALL / VOLATILE /
XCDR2, single in-flight, one-way := RTT/2, listener-driven wait on both sides, nearest-rank percentiles
computed by the identical rule. Ours = `dds.bench:run-echo-pinger` (DCPS path, `write-sample` → codec →
engine). Reference = `interop/perftest/connext/perf_pinger` ↔ `perf_responder`, same protocol, same type,
same QoS, written clean-room against the public Connext Modern C++ API.

**RTI Perftest is not bundled with Connext 7.3.1**, so the harness is a symmetric echo implemented
identically on both stacks — which is what makes the ratio apples-to-apples rather than a comparison of two
different methodologies.

## The table (one-way latency, nanoseconds)

| payload | metric | **ours** | **Connext** | **ratio** | owner target ≤1.05× |
|---|---|---|---|---|---|
| **256 B** | p50 | 22 500 | **7 041** | **3.20×** | ✗ |
| | p99 | 32 500 | 15 104 | **2.15×** | ✗ |
| | **p99.99** | **53 500** | 118 250 | **0.45×** | ✅ **we are 2.2× FASTER** |
| **32 B** | p50 | 18 000 | 9 417 | 1.91× | ✗ |
| | p99.99 | 61 500 | 149 604 | **0.41×** | ✅ **2.4× faster** |
| **1 KB** | p50 | 104 000 | 6 854 | **15.2×** | ✗✗ |
| **4 KB** | p50 | 602 500 | 9 270 | **65×** | ✗✗✗ |
| **16 KB** | p50 | 1 339 000 | 11 729 | **114×** | ✗✗✗ |

## What the table says

**1. The tail is already won.** Our p99.99 is **2.2× better than Connext's** at 256 B and 2.4× better at
32 B. This is the metric `REQUIREMENTS.md` §7 rated *low confidence* ("a GC'd runtime cannot, in general,
match a pre-alloc C++ stack on tail latency") and the one the owner's 5 % target was most likely to fail on.
It passes with margin — because the quadratic-drain/leak fix (`64b4d9d`) removed the GC pressure that was
producing 5.8 ms tails. **Connext's own tail is worse than ours** (118 µs vs our 53 µs).

**2. Small-payload median is 3.2× off.** 22.5 µs vs 7.0 µs. Real, but a normal engineering gap — and the
remaining ~7.8 KB/sample of allocation is the obvious next lever.

**3. Large payloads are catastrophically broken, and it is ONE cause.** `*fragment-size*` is **1024 bytes**,
so every sample over 1 KB is split into DATA_FRAG submessages with per-fragment framing,
HEARTBEAT_FRAG/NACK_FRAG traffic and reassembly buffers. Connext does not fragment until the transport MTU
(~63 KB): it sends a 16 KB sample as **one** datagram; we send it as **sixteen**. Fragmentation is a
sender-side choice, not a wire requirement.

Raising `*fragment-size*` to 63 000 confirms it — 1 KB p50 goes **104 µs → 35.5 µs (3×)** immediately.

**But raising it exposes the real bug underneath:** at 4 KB the send path dies with

```
BUFFER-OVERFLOW :NEED 4108 :HAVE 1992
```

There is a **fixed ~2 KB buffer** in the send path. So `*fragment-size* = 1024` was never a tuning decision —
**it was masking a hard ~2 KB ceiling on the unfragmented path.** Every sample above ~2 KB has been paying
the fragmentation tax not because the wire requires it, but because our own buffer could not hold it. That
is the single highest-value fix left, and it is worth up to two orders of magnitude at ≥4 KB.

## Where this leaves the 5 % mandate

| metric | status |
|---|---|
| p99.99 (the one predicted to fail) | ✅ **PASS — 2.2× better than Connext** |
| p50 / p99, small payloads | ✗ 3.2× / 2.15× — a normal optimisation gap; allocation is the lever |
| p50, ≥1 KB | ✗ 15–114× — **one root cause**, the ~2 KB send buffer forcing fragmentation |

The 5 % target is **not met**, and I am not going to dress that up. But the shape of the remaining work is
now known rather than guessed, and the hardest requirement — the GC tail — is already beaten.

## Next (in value order)

1. **Lift the ~2 KB send-buffer ceiling**, then raise `*fragment-size*` to the transport MTU. Worth up to
   ~100× at ≥4 KB; nothing else on this list comes close.
2. **Drive the remaining ~7.8 KB/sample of RX allocation to zero** (the arena pattern already used for TX
   and for the secured decode pool). That is the p50/p99 lever.
3. Re-run this table. Then, and only then, chase constant factors with declarations.
