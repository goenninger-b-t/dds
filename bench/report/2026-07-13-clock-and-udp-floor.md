# The measuring instrument was broken — and the UDP floor says Connext is not beating our code

2026-07-13. macOS arm64. Prerequisite work for the WP-8 latency profile (#23).

## 1. The clock had 1 µs resolution. Every latency number we ever published was quantised.

`dds.pal:monotonic-ns` was `(get-internal-real-time)` scaled to ns. On SBCL
`internal-time-units-per-second` is **1e6** — so the clock ticked at **one microsecond**. That is why every
latency figure in this repo's history lands on a multiple of 500 ns after `RTT/2`: it was quantisation, not
data. Profiling a ~22 µs path whose segments are single microseconds was not merely imprecise with that
clock, it was **impossible**. The PAL's own docstring promised a `clock_gettime` fast path "in M1"; it had
never landed.

Replaced with `clock_gettime`, one shared CFFI implementation on both impls.

**The clk_id must be chosen by MEASURED RESOLUTION, not by name** (values read from platform headers):

| clk_id | macOS (measured here) | Linux |
|---|---|---|
| `CLOCK_MONOTONIC` (6 on macOS / 1 on Linux) | **1000 ns tick** — deliberately coarsened | ns, vDSO fast path |
| `CLOCK_MONOTONIC_RAW` (4) | **41 ns tick** | may fall back to a real syscall |
| `CLOCK_MONOTONIC_COARSE` (6 on Linux) | — | **~ms**, and the call SUCCEEDS |

Picking by name is silently wrong in both directions. Using id 6 on Linux gets you a millisecond clock that
returns 0 and looks perfectly healthy. So: **4 on macOS, 1 on Linux.**

| | before | after |
|---|---|---|
| SBCL | 0.3 ns/call, **1000 ns tick** | **16 ns/call, 41 ns tick** |
| Clasp | 24 ns/call, **1000 ns tick** | **633 ns/call, 41 ns tick** |

## 2. Clasp's FFI: two real defects, root-caused (owner directive — Clasp uses the CFFI clock too)

Clasp's first CFFI clock read cost **4230 ns**. That is not "Clasp is slow"; it is two specific, fixable bugs:

| cost | measured | fix |
|---|---|---|
| **per-call `dlsym`** — Clasp re-resolves a foreign symbol on EVERY by-name call | `clock_gettime` by name **4230 ns**; bare `getpid()` by name **4824 ns**; via cached pointer **379 ns** | resolve the pointer once (`*clock-gettime-fp*`) |
| **per-call foreign `malloc`** — `with-foreign-object` really mallocs on Clasp | **3790 ns** with per-call buffer vs **518 ns** hoisted (SBCL: 12 ns either way) | per-thread pre-allocated timespec (`*thread-timespec*`, bound by `spawn`) |
| **libffi dynamic dispatch** — the residual | **~600 ns** | **NOT FIXABLE HERE** |

Result: Clasp **4230 → 633 ns/call**, same clock, same 41 ns resolution.

**Parity with SBCL (16 ns) is NOT achieved and cannot be from this repo.** CFFI exposes no direct-call
compiler macro on Clasp — verified: `COMPILER-MACRO-FUNCTION` is `NIL` for both `FOREIGN-FUNCALL` and
`FOREIGN-FUNCALL-POINTER` — so every call goes through libffi, while SBCL emits a direct inline call. Closing
it needs an upstream CFFI/Clasp contribution. It is affordable because **`monotonic-ns` is not on the
per-sample path** (blocking-wait deadlines, the flow-controller token bucket on opt-in async writers, shmem
stress loops). Every hot foreign call in this codebase must go through a cached pointer — that is the
transferable lesson.

## 3. THE FLOOR — and it reframes the entire parity problem

Raw UDPv4 loopback ping-pong, SBCL, through the same `sb-bsd-sockets` API the PAL uses, 256 B, single
in-flight, **no DDS at all**:

```
RAW UDP LOOPBACK FLOOR (one-way = RTT/2, 256 B): p50 = 6 979 ns   p99 = 21 187 ns   min = 6 354 ns
```

Now put that beside the parity table:

| | 256 B, one-way p50 |
|---|---|
| **raw UDP loopback floor (no DDS)** | **6 979 ns** |
| **RTI Connext** | **7 041 ns** |
| ours | ~22 000 ns |

**Connext is running AT the raw-UDP floor — it adds ~60 ns over a bare socket round trip.** So the gap was
never "Connext's code is 3× faster than ours". The socket path costs ~7 µs on this machine and *neither*
stack can go below it; Connext has simply reduced its own overhead to nothing. Our stack adds **~15 µs on top
of that floor**, and those 15 µs are entirely ours.

This is the correct framing for the 5 % mandate, and it changes the target:
- The 5 % budget on a 7 µs floor is ~350 ns of headroom. We are spending ~15 000 ns.
- The question is no longer "why is Connext faster" but **"what are our 15 µs doing"** — and that is a
  question about *our* code, answerable by profiling, which the new 41 ns clock finally makes possible.
- It also kills any hope that a `declaim` pass closes this. Constant factors do not account for 15 µs.

Next (#23): instrument the one-way path segment by segment — write → serialize → sendto → receiver-thread
wake → demux → store → reader wake → drain → take — and find where the 15 µs sit.

## Gates

`make test` 563/563 SBCL · `make test-clasp` 563/563 Clasp · `gate-hotpath` PASS · `gate-types` PASS.

*(Note: an earlier run of this suite showed a spurious `LJ-VOL-PRE` failure — caused by running the SBCL and
Clasp suites CONCURRENTLY, which cross-talk on shared DDS domains/ports. Run them sequentially.)*
