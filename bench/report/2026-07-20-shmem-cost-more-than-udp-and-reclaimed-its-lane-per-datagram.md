# SHMEM cost more than UDP, because it re-claimed its lane on every datagram

**Date:** 2026-07-20 · **Requirement:** NFR-MEM (0 B/sample), NFR-PERF-8 · **ADR:** 0067 (decision), 0062 (budget)
**Machine:** arm64 Darwin, SBCL · **Harness:** `dds.bench:mem-per-sample` (`make gate-mem`), payload 0, n = 3000.

## Headline

| | B/sample |
|---|---|
| before (`*shmem-dest-cache*` NIL) | **2621.0** |
| after (`*shmem-dest-cache*` T) | **2533.6** |
| `make gate-mem`, three further runs | 2533.7 / 2533.7 / 2533.7 |

**−87 B/sample (−3.3 %).** arm64 ceiling **2710 → 2600**. Cumulative under ADR 0062:
**3560 → 2534, −1026 B/sample (−29 %)**. The repeat spread is ~0.004 % — far tighter than the UDP slices'
~1 %, which is consistent with removing a *mutex* from the send path rather than only allocation.

## How the target was found — a free A/B, no code change

After ADR 0065/0066 made the UDP send and receive paths ~0 B/call, flipping the existing
`dds.disc:*shmem-enabled*` re-attributed the whole transport:

| transport | B/sample |
|---|---|
| SHMEM (the default — and what `gate-mem` measures) | 2577.3 |
| pure UDP | 2446.4 |

**The intra-host transport that exists for speed had become 131 B/sample more expensive than the network
one.** SHMEM had not regressed; UDP had got cheap, and nothing re-ranked the transports afterwards.

## The defect

Reading `%shmem-send` — not the profiler — found it:

```lisp
(let* ((sap (dds.pal:shm-sap dest))                          ; boxes a pointer, every send
       (lane (%claim-lane sap (shmem-transport-token st))))  ; ...and this, every send
```

`%claim-lane`'s **own docstring says "One-time, off the hot path."** It was being called on every
datagram: taking the segment's **pshared mutex**, scanning every lane descriptor with `load-sap-u64`, and
running an `unwind-protect` (its cleanup closure is the `CLEANUP-FUN-0` frame in the alloc profile) — all
to re-derive the lane it had already returned for the same token on the previous send.

A docstring asserting "off the hot path" is a claim, not a fact. This one had been false for as long as
the send path existed, and it sat directly under a profile frame nobody had chased.

## The fix

Resolve the destination once — `segment` + `sap` + `lane` in one `shmem-dest` — and cache it in the
*existing* attach cache, under the key the attach already used. All three have the same lifetime as the
attach, so they go stale together and there is no second thing to invalidate. A failed lane claim stays
retryable (`lane` NIL, segment still cached so the mapping is not leaked). Full rationale in ADR 0067.

## The hazard, and the falsification

A wrong cached lane is **silent mis-delivery** — two senders on one ring lane interleave and corrupt each
other's records rather than failing — so delivery alone would not have proved this correct.
`run-shmem-dest-cache-test` asserts the invariant directly: two senders, one receiver, lanes claimed,
stable across sends, **distinct**, agreeing with a fresh `%claim-lane`, and every record intact.

**It was falsified before being trusted:** forcing `%claim-lane` to return 0 for every token makes it fail
with *"two senders must hold DISTINCT lanes (0 vs 0)"* — precisely the mis-delivery case.

## Latency: measured, and it is a NULL at single-in-flight (not the win I expected)

Removing a pshared-mutex acquire and a lane scan from every send *should* help p50, and SHMEM p50 is the
number sitting at 1.37× Connext — so I measured it rather than assert it. Interleaved arms (1 0 1 0, one
confirmed-single responder per arm, `run-echo-pinger` 256 B, 12 000 samples, one-way = RTT/2):

| arm | p50 (ns) | p99 (ns) | bytes/sample |
|---|---|---|---|
| destcache=1 | 8541 | 26 562 | **2774** |
| destcache=0 | 8916 | 27 479 | 2879 |
| destcache=0 | 9520 | 29 250 | 2871 |
| destcache=1 | 12875 *(warm-up outlier, p99 78 µs)* | 78 062 | 2774 |

**The p50 arms overlap.** This box swings 16–32 µs for identical code between runs (documented), and a
per-datagram mutex acquire is tens of nanoseconds — three orders of magnitude under the jitter floor at
single-in-flight. So there is **no honest latency claim to make here**: the win is real in principle and
invisible in this instrument. The *allocation* delta, by contrast, is dead clean in the same runs — the
last column reads 2774 with the cache and 2871–2879 without, ~99 B, matching `gate-mem`.

The takeaway is the standing one: the flag's branch was proven to execute (the bytes column moves), and
what the instrument can distinguish (allocation) is reported; what it cannot (a sub-jitter p50 shift) is
not dressed up as if it could. A dedicated latency measurement of this belongs on a quiet box under load
where the mutex is contended, not on the dev laptop at one-in-flight.

## Validation

`gate-build` PASS both impls (clean cache, self-falsified) · **571/571 Clasp and SBCL** · `gate-hotpath` ·
`gate-types` · `gate-nocond` (ceiling 0) · `gate-pal` · `corpus` · `mem` · `fuzz` — all green.
