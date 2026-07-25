# The reliable reader had no lock, and three receiver threads were driving it

**Date:** 2026-07-24 · **ADR:** 0085 · **Box:** dev box, Apple silicon (arm64), SBCL · **Requirement:** NFR-STABILITY (binary gate), RTPS 2.5 §8.3.5.4

## What changed

`rtps-reader` gained a lock, taken by all twelve reader entry points. Before this, a node's up-to-three
receiver threads (unicast UDP, multicast UDP, SHMEM — all feeding `%handle-datagram`) mutated the reader's
hash tables concurrently with no synchronization at all. That corrupted the heap and broke exactly-once
delivery; see ADR 0085 for the diagnosis.

This is a hot-path change (the reader path runs per received sample), so it carries a measurement.

## Method

The end-to-end `make bench` latency is a UDP round-trip in the tens of microseconds — a per-sample mutex is
three orders of magnitude below its noise floor, so measuring there would report "no change" without
evidence. The reader entry points are therefore timed directly: 300 000 calls after a 1 000-call warm-up,
`dds.pal:monotonic-ns` around the loop, three repeats, **in-order SNs** (the steady state — out-of-order
traffic takes the `*max-gap-range*` shed path, which is a different measurement).

Three arms on the same tree, same binary, same workload:

| arm | `reader-on-data` ns/call | `reader-dedup-accept-p` ns/call | added per sample |
|---|---|---|---|
| **before** (no lock, plain tables) | 44.2 / 28.5 / 32.8 | 39.1 / 37.5 / 41.3 | — |
| **lock only** (shipped) | 64.9 / 47.5 / 47.1 | 55.7 / 55.6 / 55.0 | **≈ +31 ns** |
| lock + per-impl synchronized tables | 116.2 / 83.5 / 90.1 | 135.1 / 135.1 / 132.0 | ≈ +150 ns |

## Result: +31 ns/sample, and the synchronized-table arm was rejected

The receive path pays roughly **31 ns more per sample**. Against an end-to-end latency in the tens of
microseconds that is ~0.1%, and correctness here is a binary gate while performance is the optimization
target (operating contract §3.2) — the cost is accepted.

The third arm is the useful negative result. The first cut of this fix used implementation-provided
synchronized hash tables (SBCL `:synchronized`, Clasp `:thread-safe`) for memory safety *plus* the lock for
atomicity, on the reasoning that they buy different things. They do — but only while some access path is
unlocked. Once every one of the twelve entry points takes the reader lock, the tables are already fully
serialized and the synchronization is a **redundant inner lock per operation**: it cost **4× more**
(+150 ns vs +31 ns) for no additional safety. It was removed, along with the PAL primitive added for it.

Verified there is no unlocked access to justify keeping it: no code outside `reliable.lisp` touches
`rtps-reader-proxies`, `rtps-reader-dedup-map`, `writer-proxy-received`, `writer-proxy-reassembly` or
`dedup-origin-above` except single-threaded tests. The invariant is stated on the structs.

## Allocation

Unchanged — the lock allocates nothing. `make gate-mem` reads **1851.9 B/sample** (ceiling 1910), which also
banks the RX store-copy pool's ~36 B/sample win now that the pool re-lands (ADR 0078's own baseline was
1887.2).

## Incidental finding, not fixed here

With permanently out-of-order SNs, `reader-dedup-accept-p` measures **~146 µs/call** — five orders of
magnitude worse. Once `above` reaches `*max-gap-range*`, every call runs
`(loop for k being each hash-key of above maximize k)` to shed the highest entry, which is O(cap) per
sample. It is bounded and correct, and in-order traffic never reaches it, but a peer that streams
persistently out-of-order drives it. Worth a follow-up (a max-tracking structure instead of a full scan);
recorded here rather than fixed, to keep this change to the race.
