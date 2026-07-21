# reader-acknack allocated its NACK bitmap per HEARTBEAT — the user path now reuses a per-proxy scratch

**Date:** 2026-07-21 · **Requirement:** NFR-MEM (0 B/sample), NFR-PERF-3, NFR-PERF-8 · **ADR:** 0074, 0072
**Machine:** arm64 Darwin, SBCL · **Harnesses:** a direct `reader-acknack` alloc micro-bench (the oracle for
this slice) + `dds.bench:mem-per-sample` (`make gate-mem`) + an `sb-sprof :mode :alloc` all-threads profile.

## Headline (direct micro-bench — deterministic, no threads/timers)

| `reader-acknack`, numbits=5 | B/call |
|---|---|
| fresh `make-array` (NIL — builtin/secure/test default) | **31.457** |
| reused proxy scratch (T — user HEARTBEAT path) | **0.000** |

Every user-path ACKNACK dropped **31.5 B → 0**. The builtin/secure/test callers are byte-identical
(unchanged default).

## Why the direct bench, not gate-mem

`gate-mem` is the NFR-MEM oracle for the *end-to-end* per-sample cost, but an allocation profile
(`sb-sprof :alloc`, all threads, over `mem-per-sample`) shows the ACKNACK bitmap is a **sliver**:

| allocator | self % |
|---|---|
| `%instance-handle` (per-sample key-hash) | **10.9** |
| `%drain` + `%drain-one-sample` | 12.7 |
| `%push-one-writer-changes` (TX) | 6.4 |
| `%writer-add-bounded` (cache-change, task #3) | 6.1 |
| SHMEM `%lane-drain` / `%shmem-send` / `%rx-wait` | ~16 |
| `%on-user-heartbeat` (holds this ACKNACK) | 4.3 |

Phase split (`mem-per-sample`, payload 0): **WRITE 808 B/sample, POLL 1332 B/sample** (POLL absorbs the async
receiver-thread garbage), total ~2140. The ~31.5 B/ACKNACK is a fraction of `%on-user-heartbeat`'s 4.3 %, so
it sits below the harness's ~22 B stray-HEARTBEAT noise — hence the direct micro-bench is the honest oracle.
(The 8-run gate-mem max did fall 2162 → 2118, consistent with less per-ACKNACK garbage; not conclusive alone.)

## The fix

A per-writer-proxy 8-word (`ceil(+seqnum-set-max-bits+,32)`, the 256-bit cap) `acknack-bitmap` scratch,
returned by `reader-acknack` **opt-in** via a trailing `&optional reuse-bitmap`:

- NIL default keeps the fresh alloc — required for `%builtin-acknack-values`, which computes under
  `disc-node-lock` but serializes *after* the lock releases (a shared scratch could be clobbered by a
  concurrent builtin ACKNACK).
- The lock-free user path (`%on-user-heartbeat`) passes T: it serializes synchronously on the receiver
  thread, and a writer-proxy is single-mutator per receiver thread — the same discipline that lets
  `writer-proxy-received` be a lock-free hash (concurrent access would corrupt it; that it never does, across
  fuzz/interop/CI, is the proof the discipline holds).

`write-sequence-number-set` emits exactly `ceil(numBits/32)` words, so the fixed scratch's tail is never
serialized — byte-identical ACKNACK.

## Validation

`gate-build` PASS both impls (self-falsified). **573/573 Clasp and SBCL.** `gate-hotpath` / `gate-types` /
`gate-nocond` / `gate-pal` / `corpus` / `mem` / `fuzz` all green (fuzz drives the ACKNACK parse path).

## Next

`%instance-handle` (10.9 %) — the per-sample key-hash allocation on the take path — is the next and largest
RX-pooling slice.
