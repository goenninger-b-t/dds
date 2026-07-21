# ADR 0074 — the user-path ACKNACK reuses a per-proxy bitmap scratch (opt-in)

- **Status:** Accepted
- **Date:** 2026-07-21
- **Requirements:** NFR-MEM (0 bytes/sample), NFR-PERF-3 (the peer GC-tail), NFR-PERF-8
- **Relates to:** ADR 0073 (the same opt-in-scratch pattern on the deserialize path), ADR 0072 (which flagged this bitmap as the residual ACKNACK cost)
- **Contract touched:** none API-visible. `reader-acknack` (internal, `dds.rtps.reliable::`) gains a trailing `&optional reuse-bitmap`; all existing callers are unchanged (default NIL = today's behaviour).

## Context

`reader-acknack` (RTPS 2.5 §8.3.7.1) built its NACK bitmap with a fresh `make-array` **per ACKNACK** — a
GC-heap `(unsigned-byte 32)` vector, ~31.5 B/call even when nearly caught up (`(max 1 (ceiling numbits 32))`
is at least one word). On a reliable reader that ACKNACKs each inbound HEARTBEAT, that is per-sample-class
garbage on the receiver thread, feeding the peer's GC pause (the NFR-PERF-3 tail).

An allocation profile (`sb-sprof :mode :alloc`, all threads, over `mem-per-sample`) put this inside
`%on-user-heartbeat` (4.3 % of total) — real, but a sliver next to the genuine elephants (`%instance-handle`
10.9 %, the drain 12.7 %, `%writer-add-bounded` 6.1 %). It is banked here because it is a clean, provable
slice; the elephants are the follow-on slices.

## Decision

Give the **writer-proxy** a reusable 8-word (`ceiling(+seqnum-set-max-bits+,32)` = the 256-bit cap)
`acknack-bitmap` scratch, and let `reader-acknack` return it instead of allocating — but **opt-in**, via a
trailing `&optional reuse-bitmap`:

- **NIL (default)** — allocate a fresh bitmap, exactly as before. This is the **only** safe choice for a
  caller that serializes the returned bitmap *after* releasing a lock, or where a second same-proxy
  `reader-acknack` may interleave before serialization. `%builtin-acknack-values` is precisely this: it
  computes the bitmap under `disc-node-lock` but returns it to a caller that serializes *outside* the lock,
  so a shared scratch could be overwritten by a concurrent builtin ACKNACK. The secure and test callers keep
  the default too — byte-identical.
- **Non-NIL** — return the proxy's reused scratch (zeroed to `ceil(numBits/32)` words). Sound **only** when
  the caller serializes synchronously before any concurrent same-proxy recall. The lock-free user HEARTBEAT
  path (`%on-user-heartbeat`) does exactly that: it builds the bitmap and serializes it to every destination
  in a synchronous `dolist` on the receiver thread, and a given writer-proxy is touched by a single receiver
  thread — the **same single-mutator discipline that already lets `writer-proxy-received` be a lock-free hash**
  (concurrent access there would corrupt the table; that it does not, across fuzz/interop/CI, is the proof).

`write-sequence-number-set` serializes exactly `ceil(numBits/32)` words (not `(length bitmap)`), so the
fixed 8-word scratch's tail is never emitted — the ACKNACK is byte-identical to the freshly-allocated form.

## Consequences

- **`reader-acknack` on the user path: 31.5 → 0.0 B/call** (direct deterministic micro-bench, numbits=5).
  The builtin/secure/test paths are unchanged.
- **Not visible in `gate-mem`'s floor** — the end-to-end per-sample cost is dominated by the elephants above,
  and ACKNACKs are only a fraction of it, so the ~31.5 B/ACKNACK is below the harness's ~22 B stray-HEARTBEAT
  noise. The honest oracle for this slice is therefore the direct micro-bench, not gate-mem. (The 8-run
  gate-mem max did drop 2162 → 2118, consistent with less per-ACKNACK garbage, but over 8 runs that is not by
  itself conclusive.) The arm64 ceiling is left at 2160.
- One-time cost: 32 B of scratch per writer-proxy, allocated when the proxy is created (not per sample).

## Validation

`gate-build` PASS both impls (clean cache, self-falsified). **573/573 Clasp and SBCL** (every reliable test
exercises the ACKNACK path; a wrong-sized or stale bitmap would corrupt reliability). `gate-hotpath` /
`gate-types` / `gate-nocond` / `gate-pal` / `corpus` / `mem` / `fuzz` all green (fuzz drives the ACKNACK
parse path). The scratch reuse was reasoned safe against every one of the ~20 `reader-acknack` callers: the
production callers serialize synchronously; the tests each consume a bitmap before any same-proxy recall.

## Next (the elephants this profile named)

`%instance-handle` (the per-sample key-hash allocation, 10.9 %) is the next and largest slice, then the drain
and `%writer-add-bounded` (the cache-change, task #3).
