# The copy path deserialized into a fresh struct every sample

**Date:** 2026-07-28 · **Requirement:** NFR-MEM (0 B/sample), NFR-PERF-8 · **ADR:** 0093 (slice 4), 0062

## Result

**−32.5 B/sample** on the loan-returning DCPS take path (arm64, SBCL, payload 0), on top of slice 1.

| | RETURN B/sample (3 runs) | mean |
|---|---|---|
| slice 1 (wrapper pooling) | 1569.5 · 1567.2 · 1567.6 | 1568.1 |
| **+ slice 4 (data-struct pooling)** | 1534.9 · 1534.0 · 1536.3 | **1535.1** |

Ceiling lowered 1600 → **1570**. Cumulative saving vs the non-returning COPY arm: **~203 B/sample**
(1738 → 1535).

The win is modest next to slice 1's 171 B because `gate-mem`'s `perf-data` at payload 0 is a small struct —
this removes *one struct per sample*, whose size scales with the type. A fatter type saves proportionally
more; the harness deliberately measures the *fixed* per-sample overhead.

## What changed

`deserialize-into-<name>` has been generated for every type since the FlatData work and was **deliberately
unused**: it needs a pooled target, which is exactly what ADR 0093 introduced. It is now bound on the
type-support (`:deserialize-into`, NIL for FlatData — whose into-variant fills a *buffer*, not a struct)
and the drain decodes into a struct popped from a **per-reader** pool.

Per-reader, not the existing per-type `dds.types:sample-pool`, for two reasons: that pool is shared across
readers (so it would need its own lock, outside the reader lock added in slice 3), and its
`sample-pool-release` has **no bounds guard** — releasing past capacity writes out of the backing vector.

## ⚠️ The hazard this slice is really about

The first sample of each instance is retained **forever** by its `instance-rec` as the `get_key_value` key
holder (ADR 0093 §5 hazard 3). Had it gone back to the pool, a later delivery would decode into it and
**silently rewrite the key of an instance the application can still query** — a correct-looking API
returning another sample's data, with nothing to indicate it.

So the wrapper carrying it is **pinned** and never recycled. The pool loses one struct per *instance*:
O(instances), not O(samples), so it amortises to nothing per sample.

Every non-delivery path hands the popped struct straight back — decode failure, content-filter miss,
RESOURCE_LIMITS reject, and both EXCLUSIVE-ownership drops. Missing one would not corrupt anything; it
would quietly drain the pool until it stopped helping.

**Falsified:** ignoring the pin turns `:adr93p-not-recycled-key` red — the pool hands back the key holder.

## Gate status

623/623 SBCL and Clasp · corpus 13+1, 0 mismatches on both (the generator changed, so byte-exactness was
the thing to check) · gate-build clean-cache PASS both · gate-hotpath / types (3193) / pal / nocond /
drivers PASS · fuzz PASS.
