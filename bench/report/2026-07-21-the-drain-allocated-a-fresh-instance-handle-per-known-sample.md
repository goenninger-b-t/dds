# The drain allocated a fresh instance handle per sample — even for a known instance it already had

**Date:** 2026-07-21 · **Requirement:** NFR-MEM (0 B/sample), NFR-PERF-3, NFR-PERF-8 · **ADR:** 0076, 0075, 0062
**Machine:** arm64 Darwin, SBCL · **Harnesses:** a direct key-hash alloc micro-bench + `make gate-mem` + `make corpus`.

## Headline (direct micro-bench, deterministic)

| perf-data key-hash | B/call |
|---|---|
| unpooled (TX/register/test default) | 112.039 |
| + ser-scratch (ADR 0075) | 31.785 |
| + ser + out-scratch (ADR 0076, the drain) | **0.000** |

Output **byte-identical** across all three paths (asserted), **`corpus` green** (11 vectors, the §9.6.4.8
byte-exact oracle).

## The waste

ADR 0075 pooled the key-hash *serialization* scratch but left the **16-octet result freshly allocated every
call** — because the handle is *retained* (SampleInfo + the `dr-instance-recs`/`dr-instances` hash key). But in
steady state a reader sees the **same instance repeatedly**, and a known instance **already has a stable
handle** (its hash key). The fresh per-sample handle was needed only *transiently*, to look the instance up.

## The fix

Compute the handle into a **reused** out-scratch for the lookup; read the **stable** handle off the
instance-rec for anything retained.

- Codegen: the key-hash gains a 2nd `&optional out-scratch` (a reusable 16-octet result array).
- `instance-rec` gains a `handle` slot; `%reader-instance-rec` (the single retention choke point) copies
  scratch→stable **once per new instance** (`copy-seq`, rare); a known instance is a lock-free `gethash`.
- The drain treats the returned handle as transient (lookups only, all equalp) and uses `(instance-rec-handle
  rec)` (stable) for SampleInfo + the deadline monitor; the rare RESOURCE_LIMITS reject path `copy-seq`s.

Every handle-retaining site was audited (the two hash keys, SampleInfo, the deadline monitor, the
SAMPLE_REJECTED status) — each gets a stable handle; every lookup-only site keeps the transient scratch. Safe
because the reader take path is single-threaded-per-reader.

## Result

- **The drain's key-hash: 32 → 0 B/call on a known instance.** A new instance costs one 16-octet `copy-seq`,
  once per instance lifetime.
- **`gate-mem` floor 1988 → 1922** (min-of-8: `1922.0 1943.9 1943.9 1943.9 1965.8 1965.9 2009.2 2009.3`;
  ≈ **−66 B/sample** — the shared stable handle removes more than the raw 32 B array). Cumulative from the
  ADR 0062 baseline: **3560 → ~1922, ≈ −46 %**. **arm64 ceiling 2080 → 2060.**

## Validation

`gate-build` PASS both impls (self-falsified). **573/573 Clasp and SBCL** (every keyed take/read,
instance-state, get_key_value, EXCLUSIVE-ownership, RESOURCE_LIMITS-reject, DEADLINE test drives the handle
paths — an aliasing bug would collapse instance separation or corrupt a delivered SampleInfo). `gate-hotpath` /
`gate-types` / `gate-nocond` / `gate-pal` / `corpus` / `mem` / `fuzz` all green.
