# ADR 0076 — the drain's instance handle is reused-for-known-instance (the stable handle lives on the instance-rec)

- **Status:** Accepted
- **Date:** 2026-07-21
- **Requirements:** NFR-MEM (0 bytes/sample), NFR-PERF-3 (the peer GC-tail), NFR-PERF-8
- **Relates to:** ADR 0075 (pooled the key-hash *serialization* scratch; this pools the *result*); ADR 0062; the RX-pooling plan (task #29)
- **Contract touched:** the generated key-hash gains a **second** trailing `&optional out-scratch` (additive; all existing callers unchanged). `instance-rec` gains a `handle` slot. `%instance-handle` gains `&optional out-scratch`. All `dds.dcps::`-internal.

## Context

ADR 0075 pooled the key-hash's serialization scratch (112 → 32 B/call) but left the **16-octet result freshly
allocated every call** because the handle is *retained* — stored in SampleInfo (returned to the app) and used
as the `dr-instance-recs` / `dr-instances` hash key. That 32 B is the last per-sample allocation in the drain's
key-hash, and `%drain-one-sample` is now co-largest at 12.6 % (profile after ADR 0075).

The insight: in steady state a reader sees the **same instances repeatedly** (a known instance), and a known
instance **already has a stable handle** — its `dr-instance-recs` hash key. So the freshly-computed handle is
needed only *transiently*, to look the instance up; the retained handle can be the instance's existing stable
one. Only a **new** instance genuinely needs a fresh stable handle.

## Decision

**Compute the handle into a reused scratch for the lookup; read the STABLE handle off the instance-rec for
everything retained.**

1. **Codegen (`%key-hash-defun`):** a second `&optional out-scratch` — a reusable 16-octet array written in
   place (zero-filled first so the `<=16`-direct zero-pad is correct). With it, the key-hash allocates **zero**
   (0.000 B/call, direct micro-bench; was 32 with ADR 0075, 112 unpooled). Byte-identical across all paths.
2. **`instance-rec` gains a `handle` slot** = the instance's stable 16-octet identity.
3. **`%reader-instance-rec` — the single retention choke point** (audited: it is the *only* creator of the
   `dr-instance-recs` / `dr-instances` keys) — on a **new** instance copies the (reused-scratch) handle to a
   **stable** array used as *both* keys *and* `(instance-rec-handle rec)`. `copy-seq` runs **once per new
   instance** (rare); a known instance is a pure lock-free `gethash` (**zero alloc**).
4. **The drain (`%drain-one-sample`)** passes `(%reader-keyhash-out dr)` as the out-scratch and treats the
   returned handle as **transient** — lookups only (`%resource-reject-reason`, `%arbitrate-owner`,
   `%reader-instance-rec`, all equalp). For anything **retained** it reads `(instance-rec-handle rec)` (stable):
   SampleInfo's `instance-handle`, `%deadline-touch`. The rare **reject** path (`%reader-sample-rejected`,
   which stores the handle in the SAMPLE_REJECTED status) gets a `copy-seq` — stable, off the hot path.

**The aliasing audit (why this is safe).** Every site that *retains* the handle was checked: the two hash keys
(via `%reader-instance-rec`, now copy-on-create), SampleInfo (uses the stable rec handle), the deadline monitor
(passed the stable handle), the SAMPLE_REJECTED status (`copy-seq`). The other `dr-instances` writes
(`%select-samples` mark-accessed) either update an existing entry — CL keeps the original stable key — or insert
a handle that itself came from a (now-stable) SampleInfo. Lookup-only sites (`%resource-reject-reason`,
`%reader-keeplast-drop-oldest`, the equalp scans) safely use the transient scratch. The reader take path is
single-threaded-per-reader (`%drain` mutates the cache unlocked "on the user thread"), so the reused scratch is
never concurrently clobbered.

## Consequences

- **The drain's key-hash: 32 → 0 B/call on a known instance** (direct micro-bench); a new instance costs one
  `copy-seq` (16 octets, once per instance lifetime). Byte-identical (corpus green, 11 vectors).
- **`gate-mem` floor 1988 → 1922** (min-of-8; ≈ **−66 B/sample** — the shared stable handle removes more than
  the raw 32 B array). Cumulative from the ADR 0062 baseline: **3560 → ~1922, ≈ −46 %**. **arm64 ceiling
  2080 → 2060** (the noisy max dropped one stray band 2031 → 2009; ceiling tracks max + ~50). x86_64 (2180)
  unchanged — its floor drops to ~2020, still above 2180×0.9 = 1962, so no ratchet-demand (no arch-dance this
  slice).

## Validation

`gate-build` PASS both impls (clean cache, self-falsified). **573/573 Clasp and SBCL** — every keyed
take/read, instance-state, `get_key_value`, EXCLUSIVE-ownership, RESOURCE_LIMITS-reject, and DEADLINE test
exercises the handle paths; an aliasing bug would collapse instance separation (two instances sharing the last
handle) or corrupt a delivered SampleInfo. `gate-hotpath` / `gate-types` / `gate-nocond` / `gate-pal` /
`corpus` / `mem` / `fuzz` all green. The codegen is byte-validated by `corpus` + the nil/ser/out identity
assertion.

## Next

- **TX key-hash** (`%write-key-hash`, still 112 B/call on the 808 B WRITE phase) — needs a per-thread scratch
  (write() is concurrent).
- The drain's other allocators (SampleInfo, the cache cons) and TASK 3 (`%writer-add-bounded`, the #1 allocator).
