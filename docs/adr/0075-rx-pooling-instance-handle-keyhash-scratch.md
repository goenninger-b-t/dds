# ADR 0075 — the drain's per-sample key-hash serializes through a reused per-reader scratch

- **Status:** Accepted
- **Date:** 2026-07-21
- **Requirements:** NFR-MEM (0 bytes/sample), NFR-PERF-3 (the peer GC-tail), NFR-PERF-8
- **Relates to:** ADR 0062 (the allocation budget); ADR 0073 (the same opt-in-scratch pattern on `%deserialize-sample`); ADR 0074 (opt-in scratch on `reader-acknack`); the RX-pooling plan (task #29)
- **Contract touched:** the **generated key-hash signature** — `key-hash-<name>` and `key-hash-<name>-fd` gain a trailing `&optional ser-scratch`. Additive; every existing 1-arg caller is unchanged. `%instance-handle` (internal, `dds.dcps::`) gains a trailing `&optional kh-scratch`.

## Context

An `sb-sprof :mode :alloc` profile (all threads, over `mem-per-sample`) named `%instance-handle` the **single
largest allocator, 10.9 %**. It computes a sample's 16-octet instance handle (RTPS 2.5 §9.6.4.8) via the
type's generated key-hash — which allocated, **per call: a `make-octet-buffer 256` (struct + arena vec), a
`cursor` struct, the 16-octet result, and a `free-static`.** Measured at **112 B/call** for `perf-data`
(keyed on an `i32`), and it is called **~2×/sample** (the TX write auto-registers the instance; the RX drain
stamps SampleInfo) — ≈ 224 B/sample, matching the profile.

Of the 112 B, ~80 B is **pure serialization scratch** (the octet-buffer + cursor structs, discarded after the
handle is built); ~32 B is the **retained** 16-octet result (stored in SampleInfo and as the instance-table
key). The scratch is poolable with no aliasing risk; the retained result is not (that is a later slice).

## Decision

Pool the **serialization scratch** on the **RX drain path**, opt-in, mirroring ADR 0073/0074:

1. **Codegen (`%key-hash-defun`, `dds-gen/dsl.lisp`).** Both key-hash emitters (struct `key-hash-<name>` and
   FlatData `key-hash-<name>-fd`, previously duplicated) now share one helper and take `&optional ser-scratch`
   — a reusable `:big` cursor over a ≥256-octet buffer. Given it, the key is serialized **in place** (the
   cursor is `cursor-reset` and reused) with **zero** `make-octet-buffer`/`cursor`/`free-static`; without it
   (NIL — every TX / `register_instance` / test caller) a fresh scratch is allocated and freed exactly as
   before. The 16-octet result is always freshly allocated (it is retained). Byte-identical either way.

2. **`%instance-handle`** gains `&optional kh-scratch`, funcalled through to the key-hash.

3. **The DataReader** carries a lazily-created per-reader `keyhash-scratch` (`%reader-keyhash-scratch`), and
   **`%drain-one-sample`** passes it.

**Soundness — why a per-reader scratch is safe.** The scratch is live only within one `%instance-handle`
call, and the drain calls it once per sample. Two concurrent drains on one reader would race it — but that
cannot happen: `take`/`read` mutate the reader cache and instance-recs **unlocked, "on the user thread"**
(`%drain`), so the engine's contract is **single-threaded-take-per-reader** (concurrent take would already
corrupt the cache). The scratch rides exactly that contract. The TX side is deliberately **not** pooled here:
`%write-sample-1` computes the key-hash *outside* any per-writer lock, so this engine may support concurrent
`write()` on one writer — a shared per-writer scratch would regress that; TX pooling waits until the write
threading contract is settled.

## Consequences

- **`perf-data` key-hash 112 → 32 B/call on the drain path** (direct micro-bench); the 32 B is the retained
  result. Output **byte-identical** to the unpooled path (asserted) and **`make corpus` green** (11 vectors,
  the byte-exact §9.6.4.8 oracle — the conformance crux for interop).
- **`gate-mem` floor 2075 → 1987.6** (min-of-8; ≈ **−88 B/sample**, above the ~22 B noise — the first
  RX-pooling slice large enough to bank a ratchet). Cumulative from the ADR 0062 baseline: **3560 → ~1988,
  ≈ −44 %**. **arm64 ceiling 2160 → 2080** (floor + ~4-stray headroom; `2080×0.9 = 1872 < 1988`, so no false
  ratchet-demand). The x86_64 row is lowered from CI in the usual follow-up.

## Validation

`gate-build` PASS both impls (clean cache, self-falsified). **573/573 Clasp and SBCL.** `gate-hotpath` /
`gate-types` / `gate-nocond` / `gate-pal` / `corpus` / `mem` / `fuzz` all green. The codegen change is
byte-validated by `corpus` and the direct nil-vs-scratch identity assertion.

## Next

- The **retained 16-octet result** (32 B/call): reuse-for-known-instance on the drain (compute into the
  scratch, resolve the existing instance record's stable handle, copy only on a new instance) — a hazardous
  slice (SampleInfo/instance-key aliasing).
- The **TX** key-hash (`%write-key-hash`) — once the write threading contract is settled.
