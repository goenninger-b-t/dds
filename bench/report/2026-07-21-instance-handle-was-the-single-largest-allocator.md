# %instance-handle was the single largest allocator — the drain's key-hash now serializes through a reused scratch

**Date:** 2026-07-21 · **Requirement:** NFR-MEM (0 B/sample), NFR-PERF-3, NFR-PERF-8 · **ADR:** 0075, 0062
**Machine:** arm64 Darwin, SBCL · **Harnesses:** `sb-sprof :mode :alloc` (all threads) + a direct key-hash
alloc micro-bench + `dds.bench:mem-per-sample` (`make gate-mem`) + `make corpus` (byte-exact).

## How it was found

The previous slice's profile (all threads, alloc mode, over `mem-per-sample`) put **`%instance-handle` first
at 10.9 %** — the single largest allocator. It builds a sample's 16-octet instance handle (RTPS 2.5 §9.6.4.8)
via the generated key-hash, which per call allocated a `make-octet-buffer 256` (struct + arena vec) + a
`cursor` struct + the 16-octet result + a `free-static`:

| perf-data key-hash | B/call |
|---|---|
| before | **112.039** |
| after (pooled scratch) | **32.113** |

~80 B was **pure serialization scratch** (octet-buffer + cursor structs, discarded once the handle is built);
the remaining ~32 B is the **retained** 16-octet result (SampleInfo + instance-table key). It is called
**~2×/sample** (TX write auto-register + RX drain), ≈ 224 B/sample — matching the 10.9 %.

## The fix

Pool the scratch on the **RX drain path**, opt-in (mirrors ADR 0073/0074):

- **Codegen** (`%key-hash-defun`): both key-hash emitters (struct + FlatData, now DRY through one helper) take
  `&optional ser-scratch` — a reusable `:big` cursor. Given it, the key serializes in place (cursor-reset +
  reuse), zero `make-octet-buffer`/`cursor`/`free-static`. NIL (TX/register/test) allocates as before.
- The DataReader carries a lazily-created per-reader `keyhash-scratch`; `%drain-one-sample` passes it.

**Safe** because `take`/`read` mutate the reader cache unlocked "on the user thread" — the engine's
single-threaded-take-per-reader contract (concurrent take would already corrupt the cache), which the
per-reader scratch rides. TX is left unpooled (write computes the key-hash outside any per-writer lock, so
concurrent `write()` may be supported — a shared scratch would regress it).

## Result

- **Byte-identical** nil-vs-scratch (asserted) and **`corpus` PASS** (11 vectors, the §9.6.4.8 byte-exact
  oracle — the interop conformance crux).
- **`gate-mem` floor 2075 → 1987.6** (min-of-8: `1987.6 1987.6 1987.7 1987.7 1987.8 2009.5 2009.6 2031.4`;
  ≈ **−88 B/sample**, the first RX-pooling slice above the ~22 B noise). Cumulative from the ADR 0062
  baseline: **3560 → ~1988, ≈ −44 %**. **arm64 ceiling 2160 → 2080.**

## Phase context (unchanged targets ahead)

Phase split (`mem-per-sample`, payload 0) before this slice: WRITE 808 B/sample, POLL 1332 B/sample. The RX
key-hash lived in POLL; the TX key-hash (same 112 B/call, still allocating) lives in WRITE — a follow-up once
the write threading contract is settled. The retained 32 B result is the reuse-for-known-instance slice.

## Validation

`gate-build` PASS both impls (self-falsified). **573/573 Clasp and SBCL.** `gate-hotpath` / `gate-types` /
`gate-nocond` / `gate-pal` / `corpus` / `mem` / `fuzz` all green.
