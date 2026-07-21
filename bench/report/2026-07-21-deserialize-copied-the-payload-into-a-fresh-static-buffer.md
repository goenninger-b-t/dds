# The RX copy path allocated a buffer, copied the payload into it, then freed it — per sample

**Date:** 2026-07-21 · **Requirement:** NFR-MEM (0 B/sample), NFR-PERF-3 (the GC-tail gap), NFR-PERF-8 · **ADR:** 0073, 0062
**Machine:** arm64 Darwin, SBCL · **Harness:** `dds.bench:mem-per-sample` (`make gate-mem`), payload 0, n = 3000.

## Headline

| | B/sample (floor = min-of-N, the zero-stray-HEARTBEAT run) |
|---|---|
| before (ADR 0072 HEAD) | **~2118** |
| after (RX-pooling Phase A) | **2074.9** (8 runs: 2074.9 ×3 / 2096.8 ×2 / 2118.7 / 2162.3 ×2) |

**≈ −43 B/sample.** Cumulative from the ADR 0062 baseline: **3560 → ~2075, ≈ −42 %**. The whole drop is on
the HIT (successful-take) phase — `%deserialize-sample` runs only on a take that found a sample.

## How it was found

RX-pooling Phase A (the owner's task #2, the low-hazard warm-up per the RX-pooling plan). The non-FlatData
take path (`%drain-one-sample` → `%deserialize-sample`) did, **per sample**:

1. `make-octet-buffer (length bytes)` — a fresh PAL-static octet buffer sized to the payload, plus its struct;
2. `replace` — copy the stored `bytes` into that buffer;
3. decode it in place;
4. `free-static` — return the buffer to the pool.

Steps 1, 2, and 4 exist only because the code decoded from a *private* buffer. But `%deserialize-payload`
only **reads** the buffer (a cursor + `aref`, never a SAP) and returns an **independent** deserialized struct
(Copy #2) — so nothing needs a private copy, and nothing retains a reference to `bytes` after the call.

## The fix

Decode **in place** from the caller-owned `bytes`, through a **reused per-reader wrapper**
(`dr-deser-scratch`, an `octet-buffer` repointed at `bytes` each drain — the same per-entity-scratch pattern
as the secured path's `dr-secured-scratch`). Steady state now allocates **zero** here: no `make-octet-buffer`,
no `replace`, no `free-static` — just two slot `setf`s on the reused wrapper.

`%deserialize-sample` gains an `&optional scratch`: the hot drain path passes the reader's scratch (lazily
created once); every standalone/test caller (~8 sites: pbt/rtps/gen/echo) passes nothing and gets a fresh
`octet-buffer-over` wrapper that **still shares `bytes`** — so even the no-scratch path no longer copies or
frees; it just stops short of pooling the wrapper struct. Byte-identical decode either way.

`bytes` provably outlives the call: `%drain` runs on the user thread, the receiver never mutates a stored
sample, and `node-consume-sample` frees the slot only *after* the drain returns.

## Residual / why the ceiling did not move

The 8-run spread is ~88 B (0–4 stray HEARTBEATs × ~22 B — the per-ACKNACK bitmap + send cursor flagged in
ADR 0072). That band is now **wider than this slice's win**, so while the *floor* dropped 43 B the noisy
*max* did not, and the arm64 ceiling (2160) — which must sit above the max, and at which CI is green — is
left unchanged. Collapsing that ACKNACK noise is the immediate next slice; it re-enables a deep ratchet.

## Validation

`gate-build` PASS both impls (clean cache, self-falsified — it first caught a stale 2-arg call site) ·
**573/573 Clasp and SBCL** (every non-FlatData take/read test decodes through this path; a wrong-aliased
buffer would corrupt the sample and fail the value checks) · `gate-hotpath` / `gate-types` / `gate-nocond` /
`gate-pal` / `corpus` / `mem` / `fuzz` all green (fuzz decodes malformed payloads in place, bounds-checked
against capacity = `(length bytes)`, identical extent to the old copy).
