# ADR 0073 — RX-pooling Phase A: the take path decodes in place through a reused per-reader scratch

- **Status:** Accepted
- **Date:** 2026-07-21
- **Requirements:** NFR-MEM (0 bytes/sample), NFR-PERF-3 (close the GC-tail gap vs Connext), NFR-PERF-8
- **Relates to:** ADR 0062 (the allocation budget), the RX-pooling plan (task #29); ADR 0038 (the secured path's `dr-secured-scratch`, the pattern mirrored here); ADR 0072 (the residual ACKNACK noise this exposes as the next slice)
- **Contract touched:** none API-visible. `%deserialize-sample` (internal, `dds.dcps::`) gains a trailing `&optional scratch`; all existing 2-arg callers are unchanged.

## Context

The RX-pooling project (owner-sequenced task #2) drives the take path toward zero per-sample allocation.
Phase A is its deliberately low-hazard warm-up: pool the deserialize scratch. It is safe because the
COPY-out path produces an **independent** deserialized struct (Copy #2) — there is no loan aliasing to reason
about (that is Phases B–D).

The non-FlatData take path (`%drain-one-sample` → `%deserialize-sample`) allocated **per sample**: a fresh
PAL-static `make-octet-buffer` sized to the payload, a `replace` to copy the stored bytes into it, an
in-place decode, then a `free-static`. The buffer was private only so the decode had something to read — but
`%deserialize-payload` merely **reads** the buffer (cursor + `aref`, never a SAP) and returns an independent
struct, so the private copy was never necessary for correctness.

## Decision

Decode **in place** from the caller-owned `bytes` through a **reused per-reader `octet-buffer` wrapper**,
`dr-deser-scratch`, repointed at `bytes` on each drain — exactly the per-entity-scratch pattern the secured
path already uses (`dr-secured-scratch`).

`%deserialize-sample` gains a trailing `&optional scratch`:

```lisp
(defun* %deserialize-sample (ts bytes &optional scratch)
    (function (t (simple-array (unsigned-byte 8) (*)) &optional (or null dds.core.buffer:octet-buffer))
              (values t (or null keyword)))
  (let ((ob (cond (scratch (setf (dds.core.buffer:octet-buffer-vec scratch) bytes
                                 (dds.core.buffer:octet-buffer-capacity scratch) (length bytes))
                           scratch)
                  (t (dds.core.buffer:octet-buffer-over bytes)))))
    (%deserialize-payload ts ob)))
```

- **Hot drain path** passes the reader's scratch (lazily created once, then reused): steady state allocates
  **zero** here — no `make-octet-buffer`, no `replace`, no `free-static`, just two slot `setf`s.
- **Standalone / test callers** (~8 sites in pbt/rtps/gen/echo tests) pass nothing and get a fresh
  `octet-buffer-over` wrapper that **still shares `bytes`** — so even the no-scratch path stops copying and
  freeing; it only forgoes pooling the wrapper struct. This kept the signature backward-compatible for every
  reader-less caller (threading a `DataReader` through the core deserialize helper — a first, rejected cut —
  was wrong: those callers legitimately have only a type-support and wire bytes).

**Soundness — `bytes` outlives the call:** `%drain` runs on the user thread; the receiver thread never
mutates a stored sample; `node-consume-sample` frees the store slot only *after* the drain returns. The
reused wrapper holds no reference past the call (the returned struct is independent), so the next drain may
freely repoint it.

## Consequences

- **`gate-mem` floor 2118 → 2074.9** (min-of-8; ≈ **−43 B/sample**). Cumulative from the ADR 0062 baseline:
  **3560 → ~2075, ≈ −42 %**. The drop is entirely on the HIT (successful-take) phase.
- **The arm64 ceiling is deliberately left at 2160.** The 8-run spread is ~88 B (0–4 stray HEARTBEATs ×
  ~22 B — the per-ACKNACK bitmap + send cursor from ADR 0072's "Not addressed"). That band is now *wider than
  this slice's win*, so the noisy max did not drop even though the floor did; the ceiling must sit above the
  max, and CI is green at 2160. `gate-mem` still passes (2075 is inside `[2160×0.9, 2160]`, so the ratchet
  does not yet demand a lower row). Collapsing that ACKNACK noise is the immediate next slice, which
  re-enables a deep ratchet of both the floor and the ceiling.
- The no-scratch path is now also cheaper (no copy, no free) for every standalone deserialize — a small win
  for the test/tooling paths, though they are not measured.

## Validation

`gate-build` PASS both impls (clean cache, self-falsified — it first caught a stale 2-arg call site, proving
the gate bites) · **573/573 Clasp and SBCL** (every non-FlatData take/read test decodes through this path; a
wrong-aliased or wrong-extent buffer would corrupt the sample and fail the value checks) · `gate-hotpath` /
`gate-types` / `gate-nocond` / `gate-pal` / `corpus` / `mem` / `fuzz` all green (fuzz decodes malformed
payloads in place, bounds-checked against capacity = `(length bytes)` — identical extent to the old copy).

## Not addressed (the next slices)

- The ~88 B ACKNACK-bitmap + send-cursor noise (immediate next slice — it is both real per-sample allocation
  on the reliable path and the measurement noise blocking sub-88 B ratchets).
- RX-pooling Phases B–D (loan wrappers, N≥2 refcount, data-struct loan) — the hazardous read/take-aliasing
  work, still ahead.
- The x86_64 ceiling row is lowered from its CI number in the usual follow-up once CI reports it.
