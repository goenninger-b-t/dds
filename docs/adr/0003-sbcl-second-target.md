# ADR 0003 — SBCL added as a second landed target

- **Status:** Accepted (2026-06-04)
- **Deciders:** DG1SBG (owner), A0 (integrator)
- **Updates:** ADR 0001 (relaxes its "Clasp-only" M0 baseline to "Clasp + SBCL")

## Context

ADR 0001 made the M0 baseline Clasp-only and listed "wire `pal-sbcl.lisp` and
re-run the M0 gate on SBCL" as the first follow-up. SBCL 2.6.5 is on PATH
(`/opt/homebrew/bin/sbcl`) and is a co-equal first-class pacesetter in
REQUIREMENTS §8, so it is the cheapest and highest-value impl to add next.

## Decision

Add SBCL as a second target now. The `DDS.PAL` interface contract (ADR 0002) is
**unchanged** — this adds an implementation of it, not a new contract.

Changes:
- `src/dds-pal/pal-sbcl.lisp` — SBCL backend (memory/clock/threads via
  `static-vectors` + `bordeaux-threads`; atomics/sockets stubbed for M1, matching
  the Clasp backend). The only file permitted to carry `#+sbcl` conditionals.
- `dds-pal.asd` — per-impl backend selection via ASDF `:if-feature` so exactly
  one PAL file loads (`pal-clasp` on `:clasp`, `pal-sbcl` on `:sbcl`).
- `scripts/with-sbcl.sh` — SBCL launcher mirroring `with-clasp.sh`.
- `Makefile` — overridable `LISP` (default Clasp) plus `build-sbcl`/`test-sbcl`,
  `build-clasp`/`test-clasp`, and `build-all`/`test-all`; `make all` runs both.

## Verification

`make build-all`, `make test-all`, `make gate-hotpath` all green:

| Impl | build | test (echo) | PAL impl-name |
|---|---|---|---|
| Clasp 2.7.0 boehmprecise | pass | pass | `:clasp` |
| SBCL 2.6.5 | pass | pass | `:sbcl` |

Confirmed the PAL abstracts the per-impl pointer representation: the same
`buffer-sap` yields a Clasp `CLASP-FFI:FOREIGN-DATA` wrapper on Clasp and a
native `SB-SYS:INT-SAP` on SBCL, with identical buffer/cursor/arena semantics.

## Consequences

- M0's "loads on all three impls" gate now passes on **two of three**; only
  AllegroCL (11.0 `alisp8`, on the NAS, ADR 0001) remains to fully close M0.
- No `#+sbcl`/`#+clasp` reader conditionals leaked outside `src/dds-pal/`
  (NFR-BUILD) — the upper layers were untouched, validating the PAL boundary.
- SBCL-native hot-path fast paths (`sb-sys:sap-ref-*`, `sb-ext:cas`,
  `define-vop`) are deliberately deferred to M1, gated by a before/after bench
  number (FR-LANG-7) — none added speculatively here.

## Follow-ups

- Wire `pal-allegro.lisp` (`alisp8`) to close the three-impl M0 gate.
- Adopt `qlot`/vendoring for reproducible builds (NFR-BUILD), still open.
