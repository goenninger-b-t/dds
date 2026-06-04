# ADR 0004 — M0 marked PASSED with AllegroCL exception (owner command)

- **Status:** Accepted (2026-06-04)
- **Decision authority:** **DG1SBG (owner), by explicit command.** Recorded by A0.
- **Updates:** ADR 0001, ADR 0003 (closes the M0 milestone they tracked toward)

## Context

The IMPLEMENTATION-PLAN §4 M0 exit gate reads "every ASDF system loads on all
three impls." Two of the three landed and are green (Clasp 2.7.0 boehmprecise,
SBCL 2.6.5); AllegroCL 11.0 (`alisp8`, on the NAS) is not yet wired.

## Decision

**M0 is marked PASSED, with a documented exception for AllegroCL.** This is **not
an A0 judgement** — the owner (DG1SBG) **explicitly commanded** that M0 be
considered passed with the AllegroCL carve-out on 2026-06-04. The owner is the
scope authority (REQUIREMENTS §0, §8) and is exercising that authority here to
override the three-impl exit gate to a **two-of-three** pass.

## What actually passed (evidence)

On Clasp + SBCL, via `make`:

| Gate | Clasp | SBCL |
|---|---|---|
| `build` (umbrella `dds` loads) | exit 0 | exit 0 |
| `test` (echo-over-mock-transport) | 1 passed | 1 passed |
| `gate-hotpath` | clean (impl-independent) | — |

Plus: frozen L0–L4 contracts (ADR 0002); real static-arena + off-heap
bounds-checked buffer/cursor; reader conditionals confined to `src/dds-pal/`.

## Exception & its closure

- **AllegroCL is deferred, not waived.** Wiring `pal-allegro.lisp` (`alisp8`) +
  `scripts/with-allegro.sh` remains a tracked follow-up. When it lands and goes
  green, M0's three-impl gate is retroactively fully satisfied; no re-decision is
  needed — this ADR pre-authorizes that closure.
- The DDS.PAL contract is unchanged, so adding Allegro is additive (ADR 0003).

## Consequences

- **M1 (P0 XCDR byte-exact + real PALs) starts now** per the owner's "proceed"
  command. M0→M1 gate is satisfied under this ADR.
- Any program-level "Connext-class (core)" acceptance (REQUIREMENTS §9) still
  requires SBCL **and** AllegroCL; this exception is scoped to the **M0
  milestone gate only**, not to final acceptance.
