# ADR 0001 — M0 baseline is Clasp-first (and Clasp-only, for now)

- **Status:** Accepted (2026-06-04)
- **Deciders:** DG1SBG (owner), A0 (integrator)
- **Supersedes:** —

## Context

REQUIREMENTS §8 and §1.3 make **SBCL and AllegroCL the co-equal first-class
pacesetters**, with **Clasp the trailing target** (NFR-PORT: "MAY trail by one
profile"). The plan's M0 exit gate is "every ASDF system loads on all three
impls."

Toolchain reality on the dev host (Darwin 25.5.0, arm64) at M0 start:

- **SBCL** 2.6.5 — on PATH, runnable.
- **AllegroCL** 11.0 (`alisp8`) — present but on a Dropbox/NAS path, not wired.
- **Clasp** 2.7.0 `boehmprecise` — built from source at
  `~/gbt Dropbox/gbt/projects/clasp/build/boehmprecise/clasp` (symlink to
  `iclasp`), not installed on PATH.
- Quicklisp present; `qlot` absent.

Verified before deciding: Clasp loads `cffi`, `bordeaux-threads`, and
`static-vectors`; a static-vector allocates with a stable foreign pointer and
supports raw octet R/W — so the **NFR-MEM off-heap-arena foundation is viable on
Clasp**. (Clasp's `static-vector-pointer` returns a `CLASP-FFI:FOREIGN-DATA`
wrapper, not a bare integer SAP as on SBCL; the PAL hides this.)

## Decision

Develop the **M0 skeleton + frozen L0–L4 contracts + echo exit test against
Clasp `boehmprecise` only**, for now. The other two impls are deferred within
M0, not dropped.

## Consequences

- M0's "loads on all three impls" gate is **explicitly relaxed to Clasp-only**
  and re-tightened before M0 is declared fully closed (SBCL is the cheapest to
  add next — it is already on PATH).
- The PAL contract (`DDS.PAL`) is still authored impl-agnostically; only
  `pal-clasp.lisp` is implemented. `pal-sbcl.lisp` / `pal-allegro.lisp` follow.
- **Risk:** the hot-path `(safety 0)` purity and determinism work (NFR-PERF-3/8)
  is being shaped first against Boehm-conservative-precise — the impl the risk
  register (R5) and §6.3 flag as the determinism risk and *allows* to trail.
  Anything tuned here is re-validated on SBCL/Allegro before P4.
- Reader conditionals remain confined to `dds-pal/` (NFR-BUILD); the rest of the
  tree is impl-agnostic, so adding SBCL/Allegro is additive, not a rewrite.
- Host OS is macOS/arm64 while the spec is "Linux-first"; the Linux-specific PAL
  paths (`recvmmsg`/SHMEM/affinity) are M1+/M5 and unaffected by this ADR.

## Follow-ups

- Wire `pal-sbcl.lisp` and re-run the M0 gate on SBCL.
- Decide host-OS strategy for the Linux-first transport work (open).
- Adopt `qlot` (or vendoring) for the reproducible-build requirement (NFR-BUILD).
