# ADR 0005 — Cursor alignment origin (RTPS 2.5 §10.2)

- **Status:** Accepted (2026-06-04)
- **Deciders:** A0 (integrator)
- **Amends:** ADR 0002 (the frozen `DDS.CORE.BUFFER` contract, §7.1)

## Context

RTPS 2.5 §10.2 states that, for alignment purposes, the CDR stream is logically
**reset to the position following the 4-octet encapsulation header**. CDR
alignment of a member is therefore computed relative to that origin, not the
buffer's byte 0. The M0 cursor aligned relative to position 0 only — correct for
header-less body round-trips, wrong once a SerializedPayloadHeader precedes the
data (8-byte members would be mis-aligned).

## Decision

Extend the frozen `DDS.CORE.BUFFER` cursor with an **alignment origin**:

- New cursor slot `origin` (default `0`).
- New ops `cursor-origin` (read) and `cursor-set-origin` (set origin := current
  position). `cursor-reset` now zeroes both pos and origin.
- `align` computes padding from `(mod (- pos origin) n)` instead of `(mod pos n)`.
- `dds.cdr:make/parse-encapsulation-header` call `cursor-set-origin` after the
  4-octet header so body alignment follows RTPS §10.2.

## Compatibility

**Backward-compatible.** Default origin `0` reproduces the prior behaviour
exactly, so existing callers (the M0 echo + tsample round-trip) are unaffected
and required no change. This is an additive extension of the §7.1 contract, not a
breaking change.

## Consumers

- `dds.cdr` (cdr.lisp encapsulation header; primitives.lisp via `cdr-align`).
- `dds.tests` (the `xcdr-byte-exact-seed` origin-alignment assertion).

## Verification

New test `xcdr-byte-exact-seed` asserts that, after a header (origin→4), an XCDR1
`int64` following a `uint8` lands at the origin-relative 8-byte boundary (final
position 20, vs. 16 under the old position-0 rule). Green on Clasp + SBCL.
