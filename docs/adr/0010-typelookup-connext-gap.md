# ADR 0010 — Connext does not implement the standard TypeLookup service; M4 gate amended

- **Status:** Accepted (2026-06-10, owner decision)
- **Deciders:** Owner + A0 (integrator)
- **Amends:** the M4 exit gate (`IMPLEMENTATION-PLAN.md` §4 "remote type discovery via TypeLookup interoperates with Connext"); FR-TYPE-3's interop oracle; the Stage-5 DoD of `docs/superpowers/plans/2026-06-10-typelookup-service.md`
- **Evidence:** TypeLookup probe vs live RTI Connext 7.3.1 (2026-06-10, Task 0.1 of the TypeLookup plan; pcaps `interop/connext/tl-probe-run{A,B}-lo0.pcap`) + RTI's Extensible Types Guide

## Context

The TypeLookup plan's Stage-0 probe announced the four XTypes 1.3 Table-62 builtin-endpoint
bits (`availableBuiltinEndpoints` = `#x0000F43F`, wire-verified) and observed live Connext
7.3.1 in both pub/sub directions. Three facts, all from the wire:

1. Connext's own `availableBuiltinEndpoints` is `0x00000c3f` — **bits 12–15 clear**: it
   announces no TypeLookup endpoints.
2. Connext emitted **no `PID_TYPE_INFORMATION` (0x0075)** even with our bits announced —
   only its vendor `PID_TYPE_OBJECT_LB` (0x8021), unchanged from ADR 0009.
3. Connext announces a **vendor** service channel instead: `PID_VENDOR_BUILTIN_ENDPOINT_SET`
   (0x8017) = 0x3 with ServiceRequest endpoints `0x00020082/0x00020087`.

RTI's own Extensible Types Guide (7.3.1, ch. 1, "not supported" list) confirms in writing:
**"TypeObject v2"** and **"Builtin TypeLookup service"** are unsupported. This is vendor
policy, not configuration.

## Decision

1. **Build the standard TypeLookup service anyway** (FR-TYPE-3 is a REQUIREMENTS MUST):
   proven by offline our↔our conformance; live interop against a compliant peer (eProsima
   Fast DDS, which implements the service) lands with the FR-IO-2 open-peer work.
2. **Real Connext type-compatibility gating comes from the channel Connext actually uses**:
   a structural parse of the RTI-legacy TypeObject already captured from SEDP 0x8021
   (today: inflate + name fingerprint; the full parse was deferred by ADR 0009 and is now
   scheduled as the follow-on feature). The Stage-4 `type-gate` consumes whichever source a
   peer provides: standard TypeInformation+TypeLookup, or the 0x8021 legacy TypeObject.
3. **M4 exit gate amended:** "remote type discovery via TypeLookup interoperates with a
   compliant peer (offline conformance now; Fast DDS under FR-IO-2); type-compatibility
   assessment interoperates with Connext via its legacy TypeObject announcement."
4. Announcing the Table-62 bits stays (we do implement the endpoints; compliant peers can
   use them). The unanswered side effect on Connext is nil (it ignores the bits).

## Consequences

- The TypeLookup plan's Stage 5 is re-scoped: offline conformance + vector self-pinning
  replaces the Connext live directions; Connext live gating moves to the legacy-0x8021
  follow-on plan.
- The provisional minimal EquivalenceHash (ADR 0009) remains without an external oracle
  until a Fast DDS peer exists; it stays a self-consistent regression vector, never a gate
  against RTI peers (they never send a minimal hash).
- Consumers: `IMPLEMENTATION-PLAN.md` §4 M4 (gate text), `docs/verification.csv` FR-TYPE-3
  row, the TypeLookup spec + plan (addenda), `docs/MILESTONES.md`. Migration: none (no
  shipped behavior changes).
