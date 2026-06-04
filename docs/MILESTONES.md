# Milestone status

Exit gates are defined in `IMPLEMENTATION-PLAN.md` §4. This file tracks status.

| Milestone | Scope | Status |
|---|---|---|
| **M0** | Contracts, skeleton, CI | ✅ **PASSED** — Clasp + SBCL green. **AllegroCL exception, by explicit owner command (DG1SBG), 2026-06-04** — see ADR 0004. |
| **M1** | P0 XCDR byte-exact + real PALs | 🟡 **IN PROGRESS** — XCDR1/2 codec + spec-pinned encapsulation + s-expr type compiler (`define-dds-type` → defstruct + monomorphic codecs + type-support) round-tripping on Clasp+SBCL. Remaining: full RTI byte-exact vectors (oracle), IDL parser, mutable/appendable framing, key-hash, string/sequence member pooling. |
| M2 | P1 minimal RTPS + Connext Shapes interop | 🟡 **IN PROGRESS** — **RTPS wire-codec layer complete** — Header/SubmessageHeader/EntityId/SequenceNumber/SequenceNumberSet/HEARTBEAT/ACKNACK/GAP/DATA, all byte-exact + bounds-checked + spec-cited. Next: HistoryCache + reliable writer/reader engine (fault-injection tests) + SPDP/SEDP + UDPv4, then **Connext Shapes interop** (exit gate — needs owner's Connext + tshark). |
| M3 | P2 DCPS + QoS + conditions + content-filter | ⬜ not started |
| M4 | P3 XTypes + TypeLookup + assignability | ⬜ not started |
| M5 | P4 batching/async/SHMEM/Zero-Copy/FlatData/LZ4 + bench | ⬜ not started |
| M6 | P5 durability / late-joiner | ⬜ not started |
| M7 | P6 security (gated) | ⬜ not started |
| M8 | P7 tooling / services (gated) | ⬜ not started |

## M0 exception detail

M0's plan gate is "loads on all three impls." The owner commanded a **two-of-three
pass** (Clasp + SBCL), deferring AllegroCL. The deferral closes automatically when
`pal-allegro.lisp` lands (ADR 0004 pre-authorizes it). Final program acceptance
(REQUIREMENTS §9) still requires SBCL **and** AllegroCL.

## M1 open dependency

The P0 **exit gate** is XCDR **byte-exactness vs. RTI-generated vectors** + the
exact 16-bit encapsulation representation IDs — both of which must come from the
spec/wire oracle, never from memory (CLAUDE.md §4, FR-CDR-3). Codec machinery and
codegen proceed now (round-trip-verified); the byte-exact corpus slots in once the
oracle source is chosen.
