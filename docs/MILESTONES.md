# Milestone status

Exit gates are defined in `IMPLEMENTATION-PLAN.md` §4. This file tracks status.

| Milestone | Scope | Status |
|---|---|---|
| **M0** | Contracts, skeleton, CI | ✅ **PASSED** — Clasp + SBCL green. **AllegroCL exception, by explicit owner command (DG1SBG), 2026-06-04** — see ADR 0004. |
| **M1** | P0 XCDR byte-exact + real PALs | 🟡 **IN PROGRESS** — XCDR1/2 codec + spec-pinned encapsulation + s-expr type compiler (`define-dds-type` → defstruct + monomorphic codecs + type-support) round-tripping on Clasp+SBCL. Remaining: full RTI byte-exact vectors (oracle), IDL parser, mutable/appendable framing, key-hash, string/sequence member pooling. |
| M2 | P1 minimal RTPS + Connext Shapes interop | 🟡 **IN PROGRESS (interop validated against real RTI)** — RTPS wire codec + reliable engine + HistoryCache done. **SPDP/SEDP discovery over UDP** (unicast + **multicast**, full locator-list parsing), **reliable user-data plane over UDP**, **native UDPv4 PAL sockets**, generated ShapeType end-to-end. Output **validated against the tshark RTPS dissector** (`make wire`, the interop oracle — caught + fixed the XCDR2 encapsulation-id bug). **Live RTI Connext 7.3.1**: bidirectional SPDP+SEDP discovery confirmed (DDSSpy `New writer`), my locator resolution of RTI's multi-locator (UDPv4+SHMEM) advert, RTI→our-subscriber data received, writer/reader corrected to keyed + readerId=UNKNOWN. Standalone `square-pub/sub/spy` harness (`docs/interop-shapes.md`). Exit gate remaining: confirm `rtishapesdemo` render both directions; generic-tool (DDSSpy) display needs XTypes `PID_TYPE_OBJECT` (M4). |
| M3 | P2 DCPS + QoS + conditions + content-filter | 🟡 **STARTED** — QoS policy model + **RxO matching truth table** (FR-QOS-1/2): reliability/durability/deadline/latency-budget/ownership/liveliness/destination-order/presentation/data-representation + multi-incompat + partition; DDS 1.4 §2.2.3; green Clasp+SBCL. Next: DCPS entity model (CLOS), instance lifecycle + read/take + SampleInfo, conditions/WaitSets, content-filtered topics, builtin-topic readers. |
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
spec/wire oracle, never from memory (the operating contract §4, FR-CDR-3). Codec machinery and
codegen proceed now (round-trip-verified); the byte-exact corpus slots in once the
oracle source is chosen.
