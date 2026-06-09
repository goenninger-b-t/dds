# Milestone status

Exit gates are defined in `IMPLEMENTATION-PLAN.md` §4. This file tracks status.

| Milestone | Scope | Status |
|---|---|---|
| **M0** | Contracts, skeleton, CI | ✅ **PASSED** — Clasp + SBCL green. **AllegroCL exception, by explicit owner command (DG1SBG), 2026-06-04** — see ADR 0004. |
| **M1** | P0 XCDR byte-exact + real PALs | 🟡 **IN PROGRESS** — XCDR1/2 codec + spec-pinned encapsulation + s-expr type compiler (`define-dds-type` → defstruct + monomorphic codecs + type-support) round-tripping on Clasp+SBCL. Remaining: full RTI byte-exact vectors (oracle), IDL parser, mutable/appendable framing, key-hash, string/sequence member pooling. |
| M2 | P1 minimal RTPS + Connext Shapes interop | 🟡 **IN PROGRESS (interop validated against real RTI)** — RTPS wire codec + reliable engine + HistoryCache done. **SPDP/SEDP discovery over UDP** (unicast + **multicast**, full locator-list parsing), **reliable user-data plane over UDP**, **native UDPv4 PAL sockets**, generated ShapeType end-to-end. Output **validated against the tshark RTPS dissector** (`make wire`, the interop oracle — caught + fixed the XCDR2 encapsulation-id bug). **Live RTI Connext 7.3.1**: bidirectional SPDP+SEDP discovery confirmed (DDSSpy `New writer`), my locator resolution of RTI's multi-locator (UDPv4+SHMEM) advert, RTI→our-subscriber data received, writer/reader corrected to keyed + readerId=UNKNOWN. Standalone `square-pub/sub/spy` harness (`docs/interop-shapes.md`). Exit gate remaining: confirm `rtishapesdemo` render both directions; generic-tool (DDSSpy) display needs XTypes `PID_TYPE_OBJECT` (M4). |
| M3 | P2 DCPS + QoS + conditions + content-filter | 🟢 **CORE DONE (P2 surface complete, green Clasp+SBCL)** — **QoS** policy model + **RxO matching truth table** (FR-QOS-1/2, DDS 1.4 §2.2.3; reliability/durability/deadline/latency-budget/ownership/liveliness/destination-order/presentation/data-representation + multi-incompat + partition), with RELIABILITY/DURABILITY carried on SEDP so incompatible QoS blocks matching **and** delivery. **DCPS** entity model (CLOS) + instance lifecycle + read/take + SampleInfo. **Conditions/WaitSets** (FR-DCPS-2): Guard/Read/Query/StatusCondition + read/take_w_condition + CLOS Reader/Writer/Topic listeners fired from the receiver thread; `WaitSet::wait` is **condvar-driven** (ADR 0007), not polled. **Content-filtered topics** (FR-DCPS-5): DDS 1.4 Annex B SQL subset (lexer+recursive-descent parser → predicate closure; `= <> > >= < <= BETWEEN LIKE AND/OR/NOT`, `%n` params) filtering reader-side; QueryCondition takes SQL or a Lisp predicate. **Statuses** (FR-DCPS-3): SUBSCRIPTION/PUBLICATION_MATCHED, (OFFERED\|REQUESTED)_INCOMPATIBLE_QOS, INCONSISTENT_TOPIC, SAMPLE_REJECTED vs RESOURCE_LIMITS. **Builtin-topic readers** (FR-DCPS-6): DCPSParticipant/Publication/Subscription/Topic surfaced from SPDP+SEDP. Remaining (deferred): deadline/liveliness/sample-lost statuses need an engine timer/lease signal; SQL writer-side + nested fields; RTPS-layer (vs DCPS-cache) SAMPLE_REJECTED block/NACK. |
| M4 | P3 XTypes + TypeLookup + assignability | 🟡 **IN PROGRESS (step b2a landed)** — Structural **TypeIdentifier/TypeObject** model built by `define-dds-type` (FR-TYPE-2; primitives/string8/plain-sequence/hash-EK_MINIMAL + Minimal struct w/ key flag + byte-exact NameHash). **XCDR2-LE MinimalTypeObject serializer + EquivalenceHash** = MD5(serialized TypeObject)[0:14] (XTypes §7.3.4.5/§7.3.4.9.1; §7.4.3.5.3 VM framing, DHEADER backpatch, nested-struct recursion; golden vector for `struct pt{long x;}`). **Assignability** + TYPE_CONSISTENCY_ENFORCEMENT (FR-TYPE-4; §7.2.4.4 Tables 15-17/19; ALLOW/DISALLOW coercion decision). **Keyhash** per RTPS 2.5 §9.6.4.8 incl >16-byte MD5 (FR-TYPE-5; vendored MD5 RFC 1321). **TypeInformation codec** (FR-TYPE-3, step b1) + **SEDP `PID_TYPE_INFORMATION` (0x0075) emit/parse on the wire (b2a)**, auto-populated by DCPS create-datawriter/reader and the shapes harness. **PROVISIONAL** (owner 2026-06-06 build-now-confirm-vs-Connext): the no-encap-header hash buffer + struct/member flag bytes are spec-faithful but **unconfirmed against a Connext oracle**. **NEXT = confirm the EquivalenceHash, then b2b** (hash-equality match enforcement — gating on the provisional hash now would false-reject conformant peers). Deferred: TypeLookup request/reply service, DynamicData (FR-TYPE-6), union/enum/bitmask/array/map/alias rules, SCC/cyclic types. |
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

## M4 open dependency

The XCDR2 MinimalTypeObject serializer and its `EquivalenceHash` are **landed but
PROVISIONAL** (hash over the TypeObject serialized **without** an encapsulation header;
`struct_flags`/`member_flags` spec-faithful but unconfirmed).

**Update (2026-06-08, ADR 0009).** The `interop/connext/typeobject-probe` was driven
against live Connext 7.3.1. **Default Connext (RTI↔RTI) does not emit
`PID_TYPE_INFORMATION` (0x0075) — it advertises the type via the vendor
`PID_TYPE_OBJECT_LB` (0x8021), a ZLIB-compressed _complete_ TypeObject — so the minimal
`EquivalenceHash` is not on the wire and cannot be confirmed from this capture.** Also
`rtiddsgen` bounds the unbounded `color` at 255, a second reason our committed hash/`87 B`
won't match. Consequence: **b2b as specified ("enforce minimal-hash equality at SEDP
match time") is retired** — it would false-reject every stock Connext peer. Matching is
redirected to type-name + structural assignability, consuming `PID_TYPE_OBJECT_LB` /
TypeLookup, with minimal-hash equality only an opportunistic fast-path (ADR 0009). The
decompressed complete TypeObject **did** confirm `@final`, member ids 0..3, `@key color`,
three `INT_32`. Open: does Connext emit `0x0075` to a **foreign-vendor** peer or for a
larger type? That decides whether the hash fast-path is ever reachable.
