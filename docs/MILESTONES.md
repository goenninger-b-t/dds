# Milestone status

Exit gates are defined in `IMPLEMENTATION-PLAN.md` §4. This file tracks status.

| Milestone | Scope | Status |
|---|---|---|
| **M0** | Contracts, skeleton, CI | ✅ **PASSED** — Clasp + SBCL green. **AllegroCL exception, by explicit owner command (DG1SBG), 2026-06-04** — see ADR 0004. |
| **M1** | P0 XCDR byte-exact + real PALs | 🟡 **IN PROGRESS** — XCDR1/2 codec + spec-pinned encapsulation + s-expr type compiler (`define-dds-type` → defstruct + monomorphic codecs + type-support) round-tripping on Clasp+SBCL. Remaining: full RTI byte-exact vectors (oracle), IDL parser, mutable/appendable framing, key-hash, string/sequence member pooling. |
| M2 | P1 minimal RTPS + Connext Shapes interop | 🟢 **BIDIRECTIONAL LIVE INTEROP ACHIEVED (2026-06-09)** — RTPS wire codec + reliable engine + HistoryCache; **SPDP/SEDP discovery over UDP** (unicast + multicast, full locator-list parsing); **reliable user-data plane over UDP**; **native UDPv4 PAL sockets**; generated ShapeType end-to-end; tshark-validated (`make wire`). **Full bidirectional data exchange with live RTI Connext 7.3.1 over UDP, reliable:** forward (Connext→our `square-sub`) **251 ShapeType samples**; reverse (our `square-pub`→Connext `shapes_sub`) **228 samples** with Connext ACKNACKing our writer. Required a chain of interop fixes (all 2026-06-09): non-zero **VendorId** `0x01FF` (Connext ignores the zero/unknown id); **reliable builtin-SEDP ACKNACK** (Connext now pushes its SEDP); **user-data HEARTBEAT** keyed by the remote writer's EntityId; **stable per-writer SEDP sequence numbers** (an incrementing SN gapped Connext's reliable discovery reader permanently — the real match blocker); **DATA InlineQos (Q) parsing** for keyed samples (`PID_KEY_HASH`); and **keyed writer kind 0x02 + announced/data-plane EntityId alignment** (a no-key writer never matches Connext's keyed reader; the id mismatch caused a retransmit storm). Standalone `square-pub/sub/spy` harness (`docs/interop-shapes.md`) + Connext-side oracles (`interop/connext/shapes-pub|sub`). Residual (non-blocking): `rtishapesdemo` GUI render check; generic-tool (DDSSpy) display needs XTypes `PID_TYPE_OBJECT` (M4); DATA_FRAG; per-type keyed/no-key selection (keyed-only today). |
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

**Update (2026-06-09).** The foreign-vendor question is **resolved: no** — with our stack
on VendorId `0x01FF` + reliable SEDP, Connext pushed its SEDP to our foreign-vendor reader
carrying `PID_TYPE_OBJECT_LB` and **no** `0x0075`, so the LB reader is the **required** path,
not optional. The inbound LB path landed in increments: `inflate-type-object-lb` (ZLIB +
`*max-type-object-bytes*` guard, `chipz`), SEDP capture (`+pid-type-object-lb+` 0x8021 →
`endpoint-data-type-object-lb`, opaque at L4), and a type **fingerprint**
(`type-object-strings` / `type-object-mentions-all-p`) — the inflated payload is RTI's
proprietary legacy TypeObject, so the full structural parse is deferred (robustness-only).
On top of that an **advisory** match-time hook landed: `assess-type-object-lb` +
`type-support-fingerprint-names` yield a verdict that DCPS `%on-disc-match` records per matched
endpoint (`entity-type-compat`) and can log (`*type-compat-log*`) — **advisory only, never a
match gate** (ADR 0009). `b2b` (minimal-hash equality enforcement) stays retired.
