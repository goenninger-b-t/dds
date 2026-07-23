# REQUIREMENTS — Common Lisp DDS/RTPS Stack (XCDR-based), Connext-class

**Status:** Draft for review · **Audience:** implementing engineers + coding subagents · **Tone:** normative, terse.
**Scope owner:** DG1SBG. **Working name in this doc:** `dds` (rename at will).

> Read `IMPLEMENTATION-PLAN.md` alongside this. This file says *what* and *how well*; the plan says *how* and *in what order*.

---

## 0. How to read this document

- **MUST / SHALL** = hard requirement, conformance-gating.
- **SHOULD** = strong default; deviation requires an ADR (architecture decision record).
- **MAY** = optional / profile-gated.
- **Confidence tags** `(C: high|moderate|low|unknown)` mark *my* certainty about a stated external fact, not the priority of the requirement. Anything `(C: low|unknown)` MUST be verified against the cited spec before code depends on it.
- Requirement IDs are stable handles for the plan and the verification matrix.

---

## 1. Purpose & scope

Build a **data-centric publish/subscribe** middleware in Common Lisp implementing the **OMG DDS** application model on the **OMG DDSI-RTPS** wire protocol, with **OMG CDR / Extended CDR (XCDR1 + XCDR2)** as the foundational serialization layer. The stack MUST **interoperate on the wire** with RTI Connext and at least one open-source RTPS implementation, and MUST approach Connext-class **median** performance on the supported Lisp implementations.

### 1.1 In scope (this program)

Core DDS/DCPS + RTPS + discovery + XTypes/XCDR + the high-value performance differentiators (batching, asynchronous publication with flow control, shared-memory transport, zero-copy/SHMEM, a FlatData-equivalent language binding, serialization-time compression, durable history). DDS Security as a gated late profile. A type/IDL compiler (the `rtiddsgen` analogue) generating `defstruct`s and codecs.

### 1.2 Explicitly out of scope (this program) — see §13

Routing Service, Recording/Replay Service, Cloud Discovery Service, Admin Console / Monitor GUIs, Database/Web Integration, Limited-Bandwidth plugins, Queuing Service, TSS, spreadsheet add-ins. **(Two services are now IN scope, each by explicit owner directive and each recorded in an ADR: the durability/persistence service — 2026-06-18, ADR 0021 — because DDS TRANSIENT/PERSISTENT durability requires it; and the distributed logging service — 2026-07-23, ADR 0082 — §5.14. The remaining services listed here stay out. Exceptions are enumerated rather than inferred: a scope boundary that grows silently is not a boundary.)** **Rationale:** these are the bulk of what makes Connext *Professional* "Professional," and each is a project. They are deferred, not designed-out; the architecture MUST NOT preclude them.

### 1.3 The non-negotiable constraints (from the brief)

1. **CLOS is permitted and preferred wherever it exhibits no performance degradation.** It is the default for the control plane, the public API, listeners, conditions, discovery, the type compiler, and tooling. `defstruct` + monomorphized code generation (and, where per-sample dispatch across many types is required, manual vtables) is mandatory only on the **measured hot path** (CDR primitives, generated per-type codecs, buffer/cursor, `CacheChange`/`SampleInfo`, the RTPS engine's per-sample type dispatch). The boundary is decided by **measurement, not dogma** (see FR-LANG / NFR-CLOS).
2. **A per-implementation lower layer** (Platform Abstraction Layer, PAL) isolating implementation-specific optimizations for **SBCL, AllegroCL, and Clasp**.
3. **Connext-class features and performance** as the north star, scoped per §1.1 and quantified in §6 and NFR-PERF.

---

## 2. Normative references

Implementations MUST conform to the following, at the versions stated. Where a version is `(C: low)`, confirm the exact OMG formal document number before relying on clause numbers.

| Ref | Spec | Version | Note |
|-----|------|---------|------|
| [DDS] | Data Distribution Service | **1.4** (formal, Apr 2015) | DCPS model, QoS, entities. `(C: high)` |
| [RTPS] | DDS Interoperability Wire Protocol (DDSI-RTPS) | **2.5** (formal, Apr 2022) | Wire protocol, discovery, reliability. `(C: high)` |
| [XTYPES] | Extensible and Dynamic Topic Types for DDS | **1.3** (formal); 1.4 in RTF | Type system, XCDR1/XCDR2, TypeObject/TypeIdentifier, TypeLookup. `(C: high for 1.3; moderate that 1.3 is still latest *formal*)` |
| [CDR] | CDR as defined by CORBA/GIOP, extended by [XTYPES] | — | Classic CDR = XCDR1 PLAIN baseline. `(C: high)` |
| [SEC] | DDS Security | **1.1** (formal, ~2018) | Auth/AccessControl/Crypto/Logging/Tagging plugins. `(C: moderate)` |
| [IDL] | OMG Interface Definition Language | **4.2** | Type definition source language. `(C: moderate)` |
| [DDS-RPC] | RPC over DDS | **1.0** | Request/Reply + RPC pattern. `(C: moderate)` |
| [PSM-CXX] | ISO/IEC C++ PSM (DDS-PSM-Cxx) | 1.x | Basis of RTI's "Modern C++" API; used as an API-shape reference only. `(C: moderate)` |

**Reference implementations for clean-room study (NOT to copy):** RTI Connext 7.x (gold interop target, proprietary — study behavior, never source), eProsima Fast DDS (Apache-2.0), Eclipse Cyclone DDS (EPL/EDL), OpenDDS (open). Wireshark RTPS dissector for wire validation. See NFR-IP.

---

## 3. Definitions (abbreviated glossary)

DCPS (Data-Centric Pub/Sub); GUID = `GuidPrefix (12B) + EntityId (4B)`; Locator = `(kind, port, address[16])`; SN = 64-bit sequence number; PID = Parameter ID (in a RTPS ParameterList); SPDP/SEDP = Simple Participant/Endpoint Discovery Protocol; PDP/EDP = Participant/Endpoint Discovery Phase; HB = HEARTBEAT; XCDR1/XCDR2 = Extended CDR encoding versions; DHEADER = delimiter header (XCDR2 appendable); EMHEADER = member header (XCDR2 mutable); RxO = Requested-offered QoS matching; PAL = Platform Abstraction Layer (this project's L0); type-support = generated per-type function bundle. Full glossary maintained in `/docs/glossary.md`.

---

## 4. Conformance profiles

Conformance is **profiled** so milestones are demonstrable and "parity" is decomposable.

- **P0 — CDR Core:** XCDR1 + XCDR2 codec, byte-exact against vectors. (Foundational.)
- **P1 — Minimal RTPS:** best-effort + reliable stateful writer/reader, DATA/HEARTBEAT/ACKNACK/GAP, SPDP+SEDP, UDPv4 uni+multicast. **Interop with Connext "Shapes"** required.
- **P2 — DCPS:** full entity model, QoS set + RxO matching, conditions/WaitSets, instances, read/take, content-filtered topics, query conditions.
- **P3 — XTypes:** extensible/appendable/mutable types, TypeObject/TypeIdentifier, TypeLookup, type assignability + `@key`, `@optional`, `@default`, etc.
- **P4 — Performance differentiators:** batching, async + flow controllers, SHMEM transport, Zero-Copy-over-SHMEM, FlatData-equivalent binding, serialization-time compression, fragmentation (DATA_FRAG).
- **P5 — Durability/Reliability hardening:** TRANSIENT_LOCAL durability, durable writer history, large-data + late-joiner correctness, multi-channel writers.
- **P6 — Security (gated):** DDS-Security plugins.
- **P7 — Tooling/Services (gated, mostly §13):** spy, gen, monitoring hooks; services only if separately funded.

A build is "**Connext-class (core)**" when P0–P5 pass conformance + interop + the §6 performance gates on SBCL and AllegroCL; Clasp is allowed to trail by one profile (NFR-PORT).

---

## 5. Functional requirements

### 5.1 FR-CDR — Common Data Representation (foundational)

- **FR-CDR-1 (MUST):** Implement **XCDR1** (classic CDR) encode/decode: primitives with natural alignment (1/2/4/8), both endiannesses, strings (4-byte length + NUL-terminated octets), bounded/unbounded sequences (4-byte length + elements), arrays, structs, unions (discriminator + branch), enums.
- **FR-CDR-2 (MUST):** Implement **XCDR2**: FINAL (plain), APPENDABLE (DHEADER-delimited), MUTABLE (per-member EMHEADER with member-id + length-code), plus `@optional` member handling. XCDR2 **caps maximum alignment at 4 bytes** (8-byte primitives align to 4, unlike XCDR1's align-to-8). `(C: moderate-high; verify against [XTYPES] §7.4 serialization rules — this divergence is the single most common interop bug, and it makes FINAL-only types that contain 8-byte members *non*-equivalent between XCDR1 and XCDR2.)`
- **FR-CDR-3 (MUST):** Encapsulation header handling: 4-byte SerializedPayload header = 2-byte RepresentationIdentifier + 2-byte options. Support identifiers for `CDR_BE/LE` (XCDR1 plain), `PL_CDR_BE/LE` (XCDR1 mutable/param-list), `CDR2_BE/LE` (XCDR2 plain), `D_CDR2_BE/LE` (delimited), `PL_CDR2_BE/LE` (mutable). **CDR alignment origin is the first byte after the 4-byte encapsulation header.** `(C: moderate-high; exact 16-bit identifier constants MUST be taken from [XTYPES]/[RTPS] tables — do not hard-code from memory.)`
- **FR-CDR-4 (MUST):** Default data representation is **XCDR2** for new types; XCDR1 retained for legacy/builtin interop. `(C: high — confirmed by XTypes RTF intent.)`
- **FR-CDR-5 (MUST):** A two-pass or precomputed **serialized-size** path so buffer allocation is exact and copy-free; no "grow buffer" reallocation in the data path.
- **FR-CDR-6 (MUST):** Map/struct/sequence DHEADER semantics per spec (note the known XTypes ambiguity: non-trivial maps carry a DHEADER but **not** an entry count, unlike sequences — implement per spec and add an interop toggle). `(C: moderate; this is a live OMG issue.)`
- **FR-CDR-7 (SHOULD):** Codec functions are **generated per type** (monomorphic) for the data path; a generic reflective codec MAY exist for tools/DynamicData but MUST NOT be on the hot path.
- **FR-CDR-8 (MUST):** Byte-exact conformance against (a) RTI-generated reference vectors and (b) [XTYPES] worked examples, both endiannesses, all extensibility kinds.

### 5.2 FR-TYPE — Type system & XTypes

- **FR-TYPE-1 (MUST):** Support FINAL / APPENDABLE / MUTABLE extensibility; `@key`, `@optional`, `@default`, `@id`, `@hashid`, `@external`, `@must_understand`, `@nested`, bit_bound for enums/bitmask, bitset, union, sequence/array/string/wstring bounds, alias/typedef. `(C: moderate; confirm full annotation list against [XTYPES] Table 21.)`
- **FR-TYPE-2 (MUST):** **TypeObject / TypeIdentifier** (Minimal and Complete) generation and parsing; equality/hash for TypeIdentifier.
- **FR-TYPE-3 (MUST):** **TypeLookup Service** builtin endpoints (request/reply) for remote type discovery; data representation XCDR2. `(C: moderate-high.)`
- **FR-TYPE-4 (MUST):** **Type assignability / consistency enforcement** per `TYPE_CONSISTENCY_ENFORCEMENT` (TypeConsistencyKind, ignore_sequence_bounds, ignore_string_bounds, ignore_member_names, prevent_type_widening, force_type_validation).
- **FR-TYPE-5 (MUST):** **Key handling** — compute the key hash (MD5 of the serialized key fields, big-endian XCDR, per [RTPS]/[XTYPES] rules; ≤16 bytes used directly, else MD5) for instance identity. `(C: moderate-high; verify the exact keyhash rule, including the "≤16 serialized key bytes" shortcut.)`
- **FR-TYPE-6 (MUST):** **DynamicType / DynamicData** for tools and schema-on-the-fly (reflective, off hot path). MAY be a later sub-deliverable but the TypeObject machinery it needs is P3.

### 5.3 FR-LANG — Language mapping (CLOS-where-free, defstruct-on-the-hot-path)

**Governing rule (FR-LANG-0, MUST):** CLOS is **permitted and preferred** for any construct that exhibits **no performance degradation** against the NFR-PERF targets. `defstruct` + monomorphized code generation + (where needed) manual vtables are **mandatory only on the measured hot path**. "Hot path" = anything executed per sample or per primitive field on the latency/throughput path: CDR primitive ops, generated per-type codecs, buffer/cursor, `CacheChange`/`SampleInfo`, and the RTPS engine's per-sample type dispatch. Everything else (entity model, QoS, listeners, conditions, discovery events, the type compiler, DynamicData, tooling) defaults to CLOS. **Disputes are settled by the bench harness (NFR-PERF), not by preference.**

- **FR-LANG-1 (MUST):** **Hot-path data types** (the wire-mapped sample structs the codec touches per field) map to a **standard `defstruct`** (structure-object; not `:type list/vector`, to preserve type tagging and inline-able typed accessors). The generated codec for these types is **monomorphic functions**, never generic functions. **Entity, QoS, and configuration types MAY be CLOS** (and are preferred to be where it costs nothing — see FR-LANG-1b).
- **FR-LANG-1b (SHOULD):** The **entity model** (`DomainParticipant`, `Publisher`, `Subscriber`, `DataWriter`, `DataReader`, `Topic`) SHOULD use CLOS for structure, inheritance, and extensibility, **provided** the per-sample operations (`write`/`read`/`take`) reach the monomorphic generated codec through a directly-stored function/closure slot (or a verified-monomorphic call site), so that at most **one** dispatch occurs per operation and the heavy work is dispatch-free. A **dispatch-free typed fast-path entry** MUST also be provided for batching/burst loops.
- **FR-LANG-2 (MUST):** Template-style polymorphism (per type) is achieved by **code generation** (monomorphization). Virtual-dispatch-style polymorphism on the **per-sample** path (the engine iterating endpoints of many different types — a megamorphic call site, CLOS's worst case) is achieved by a **manual vtable**: a plain `defstruct` whose slots hold `function` objects. Dispatch there = one typed slot read + `funcall`, with no type-cache probe. **Off** the per-sample path, generic-function dispatch is permitted and preferred.
- **FR-LANG-3 (MUST):** A **`type-support` record** per registered type bundles: `serialize`, `deserialize`, `serialized-size`, `key-hash`, `typeobject`, `typeidentifier`, allocator/pool hooks, and FlatData offset/builder accessors (P4). For zero-probe per-sample dispatch it is a **`defstruct` of function objects**; the *registry* that maps types→`type-support` and the surrounding machinery MAY be CLOS. Engine hot-path code is written against this record only.
- **FR-LANG-4 (MUST):** The **CL condition system** is used normally for the control-plane error/return model (it never executes on the steady-state sample path). Listeners, status/error handling, and lifecycle errors use idiomatic CLOS/conditions.
- **FR-LANG-5 (SHOULD):** No data-path **consing**, regardless of CLOS-vs-defstruct elsewhere. Generated codecs use preallocated pools, `dynamic-extent` for transients, and write into caller-supplied buffers. Vtable closures are created once at type-registration, never per sample. **Instantiating a CLOS object (or any object) per sample is a hot-path allocation and is therefore forbidden on the hot path for the same reason consing is** (NFR-DET). CLOS-where-free means CLOS *off* the per-sample path; it never licenses per-sample object creation.
- **FR-LANG-6 (MUST):** Public API symbols, packages, and naming are stable and documented; the generated-code contract (function names/signatures the compiler emits) is versioned.
- **FR-LANG-7 (MUST):** Every conversion of a construct from CLOS to defstruct/codegen/manual-vtable (or the reverse) is justified by a **before/after measurement** recorded in the bench report and, if it changes a contract, an ADR. No such change is made on intuition alone.
- **FR-LANG-8 (MUST):** **Every function parameter has a type declaration and every function has a fully type-specified signature** — declared argument types **and** a declared return type, expressed via `declaim (ftype (function (<arg-types>) <return-type>) <name>)` and/or inline `(declare (type ...))` / `the`. This holds for **hot-path and non-hot-path code alike**; an untyped parameter or an unspecified return type is a **defect, not a style choice**. Generated code (FR-TOOL-1) MUST emit these declarations for every function it produces. Rationale: maximal compiler type inference (hot-path performance, NFR-PERF), compile-time type-error detection, and the signature *is* the documented contract (FR-LANG-6). *(Owner directive, 2026-06-04; a CI `gate-types` lint SHOULD enforce it.)*

### 5.4 FR-DCPS — Entities, QoS, access

- **FR-DCPS-1 (MUST):** Entities: `DomainParticipant`, `DomainParticipantFactory`, `Topic` (+ ContentFilteredTopic, MultiTopic optional), `Publisher`, `Subscriber`, `DataWriter`, `DataReader`, `TypeSupport`. **CLOS preferred** (structure/inheritance/extensibility), subject to FR-LANG-1b (per-sample ops reach the monomorphic codec through a stored function slot + a dispatch-free fast path). Explicit lifecycle (create/delete, enable, factory autoenable per ENTITY_FACTORY).
- **FR-DCPS-2 (MUST):** **Listeners, Conditions, WaitSets, GuardConditions, StatusConditions, ReadConditions, QueryConditions.** WaitSet wait with timeout; condition triggering integrated with the event loop. **Listeners SHOULD be CLOS objects with overridable methods** (the natural DDS idiom and off the per-sample path — events such as DATA_AVAILABLE coalesce and do not fire per sample); a plain-callback form MAY also be offered for convenience.
- **FR-DCPS-3 (MUST):** **All standard statuses** with correct change/reset semantics: INCONSISTENT_TOPIC, OFFERED/REQUESTED_DEADLINE_MISSED, OFFERED/REQUESTED_INCOMPATIBLE_QOS, SAMPLE_LOST, SAMPLE_REJECTED, DATA_ON_READERS, DATA_AVAILABLE, LIVELINESS_LOST/CHANGED, PUBLICATION/SUBSCRIPTION_MATCHED.
- **FR-DCPS-4 (MUST):** **Instance lifecycle**: register/unregister/dispose; instance states (ALIVE, NOT_ALIVE_DISPOSED, NOT_ALIVE_NO_WRITERS); view states (NEW, NOT_NEW); sample states (READ, NOT_READ). `read`/`take` with sample selection by states, plus `*_w_condition`, `*_instance`, `*_next_instance`. `SampleInfo` fully populated (source/reception timestamps, SN, generation counts, ownership, valid_data flag).
- **FR-DCPS-5 (MUST):** **Content-filtered topics** with an SQL-like filter grammar (the DDS filter expression + parameters), evaluated writer-side and/or reader-side; **query conditions** reusing the same grammar. `(Grammar per [DDS] Annex on the SQL subset.)`
- **FR-DCPS-6 (MUST):** **Builtin topics**: `DCPSParticipant`, `DCPSPublication`, `DCPSSubscription`, `DCPSTopic` readers exposed to the app.
- **FR-DCPS-7 (SHOULD):** `DataWriter` `write_w_timestamp`, `dispose`, `unregister_instance`, `lookup_instance`, `get_key_value`, coherent sets (PRESENTATION), and `wait_for_acknowledgments`.

### 5.5 FR-QOS — Policies and matching

- **FR-QOS-1 (MUST):** Implement the **DDS 1.4 standard QoS policies** with correct defaults and mutability rules: USER_DATA, TOPIC_DATA, GROUP_DATA, DURABILITY, DURABILITY_SERVICE, PRESENTATION, DEADLINE, LATENCY_BUDGET, OWNERSHIP, OWNERSHIP_STRENGTH, LIVELINESS, TIME_BASED_FILTER, PARTITION, RELIABILITY, TRANSPORT_PRIORITY, LIFESPAN, DESTINATION_ORDER, HISTORY, RESOURCE_LIMITS, ENTITY_FACTORY, WRITER_DATA_LIFECYCLE, READER_DATA_LIFECYCLE. Plus XTypes' **DATA_REPRESENTATION** and **TYPE_CONSISTENCY_ENFORCEMENT**. `(C: high for the 22 + 2 list.)`
- **FR-QOS-2 (MUST):** **Request/Offered (RxO) compatibility** computed exactly per spec; incompatibilities raise OFFERED/REQUESTED_INCOMPATIBLE_QOS and prevent match. Immutable-after-enable policies enforced.
- **FR-QOS-3 (MUST):** QoS policies with copy-by-value semantics and profile loading from XML (a Connext-style QoS profiles file) — XML loader MAY be later but the in-memory model is P2. **Implementer's choice of `defstruct` or CLOS** (`defstruct` leans cleaner for value-copy semantics; CLOS leans cleaner for validation/mutability); QoS objects are control-plane and not performance-gating, so CLOS is permitted and fine.
- **FR-QOS-4 (MUST):** Vendor-extension QoS namespace reserved and clearly separated from standard policies.

### 5.6 FR-RTPS — Wire protocol engine

- **FR-RTPS-1 (MUST):** RTPS **Message** = Header (`"RTPS"` magic, ProtocolVersion 2.5, VendorId, GuidPrefix) + sequence of **Submessages**. Implement submessages: PAD, ACKNACK, HEARTBEAT, GAP, INFO_TS, INFO_SRC, INFO_REPLY (+IP4), INFO_DST, NACK_FRAG, HEARTBEAT_FRAG, DATA, DATA_FRAG. Security submessages (SEC_PREFIX/POSTFIX, SRTPS_PREFIX/POSTFIX) gated to P6. `(C: high for the core submessage set.)`
- **FR-RTPS-2 (MUST):** **VendorId** — obtain/declare a vendor id; until assigned, use a clearly non-conflicting development value and document it. `(C: n/a; must be coordinated with OMG.)`
- **FR-RTPS-3 (MUST):** Stateful **Writer** with per-matched-reader `ReaderProxy`, changes-for-reader state machine, HEARTBEAT scheduling (periodic + on-demand), responsive ACKNACK handling, GAP generation. Stateless writer for SPDP. Best-effort and reliable variants.
- **FR-RTPS-4 (MUST):** Stateful **Reader** with per-matched-writer `WriterProxy`, in-order/best-effort delivery, missing-sample tracking, ACKNACK generation (positive+negative), duplicate suppression, reliable reordering.
- **FR-RTPS-5 (MUST):** **HistoryCache** abstraction (writer and reader sides) honoring HISTORY (KEEP_LAST n / KEEP_ALL) and RESOURCE_LIMITS (max_samples / max_instances / max_samples_per_instance), with sample lifecycle and LIFESPAN expiry.
- **FR-RTPS-6 (MUST):** **Fragmentation** (DATA_FRAG / HEARTBEAT_FRAG / NACK_FRAG) for samples exceeding transport MTU; correct reassembly; configurable fragment size.
- **FR-RTPS-7 (MUST):** **Sequence numbers** as 64-bit (high i32 + low u32 on the wire), SequenceNumberSet bitmap encode/decode (the off-by-one and bitmap-base rules are a classic bug source — test exhaustively). `(C: high that this is bug-prone.)`
- **FR-RTPS-8 (MUST):** **GUID / EntityId / Locator** types and the well-known builtin EntityIds. Implement the **port-mapping formula**: with PB=7400, DG=250, PG=2, d0=0, d1=10, d2=1, d3=11 — discovery multicast `PB+DG·domainId+d0`; discovery unicast `PB+DG·domainId+d1+PG·participantId`; user multicast `PB+DG·domainId+d2`; user unicast `PB+DG·domainId+d3+PG·participantId`. `(C: high; standard DDS port mapping.)`
- **FR-RTPS-9 (MUST):** **ParameterList** (PID) encoding/decoding for discovery and PL_CDR types; handle `PID_SENTINEL`, unknown-PID skip, `must_understand` PIDs, and vendor PID ranges. Exact PID constants from [RTPS]/[XTYPES] tables. `(C: moderate; do not memorize PIDs.)`
- **FR-RTPS-10 (MUST):** Correct timing: HEARTBEAT period, nack-response/suppression delays, ACKNACK period, lease durations, with sane Connext-interoperable defaults.

### 5.7 FR-DISC — Discovery

- **FR-DISC-1 (MUST):** **SPDP** — periodic participant announcements via well-known multicast (default `239.255.0.1`, configurable), `SPDPdiscoveredParticipantData`, lease duration + liveliness, builtin participant writer/reader. `(C: moderate-high on the default multicast address.)`
- **FR-DISC-2 (MUST):** **SEDP** — reliable builtin Publications/Subscriptions/Topics writers+readers exchanging `DiscoveredWriterData` / `DiscoveredReaderData` / `DiscoveredTopicData`; endpoint matching driven by topic name + type + QoS RxO.
- **FR-DISC-3 (MUST):** **Participant liveliness** via the builtin ParticipantMessage (P2P) writer/reader; AUTOMATIC and MANUAL liveliness kinds.
- **FR-DISC-4 (SHOULD):** Discovery scalability controls (initial peers list, unicast-only mode for no-multicast networks, peer participant index ranges).
- **FR-DISC-5 (MAY):** A Cloud-Discovery-Service-equivalent rendezvous for WAN/no-multicast is **deferred** (§13) but the initial-peers mechanism (FR-DISC-4) MUST cover the common no-multicast LAN case.

### 5.8 FR-XPORT — Transports

- **FR-XPORT-1 (MUST):** **UDPv4** unicast + multicast, with `SO_REUSEADDR`/`SO_REUSEPORT`, multicast TTL, `IP_MULTICAST_IF`, configurable socket buffer sizes.
- **FR-XPORT-2 (MUST):** **Shared memory (SHMEM)** transport for intra-host traffic (prerequisite for Zero-Copy).
- **FR-XPORT-3 (SHOULD):** **UDPv6**.
- **FR-XPORT-4 (SHOULD):** **TCP** transport (for NAT traversal / firewall-friendly WAN), including a TCP-WAN mode.
- **FR-XPORT-5 (MUST):** **Pluggable transport API** so transports are added without touching the engine; transport selection/priority per locator. The transport object MAY be CLOS; the **per-packet `send`** path MUST be reachable dispatch-free (a stored function/closure slot, or a call site verified monomorphic by the bench harness), since send sits in the latency path.
- **FR-XPORT-6 (SHOULD):** Batched syscall I/O (`sendmmsg`/`recvmmsg`) and scatter/gather (`sendmsg` iovec) where the OS supports it, surfaced through the PAL.

### 5.9 FR-PERF-FEAT — Performance differentiators (the Connext "Professional" deltas worth having)

- **FR-PF-1 (MUST):** **Batching** — multiple samples per RTPS submessage/packet, time- and size-triggered, to amortize per-sample overhead for small samples. `(C: high that this is decisive for small-sample throughput.)`
- **FR-PF-2 (MUST):** **Asynchronous publication + flow controllers** — a sender thread/queue decoupled from `write()`, with token-bucket / rate-shaped flow control; required for large data and DATA_FRAG pacing.
- **FR-PF-3 (MUST):** **Zero-Copy-over-SHMEM** — writer places samples in a SHMEM segment it owns and transmits small (≈16-byte) references; reader maps and reads in place; loan/return sample-pool ownership model. `(C: high; this is exactly RTI's mechanism — 16-byte references, zero intra-host copies.)`
- **FR-PF-4 (MUST):** **FlatData-equivalent language binding** — for annotated types, the in-memory layout **equals** the XCDR wire layout, so serialization/deserialization cost is zero; the type compiler emits **Offset** accessors (read/modify in place) and, for variable-size/mutable types, a **Builder**. FINAL FlatData types are restricted to fixed-size members. `(C: high; mirrors RTI FlatData: in-memory == wire, Offset + Builder, fixed-size-only for final.)`
- **FR-PF-5 (SHOULD):** **Serialization-time compression** (LZ4 mandatory; ZLIB/optional others) negotiated via QoS/PID, compressing once at serialization (not per transmission). `(C: high that RTI offers LZ4/ZLIB/BZIP2 at serialization.)`
- **FR-PF-6 (SHOULD):** **Multi-channel DataWriter** (partition traffic across locators/channels by filter) — P5.
- **FR-PF-7 (MUST):** **Pre-allocation mode** — steady-state operation performs **zero heap allocation**; all hot-path memory comes from the static, startup-allocated, non-GC'd arena sized by `*static-arena-bytes*` (NFR-MEM). This is the **default for hot paths**, not an optional add-on. The determinism lever; see NFR-DET and NFR-MEM.

### 5.10 FR-SEC — DDS Security (gated, P6)

- **FR-SEC-1 (MAY/MUST-if-P6):** Implement the five [SEC] plugins: Authentication (PKI/DH handshake), Access Control (permissions/governance documents, signed), Cryptographic (AES-GCM payload/submessage/RTPS-message protection), Logging, Data Tagging. Secure discovery (authenticated SPDP/SEDP). `(C: moderate on plugin breakdown.)`
- **FR-SEC-2 (MUST-if-P6):** Crypto MUST use vetted native libraries via the PAL FFI (e.g., libsodium/OpenSSL); **no hand-rolled crypto**.

### 5.11 FR-API — Lisp API surface

- **FR-API-1 (MUST):** A Lisp-idiomatic API over the `defstruct` entities: constructors with keyword QoS, `with-…` macros for scoped lifecycle, condition-based error handling (per FR-LANG-4), and a typed reader/writer obtained from a registered type (`(make-data-writer pub topic :type 'sensor-sample …)` → a struct whose `write` slot is the monomorphic generated function).
- **FR-API-2 (SHOULD):** An optional API layer shaped after the **ISO C++ PSM ("Modern C++")** semantics (RAII-equivalent via `with-…`, reference-type-equivalent handles) for users porting from Connext Modern C++.
- **FR-API-3 (MUST):** **Request/Reply + RPC** ([DDS-RPC]) as a layer over DCPS.
- **FR-API-4 (MUST):** Stable error/return model; every failure path documented; no silent drops outside explicitly-best-effort paths.

### 5.12 FR-TOOL — Tooling

- **FR-TOOL-1 (MUST):** **Type/IDL compiler** (`rtiddsgen` analogue): input IDL 4.2 *and* an s-expression type DSL; output `defstruct`s + monomorphic codecs + TypeObject/TypeIdentifier + key-hash + FlatData accessors + a `type-support` registration form. This is the linchpin of the no-CLOS strategy.
- **FR-TOOL-2 (SHOULD):** A **spy** tool (`rtiddsspy` analogue) printing discovered entities and sample traffic; built on DynamicData.
- **FR-TOOL-3 (SHOULD):** Wireshark/tshark-based **wire conformance harness** in CI.
- **FR-TOOL-4 (MAY):** Monitoring/statistics export (P7); GUIs out of scope (§13).

### 5.13 FR-INTEROP — Interoperability

- **FR-IO-1 (MUST):** Wire-interoperate with **RTI Connext 7.x** (publish/subscribe both directions) on the standard **Shapes** type, best-effort and reliable, with content filtering and the common QoS.
- **FR-IO-2 (MUST):** Wire-interoperate with **≥1** of Fast DDS / Cyclone DDS / OpenDDS.
- **FR-IO-3 (MUST):** Pass an **interop matrix** (each impl × each peer × each profile feature) maintained as living CI artifacts.
- **FR-IO-4 (MUST):** XCDR byte-exactness validated against peer-generated payloads (FR-CDR-8).

### 5.14 FR-LOG — Distributed logging (service + `dds.log` API; ADR 0082)

In scope by owner directive 2026-07-23 (§1.2). The service is the second carved-out exception to the
out-of-scope service suite, after durability.

- **FR-LOG-1 (MUST):** A **public, language-neutral log type** `LogEvent`, `@appendable` (XTypes 1.3 §7.2.2), **bounded** in every string, **keyed on source identity** (`host`, `process`). Published from any vendor's binding — C, C++, this stack — so the IDL (`interop/log/DdsLog.idl`) and the `define-dds-type` form are kept in lockstep and the type is validated by XCDR byte-exact corpus vectors (FR-CDR-8) in both endiannesses. Bounds are a **permanent** contract: `@appendable` permits added fields, never a widened bound.
- **FR-LOG-2 (MUST):** **Severity is the syslog numbering of RFC 5424 §6.2.1** (EMERG 0 … DEBUG 7), extended with **TRACE = 8** below DEBUG. Values are read from the RFC and cited at the definition, never recalled.
- **FR-LOG-3 (MUST):** A **`dds.log` package** providing one macro per severity plus `with-trace-scope`, and **categories** (`SUP`, `MEM`, …) with an independent per-category threshold. Call sites carry **function, file and line** captured at compile time — function exactly (via `defun*`), file/line best-effort through the PAL, reporting 0 where an implementation cannot supply a line (a documented NFR-PORT gap, never a silent zero).
- **FR-LOG-4 (MUST):** **A disabled level costs one threshold check and allocates nothing** — one `aref` at a constant index plus a comparison; `with-trace-scope` does not read the clock when TRACE is off. Verified by measurement, not assertion. Enabled emission allocates (it formats); `dds.log` is **not** hot-path-pure and the RTPS data plane MUST NOT call it except behind a level disabled by default.
- **FR-LOG-5 (MUST):** **The emit path never blocks the caller.** A bounded ring is drained by a worker thread that publishes RELIABLE/KEEP_ALL; backpressure is absorbed by the ring and by the worker, never by the application.
- **FR-LOG-6 (MUST):** **Overflow sheds by severity and is reported.** TRACE is shed first, then DEBUG, then INFO; EMERG/ALERT/CRIT/ERR are never shed while a slot remains. Drops are counted per severity and **reported through the DDS status machinery** (a vendor status bit clear of the OMG 0–14 range, StatusCondition, listener, `get_*_status` snapshot) — never printed. A per-source monotonic `sequence` makes loss independently observable at the collector.
- **FR-LOG-7 (MUST):** A **collector service** subscribing on a **configurable domain**, built on the durability service's shape (embedded library entity, multi-service runner, OTP-style supervisor, `log-service-main` CLI/env entrypoint returning a `ReturnCode_t`), with its own queue between reader and sinks so a slow sink cannot stall reception.
- **FR-LOG-8 (MUST):** **Configurable sinks with replaceable renderers.** Formatters and sinks are structs of closures (the durability store-vtable pattern). Slice 1: the five-field text file and newline-delimited JSON file. Follow-on: RFC 5424 UDP syslog (`PRI = facility*8 + severity`), HTTP bulk. JSON is produced by a **formatter function** that a deployment may replace.
- **FR-LOG-9 (MUST):** **Text rendering is fixed and golden-tested**: `<ISO 8601 UTC, 6 fractional digits>Z | <severity, left-aligned, 6 columns> | <category> | <function>() - <file>:<line> | <message>`. The 6-column field fixes `WARNING` → **`WARN`**. The owner's two reference lines are byte-exact test vectors.

---

## 6. Performance requirements (quantified) — NFR-PERF

Targets are **parity bands relative to RTI Connext on identical hardware/OS/transport**, not absolute numbers (absolute numbers depend entirely on the machine). Measure with a `perftest`-equivalent harness (NFR-TEST). All numbers are **p50 unless stated**; report full distributions.

| ID | Metric | Target | Confidence in attainability |
|----|--------|--------|------------------------------|
| NFR-PERF-1 | Small-sample (≤256 B) one-way latency, UDP loopback/LAN, p50 | within **1.5×** of Connext | moderate-high |
| NFR-PERF-2 | Small-sample one-way latency, **p99** | within **2×** of Connext | moderate |
| NFR-PERF-3 | Small-sample one-way latency, **p99.99 / max (jitter)** | within **3×** of Connext | **low** (GC tail risk) |
| NFR-PERF-4 | Throughput, small samples with batching | within **1.5×** | moderate-high |
| NFR-PERF-5 | Throughput, large samples (≥64 KB), UDP | within **1.2×**; ≥90% of line rate on GbE | moderate-high |
| NFR-PERF-6 | Zero-Copy/SHMEM large-sample latency | within **1.5×** (dominated by SHMEM + mmap, not Lisp) | moderate-high |
| NFR-PERF-7 | FlatData fixed-size sample: ser/deser cost | **zero** (read/write in place), matching RTI | high |
| NFR-PERF-8 | Steady-state heap allocation in pre-alloc mode | **0 bytes/sample** (verified by allocation counters) | moderate-high on SBCL/Allegro; **low** on Clasp |
| NFR-PERF-9 | Discovery time, 100 participants | within **2×** of Connext | moderate |

**Context anchors (verified):** RTI publishes sub-millisecond latency scaling ~linearly with payload, throughput >90% of line rate on GbE, and <100 µs at >200K samples/s; small-sample one-way latencies on fast x86 land in the tens-of-µs range; Zero-Copy reduces intra-host copies to zero; FlatData reduces copies from four to two. `(C: high — from RTI's own benchmark documentation.)`

**Brutal note (C: high):** NFR-PERF-3 is the requirement most likely to fail. A GC'd runtime cannot, in general, match a pre-allocating C++ stack's worst-case jitter without GC-inhibition tricks that trade safety for determinism. Treat hard-real-time tail parity as a research risk, not a commitment. If a hard-RT customer is the actual driver, the honest answer is "use Connext (or Connext Cert/Micro) for that node."

---

## 7. Non-functional requirements

### 7.1 NFR-CLOS — CLOS policy & hot-path purity
**(MUST)** CLOS is **permitted and preferred** wherever it exhibits no performance degradation against NFR-PERF. **(MUST)** The **hot path** is CLOS-free: no `defgeneric`/`defmethod` dispatch and no per-sample CLOS instantiation in the CDR primitives, generated per-type codecs, buffer/cursor, `CacheChange`/`SampleInfo`, or the RTPS engine's per-sample type dispatch — these use `defstruct` + monomorphic functions + manual vtables. **(MUST)** `print-object` and other GFs MUST NOT appear on hot-path data structs in a way that introduces dispatch on the sample path; provide explicit printer functions for those. **(MUST)** CI enforces a **hot-path-purity gate**: the build fails if `defmethod`/`defgeneric`/`defclass` (or per-sample CLOS allocation) appears in the designated hot-path packages (`dds.cdr`, generated-codec output, `dds.core.buffer`, the engine's per-sample dispatch module, `dds.rtps.history` change ops). Outside those packages, CLOS is unrestricted and is the preferred default. **(MUST)** Any change moving the CLOS/defstruct boundary is backed by a bench measurement (FR-LANG-7).

### 7.2 NFR-PORT — Portability across SBCL / AllegroCL / Clasp
**(MUST)** All layers above L0 are implementation-agnostic and depend **only** on the PAL contract. **(MUST)** SBCL and AllegroCL are co-equal first-class targets and the performance pacesetters. **(MAY-trail-by-one-profile)** Clasp is supported but permitted to lag by one conformance profile and to relax NFR-PERF-3/8 with a documented gap, given its conservative-GC determinism limits. **(MUST)** No feature is gated behind a single implementation except where it is intrinsically impossible elsewhere (documented per case).

### 7.3 NFR-DET — Determinism & GC posture
**(MUST)** Provide a **pre-allocation mode** (FR-PF-7): pools, history caches, buffers, fragment buffers, and per-reader/per-writer state are carved at init from the static, non-GC'd arena sized by `*static-arena-bytes*` (NFR-MEM); steady state allocates nothing. **(MUST)** No data-path consing (FR-LANG-5). **(SHOULD)** Tune per-impl GC (SBCL `bytes-consed-between-gcs`, generational sizing; Allegro `gsgc` parameters; Clasp Boehm/MPS tuning) and expose hooks. **(MAY, dangerous)** Short, bounded GC-inhibition windows around the tightest critical section, behind an explicit unsafe flag, only where measurement proves benefit and correctness is preserved. **(MUST)** Document the determinism gap vs. Connext honestly per impl.

### 7.4 NFR-MEM — Memory model (static, startup-allocated, non-GC'd memory on hot paths)
**(MUST)** All hot code paths use **static memory allocated once at startup that is not garbage-collected**, wherever meaningful (i.e., wherever the alternative is per-sample/per-packet allocation, or wherever a raw pointer/SAP into the memory is taken). "Not garbage-collected" means **off-heap / foreign memory** (e.g., `static-vectors`-style foreign-backed octet arrays, FFI-allocated regions, SHMEM segments) that the GC neither scans, moves, nor reclaims — **not** merely "pooled heap objects that happen to stay live."
**(MUST)** The **total amount of this static memory is configurable by a special (dynamic) variable** — the authoritative knob is **`*static-arena-bytes*`** (an integer byte budget), read **once at initialization** (DomainParticipantFactory init / first participant creation). Optional finer-grained special variables MAY refine the partition (`*wire-buffer-pool-bytes*`, `*max-cache-changes*`, `*max-fragment-reassembly-bytes*`, `*sample-info-pool-size*`, …), each defaulting to a documented partition of, or value subordinate to, the master budget. **Rebinding any of these variables after initialization has no effect** until the arena is torn down and reinitialized; this is documented behaviour, not a silent no-op.
**(MUST)** **Any buffer addressed by a raw pointer/SAP MUST be foreign/static, never a plain heap array.** Rationale: SBCL's and AllegroCL's GCs *move* objects, invalidating SAPs across a GC; foreign/static memory is the only representation stable across all three target GCs (Clasp/Boehm is non-moving but conservative — still use foreign memory for uniformity and to keep it out of the conservative scan). Transient pins (`with-pinned-objects` / equivalent) are for **bounded** critical sections only, never for persistent buffers.
**(MUST)** **Static-arena exhaustion is a hard, observable event, never a silent fallback to the GC heap on the hot path.** When provisioned static memory is exhausted at runtime, the stack applies DDS **RESOURCE_LIMITS** semantics — reject (`SAMPLE_REJECTED`) or block per RELIABILITY/HISTORY — and surfaces the condition plus a metric, rather than allocating from the GC heap. Static pool sizes SHOULD be derived from / kept consistent with the relevant **RESOURCE_LIMITS** QoS so the DDS-level limit and the memory-level limit agree. An explicit, **off-by-default** "elastic" mode MAY permit heap fallback for non-real-time users; enabling it forfeits the determinism guarantees and is logged.
**(MUST)** Object pools (for `CacheChange`, `SampleInfo`, fragment/reassembly buffers, submessage scratch, per-endpoint state) are **carved from the static arena at startup**; steady-state acquire/release is pointer/index manipulation with **zero allocation**. **(MUST)** `dynamic-extent` for transient stack data where the impl honors it.
**(SHOULD)** Expose, at init, a **report** of the static arena sizes actually reserved, and at runtime a **high-water-mark** metric per pool, so provisioning can be tuned against real workloads (NFR-OBS).

### 7.5 NFR-CONC — Concurrency
**(MUST)** Lock-free or low-contention queues on the data path (SPSC writer→sender, MPSC receiver→readers). **(MUST)** A portable atomics/threads substrate (e.g., `bordeaux-threads` + a portable `atomics` CAS layer) with **per-impl fast paths** in the PAL (SBCL `sb-concurrency`/`sb-ext` atomics; Allegro native atomics+`mp:`; Clasp `mp:`/C++-`std::atomic` via interop). **(SHOULD)** Thread-affinity / priority controls where the impl/OS expose them. **(MUST)** A documented memory-ordering model; fences inserted explicitly, not assumed.

### 7.6 NFR-OBS — Observability
**(MUST)** Structured, low-overhead logging with compile-time-elidable levels; **zero logging cost** on the hot path when disabled. **(SHOULD)** Counters/metrics (samples in/out, naks, retransmits, drops, queue depths, GC events) exportable. **(SHOULD)** A distributed-logger-equivalent topic. GUIs out of scope.

### 7.7 NFR-TEST — Testability & verification
**(MUST)** Unit tests per module; **property-based + fuzz** tests for the CDR codec and the RTPS submessage parser (parsers facing the network are the attack surface — fuzz them). **(MUST)** A byte-exact **CDR conformance corpus**. **(MUST)** An **interop matrix** (FR-IO-3) and a **`perftest`-equivalent** harness (NFR-PERF). **(MUST)** Per-impl CI on SBCL/Allegro/Clasp. **(SHOULD)** Soak/jitter tests (24h+) reporting latency-distribution drift and GC behavior.

### 7.8 NFR-SEC-POSTURE — Security hygiene (independent of the optional DDS-Security profile)
**(MUST)** All network-facing parsers are bounds-checked **even in `(safety 0)` hot paths** — i.e., validate lengths/offsets against buffer extents before trusting wire data; a malformed RTPS submessage MUST NOT cause out-of-bounds access. This is the single most important safety requirement given `(safety 0)` codegen. **(MUST)** Resource-exhaustion guards (max fragments, max reassembly memory, max instances) to resist amplification/DoS.

### 7.9 NFR-BUILD — Build & packaging
**(MUST)** ASDF systems with conditional compilation (`#+sbcl`/`#+allegro`/`#+clasp`) confined to the PAL. **(MUST)** Reproducible builds; pinned dependency versions. **(SHOULD)** A minimal external-dependency footprint; vendor or pin anything on the hot path.

### 7.10 NFR-IP — Intellectual-property / clean-room discipline
**(MUST)** Implement **clean-room from the OMG specifications**. **(MUST NOT)** copy, decompile, or paste RTI Connext source, headers, or `rtiddsgen` output. **(MAY)** read Apache-2.0 (Fast DDS) / EPL-EDL (Cyclone) / open (OpenDDS) sources *for understanding*, but copying their code imports their license obligations — track provenance. **(MUST)** Review OMG IPR terms: RTPS is published under **RF-Limited** mode — confirm there are no patent encumbrances on the specific mechanisms used, especially Zero-Copy/FlatData-style techniques (RTI holds patents in adjacent areas — **legal review required before shipping a FlatData/Zero-Copy equivalent**). `(C: moderate; this is a genuine legal risk, not boilerplate — get counsel.)`

---

## 8. Constraints & assumptions

- Target OS: Linux first (best `recvmmsg`/SHMEM/affinity story); other POSIX + Windows later via PAL.
- 64-bit only.
- The owner already runs AllegroCL and Connext in production → Allegro is a hard target and Connext is the available gold interop reference.
- Network has multicast on the dev LAN; unicast-only mode required for deployment realism (FR-DISC-4).
- "Subagent-driven" development is assumed (see `IMPLEMENTATION-PLAN.md` §3) — requirements are written to be independently verifiable per work package.

## 9. Acceptance criteria (program-level)

A release is **accepted as "Connext-class (core)"** iff, on **SBCL and AllegroCL**:
1. P0–P5 conformance suites pass (XCDR byte-exact; RTPS reliability correctness; QoS RxO; XTypes assignability; durability/late-joiner).
2. FR-IO-1 (Connext interop) and FR-IO-2 (one open peer) pass across the interop matrix.
3. NFR-PERF-1,4,5,6,7,8 met; NFR-PERF-2 met; NFR-PERF-3 **measured and its gap documented** (not necessarily met); hot-path workloads run to completion **entirely from the static arena** (no GC-heap fallback) at the documented provisioning, with high-water-mark within `*static-arena-bytes*`.
4. NFR-CLOS hot-path-purity gate green; NFR-SEC-POSTURE fuzz suite green.
5. Clasp passes through at least P4 with documented perf/determinism gaps.

## 10. Verification matrix (skeleton — maintained in `/docs/verification.csv`)

| Req | Method (test/inspect/analyze/demo) | Artifact | Gate |
|-----|-----|-----|-----|
| FR-CDR-* | byte-exact vectors + fuzz | `tests/cdr/` | P0 |
| FR-RTPS-* | unit + interop + Wireshark | `tests/rtps/`, tshark CI | P1 |
| FR-QOS-2 | RxO truth-table tests | `tests/qos/` | P2 |
| FR-TYPE-4 | assignability matrix | `tests/xtypes/` | P3 |
| FR-PF-3/4 | perf + interop + alloc counters | `bench/`, `tests/flatdata/` | P4 |
| NFR-PERF-* | perftest-equiv harness | `bench/report/` | per gate |
| NFR-MEM | startup arena report + per-pool high-water-mark + no-heap-fallback assertion | `bench/`, `tests/mem/` | P4+ |
| NFR-CLOS | hot-path static analyzer + per-sample alloc check | CI job `hotpath-purity-gate` | all |
| NFR-SEC-POSTURE | AFL/libfuzzer-style fuzz of parser | `tests/fuzz/` | P1+ |

## 11. Open issues / decisions needed from owner

1. ~~**FR-LANG-4 carve-out:** condition system allowed, or literally zero CLOS?~~ **RESOLVED:** CLOS is permitted and preferred wherever it shows no performance degradation; the hot path stays CLOS-free and per-sample-allocation-free (FR-LANG-0, NFR-CLOS). Remaining sub-decision: confirm the exact set of packages designated "hot path" for the purity gate (current proposal in NFR-CLOS). `(confirm package list)`
2. **Scope of "Professional":** core+differentiators **+ the durability/persistence service + the distributed logging service** — RESOLVED 2026-06-18 (ADR 0021): the durability service is in scope (TRANSIENT/PERSISTENT need it); EXTENDED 2026-07-23 (ADR 0082, §5.14): the distributed logging service is in scope. The remaining Professional services stay out. `(resolved)`
3. **Hard-RT requirement?** If yes, NFR-PERF-3 must be renegotiated or the RT nodes delegated to Connext Micro/Cert. `(decision)`
4. **VendorId** acquisition path with OMG. `(action)`
5. **FlatData/Zero-Copy patent clearance** — legal review owner + deadline. `(action, gating P4 ship)`
6. **IDL vs s-expr DSL priority** for the type compiler (recommend s-expr first for velocity, IDL parser second for interop with existing `.idl`). `(decision)`
7. **Clasp determinism stance:** accept documented gap, or invest in MPS-precise-GC tuning? `(decision)`

---

*End REQUIREMENTS.md*
