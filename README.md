# Common Lisp DDS

A from-scratch, **data-centric publish/subscribe** middleware in Common Lisp implementing
the **OMG DDS 1.4** application model over the **OMG DDSI-RTPS 2.5** wire protocol, with
**OMG XCDR (1 + 2)** as the foundational serialization. The design goal is to **interoperate
on the wire with RTI Connext 7.x** and approach **Connext-class median performance** on the
supported Lisp implementations.

> **Status: pre-release, under active development.** The DCPS application layer (P2) is
> complete; the XTypes layer (P3) is well advanced. See [Status](#status) for the precise,
> honest per-profile picture. This is research/engineering code, not a shipping product.

The two authoritative specs for this repository are [`REQUIREMENTS.md`](REQUIREMENTS.md)
(*what* and *how well*) and [`IMPLEMENTATION-PLAN.md`](IMPLEMENTATION-PLAN.md) (*how* and
*in what order*). They win over this README on any conflict.

---

## What it is

DDS is a peer-to-peer, brokerless pub/sub standard: applications declare **Topics** (a name + a strongly-typed schema) and exchange **samples** through **DataWriters** and **DataReaders** whose **QoS** policies must be compatible for them to match. Underneath, **RTPS** is the interoperable wire protocol (discovery, reliability, fragmentation) and **XCDR** is the binary serialization. **Common Lisp DDS** implements that stack natively:

- **CLOS where it's free, `defstruct` where it counts.** The control plane (entities, QoS,
  listeners, conditions, discovery, the type compiler, tooling) is idiomatic CLOS. The
  **measured hot path** (CDR primitives, generated per-type codecs, buffer/cursor,
  `CacheChange`/`SampleInfo`, the engine's per-sample dispatch) is `defstruct` +
  monomorphized code generation + manual vtables — **no generic-function dispatch and no
  per-sample allocation**. A CI gate enforces the boundary.
- **Static, non-GC'd memory on the hot path.** All hot-path buffers/pools are carved once at
  startup from an off-heap arena sized by `*static-arena-bytes*`; steady state allocates
  **zero** bytes per sample, and arena exhaustion maps to DDS `RESOURCE_LIMITS`, never a
  silent GC-heap fallback.
- **The wire is the oracle.** Correctness is established by **XCDR byte-exactness** against
  reference vectors and by **interop validated with the Wireshark/tshark RTPS dissector** —
  not by "it looks right." Wire constants are pinned from the in-repo OMG specs and verified,
  never hardcoded from memory.
- **A type compiler** (`define-dds-type`, the `rtiddsgen` analogue) turns a type definition
  into a `defstruct` + monomorphic XCDR codecs + key-hash + the XTypes TypeObject + a
  `type-support` registration — the linchpin of the no-CLOS-on-the-hot-path strategy.

**Targets:** SBCL, AllegroCL, Clasp (64-bit, Linux-first). Landed and CI-exercised today:
**SBCL + Clasp** (AllegroCL is a first-class target, not yet wired in — ADR 0004).

---

## Scope

### In scope

Core DDS/DCPS + RTPS + discovery + XTypes/XCDR, plus the high-value performance
differentiators that distinguish Connext *Professional*: batching, asynchronous publication
with flow control, shared-memory transport, Zero-Copy-over-SHMEM, a FlatData-equivalent
binding, serialization-time compression, and durable history. DDS Security is a gated late
profile. Conformance is decomposed into profiles **P0–P7** (see below).

### Explicitly out of scope

The Connext *Professional* **service suite** — Routing Service, Recording/Replay Service,
Persistence Service (as a separate process), Cloud Discovery Service, Admin Console /
Monitor GUIs, and similar. Each is its own program; they are **deferred, not designed out** —
the architecture must not preclude them. See `REQUIREMENTS.md` §13.

---

## Status

Conformance profiles and where they stand (the canonical, per-requirement matrix is
[`docs/verification.csv`](docs/verification.csv)):

| Profile | What | State |
|---|---|---|
| **P0** CDR core | XCDR1 + XCDR2 codec, encapsulation, alignment | **partial** — primitives/strings/sequences/structs + DHEADER/EMHEADER pinned & spec-seed byte-exact; the XCDR2 encapsulation options pad bits are emitted + interpreted per DDS-XTypes 1.3 §7.6.3.1.2; full RTI reference-vector corpus pending |
| **P1** Minimal RTPS | submessages, reliable + best-effort writer/reader, SPDP+SEDP, UDPv4 uni/multicast | **partial** — engine + discovery + data plane run over real UDP, tshark-validated; **bidirectional Connext Shapes interop achieved 2026-06-09** (live RTI Connext 7.3.1, reliable, both directions); **fragmented large-sample interop (DATA_FRAG + HEARTBEAT_FRAG + NACK_FRAG) achieved 2026-06-10** — 8000-octet LargeData byte-exact both ways, incl. forced-fragment-loss recovery where Connext's NACK_FRAG is answered with exactly the missing fragments |
| **P2** DCPS | entities, full QoS + RxO matching, conditions/WaitSets, instances, read/take, content-filtered topics, builtin topics | **complete** (offline conformance) |
| **P3** XTypes | TypeObject/TypeIdentifier, assignability + `TYPE_CONSISTENCY_ENFORCEMENT`, XCDR2 TypeObject serializer + EquivalenceHash, `TypeInformation` over SEDP, inbound Connext `PID_TYPE_OBJECT_LB` reader + advisory type-compat | **in progress** — all of the above landed; the serializer's canonical bytes + EquivalenceHash are **externally confirmed vs live Fast DDS 3.6.1** for the exercised path (FINAL struct + `i32` + unbounded `string8`; its 92-octet SEDP `PID_TYPE_INFORMATION` is locked as a regression vector, test `fastdds-type-information-vector`, and our ShapeType hash + serialized size 87 match byte-for-byte — the parser also now consumes the foreign `LC=5` framing; provisional only for the unexercised serialization-VM edges: unions, MUTABLE structs, `TK_NONE` base, sequence-member TIs, nested-dependency hashes); the inbound `PID_TYPE_OBJECT_LB` path is ZLIB-inflate + a name fingerprint feeding an **advisory** match-time verdict (never a gate — ADR 0009); the built-in TypeLookup service is **complete offline** — the `TypeLookup_Request` and `TypeLookup_Reply` XCDR2 codecs (framing aligned to the Fast DDS `@final` convention: `CDR2_LE` encapsulation, union DHEADERs, `LC=5` mutable members), the MinimalTypeObject deserializer (`parse-minimal-type-object`, the byte-exact inverse of the serializer, so a received TypeObject feeds assignability), the transport-free server core (`find-type-support-by-hash` hash index + `type-lookup-respond`), and the four built-in service endpoints (XTypes 1.3 Table 61) wired into the discovery node — a reliable request reader/reply writer serving the registry plus a `type-lookup-query` getTypes client with timeout sweep and an in-flight cap — are in; **no Connext oracle exists** (RTI doesn't implement the protocol — ADR 0010), so the emitted bytes are frozen as **self-pinned regression vectors** (test `typelookup-vectors`) and independently cross-checked by the tshark RTPS dissector, which decodes both payloads **field-by-field with zero disagreements** (`make wire` gates two TL frames; live Fast DDS frames re-pinned the framing 2026-06-12 — see the CONFIRM-VS-PEER walk below); **FR-TYPE-4 gated matching is wired end-to-end (offline)**: every `DomainParticipant` installs an assignability gate on the engine's SEDP `type-gate` hook — equal EquivalenceHashes match with zero wire traffic; differing hashes fetch the remote Minimal TypeObject via TypeLookup (nested member hashes resolved with bounded follow-up queries) and decide via is-assignable-from under the **reader's** `TYPE_CONSISTENCY_ENFORCEMENT`, an `:incompatible` verdict raising INCONSISTENT_TOPIC; every unassessable case (no/malformed TypeInformation, unknown hash, timeout, depth bound) falls back to name-based matching, never a rejection; **legacy-TypeObject degrading tier complete (2026-06-11)**: `parse-legacy-type-object` recognizes union (member-kind `0x15`) and array (member-kind `0x11`) members, both then confirmed to degrade the whole parse to `:unsupported` (fail-open) via live Connext 7.3.1 captures (`C_Union`, `C_Array`); bitmask not capturable (`rtiddsgen 4.3.1` rejects the keyword — documented gap); **90 tests green SBCL**; **legacy enum members now gate STRUCTURALLY (2026-06-12, Task S0.3)**: enum (member-kind `0x0E`) is flipped OUT of the degrade tier — the enum-definition node (CODE 5) is resolved by the shared 8-octet type-hash mechanism, its bit-bound + literals (each carrying a literal name, so NameHashes match a local model) folded into an `EK_MINIMAL` enumerated `type-identifier`; the live `C_Enum` (`@key long id; SomeEnum{RED=0,GREEN=1,BLUE=2} e`) parses to a `minimal-struct-type` whose `e` member drives `struct-assignable-from` through `enum-assignable-from` (XTypes Table 18) — a matching local is assignable both ways, a BLUE-value-changed local is rejected, no false-reject on re-run (**96 tests green SBCL**); **legacy single-dimension array members now gate STRUCTURALLY (2026-06-12, Task 1.3)**: array (member-kind `0x11`) is flipped OUT of the degrade tier — the array-definition node (CODE 3) is resolved by the shared 8-octet type-hash mechanism, its element type-kind (CODE 100 child, long 5→`i32`) and single fixed dimension (CODE 200 child: `count:u32`=1 then the bound `4`) folded into a plain-array `type-identifier`; the live `C_Array` (`@key long id; long arr[4]`) parses to a `minimal-struct-type` whose `arr` member drives `struct-assignable-from` (XTypes Table 17, arrays not resizable → identical dimensions) — a matching local (`i32`×4) is assignable both ways, an `arr[5]` (size) or short `arr[4]` (element-kind) local is rejected, no false-reject on re-run; multi-dimensional arrays (`count≠1`) and non-primitive elements remain a documented fail-open gap (**99 tests green SBCL + Clasp**); **legacy union members now gate STRUCTURALLY (2026-06-12, Task 2.3)**: union (member-kind `0x15`) is flipped OUT of the degrade tier — the union-definition node (CODE 10) is resolved by the shared 8-octet type-hash mechanism, its cases container (CODE 100: `count:u32` then per entry a named CODE-0 node + a CODE-100 label-list child) folded into an `EK_MINIMAL` union `type-identifier` (the first entry the discriminator, each later entry a member with its case label + member name, so NameHashes match a local model); the live `C_Union` (`@key long id; SomeUnion switch(long){case 0: long a; case 1: double b} u`) parses to a `minimal-struct-type` whose `u` member (disc `i32`; `{0}`→`a` `i32`; `{1}`→`b` `f64`) drives `struct-assignable-from` through `union-assignable-from` (XTypes Table 19 UNION_TYPE row, by shared case label) — a matching local is assignable both ways, a local where case 0's member type changes `long`→`double` is rejected, no false-reject on re-run; a default member, a non-primitive discriminator/member, or a multi-label case remains a documented fail-open gap (`ti-delimited-p` was extended so a union of delimited members self-delimits, removing a false-reject for a FINAL-struct union member) (**102 tests green SBCL + Clasp**); **LIVE Connext legacy-TypeObject type-gating ACHIEVED 2026-06-11 (ADR 0011, completes ADR 0010)** — wired into the DCPS gate, `parse-legacy-type-object` now decides matching against a **live RTI Connext 7.3.1** writer: a DCPS-level gated subscriber (`dds.shapes:run-gated-subscriber` / `make gated-sub`) faces Connext's real `PID_TYPE_OBJECT_LB`, gating a structurally-compatible local `C_Shape` `:compatible` (matched, 25 samples delivered) and a structurally-incompatible local (`shapesize` long→`i64`) `:incompatible` (INCONSISTENT_TOPIC, 0 samples), and never false-rejecting the compatible peer on a re-run (**91 tests green SBCL**); **EquivalenceHash externally confirmed 2026-06-12 (FR-IO-2 S3)** — the live Fast DDS 3.6.1 `PID_TYPE_INFORMATION` locked as a vector closes the ADR 0009 unconfirmed thread for the exercised path (**92 tests green SBCL + Clasp**, the latter after root-causing a Clasp unmanaged-free heap corruption to the runtime, not the test — NFR-PORT row in `docs/verification.csv`); **TypeLookup getTypes client live vs Fast DDS 3.6.1 (FR-IO-2 S4 leg A, 2026-06-12)** — `dds.shapes:run-typelookup-probe` (`make fastdds-tl-probe`) queried their TypeLookup server for the SEDP-announced EK_MINIMAL hash and consumed the reply live (request/reply frames 85/86-87 in `interop/fastdds/captures/s4-ourclient-lo0.pcap`), surfacing + fixing failing-locked-vector-test-first the conformant answer shape our client lacked: a MINIMAL query may be answered with the COMPLETE TypeObject plus the `complete_to_minimal` mapping (XTypes 1.3 §7.6.3.3.4.2), now reconstructed to MINIMAL via the new `dds.types:complete-to-minimal-type-object` (the locked Fast DDS reply reconstructs **byte-identical** to our own ShapeType MinimalTypeObject, test `fastdds-typelookup-reply-vector`; **93 tests green SBCL**); **TypeLookup CONFIRM-VS-PEER walk closed (FR-IO-2 S4 leg B-patched, 2026-06-12)** — under a controller-approved NON-STOCK diagnostic (Fast DDS's SEDP vendor gate neutralized locally, then restored + re-proven stock) their stock TypeLookup client queried our server and **built its DynamicType from our reply** (600/600 RELIABLE samples; their JSON-dump failures root-caused to a Fast DDS defect — raw MINIMAL `NameHash` bytes as member names — not our framing), peer-confirming the codec framing in both directions: instanceName forms, ReplyHeader remoteEx placement, EMHEADER1 LC=5 rule-22 reuse, top-level `@final`/`CDR2_LE`, and the Call/Return/Result union DHEADERs; still self-pinned: the non-OK Return-arm omission + non-CDR2_LE encapsulations (walk table in `interop/fastdds/README.md`); DynamicData deferred |
| **P4** Performance differentiators | batching, async/flow-control, SHMEM, Zero-Copy, FlatData, LZ4 | **not started** — except large-sample fragmentation (DATA_FRAG), pulled forward and Connext-validated under P1 |
| **P5** Durability/late-joiner | TRANSIENT_LOCAL, durable writer history, large-data | **not started** |
| **P6** Security (gated) | the five DDS-Security plugins | **not started** |
| **P7** Tooling/services (gated) | spy, IDL parser, monitoring | partial (a Shapes harness + tshark wire gate exist) |

**Verification right now:** unit/integration suite **green on SBCL and Clasp** (latest run:
all tests passing); quality gates green — `gate-types` (every function is `ftype`-declared),
`gate-hotpath` (no CLOS/alloc in hot-path packages), `mem` (0 bytes/sample), `wire` (tshark
RTPS dissector). **Live Connext interop has run** against RTI Connext 7.3.1 (the harness +
oracle apps are in [`interop/connext/`](interop/connext/)): bidirectional reliable ShapeType
exchange and bidirectional fragmented LargeData exchange (`make large-pub` / `make large-sub`;
`DROP=3` injects fragment loss to exercise NACK_FRAG recovery), tshark-validated on `lo0`
captures. **Live Fast DDS interop has run** against eProsima Fast DDS 3.6.1 (the peer harness
is in [`interop/fastdds/`](interop/fastdds/); `make fastdds-pub` / `make fastdds-sub`):
mutual SPDP/SEDP discovery plus bidirectional **reliable** ShapeType exchange (forward 95/100
with head-of-stream sns 1-5 declared unavailable pre-match (HB first=5 + GAP of sn 5); reverse 250/250 with full pre-match
recovery), HEARTBEAT/ACKNACK verified on the user endpoints both directions and the payloads
tshark-validated — the FR-IO-2 data-plane DoD; the **EquivalenceHash byte-level lock landed**
(S3: Fast DDS's `PID_TYPE_INFORMATION` locked as a regression vector, test
`fastdds-type-information-vector`, matching our hash + serialized size byte-for-byte); and the
**TypeLookup getTypes client leg ran live** (S4 leg A: `make fastdds-tl-probe` queries their
TypeLookup server and consumes the reply — see the P3 row above); S4 leg B (their client
against our TypeLookup server) closed with a documented **finding**: Fast DDS 3.6.1 discards
`PID_TYPE_INFORMATION` from non-eProsima vendors, so no foreign announcement can trigger its
TypeLookup client — the type-blind leg-B harness (`make fastdds-type-probe`) is proven
end-to-end against an eProsima peer and ready unchanged for any peer without that gate (see
the S4 leg B section of [`interop/fastdds/README.md`](interop/fastdds/README.md)). The one
direction that gate blocks — **our `TypeLookup_Reply` consumed by their client** — was then
verified under a controller-approved **NON-STOCK diagnostic** (the vendor gate neutralized in
a local Fast DDS build, afterwards restored and re-proven stock): their stock TypeLookup
engine queried our server (getTypeDependencies + getTypes), **built its DynamicType from our
MINIMAL TypeObject**, and took **600/600** RELIABLE samples — closing the TypeLookup
**CONFIRM-VS-PEER walk** in both directions (the walk table, the exact patch, and the
explicitly-not-stock caveat live in
[`interop/fastdds/README.md`](interop/fastdds/README.md)). With that,
**FR-IO-2 is met and closed** ([ADR 0012](docs/adr/0012-fastdds-peer-fr-io-2.md),
2026-06-12): every stock-citable element — discovery, the bidirectional reliable data
plane, the type-identity oracle, and the TypeLookup client leg — ran against an
**unmodified** Fast DDS 3.6.1 peer; only the leg-B reply direction carries the non-stock
label, and it travels with that result wherever it is cited.

---

## Architecture

Strict bottom-up layering; each layer depends only on the contract of the one below, and
nothing above L0 contains implementation-conditional code.

```
L9  API & tooling     Lisp API, Request/Reply (planned), gen, spy, Shapes harness
L8  Advanced features  batching, async+flow, Zero-Copy/SHMEM, FlatData, compression, durability, security   (P4+)
L7  Transports         UDPv4 (+ SHMEM/TCP planned) behind a pluggable transport record
L6  DCPS               entities, QoS+RxO, conditions/WaitSets, instances, read/take, content filters
L5  Discovery          SPDP, SEDP, builtin endpoints, PID_TYPE_INFORMATION
L4  RTPS engine        submessage codec, reliable/best-effort writer+reader, HistoryCache, HEARTBEAT/ACKNACK/GAP
L3  Type system + gen  XTypes model, TypeObject/TypeIdentifier + EquivalenceHash, the type compiler
L2  CDR codec          XCDR1 + XCDR2 (PLAIN/DELIMITED/MUTABLE), encapsulation, alignment, endianness
L1  Core runtime       static arena, off-heap octet buffers + cursors, pools, MD5, byte-order ops
L0  PAL (per-impl)     raw memory/SAP, threads, sockets, GC control — the ONLY place with #+sbcl/#+clasp
```

### ASDF systems

| System | Layer | Package | Responsibility |
|---|---|---|---|
| `dds-pal`   | L0 | `dds.pal` | platform abstraction (memory, threads, sockets, clock) |
| `dds-core`  | L1 | `dds.core.arena`, `dds.core.buffer`, `dds.core.md5` | arena, buffers/cursors, vendored MD5 |
| `dds-cdr`   | L2 | `dds.cdr` | XCDR1/2 primitive + composite codec, encapsulation |
| `dds-types` | L3 | `dds.types` | `type-support` vtable + registry, XTypes model, assignability, TypeObject serializer |
| `dds-gen`   | L3 | `dds.gen` | `define-dds-type` — the type/IDL compiler |
| `dds-qos`   | L3 | `dds.qos` | DDS 1.4 QoS policies + Requested/Offered matching |
| `dds-rtps`  | L4 | `dds.rtps.*` | submessage codec, reliable engine, HistoryCache, discovery wire |
| `dds-disc`  | L5 | `dds.disc` | SPDP/SEDP discovery + reliable data plane over UDP |
| `dds-dcps`  | L6 | `dds.dcps` | the DDS entity model, conditions, statuses, content filters, builtin topics |
| `dds-xport` | L7 | `dds.xport`, `dds.xport.udp` | the transport record + UDPv4 |
| `dds-shapes`| L9 | `dds.shapes` | standalone Square/ShapeType interop harness |
| `dds-tests` | —  | `dds.tests` | the cross-cutting unit/integration suite |
| `dds`       | —  | umbrella | loads the landed stack |

---

## Build & test

Requires a Lisp (SBCL and/or Clasp) with Quicklisp. The `Makefile` wraps per-implementation
invocation (`scripts/with-sbcl.sh`, `scripts/with-clasp.sh`).

```sh
make build         # load all systems (LISP=./scripts/with-clasp.sh by default; or with-sbcl.sh)
make test          # run the unit/integration suite
make build-all     # build on both landed impls (Clasp + SBCL)
make test-all      # test on both
make gate-types    # every defun has a single-line ftype declaim (FR-LANG-8)
make gate-hotpath  # no CLOS dispatch / per-sample alloc in hot-path files (NFR-CLOS)
make mem           # measured 0 bytes/sample serialize/deserialize (NFR-PERF-8)
make wire          # validate emitted RTPS against the tshark RTPS dissector (FR-TOOL-3)
make all           # build-all + test-all + gates + mem
```

Standalone Shapes interop participants (multicast discovery on domain `DOMAIN`):

```sh
make square-pub COLOR=BLUE       # publish an animated Square (ShapeType)
make square-sub                  # subscribe and print received shapes
make square-spy                  # discovery diagnostic: print discovered participants/locators
```

---

## Quickstart

```lisp
(ql:quickload :dds)

;; 1. Define a topic type. The compiler emits a defstruct + monomorphic XCDR codecs +
;;    key-hash + XTypes TypeObject + a registered type-support.
(dds.gen:define-dds-type sensor (:extensibility :final)
  (id    :i32 :key t)        ; @key -> drives the instance key-hash
  (temp  :i32)
  (label :string))

;; 2. Two participants, a writer, and a reader on the same Topic/type.
(let* ((ts  (dds.types:find-type-support "sensor"))
       (p1  (dds.dcps:create-participant :domain 0))
       (p2  (dds.dcps:create-participant :domain 0))
       (tw  (dds.dcps:create-topic p1 "Sensors" "sensor" ts))
       (tr  (dds.dcps:create-topic p2 "Sensors" "sensor" ts))
       (dw  (dds.dcps:create-datawriter (dds.dcps:create-publisher  p1) tw))
       (dr  (dds.dcps:create-datareader (dds.dcps:create-subscriber p2) tr)))
  ;; 3. Let discovery match the endpoints (caller-driven spin in v1).
  (loop repeat 100 until (plusp (dds.dcps:matched-count p1))
        do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
  ;; 4. Write a sample; take it on the reader.
  (dds.dcps:write-sample dw (make-sensor :id 1 :temp 21 :label "rack-A"))
  (loop repeat 100 for s = (dds.dcps:take-samples dr) until s
        do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02)
        finally (format t "~&got ~s~%"
                        (and s (dds.dcps:cached-sample-data (first s)))))
  (dds.dcps:delete-participant p1)
  (dds.dcps:delete-participant p2))
```

More worked examples — per feature, with API references — are in the
**[wiki](docs/wiki/README.md)**.

---

## Interop with RTI Connext

[`interop/connext/`](interop/connext/) is a Connext-side test harness (built against the
Connext **public API** + your own IDL — clean-room; no Connext source is copied) that serves
as the gold interop/oracle reference: a TypeObject/EquivalenceHash probe, bidirectional
Shapes pub/sub, and a byte-exact XCDR payload capture. It requires a Connext install and is
**not** part of this repo's CI. See [`interop/connext/README.md`](interop/connext/README.md).

[`interop/fastdds/`](interop/fastdds/) is the equivalent **eProsima Fast DDS 3.6.1** peer
harness (FR-IO-2): a standards-conformant peer that — unlike Connext (ADR 0010) — speaks the
builtin TypeLookup service, making it the oracle for our TypeLookup CONFIRM-VS-PEER path. It
runs through the pinned toolchain in `scripts/with-fastdds.sh` and is **not** part of CI.
See [`interop/fastdds/README.md`](interop/fastdds/README.md).

---

## Repository layout

```
src/            the Lisp stack (one directory per ASDF system; see the table above)
docs/
  wiki/         per-system/feature API + use-case guide (start at docs/wiki/README.md)
  specs/        the in-repo OMG specs (DDS 1.4, RTPS 2.5, XTypes 1.3, IDL) — the clean-room source
  adr/          architecture decision records
  verification.csv   the requirement -> evidence -> gate matrix
  provenance.md      clean-room provenance log (NFR-IP)
interop/connext/  the RTI Connext live-test / oracle harness (C++; needs Connext)
interop/fastdds/  the Fast DDS peer harness (C++; pinned toolchain via scripts/with-fastdds.sh)
scripts/        per-impl launchers + the quality-gate scripts
tools/          rtps-pcap (wire-conformance pcap builder)
bench/          performance reports (P4)
REQUIREMENTS.md, IMPLEMENTATION-PLAN.md   the operating contract
sbom.spdx.json    SPDX 3.0.1 JSON-LD SBOM (EU CRA / BSI TR-03183-2; auto-generated)
```

---

## Software Bill of Materials (SBOM)

[`sbom.spdx.json`](sbom.spdx.json) is an **SPDX 3.0.1 JSON-LD** Software Bill of Materials,
structured to the EU **Cyber Resilience Act** (Reg. (EU) 2024/2847, Annex I) and **BSI
TR-03183-2** data-field requirements (SBOM author + timestamp; per component: supplier, name,
version, dependency relationships, licence where determinable, a unique identifier). It covers
the top-level dependencies (`static-vectors`, `cffi`, `bordeaux-threads`) and the Common Lisp
runtime. It is produced by `scripts/generate-sbom.py` from the live `*.asd` top-level
`:depends-on` set, and **kept current automatically**: the `scripts/git-hooks/pre-commit` hook
regenerates + stages it before every commit (activate once per clone with `make hooks`).
Regenerate manually with `make sbom`. Do not hand-edit it.

---

## License

The Common Lisp DDS code and documentation are © 2026 **Gönninger B&T GmbH, Deutschland**
(author: Frank Gönninger), licensed under **Creative Commons Attribution-NoDerivatives 4.0
International (CC BY-ND 4.0)** — share verbatim with attribution; no derivatives. See
[`LICENSE.md`](LICENSE.md) and [`COPYRIGHT.md`](COPYRIGHT.md). Third-party dependencies keep
their own licenses (enumerated in [`sbom.spdx.json`](sbom.spdx.json)).

---

## Intellectual-property posture (clean-room)

Implemented **clean-room from the OMG specifications** (in `docs/specs/`). RTI Connext is a
**behavioral reference via interop only** — its source, headers, and `rtiddsgen` output are
never copied.

---

## Contributing / working in this repo

Read `REQUIREMENTS.md` and `IMPLEMENTATION-PLAN.md`. Non-negotiables: hot-path purity (CLOS-free + zero per-sample
alloc), static-arena memory, no hardcoded wire constants, bounds-checked network parsers,
and **every API symbol carries a docstring and the `docs/wiki/` +
this README are kept in lockstep with the source on every change.**
