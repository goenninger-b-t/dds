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
| **P0** CDR core | XCDR1 + XCDR2 codec, encapsulation, alignment | **partial** — primitives/strings/sequences/structs + DHEADER/EMHEADER pinned & spec-seed byte-exact; full RTI reference-vector corpus pending |
| **P1** Minimal RTPS | submessages, reliable + best-effort writer/reader, SPDP+SEDP, UDPv4 uni/multicast | **partial** — engine + discovery + data plane run over real UDP, tshark-validated; **bidirectional Connext Shapes interop achieved 2026-06-09** (live RTI Connext 7.3.1, reliable, both directions); **fragmented large-sample interop (DATA_FRAG + HEARTBEAT_FRAG + NACK_FRAG) achieved 2026-06-10** — 8000-octet LargeData byte-exact both ways, incl. forced-fragment-loss recovery where Connext's NACK_FRAG is answered with exactly the missing fragments |
| **P2** DCPS | entities, full QoS + RxO matching, conditions/WaitSets, instances, read/take, content-filtered topics, builtin topics | **complete** (offline conformance) |
| **P3** XTypes | TypeObject/TypeIdentifier, assignability + `TYPE_CONSISTENCY_ENFORCEMENT`, XCDR2 TypeObject serializer + EquivalenceHash, `TypeInformation` over SEDP, inbound Connext `PID_TYPE_OBJECT_LB` reader + advisory type-compat | **in progress** — all of the above landed; the serializer's canonical bytes are **provisional pending Connext confirmation**; the inbound `PID_TYPE_OBJECT_LB` path is ZLIB-inflate + a name fingerprint feeding an **advisory** match-time verdict (never a gate — ADR 0009); the built-in TypeLookup service is **complete offline** — the `TypeLookup_Request` and `TypeLookup_Reply` XCDR2 codecs (framing aligned to the Fast DDS `@final` convention: `CDR2_LE` encapsulation, union DHEADERs, `LC=5` mutable members), the MinimalTypeObject deserializer (`parse-minimal-type-object`, the byte-exact inverse of the serializer, so a received TypeObject feeds assignability), the transport-free server core (`find-type-support-by-hash` hash index + `type-lookup-respond`), and the four built-in service endpoints (XTypes 1.3 Table 61) wired into the discovery node — a reliable request reader/reply writer serving the registry plus a `type-lookup-query` getTypes client with timeout sweep and an in-flight cap — are in; **no Connext oracle exists** (RTI doesn't implement the protocol — ADR 0010), so the emitted bytes are frozen as **self-pinned regression vectors** (test `typelookup-vectors`) and independently cross-checked by the tshark RTPS dissector, which decodes both payloads **field-by-field with zero disagreements** (`make wire` gates two TL frames; a live Fast DDS capture re-pins later); **FR-TYPE-4 gated matching is wired end-to-end (offline)**: every `DomainParticipant` installs an assignability gate on the engine's SEDP `type-gate` hook — equal EquivalenceHashes match with zero wire traffic; differing hashes fetch the remote Minimal TypeObject via TypeLookup (nested member hashes resolved with bounded follow-up queries) and decide via is-assignable-from under the **reader's** `TYPE_CONSISTENCY_ENFORCEMENT`, an `:incompatible` verdict raising INCONSISTENT_TOPIC; every unassessable case (no/malformed TypeInformation, unknown hash, timeout, depth bound) falls back to name-based matching, never a rejection; the full RTI-legacy structural parse + DynamicData deferred |
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
captures.

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
