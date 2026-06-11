# Provenance log (clean-room discipline — REQUIREMENTS NFR-IP)

Every external source consulted and its influence is recorded here. RTI Connext
artifacts are **behavioural references via interop only** — never source,
headers, or `rtiddsgen` output.

## M0 (2026-06-04)

- **OMG specifications** (DDS 1.4, DDSI-RTPS 2.5, XTypes 1.3, CDR) — the sole
  design source. No clause values memorized into code: CDR representation IDs,
  PIDs, EntityIds, and the keyhash rule are left TBD until pinned by byte-exact
  vectors / live captures (FR-CDR-3, FR-RTPS-9).
- **No RTI Connext source/headers/generated code consulted or copied.**
- **No Fast DDS / Cyclone / OpenDDS source read** during M0.

## M1 (2026-06-04)

Normative OMG specs added to `docs/specs/` (PDF + machine-readable) and read
directly to pin wire constants — the required clean-room source (the operating contract §4):

- **XTypes 1.3 §7.4.3.4 (ENC_HEADER illustration)** — the encapsulation
  representation identifiers. **⚠ SUPERSEDED in M2 — the XCDR2 values pinned here
  were WRONG.** The §7.4 ENC_HEADER prose lists PLAIN_CDR2=0x0010/11,
  PL_CDR2=0x0012/13, DELIMITED_CDR=0x0014/15, XML=0x0100. Those are a non-normative
  inconsistency; the normative on-the-wire table is §7.6 Table 60 (see M2). The
  XCDR1 values pinned here (PLAIN_CDR 0x00/01, PL_CDR 0x02/03) are correct.
- **XTypes 1.3 §7.4.3.4.1 (DHEADER)** and **§7.4.3.4.2 (EMHEADER1/LC/NEXTINT)** —
  `EMHEADER1=(M_FLAG<<31)+(LC<<28)+(MemberId&0x0fffffff)`, LC 0–7 semantics.
  → `src/dds-cdr/primitives.lisp`.
- **RTPS 2.5 §10.2** — `SerializedPayloadHeader` = 2-octet representation_identifier
  + 2-octet representation_options (sender 0); CDR alignment origin resets after
  the header. Cross-checked §10.3 Table 10.1. → cdr.lisp + cursor origin.
- Text extracted locally with `pdftotext` (poppler); no external service used.
- Still **no RTI/Fast DDS/Cyclone/OpenDDS source** consulted.

## M2 (2026-06-04) — wire validation against the tshark RTPS dissector

The discovery + reliable data plane now run over real UDP. To validate the wire
format short of a live Connext peer, representative messages built by the project
codecs (SPDP DATA, SEDP DATA, user DATA+HEARTBEAT, ACKNACK) are framed into a
DLT_RAW pcap (`tools/rtps-pcap.lisp`) and dissected with **Wireshark/tshark 4.6.6
RTPS dissector** — the same reference dissector used to validate Connext interop.
No RTI artifacts involved; the dissector is the OMG-spec-derived oracle.

- **Encapsulation identifier correction (the wire is the oracle).** The dissector
  flagged our PLAIN_CDR2_LE = `0x0011` as **Unknown**. Investigation found the
  DDS-XTypes 1.3 spec contradicts itself: the **§7.4 ENC_HEADER illustration**
  lists the XCDR2 kinds as 0x10–0x15, but the **normative §7.6 Table 60 "RTPS
  encapsulation identifier"** lists CDR2 = `0x06/0x07`, D_CDR2 = `0x08/0x09`,
  PL_CDR2 = `0x0a/0x0b`, XML = `0x04`. Table 60 is the on-the-wire table and
  matches the dissector (and Connext / Fast DDS / Cyclone) exactly. The M1 pinning
  trusted the wrong (§7.4) table; **corrected to Table 60 values** in
  `src/dds-cdr/cdr.lisp`, re-confirmed: tshark now reads our payload as
  `CDR2_LE (0x0007)`. Lesson: a spec can be internally inconsistent — the wire
  (dissector / interop) is the final arbiter (the operating contract §4).
- All four submessage shapes dissect cleanly: `DATA(p)` (SPDP participant data),
  `DATA(w) -> Square` (SEDP — the dissector extracted our PID_TOPIC_NAME),
  `DATA, HEARTBEAT`, and `ACKNACK` (SequenceNumberSet). Our SPDP writer EntityId is
  recognized as `ENTITYID_BUILTIN_PARTICIPANT_WRITER (0x000100c2)`, guidPrefix,
  flags, and sequence numbers all parse correctly. Repeatable via `make wire`.

## M3 (2026-06-05) — DCPS (P2)

DDS 1.4 DCPS spec added to `docs/specs/` by the owner (`dds-1_4-dcps.pdf`,
`dds_rtf2_dcps.idl`, `dds_rtf2_dlrl.idl`) — the required clean-room source for P2.

- **QoS RxO** pinned from **DDS 1.4 §2.2.3** (the RxO compatibility table) →
  `src/dds-dcps/qos.lisp`. (Implemented before the spec PDF was in-repo; the table is
  standard and was cited inline — now backed by the in-repo spec.)
- **SampleInfo + state kinds** pinned from the machine-readable **`dds_rtf2_dcps.idl
  §SampleInfo`** (the 12 fields) and the SampleState/ViewState/InstanceState kind
  constants (READ/NOT_READ, NEW/NOT_NEW, ALIVE/NOT_ALIVE_DISPOSED/_NO_WRITERS) →
  `src/dds-dcps/entities.lisp`. State kinds kept as keywords in-Lisp; `sequence-number`
  is a documented vendor extension.
- **Instance keyhash** (the 16-octet instance handle) from **RTPS 2.5 §9.6.3.3 /
  XTypes FR-TYPE-5**: @key members serialized big-endian, ≤16 bytes used directly
  (the >16 → MD5 path is a later increment, needs ironclad) → emitted by
  `define-dds-type` into the type-support `key-hash` slot (`src/dds-gen/dsl.lisp`).
- **SEDP QoS PIDs** pinned from **RTPS 2.5 §9.6.3.2** (the PID table): PID_RELIABILITY
  0x001a, PID_DURABILITY 0x001d (DEADLINE 0x0023, LATENCY_BUDGET 0x0027, LIVELINESS
  0x001b, DESTINATION_ORDER 0x0025, OWNERSHIP 0x001f, PRESENTATION 0x0021, PARTITION
  0x0029 are recorded for the follow-up). QoS-policy enum kind values from the
  **DDS-XTypes 1.3 discovery builtin-topic IDL** (durability VOLATILE..PERSISTENT
  0–3, etc.). DiscoveredWriter/ReaderData now carry reliability + durability; matching
  uses dds.qos:qos-rxo-compatible. Confirmed against the tshark RTPS dissector
  (PID_DURABILITY: TRANSIENT_LOCAL). → `src/dds-rtps/discovery.lisp`.
- Still **no RTI/Fast DDS/Cyclone/OpenDDS source** consulted.

## M4 (2026-06-06) — XTypes (P3), start

- **MD5 (RFC 1321)** implemented **clean-room from the algorithm description in RFC
  1321** (the public byte/round/constant definition: the K[i]=floor(2^32·|sin(i+1)|)
  table, the per-round shifts, the F/G/H/I round functions, little-endian length
  padding). No third-party MD5 source (ironclad/openssl/etc.) was read or copied —
  owner chose to vendor rather than add a dependency. Used as a **content/identity
  hash only** (XTypes EquivalenceHash/NameHash FR-TYPE-2, the >16-byte keyhash
  FR-TYPE-5); it is explicitly **NOT** a DDS-Security primitive (FR-SEC-2 still
  mandates vetted native crypto for the security profile). → `src/dds-core/md5.lisp`.
  Verified byte-exact against the **RFC 1321 §A.5 test suite** and the **XTypes 1.3
  TypeObject NameHash example** (MD5("color")[0:4] = {0x70,0xDD,0xA5,0xDF}).
- **XTypes 1.3 TypeObject IDL** (`docs/specs/xtypes-1_3_typeobject.idl`) read to pin
  the TypeIdentifier/TypeObject data model, the EquivalenceKind/TypeKind octets, and
  the EquivalenceHash rule (first 14 octets of MD5 of the XCDR2-LE MinimalTypeObject).
- Still **no RTI/Fast DDS/Cyclone/OpenDDS source** consulted.

## M4 (2026-06-06) — Connext interop/oracle harness (`interop/connext/`)

Connext-side test apps (`typeobject-probe`, `shapes-pub`, `shapes-sub`, `cdr-capture`)
built **against the RTI Connext public API + our own `ShapeType.idl`** to use Connext as
the gold interop/oracle reference (REQUIREMENTS §8, FR-IO-1). This is the allowed
behavioural-reference-via-interop use, not a clean-room breach:

- **No Connext source, headers, or `rtiddsgen` output is copied into this repo.** The
  committed files are clean-room (our `.cxx` + `ShapeType.idl` + Makefiles only). The
  `rtiddsgen`-generated type support is produced at build time on the machine where Connext
  is installed and is **git-ignored** (`interop/connext/.gitignore`) — never committed.
- Purpose: produce reference bytes to **confirm or correct** the PROVISIONAL XTypes
  serializers (TypeObject/EquivalenceHash FR-TYPE-2, TypeInformation FR-TYPE-3) and the XCDR
  payload (FR-CDR-8), and to validate bidirectional Shapes interop. The authoritative byte
  read uses the **same Wireshark/tshark RTPS dissector** already used by `make wire`.
- Built and run only where Connext lives (the owner's environment); **not** part of this
  repo's CI. `ShapeType.idl` is defined to match this stack's `shape-type` exactly so the
  EquivalenceHash is an apples-to-apples comparison.
- Still **no RTI/Fast DDS/Cyclone/OpenDDS source** read or copied.

## M4 — Connext 7.3.1 wire capture (2026-06-08)

- `interop/connext/typeobject-probe` was **built and run against live RTI Connext 7.3.1**
  (arm64 macOS) and its SEDP read with the Wireshark/tshark RTPS dissector. This is a
  **behavioural reference via the wire only** (NFR-IP) — the influence is recorded in
  **ADR 0009**. **No Connext source, headers, or `rtiddsgen` output was copied**; the
  generated type support stays git-ignored. The decompressed `PID_TYPE_OBJECT_LB` complete
  TypeObject and the absence of `PID_TYPE_INFORMATION` are facts read off the wire, not from
  any RTI artifact.
- The only design input taken: Connext advertises small types via the vendor
  `PID_TYPE_OBJECT_LB` (ZLIB complete TypeObject) and not the minimal hash → our
  type-matching must be name + structural, not a minimal-hash gate (ADR 0009).

## M4 — VendorId selection + live discovery finding (2026-06-09)

- **OMG DDS-RTPS vendor-id registry** read from the **DDS Foundation** page
  (`dds-foundation.org/dds-rtps-vendor-and-product-ids`) and cross-checked against the
  **Wireshark `packet-rtps.c` vendor table** — public registries, not vendor source. Used
  only to choose a **non-conflicting** provisional development VendorId (`0x01FF`) per
  FR-RTPS-2; the registry's sequential assignments reach `0x0119`. No code copied.
- **Live Connext 7.3.1 behavioural observation** (interop, NFR-IP): a participant
  advertising `VENDORID_UNKNOWN` (`0x0000`) is ignored by Connext (no unicast discovery);
  with a non-zero id (`0x01FF`) Connext accepts it and runs the reliable discovery channel.
  Read off the wire via tshark; no RTI artifact consulted.

## Third-party runtime dependencies (licenses apply; not vendored yet)

| Dependency | Use | License |
|---|---|---|
| `static-vectors` | off-heap octet buffers (NFR-MEM) | MIT |
| `cffi` | FFI (sockets/SHMEM/crypto later) | MIT |
| `bordeaux-threads` | portable threads/locks | MIT |
| `chipz` | pure-Lisp ZLIB inflate of inbound RTI `PID_TYPE_OBJECT_LB` (ADR 0009; control plane, off the hot path) | BSD-3-Clause |
| Quicklisp | dependency loading (dev) | — |
| Clasp `boehmprecise` | the M0 target implementation | LGPL-2.1 (runtime) |

Pinning/vendoring of hot-path dependencies (NFR-BUILD) is a tracked M1 follow-up.

## M4 (2026-06-09) — inbound RTI PID_TYPE_OBJECT_LB (ADR 0009)

- **`chipz` 0.8 (BSD-3-Clause, Nathan Froyd)** added as a runtime dependency for ZLIB
  inflate of Connext's vendor `PID_TYPE_OBJECT_LB` (the compressed COMPLETE TypeObject).
  Pure-Lisp (no native libz), control plane only — justified per the operating contract §9.
- **RTI `PID_TYPE_OBJECT_LB` (0x8021) wire layout is reverse-engineered from the live
  Connext 7.3.1 wire** (clean-room — observed bytes via tshark, no RTI source/headers): a
  little-endian header `compression_class_id u32 (1=ZLIB) + uncompressed_length u32 +
  compressed_length u32` followed by the zlib stream. This is an RTI-vendor parameter, NOT
  an OMG-spec construct; treated as a behavioural interop reference (NFR-IP). →
  `src/dds-types/type-object-lb.lisp` (`inflate-type-object-lb`).

## M4 (2026-06-10) — TypeLookup wire framing convention (ADR 0010, FR-TYPE-3)

- **Fast DDS (Apache-2.0, eProsima) read for understanding only — no code copied**:
  `src/cpp/fastdds/builtin/type_lookup_service/detail/{TypeLookupTypes.idl,rpc_types.idl}`
  and `TypeLookupManager.cpp` (GitHub master, 2026-06-10) consulted to determine the
  de-facto wire convention for the XTypes 1.3 §7.6.3.3 service, whose top-level types the
  spec IDL leaves unannotated: Fast DDS pins `TypeLookup_Request`/`TypeLookup_Reply` and
  every DDS-RPC header struct `@final` and serializes with XCDRv2. **Fast CDR**
  (`src/cpp/Cdr.cpp`) consulted for the mutable-member length-code selection: when a
  member value begins with its own DHEADER/length, the encoder emits `EMHEADER1 LC=5`
  with NEXTINT doubling as that leading UInt32 (XTypes 1.3 §7.4.3.5.3 rule (22)).
- **Wireshark `epan/dissectors/packet-rtps.c` (GPL-2.0) read for understanding only — no
  code copied**: the reference RTPS dissector's TypeLookup dissection (release-4.6)
  consulted to confirm it implements exactly the Fast DDS layout (CDR2_LE-gated, no
  top-level DHEADER, union DHEADERs, NEXTINT-as-count members). Used as the independent
  framing/payload oracle for the self-pinned vectors (`make wire`; no live peer exists,
  ADR 0010). → `src/dds-types/typelookup.lisp`.
