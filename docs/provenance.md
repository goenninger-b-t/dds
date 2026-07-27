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
| OpenSSL (`libcrypto`) ≥ 3.5 | vetted native CNSA-2.0 crypto for `dds-dare` Data-At-Rest Encryption (AES-256-GCM + ML-KEM-1024 + SHA-384/HKDF) via CFFI; FR-SEC-2 (no hand-rolling); control plane, off the hot path (ADR 0025) | Apache-2.0 |
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

## M4 (2026-06-11) — legacy-TypeObject TLV framing, derived by differential capture (ADR 0009)

Clean-room reverse engineering of RTI's proprietary legacy TypeObject (the inflated
`PID_TYPE_OBJECT_LB` / 0x8021). The byte structure's meaning is derived **only** from
captured bytes + a differential experiment — no RTI source/headers/`rtiddsgen` output read,
and the GPL Wireshark RTPS dissector was **not** used to decode the TypeObject. Tools used:
our own `dds.types:inflate-type-object-lb`, `tools/legacy-typeobject-diff.lisp` (`lto-diff`),
and live captures via `make corpus-capture` against our own `corpus_pub`.

### Experiment: C_Shape vs C_Shape2 (member rename color→colour)

- **IDL change** (`interop/connext/typeobject-corpus/Corpus.idl`): added a sibling
  `@final struct C_Shape2 { @key string colour; long x; long y; long shapesize; }` —
  identical to `C_Shape` except the key member is renamed `color`→`colour` (one octet
  longer) and the type `C_Shape`→`C_Shape2`. Captured both with `corpus_pub 0 Square
  C_Shape{,2}` ↔ `make corpus-capture` (loopback), then `lto-diff` on the two inflated
  TypeObjects (C_Shape = 536 octets, C_Shape2 = 540 octets).
- **`lto-diff` reported** (common prefix 8 octets, common suffix 4 octets): the changed
  middle differs in exactly the expected places —
  - type-name string: A `08 00 00 00 "C_Shape\0"` (len=8, 4-aligned) vs
    B `09 00 00 00 "C_Shape2\0\0\0\0"` (len=9, NUL-padded to 12);
  - member-name string: A `06 00 00 00 "color\0\0\0"` (len=6, padded to 8) vs
    B `07 00 00 00 "colour\0\0"` (len=7, padded to 8);
  - the +1 octet of `colour` cascaded `+4` through every enclosing length field
    (outer node 492→496, type-def node 324→328, struct-header node 28→32);
  - the struct's 8-octet type-hash changed (A `7B 0B 1F 98 CC 73 2D ED`, B
    `EB 69 87 1D 0D 30 FE 5D`) and recurs at both the struct head and the trailing node.
- **Framing conclusion** (offsets cite the 536-octet C_Shape inflate; identical structure
  in the 540-octet ShapeType per the corpus README hexdump): the payload is a back-to-back
  **sequence of nodes**, each one of two TAG-distinguished forms —
  - LONG `tag = 01 7F 08 00` : `tag(4) + code:u32(4) + length:u32(4) + value[length]`;
  - SHORT `tag = 02 7F 00 00` : a bare 4-octet leaf/terminator marker, empty value.
  A LONG value is a kind-specific fixed-field header (counts/ids/8-octet type-hashes, NOT
  interpreted) interleaved with nested LONG/SHORT child nodes. Length-prefixed strings are
  `len:u32 + len octets (trailing NUL counted) NUL-padded to the next 4-octet boundary`; the
  differential proves `length` is the real content extent. This is **not pure generic TLV**
  — the only structural anchoring is the two known TAG words, used to separate nested nodes
  from the opaque header/hash bytes; no per-type-kind semantics are decoded. The tokenizer
  rejects a `len=1` (bare-NUL) degenerate as a non-name (a real name is ≥1 printable octet +
  NUL, so single-char members like `x`/`y` are length-2). →
  `src/dds-types/legacy-type-object.lisp` (`tokenize-legacy-type-object`).
- **Corpus artifacts**: only the `Corpus.idl` + `corpus_pub.cxx` source edits are tracked;
  all `rtiddsgen` output and the `corpus_pub` binary stay git-ignored (NFR-IP).

### Experiment: C_Shape3 (+ a 5th member `long w`) — member counting + appended id

- **IDL change** (`interop/connext/typeobject-corpus/Corpus.idl`): added
  `@final struct C_Shape3 { @key string color; long x; long y; long shapesize; long w; }` —
  C_Shape plus a trailing `long w`. Captured `corpus_pub 0 Square C_Shape3` ↔ `make
  corpus-capture TOPIC=Square TYPE=C_Shape3 SECONDS=25` (loopback), then inflated +
  tokenized (`inflate-type-object-lb` → `tokenize-legacy-type-object`); C_Shape3 inflates
  to 592 octets (vs C_Shape 536).
- **Captured PID_TYPE_OBJECT_LB (240 octets)**: `(1 0 0 0 80 2 0 0 225 0 0 0 120 218 99 172
  231 96 0 1 21 38 6 6 38 48 139 133 65 12 72 50 2 197 57 129 116 13 35 132 13 2 10 32 113
  176 44 3 67 167 140 225 234 237 252 250 151 65 106 156 227 131 51 18 11 82 141 25 160 250
  24 193 166 64 0 136 159 130 198 79 5 153 5 84 196 202 128 48 91 5 108 54 4 8 67 233 138
  171 62 105 150 76 91 42 217 128 236 228 252 156 252 34 44 230 51 213 35 204 16 129 217 193
  0 50 155 21 236 159 10 34 245 48 33 233 169 36 160 71 6 42 198 12 213 195 5 164 139 65 33
  80 156 89 149 74 164 125 44 72 246 149 227 208 3 195 32 81 97 168 26 144 41 37 72 225 166 3
  118 187 48 74 120 137 130 220 83 82 148 153 151 30 111 100 106 26 159 156 145 88 148 152 92
  146 90 68 40 126 120 128 48 21 42 3 18 63 1 21 255 143 228 30 152 126 1 32 22 131 154 1 75
  11 32 121 0 25 248 54 140 0 0 0)`.
- **Observed**: the member-list container (the node with `CODE 101`) has its first value
  word = **5** (was 4 for C_Shape) — confirming **the container's first value word is the
  member count**. The members tokenize in declaration order with the per-member id at the
  member node's `VALUE-START+4`: `color 0, x 1, y 2, shapesize 3, w 4`. The appended `w`
  took the next sequential id **4** — i.e. `@autoid(SEQUENTIAL)` assigns the **0-based
  declaration index**, and a trailing append does not perturb the earlier ids.

### Experiment: C_Shape4 (reorder x before the @key) — positional vs explicit id

- **IDL change**: added `@final struct C_Shape4 { long x; @key string color; long y; long
  shapesize; }` — C_Shape with `x` moved ahead of the `@key` member. Captured `corpus_pub 0
  Square C_Shape4` ↔ `make corpus-capture TOPIC=Square TYPE=C_Shape4 SECONDS=25`; C_Shape4
  inflates to 540 octets.
- **Captured PID_TYPE_OBJECT_LB (232 octets)**: `(1 0 0 0 28 2 0 0 218 0 0 0 120 218 99 172
  231 96 0 129 15 140 12 12 76 96 22 11 131 24 144 100 4 138 115 2 105 15 70 8 27 4 20 64
  226 96 89 6 6 245 93 42 223 158 238 125 252 17 164 198 57 62 56 35 177 32 213 132 1 170
  143 17 108 10 4 128 248 41 104 252 84 32 253 6 42 6 51 91 132 1 1 88 129 16 228 150 10 44
  230 49 213 35 244 168 128 221 3 193 194 80 249 138 171 62 105 150 76 91 42 217 128 236 228
  252 156 252 34 2 102 192 236 101 66 178 183 146 128 30 25 168 24 51 84 15 23 144 46 6 133
  64 113 102 85 42 14 189 48 12 18 21 134 170 1 153 86 130 20 6 58 96 119 8 163 248 67 20 100
  118 73 81 102 94 122 188 145 169 105 124 114 70 98 81 98 114 73 106 17 161 176 230 1 194 84
  168 12 72 252 4 84 252 63 146 123 96 250 5 128 88 12 106 6 44 94 65 242 0 69 46 58 13 0 0)`.
- **Observed**: the members tokenize in declaration order with ids `x 0, color 1, y 2,
  shapesize 3`. `color`'s id moved **0→1** when it moved to declaration index 1, and `x`'s
  moved **1→0** — so **the member id is POSITIONAL** (the declaration index), NOT a stable
  per-member assignment carried across a reorder. The member node's `VALUE-START+0` word is
  the `@key` flag (color/`@key` = 1, the longs = 0); the **id is the `VALUE-START+4` word**,
  consistent across both the key/string member layout and the plain-`long` member layout.

### Conclusion — legacy-TypeObject struct skeleton (Task 2.1, drives `parse-legacy-type-object`)

Combining the three experiments (the type-name node + the member-id encoding; offsets cite
the 536-octet C_Shape inflate):

- **Type name**: the struct-definition node is the unique LONG node with `CODE 9`; its
  **first NAMED child** carries the qualified type name (`C_Shape` @ value `[48..76]`,
  len-prefixed `08 00 00 00 "C_Shape\0"`).
- **Members**: the struct node's child with `CODE 101` is the member-list container; its
  **NAMED `CODE 0` children** are the members in declaration order (the interleaved unnamed
  `CODE 0`/`CODE 1` and SHORT nodes are framing/terminators, not members). The container's
  first value word is the member count (cross-check). Each member node carries the **0-based
  declaration-order member id** as the u32 at `VALUE-START+4` (the `100`/`101` values seen in
  the framing dump are node **CODE**s — container kinds — NOT member ids; the member nodes are
  `CODE 0`). The id is positional (C_Shape4) and sequential-on-append (C_Shape3).
- **Extensibility**: every captured corpus type is `@final`; `parse-legacy-type-object`
  defaults `:final` for Task 2.1 and leaves `@appendable`/`@mutable` derivation (the
  struct-node flag field) to Task 2.4.
- **Out of scope here**: member TYPES (the `05 00 05 00` / `13 00 00 00` / 8-octet type-hash
  descriptors in the member node values) are NOT decoded — that is Task 2.2/2.3; the parsed
  member `type-identifier` slot is left NIL. →
  `src/dds-types/legacy-type-object.lisp` (`parse-legacy-type-object`).
- **Corpus artifacts**: only the `Corpus.idl` + `corpus_pub.cxx` source edits are tracked;
  the C_Shape3/C_Shape4 `rtiddsgen` output and the `corpus_pub` binary stay git-ignored (NFR-IP).

### Experiment set: C_ShapeP_<prim> — primitive member type-kind (Task 2.2, 2026-06-11)

- **IDL change** (`interop/connext/typeobject-corpus/Corpus.idl`): added one
  `@final struct C_ShapeP_<prim> { @key string color; <prim> x; long y; long shapesize; }`
  per primitive — each is C_Shape with member `x` (a `long` in the base) RETYPED to one
  primitive, isolating the type-kind change in member x's node. Built with
  `make -C interop/connext/typeobject-corpus` (rtiddsgen 4.3.1) and captured each live via
  `corpus_pub 0 Square C_ShapeP_<prim>` ↔ `make corpus-capture TOPIC=Square TYPE=C_ShapeP_<prim>
  SECONDS=20` (loopback), then `inflate-type-object-lb` + `tokenize-legacy-type-object`.
- **Localization**: in every capture, member x's node value (the `CODE 0` named member node)
  has the fixed layout `[ @key:u32 @ +0 ][ id:u32 @ +4 ][ KIND:u16 @ +8 ][ KIND:u16 @ +10
  (repeated) ][ name-len:u32 @ +12 ][ name… ]`. The base `long x` node was
  `00 00 00 00 | 01 00 00 00 | 05 00 05 00 | 02 00 00 00 | 78 00 00 00` (id=1, kind=`05 00`,
  name-len=2 "x\0"). Retyping x changed ONLY the `+8`/`+10` kind word; id, name-len and name
  were unchanged. So **the primitive type-kind is the u16 at the member node's VALUE-START+8**
  (redundantly repeated at +10).
- **RTI kind octet → keyword (the differential, member x node `+8` u16, low octet):**

  | IDL primitive       | x-node bytes (`+0..`)                                   | RTI kind | our keyword | +tk-* (octet) |
  |---------------------|---------------------------------------------------------|----------|-------------|---------------|
  | `boolean`           | `00..|01..|`**`01 00 01 00`**`|02..`                    | `0x01`   | `:bool`     | TK_BOOLEAN 0x01 |
  | `octet`             | `00..|01..|`**`02 00 02 00`**`|02..`                    | `0x02`   | `:u8`       | TK_BYTE 0x02 |
  | `short`             | `00..|01..|`**`03 00 03 00`**`|02..`                    | `0x03`   | `:i16`      | TK_INT16 0x03 |
  | `unsigned short`    | `00..|01..|`**`04 00 04 00`**`|02..`                    | `0x04`   | `:u16`      | TK_UINT16 0x06 |
  | `long` (base)       | `00..|01..|`**`05 00 05 00`**`|02..`                    | `0x05`   | `:i32`      | TK_INT32 0x04 |
  | `unsigned long`     | `00..|01..|`**`06 00 06 00`**`|02..`                    | `0x06`   | `:u32`      | TK_UINT32 0x07 |
  | `long long`         | `00..|01..|`**`07 00 07 00`**`|02..`                    | `0x07`   | `:i64`      | TK_INT64 0x05 |
  | `unsigned long long`| `00..|01..|`**`08 00 08 00`**`|02..`                    | `0x08`   | `:u64`      | TK_UINT64 0x08 |
  | `float`             | `00..|01..|`**`09 00 09 00`**`|02..`                    | `0x09`   | `:f32`      | TK_FLOAT32 0x09 |
  | `double`            | `00..|01..|`**`0A 00 0A 00`**`|02..`                    | `0x0A`   | `:f64`      | TK_FLOAT64 0x0A |
  | `char`              | `00..|01..|`**`0C 00 0C 00`**`|02..`                    | `0x0C`   | `:char`     | TK_CHAR8 0x10 |

- **Key finding**: the kind octet is **RTI's OWN internal primitive enumeration, NOT the XTypes
  TK_* octets** — they coincide for boolean/byte/short/int64/uint64/float32/float64 but DIVERGE
  for long (RTI 5 vs TK_INT32 4), unsigned long (RTI 6 vs TK_UINT32 7), unsigned short (RTI 4 vs
  TK_UINT16 6) and char (RTI 0x0C vs TK_CHAR8 0x10). The table `*lto-primitive-kind-keyword*` maps
  RTI's octet to our `primitive-type-identifier` keyword, which then yields the correct in-memory
  `+tk-*+` kind. → `src/dds-types/legacy-type-object.lisp` (`%lto-member-type-identifier`).
- **Gaps**: `int8`/`uint8` were NOT captured (corpus uses `octet` for the 8-bit kind). Per RTI's
  Extensible Types Guide (cited earlier in this file) `int8`/`uint8` map to `octet` on the wire,
  i.e. RTI kind `0x02` (TK_BYTE) — consistent with the `octet` capture above; untested here, so
  recorded as a fail-open gap. RTI value `0x0B` (`char16`/`wchar`) and `0x0A`-vs-`0x0B` boundaries
  were not exercised; any kind not in the table is treated as non-primitive (TI left NIL).
- **C_Shape-string-handling decision (a)**: a member whose `+8` kind word is not in the primitive
  table — the `@key string color` member, whose node instead carries `13 00 00 00` + an 8-octet
  type-hash at `+8` — leaves its `type-identifier` NIL and parsing CONTINUES (it does NOT make the
  whole parse `:unsupported`). So the base C_Shape still parses (color NIL; x/y/shapesize TK_INT32)
  while the primitive variants assert their kinds. Task 2.3 decodes string/sequence/nested members;
  a TRULY unmodelable kind becomes `:unsupported` then.
- **Corpus artifacts**: only the `Corpus.idl` + `corpus_pub.cxx` source edits are tracked; all
  `rtiddsgen` output and the `corpus_pub` binary stay git-ignored (NFR-IP).

### Experiment set: C_ShapeS32 / C_ShapeS300 / C_ShapeNoKey — string bound + @key flag (Task 2.3, 2026-06-11)

- **IDL change** (`interop/connext/typeobject-corpus/Corpus.idl`): three differentials of the base
  `C_Shape` (`@key string color; long x,y,shapesize`):
  - `C_ShapeS32` — `color` is `string<32>` (bounded).
  - `C_ShapeS300` — `color` is `string<300>` (bounded > 255, forces the large form in our model).
  - `C_ShapeNoKey` — `color` is a plain `string` (not @key); the @key moves to `long x`.
  Each captured live: `corpus_pub 0 Square <type>` ↔ `make corpus-capture TOPIC=Square TYPE=<type>
  SECONDS=30` (loopback), then `inflate-type-object-lb` + `tokenize-legacy-type-object`. (RTI
  install at `/Applications/rti_connext_dds-7.3.1`, arch `arm64Darwin20clang12.0`; corpus_pub's
  `@loader_path` RTI dylibs were symlinked next to the binary — git-ignored — since macOS SIP
  strips `DYLD_LIBRARY_PATH`.) Cross-check: `Corpus.cxx` generated
  `initialize_string_typecode((32L))` / `((300L))` / `((255L))` respectively — confirming
  C_ShapeNoKey's `color` stays the RTI-default 255.
- **String-bound localization — the bound is NOT inline in the member node.** The string member
  node (the `CODE 0` named member whose `+8` kind u16 is `0x13`) has the layout
  `[ @key:u32 @+0 ][ id:u32 @+4 ][ kind=0x13:u16 @+8 ][ 0:u16 @+10 ][ 0:u32 @+12 ][ 8-octet
  type-hash @+16 ][ name-len:u32 @+28 ][ name… ]`. The 8-octet hash at `+16` REFERENCES a separate
  **string-definition node** (`CODE 8`, `+lto-code-string-def+`): that node's `CODE 0` child
  echoes the same 8-octet hash at its own `VALUE-START+8` and carries the `string_<N>_character`
  name; its `CODE 100` child holds the element kind (`0C 00` = char); and its **`CODE 200` child
  (`+lto-code-string-bound+`) holds the bound as a u32 at its `VALUE-START`**. Evidence (the
  `CODE 200` child's bound u32): C_Shape `FF 00 00 00` = **255**; C_ShapeS32 `20 00 00 00` = **32**;
  C_ShapeS300 `2C 01 00 00` = **300**. Member-node `+8` kind, id, name-len and the hash mechanism
  were unchanged across all three — only the referenced node's `CODE 200` value moved.
- **Small/large threshold — RTI uses a u32 bound at ALL magnitudes; the small/large split is OURS.**
  32, 255, and 300 are all encoded as a plain little-endian u32 in the `CODE 200` child; RTI's
  legacy encoding has NO small/large byte-form distinction. The XTypes 255 boundary (idl §56-70,
  `TI_STRING8_SMALL` SBound ≤255 vs `TI_STRING8_LARGE` LBound >255) is applied only when we BUILD
  the in-memory `type-identifier` (`string8-type-identifier`): bound 32/255 → `+ti-string8-small+`,
  bound 300 → `+ti-string8-large+`. The decoder reads RTI's u32 and selects our kind by `> 255`.
- **@key flag localization — the member node's `+0` word.** Across all members of all four types,
  the `VALUE-START+0` u32 is **1 for the @key member, 0 for the rest**:
  - C_Shape / C_ShapeS32 / C_ShapeS300: `color +0=1`, `x/y/shapesize +0=0`.
  - C_ShapeNoKey: `color +0=0`, `x +0=1`, `y/shapesize +0=0` — confirming the @key moved to `x`
    drops color's `+0` to 0 and raises x's to 1, both directions.
  This corroborates the Task 2.1 note (color/`@key`=1, the longs=0) and is now DECODED into
  `minimal-struct-member-key-p` via `%lto-member-key-p`.
- **Decode** → `src/dds-types/legacy-type-object.lisp`: `%lto-member-type-identifier` (string arm),
  `%lto-find-string-bound` (hash→string-def→bound, every span bounds-checked), `%lto-member-key-p`,
  and constants `+lto-member-kind-string+` (0x13), `+lto-code-string-def+` (8), `+lto-code-string-bound+`
  (200). The model constructor `string8-type-identifier` lives in `src/dds-types/xtypes.lisp`.
- **Gaps**: only the `char`-element narrow `string` (RTI element kind `0x0C`) was exercised;
  `wstring` (`string16`) and a string with a non-default element were NOT captured. A string member
  whose referenced string-def node or `CODE 200` bound child is missing leaves its `type-identifier`
  NIL (fail-open, parsing continues) — recorded as a gap, not an error.
- **Corpus artifacts**: only the `Corpus.idl` + `corpus_pub.cxx` source edits are tracked; all
  `rtiddsgen` output, the `corpus_pub` binary, and the symlinked RTI dylibs stay git-ignored (NFR-IP).

### Experiment set: C_ShapeAppend / C_ShapeMutable — struct extensibility flag (Task 2.4, 2026-06-11)

- **IDL change** (`interop/connext/typeobject-corpus/Corpus.idl`): two differentials of the base
  `C_Shape` (`@key string color; long x,y,shapesize`) with only the struct extensibility changed:
  - `C_ShapeAppend` — `@appendable struct` (members otherwise identical to the base).
  - `C_ShapeMutable` — `@mutable struct` (members otherwise identical).
  Each captured live: `corpus_pub 0 Square <type>` ↔ `make corpus-capture TOPIC=Square TYPE=<type>
  SECONDS=25` (loopback), then `inflate-type-object-lb` + `tokenize-legacy-type-object`. (RTI
  install at `/Applications/rti_connext_dds-7.3.1`, arch `arm64Darwin20clang12.0`; the `@loader_path`
  RTI dylibs were symlinked next to `corpus_pub` — git-ignored — since macOS SIP strips
  `DYLD_LIBRARY_PATH`.)
- **Extensibility-flag localization — the FIRST child of the struct-def node (CODE 9).** The
  struct-definition node (`+lto-code-struct+` = 9) has as its FIRST child a `LONG` `CODE 0` node
  (the one carrying the struct type-name). The **u16 at that first child's `VALUE-START+0`** is the
  extensibility flag; the u16 at `+2` is a constant `0x0016` (then the type-name follows). The
  member nodes were **byte-for-byte identical** across @final/@appendable/@mutable — only this flag
  word and the type-name string changed; @mutable did NOT alter member encoding here.
- **Wire values** (the first-child `VALUE-START+0` u16):
  - `@final` (base `C_Shape`):    **0x0001**
  - `@appendable` (`C_ShapeAppend`): **0x0000**
  - `@mutable` (`C_ShapeMutable`):  **0x0002**
  This is RTI's OWN internal extensibility enumeration (`appendable=0, final=1, mutable=2`), NOT the
  XTypes `IS_FINAL`/`IS_APPENDABLE`/`IS_MUTABLE` struct-flag bits (XCDR2 TypeObject, `typeobject-cdr.lisp`:
  final=0x0001, appendable=0x0002, mutable=0x0004) — the two enumerations COINCIDE only for `final`
  and DIFFER for the others, so the value must be read from this differential, never assumed from the
  XTypes flag. The high `0x0016` halfword is opaque (not interpreted).
- **Decode** → `src/dds-types/legacy-type-object.lisp`: `%lto-struct-extensibility` reads the u16 at
  the struct-def node's first `CODE 0` child's `VALUE-START+0` (bounds-checked against that child's
  `VALUE-END` FIRST), mapping `0→:appendable, 1→:final, 2→:mutable`; any other value (or an OOB/missing
  read) → `:final` (fail-open: `:final` is the strictest extensibility for gating, so a wrong-but-final
  guess never widens evolution rules). `parse-legacy-type-object` replaces its hardcoded `:final` with
  this decode. The parsed model is the SAME `minimal-struct-type` the local generator builds, so it
  flows into `struct-assignable-from` (`assignability.lisp`) unchanged — the assignability gate keys
  off `minimal-struct-type-extensibility` (same-extensibility precondition + FINAL/APPENDABLE/MUTABLE
  member-matching) directly on the wire-derived value.
- **Gaps**: only flat-struct extensibility was exercised. `@mutable` here left member encoding identical
  to `@final` (the corpus members are scalar/string); a `@mutable` struct with members that DO carry
  explicit per-member EMHEADER-like ids (e.g. optional/large members) was NOT captured — if such a
  member-encoding divergence exists it is unexercised and would be a Stage-3+ finding. Unknown flag
  values fail open to `:final` (recorded above).
- **Corpus artifacts**: only the `Corpus.idl` + `corpus_pub.cxx` source edits are tracked; all
  `rtiddsgen` output, the `corpus_pub` binary, and the symlinked RTI dylibs stay git-ignored (NFR-IP).

### Experiment set: C_Seq / C_SeqL / C_SeqL100 — sequence member element + bound (Task 3.1, 2026-06-11)

- **Goal**: decode `sequence<T>` (bounded + unbounded) members from the legacy TypeObject into our
  `sequence-type-identifier` (element TI + bound). Three live captures, each a struct with a `@key long
  id` plus one sequence member `payload`:
  - `C_Seq` — `sequence<octet> payload` (matches the LargeData shape; unbounded → RTI default bound).
  - `C_SeqL` — `sequence<long, 10> payload` (bounded element=long, bound 10).
  - `C_SeqL100` — `sequence<long, 100> payload` (bound 100; confirms the bound field width).
- **Method**: `make corpus-capture TOPIC=Square TYPE=<typename>` ↔ `corpus_pub 0 Square <typename>`,
  loopback (NDDSHOME=/Applications/rti_connext_dds-7.3.1, CONNEXTDDS_ARCH=arm64Darwin20clang12.0; RTI
  dylibs symlinked next to `corpus_pub`, git-ignored — macOS SIP strips `DYLD_LIBRARY_PATH`). Raw LB
  vectors captured: C_Seq 200 octets (inflate 420), C_SeqL 204 (inflate 420), C_SeqL100 204 (inflate
  424). Tokenized + structurally walked vs the base C_Shape.
- **Sequence member node** (e.g. C_Seq `payload`, value bytes `00 00 00 00 | 01 00 00 00 | 12 00 00 00
  | 00 00 00 00 | AB C3 A5 34 8D CC 0E 0D | 08 00 00 00`):
  - `+0` u32 = the `@key` flag (0 — payload not key), as for every member (Task 2.3).
  - `+4` u32 = the member id (1 — declaration index), as for every member (Task 2.1).
  - `+8` **u16 = 0x0012 (18)** = the SEQUENCE member-kind (string is 0x13; sequence is **0x12**). The
    `+10` u16 is the redundant mirror copy (same convention as the primitive/string member-kind).
  - `+16` 8 octets = the **type-hash** referencing the sequence-definition node — the SAME
    hash-reference mechanism strings use (Task 2.3), just a different def-node CODE.
- **Sequence-definition node**: the LONG node with **CODE 7** (strings use CODE 8) whose CODE-0 child
  echoes the member's 8-octet hash at its `VALUE-START+8` (identical to the string-def echo). Its
  named CODE-0 child also carries RTI's internal type name (`sequence_100_Byte` / `sequence_10_Int32`
  / `sequence_100_Int32` — the embedded number is the bound, a useful cross-check). Under it:
  - a **CODE 100** child whose `VALUE-START` u16 is the **element type-kind**, in RTI's OWN primitive
    enum (`*lto-primitive-kind-keyword*`, same as the member primitive kind): C_Seq `02 00 02 00` →
    octet (2), C_SeqL / C_SeqL100 `05 00 05 00` → long (5). (The value is the kind repeated as two u16.)
  - a **CODE 200** child whose `VALUE-START` u32 is the **sequence bound**: C_Seq `64 00 00 00` = 100,
    C_SeqL `0A 00 00 00` = 10, C_SeqL100 `64 00 00 00` = 100. CODE 200 is the SAME bound-child code the
    string-def uses — the bound is always a u32 (4-octet child value, len=4).
- **Unbounded default**: `C_Seq`'s `sequence<octet>` is IDL-unbounded, yet RTI emits **bound 100**
  (the `sequence_100_Byte` token confirms it) — RTI's default unbounded-sequence bound, directly
  analogous to the **255** default for unbounded strings. The decoder reads the wire bound; it does not
  synthesize 100 (recorded as `+lto-sequence-default-bound+` for documentation only).
- **Decode** → `src/dds-types/legacy-type-object.lisp`: `%lto-member-type-identifier` dispatches kind
  `+lto-member-kind-sequence+` (0x12) to `%lto-sequence-type-identifier`, which resolves the
  `+lto-code-sequence-def+` (7) node via the shared `%lto-find-def-node` (refactored out of the string
  path — DRY), reads the element kind from its `+lto-code-sequence-element+` (100) child and the bound
  from its `+lto-code-string-bound+` (200) child, and builds `(sequence-type-identifier
  (primitive-type-identifier <kw>) <bound>)`. The string path now also uses `%lto-find-def-node`.
- **Decoded coverage**: sequence-of-PRIMITIVE only (octet/long proven; the full
  `*lto-primitive-kind-keyword*` map applies). A sequence whose element is itself a string, a nested
  aggregate, or another sequence is a **Task 3.2 gap**: the element kind word is non-primitive, so
  `%lto-sequence-type-identifier` returns NIL and the member TI stays NIL (fail-open, parse continues).
  These element kinds were NOT captured here. `wstring`-element and char16 sequences are likewise
  untested gaps.
- **Corpus artifacts**: only the `Corpus.idl` + `corpus_pub.cxx` source edits are tracked; all
  `rtiddsgen` output, the `corpus_pub` binary, and the symlinked RTI dylibs stay git-ignored (NFR-IP).

### Experiment set: C_Nested / C_Nested2 — nested-struct member + recursion (Task 3.2, 2026-06-11)

- **Goal**: decode a NESTED-STRUCT (aggregate) member from the legacy TypeObject into an
  EK_MINIMAL `hash-type-identifier` whose `referenced` slot is the parsed nested
  `minimal-struct-type`, and make `struct-assignable-from` recurse through it (FR-TYPE-4). Two
  live captures:
  - `C_Nested` — `@final struct C_Nested { @key long id; C_Inner inner; }` with
    `@final struct C_Inner { long a; long b; }`.
  - `C_Nested2` — adds a second `C_Inner inner2` (proves the resolver + the visited-hash guard
    handle a REPEATED reference to the same def; the corpus DSL is acyclic).
- **Method**: `make corpus-capture TOPIC=Square TYPE=<typename>` ↔ `corpus_pub 0 Square <typename>`,
  loopback (NDDSHOME=/Applications/rti_connext_dds-7.3.1, CONNEXTDDS_ARCH=arm64Darwin20clang12.0;
  RTI dylibs symlinked next to `corpus_pub`, git-ignored — macOS SIP strips `DYLD_LIBRARY_PATH`).
  Raw LB vectors: C_Nested 192 octets (inflate 508), C_Nested2 208 (inflate 576). Tokenized +
  structurally walked.
- **TypeLibrary structure**: publishing `C_Nested` makes RTI emit a legacy TypeObject containing
  TWO top-level `+lto-code-struct+` (CODE 9) definition nodes under the outer wrapper — the OUTER
  `C_Nested` def FIRST (pre-order) and `C_Inner`'s def as a SIBLING after it. So a legacy
  TypeObject is a TypeLibrary: the nested type's def travels in-band, parseable by the SAME
  struct-parse path. The top-level entry (`%lto-find-code root +lto-code-struct+`, first match)
  correctly selects the outer struct; the nested resolver finds the sibling by hash.
- **Nested-struct member node** (C_Nested `inner`, value bytes `00 00 00 00 | 01 00 00 00 |
  16 00 00 00 | 00 00 00 00 | DC ED 95 59 17 6D 83 9F | 06 00 00 00 69 6E 6E 65 …`):
  - `+0` u32 = the `@key` flag (0 — inner not key), as for every member.
  - `+4` u32 = the member id (1 — declaration index), as for every member.
  - `+8` **u16 = 0x0016 (22)** = the NESTED-STRUCT member-kind (string 0x13, sequence 0x12, nested
    struct **0x16**). The `+10` u16 is the redundant mirror (0x0000 here).
  - `+16` 8 octets = the **type-hash** referencing the nested struct-def — the SAME
    hash-reference mechanism strings (CODE 8) and sequences (CODE 7) use, here pointing at a
    `+lto-code-struct+` (CODE 9) def node.
- **Reference resolution**: the existing `%lto-find-def-node` (find the DEF-CODE node whose CODE-0
  child echoes the member's 8-octet hash at its `VALUE-START+8`) resolves the nested member with
  `def-code = +lto-code-struct+` (9) UNCHANGED. Verified: `inner` hash `DC ED 95 59 17 6D 83 9F` ==
  C_Inner's CODE-0 child "C_Inner" echo at +8; `%lto-find-def-node` returns the C_Inner def
  (name "C_Inner", code 9). C_Nested2's `inner` and `inner2` BOTH carry that same hash — the def is
  shared, the two members resolve independently.
- **Struct-parse refactor (DRY)**: the struct-node→model core of `parse-legacy-type-object`
  (type-name + member-list container + per-member fold + member-count cross-check) is factored into
  `%lto-parse-struct-node (octets root sdef depth visited)`, called BOTH by the top-level entry and
  by the nested resolver — so nesting recurses naturally through the same code. The nested arm is
  `%lto-nested-type-identifier`: resolve the CODE-9 def via `%lto-find-def-node`, parse it with
  `%lto-parse-struct-node` at `(1+ depth)` with the member-hash added to `visited`, wrap the result
  in `(hash-type-identifier +ek-minimal+ :referenced model)`. `%lto-member-type-identifier` gains
  `depth`/`visited` params and dispatches kind 0x16 to it.
- **Cycle + depth guard (NFR-SEC-POSTURE, MANDATORY)**: `*lto-max-type-depth*` (16) caps nested
  resolution depth — guaranteeing termination even for a hostile chain. A `visited` list of member
  hash@+16 keys (packed u64) short-circuits a self-/mutually-referential reference: when a member's
  hash is already in `visited`, the resolver returns NIL (fail-open, member TI NIL, parse
  continues) at depth 1 rather than looping. The two guards are belt-and-suspenders: depth bounds
  any chain; the visited set breaks an exact cycle immediately. Because the corpus IDL is acyclic
  (no cyclic TypeObject capturable), the guard is verified by (a) `*lto-max-type-depth*` 0 forcing
  every nested member open while flat members still decode (`:lto-nested-depth-guard`), and (b)
  C_Nested2's legitimate repeated reference NOT being over-blocked (`:lto-nested2-both-resolved`).
  Reasoning for the self-ref case: a `struct S { S inner; }` member's hash == S's def-hash; first
  resolution adds it to `visited` and recurses into S; the inner `inner` member's hash is now in
  `visited` → NIL → recursion stops at depth 1. The visited set is passed BY VALUE down the
  recursion (not mutated), so sibling members at the same level (C_Nested2 inner/inner2) do not
  pollute each other.
- **Assignability proof (through the REAL gate)**: the parsed `inner` aggregate TI's `referenced`
  C_Inner {a,b long} feeds `struct-assignable-from`. Note: a `@final` nested element is NOT
  self-delimiting under XCDR2 (§7.2.4.2), so the stack's strong-assignability rule
  (`:asg-strong-delimited`) would mask the recursion for a `@final`/`@final` pair — therefore the
  recursion proof uses a `@mutable` outer + `@appendable` nested C_Inner (mirroring the stack's
  established `:asg-nested` fixture), where the nested member-type DRIVES the verdict: a
  nested-compatible local → T (both directions); a nested-INCOMPATIBLE local (C_Inner.a or .b
  retyped long→double) → NIL — the gate recurses into the referenced model to decide. (A member-SET
  change is not used: APPENDABLE allows truncation both ways, so a dropped member stays assignable;
  only a member-TYPE change flips the recursed verdict.)
- **Decoded coverage**: nested-struct members (any depth, under the depth/cycle guards) decode +
  recurse through assignability. STILL `:unsupported` / member-TI NIL (fail-open): sequence-OF-
  aggregate (sequence element kind non-primitive — Task 3.x), and any Stage-4 aggregate variant
  (unions, enums, typedefs, arrays, nested mutable members carrying explicit per-member EMHEADER
  ids) — NOT captured here.
- **Corpus artifacts**: only the `Corpus.idl` + `corpus_pub.cxx` source edits are tracked; all
  `rtiddsgen` output, the `corpus_pub` binary, and the symlinked RTI dylibs stay git-ignored (NFR-IP).

### Experiment set: C_Enum — enum member-kind + the degrading policy (Task 4.1, 2026-06-11)

Method: clean-room differential, meanings ONLY from captured bytes (no RTI source / GPL dissector).
Added `enum SomeEnum { RED, GREEN, BLUE };` + `@final struct C_Enum { @key long id; SomeEnum e; };`
to `Corpus.idl` (+ one `corpus_pub` dispatch arm), rebuilt with `rtiddsgen`, captured the live
SEDP `PID_TYPE_OBJECT_LB` via `make corpus-capture TOPIC=Square TYPE=C_Enum`.

- **Capture**: 208-octet LB; inflates to a **444-octet** legacy TypeObject. `type-object-strings`
  fingerprint = `("C_Enum" "SomeEnum" "RED" "GREEN" "BLUE")` — the enum type name + the three
  enumerator names travel in-band.
- **Member walk** (tokenized; member-list container's CODE-0 named children):
  - `id`: `+0` key=1, `+4` id=0, `+8` u16 kind = **0x05** = RTI `long` → decodes to `TK_INT32` (as
    before; the flat @key long).
  - `e` (the enum member): `+0` key=0, `+4` id=1, `+8` u16 kind = **0x0E (14)**. This is the
    ENUM member-kind word, at the SAME `VALUE-START+8` offset every member-kind lives at (primitive
    1–0x0C, string 0x13, sequence 0x12, nested struct 0x16, **enum 0x0E**). It is ABSENT from
    `*lto-primitive-kind-keyword*` (1–10, 0x0C) so it is NOT mis-decoded as a primitive.
- **Decision rule (the operating contract, Task 4.1 — never emit a TI assignability will mis-handle)**:
  `src/dds-types/assignability.lisp` models ONLY primitives, narrow strings, plain sequences, and
  (nested) structs (its own header: "Union/enum/bitmask/array/map/alias assignability awaits their
  type model … conservatively non-assignable"). There is **no enum TypeIdentifier** and no
  `+tk-enum+`/`bit_bound` representation. Therefore an enum member is **UNMODELABLE**: we do NOT
  decode it to its underlying integer (that would silently widen an enum to `long` and let the gate
  pass an enum-vs-long mismatch), and we do NOT invent an enum TI the gate cannot use. Outcome:
  **enum member → the whole `parse-legacy-type-object` returns `:unsupported`** (fail-open to
  name-match at the Stage-5 gate). Recorded as a **gap**: enum decode-as-int is unlocked the day
  assignability gains an enum TI.
- **GATE-SAFETY policy flip (Part A, the crux of "degrading correctly")**: previously an unmodeled
  member kind left that member's `type-identifier` NIL and `parse-legacy-type-object` CONTINUED,
  returning a struct with a NIL-TI member. That is a gate hazard once the model feeds
  `struct-assignable-from` (a NIL-TI member could mis-gate or error). New policy: in
  `%lto-parse-struct-node`, a member that DECLARES a type (kind word present at `+8`,
  `%lto-member-has-kind-p`) but whose TI cannot be built (`%lto-member-type-identifier` NIL — an
  unmapped kind like enum/union/array/bitmask, an unresolvable hash, a sequence-of-aggregate, or an
  over-depth/cyclic nested struct) degrades the WHOLE parse to `:unsupported`. The Stage-5 gate then
  falls OPEN to name-match — never gates on a partial model.
- **Regression of prior tests**: all 7 tier-1/2/3 lto tests stay green (C_Shape and its primitive /
  string / extensibility / sequence / nested variants have only modelable members — they were never
  NIL-TI, so the flip does not touch them). ONE existing sub-check flipped: the nested depth-guard
  (`:lto-nested-depth-guard`) previously asserted `*lto-max-type-depth* 0` left the nested member's
  TI NIL with the parse CONTINUING; under the policy that over-depth nested member is unmodelable, so
  the parse now correctly degrades to `:unsupported` — the test was updated to assert that (the
  over-depth nested struct IS unmodelable at that depth, not a decode gap; degrading is the correct
  verdict). No test relied on a NIL-but-continue that masked a type we DO model.
- **Decoded coverage update**: still `:unsupported` (fail-open) — enum (0x0E), and every Stage-4
  aggregate variant (union/bitmask/array/map/typedef) plus sequence-of-aggregate. The difference
  from before is the FAILURE MODE: these now degrade the WHOLE type to `:unsupported` instead of
  emitting a partial model — strictly safer for the gate.
- **Corpus artifacts (C_Enum)**: only the `Corpus.idl` + `corpus_pub.cxx` source edits are tracked;
  all `rtiddsgen` output, `corpus_pub`, and the symlinked RTI dylibs stay git-ignored (NFR-IP).

### C_Enum legacy enum def-node — structural enum decode (Task S0.3, 2026-06-12)

Method: clean-room differential over the SAME locked C_Enum capture (444-octet inflated), meanings
ONLY from captured bytes — the tokenized tree was dumped (each node's tag/code/[value-start,value-end)
+ leading value bytes) and read directly; no RTI source / GPL dissector. This RE flips enum OUT of
the Task-4.1 degrade tier into a real EK_MINIMAL enumerated TypeIdentifier.

- **Enum member `e`** (member-list CODE-0 child node `[188..220)`):
  bytes `00000000 | 01000000 | 0E000000 | 00000000 | 96B9AFC0 319DC514 | 02000000 | 65000000`.
  `+0` key=0, `+4` id=1, `+8` u16 kind = **0x0E (14)** = enum (already pinned in Task 4.1), `+16`
  8-octet type-hash `96 B9 AF C0 31 9D C5 14` — the SAME hash@+16 reference mechanism strings
  (0x13/CODE-8), sequences (0x12/CODE-7) and nested structs (0x16/CODE-9) use.
- **Enum-def node = CODE 5** (`+lto-code-enum-def+`), node `[268..408)`. Its CODE-0 child `[280..312)`
  (name="SomeEnum") echoes the member's hash at its `VALUE-START+8`: `96 B9 AF C0 31 9D C5 14` —
  byte-identical to the member's `+16` hash. So `%lto-find-def-node octets root member-node 5`
  resolves it by the shared hash-reference pattern. The differential that establishes CODE 5 = enum:
  no other tier (string-def 8 / sequence-def 7 / struct-def 9) carries this hash, and CODE 5 is the
  unique node whose CODE-0 child name is the enum type name "SomeEnum".
- **Bit-bound child = CODE 100** (`+lto-code-enum-bitbound+`), child `[340..344)` = `20 00 00 00`
  = **0x20 = 32** (a u32). (CODE value 100 coincides with the sequence element-type child; the two
  are disambiguated by the PARENT code — enum-def 5 vs sequence-def 7 — never read on the same node.)
- **Literal-list child = CODE 101** (`+lto-code-enum-literals+`), child `[356..404)`, 48 bytes:
  ```
  03 00 00 00                          count = 3
  00 00 00 00  04 00 00 00  52 45 44 00              value=0, len=4, "RED\0"           → RED  / 0
  01 00 00 00  06 00 00 00  47 52 45 45 4E 00 00 00  value=1, len=6, "GREEN\0"+NULpad  → GREEN/ 1
  02 00 00 00  05 00 00 00  42 4C 55 45 00 00 00 00  value=2, len=5, "BLUE\0"+NULpad   → BLUE / 2
  ```
  Layout: `count:u32`, then per literal `value:u32` + a length-prefixed NUL-padded literal NAME (the
  exact `%lto-read-name` framing: len:u32 + len octets, trailing NUL counted, padded to 4). Decoded
  RED=0 GREEN=1 BLUE=2 — matching the `Corpus.idl` ground truth `enum SomeEnum { RED, GREEN, BLUE }`
  (sequential 0,1,2). (CODE value 101 coincides with the struct member-list container; disambiguated
  by parent code — enum-def 5 vs struct-def 9 — the decoder reads it only via the resolved enum-def.)
- **Wire stores NAMES, not hashes**: the literal node carries the literal name STRING ("RED"/"GREEN"/
  "BLUE"), so the decoder builds each literal with `make-enum-literal NAME VALUE` — its NameHash =
  MD5(NAME)[0:4], the SAME hash a locally-built model computes. That makes the wire-parsed enum and a
  local enum match by NameHash in `enum-assignable-from` (which compares same-name/different-value).
- **Assignability proof** (`run-lto-enum-assignability-test`): the parsed C_Enum's `e` member is an
  EK_MINIMAL TI → `minimal-enumerated-type` {RED 0, GREEN 1, BLUE 2}, bit-bound 32. The struct is
  `@final`; an enum TI is delimited (fixed bit-bound storage, `ti-delimited-p`), so the @final
  struct-member match runs `strongly-assignable-from` → `enum-assignable-from`. A matching local
  (BLUE=2) is assignable both ways; a local with BLUE=3 (same NameHash, different value) is a PROVABLE
  enum incompatibility → NOT assignable both ways; re-running the compatible case proves no false-reject.
- **Decoded coverage update**: enum (0x0E) is now **structurally modeled** (no longer in the degrade
  tier). The remaining degrade tier is union (0x15) / array (0x11) / bitmask (uncaptured) / map /
  typedef + sequence-of-aggregate — still `:unsupported` (fail-open). The live legacy-gate fail-open
  case (3) driver was repointed from C_Enum to C_Union (`run-dcps-legacy-gate-test`,
  `integration-test.lisp`) since enum no longer degrades.
- **Corpus artifacts**: unchanged from the Task-4.1 entry — only `Corpus.idl` + `corpus_pub.cxx`
  edits tracked; `rtiddsgen` output + RTI dylibs stay git-ignored (NFR-IP). No new capture was taken;
  this RE re-reads the existing C_Enum bytes.

### Experiment set: C_Union + C_Array — union/array member-kinds, degrading tier (Task 4.2, 2026-06-11)

Method: clean-room differential, meanings ONLY from captured bytes (no RTI source / GPL dissector).
Added `union SomeUnion switch(long) { case 0: long a; case 1: double b; }` + `@final struct C_Union
{ @key long id; SomeUnion u; }` and `@final struct C_Array { @key long id; long arr[4]; }` to
`Corpus.idl` (+ two `corpus_pub` dispatch arms), rebuilt with `rtiddsgen 4.3.1`, captured via
`make corpus-capture TOPIC=UnionTopic TYPE=C_Union` and `make corpus-capture TOPIC=ArrayTopic
TYPE=C_Array`. A third construct, C_Bitmask (`bitmask SomeBits { FLAG_A, FLAG_B, FLAG_C }`), was
attempted but **NOT CAPTURABLE**: `rtiddsgen 4.3.1` rejects the `bitmask` keyword with
`"mismatched input 'bitmask' expecting EOF"` (IDL4 construct, not supported by this version). The
gap is recorded here; a newer `rtiddsgen` can add that capture.

**C_Union capture (232 octets, inflates to 608 octets, 2026-06-11)**:
```lisp
(1 0 0 0 96 2 0 0 219 0 0 0 120 218 99 172 231 96 0 1 19 38 6 6 38 48 139 133 65 12 72 50 2 197 57
 129 244 5 40 27 4 100 64 108 176 44 3 131 157 71 4 51 115 185 137 34 72 198 57 62 52 47 51 63 15
 172 142 17 108 2 4 128 248 41 104 252 84 32 93 193 0 177 11 102 174 8 216 92 8 96 5 66 102 32 157
 153 194 128 97 30 83 61 66 143 2 204 76 32 22 133 178 253 237 184 230 77 58 187 44 16 100 118 41
 3 118 253 48 12 18 21 133 170 225 2 210 6 140 232 102 139 162 152 9 82 19 156 159 155 10 241 41 3
 78 191 62 1 98 102 6 76 119 194 252 198 7 164 83 50 139 147 139 50 115 51 243 18 75 242 139 240
 152 133 205 223 34 72 254 6 153 7 242 107 34 30 51 56 144 194 22 155 57 32 253 92 64 8 162 147
 136 48 135 17 45 28 97 234 5 128 88 12 170 7 150 54 64 242 0 101 206 48 253 0)
```
- `type-object-strings`: `("C_Union" "SomeUnion" "discriminator" ...)` — the union type name and
  the discriminator member surface as strings (the opaque hash tokens `">HX"` / `"w4!"` are
  internal fingerprints, not type names).
- **Member walk** (tokenized member-list):
  - `id`: `+8` u16 kind = **0x05 (5)** = RTI `long` → TK_INT32 (as expected).
  - `u` (the union member): `+8` u16 kind = **0x15 (21)**. This is the UNION member-kind word.
    It is ABSENT from `*lto-primitive-kind-keyword*` (range 1–0x0C); `%lto-member-type-identifier`
    returns NIL; `%lto-member-has-kind-p` is T → the **degrading policy** fires → the whole
    `parse-legacy-type-object` returns `:unsupported` (fail-open). No collision with any mapped
    kind (0x12 sequence / 0x13 string / 0x16 nested struct).

**C_Array capture (200 octets, inflates to 416 octets, 2026-06-11)**:
```lisp
(1 0 0 0 160 1 0 0 185 0 0 0 120 218 99 172 231 96 0 129 18 70 6 6 38 48 139 133 65 12 72 50 2 197
 57 129 244 5 40 27 4 100 64 108 176 44 3 131 80 130 235 165 205 237 21 9 32 25 231 120 199 162 162
 196 74 176 58 70 176 9 16 0 226 167 160 241 83 129 116 5 3 196 46 152 185 34 96 115 33 128 21 8
 153 129 116 102 10 3 134 121 76 245 8 61 10 48 51 129 88 16 202 142 62 203 46 106 245 234 154 49
 72 125 98 81 17 86 253 48 12 18 21 132 186 1 100 95 1 146 123 84 192 238 19 68 49 147 15 98 102
 98 101 188 73 188 103 94 137 177 17 3 3 94 255 130 252 145 10 149 1 137 159 0 210 28 80 247 178
 32 185 5 102 134 0 16 139 65 205 129 133 45 72 30 0 170 113 41 112 0 0 0)
```
- `type-object-strings`: `("C_Array" "arr" "array_4_Int32")` — the array member name and RTI's
  internal array-type token `array_4_Int32` (confirming `long arr[4]`).
- **Member walk** (tokenized member-list):
  - `id`: `+8` u16 kind = **0x05 (5)** = RTI `long` → TK_INT32 (as expected).
  - `arr` (the array member): `+8` u16 kind = **0x11 (17)**. This is the ARRAY member-kind word.
    It is ABSENT from `*lto-primitive-kind-keyword*` (range 1–0x0C); `%lto-member-type-identifier`
    returns NIL; `%lto-member-has-kind-p` is T → **degrading policy** fires → `:unsupported`
    (fail-open). No collision with any mapped kind.

**Kind table for this task (all at member node VALUE-START+8, little-endian u16)**:
| Construct | Member-kind u16 | Hex | In primitive map? | In any mapped kind? | Result |
|-----------|----------------|-----|-------------------|---------------------|--------|
| enum      | 14             | 0x0E| no                | no                  | :unsupported |
| union     | 21             | 0x15| no                | no                  | :unsupported |
| array     | 17             | 0x11| no                | no                  | :unsupported |
| bitmask   | (not captured — rtiddsgen 4.3.1 rejects `bitmask`)| —  | —  | — | gap |

**No guard needed in `%lto-member-type-identifier`**: none of these kind values collide with any
mapped kind (0x12 sequence, 0x13 string, 0x16 nested struct, 0x01–0x0C primitives). The Task-4.1
policy flip in `%lto-parse-struct-node` (`%lto-member-has-kind-p` present but `%lto-member-type-identifier`
NIL → `:unsupported`) already handles all three correctly without any new code.

**Degrading tier complete** (2026-06-11): every non-{primitive,string,sequence,struct} construct
(enum 0x0E, union 0x15, array 0x11, bitmask — not capturable) fails open to `:unsupported`, so
the Stage-5 gate falls open to name-match and never sees a partial model with a NIL-TI member.

- **Corpus artifacts (C_Union, C_Array)**: only the `Corpus.idl` + `corpus_pub.cxx` source edits
  are tracked; all `rtiddsgen` output, `corpus_pub`, and the symlinked RTI dylibs stay git-ignored
  (NFR-IP).

### C_Array legacy array def-node — structural array decode (Task 1.3 / FR-TYPE-4 S1, 2026-06-12)

Method: clean-room differential over the SAME locked C_Array capture (200-octet LB, 416-octet
inflated), meanings ONLY from captured bytes — the tokenized tree was dumped (each node's
tag/code/[value-start,value-end) + leading value bytes) and read directly; no RTI source / GPL
dissector. This RE flips array OUT of the Task-4.1/4.2 degrade tier into a real plain-array
TypeIdentifier (element TI + single fixed dimension), mirroring the enum stage's def-node pattern.

- **Array member `arr`** (member-list CODE-0 child node `[188..220)`):
  bytes `00000000 | 01000000 | 1100 0000 | 00000000 | 5BCD0715 3AEAD633 | 04000000 | 61727200`.
  `+0` key=0, `+4` id=1, `+8` u16 kind = **0x11 (17)** = array (already pinned in Task 4.2), `+16`
  8-octet type-hash `5B CD 07 15 3A EA D6 33` — the SAME hash@+16 reference mechanism strings
  (0x13/CODE-8), sequences (0x12/CODE-7), nested structs (0x16/CODE-9) and enums (0x0E/CODE-5) use.
- **Array-def node = CODE 3** (`+lto-code-array-def+`), node `[268..380)`. Its CODE-0 child `[280..316)`
  (name="array_4_Int32", RTI's internal array-type token) echoes the member's hash at its
  `VALUE-START+8`: `5B CD 07 15 3A EA D6 33` — byte-identical to the member's `+16` hash. So
  `%lto-find-def-node octets root member-node 3` resolves it by the shared hash-reference pattern.
  CODE 3 is the unique node whose CODE-0 child carries this hash; no other tier (string-def 8 /
  sequence-def 7 / enum-def 5 / struct-def 9) carries it.
- **Element-kind child = CODE 100** (`+lto-code-array-element+`), child `[344..348)` = `05 00 05 00`
  → u16@+0 = **0x05 = RTI `long` → i32 / TK_INT32** (repeated at +2, same as the sequence element-kind
  child). Mapped via `*lto-primitive-kind-keyword*` (5 → `:i32`). Element-of-non-primitive (a kind
  absent from that table) yields NIL → member unmodelable → whole parse degrades (fail-open). CODE
  value 100 coincides with the sequence element-type child and the enum bit-bound child; all three
  are disambiguated by the PARENT code (array-def 3 vs sequence-def 7 vs enum-def 5).
- **Dimension child = CODE 200** (`+lto-code-array-dims+`), child `[368..376)`, 8 bytes:
  `01 00 00 00  04 00 00 00` → `count:u32 = 1`, then `dim[0]:u32 = 4`. Layout: a dimension COUNT
  followed by COUNT u32 bounds. For `long arr[4]` (1-D, size 4): count=1, dim[0]=4 — matching the
  `Corpus.idl` ground truth. **Multi-dim detection/rejection**: the decoder requires count = 1 AND
  the child extent exactly 8 octets (4 count + 4 single bound); a count ≠ 1 (or a longer extent
  carrying additional bounds) is a MULTI-DIM array → NIL → member unmodelable → whole parse degrades
  to `:unsupported` (fail-open — the in-memory model carries a single fixed dimension only; multi-dim
  is a documented decode gap). CODE value 200 coincides with the string/sequence bound child;
  disambiguated by parent code (array-def 3 vs string-def 8 / sequence-def 7).
- **Cross-check**: element = i32 (RTI kind 5), size = 4, dims = [4], ONE dimension — exactly the
  `@final struct C_Array { @key long id; long arr[4]; }` ground truth.
- **Assignability proof** (`run-lto-array-assignability-test`): the parsed C_Array's `arr` member is
  a plain-array TI (i32 × 4). `struct-assignable-from` gates it: a matching local (i32 × 4) is
  assignable both ways; a local with arr[5] (size mismatch — arrays are not resizable, identical
  dimensions required per XTypes 1.3 §7.2.4.4.6 Table 17) or short arr[4] (element kind mismatch) is
  NOT; re-running the compatible case proves no false-reject.
- **Decoded coverage update**: array (0x11) is now **structurally modeled** (no longer in the degrade
  tier). The remaining degrade tier is union (0x15) / bitmask (uncaptured) / map / typedef +
  sequence/array-of-aggregate — still `:unsupported` (fail-open). Multi-dim array + array-of-aggregate
  + array-of-string are recorded fail-open residue (the in-memory model is single-dimension,
  primitive-element only).
- **Corpus artifacts**: unchanged from the Task-4.2 entry — no new capture taken; this RE re-reads
  the existing C_Array bytes. `rtiddsgen` output + RTI dylibs stay git-ignored (NFR-IP).

### C_Union legacy union def-node — structural union decode (Task 2.3 / FR-TYPE-4 S2, 2026-06-12)

Method: clean-room differential over the SAME locked C_Union capture (232-octet LB, 608-octet
inflated), meanings ONLY from captured bytes — the tokenized tree was dumped (each node's
tag/code/[value-start,value-end) + leading value bytes) and read directly; no RTI source / GPL
dissector. This RE flips union OUT of the Task-4.1/4.2 degrade tier into a real EK_MINIMAL union
TypeIdentifier (discriminator TI + per-case members), mirroring the enum/array def-node pattern.
Ground truth: `union SomeUnion switch(long) { case 0: long a; case 1: double b; };` embedded as
member `u` in `@final struct C_Union { @key long id; SomeUnion u; }`.

- **Union member `u`** (member-list CODE-0 child node `[188..220)`):
  bytes `00000000 | 01000000 | 1500 0000 | 00000000 | 4F3E0A9E 92CDA651 | 02000000 | 75000000`.
  `+0` key=0, `+4` id=1, `+8` u16 kind = **0x15 (21)** = union (already pinned in Task 4.2), `+16`
  8-octet type-hash `4F 3E 0A 9E 92 CD A6 51` — the SAME hash@+16 reference mechanism strings
  (0x13/CODE-8), sequences (0x12/CODE-7), nested structs (0x16/CODE-9), enums (0x0E/CODE-5) and
  arrays (0x11/CODE-3) use.
- **Union-def node = CODE 10** (`+lto-code-union-def+`), node `[268..572)`. Its CODE-0 child `[280..312)`
  (name="SomeUnion") echoes the member's hash at its `VALUE-START+8`: `4F 3E 0A 9E 92 CD A6 51` —
  byte-identical to the member's `+16` hash. So `%lto-find-def-node octets root member-node 10`
  resolves it by the shared hash-reference pattern; CODE 10 is the unique node whose CODE-0 child
  carries this hash (no other def tier carries it).
- **Cases container = CODE 100** (`+lto-code-union-cases+`), child `[340..568)`. Its `VALUE-START+0`
  u32 = **3** — the entry count: the discriminator PLUS the two members. Its CHILDREN, in order, are
  the entries, each a named CODE-0 LONG node IMMEDIATELY FOLLOWED by a CODE-100 label-list LONG node:
  - **discriminator** CODE-0 `[356..388)` (name="discriminator"): `+8` u16 kind = `05 00` = **0x05 =
    RTI `long` → i32 / TK_INT32** (mapped via `*lto-primitive-kind-keyword*`). Its following CODE-100
    label list `[416..420)` is 4 octets = `00 00 00 00` → label-count **0** (the discriminator has no
    case labels — the signal that this entry IS the discriminator, not a member).
  - **member `a`** CODE-0 `[436..456)` (name="a"): `+4` id=1, `+8` u16 kind = `05 00` = **0x05 = i32**.
    Its following CODE-100 label list `[484..492)` is 8 octets = `01 00 00 00  00 00 00 00` →
    label-count **1**, label[0]:i32 = **0** → `case 0: long a` ✓.
  - **member `b`** CODE-0 `[508..528)` (name="b"): `+4` id=2, `+8` u16 kind = `0A 00` = **0x0A = RTI
    `double` → f64 / TK_FLOAT64**. Its following CODE-100 label list `[556..564)` is 8 octets =
    `01 00 00 00  01 00 00 00` → label-count **1**, label[0]:i32 = **1** → `case 1: double b` ✓.
- **Member NAME matching**: the union-def stores the member NAMES ("a", "b") length-prefixed +
  NUL-padded in each CODE-0 entry (the same string framing `%lto-read-name` decodes), so
  `make-union-member` hashes both the wire model's and a locally-built model's member names
  identically (the NameHash IS the union-member identity — no false reject on name).
- **CODE 100 disambiguation**: CODE value 100 is REUSED — it is both the union cases CONTAINER and
  each entry's label-list child, AND coincides with the sequence/array element-type child and the
  enum bit-bound child. All are disambiguated by the PARENT code (union-def 10 vs sequence-def 7 /
  array-def 3 / enum-def 5); the union decoder reads CODE-100 nodes only via the resolved union-def
  node, so there is no collision.
- **Cross-check**: discriminator = i32 (RTI kind 5); case 0 → member "a" type i32 (RTI kind 5),
  label {0}; case 1 → member "b" type f64 (RTI kind 0x0A), label {1} — exactly the `union SomeUnion
  switch(long) { case 0: long a; case 1: double b; }` ground truth.
- **Assignability proof** (`run-lto-union-assignability-test`): the parsed C_Union's `u` member is an
  EK_MINIMAL union TI (disc i32; {0}→a i32; {1}→b f64). `struct-assignable-from` gates it through
  `union-assignable-from` (§7.2.4.4.8 Table 19 UNION_TYPE row): a matching local is assignable both
  ways; a local where case 0's member type changes long→double (shared label {0}, member types not
  assignable) is NOT; re-running the compatible case proves no false-reject. NOTE: the union member
  sits in a FINAL struct, so the member-match rule requires STRONG assignability, which requires the
  member type to be DELIMITED. `ti-delimited-p` was extended (this task) to treat a union as delimited
  iff its discriminator AND every member type are delimited — a sound, verifiable condition (a FINAL
  union of delimited members is bounded by discriminator + selected member); this removes the
  false-reject that the conservative "union = NOT delimited" default produced.
- **Fail-open residue (still `:unsupported`, gate falls open to name-match)**: a **default member**
  (`default: …` — no capture, the label encoding is unverified), a **non-primitive discriminator**
  (only `*lto-primitive-kind-keyword*` kinds 1–0x0C decode), a **non-primitive member type** (string /
  nested aggregate / sequence / array case member), and a **multi-label case** (`case 0: case 1: …` —
  label-count ≠ 1, the multi-label encoding is unverified) ALL yield NIL → the union member is
  unmodelable → the whole parse degrades to `:unsupported`. Union gates ONLY where the wire is safely
  modelable (primitive discriminator, single-label primitive-typed cases) — better to fail open than
  to gate on a guessed encoding.
- **Corpus artifacts**: unchanged from the Task-4.2 entry — no new capture taken; this RE re-reads
  the existing C_Union bytes. `rtiddsgen` output + RTI dylibs stay git-ignored (NFR-IP).

### Live legacy-TypeObject type-gating acceptance test (Task 6.1, ADR 0011, 2026-06-11)

- **What was consulted**: live RTI Connext 7.3.1 on the wire only — its SEDP `PID_TYPE_OBJECT_LB`
  (0x8021) and reliable DATA, via `interop/connext/typeobject-corpus/corpus_pub 0 Square C_Shape`
  (which both announces the legacy TypeObject and writes C_Shape samples). The test observes
  Connext's wire behaviour and our own gate's verdict; **no RTI source, header, or `rtiddsgen`
  output was read or copied** to build or interpret anything (clean-room, NFR-IP — same posture as
  every earlier corpus experiment).
- **Our side**: the new DCPS-level gated subscriber `dds.shapes:run-gated-subscriber` (`make
  gated-sub`) — the standalone `run-subscriber` is a bare `dds.disc` node with no gate; only a
  DCPS participant installs the FR-TYPE-4 gate (`%install-type-gate`).
- **Result** (verbatim gate verdicts + counts in `interop/connext/typeobject-corpus/README.md` and
  `docs/adr/0011-legacy-typeobject-live-gating.md`): a compatible local `C_Shape` gated
  `:compatible` (matched, 25 samples), an incompatible local (`shapesize` long→`i64`) gated
  `:incompatible` (INCONSISTENT_TOPIC, 0 samples), and the compatible peer was not false-rejected on
  a re-run. No new external dependency was introduced.
- **Artifacts**: `corpus_pub`, `rtiddsgen` output, pcaps, the symlinked RTI dylibs, and the run logs
  remain git-ignored (NFR-IP). Only the harness source (`src/dds-shapes/`, `Makefile`) + docs are
  tracked.

## M4 (2026-06-11) — Fast DDS 3.6.1 test-peer toolchain (FR-IO-2)

A pinned Fast DDS toolchain built from source **outside this repo** to serve as the second
interop peer for FR-IO-2 (confirms TypeLookup `CONFIRM_VS_PEER` + provisional EquivalenceHash
against a non-Connext implementation). This is a **test peer only** — it is **not** a code
dependency of the shipped systems and receives **no SBOM entry**; provenance is recorded here
per the clean-room and IP rules (the operating contract §4, §5.2).

### Toolchain location

Outside this repository, as a sibling project of the repo's parent
`projects/` directory (`projects/fastdds/`) — `src/` holds the clones,
`install/` is the shared CMake install prefix (`$FASTDDS_PREFIX`,
overridable). The env helper
`scripts/with-fastdds.sh` (mode 755) sets `FASTDDS_PREFIX`, `FASTDDSGEN`, and
`DYLD_LIBRARY_PATH` for any command run against this peer.

### Repository pins

| Repository | Tag | Commit |
|---|---|---|
| https://github.com/eProsima/Fast-DDS | v3.6.1 | 4e81e8b71bcd6e7c5213c000503cba8e49d6022a |
| https://github.com/eProsima/Fast-CDR | v2.3.5 | 7d33a3b51a1585f5631b0a8d905bcc4f249d0f34 |
| https://github.com/eProsima/foonathan_memory_vendor | v1.4.1 | 347cb67581e51273a612780eb256a3c134c10bae |
| https://github.com/eProsima/Fast-DDS-Gen | v4.3.0 | cc0072b8849b35c67bd7e187990efad58e2871ae |

Fast-CDR and foonathan_memory_vendor tags taken from the Fast-DDS v3.6.1
`fastdds.repos` manifest. Fast-DDS-Gen v4.3.0 selected per the eProsima
versions compatibility table (see docs consulted below). All four repositories
are **Apache-2.0**.

### Build configuration

- CMake 4.3.3, build type Release, `BUILD_SHARED_LIBS=ON`, single shared
  install prefix (`fastdds/install/`).
- Brew packages installed for the build (host macOS arm64):
  - `openjdk` 26.0.1 — Fast-DDS-Gen JVM (NOT symlinked into `/Library`; used
    via `PATH=/opt/homebrew/opt/openjdk/bin`).
  - `asio` 1.36.0 — header-only async I/O.
  - `tinyxml2` 11.0.0 — XML parsing.
  - `openssl@3` 3.6.2 — TLS/crypto support.

### Docs consulted

- https://fast-dds.docs.eprosima.com/en/stable/installation/sources/sources_mac.html —
  macOS source-build instructions.
- https://fast-dds.docs.eprosima.com/en/stable/notes/versions.html — versions
  compatibility table (used to select the matching Fast-DDS-Gen v4.3.0 tag).

### Clean-room note

eProsima sources and examples **may be consulted read-only** for harness API
usage (FR-IO-2 peer apps); **no eProsima source is copied into `src/`**. No
RTI source or headers were consulted. The GPL Wireshark RTPS dissector source
was not used (only the binary dissector, as before).

## M4 (2026-06-11) — Fast DDS shapes harness (`interop/fastdds/`, FR-IO-2 S0)

The harness apps (`shapes_pub.cpp`, `shapes_sub.cpp`, `profiles.xml`, Makefiles) were
**written fresh** against the installed public headers; eProsima sources were consulted
**read-only** to reconcile 3.x API drift, per the clean-room note above. Files consulted
(all Apache-2.0, in the pinned Fast-DDS v3.6.1 tree):

- `examples/cpp/hello_world/PublisherApp.cpp` + the `hello_world/` file listing —
  3.x entity-creation idioms (`create_participant_with_default_profile`, `TypeSupport`,
  `RETCODE_OK`, listener signatures).
- `examples/cpp/hello_world/hello_world_profile.xml` — profile XML shape.
- `share/fastdds/fastdds_profiles.xsd` (installed) — element names for
  `transport_descriptors`/`interfaceWhiteList`/`propertiesPolicy`; confirmed the 2.x
  `<typelookup_config>` element no longer exists.
- `src/cpp/rtps/builtin/BuiltinProtocols.cpp`, `src/cpp/fastdds/utils/TypePropagation.cpp`,
  `include/fastdds/dds/core/policy/ParameterTypes.hpp`, `src/cpp/xmlparser/XMLParser.cpp`,
  `src/cpp/xmlparser/XMLParserCommon.cpp` — how TypeLookup client+server are enabled in
  3.x (participant property `fastdds.type_propagation`, default `enabled`).
- Installed headers `fastdds/dds/domain/DomainParticipantFactory.hpp`,
  `fastdds/dds/core/policy/QosPolicies.hpp` — API signature verification.

The `fastddsgen` 4.3.0 output under `interop/fastdds/shapes/gen/` is **committed
verbatim** (Apache-2.0 generator output, header notice retained) so the harness builds
without a JDK. No RTI source/headers/generated code was consulted or copied.

## M4 (2026-06-12) — Fast DDS type_probe harness + leg-B diagnosis (`interop/fastdds/type_probe/`, FR-IO-2 S4 leg B)

`type_probe.cpp` was **written fresh** against the installed public headers, following
the remote-type-discovery workflow shown in eProsima's public example; eProsima sources
were consulted **read-only** (Apache-2.0, pinned Fast-DDS v3.6.1 tree), per the
clean-room note above. Files consulted:

- `examples/cpp/xtypes/SubscriberApp.{cpp,hpp}` — the remote type discovery + DynamicType
  workflow pattern (`on_data_writer_discovery` → `type_object_registry().get_type_object`
  → `create_type_w_type_object` → `DynamicPubSubType(type, type_information)`).
- Installed headers `fastdds/dds/domain/DomainParticipantListener.hpp`,
  `fastdds/dds/xtypes/dynamic_types/DynamicPubSubType.hpp`,
  `fastdds/dds/xtypes/type_representation/ITypeObjectRegistry.hpp`,
  `fastdds/dds/xtypes/utils.hpp` (json_serialize), `fastdds/dds/log/Log.hpp`,
  `fastdds/dds/builtin/topic/PublicationBuiltinTopicData.hpp`,
  `fastdds/rtps/builtin/data/PublicationBuiltinTopicData.hpp`,
  `fastdds/dds/core/policy/QosPolicies.hpp` (TypeInformationParameter) — signature
  reconciliation.
- `src/cpp/fastdds/builtin/type_lookup_service/TypeLookupManager.{hpp,cpp}` and
  `TypeLookupReplyListener.cpp` — their client's getTypeDependencies→getTypes flow
  (read to verify our server answers both operations).
- `src/cpp/rtps/builtin/data/WriterProxyData.cpp` + `ReaderProxyData.cpp` — the leg-B
  finding: `PID_TYPE_INFORMATION` is ignored for non-eProsima vendorIds.
- `src/cpp/rtps/builtin/discovery/participant/{PDP.cpp,PDPSimple.cpp,PDPListener.cpp}`,
  `src/cpp/fastdds/domain/{DomainParticipantFactory.cpp,DomainParticipantImpl.cpp}` —
  read during the wire-first diagnosis of the (ultimately environmental, macOS
  firewall) discovery failure; no code copied.

No eProsima code was copied into the harness or `src/`; no RTI material was consulted.

## M4 (2026-06-12) — Fast DDS vendor-gate NON-STOCK diagnostic + json_serialize root-cause (FR-IO-2 S4 closeout, ADR 0012)

Two further read-only consultations of the pinned Fast-DDS v3.6.1 tree (Apache-2.0),
per the clean-room note above; nothing copied into the harness or `src/`:

- `src/cpp/rtps/builtin/data/WriterProxyData.cpp` + `ReaderProxyData.cpp` — the
  controller-approved **NON-STOCK diagnostic**: the `PID_TYPE_INFORMATION` vendor-gate
  early-return was neutralized by a one-line `if (false && ...)` edit in a **local
  build only** (the diff is archived as
  `interop/fastdds/captures/s4-theirclient-patched-nonstock.diff`; the modified files
  stayed in the out-of-repo toolchain tree, Apache-2.0 permits the modification, and
  the stock state was restored, rebuilt, and re-proven —
  `captures/s4-theirclient-restored-probe.out`). The repo contains the diff as
  evidence, not as shipped code.
- `src/cpp/fastdds/xtypes/dynamic_types/DynamicTypeBuilderFactoryImpl.cpp` (line 1626,
  `get_string_from_name_hash`) — read to root-cause THEIR per-sample `json_serialize`
  failures (`type_error.316`): raw `NameHash` `uint8_t` bytes streamed through the
  `char` `operator<<` overload yield non-UTF-8 member names from any MINIMAL
  TypeObject. A Fast DDS defect (upstream-reportable), not our framing.

## M4 (2026-06-12) — no-key endpoint-kinds live Connext interop (keyed/no-key feature, RTPS 2.5 §9.3.1.2)

Live oracle for the keyed/no-key endpoint-kinds feature against RTI Connext 7.3.1
(`arm64Darwin20clang12.0`, same host; same-host RTPS on `lo0`). Clean-room: our own
keyless `NoKeyData` IDL drives `rtiddsgen` at build time; the generated type support is
git-ignored, never copied into `src/`. No RTI source/headers were consulted.

Wire-confirmed against the OMG DDSI-RTPS 2.5 §9.3.1.2 Table 9.1 entity kinds
(the resolved loopback captures `captures/nokey-{fwd,rev}-loopback-lo0.pcap` via the
tshark RTPS dissector):

- our NO_KEY **reader** endpoint GUID ends `0x04` (NO_KEY reader);
- our NO_KEY **writer** endpoint GUID ends `0x03` (NO_KEY writer);
- both announce topic `NoKeyTopic` / type `nokey-data` correctly.

**Live interop ACHIEVED both directions (2026-06-12, loopback on `lo0`;
`captures/nokey-{fwd,rev}-loopback-*`):** forward Connext `nokey_pub` -> our `nokey-sub`
`MATCHED 1`, received 147/150; reverse our `nokey-pub` -> Connext `nokey_sub` our pub
`matched=1`, Connext received 159/160 (the head-of-stream sample(s) pre-date the match
under VOLATILE — expected). Connext's `CONNEXT_VERBOSE=1` log confirms it matches our
NO_KEY writer EntityId `0x00000103` against its NO_KEY reader (`0x80000004`) "with reliable
reader service", logging `Remote unkeyed user datawriter … matched with local unkeyed user
datareader` and `TypeObject not received (topic: 'NoKeyTopic', type: 'nokey-data')` — a
topic+type-name match, no XTypes assignability required.

Earlier same-host failure — RESOLVED, NOT a NO_KEY defect. The first run's `matched=0`
("Connext never advances past SPDP for our `4742…` prefix") was an environment artifact:
(1) a stale keyed `shapes_pub` held discovery port `7410` (and a stale `sbcl` held
`7400`), forcing Connext's `nokey_pub` to participant index 1 (`7412`) so our unicast SPDP
to `7410` missed it and the two Connext instances discovered each other
(`FAILED TO BIND | Invalid port 7410`; `Discovered new remote participant 0x0101DCD1,…`, a
Connext prefix, never our `4742…`); (2) the macOS LAN-UDP application-firewall would
independently drop LAN-sourced UDP to the freshly built unapproved `nokey_pub`/`nokey_sub`
(the same gate the Fast DDS leg B hit). After killing the stale processes and running
loopback-only (`allow_interfaces=127.0.0.1`) with unicast SPDP (`PEERS=127.0.0.1:7410`),
both legs matched. Harness/environment fix only: a `:peers` unicast-SPDP passthrough was
threaded into the DCPS path (`dds.dcps:create-participant :peers`,
`dds.shapes:run-nokey-{publisher,subscriber} :peers`, Makefile `PEERS=`) and the profile
pinned to `127.0.0.1`. No change to the NO_KEY mechanism; suite stays 106 green
(`make test-sbcl`). See `interop/connext/nokey/README.md`.

## M4 (2026-06-12) — liveliness / participant-lease-expiry live test (FR-DCPS S0/S1)

- **What was consulted**: live RTI Connext 7.3.1 on the wire only — its SPDP/participant
  liveliness behaviour and reliable C_Shape DATA, via
  `interop/connext/typeobject-corpus/corpus_pub 0 Square C_Shape` (the proven 2026-06-11
  legacy-gate match peer) plus a raw `lo0` packet capture of a lone Connext participant.
  **No RTI source, header, or `rtiddsgen` output was read or copied** (clean-room, NFR-IP).
- **Participant-lease prune — live PASS.** Our DCPS gated subscriber (`make gated-sub`)
  matched the live Connext writer (`MATCHED 0 -> 1`, gate verdict `:compatible`, 26 C_Shape
  samples received); after `kill`-ing `corpus_pub`, our `%lease-sweep` (RTPS §8.5.3.3.2)
  found the participant stale past its announced `leaseDuration` (shortened to 12 s for the
  run), purged it, and the DCPS unmatch hook decremented `SUBSCRIPTION_MATCHED`:
  `MATCHED 1 -> 0 (remote pruned — participant lease expired)`; final `matched=0`,
  `INCONSISTENT_TOPIC total=0`. This is the FR-DCPS S0 deliverable confirmed against a real
  Connext peer (offline tests use synthetic disc-nodes).
- **Finding — RTI proprietary `NDDSPING`, not standard `ParticipantMessageData`.** A raw
  capture of a lone Connext participant shows its participant-liveliness frames carry the
  RTPS magic + the literal `NDDSPING` (`52 54 50 53 02 05 01 01 4e 44 44 53 50 49 4e 47`),
  RTI's vendor ping — **not** the standard RTPS §8.4.13 `ParticipantMessageData` on
  `0x000200c2`. Mirrors ADR 0009 (RTI emits `PID_TYPE_OBJECT_LB 0x8021`, not
  `PID_TYPE_INFORMATION 0x0075`): default RTI↔RTI discovery uses the vendor artifact. Our
  stack implements the **standard** WLP mechanism (the conformant default a non-RTI peer
  expects), so the live **byte-validation** of `ParticipantMessageData` is deferred to the
  Fast DDS leg (FR-IO-2), not this RTI run. RTI still accepts the standard
  `ParticipantMessageData` (spec-mandated), so emitting it toward Connext is safe.
- **Tooling note**: the bundled `tshark` did not dissect the `lo0` capture in this shell
  (`Protocols in frame:` empty, sandboxed and un-sandboxed); the RTPS/`NDDSPING` ID is from
  the raw `capinfos`/hexdump bytes. Re-dissect in the Wireshark GUI for frame-level detail.
- **Artifacts**: `corpus_pub`/`rtiddsgen` output, the symlinked RTI dylibs, the `.pcap`, and
  the run logs remain git-ignored (NFR-IP). Tracked: the harness change
  (`src/dds-shapes/shapes.lisp` gated-sub MATCHED-transition logging) +
  `interop/connext/liveliness/{USER_QOS_PROFILES.xml,README.md}` + docs.

## M4 (2026-06-12) — standard ParticipantMessageData byte-validation vs Fast DDS (FR-IO-2 / FR-RTPS-WLP)

- **What was consulted**: live eProsima Fast DDS 3.6.1 (the CONFORMANT peer) on the wire only —
  its BuiltinParticipantMessageWriter (EntityId 0x000200c2) DATA submessage carrying the standard
  RTPS §8.4.13.4 / §9.6.3.2 `ParticipantMessageData`. **No Fast DDS source was copied** (clean-room,
  NFR-IP); the harness builds against the public API.
- **Why this leg exists**: live RTI Connext emits the proprietary `NDDSPING` for participant
  liveliness, NOT the standard `ParticipantMessageData` (see the 2026-06-12 liveliness entry), so the
  standard-message byte-validation was deferred to a conformant peer. Fast DDS implements the standard.
- **Mechanism finding**: a Fast DDS participant with only DDS-default liveliness (AUTOMATIC, INFINITE
  lease) sets up the WLP reliable channel (HEARTBEAT/ACKNACK on 0x000200c2) but **writes NO
  ParticipantMessageData sample** (empty writer history). Emission requires a writer with a FINITE
  liveliness lease that actually asserts — added env-gated to the harness (`WLP_LEASE_MS`, off by
  default; `interop/fastdds/shapes/shapes_pub.cpp`). With `WLP_LEASE_MS=1000` the WLP writer emitted
  68 DATA(ParticipantMessageData) submessages over ~10 s. This mirrors our own design (we assert only
  when a local writer's LIVELINESS requires it).
- **Byte-exact result** (`interop/fastdds/captures/wlp-participant-message-lo0.pcap` frame 89,
  AUTOMATIC assertion): the SerializedPayload is `00 01 00 00` (PLAIN_CDR_LE encapsulation, options 0)
  + `01 0f 3a f1 63 67 ed 4d 00 00 00 00` (guidPrefix) + `00 00 00 01` (kind octet[4] = AUTOMATIC) +
  `00 00 00 00` (sequenceSize = 0). Our `serialize-participant-message` reproduces the 20-octet bare
  struct BYTE-EXACT, and `parse-participant-message` decodes Fast DDS's bytes (kind=AUTOMATIC, empty
  data, prefix recovered). Locked as the regression test `fastdds-participant-message`
  (`src/dds-tests/rtps-test.lisp`, mirroring the `rtps-participant-message` self-vector pattern).
  117 green SBCL+Clasp. The kind being `octet[4]` (§9.6.3.2) is endianness-independent, confirmed by
  the wire `00 00 00 01` matching our big-endian-stored {0,0,0,1}.
- **Capture tooling note**: this host's Wireshark profile disables the null/ip/udp dissectors
  (`disabled_protos`); `--enable-protocol` is unreliable in this shell. The robust fix is a clean
  profile: `WIRESHARK_CONFIG_DIR=/tmp/wscfg tshark -r f.pcap -Y rtps ...`. Loopback-only on lo0.
- **Artifacts**: the harness change (env-gated `WLP_LEASE_MS` liveliness in `shapes_pub.cpp`) + the
  committed pcap (`interop/fastdds/captures/wlp-participant-message-lo0.pcap`, the captures/ exception)
  + the regression test + docs are tracked; the RTI/Fast DDS dylibs + build output remain git-ignored.

## M4 (2026-06-12) — reverse WLP: Fast DDS ACCEPTS our ParticipantMessageData + PID_LIVELINESS in SEDP (FR-IO-2 / FR-RTPS-WLP)

- **What was consulted**: live eProsima Fast DDS 3.6.1 (the conformant peer) on the wire + via its
  public DataReaderListener API (`on_liveliness_changed`). **No Fast DDS source copied** (clean-room).
- **Conformance addition (prerequisite)**: our SEDP did not advertise writers' LIVELINESS QoS, so no
  peer could RxO-match or track our liveliness. Added `PID_LIVELINESS` (0x001b) emit+parse
  (`serialize-/parse-endpoint-data`, `src/dds-rtps/discovery.lisp`): the 12-octet
  `{ kind:u32 LE (= dds.qos:liveliness-rank, AUTOMATIC=0/MANUAL_BY_PARTICIPANT=1/MANUAL_BY_TOPIC=2),
  lease_duration Duration_t{sec,nanosec} u32 LE }`. ParameterId 0x001b pinned from
  `docs/specs/xtypes-1_3-discovery-builtin-topic.idl:218` (`@id(0x001B) LivelinessQosPolicy`) + the
  DDS PSM LivelinessQosPolicyKind. Byte-exact vs the Fast DDS oracle (frame 67: AUTOMATIC+1s =
  `1b 00 0c 00 00 00 00 00 01 00 00 00 00 00 00 00`); locked test `pid-liveliness`. Inbound unknown
  kind / length≠12 fail open (never reject). RxO non-regression verified: default writer offers
  AUTOMATIC+infinite, default reader requests same → still compatible (no existing match broke).
- **Live strong proof — MANUAL_BY_PARTICIPANT** (`interop/fastdds/captures/reverse-wlp-manual-lo0.pcap`):
  our `run-publisher` offers MANUAL_BY_PARTICIPANT + 5 s lease and asserts on the ~1.5 s announce
  cadence; Fast DDS `shapes_sub` requests MANUAL_BY_PARTICIPANT + 10 s. Fast DDS RxO-matched on our
  advertised PID_LIVELINESS (`matched total: 1`) and reported `LIVELINESS_CHANGED alive=1 (1)`. We
  emitted 15 `ParticipantMessageData` DATA on writer 0x000200c2 from our prefix `47425030…`, kind
  `MANUAL_LIVELINESS_UPDATE (0x00000002)` (Wireshark dissects our bytes cleanly). On killing our
  publisher Fast DDS fired `LIVELINESS_CHANGED alive=0 (-1) not_alive=1 (1)`. Because MANUAL liveliness
  is NOT kept alive by SPDP alone, the ALIVE state proves Fast DDS received + semantically acted on our
  MANUAL `ParticipantMessageData`; the not_alive on cessation confirms it.
- **Live baseline — AUTOMATIC** (`interop/fastdds/captures/reverse-wlp-automatic-lo0.pcap`): our pub
  offers AUTOMATIC + 5 s; Fast DDS sub requests AUTOMATIC + 10 s; matched + `LIVELINESS_CHANGED
  alive=1 (1)`, our emitted PM kind `AUTOMATIC_LIVELINESS_UPDATE (0x00000001)`.
- **Harness**: env-gated reader liveliness on Fast DDS `shapes_sub` (`SUB_LIVELINESS_LEASE_MS` +
  `SUB_LIVELINESS_KIND`, off by default) + `on_liveliness_changed` logging; `run-publisher`
  `:liveliness`/`:liveliness-lease-seconds` (Makefile `LIVELINESS=`/`LEASE=`). Loopback lo0, unicast
  SPDP `PEERS=127.0.0.1:7410`, `WIRESHARK_CONFIG_DIR=/tmp/wscfg` for reliable dissection.
- **Artifacts**: both pcaps committed (captures/ exception); the Lisp + C++ harness changes + the
  locked `pid-liveliness` test + docs tracked. 118 green SBCL+Clasp; gate-types+gate-hotpath green.

## M4 (2026-06-13) — REGRESSION FIX: RTPS Duration_t wire fraction in PID_LIVELINESS (FR-RTPS-WLP)

- **Regression**: the reverse-WLP feature (commit 930cabb) began emitting PID_LIVELINESS lease_duration
  but wrote the DCPS Duration_t **nanosec** field directly into the RTPS-wire Duration_t **fraction**
  field. The DCPS PSM Duration_t carries nanoseconds (dds_rtf2_dcps.idl DURATION_INFINITE_NSEC =
  0x7fffffff); the RTPS-wire Duration_t carries a fraction in units of sec/2^32 with DURATION_INFINITE
  {seconds 0x7fffffff, fraction 0xffffffff} (DDSI-RTPS 2.5 §9.3.2 / §8.3.5.5 struct Duration_t).
  Emitting raw nanosec made our default reader's INFINITE requested lease read as a FINITE ~0.5 s on a
  conformant peer → an INFINITE-offered writer failed RxO (offered_infinite <= requested_finite is
  FALSE) → **Fast DDS refused to match our reader and sent no user DATA** (forward Fast DDS interop
  silently broke; integer-second leases were unaffected because fraction=nanosec=0, which is why the
  original byte-validation and the reverse direction missed it).
- **Wire oracle confirmation**: a live Fast DDS 1.5 s lease emits `seconds 1, fraction 0x80000000`
  (= 0.5 x 2^32), proving QoS Duration_t on the wire is {seconds, fraction(2^-32)}, NOT nanosec
  (`/tmp/lifecycle/subsec.pcap` frame 63). Our fixed codec reproduces it byte-exact: nanosec
  500000000 -> fraction 0x80000000; infinite 0x7fffffff -> 0xffffffff; both round-trip.
- **Fix**: `dds.qos:duration-nanosec->wire-fraction` / `wire-fraction->duration-nanosec` (qos.lisp,
  exported) do the boundary conversion incl. the infinite sentinel; serialize-/parse-endpoint-data
  (PID_LIVELINESS) use them. Test `pid-liveliness` extended for the infinite + sub-second cases.
- **Verified live**: forward Fast DDS leg now matches (`matched change: 1`) and our subscriber receives
  BLUE Square samples; the reverse direction (our pub -> Fast DDS sub) still works. 129 green
  SBCL+Clasp. Connext was lenient (matched by name despite the bad value, NDDSPING not standard WLP),
  so this is a straight conformance fix improving correctness toward all peers; the exported helpers
  are reused when PID_DEADLINE/PID_LATENCY_BUDGET/lifespan land (any wire Duration_t needs them).

## M4 (2026-06-13) — instance lifecycle LIVE both directions vs Fast DDS (instance lifecycle S3)

- **What was consulted**: live eProsima Fast DDS 3.6.1 on the wire + via its public DataReader API
  (SampleInfo.instance_state). No Fast DDS source copied (clean-room). Required the Duration_t
  fraction regression fix (32f49a4) to restore forward Fast DDS data flow first.
- **Forward — Fast DDS disposes -> our reader reports NOT_ALIVE_DISPOSED**
  (interop/fastdds/captures/instance-dispose-forward-lo0.pcap): our DCPS gated-sub received 38 BLUE
  ShapeType samples from the live Fast DDS keyed writer, then `INSTANCE_STATE NOT-ALIVE-DISPOSED
  (no data) handle=#(ca c2 17 c3 ...)`. The handle equals the dispose's PID_KEY_HASH AND the instance
  our reader built from the data samples — proving our key-hash computation (RTPS §9.6.4.8) agrees
  with Fast DDS's and our reader resolves the inbound dispose to the right instance.
- **Reverse — our writer disposes -> Fast DDS reader reports NOT_ALIVE_DISPOSED**
  (interop/fastdds/captures/instance-dispose-reverse-lo0.pcap): our publisher (run-publisher
  :dispose-after, the S1 disc dispose path) sent 25 BLUE samples then disposed the instance; Fast DDS
  shapes_sub received 24 samples then logged `INSTANCE_STATE 2` (Fast DDS InstanceStateKind
  NOT_ALIVE_DISPOSED = 0x1<<1) and reliably ACKNACKed our data + dispose (our pub: 38 ACKNACKs). The
  conformant peer semantically consumes + acts on our dispose.
- **Harness**: Fast DDS shapes_pub env DISPOSE_AFTER/UNREGISTER_AFTER (stop+grace); shapes_sub logs
  on_data_available instance_state for invalid-data samples; our run-publisher :dispose-after; our
  gated-sub logs instance_state for invalid-data samples. Loopback lo0, unicast SPDP
  PEERS=127.0.0.1:7410, WIRESHARK_CONFIG_DIR=/tmp/wscfg.
- Unregister is byte-validated offline (S0 vs frame 113) + S2 tests; dispose is the live-tested
  headline (shared wire path, only the StatusInfo U flag differs). 129 green SBCL+Clasp.

## M4 (2026-06-13) — OWNERSHIP EXCLUSIVE live + a multi-writer SN-aliasing data-plane fix (ownership S1/S2)

- **Live EXCLUSIVE arbitration PROVEN** (two same-instance writers, different OWNERSHIP_STRENGTH,
  distinguished by shapesize): two EXCLUSIVE publishers strength 10/shapesize 30 + strength
  20/shapesize 60 (same BLUE instance) -> our `:ownership :exclusive` gated-sub. While both alive:
  the reader delivered ONLY shapesize 60 (the strength-20 owner), zero shapesize 30 (the
  lower-strength writer dropped). After killing the strength-20 owner: the participant was pruned,
  `%clear-owner-on-vanish` cleared the owner, and the strength-10 (shapesize 30) writer reclaimed +
  resumed delivering — DDS 1.4 §2.2.3.9.2 first-owner + takeover confirmed end-to-end. Harness:
  env-gated OWNERSHIP_STRENGTH + SHAPESIZE on the Fast DDS shapes_pub AND the Connext shapes_pub
  (clean-room, public OMG DDS C++ PSM, no RTI source copied); our gated-sub gained `:ownership`;
  Makefile `gated-sub OWNERSHIP=`.
- **Data-plane fix surfaced by the live test — multi-writer SN aliasing.** The reader keyed its user-
  sample store by raw SequenceNumber alone, but an RTPS SN is unique only per writer GUID (RTPS 2.5
  §8.3.5.4); two writers sharing the user-writer EntityId 0x00000102 across participants both start
  at SN 1, colliding in the store so one writer's data was dropped before arbitration. Fixed: the
  reader's sample pipeline is now keyed by the full (source-GUID, SN) — a 2-level GUID->(SN->sample)
  table (no per-sample bignum / NFR-MEM-clean; one %source-guid per sample) — and the DCPS drain's
  exactly-once watermark is per-writer. EXCLUSIVE pre-match samples (source identified but SEDP match
  not yet arrived) are kept PENDING (not watermark-advanced) so they deliver once the match + strength
  are known, never lost. KNOWN FOLLOW-UP (documented, does NOT affect single-writer or EXCLUSIVE data
  delivery): the dispose/unregister lifecycle store + the reliable writer/reader proxy still key by
  SN/EntityId, so two same-EntityId writers still alias in the dispose + ACKNACK/repair paths.
- 133 green SBCL+Clasp; gate-types+gate-hotpath green.

## M5 (2026-06-14) — WP-SHMEM shared-memory intra-host transport (FR-XPORT-2, ADR 0013)

The shared-memory transport is **clean-room from public, non-proprietary sources only** — no DDS
vendor's SHMEM/data-sharing implementation was read or copied.

- **POSIX.1-2017 — the sole external source for the segment + notification primitives.** `shm_open`,
  `ftruncate`, `mmap`/`munmap`, `shm_unlink` (POSIX.1-2017 §3.254, §3.288) for the segment; the
  `pthread_mutexattr_setpshared` / `pthread_condattr_setpshared` `PTHREAD_PROCESS_SHARED` mutex+condvar
  family for the in-segment cross-process notification. All are thin CFFI wrappers in `pal-net.lisp`;
  **no external library dependency** and **no third-party SHMEM code** was consulted. (The named-POSIX-
  semaphore path provisioned in ADR 0013's Decision was dropped — `sem_open` is undrivable from the Lisp
  runtime on macOS arm64 — and the pthread pshared path was used instead.)
- **Each implementation's OWN atomics API** for the M1 fast path: SBCL `sb-ext:cas` / `sb-ext:atomic-incf`
  over `sb-sys:sap-ref-64` and `sb-thread:barrier` for the real `fence`; Clasp `mp:fence` (the Clasp
  foreign-place CAS gap is recorded in ADR 0013). These are documented impl internals, not copied code.
- **The SHMEM segment + ring layout is OURS.** There is **no standard RTPS SHMEM wire format**: RTI and
  Fast DDS each use a different, proprietary segment and a different vendor locator kind, and the OMG
  RTPS spec defines none. The segment layout (header + pshared notify block + K per-sender SPSC
  length-prefixed-record lanes), the conditional-wakeup (parked-flag Dekker StoreLoad) handshake, the
  ABI magic/version guard, and the selection metadata — the SHMEM `Locator_t` kind `0x47420001` and
  `PID_SHMEM_HOST_UUID 0x8040` (host-uuid = low 8 octets of the vendored MD5 of the hostname) — are all
  this project's own design, **pinned in ADR 0013, not taken from any spec clause or vendor artifact**.
  Cross-vendor SHMEM interop is out of scope by construction (a foreign peer sees an unknown locator
  kind and falls back to UDP).
- **No RTI Connext / Fast DDS / Cyclone / OpenDDS source, headers, or generated code** was read or
  copied for this work package. The transport is validated functionally (in-process + a real two-process
  cross-image round-trip), under fuzz (the ring record parser), and by an SBCL-vs-UDP-loopback benchmark
  (`bench/report/2026-06-14-wp-shmem.md`) — none of which involves a vendor artifact.
- 165 tests green SBCL; gate-types + gate-hotpath + fuzz + mem green.

## M5 (2026-06-14) — WP-ZEROCOPY per-writer SHMEM sample-pool (FR-PF-3, ADR 0014)

The per-writer SHMEM sample-pool (`src/dds-xport/zerocopy-pool.lisp`) is **clean-room
from FR-PF-3 + the OMG DDSI-RTPS 2.5 spec only** — no RTI Connext source, headers, or
`rtiddsgen` output was consulted.

- **Sources consulted**: POSIX.1-2017 (the `pshared` mutex primitives, already covered
  under WP-SHMEM, ADR 0013); the operating contract §4 (FR-PF-3 feature requirement);
  the in-repo OMG DDSI-RTPS 2.5 spec (the 16-byte reference payload encoding). No RTI
  Zero-Copy patent / whitepaper / header / source was read.
- **The pool layout, slot lifecycle, and the 16-byte reference format are this project's
  own design.** The SHMEM segment layout (`{header: magic + version + slot-count +
  slot-bytes + free-head + pshared-mutex} + K slots`), each slot's sub-layout
  (`{refcount:u32, generation:u32, len:u32, _pad:u32, pubseq:u64, payload:slot-bytes}`),
  the freelist-over-`len` encoding while free, the generation-bump + force-reclaim
  lifecycle, the `*zc-pubseq*` monotonic ordering for oldest-slot reclaim, and the
  segment-naming convention (from the writer GUID) are not taken from any spec clause or
  vendor artifact. Pinned in ADR 0014; constants are vendor-chosen (not OMG-assigned).
- **NOT cleared for ship — pending counsel (R6).** The operating contract and ADR 0014
  require counsel to perform the authoritative claim clearance before any
  `*zerocopy-enabled*`-on ship. This entry records provenance for that review.
- **No RTI Connext / Fast DDS / Cyclone / OpenDDS source, headers, or generated code**
  was read or copied for this work package.

## M5 (2026-06-15) — WP-FLATDATA FlatData-equivalent fixed-size binding (FR-PF-4, ADR 0015)

The `:flatdata t` codegen (`src/dds-gen/dsl.lisp` — compile-time XCDR2 Offset accessors, the
`make-<name>-flatdata` constructor, identity `serialize` / read-in-place `deserialize`,
`+<name>-flatdata-size+`, the `flatdata-layout`) and the FlatData-over-Zero-Copy single-copy RX
(`src/dds-xport/zerocopy-pool.lisp` `%zc-resolve-fresh`; `src/dds-disc/dataplane.lisp`) are
**clean-room from FR-PF-4 + the OMG XCDR (DDS-XTypes 1.3 / CDR) spec only** — **no RTI Connext
source, headers, or `rtiddsgen` output** was consulted.

- **Sources consulted**: the in-repo OMG DDS-XTypes 1.3 / XCDR spec (the PLAIN_CDR2 fixed-size
  member layout + alignment rules already pinned for the existing serializer; the encap header +
  OPTIONS trailing-pad rule, §7.6.3.1.2); the operating contract §4 (FR-PF-4 + NFR-PERF-7 feature
  requirements). The buffer-equals-SerializedPayload identity, the compile-time constant-offset
  fold, and the Offset-accessor get/`setf` pattern are this project's own design derived from first
  principles and reuse the project's existing `cdr-size-align` / fixed-offset CDR primitives.
- **No Apache-2.0 (Fast DDS) / EPL-EDL (Cyclone) / OpenDDS source was read** for this work
  package — FlatData mirrors RTI's *patented* mechanism (R6), so the design was kept strictly to
  the OMG XCDR layout + the project's own code; no other vendor's FlatData/zero-copy implementation
  was consulted, and no RTI FlatData patent / whitepaper / header / source was read.
- **NOT cleared for ship — pending counsel (R6).** FlatData is opt-in per type (`:flatdata t`); the
  default codegen path is byte-identical to before. Counsel performs the authoritative claim
  clearance before any FlatData type ships; this entry + ADR 0015 record provenance for that review.
- Validated functionally + byte-exact against the engine's own serializer (the in-memory == wire
  oracle), under fuzz (the untrusted-payload wrap, incl. a `(safety 0)` arm), and by an SBCL bench
  (`bench/report/2026-06-14-wp-flatdata.md`) — none of which involves a vendor artifact.

## M5 (2026-06-16) — WP-FLATDATA-ZC-LOAN literal-0-copy RX loan API (FR-PF-3/4, ADR 0017, Phases D–F)

The literal-0-copy FlatData-over-Zero-Copy RX (`src/dds-pal/*` `load-sap-u8/u16/u32`;
`src/dds-gen/dsl.lisp` SAP-mode `<name>-<field>-fd`; `src/dds-types/type-support.lisp` `flatdata-view`;
`src/dds-xport/zerocopy-pool.lisp` `%zc-acquire-for-read` + the force-reclaim `refcount>0` skip;
`src/dds-disc/{disc,dataplane}.lisp` the `zc-loan-capable` flag + `%zc-defer` + the `zc-loan-marker`;
`src/dds-dcps/entities.lisp` `take-loaned`/`read-loaned`/`return-loan` + the per-reader loan registry +
freelist + the loan-capable wiring) is **clean-room**:

- Implemented from **FR-PF-3 / FR-PF-4 + the OMG XCDR 1.3 fixed-size layout + the OMG DDS 1.4
  `read()`/`take()` + `return_loan()` read-by-reference model (§2.2.2.5)** only. The loan/return-by-reference
  flow, the per-reader `zc-loan-capable` targeting, the refcount-spanning slot lifetime (held by the writer's
  `%zc-loan` refcount through the receiver-thread store, the DCPS acquire-without-inc, the app reads, until
  `return-loan`), and the force-reclaim `refcount>0` skip are this project's **own design from first
  principles** + the OMG loan model. The PAL foreign-SAP fixed-width reads are this project's own thin
  wrappers over SBCL's documented `sb-sys:sap-ref-{8,16,32}`.
- **No RTI source, headers, or `rtiddsgen` output consulted; no other vendor's FlatData/Zero-Copy/loan
  implementation read; no RTI patent / whitepaper read.** No Apache-2.0 (Fast DDS) / EPL-EDL (Cyclone) /
  OpenDDS source was read for this work package.
- **NOT cleared for ship — pending counsel (R6).** This IS the FlatData+Zero-Copy literal-0-copy mechanism
  RTI's patents touch; gated default-OFF twice (`dds.disc:*zerocopy-enabled*` nil **and** the per-type
  `:flatdata t`). With either off the data path is byte-identical. Counsel performs the authoritative claim
  clearance before any `*zerocopy-enabled*`-on FlatData-loan ship; this entry + ADR 0017 record provenance.
- Validated by `zc-defer` (the receiver-thread defer/no-release vs the shipped resolve-copy-release) +
  `dcps-loan-roundtrip` (the full DCPS stack: byte-exact 0-copy loaned read, slot-reusable-after-return,
  double-return-safe, reader-close-returns-loans), the existing `zerocopy-end-to-end` / `flatdata-zerocopy` /
  `zc-xproc` (the copy path + the real 2-process exchange, byte-unchanged), and fuzz (the forged-len ZC clamp,
  `(safety 0)` arm) — none of which involves a vendor artifact.
- **Phase F (`src/dds-tests/{integration-test,echo-test,pbt-test}.lisp`, `Makefile`):** the literal-0-copy
  headline + lifetime stress + loan-acquire fuzz + the bench are likewise clean-room — measured with this
  project's own `dds.pal:bytes-consed` seam over its own pool primitives; no vendor artifact, benchmark, or
  number consulted. `run-flatdata-zc-loan-e2e-test` (the `take-loaned`/read/`return-loan` loop + the RX
  `bytes-consed` progression `~32 → ~79 → ~65551`), `run-flatdata-zc-loan-stress-test` (the concurrency
  lifetime safety property under real threads — held-loan-byte-integrity-under-churn, pool-full fallback, no
  refcount leak, leaked-loan-degrades-to-fallback), `fuzz-flatdata-zc-loan-wrap` (the untrusted loan-acquire
  bounds — forged slot/generation/recorded-len ⇒ NIL or a slot-clamped view, never an OOB even at `(safety 0)`),
  `run-bench-flatdata-zc-loan` (`make bench-flatdata-zc-loan` → `bench/report/2026-06-16-wp-flatdata-zc-loan.md`).
  HONEST (FR-LANG-7): the report states the literal-0-copy RX *allocation* win (the eliminated owned vector)
  AND the loan/return per-sample overhead (the explicit acquire/release calls + the app's return obligation) —
  no `0-cost`/`free` claim. The cross-process FlatData-over-ZC exchange stays covered by `make zc-xproc` (the
  reference resolves across two OS processes; literal-0-copy is a LOCAL read optimization — the wire is
  byte-identical, so no separate loan-variant cross-process harness was added).

## M5 (2026-06-16) — WP-ZC-LOAN-LOCKFREE lock-free 0-alloc loaned RX (FR-PF-3/4, NFR-PERF-7, ADR 0018, Phases A–C)

The lock-free loaned-RX path (`src/dds-xport/zerocopy-pool.lisp` `%zc-loan` payload→`fence :release`→
generation-store-LAST + the freelist drop + `%zc-take-free-or-reclaim` always-scan, `%zc-acquire-for-read`
generation-acquire-load→`fence :acquire`→validate→clamped read, `%zc-release` direct `cas-sap-u32` refcount
decrement; `src/dds-pal/{pal-contract,pal-sbcl,pal-clasp}.lisp` the `cas-sap-u32` primitive;
`src/dds-tests/{echo-test,pbt-test}.lisp`, `Makefile` the unit tests + the bench) is **clean-room**:

- Implemented from **FR-PF-3 / FR-PF-4 + the OMG XCDR fixed-size layout + the OMG DDS `read()`/`take()` +
  `return_loan()` read-by-reference model + the standard lock-free single-producer release/acquire publication
  protocol** (a release store of a generation/version word after the payload, paired with an acquire load
  before the consumer reads — the textbook handshake this project already uses for the WP-SHMEM ring cursor,
  ADR 0013). The payload→release-fence→generation-last reorder, the always-scan reclaim, the no-freelist
  `cas`-decrement release, and the direct-u32-refcount CAS are this project's **own design from first
  principles** + the OMG loan model + the WP-SHMEM ring pattern. No RTI mechanism.
- **The arm64 barrier analysis is from SBCL's own VOP disassembly, no external source.** That
  `dds.pal:fence :release`/`:acquire` lower to a real `DMB SY` store/load barrier and that `sb-ext:cas` over
  `sb-sys:sap-ref-32` lowers to a full-barrier `CASAL` was confirmed by **disassembling SBCL's own generated
  code** (`disassemble` over the PAL primitives), not by reading any external/vendor source — the same
  clean-room rule as code: verify against the toolchain, never invent.
- **No RTI source, headers, or `rtiddsgen` output consulted; no other vendor's FlatData/Zero-Copy/lock-free
  loan implementation read; no RTI patent / whitepaper read.** No Apache-2.0 (Fast DDS) / EPL-EDL (Cyclone) /
  OpenDDS source was read for this work package.
- **NOT cleared for ship — pending counsel (R6).** This only makes the release/acquire of the already-R6-gated
  FlatData+Zero-Copy literal-0-copy loan path (ADR 0017) lock-free — the patent posture is unchanged; gated
  default-OFF twice (`dds.disc:*zerocopy-enabled*` nil **and** the per-type `:flatdata t`). With either off the
  data path is byte-identical (only the writer's local slot-store order + slot-acquisition strategy changed;
  the wire bytes are unchanged). Counsel performs the authoritative claim clearance before any
  `*zerocopy-enabled*`-on FlatData-loan ship; this entry + ADR 0018 record provenance.
- Validated by `zc-loan-nofreelist` (the always-scan reclaim sans the freelist), `zc-lockfree-acquire` /
  `zc-lockfree-release` (the lock-free fenced-read acquire + the `cas`-decrement release, 0-alloc),
  `zc-lockfree-release-biggen` (the Phase-B amendment regression guard — asserts the release is 0-alloc at
  generation `2^31`; FAILS at ~32 B against the dropped combined-word `cas-sap-u64` overlay that boxed a
  bignum), `zc-lockfree-stress` (the lock-free release-race under real threads — no torn read, no refcount
  underflow/leak, no slot overwritten under a reader), the existing `zc-xproc` (the genuine cross-process
  release/acquire — byte-exact), and `run-bench-zc-loan-lockfree`
  (`make bench-zc-loan-lockfree` → `bench/report/2026-06-16-wp-zc-loan-lockfree.md`) — none of which involves a
  vendor artifact; measured with this project's own `dds.pal:bytes-consed` / `dds.pal:monotonic-ns` seams over
  its own pool primitives. HONEST (FR-LANG-7): the report states the loaned RX *literal 0-alloc* win AND the
  writer's O(slots)-scan tradeoff (the dropped O(1) freelist-pop) + the loan/return calls + the app's return
  obligation — no `0-cost`/`free` claim.

## M5 (2026-06-16) — WP-RELIABLE-ZC reliable Zero-Copy loan delivery, scope A (FR-PF-3/4, FR-RTPS reliability, ADR 0017)

The reliable Zero-Copy loan delivery verify+harden+test work (`src/dds-qos/qos.lisp` the
`make-reader-qos`/`make-writer-qos` default-ordering fix; `src/dds-tests/{integration-test,echo-test}.lisp`
the five `run-reliable-zc-*` scenarios + the test-only `%saturate-zc-pool`/`%zc-pool-full-p`/
`%release-zc-loans`/`%deliver-one-zc-loan` helpers) is **clean-room** and introduced **no new external source**:

- The reliability model is **OMG DDSI-RTPS 2.5 §8.4** (the StatefulWriter/StatefulReader HEARTBEAT/ACKNACK/GAP
  protocol, the full-ACK HistoryCache purge §8.4.1) + the OMG DDS 1.4 `read()`/`take()` + `return_loan()`
  loan-by-reference model (§2.2.2.5) — the same authorities ADR 0017 / ADR 0018 already record. The finding
  that reliable ZC delivery rides the existing reliable path (HC full payload + retransmit; the retransmit
  copy-fallback as-built; the loan composing with reliability via the refcount; the loaned slot outliving the
  full-ACK purge), and the two scope-B follow-ups (re-loan-on-retransmit needing per-peer `%zc-readers`; true
  writer-side reliable ZC) are this project's **own analysis of its own engine** from first principles.
- The `make-reader-qos`/`make-writer-qos` fix is a **plain Common Lisp keyword-precedence correction**
  (HyperSpec 3.4.1.4 — the leftmost of duplicate keyword arguments wins): the implementation was made to match
  its own documented "ARGS override" docstring contract. No external artifact informed it.
- **No RTI source, headers, or `rtiddsgen` output consulted; no other vendor's reliable / Zero-Copy / loan
  implementation read; no RTI patent / whitepaper read.** No Apache-2.0 (Fast DDS) / EPL-EDL (Cyclone) /
  OpenDDS code was consulted. The scenarios reuse this project's own `fd-abc` FlatData fixture, the loan-capable
  DCPS reader setup, and the `dds.disc:*debug-drop-sample-numbers*` loss-injection seam.
- **NOT cleared for ship — pending counsel (R6).** WP-RELIABLE-ZC exercises the FlatData + Zero-Copy
  literal-0-copy loan path (ADR 0017 / ADR 0018) under RELIABLE reliability; the patent posture is unchanged;
  gated default-OFF twice (`dds.disc:*zerocopy-enabled*` nil **and** the per-type `:flatdata t`). This entry +
  ADR 0017 record provenance for that review.
- Validated by `run-reliable-zc-retransmit-test` / `run-reliable-zc-poolfull-fallback-test` /
  `run-reliable-zc-mixed-test` / `run-reliable-zc-slot-outlives-purge-test` / `run-reliable-zc-qos-test`
  (211 green SBCL + Clasp; the ZC-gated scenarios pass-skip on the Clasp/macOS by-name-attach gap, ADR 0013) —
  none of which involves a vendor artifact. HONEST (FR-LANG-7): the docs state the reader-RX + 16-byte-wire ZC
  win AND that the retransmit is copy-fallback (not re-loan) and the writer keeps the HistoryCache full-payload
  copy (writer-side double-storage, not zero-copy under reliability) — no writer-side-zero-copy overclaim.

## M5 (2026-06-15) — WP-ASYNC-FLOW asynchronous flow control (FR-PF-2, ADR 0016, Phases A–F)

The whole WP-ASYNC-FLOW — the `flow-token-bucket` metering primitive (`src/dds-disc/flow-control.lisp`
— the bytes/period lazy-refill bucket, `make-flow-token-bucket`, `%fb-refill`, `%fb-acquire`), the
shared `flow-controller` object + its round-robin scheduler thread + pluggable policy hook + per-node
emit barrier, the block-up-to-`max_blocking_time` backpressure (`src/dds-rtps/reliable.lisp`
`space-cv`), and the honest rate-shaping bench (`run-bench-async-flow`,
`bench/report/2026-06-15-wp-async-flow.md`) — is **clean-room from FR-PF-2 + the WP-ASYNC-FLOW design
spec only** — **no RTI Connext source, headers, or `rtiddsgen` output** was consulted.

- **Sources consulted**: the operating contract §4 (FR-PF-2); the in-repo design spec
  `docs/superpowers/specs/2026-06-15-wp-async-flow-design.md`; the DDSI-RTPS 2.5 reading that the
  wire constrains submessage format + reliable-eventual-delivery but is **silent on sender-side
  scheduling** (so flow control is a wire-invisible additive extension, not a wire change).
- The token bucket is the **standard textbook rate-limiter** algorithm (lazy on-acquire refill,
  multiply-before-divide integer rate, max-burst cap, deficit-wait) — not an RTI mechanism. The
  `flow-controller` object shape (Alt B — a shared object + its own scheduler thread + a pluggable
  policy hook), the per-node emit barrier (the use-after-free fix for a shared scheduler), and the
  round-robin one-datagram-per-writer-per-turn scheduling are all this project's **own design from
  first principles** — the FlowController/PublishMode *concept* is RTI's, but the **implementation
  is clean-room** (derived from FR-PF-2 + the DDSI-RTPS reading, not from any RTI artifact).
- **Flow control is NOT patent-gated** — it is standard DDS; no R6 marker, no "NOT cleared for
  ship" header (the explicit contrast with WP-ZEROCOPY/WP-FLATDATA). The `FlowController` /
  asynchronous-PublishMode / round-robin / EDF / highest-priority-first names are RTI
  vendor-extension *names*, not normative OMG symbols; none were taken from RTI artifacts. The
  block-up-to-`max_blocking_time` backpressure is the standard DDS RELIABILITY behaviour over a
  bounded HISTORY/RESOURCE_LIMITS cache (OMG DDS 1.4 §2.2.3), not a new mechanism.
- **No Apache-2.0 (Fast DDS) / EPL-EDL (Cyclone) / OpenDDS source was read** for this work package.
- Validated by a deterministic unit test with an injected (settable-counter) clock — no wall-clock
  dependence (`run-flow-token-bucket-test`, SBCL + Clasp) — plus the integration/stress tests
  (`flow-pacing`, `flow-multiwriter-rr`, `flow-backpressure`, `flow-concurrency-stress`,
  `flow-teardown`, `flow-off-byte-identical`) and the honest rate-shaping bench (`run-bench-async-flow`),
  none of which consult any vendor artifact.

## M5 (2026-06-16) — WP-KEEPLAST per-instance KEEP_LAST history + GAP both directions (DDS 1.4 §2.2.3.18, RTPS 2.5 §8.3.7.4/§8.4.1)

- WP-KEEPLAST — making HISTORY `KEEP_LAST` apply **per instance** on both sides (the HistoryCache
  keyhash→SN index + the single `%hc-remove-change` removal path in `src/dds-rtps/history.lisp`, the
  additive `key-hash` threading through `writer-write`/`publish-sample`/`write-sample`, the writer HC +
  reader DCPS-cache QoS honoring via `enable-publisher` + `%drain-one-sample`, the default flip to spec
  KEEP_LAST-1, the GAP send `%on-user-acknack` + the reader `+submsg-gap+` dispatch with the
  `*max-gap-range*` cap, and the honest write-path bench `run-keeplast-bench` /
  `bench/report/2026-06-16-wp-keeplast.md`) — is **clean-room from OMG DDS 1.4 §2.2.3.18 + DDSI-RTPS 2.5
  §8.3.7.4/§8.4.1 + the in-repo WP-KEEPLAST design spec only** — **no RTI Connext source, headers, or
  `rtiddsgen` output** was consulted.
- **Sources consulted**: the operating contract §4 (FR-QOS); the in-repo design spec
  `docs/superpowers/specs/2026-06-16-wp-keeplast-perinstance-design.md`; DDS 1.4 §2.2.3.18 ("KEEP_LAST …
  keep the last `depth` values **for each instance**") + §2.2.3 (the generic QoS default table, HISTORY =
  KEEP_LAST depth 1); DDSI-RTPS 2.5 §8.3.7.4 (GAP — irrelevant/no-longer-available SNs) + §8.4.1
  (HistoryCache + the writer's first/last SN in HEARTBEAT). The per-instance index (a keyhash→ordered-SN
  bucket, evict-from-head) and the reactive-GAP-on-NACK wiring are this project's **own implementation
  from the OMG clauses**, not from any RTI artifact.
- **This is standard DDS QoS conformance — NOT patent-gated** (no R6 marker, no "NOT cleared for ship"
  header): per-instance KEEP_LAST and the GAP are normative OMG behaviour.
- **No Apache-2.0 (Fast DDS) / EPL-EDL (Cyclone) / OpenDDS source was read** for this work package.
- Validated by the HistoryCache-unit tests (`hc-perinstance-keeplast`, `hc-keeplast-unkeyed`,
  `hc-remove-change-consistency`, `rtps-history-purge`, `purge-reliable-only`), the end-to-end scenarios
  (`keeplast-writer-perinstance-e2e`, `keeplast-interior-hole-gap-e2e`, `keeplast-firstsn-advance`,
  `keeplast-reader-perinstance-e2e`, `keeplast-unkeyed-collapse`, `keeplast-keepall-regression`,
  `keeplast-reliability-composition`), the keyhash-threading test (`keeplast-keyhash-threaded`), and the
  honest write-path bench (`run-keeplast-bench`) — 226 green SBCL + Clasp — none of which consult any
  vendor artifact.

## M5 (2026-06-17) — WP-KEYED-FLATDATA keyed FlatData / the buffer-reading keyhash (FR-PF-4 + FR-TYPE-5, RTPS 2.5 §9.6.4.8, ADR 0015)

- WP-KEYED-FLATDATA — lifting FlatData v1's NO_KEY restriction for **fixed-size scalar `@key` members**
  (the buffer-reading keyhash `key-hash-<name>-fd` emitted by `define-dds-type` in `src/dds-gen/dsl.lisp`,
  its `type-support` wiring `:keyed-p t` + `:key-hash`, the real per-key `%loan-instance-handle` + the
  loan-path per-instance KEEP_LAST drop in `%drain-one-loan` in `src/dds-dcps/entities.lisp`, and the
  internal tests in `src/dds-tests/{rtps-test,integration-test}.lisp`) — is **clean-room from OMG DDSI-RTPS
  2.5 §9.6.4.8 (KeyHash) + OMG DDS 1.4 §2.2.2.5 (instance lifecycle) / §2.2.3.18 (KEEP_LAST) + DDS-XTypes
  1.3 §7.6.3 (XCDR2 FINAL fixed-size layout) + the in-repo WP-KEYED-FLATDATA design spec only** — **no RTI
  Connext source, headers, or `rtiddsgen` output** was consulted.
- **Sources consulted**: the operating contract §4 (FR-PF-4, FR-TYPE-5); the in-repo design spec
  `docs/superpowers/specs/2026-06-17-wp-keyed-flatdata-design.md` + plan
  `docs/superpowers/plans/2026-06-17-wp-keyed-flatdata.md`; DDSI-RTPS 2.5 §9.6.4.8 (the 16-octet instance
  KeyHash — the key members in member order to a big-endian XCDR2 cursor, ≤16 → zero-padded direct / >16 →
  MD5 of the bytes); ADR 0015 (the FlatData v1 NO_KEY deviation, now closed). The keyhash REUSES this
  project's own existing `key-hash-<name>` struct-keyhash serialization (itself derived clean-room from
  §9.6.4.8) — only the value source changed (the `<name>-<field>-fd` Offset accessor reading the LE buffer
  in place, vs the struct slot accessor); no new wire rule was derived, and no constant was taken from memory.
  Byte-exactness is established against a hand-computed §9.6.4.8 vector AND against our own struct keyhash for
  the same key values (`run-keyed-flatdata-keyhash-test`), not from any RTI artifact.
- **R6 — patent-gated** (rides the FlatData / Zero-Copy line): built behind `:flatdata t` + (for the loan
  path) `dds.disc:*zerocopy-enabled*` (default OFF) + the `NOT cleared for ship — pending counsel (R6); see
  ADR 0015/0017` marker on the new codegen. The copy/wire path is both-impl; the loan path is SBCL-only
  (ZC is an NFR-PORT gap on Clasp, ADR 0013).
- **No Apache-2.0 (Fast DDS) / EPL-EDL (Cyclone) / OpenDDS source was read** for this work package.
- Validated by the keyhash byte-exact test (`keyed-flatdata-keyhash` — the ≤16 direct + >16 MD5 paths, both
  cross-checked vs the struct keyhash; the variable-size `@key` compile-error preserved) and the keyed
  behavior tests (`keyed-flatdata-loan-handle`, `keyed-flatdata-loan-keeplast`, `keyed-flatdata-copy-behavior`,
  `keyed-flatdata-dispose`) — 231 green SBCL + Clasp (the SBCL-only ZC loan tests pass-skip on Clasp) — none
  of which consult any vendor artifact. The cross-DDS interop verification vs RTI Connext + Fast DDS (the
  keyhash/instance-identity on the wire) is the **pending F1 final gate** per the 2026-06-17 per-feature DoD.

## M5 (2026-06-17) — WP-KEYED-FLATDATA F1 cross-DDS interop harness (`interop/keyed-flatdata/`, FR-PF-4, RTPS 2.5 §9.6.4.8)

- The F1 cross-DDS interop gate for keyed FlatData: a shared `KeyedFlat.idl` (`struct KeyedFlat { @key long
  id; long x; long y; }`, defined to match this stack's `keyed-flat` type), Connext + Fast DDS peer apps, an
  our-side DCPS COPY/UDP harness (`dds.shapes:run-keyed-flat-{publisher,subscriber}`), `make` run targets, and
  an extended offline keyhash conformance test (`keyed-flat-interop-keyhash`, `src/dds-tests/rtps-test.lisp`)
  whose expected peer keyhash is **derived from first principles** (`%expected-i32-keyhash`, RTPS 2.5 §9.6.4.8),
  not from this project's serializer.
- **RTI Connext 7.3.1 — behavioural reference via interop only** (REQUIREMENTS §8, FR-IO-1, NFR-IP). The
  Connext apps (`interop/keyed-flatdata/connext/keyed_flat_{pub,sub}.cxx`) are built **against the RTI Connext
  public Modern C++ API + our own `KeyedFlat.idl`**; the `rtiddsgen` output (`KeyedFlat.{hpp,cxx}`,
  `KeyedFlatPlugin.{hpp,cxx}`) is produced at build time and **git-ignored** (`.gitignore`) — **never
  committed; no Connext source, headers, or generated code is copied** into any hand-written file. Built + run
  live in-session: the REVERSE leg (our pub → Connext sub) confirmed Connext computes the SAME per-key 16-octet
  instance keyhash for our keyed FlatData samples as our offline test pins (`00000000…`/`00000001…`/`00000002…`
  for id 0/1/2), and dispose-by-key resolved to the correct instance. Archived loopback pcap
  `captures/kflat-reverse-loopback.pcap`. (The forward-leg representation limitation noted here was a
  conformance follow-up, not an IP matter — subsequently CLOSED by WP-FLATDATA-XCDR-TRANSCODE; see the
  next M5 section.)
- **eProsima Fast DDS — `fastddsgen` output committed verbatim (Apache-2.0).** The Fast DDS peer apps
  (`interop/keyed-flatdata/fastdds/keyed_flat_{pub,sub}.cpp`) are built against the Fast DDS **public API** +
  our `KeyedFlat.idl`; the `fastddsgen`-generated type support under `fastdds/gen/` (`KeyedFlat.hpp`,
  `KeyedFlatCdrAux.{hpp,ipp}`, `KeyedFlatPubSubTypes.{hpp,cxx}`, `KeyedFlatTypeObjectSupport.{hpp,cxx}`) is
  **committed verbatim** (Apache-2.0 output of the pinned generator — **Fast-DDS-Gen v4.3.0**, pinned in
  `interop/fastdds/README.md`; the header notice `"This file was generated by the tool fastddsgen (version:
  4.3.0)"` is retained), the same convention as `interop/fastdds/shapes/gen/`. Generated 2026-06-17 with
  `scripts/with-fastdds.sh "$FASTDDSGEN" -replace -d gen ../KeyedFlat.idl`; the `GENERATE.md` placeholder is
  removed now that the output is committed. **No Fast DDS source is copied** into the hand-written harness files.
- The keyhash + the dispose `PID_KEY_HASH`/`PID_STATUS_INFO` wire forms are pinned from OMG DDSI-RTPS 2.5
  §9.6.4.8 / §9.6.4.9; no constant was taken from memory or from any vendor artifact.

## M5 (2026-06-17) — WP-FLATDATA-XCDR-TRANSCODE keyed-FlatData bidirectional interop, LIVE (FR-PF-4)

- The transcode WP's forward-leg DoD AND the keyed-FlatData Fast DDS leg, both verified **live** on this host
  (loopback `lo0`), all four legs vs **RTI Connext 7.3.1** and **eProsima Fast DDS 3.6.1**. Frames captured with
  the Wireshark/tshark RTPS dissector under a clean `WIRESHARK_CONFIG_DIR` (the same disabled-protos guard
  `scripts/wire-check.sh` uses); archived under `interop/keyed-flatdata/captures/`.
  - **Forward (peer pub → our FlatData sub) — the transcode**: both Connext and Fast DDS emitted
    `PLAIN_CDR_LE (0x0001)` (XCDR1-LE) on the wire; our `:flatdata t` reader **transcoded** it into its
    canonical XCDR2-LE buffer (the WP-FLATDATA-XCDR-TRANSCODE feature) and delivered 29/30 samples into exactly
    3 per-key instances with byte-identical keyhashes + dispose-by-key. This is the F1 forward leg that
    previously REJECTED. Pcaps `captures/kflat-forward-connext.pcap`, `captures/kflat-forward-fastdds.pcap`.
  - **Reverse (our pub → peer sub) — the keyhash crux**: our writer emitted `PLAIN_CDR2_LE (0x0007)`
    (XCDR2-LE); both peers grouped our 30/30 samples into exactly 3 per-key instances
    (`00000000…`/`00000001…`/`00000002…`) and resolved dispose-by-key to the right instance. Pcaps
    `captures/kflat-reverse-connext.pcap`, `captures/kflat-reverse-fastdds.pcap`.
- **Harness changes, clean-room (no vendor source).** `fastdds/keyed_flat_pub.cpp` now offers BOTH
  `XCDR_DATA_REPRESENTATION` (XCDR1) and `XCDR2_DATA_REPRESENTATION` on the writer (was XCDR2-only): Fast DDS
  enforces the DDS-XTypes §7.6.3.1.1 data-representation compatibility on the WRITER side and refused to match
  our reader (whose SEDP advertises no `PID_DATA_REPRESENTATION`, i.e. the XCDR1 default), so it never sent —
  offering XCDR1 makes the match symmetric and Fast DDS then publishes the common rep (XCDR1-LE), which our
  transcode reads. `fastdds/profiles.xml` `interfaceWhiteList` pinned to `127.0.0.1` only (loopback-only for
  the same-host rendezvous; with a LAN address whitelisted Fast DDS routed the user dataflow off `lo0`). Both
  are hand-written/edited against the **public** Fast DDS API + XML schema; no Fast DDS source pasted.
- The advertise-`PID_DATA_REPRESENTATION=XCDR2`-on-our-SEDP follow-up named in the README is a production-side
  XTypes item (out of scope for this interop-verification WP); it is NOT a transcode or keyhash defect.
- **The transcode feature itself is clean-room — no new external source consulted.** The FlatData-reader
  representation transcode (`dds.cdr:flatdata-rx-rep-plan` in `src/dds-cdr/cdr.lisp` classifying the rep-id;
  the decode-then-reserialize branch in `src/dds-gen/dsl.lisp`'s `deserialize-into-<name>-fd`) is implemented
  from **DDS-XTypes 1.3 §7.6.3.1.2** (the RTPS encapsulation-identifier table — the rep-ids are read from the
  already-pinned `+representation-ids+`/Table 60 values, never hardcoded from memory) + **§7.4** (the XCDR1 8-
  vs XCDR2 4-byte alignment divergence that makes the transcode a re-align, not a pure byte-swap) + first
  principles. It reuses the existing sibling struct codec (`deserialize-<name>` / `serialize-<name>`) — no new
  codec. No RTI/Fast DDS/Cyclone/OpenDDS source, headers, or generated code was read or copied for it; ADR 0015
  records the design.

## M5 (2026-06-17) — WP-SENDER-ERROR-RESILIENCE sender-thread emit guard (FR-PF-2, RTPS 2.5 §8.4, ADR 0016)

The sender-thread emit guard — the DRY `with-sender-emit-guard` macro + `*sender-emit-error-hook*` +
per-thread counters + the Option-1 drop-and-advance flow path + the `*debug-emit-fault*` test injector
(`src/dds-disc/dataplane.lisp` + `src/dds-disc/flow-control.lisp`) — is **clean-room; no new external source
was consulted.**

- **Sources consulted**: the operating contract §4 (FR-PF-2); the in-repo design spec
  `docs/superpowers/specs/2026-06-17-wp-sender-error-resilience-design.md`; **RTPS 2.5 §8.4.1–§8.4.2** (the
  reliable-writer HistoryCache retention + the HEARTBEAT/ACKNACK repair) and **§8.4.2.2** (pushMode=true
  proactive push) — the spec basis for "drop + advance, reliability recovers". DDS 1.4 / DDSI-RTPS 2.5 does
  **not** specify local send-error handling (it is implementation-defined, not wire-observable), so the
  Option-1 rationale is *derived from* the reliability model, not taken from a mandate, and the wire is
  unchanged.
- The guard **mirrors this repo's own existing pattern** — the RX receiver thread's per-iteration
  `(handler-case … (error () nil))` (`src/dds-xport/udp.lisp:105`); it is the symmetric sender-side
  application of an in-house idiom, not a copy of any vendor's mechanism. The "catch `error` not
  `serious-condition`", the rate-limited default hook, and the snapshot-watermark no-spin argument are all
  first-principles design.
- **This is standard DDS hardening — NOT patent-gated** (no R6 marker, no "NOT cleared for ship" header).
- **No RTI Connext source/headers/`rtiddsgen` output, and no Apache-2.0 (Fast DDS) / EPL-EDL (Cyclone) /
  OpenDDS source, was read or copied** for this work package. The live cross-DDS interop
  (`interop/sender-resilience/`) reuses the already-committed Connext `shapes-sub` and Fast DDS `shapes`
  subscribers (provenance recorded above); no new vendor source/output is added by this leg.

## M5 (2026-06-17) — WP-DATA-REPRESENTATION PID_DATA_REPRESENTATION + TX in the offered representation (FR-QOS / FR-IO, DDS-XTypes 1.3 §7.6.3.1.1, ADR 0020)

The `PID_DATA_REPRESENTATION` (0x0073) SEDP emit/parse, the role-aware QoS advertising, the spec-strict RxO
on truthful values, the TX-in-offered-representation (XCDR1-LE / XCDR2-LE) path, and the RX generalization
(`src/dds-rtps/{message,discovery,packages}.lisp`, `src/dds-qos/qos.lisp`, `src/dds-dcps/entities.lisp`,
`src/dds-gen/dsl.lisp`) are **clean-room; no new external source code was consulted.**

- **Sources consulted**: the operating contract §4; the in-repo design spec
  `docs/superpowers/specs/2026-06-17-wp-data-representation-design.md`; **DDS-XTypes 1.3 §7.6.3.1.1**
  (the `DataRepresentationQosPolicy`, `DataRepresentationId_t` — XCDR1=0, XML=1, XCDR2=2 — and the RxO rule)
  + **§7.6.3.1.2 / Table 60** (the *distinct* encapsulation ids — `PLAIN_CDR_LE` 0x0001, `PLAIN_CDR2_LE`
  0x0007); **RTPS 2.5 §8.5** (SEDP), **§9.6** (the PL_CDR parameter encoding), **§9.6.4.8** (the keyhash,
  unchanged — always XCDR2-BE, rep-independent), **§10.2** (the SerializedPayload header); DDS 1.4 §2.2.3
  (the QoS RxO / INCOMPATIBLE_QOS). The wire constants were **NOT taken from memory or from this doc**: the
  `DataRepresentationId_t` values and the `sequence<short>` encoding were pinned from the §7.6.3.1.1 clause
  text AND verified **byte-exact** against a live RTI Connext 7.3.1 + eProsima Fast DDS 3.6.1 SEDP capture
  (the wire-is-oracle, the operating contract §4) — recorded in
  `interop/data-representation/captures/NOTES.md` and re-dissected from our own emitted frames in
  `interop/data-representation/README.md`. The live SEDP capture (the only new "external artifact") is a
  **behavioural reference via interop only** — a tshark dissection of bytes on `lo0`, never source/headers.
- The work **reuses this repo's own existing machinery** — the SEDP PID emit/parse idiom (the
  PID_RELIABILITY / PID_LIVELINESS precedents), the `qos-rxo-compatible` rule, the `+representation-ids+`
  encapsulation-id table + `make-encapsulation-header`, the generated struct codec's dual-mode
  serialize/serialized-size, and the FlatData transcode builder (ADR 0015). It is the in-house application of
  in-house idioms, not a copy of any vendor's mechanism.
- **This is standard DDS conformance — NOT patent-gated, with ONE R6 exception**: the FlatData TX-transcode
  (the `:xcdr1`-offered FlatData write path) is gated like the existing FlatData RX-transcode (ADR 0015) and
  carries the `NOT cleared for ship — pending counsel (R6)` marker; everything else is unrestricted standard
  DDS, green on SBCL + Clasp.
- **No RTI Connext source/headers/`rtiddsgen` output, and no Apache-2.0 (Fast DDS) / EPL-EDL (Cyclone) /
  OpenDDS source, was read or copied** for this work package. The live cross-DDS interop
  (`interop/data-representation/`) reuses the already-committed Connext `shapes-sub`/`shapes-pub` and Fast
  DDS `shapes` peers (provenance recorded above); the loopback `USER_QOS_PROFILES.xml` is a copy of the
  in-repo `interop/connext/liveliness/USER_QOS_PROFILES.xml` (a capture-only aid, not run by CI). No new
  vendor source/binaries are added by this leg.

## M5 (2026-06-18) — WP-SHMEM-SEND-SELF-GUARD: a signalled %shmem-send fault degrades to the UDP fallback (FR-XPORT-2, ADR 0013)

A signalled `%shmem-send` hard fault is caught in `%send-raw-buf` (`dds.disc`), counted
(`disc-node-shmem-send-faults`), observed via `*sender-emit-error-hook*` (context
`:shmem-send-fault`), and degraded to the existing UDP fallback
(`src/dds-disc/{dataplane,disc,packages}.lisp`, `src/dds-xport/{shmem,packages}.lisp`). This is
**clean-room; no new external source code was consulted.**

- **Sources consulted**: the operating contract §4; the in-repo design spec
  `docs/superpowers/specs/2026-06-18-wp-shmem-send-self-guard-design.md`; **FR-XPORT-2** (the SHMEM
  transport). Local send-error handling is **implementation-defined** — no RTPS clause governs it (the same
  posture as WP-SENDER-ERROR-RESILIENCE) — so **no wire constant or wire behaviour is involved**; the
  UDP-fallback delivery is backstopped for genuinely lost reliable samples by **RTPS 2.5 §8.4 / §8.4.1**
  (the HEARTBEAT/ACKNACK repair, unchanged). The fault injector is a test affordance (NFR-SEC-POSTURE), inert
  in production, never wire-triggered.
- The work **reuses this repo's own existing machinery** — the `*sender-emit-error-hook*` `(condition context
  count)` contract + the `%note`/`ignore-errors` fire idiom (WP-SENDER-ERROR-RESILIENCE, ADR 0016), the
  `disc-node` diagnostic counter pattern (`shmem-sends`), the `%send-raw-buf` SHMEM-then-UDP fallback (ADR
  0013), and the `*debug-*-fault*` test-injector pattern (`*debug-emit-fault*`). It is the in-house
  application of in-house idioms, no copy of any vendor's mechanism.
- **This is standard DDS — NOT patent-gated, NOT R6**: SHMEM is a standard transport (FR-XPORT-2) and the
  graceful-degrade is implementation-defined local error handling; green on SBCL + Clasp.
- **No RTI Connext source/headers/`rtiddsgen` output, and no Apache-2.0 (Fast DDS) / EPL-EDL (Cyclone) /
  OpenDDS source, was read or copied** for this work package. SHMEM is same-host ours-to-ours, so the
  cross-DDS surface is **no-regression** (a foreign peer always gets UDP — the guard is inert for it); the
  no-regression interop (`interop/shmem-send-self-guard/`) reuses the already-committed Connext + Fast DDS
  Shapes peers (provenance recorded above). No new vendor source/binaries are added by this leg.

## M6/P5 — WP-DURABILITY-SERVICE-TRANSIENT Task 1 Spike (2026-06-18)

- **RTI Connext source/headers:** NOT read. The `PID_ORIGINAL_WRITER_INFO (0x0061)` byte layout and
  dedup mechanism were identified purely by live wire capture: `rtipersistenceservice` v7.3.1 TRANSIENT
  relay on `lo0`, dissected with tshark RTPS dissector.
  Capture: `interop/durability-transient/captures/spike-rtips-transient-virtual-guid.pcap`. CLEAN.
- **eProsima Fast DDS source** (Apache-2.0,
  `$HOME/gbt Dropbox/gbt/projects/fastdds/src/fastdds/`): read for cross-vendor confirmation of the
  identified PID. Specific files and lines are recorded in
  `docs/superpowers/spikes/2026-06-18-durability-virtual-guid-findings.md` §6. No code was copied.
  Purpose: confirm that `PID_ORIGINAL_WRITER_INFO = 0x0061` is shared by both RTI and eProsima, and
  that the receiver-side dedup map is the standard mechanism. Influence: the findings doc §5
  Phase 2 design recommendation (emit `PID_ORIGINAL_WRITER_INFO`; receiver dedup map).
- **OMG RTPS 2.5 spec citations:** `PID_ORIGINAL_WRITER_INFO` is defined in §8.3.5.4
  (`OriginalWriterInfo`) and Table 9.12; `SequenceNumber` layout in §8.3.3.4. These are the
  normative references for the Phase 2 implementation.

## M6/P5 — WP-DURABILITY-DARE: OpenSSL ≥ 3.5 native crypto (2026-06-19, ADR 0025)

- **OpenSSL (`libcrypto`) ≥ 3.5 (Apache-2.0, The OpenSSL Project)** added as a **native runtime
  dependency** of the new `dds-dare` system — the vetted CNSA-2.0 crypto backend for the durability
  service's always-on Data-At-Rest Encryption (ADR 0021 capability 7): AES-256-GCM (FIPS-197 / NIST
  SP 800-38D), ML-KEM-1024 (FIPS-203), and SHA-384 + HKDF (FIPS-180-4 / RFC 5869 / NIST SP 800-56C).
  This satisfies **FR-SEC-2 (vetted native crypto, NO hand-rolling)**: we bind + compose
  (KEM-DEM envelope, the HKDF domain-separator label, counter-nonce discipline, AAD) per NIST
  guidance and implement no primitive ourselves. The version verified on this host is **OpenSSL
  3.6.2 (7 Apr 2026)**; **≥ 3.5 is a hard requirement** (ML-KEM landed in the 3.5 LTS),
  runtime-checked at startup (`dare-available-p` → `(values NIL reason)` fail-closed status, ADR 0064; never a plaintext fallback).
- **No OpenSSL source/headers were copied.** The CFFI bindings (`src/dds-dare/openssl-ffi.lisp`)
  are clean-room: each EVP signature is **pinned against the installed OpenSSL 3.6.2 public headers**
  (`evp.h`/`kdf.h`/`core.h`/`crypto.h`, file + line cited in-source) and verified by **published
  NIST/IETF/Wycheproof Known-Answer Tests** (FIPS-180-4 SHA-384, Google Wycheproof HKDF-SHA-384,
  NIST SP 800-38D GCM Test Case 16, C2SP/CCTV ML-KEM-1024 — never self-generated). The OSSL_PARAM
  struct layout was confirmed by C `offsetof` on this host (arm64-macOS), recorded in-source, not
  taken from any vendor artifact.
- **Google Wycheproof (Apache-2.0, Google) — published crypto test-vector source, read as data only,
  no code copied.** The HKDF-SHA384 KAT (`src/dds-tests/dare-test.lisp`) pins two vectors verbatim
  from **`testvectors_v1/hkdf_sha384_test.json`** (`algorithm "HKDF-SHA-384"`, schema
  `hkdf_test_schema_v1.json`): tcId 1 (empty salt + empty info — matches `derive-dek`'s empty-salt
  usage) and tcId 4 (empty salt + non-empty info). Wycheproof computes its expected OKM with a different
  implementation, so our OpenSSL EVP_KDF reproducing them byte-exactly on both SBCL and Clasp is
  genuine independent conformance — replacing the prior self-generated (OpenSSL-CLI-derived) HKDF
  regression vector, which only self-tested OpenSSL against itself (RFC 5869 standardises no SHA-384
  vector). The SHA-384("abc") KAT stays anchored to FIPS PUB 180-4 §B.2.
- **libsodium NOT used** (owner directive "use libsodium if appropriate" → not-appropriate): it
  lacks ML-KEM and SHA-384; OpenSSL ≥ 3.5 covers all three, so libsodium would be redundant FFI/SBOM
  surface. Recorded in ADR 0025.
- **SBOM:** OpenSSL is pinned in `scripts/generate-sbom.py`'s component table and emitted as a native
  runtime `software_Package` (Apache-2.0, `dependsOn` the product), mirroring the SBCL runtime entry
  — CRA Annex I top-level coverage. (Loaded via CFFI, it is not an ASDF `:depends-on`, so it is
  emitted explicitly rather than via the ASDF scan.)

## M6/P5 — WP-DURABILITY-COEXIST-DEDUP: RTI PS per-sample origin encoding (2026-06-20, ADR 0026 §10)

- **RTI Connext Persistence Service v7.3.1 — reverse-engineered from the wire ONLY.** Spike Task 1
  decoded how RTI PS conveys per-sample origin identity when relaying durable history. No RTI source,
  headers, or generated code were read. Behavior observed via live `rtipersistenceservice` v7.3.1 on
  `lo0` (domain 0, loopback) and decoded with our own raw RTPS submessage byte-walk
  (`interop/durability-persistent/coexistence/analyze-capture.py`, extended with an `--owi-dump` mode).
  Finding: RTI PS stamps the **OMG-standard `PID_ORIGINAL_WRITER_INFO (0x0061)`** (NOT a vendor PID)
  on its retained-history replay to a late joiner, carrying the original writer's REAL `(GUID, SN)`
  — Branch A. Captures: `interop/durability-transient/captures/spike-rtips-transient-virtual-guid.pcap`
  (2026-06-18, 1085 OWI vectors) and `interop/durability-coexist-dedup/spike/captures/rti-ps-replay-owi.pcap`
  (2026-06-20, this session). CLEAN-ROOM.
- **Wireshark/tshark RTPS dissector (GPL-2.0, The Wireshark Foundation)** — used ONLY as an independent
  cross-check of our byte offsets against C1 frame 1102 (the dissector's `virtualGUIDSuffix` /
  `virtualSeqNumber` labels under `PID_ORIGINAL_WRITER_INFO` confirm RTI's "virtual" origin IS the
  standard `OriginalWriterInfo`). Output read for verification, no code copied. The dissector is a
  separate tool we run, not a dependency we link.
- **OMG DDSI-RTPS 2.5 spec citations:** `PID_ORIGINAL_WRITER_INFO (0x0061)` / `OriginalWriterInfo` —
  §8.3.5.4 + Table 9.12; `SequenceNumber` (int32 high + uint32 low) — §8.3.3.4; DATA submessage /
  `octetsToInlineQoS` — §8.3.7.2. Normative pins for the 24-byte LE layout recorded in the findings doc
  (`docs/superpowers/spikes/2026-06-20-rti-vendor-origin-findings.md` §2.1).
- **Builds on** the 2026-06-18 Task-7 SEDP spike (`docs/superpowers/spikes/2026-06-18-durability-virtual-guid-findings.md`):
  that one established the SEDP-level RTI vendor `PID_ENTITY_VIRTUAL_GUID (0x8002)` /
  `PID_SERVICE_KIND (0x8003)`; this one establishes the **per-sample** carrier (the standard `0x0061`)
  and corrects the Phase-3b over-generalization that RTI PS emits "ZERO" OWI (true only of the
  live-forward path, not the replay path).
- **Task 2 (live dual-relay exactly-once, both directions) — RTI PS observed on the wire ONLY.** The
  coexistence harness `interop/durability-coexist-dedup/` runs live `rtipersistenceservice` v7.3.1 +
  `shapes_pub`/`shapes_sub` on `lo0`; all RTI behavior (OWI on replay, KEEP_ALL retention, the relay
  virtual-GUID origin entity `0x80000002`, the TRANSIENT-vs-TRANSIENT_LOCAL replay-tier semantics) was
  established by the raw RTPS byte-walk over loopback captures, never from RTI source/headers/generated
  code. `RTI_PS_TRANSIENT.xml` is configuration (KEEP_ALL relay QoS) authored against the published RTI
  persistence-service XSD (`.../resource/schema/rti_persistence_service.xsd`, read for the element set
  only). The `analyze-capture.py` `--dedup-union` mode is our own. CLEAN-ROOM.

## M7/P6 — WP-DDS-SECURITY-AUTH-KEYX T0: KxKey/KeyMaterial/CryptoToken constants (2026-06-26)

- **OMG DDS-Security 1.1 formal/2018-04-01** — primary authority for §9.5.3 KxKey derivation
  and §9.5.2 KeyMaterial structure. PDF binary; clause numbers cited in the spike doc.
- **eProsima Fast DDS (Apache-2.0) — source read for understanding only; no code copied.**
  Files read:
  - `src/cpp/security/cryptography/AESGCMGMAC_KeyFactory.cpp` — `create_kx_key()` and
    `register_matched_remote_participant()`: corroborated the two-step HMAC-SHA256 KDF, the
    two 16-byte labels (`"key exchange key"`, `"keyexchange salt"`), and the challenge/shared-secret
    input ordering.
  - `src/cpp/security/cryptography/AESGCMGMAC_KeyExchange.cpp` — `KeyMaterialCDRSerialize()`,
    `KeyMaterialCDRDeserialize()`, `create_local_participant_crypto_tokens()`,
    `set_remote_participant_crypto_tokens()`, `create_local_datawriter_crypto_tokens()`,
    `set_remote_datawriter_crypto_tokens()`: established the 88-byte CDR layout (3-zero-pad +
    1-byte length framing), the binary property name `"dds.cryp.keymat"`, the DataHolder
    class_id `"DDS:Crypto:AES_GCM_GMAC"`, and the MATERIAL FINDING that Fast DDS sends
    KeyMaterial in plaintext (KxKey-AEAD encryption commented out).
  - `src/cpp/security/cryptography/AESGCMGMAC_Types.h` — `KeyMaterial_AES_GCM_GMAC` struct
    field names and types.
  - `src/cpp/security/authentication/PKIDH.cpp` — confirmed challenge sizes (32 bytes each,
    BN_rand(256)) and SharedSecret population (32-byte SHA-256 of DH/ECDH output).
  - `src/cpp/rtps/security/SecurityManager.cpp` — the three `GMCLASSID_SECURITY_*` macro
    strings: `"dds.sec.participant_crypto_tokens"`, `"dds.sec.datawriter_crypto_tokens"`,
    `"dds.sec.datareader_crypto_tokens"`.
  No code was copied. Influence: corroboration only; all constants are independently pinned
  from the OMG spec clause; Fast DDS confirms or is noted as deviating (KxKey-plaintext).
- **IETF RFC 4231** — published HMAC-SHA-256 test vectors (TC1, TC4) for KAT validation of
  `dds.dare:hmac-sha256`. URL: https://www.rfc-editor.org/rfc/rfc4231. Read as data only.
- **NIST FIPS PUB 180-4 §B.1** — published SHA-256 "abc" test vector for component-primitive
  KAT. URL: https://csrc.nist.gov/publications/detail/fips/180/4/final. Read as data only.
- **No RTI Connext source, headers, or generated code consulted.** CLEAN-ROOM.

## M7 (2026-06-26) — WP-DDS-SECURITY-ACCESS-CONTROL T0 (AccessControl spike)

AccessControl plugin: Governance + Permissions document formats + CMS signing + XML library.

- **OMG DDS-Security 1.1 formal/19-04-03 §9.4.1 + Annex B** — sole normative source for the
  Governance/Permissions XSD element set (§9.4.1.2.3 Tables 30–34, §9.4.1.3.2 Tables 35–41,
  Annex B XSD schema locations). No external service; spec read from prior knowledge with
  clause citations. All element names + enumeration values pinned from §9.4.1.2.3 / §9.4.1.3.2.
- **OpenSSL 3.6.2 headers** (`/opt/homebrew/opt/openssl@3/include/openssl/cms.h`) — read to pin
  the exact C API signatures: `SMIME_read_CMS` (line 226), `CMS_verify` (lines 276-277),
  `CMS_get0_signers` (line 283), and the `CMS_*` flag constants (lines 180-200). No code copied;
  influence: the FFI binding signature for `dds.dare:cms-verify` (T1).
- **`xmls` 3.3.0 (MIT, Shannon Spires / rpgoldman)** — added as a runtime dependency for
  Governance + Permissions XML parsing. Pure Common Lisp, zero transitive dependencies; selected
  over `cxml` (which also loads on both Clasp and SBCL but adds 4 transitive systems).
  Justified per the operating contract §9: control-plane only (never on the hot path); the
  Clasp+SBCL-both-validate directive is satisfied (smoke-loaded on both, identically).
  SBOM entry: `SPDXRef-xmls`, version 3.3.0, MIT, `https://github.com/rpgoldman/xmls`.
- Test fixtures generated in `interop/security-access-control/pki/` — a throwaway Permissions CA
  (EC P-256) + signed governance.xml + signed permissions.xml. Keys are throwaway test-only
  credentials; committed intentionally. No external CA or existing PKI consulted.
- **No Fast DDS, Cyclone, OpenDDS, or RTI Connext source read.** CLEAN-ROOM.

## M7 (2026-06-26) — WP-DDS-SECURITY-ACCESS-CONTROL T2 (Governance/Permissions parser + matcher)

- **`xmls` 3.3.0 (MIT)** added to `dds-security.asd :depends-on` for XML parsing; zero transitive
  deps, pure Common Lisp, T0-verified on both SBCL and Clasp; justification in T0 section above.
- **OMG DDS-Security 1.1 §9.4.1.2.3 + §9.4.1.3.2** — sole normative source for the element set,
  first-match-wins rule evaluation order (§9.4.1.3.2.10), and fnmatch topic matching (§9.4.1.3.2.7).
- Fixtures `interop/security-access-control/pki/governance.xml` + `permissions.xml` (unsigned XML,
  committed from the T0 gen-test-permissions.sh run) used as parse KAT and fuzz base.
- **No RTI Connext, Fast DDS, Cyclone, or OpenDDS source read.** CLEAN-ROOM.

## M7/P6 — WP-DDS-SECURITY-SECURE-DISCOVERY T0: secure-discovery constants spike (2026-06-27)

Pinned the §7.3.7/§7.4.5/§9.5 secure-discovery wire constants (secure builtin EntityIds, secure RTPS
submessage kinds, the receiver-specific-key KDF label, the governance ProtectionKind enum + XSD encoding),
each dual-corroborated. Spike: `docs/superpowers/spikes/2026-06-27-dds-security-secure-discovery.md`.

- **OMG DDS-Security 1.1 / DDSI-RTPS 2.5 §-clauses** are the primary source (§7.3.7 submessage kinds;
  §7.4.5 secure builtin EntityIds; §9.5.3.3.4.2/.3 KDF labels; §9.4.1.2 / Annex B `dds_governance.xsd`
  ProtectionKind; §9.5.2.2 / §7.4.4 token `message_class_id`s). NOTE: the DDS-Security 1.1 PDF is **not**
  in `docs/specs/` (only RTPS/DCPS/XTypes are) — clause numbers are carried from the design + brief + the
  prior in-repo security spikes; values are corroborated by the two independent reads below.
- **Fast DDS (eProsima, Apache-2.0) — read for understanding only, NO code copied** (clean-room READ is
  authorized for this slice). Files consulted at `/Users/frgo/gbt Dropbox/gbt/projects/fastdds/src/fastdds`:
  - `include/fastdds/rtps/common/EntityId_t.hpp` lines 55-64 (`#if HAVE_SECURITY`) — corroborated the 8
    secure builtin EntityIds (`0xff0003c2/c7`, `0xff0004c2/c7`, `0xff0200c2/c7`, `0xff0101c2/c7`).
  - `src/cpp/rtps/security/cryptography/CryptoTypes.h` lines 27-41 — corroborated the secure submessage
    kinds (`SEC_BODY 0x30`, `SEC_PREFIX 0x31`, `SEC_POSTFIX 0x32`, `SRTPS_PREFIX 0x33`, `SRTPS_POSTFIX 0x34`)
    and the three `GMCLASSID_SECURITY_*_CRYPTO_TOKENS` strings (already pinned in `keyexchange.lisp`).
  - `src/cpp/security/cryptography/AESGCMGMAC_Transform.cpp` lines 1480-1481 — corroborated the KDF
    id_strings `"SessionKey"` (reused `+session-key-id-string+`) and `"SessionReceiverKey"` (new
    `+kdf-label-session-receiver-key+`).
  - `src/cpp/security/accesscontrol/GovernanceParser.cpp` lines 35-52 — corroborated the Governance XML
    element names and the 5 ProtectionKind XSD tokens (`NONE`, `SIGN`, `ENCRYPT`,
    `SIGN_WITH_ORIGIN_AUTHENTICATION`, `ENCRYPT_WITH_ORIGIN_AUTHENTICATION`).
- **Wireshark/tshark 4.6.6 RTPS dissector** (installed; vendor-neutral, OMG-derived) is the Connext-side
  oracle for these constants; live secure-capture confirmation is folded into T12. **No RTI Connext
  source/headers read** — confirmed the RTI Security Plugins are absent
  (`/Applications/rti_connext_dds-7.3.1/lib/arm64Darwin20clang12.0/` has no `libnddssecurity*`).
- **Fixtures** `interop/security-secure-discovery/pki/` — 3 signed governance variants (secure /
  origin-auth / none) + signed permissions, signed by the **reused** Slice-3 Permissions CA and
  referencing the Slice-2 Identity CA (no new CA created). `openssl smime`/`cms -verify` confirmed.
  Throwaway test keys, committed intentionally; no external CA or production PKI consulted.

## M7/P6 — WP-DDS-SECURITY-SECURE-DISCOVERY T2: submessage protection AAD decision (2026-06-27)

§8.5.1.7-.9 submessage protection (SEC_PREFIX/SEC_BODY/SEC_POSTFIX, SIGN+ENCRYPT — `src/dds-security/
crypto/submessage.lisp`). The single design decision needing an external oracle was the **AEAD AAD
composition**, resolved by the controller per the operating contract §4 (the wire is the oracle; match
the readable conformant impl we must interop with at T12) and independently corroborated here.

- **OMG DDS-Security 1.1 §8.5.1.7-.9 / §9.5.3.3** — primary authority for the 3-submessage bracket
  and the CryptoHeader/CryptoContent/CryptoFooter elements; §9.5.3.3.1 Table for the CryptoTransformKind
  octet[4] values. Clause numbers carried from the design + the T0 spike (the DDS-Security 1.1 PDF is
  not in `docs/specs/`); the two values used (AES256_GCM, AES256_GMAC) are corroborated below.
- **eProsima Fast DDS (Apache-2.0) — read for understanding only, NO code copied** (clean-room READ is
  authorized for this slice). File `src/cpp/security/cryptography/AESGCMGMAC_Transform.cpp` at
  `/Users/frgo/gbt Dropbox/gbt/projects/fastdds/src/fastdds`:
  - `serialize_SecureDataBody` (read at lines ~1531-1705): the **ENCRYPT** branch (the `do_encryption`
    arm, ~1607-1686) calls `EVP_EncryptUpdate(e_ctx, output_buffer_raw, …, plain_buffer, …)` to encrypt
    the plaintext with **NO prior `EVP_EncryptUpdate(…, NULL, …)` AAD call** ⇒ **AAD = empty**; the
    SEC_BODY carries the ciphertext (length-prefixed). The **SIGN/auth-only** branch (`!do_encryption`,
    ~1578-1606) `memcpy`s the plaintext out **verbatim** and calls
    `EVP_EncryptUpdate(e_ctx, nullptr, &actual_size, plain_buffer, plain_buffer_len)` ⇒ **AAD = the
    plaintext**, empty ciphertext (the common_mac is a GMAC over the plaintext). Comment at L1580:
    "Auth only. SEC_BODY should not be created. Plain buffer should be copied instead."
  - `deserialize_SecureDataBody` (~1954-2064): symmetric — `do_encryption` reads the BE content length
    then `EVP_DecryptUpdate(plain, …, input, …)` with no prior AAD; auth-only sets `output=nullptr` so
    `EVP_DecryptUpdate(NULL, …, input, body_length)` feeds the body as AAD, then `memcpy`s it out.
  - `encode_datawriter_submessage` (~179-303): `serialize_SecureDataHeader` (the 20-byte CryptoHeader)
    is serialized SEPARATELY from `serialize_SecureDataBody` and **never fed to the cipher** ⇒ the
    CryptoHeader is NOT part of the AAD in either mode (it is implicitly integrity-bound: its
    transformation_key_id/session_id/init_vector_suffix derive the session key + nonce, so tampering
    them fails the GCM tag).
  - `AESGCMGMAC_Types.h` lines 45-54 — the CryptoTransformKind octet[4] values pinned for SIGN-vs-ENCRYPT
    on-wire signalling: `CRYPTO_TRANSFORMATION_KIND_AES256_GCM { {0,0,0,4} }` (ENCRYPT) and
    `CRYPTO_TRANSFORMATION_KIND_AES256_GMAC { {0,0,0,3} }` (SIGN). `+transformation-kind-aes256-gmac+`
    (crypto.lisp) is the new pin; the GCM value was already pinned (Slice-1).
  - **DECISION as implemented (Option A, Fast-DDS-faithful):** ENCRYPT AAD = empty, SEC_BODY =
    ciphertext; SIGN AAD = the plaintext submessage, SEC_BODY = that plaintext verbatim; the wire
    transformation_kind (GCM vs GMAC) is what the decoder dispatches on. The shared AEAD core
    (`%seal-with-km`/`%open-with-km`, transform.lisp) takes the AAD as a PARAMETER so each tier composes
    its own; the CryptoHeader is never folded in here.
- **LATENT INTEROP FINDING #1 — Slice-1 serialized-payload AAD diverges from Fast DDS.** Our shipped
  Slice-1 data-protection tier (`encode-serialized-payload`, §9.5.3.3.4.4) uses **AAD = the 20-byte
  SecureDataHeader**, whereas Fast DDS `serialize_SecureDataBody` for the SERIALIZED-PAYLOAD path
  (`encode_serialized_payload` → `serialize_SecureDataBody(submessage=false)`) takes the same empty-AAD
  ENCRYPT branch as above (no SecureDataHeader in the AAD). This is a real cross-vendor divergence on
  the data-protection tier (it would break byte-exact data-protection interop with Fast DDS). It is
  **NOT changed here** (it is shipped wire + anchors our own byte-exact corpus; reconciling it is a
  separate data-protection decision the controller will carry forward). T2's submessage tier does NOT
  inherit it — the AAD is a parameter, so the submessage tier uses empty/plaintext per Option A.
- **RESOLVED (T2 review fix, 2026-06-27) — SIGN now emits NO SEC_BODY, conformant with §9.5.3.3.4.3 +
  Fast DDS.** The original T2 wire (per the brief's "uniform SEC_BODY") wrapped the SIGN plaintext in a
  SEC_BODY (0x30) + uint32 length prefix. That is **non-conformant**: a conformant GMAC peer computes the
  tag over the *original submessage* (it would MAC different bytes ⇒ tag mismatch ⇒ false REJECT), and the
  recovered "submessage" would start with 0x30 rather than a valid submessageId — both broken by the
  wrapper. The operating contract Global Constraint (OMG conformance is non-negotiable; a false REJECT is
  the worst defect class) governs, so the fix emits the conformant framing:
    * ENCRYPT — unchanged: SEC_PREFIX ‖ SEC_BODY(0x30, length-prefixed ciphertext) ‖ SEC_POSTFIX.
    * SIGN — SEC_PREFIX ‖ <ORIGINAL submessage VERBATIM, no SEC_BODY, no length prefix> ‖ SEC_POSTFIX;
      decode recovers the original by parsing its OWN RTPS submessage header (submessageId ‖ flags ‖
      octetsToNextHeader honoring the embedded E-flag, then octetsToNextHeader octets), verifies the GMAC
      over it (AAD), and returns it. The GMAC value is byte-identical to the prior framing (same AAD = the
      original submessage, same key + nonce); only the wrapping changed. SIGN corpus vector shrinks 88→80.
  Re-corroborated CLEAN-ROOM (read-only, no code copied) against eProsima Fast DDS (Apache-2.0)
  `src/cpp/security/cryptography/AESGCMGMAC_Transform.cpp` at `/Users/frgo/gbt Dropbox/gbt/projects/fastdds/src/fastdds`:
    * `serialize_SecureDataBody` (L1531) — `do_encryption` is true only for AES128/256-**GCM** (L1542-1543);
      the auth-only/**GMAC** branch (`!do_encryption`, L1578-1606) `memcpy`s the plaintext submessage
      **verbatim** onto the wire (L1588) and writes NO SecureBody submessage — comment L1580 verbatim:
      "Auth only. SEC_BODY should not be created. Plain buffer should be copied instead." The ENCRYPT
      branch (L1607+) DOES write `SecureBodySubmessage << flags` (L1617-1619) — so SEC_BODY is
      ENCRYPT-only, exactly the framing the fix now produces.
    * `predeserialize_SecureDataBody` (L2066-2095) returns `(secure_submsg_id == SecureBodySubmessage)`:
      Fast DDS detects encryption by whether a SEC_BODY (0x30) follows SEC_PREFIX; for the SIGN case it
      reads the original submessage's OWN header — submessageId ‖ flags ‖ uint16 length, endianness per
      `flags & BIT(0)` (the E-flag, L2078-2088) — which is exactly our `%read-embedded-submessage` extent
      logic.
  REMAINING T12 NUANCE (live interop only, not a T2 blocker): our GMAC AAD = the FULL original submessage
  octets (header + payload); Fast DDS's auth-only `EVP_*Update` byte-range is set from its
  `body_state`/`body_length` (`deserialize_SecureDataBody` L1954-2049), so the exact GMAC AAD span for
  cross-vendor GMAC verification remains a T12 live-capture reconciliation item — orthogonal to the
  framing, which is now conformant. NO RTI Connext source consulted. CLEAN-ROOM.
- **Wireshark/tshark RTPS dissector** is the vendor-neutral oracle for the secure submessageIds
  (0x30/0x31/0x32, already pinned in T0); live secure-capture confirmation is T12. **No RTI Connext
  source/headers/generated code consulted.** CLEAN-ROOM.

## M7/P6 — WP-DDS-SECURITY-SECURE-DISCOVERY T3: origin authentication (2026-06-27)

Origin authentication (the §9.5.3.3.4.3 *_WITH_ORIGIN_AUTHENTICATION protection kinds): per-matched-
receiver session-key material + a `receiver_specific_macs` list in the CryptoFooter — encode emits one
GMAC per receiver, decode finds + constant-time-verifies its OWN entry in addition to the common_mac.
The two corroboration questions T3 had to settle from the readable conformant impl (the EXACT receiver-MAC
input + nonce, and the receiver-specific session-key KDF) are answered below.

- **OMG DDS-Security 1.1 §9.5.3.3.4.3** — primary authority for the receiver-specific session key and the
  per-receiver MAC. Clause carried from the design + the T0 spike (the DDS-Security 1.1 PDF is not in
  `docs/specs/`); values corroborated below against the Fast DDS direct reads.
- **eProsima Fast DDS (Apache-2.0) — read for understanding only, NO code copied** (clean-room READ is
  authorized for this slice). File `src/cpp/security/cryptography/AESGCMGMAC_Transform.cpp` at
  `/Users/frgo/gbt Dropbox/gbt/projects/fastdds/src/fastdds`:
  - `compute_sessionkey(receiver_specific=true, …)` (read at L1468-1519): the receiver-specific session
    key is `HMAC-SHA256(master_receiver_specific_key, source)` where `source = "SessionReceiverKey"(18) ‖
    master_salt(key_len=32) ‖ session_id(4)` (the label at L1481; the `memcpy` framing L1484-1495). It uses
    `EVP_DigestSign`/`EVP_sha256` over `EVP_PKEY_HMAC` — i.e. HMAC-SHA256, the same primitive as the sender
    session key. **Finding — counter divergence:** Fast DDS does NOT append the `"0001"` counter (the
    `source[18+32+4]` buffer has no room for it). Our `derive-receiver-specific-session-key`
    (`crypto/submessage.lisp`) DOES append it, mirroring our shipped `derive-session-key` and the §9.5.3.3.4.2
    Table-70 framing (the shared `%derive-labeled-session-key`, crypto.lisp). This is the SAME pre-existing
    divergence already present on our COMMON-MAC session key (Slice-1 `derive-session-key`), NOT introduced
    by T3 — it affects cross-vendor live interop (T12) only; our encode/decode are self-consistent and the
    corpus is reproducible across SBCL + Clasp. DECISION: keep the spec-faithful counter; reconcile at T12.
  - `serialize_SecureDataTag` (read at L1708-1827): the per-receiver MAC is a pure GMAC. For each receiving
    entity it (1) derives the receiver-specific session key (L1767-1768), (2) `EVP_EncryptInit(EVP_aes_256_gcm,
    SessionKey, initialization_vector)` — **the SAME 12-octet `initialization_vector` (= session_id ‖
    iv_suffix) as the common_mac**, comment L1771 "Obtain MAC using ReceiverSpecificKey and the same
    Initialization Vector as before" (L1787-1799), (3) `EVP_EncryptUpdate(e_ctx, NULL, &sz, tag.common_mac.data(),
    16)` — feeds **the 16-octet common_mac as AAD with NO ciphertext** (L1800), (4) `EVP_EncryptFinal` then
    `EVP_CIPHER_CTX_ctrl(EVP_CTRL_GCM_GET_TAG, AES_BLOCK_SIZE=16, …)` — the 16-octet GCM tag IS the
    `receiver_mac` (L1807-1816). So: **receiver_mac = AES-256-GCM-GMAC(key = recv_session_key, nonce = the
    common_mac's IV, AAD = common_mac, plaintext = empty)**. This is exactly our
    `compute-receiver-specific-mac (recv-session-key nonce common-mac)` over `dds.dare:aes-256-gcm-seal`
    (empty plaintext → tag). The nonce is load-bearing, hence the 3-argument signature (the brief's 2-arg
    sketch omitted the IV it asked to confirm).
  - `deserialize_SecureDataTag` (read at L2097-2206): the decode side mirrors it — read common_mac + the
    BIG-ENDIAN `sequence_length`, scan entries for the one whose `receiver_mac_key_id == receiver_specific_key_id`
    (MY key id; not-found ⇒ "message does not target this Participant" ⇒ reject, L2123-2138), then derive the
    receiver-specific session key and `EVP_DecryptInit(IV = initialization_vector)` /
    `EVP_DecryptUpdate(NULL, …, common_mac, 16)` / `EVP_CTRL_GCM_SET_TAG(receiver_mac)` / `EVP_DecryptFinal`
    (L2147-2202). Our `%verify-receiver-mac` recomputes the GMAC and constant-time-compares (`%ct-equal`)
    — equivalent to OpenSSL's `EVP_DecryptFinal` tag check; the key_id LOOKUP is not constant-time (key_ids
    are public on the wire), the MAC COMPARE is. **Finding — count endianness:** Fast DDS serializes/parses
    the `receiver_specific_macs` count BIG-ENDIAN (L1824 / L2111); our T1 codec (`parse/serialize-crypto-footer`)
    uses the cursor's little-endian, consistent with our own encode/decode and the rest of our LE wire — a
    T1-owned cross-vendor divergence (live-interop/T12), not changed here.
- **Wireshark/tshark RTPS dissector** — the receiver_specific_macs sub-element is part of the SEC_POSTFIX
  CryptoFooter already pinned in T0/T1; live secure-capture confirmation of the origin-auth footer is folded
  into T12. **No RTI Connext source/headers/generated code consulted.** CLEAN-ROOM.

## M7/P6 — WP-DDS-SECURITY-SECURE-DISCOVERY T4: whole-RTPS-message protection (2026-06-27)

Whole-RTPS-message protection (DDS-Security 1.1 §8.5.1.10-.12 / §9.5.3.3.4 — the `rtps_protection_kind`
transform): protect the ENTIRE submessage stream of a datagram (everything AFTER the 20-octet RTPS Header)
as `SRTPS_PREFIX (0x33)` ‖ `<body>` ‖ `SRTPS_POSTFIX (0x34)`, keyed by the per-participant ParticipantCrypto
KeyMaterial. Same AES-GCM-GMAC mechanism as the §8.5.1.7-.9 submessage tier (T2/T3) over the SHARED
`%encode-secured-region` / `%decode-secured-region` engine (`src/dds-security/crypto/submessage.lisp`); the
tier wrapper is `src/dds-security/crypto/rtps-message.lisp`. The one tier-specific decode question — how to
LOCATE the verbatim body on SIGN, where the protected unit is the whole (multi-submessage) STREAM rather
than one submessage — is settled below from the readable conformant impl.

- **OMG DDS-Security 1.1 §8.5.1.10-.12 / §9.5.3.3.4** — primary authority for the SRTPS bracket and the
  AES-GCM-GMAC framing (the SRTPS submessage kinds 0x33/0x34 were pinned in T0; the CryptoHeader/Content/
  Footer widths in T1). The DDS-Security 1.1 PDF is not in `docs/specs/`; the layout + the SIGN decode-locate
  are corroborated below against the Fast DDS direct reads.
- **eProsima Fast DDS (Apache-2.0) — read for understanding only, NO code copied** (clean-room READ is
  authorized for this slice). File `src/cpp/security/cryptography/AESGCMGMAC_Transform.cpp` at
  `/Users/frgo/gbt Dropbox/gbt/projects/fastdds/src/fastdds`:
  - `encode_rtps_message` (read at L463-602): the wire is `SRTPS_PREFIX ‖ flags ‖ length(u16) ‖
    SecureDataHeader(=20-octet CryptoHeader)` (serialize_SecureDataHeader, L526-541, length = the CryptoHeader
    octet count), then `serialize_SecureDataBody(...)` — **the SAME body function as the submessage tier**
    (ENCRYPT emits a SecureBody/SEC_BODY ciphertext; SIGN copies the plain stream verbatim, no SEC_BODY),
    then `SRTPS_POSTFIX ‖ flags ‖ length(u16) ‖ SecureDataTag(=CryptoFooter)` (L571-582). Confirms our
    `%encode-secured-region` produces the byte-identical SRTPS bracket as the submessage tier with only the
    prefix/postfix submessage ids changed (0x31/0x32 → 0x33/0x34) — DRY, no copy-paste.
  - `decode_rtps_message` (read at L603-805): reads SRTPS_PREFIX + the SecureDataHeader, then
    `predeserialize_SecureDataBody` (L706 → L2066-2094: returns `is_encrypted` = whether the next submessage
    id is SecureBody/SEC_BODY 0x30). **The SIGN decode-locate is a WALK:** when NOT encrypted the loop
    `while (!is_encrypted && (id != SRTPS_POSTFIX)) { … decoder >> length; … decoder.jump(length + body_align);
    decoder >> id; }` (L726-751) skips submessage-by-submessage — reading each 4-octet SubmessageHeader and
    advancing octetsToNextHeader — until the next id equals SRTPS_POSTFIX, accumulating the protected body
    length; then it reads SRTPS_POSTFIX + the SecureDataTag (L753-789). This is exactly our
    `%walk-verbatim-body` (sign-walk-p T): walk to the trailing SRTPS_POSTFIX, the body = the bytes in
    between, then re-read the postfix + CryptoFooter. **DECISION — walk, not compute-from-end:** the postfix
    is NOT fixed-size when origin-auth adds receiver_specific_macs (the CryptoFooter grows with rsm_count, a
    field INSIDE the postfix), so the start of the postfix cannot be computed from the message end without
    parsing it; the forward walk Fast DDS uses handles the variable-size postfix and the multi-submessage
    body uniformly. The ENCRYPT path needs no walk (the SecureBody is the single submessage right after the
    prefix), matching our shared engine's ENCRYPT branch.
  - **Finding — submessage alignment:** Fast DDS re-aligns each skipped submessage to a 4-octet boundary in
    the walk (`body_align = decoder.alignment(…, sizeof(int32_t))`, L744). Our `%encode-secured-region` writes
    the SIGN body VERBATIM with NO inter-submessage padding and our `%walk-verbatim-body` advances by exactly
    octetsToNextHeader (no re-align), so our encode↔decode are self-consistent for any stream. For live
    cross-vendor interop a stream whose submessages are not already 4-aligned could diverge; this is folded
    into the T12 live-peer reconciliation (alongside the pre-existing T1 footer-count-endianness and the
    derive-session-key "0001" KDF-counter divergences). For T4 (our-to-our self-consistency) it is a non-issue
    — RTPS submessages are 4-aligned in the normal case, and the corpus/round-trip/fuzz are reproducible
    across SBCL + Clasp.
- **Wireshark/tshark RTPS dissector** — the SRTPS_PREFIX/SRTPS_POSTFIX submessages + their CryptoHeader/
  CryptoFooter were pinned vendor-neutrally in T0/T1; live SRTPS-capture confirmation is folded into T12.
  **No RTI Connext source/headers/generated code consulted.** CLEAN-ROOM.

## M7/P6 — WP-DDS-SECURITY-SECURE-DISCOVERY T-RECONCILE: align crypto wire to Fast DDS (2026-06-27)

Owner-directed reconciliation (pulled forward from T12) of the foundational AES-GCM-GMAC wire divergences
that sat UNDER every crypto tier (serialized-payload, submessage, origin-auth, whole-RTPS). Three fields
reconciled toward the readable conformant impls. Each was corroborated CLEAN-ROOM against TWO independent
readable implementations (eProsima Fast DDS, Apache-2.0, read locally; Eclipse Cyclone DDS, EPL-2.0/EDL,
read via the public GitHub raw source) — they AGREE on all three, which is strong confirmation. **No RTI
Connext source/headers/generated code consulted.** The OMG DDS-Security 1.1 PDF is not in `docs/specs/` and
its §9.5.3.3.4.2 text was not freely locatable online; the two impls are the oracle (the operating
contract §4 — the wire is the oracle; a false-REJECT / non-interop is the worst defect class).

- **Fix 1 — session-key KDF: NO trailing counter** (`src/dds-security/crypto.lisp`
  `%derive-labeled-session-key`, behind `derive-session-key` AND `derive-receiver-specific-session-key`).
  - Fast DDS `AESGCMGMAC_Transform.cpp` `compute_sessionkey` (read at L1456-1519, at
    `/Users/frgo/gbt Dropbox/gbt/projects/fastdds/src/fastdds`): `unsigned char source[18 + 32 + 4]`;
    `seq="SessionKey"` (10) / `receiver_seq="SessionReceiverKey"` (18); `memcpy(source, seq, 10)` then
    `memcpy(source+sourceLen, master_salt.data(), key_len)` (key_len=32) then
    `memcpy(source+sourceLen, &session_id, 4)`; HMAC-SHA256 over `source[0:sourceLen]`. The input is exactly
    `label ‖ master_salt(32) ‖ session_id(4)` (sender 46 B / receiver 54 B) — **the `source` buffer
    (18+32+4=54) has NO room for a trailing counter.**
  - Cyclone DDS `crypto_utils.c` `crypto_calculate_session_key` (→ `crypto_calculate_key_impl`, read via
    raw.githubusercontent.com): `memcpy(buffer, prefix, strlen(prefix)); memcpy(&buffer[strlen(prefix)],
    master_salt, key_bytes); memcpy(&buffer[strlen(prefix)+key_bytes], &id, sizeof(id))`, size =
    `strlen(prefix)+key_bytes+sizeof(id)` — **no counter** (AES-256 total = 10+32+4 = 46 B). AGREES with Fast DDS.
  - Our prior code appended a `"0001"` counter (a T0-spike belief cited to "§9.5.3.3.4.2 Table 70"); both
    impls omit it, so it was REMOVED (the dead `+session-key-counter-string+` constant, internal/unexported,
    was deleted; consumers' docstrings + `crypto/constants.lisp` updated). **Session_id note (orthogonal,
    out of scope):** the two impls differ ONLY on the session_id byte order WITHIN the KDF input — Fast DDS
    `memcpy(&session_id,4)` (host/LE order), Cyclone `ddsrt_toBE4u(id)` (BE). We splice the wire
    `SecureDataHeader.session_id` octet[4] VERBATIM, which is Fast-DDS-faithful (its wire session_id ==
    its KDF session_id bytes, both from `memcpy(&session->session_id,4)`); this is NOT one of the three
    reconciled fields and is unchanged here.
- **Fix 2 — CryptoFooter `receiver_specific_macs_count` BIG-ENDIAN** (`crypto/crypto-header.lisp`
  `serialize/parse-crypto-footer`).
  - Fast DDS `serialize_SecureDataTag` (L1822-1825 / L1938): `serializer.serialize(length,
    Cdr::Endianness::BIG_ENDIANNESS)`; `deserialize_SecureDataTag` (L2110-2111):
    `decoder.deserialize(sequence_length, Cdr::Endianness::BIG_ENDIANNESS)`. The count is FORCED big-endian
    regardless of the submessage's E-flag (which is LITTLE on LE targets, `flags = BIT(0)`, L234-239).
  - Cyclone `crypto_transform.c`: `footer->postfix.receiver_specific_macs._length = ddsrt_toBE4u(length+1)`
    (`add_specific_mac`); `postfix->length = ddsrt_fromBE4u(*(uint32_t*)submsg_view.ptr)` (`read_secure_postfix`).
    AGREES.
  - Our T1 codec used the cursor's little-endian; now forced BE via the new `%put-u32-be`/`%get-u32-be`.
- **Fix 3 — CryptoContent length BIG-ENDIAN (SIBLING found in the Step-2 audit)** (`crypto/crypto-header.lisp`
  `serialize/parse-crypto-content`). The audit of every multi-byte crypto-wire integer found the
  `crypto_content` length is the SAME class of divergence as the footer count and ALSO diverged.
  - Fast DDS `serialize_SecureDataBody` writes a dummy `cnt_length` then OVERWRITES it big-endian:
    `serializer.serialize(cnt_length, Cdr::Endianness::BIG_ENDIANNESS)` (L1682). It is read big-endian on
    EVERY decode path: `decode_serialized_payload` (the Slice-1 path) `decoder.deserialize(body_length,
    BIG_ENDIANNESS)` (L1412); `deserialize_SecureDataBody` (submessage + RTPS paths)
    `decoder.deserialize(protected_len, BIG_ENDIANNESS)` (L2006). `encode_serialized_payload` (L76-177)
    routes through the same `serialize_SecureDataBody`, so the serialized-payload tier's length is BE too.
  - Cyclone: `content->length = ddsrt_toBE4u((uint32_t)encrypted_data.x.length)` (`encode_submessage_encrypt`);
    `estate->body.data.length = ddsrt_fromBE4u(*(uint32_t*)payload->ptr)` (`split_encoded_serialized_payload`).
    AGREES — big-endian.
  - Our codec used the cursor's little-endian; now forced BE via `%put-u32-be`/`%get-u32-be`. This is why the
    brief's Step-2 audit instruction existed: the brief's "Key facts" pre-analysis (only count>0 footers
    change) covered the footer count but not this body-length sibling.
- **Sibling-audit conclusion (Step 2):** the CryptoContent length (Fix 3) is the ONLY additional diverging
  integer. The submessage `octetsToNextHeader` (uint16, SEC_PREFIX/BODY/POSTFIX + SRTPS) follows the RTPS
  E-flag (LITTLE on LE) in BOTH us and Fast DDS — a MATCH, not a sibling. All remaining crypto-wire fields
  are opaque octet arrays (transformation_kind[4], transformation_key_id[4], session_id[4],
  init_vector_suffix[8], common_mac[16], receiver_mac_key_id[4], receiver_mac[16]) and are NOT
  endianness-sensitive (Fast DDS `std::array<uint8_t,N>` byte-copy; our put-octets/get-octets).
- **Mechanism:** new private `%put-u32-be`/`%get-u32-be` in `crypto/crypto-header.lisp` force big-endian by
  save/set/restore of the cursor endianness around the shared `put-u32`/`get-u32` (DRY), so the
  surrounding LE RTPS stream is untouched — exactly Fast DDS's per-field `BIG_ENDIANNESS` override. No frozen
  contract (dds.core.buffer) changed.
- **Corpus regenerated:** the fix changes the reference bytes for the Slice-1 payload vector + T1
  byte-identity, T2 ENCRYPT+SIGN, T3 ENCRYPT+SIGN origin-auth (count now BE), and T4 ENCRYPT+SIGN. Recomputed
  DETERMINISTICALLY (`make-test-key-material`, iv-counter=0, session_id=0) and re-pinned as REAL `equalp`
  literal-vector assertions (NOT weakened to round-trip-only). Structural fields verified by inspection
  (ct_len → BE `00000020`/`0000002c`; rsm_count>0 → BE `00000002`; rsm_count=0 unchanged; headers unchanged;
  T3 prefix/common_mac still == T2). Byte-IDENTICAL on SBCL + Clasp (same OpenSSL ≥ 3.5). This intentionally
  changes shipped Slice-1 serialized-payload wire (the divergences sat under it).
- **This RESOLVES** the two divergences logged in the T1 and T3 entries above (footer-count endianness;
  derive-session-key "0001" counter) AND the body-length sibling — they are no longer deferred to T12. T12
  remains the LIVE cross-vendor capture; the remaining open item folded into it is the SIGN inter-submessage
  4-octet re-alignment (T4 finding), unrelated to these three.

## M7/P6 — WP-DDS-SECURITY-SECURE-DISCOVERY T7: PVMS bootstrap-key derivation + protection-kind (2026-06-28)

The reliable ParticipantVolatileMessageSecure (PVMS) builtin endpoint's protection KeyMaterial is derived
DIRECTLY from the authenticated SharedSecret + the two handshake challenges (DDS-Security 1.1 §9.5.3.1, no
token exchange — PVMS is the bootstrap carrier for the OTHER tokens). Two interop-critical facts pinned —
the EXACT derivation and the protection-kind (ENCRYPT vs SIGN) — corroborated CLEAN-ROOM (read-only, no code
copied) against eProsima Fast DDS (Apache-2.0), read locally at
`/Users/frgo/gbt Dropbox/gbt/projects/fastdds/src/fastdds`. **No RTI Connext source/headers/generated code
consulted.** A second readable impl (Cyclone/OpenDDS) was NOT separately read for this fact because the
underlying KxKey/KxSalt KDFs were ALREADY dual-corroborated in the AUTH-KEYX spike (see the 2026-06-26 entry
above); T7 only confirms those same KDFs are how Fast DDS assembles the VOLATILE-endpoint KeyMaterial.
Confidence: **high** (the Fast DDS read is unambiguous + the KDFs are independently pinned).

- **File read:** `src/cpp/security/cryptography/AESGCMGMAC_KeyFactory.cpp`.
  - `create_kx_key(out, first, cookie, second, shared_secret)` (L48-95): `out = HMAC-SHA256(key =
    SHA-256(first(32) ‖ cookie(16) ‖ second(32)), data = shared_secret)` — `uint8_t tmp_data[32+16+32]`,
    `EVP_Digest(...EVP_sha256...)` then `EVP_DigestSign...` over `shared_secret`. IDENTICAL to our
    `%kx-create-key` (keyexchange.lisp), confirming `derive-kx-key`/`derive-kx-salt` are the right primitives.
  - `register_matched_remote_participant(...)` (L231+), the `Participant2ParticipantKxKeyMaterial`
    block "// based on the SharedSecret" (L250+): `challenge_1 = find_data_value(shared_secret,
    "Challenge1")`, `challenge_2 = ..."Challenge2"`, `shared_secret_ss = ..."SharedSecret"`;
    `buffer.transformation_kind = c_transfrom_kind_aes256_gcm` (L296);
    `buffer.sender_key_id.fill(0)` (L297); `buffer.receiver_specific_key_id.fill(0)` (L298);
    `buffer.master_receiver_specific_key.fill(0)` (L299);
    `create_kx_key(buffer.master_salt,       challenge_1, "keyexchange salt", challenge_2, shared_secret_ss)` (L303);
    `create_kx_key(buffer.master_sender_key, challenge_2, "key exchange key", challenge_1, shared_secret_ss)` (L310).
    So the PVMS KeyMaterial = { kind=AES256-GCM; master_salt=KxSalt; master_sender_key=KxKey; sender_key_id=0;
    receiver fields=0 }. Mapped to ours: `master_salt = derive-kx-salt(ss, c1, c2)`,
    `master_sender_key = derive-kx-key(ss, c1, c2)` (BYTE-for-byte, both via `create_kx_key` with the same
    first/cookie/second ordering), `sender_key_id = #(0 0 0 0)`. This is exactly `%pvms-derive-bootstrap-km`.
  - Same function (L327-335): that Kx `buffer` is pushed into the builtin key-exchange WRITER handle —
    `wHandle->EndpointPluginAttributes = PLUGIN_ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_SUBMESSAGE_ENCRYPTED`
    (L329); `wHandle->Participant_master_key_id = c_transformKeyIdZero` (L330);
    `wHandle->EntityKeyMaterial.push_back(buffer)` (L334); `Entity2RemoteKeyMaterial.push_back(buffer)` (L335).
    **IS_SUBMESSAGE_ENCRYPTED → PVMS protection-kind = ENCRYPT** (not SIGN). So our codec is invoked as
    `encode/decode-datawriter-submessage km :encrypt …`.
  - `register_local_datawriter(...)` (L405-417): when a property `dds.sec.builtin_endpoint_name` equals
    `"BuiltinParticipantVolatileMessageSecureWriter"` → `use_kx_keys = true`; then
    `if (use_kx_keys) return participant_handle->Writers.at(0).get();` — i.e. the PVMS local writer REUSES the
    Kx-key handle built above (it does NOT mint a random per-endpoint key). `register_local_datareader(...)`
    (L629) does the same for `"BuiltinParticipantVolatileMessageSecureReader"`.
  - `c_transfrom_kind_aes256_gcm = CRYPTO_TRANSFORMATION_KIND_AES256_GCM` (`AESGCMGMAC_Types.h:65`) =
    our `+transformation-kind-aes256-gcm+` {0,0,0,4}.
- **Implementation:** `src/dds-disc/volatile-secure.lisp` `%pvms-derive-bootstrap-km` REUSES
  `derive-kx-salt` (→ master_salt) + `derive-kx-key` (→ master_sender_key) (DRY — the already-pinned §9.5.3
  KDFs), `sender_key_id = #(0 0 0 0)`, kind = AES256-GCM, into a §9.5.2 `key-material`. The endpoint reuses
  the M2 reliable engine (HEARTBEAT/ACKNACK) configured VOLATILE (KEEP_ALL, no durability); each DATA is
  `:encrypt`-protected with the per-matched-remote bootstrap KM.
- **CARRY (T8) — bidirectional nonce uniqueness.** The Kx KeyMaterial is SYMMETRIC across the pair (both
  sides derive identical key bytes). Fast DDS sets a DISTINCT `Session.session_id` per remote crypto
  (register_matched_remote_participant L319-323: `session_id = max(); if (== local) session_id -= 1`), which
  separates the two directions' nonces. Our codec currently uses the Slice-1 `+fixed-session-id+` (all-zeros),
  so two sides encoding under the shared key from iv-counter 0 would COLLIDE nonces. T7 traffic is
  one-directional per exchange (no collision); T8 (bidirectional token exchange) MUST give the two roles
  disjoint nonce spaces (distinct session_ids or iv ranges). Flagged in the source + report; never silent.

## M7/P6 — WP-DDS-SECURITY-SECURE-DISCOVERY T8: crypto-token exchange over PVMS + :keyed promotion (2026-06-28)

T8 wires the §8.5.2 crypto-token exchange onto the reliable PVMS endpoint (T7) and drives the §7.2
`:authenticated→:keyed` promotion through the crypto-manager (T6). Three interop/safety facts:

- **DISJOINT per-role nonce spaces (safety-critical; resolves the T7 carry above).** The PVMS bootstrap KM
  is SYMMETRIC, the submessage codec's `session_id` was the Slice-1 `+fixed-session-id+` (all-zeros) and each
  KeyMaterial's `iv-counter` starts at 0 — so if BOTH directions encoded PVMS submessages with `session_id=0`
  from `iv_suffix=0` they would reuse the IDENTICAL (session-key, nonce) pair → CATASTROPHIC AES-GCM reuse
  (NIST SP 800-38D §8.3: confidentiality AND integrity break). Resolution: thread a per-role 4-octet
  `session_id` into the PVMS encode path (`dds.disc:%pvms-role-session-id`, threaded through
  `encode-datawriter-submessage :session-id` → `%encode-secured-region`; default stays `+fixed-session-id+`
  so the Slice-1/T2/T4 byte-exact corpus is UNCHANGED — verified: the 7 crypto corpus tests stay green).
  Rule: the lexicographically GREATER 12-octet GUID prefix is the deterministic "winner" (both peers agree;
  RTPS GUIDs are unique); `base = (2^31 | fold(winner-prefix))` (high bit set → non-zero); the winner's
  outbound `session_id = base-1`, the loser's = `base`. Distinct (`base ≠ base-1`), both non-zero, both
  distinct from the all-zero non-PVMS value. Because the session key is derived from `session_id` AND the
  nonce is `session_id ∥ iv_suffix`, the two directions use DIFFERENT session keys AND non-overlapping
  nonces. DECODE needs no agreement — the codec reads `session_id` from the wire CryptoHeader, so the value
  is self-describing (interop decode works regardless of the peer's derivation). Corroborated CLEAN-ROOM
  (read-only, no code copied) against eProsima Fast DDS (Apache-2.0) `AESGCMGMAC_KeyFactory.cpp`
  `register_matched_remote_participant` (per-remote `Session.session_id = max(...)` with a `-=1` tiebreak
  that separates the two directions). Our exact base derivation is our-implementation-choice (only per-role
  DISTINCTNESS is load-bearing for our-to-our; the wire self-describes). RTI source NEVER read. Concrete
  example (test prefixes all-0x0B / all-0x16): A→B `session_id=0x96161616`, B→A `0x96161615` (differ by 1,
  both non-zero); the prior all-zero scheme gave both `0x00000000` (the demonstrated RED for the no-reuse
  property). Structural test guard: `run-secure-discovery-keyed-test` asserts the two roles' session_ids
  DIFFER and are non-zero. INTEROP NOTE (deferred to T12, live Fast DDS): cross-vendor A↔Fast-DDS no-reuse
  on the shared Kx key would need our base value to MATCH Fast DDS's exact rule; since we couldn't read the
  exact `max()` operand bytes (Fast DDS source not on disk this run; the T7 author's line-referenced
  paraphrase is the corroboration), our value derivation may differ — harmless for our-to-our (the headline
  T8 deliverable) and for cross-vendor DECODE (self-describing wire), flagged for the live T12 cross-vendor run.
- **Conformant token payload — KxKey app-encryption DROPPED (design §6.5).** KEYX (interim) KxKey-AEAD-wrapped
  the crypto-token payload over best-effort PSM. The conformant path: the §9.5.2 KeyMaterial rides as a
  PLAINTEXT DataHolder (`dds.security:serialize-crypto-token-plain` / `parse-crypto-token-plain` — the 88-octet
  KeyMaterial CDR inside the existing `handshake-token->dataholder` framing, no nonce/cipher) INSIDE the
  PVMS submessage-protected message; the PVMS ENCRYPT (T7 bootstrap key) is the confidentiality boundary. The
  KxKey-wrap codec (`serialize-crypto-token`/`parse-crypto-token`) is retained for the KEYX KAT regression but
  is off the live exchange path. Token classes (T0-pinned): participant→`participant_crypto_tokens`,
  writer→`datawriter_crypto_tokens`, reader→`datareader_crypto_tokens` (§9.5.2.2).
- **KEYX per-writer KM migration (reconciliation #2).** KEYX exchanged the participant's single user-writer
  KeyMaterial under `participant_crypto_tokens` over best-effort PSM into the auth-manager `writer-km-table`
  + per-remote `auth-remote-remote-km`, with a bespoke CRYPTO-KEYS resolver. T8 RETIRES that entire path
  (no parallel token paths): the user writer/reader are registered as crypto-manager LOCAL-ENTITY-CRYPTO
  (keyed by the node's user-writer-id/user-reader-id) and exchanged as `datawriter/datareader_crypto_tokens`
  over reliable PVMS alongside the secure-SEDP builtin EntityCrypto, landing in the crypto-manager
  remote-entity registries (keyed by the source_endpoint_key GUID + the transformation_key_id index). The
  user-data encode/decode resolver is now `cm-decode-keys` (installed on `:keyed` by `%cm-try-promote`). The
  KEYX tests moved with it (`run-auth-manager-handshake-test` + `run-auth-encrypted-pubsub-keyx-test` now
  assert the crypto-manager registries, not the retired `writer-km-table`/`auth-remote-remote-km`); both stay
  green on the migrated PVMS path. Promotion gate: ParticipantCrypto + the secure-SEDP publications-secure-writer
  (DW) + subscriptions-secure-reader (DR) all installed → `:keyed`.

## M7/P6 — WP-DDS-SECURITY-SECURE-DISCOVERY T-ORIGINAUTH: origin-auth for the builtin secure endpoints (2026-06-28)

Wired the `*_WITH_ORIGIN_AUTHENTICATION` discovery tier (receiver-specific MACs, §9.5.3.3.4.3) for the builtin
secure-SEDP endpoints: origin-auth EntityCrypto registration + the receiver-specific KeyMaterial exchange (the
120-byte CDR form) + the secure-SEDP receiver-MAC resolvers, replacing T9's fail-closed refusal. The receiver
session-key KDF + per-receiver-MAC INPUT were already corroborated in T3 (this section adds the KeyMaterial CDR
receiver-key carry + the key model).

- **OMG DDS-Security 1.1** — §9.5.2 Table 65 (`CryptoTransformKeyMaterial`: `receiver_specific_key_id` octet[4]
  + `master_receiver_specific_key` sequence<octet,32>), §9.5.3.3.4.3 (origin authentication: per-receiver MAC
  under the RECEIVER's receiver-specific key, keyed by the receiver's `receiver_specific_key_id`), §9.4.1.2.3
  (`discovery_protection_kind` ProtectionKind incl. the `*_WITH_ORIGIN_AUTHENTICATION` variants). PDF binary;
  clause numbers cited in the source docstrings.
- **eProsima Fast DDS (Apache-2.0) — source read for understanding only; no code copied.**
  File `src/cpp/security/cryptography/AESGCMGMAC_KeyExchange.cpp` at
  `/Users/frgo/gbt Dropbox/gbt/projects/fastdds/src/fastdds`:
  - `KeyMaterialCDRSerialize()` (read at L380-458): corroborated the 120-byte origin-auth CDR form. The
    `receiver_specific_key_id` is written as 4 octets (L432-438) accumulating `has_specific_key` = OR of those
    4 octets; when `has_specific_key == 0` the trailer is 4 zero octets (the 88-byte absent form, L440-444),
    otherwise a `master_receiver_specific_key` sequence = 3 zero pad + 1 length octet (`key_len` = 0x20 for
    AES256) + 32 key octets (L445-453). Our `%serialize-km-cdr` (`src/dds-security/auth/keyexchange.lisp`)
    keys the 88-vs-120 choice on the SAME `has_specific_key` discriminator (non-zero `receiver_specific_key_id`)
    and emits the identical pad(3)+len(0x20)+key(32) layout — byte-identical to the prior 88-byte serializer
    when the receiver id is all-zero (the SIGN/ENCRYPT path is unchanged).
  - `KeyMaterialCDRDeserialize()` (read at L460-530): the decode mirror — `has_specific_key` = OR of the
    `receiver_specific_key_id` octets (L511-517); non-zero -> skip 3 pad, read the 1 length octet, `memcpy`
    32 key octets (L519-528). Our `%parse-km-cdr` accepts both the 88- and 120-octet forms with the same
    discriminator + a fail-closed form/marker consistency check, and RETAINS the receiver key so the
    matched-remote EntityCrypto the crypto token installs keeps the remote's origin-auth receiver key.
  No code was copied. Influence: corroboration only; the constants are pinned from the OMG clause; Fast DDS
  confirms the framing. Cross-vendor (Connext) CDR/wire alignment for origin-auth is deferred to Slice 5 / ADR 0034
  (the same NEEDS-VERIFICATION carry as the 88-byte T8 framing).
- **Origin-auth KEY MODEL (owner-directed, corroborated against Fast DDS `serialize_SecureDataTag` T3 read).**
  The receiver-specific MAC uses the RECEIVER's key: sender A, for each matched remote, GMACs the common_mac
  under the matched-remote READER's receiver-specific session key (derived from that reader's
  `master_receiver_specific_key`, received in its crypto token) and tags it with that reader's
  `receiver_specific_key_id`; receiver B verifies the footer entry tagged with its OWN
  `receiver_specific_key_id` under its OWN `master_receiver_specific_key`. For the builtin secure-SEDP tier the
  receiving endpoint is the matched secure-SEDP READER (publications writer 0xff0003c2 <-> reader 0xff0003c7;
  subscriptions writer 0xff0004c2 <-> reader 0xff0004c7), so only the secure-SEDP readers are minted with a
  receiver-specific key (the writers encode under the matched remote reader's key, never their own). The
  per-receiver session-key KDF (`derive-receiver-specific-session-key`) uses the SENDER (writer) `master_salt`,
  which both sides share (the receiver holds the writer's KeyMaterial via the token exchange) — corroborated in
  the T3 section above (`compute_sessionkey(receiver_specific=true)` source ordering). NEVER read RTI Connext source.

## M7/P6 — WP-DDS-SECURITY-SECURE-DISCOVERY T10: rtps_protection engagement (whole-datagram, live path) (2026-06-28)

Engaged the §8.5.1.10-.12 whole-RTPS-message codec (T4) on the live send / `%handle-datagram` data path: once two
participants are `:keyed`, user-data datagrams are wrapped `RTPS-Header ‖ SRTPS_PREFIX ‖ SEC_BODY ‖
SRTPS_POSTFIX` keyed by the per-pair ParticipantCrypto; SPDP + PSM are exempt. No NEW external source was read —
the SRTPS layout/kinds are T0/T4-pinned, the AES-GCM-GMAC mechanism is T1-T4, and the participant-level origin-auth
key model is the T-ORIGINAUTH model applied at the participant tier.

- **OMG DDS-Security 1.1** — §8.5.1.10-.12 (`encode/decode_rtps_message`: the SecureRTPSPrefix/SecureRTPSPostfix
  whole-message transform keyed by the ParticipantCrypto), §9.4.1.2.3 (`rtps_protection_kind` ProtectionKind incl.
  the `*_WITH_ORIGIN_AUTHENTICATION` variants), §9.5.3.3.4.3 (per-receiver MAC under the receiver's
  receiver-specific key). §7.4.5 / §8.5.1.10: the bootstrap **SPDP** and the **ParticipantStatelessMessage** (PSM)
  are NOT subject to rtps_protection (they precede keying). Clause numbers cited in the source docstrings.
- **Engagement gating (implementation choice, no external source).** rtps_protection is per-pair: the send wrap is
  gated on the destination being `:keyed` (its ParticipantCrypto is held — `cm-decode-participant-km` non-NIL) AND
  governance `rtps_protection_kind ≠ NONE`. SPDP is structurally exempt (it is sent via `%send-paramlist`, never
  through the wrap chokepoint `%send-raw-buf`); PSM is exempt because it is sent pre-keying (the dest is not yet
  `:keyed`). The receive side decrypts any inbound `SRTPS_PREFIX` (0x33) datagram keyed by the source-prefix
  ParticipantCrypto and fails closed (drop) on an unknown/not-keyed source or an undecryptable bracket.
- **Participant-level origin-auth KEY MODEL (the T-ORIGINAUTH model at the participant tier).** A MACs the
  common_mac under remote B's ParticipantCrypto receiver-specific key (learned from B's ParticipantCryptoToken,
  §9.5.2); B verifies the footer entry tagged with its OWN `receiver_specific_key_id` under its OWN
  `master_receiver_specific_key`. rtps_protection is per-pair (one datagram → one destination participant), so the
  encode `:receivers` list is exactly that one remote's descriptor and decode's `my-receiver-key` is the local
  participant's own — `cm-rtps-encode-receivers` / `cm-rtps-decode-receiver` mirror the entity-level
  `cm-secure-sedp-encode-receivers` / `-decode-receiver` (T-ORIGINAUTH) at the participant level. NEVER read RTI
  Connext source.
- **Scope (documented residual).** T10 wraps the USER DATA PLANE (the hot path); the builtin metatraffic (secure
  SEDP, PVMS, plain SEDP, liveliness, TypeLookup) flows plain (secure SEDP carries its own §8.5.1.7-.9 submessage
  protection). The hot-path NFR-MEM migration reuses the node send/receive BUFFER in place (no per-datagram
  message-sized array); the residual per-datagram heap is the codec's `→octets` return + AEAD intermediates (the
  inherited T4 carry) + one plain-region subseq (measured in `bench/report/2026-06-28-wp-secure-discovery-t10.md`).
  Wrapping the builtin metatraffic + a fully zero-alloc into-buffer AEAD codec are the documented follow-ons.

## WP-DDS-SECURITY-SECURE-DISCOVERY T12 — live Fast DDS-Security cross-vendor (2026-06-28)

Built a **SECURITY=ON** eProsima Fast DDS v3.6.1 (Apache-2.0) from the present source tree and ran it
live against our stack to find cross-vendor secure-discovery wire divergences. Fast DDS source read for
understanding only (clean-room; no code copied). RTI Connext source NEVER read. Files consulted + the
constant/behaviour each corroborates:

- `src/cpp/rtps/security/SecurityManager.cpp:933-938,1462-1470` — ParticipantStatelessMessage SerializedPayload
  carries the 4-octet CDR encapsulation header (`addOctet 0`, `DEFAULT_ENCAPSULATION`, `addUInt16 0`), read
  back on receive. Corroborates fix #1 (our PSM omitted it). `:605` — `discovered_participant` calls
  `security_attributes().match(...)` (with `SecurityMaskUtilities.h` `security_mask_matches`: lenient when
  either IS_VALID bit is clear) — so a missing PID_PARTICIPANT_SECURITY_INFO is NOT a discovery blocker.
- `src/cpp/security/accesscontrol/Permissions.cpp:354,408` — governance/permissions parsed with
  `SMIME_read_PKCS7` + `PKCS7_verify(..., PKCS7_TEXT|PKCS7_NOVERIFY|PKCS7_NOINTERN)`; PKCS7_TEXT requires the
  multipart/signed `Content-Type: text/plain` MIME container (NOT PEM PKCS7). `:632,1047` — subject_name match
  via `rfc2253_string_compare(grant.subject_name, cert_sn_rfc2253_)`. Corroborates the .smime MIME-format fix +
  fix #3 (RFC2253 subject DN). `:255-256,464-469` PID_PARTICIPANT_SECURITY_INFO (0x1005) wire = {uint32
  security_attributes, uint32 plugin_security_attributes}.
- `src/cpp/security/accesscontrol/GovernanceParser.cpp:73-88,99-135` — governance root is `<dds>` with
  `<domain_access_rules>` as a DIRECT child (rejects any other first child). Corroborates fix #2 (our
  non-conformant `<policies>` wrapper).
- `src/cpp/security/authentication/PKIDH.cpp:1039-1056` — IdentityToken class_id `DDS:Auth:PKI-DH:1.0` +
  properties dds.cert.sn/dds.cert.algo/dds.ca.sn/dds.ca.algo (names match ours).
- `src/cpp/rtps/messages/CDRMessage.cpp:828-906` — **`addProperty`/`readProperty` + `addBinaryProperty`/
  `readBinaryProperty` serialize/parse a Token Property/BinaryProperty as `{name,value}` ONLY — the
  `propagate` flag is a local include-filter, NEVER on the wire.** Corroborates the PRIMARY residual divergence
  (#5): our token codec writes/reads a spurious 4-octet `propagate` field per property, misaligning every
  cross-vendor token (IdentityToken/handshake/crypto/permissions) — the §8.7 handshake rejects at the remote
  IdentityToken parse. Spec-conformant fix = drop the propagate field across our Property/BinaryProperty codec
  + regenerate the token corpus (a slice-wide change; Slice-5 / dedicated WP).
- `src/cpp/rtps/security/accesscontrol/{ParticipantSecurityAttributes.h,SecurityMaskUtilities.h}` — the
  Participant + Plugin security-attribute mask bit layout + `match`/`security_mask_matches` semantics.
- `examples/cpp/security/{PublisherApp.cpp,SubscriberApp.cpp,CLIParser.hpp,secure_*_profile.xml,main.cpp}` —
  the headless secure HelloWorld peer used as the live oracle (topic HelloWorldTopic, type HelloWorld).

## WP-DDS-SECURITY-SECURE-DISCOVERY T13 — capstone provenance closeout (2026-06-28)

The Slice-4 capstone (ADR 0036 + wiki/README/`verification.csv` + this closeout + the
`src/dds-tests/security-test.lisp:15` stale-docstring fix + the final dual-impl gate sweep) consulted **no
new external source** — it is documentation + verification only. Every Fast DDS (Apache-2.0, read for
understanding only) and Eclipse Cyclone DDS source consulted across the slice is logged in the entries above:
T0 (secure EntityIds + submessage kinds + KDF labels + ProtectionKind table), T2 (the AESGCMGMAC_Transform
submessage AAD), T3 (the receiver-specific-MAC input), T4 (the SRTPS body-walk), T-RECONCILE (the no-counter
session-key KDF + the big-endian footer-count / crypto_content-length, Fast DDS **and** Cyclone), T7 (the
PVMS bootstrap-key derivation), T8 (the per-role `session_id` derivation), T-ORIGINAUTH (the 88/120-byte
KeyMaterial CDR + the §9.5.3.3.4.3 receiver-key model), T10 (the participant-tier origin-auth), and T12 (the
live Fast DDS-Security peer + the propagate-byte / governance-root / RFC2253-DN / S-MIME corroborations).
**RTI Connext source, headers, and generated code were never read at any point in this slice — clean-room.**
The DDS-Security 1.1 PDF could not be located in `docs/specs/` (only RTPS/DCPS/XTypes are present); the clause
sub-numbers are carried from the design/spike, every *value* dual-corroborated against Fast DDS + the tshark
RTPS-security dissector (the propagate-byte fix's Slice-5 carry explicitly requires pinning the actual OMG
clause for the on-wire Property layout).

## WP-DDS-SECURITY-FASTDDS-INTEROP T0 — pin the §9.3.4 Property serialization (Slice 5, 2026-06-28)

Slice-5 spike. Re-confirmed the live SECURITY=ON Fast DDS v3.6.1 peer (build intact from T12; runs) and
reproduced the live baseline (ours↔Fast DDS, GOV=none, both directions: SPDP `discovered=2`, auth REJECT at
the remote IdentityToken — `captures/ssd-none-{ours2fast,fast2ours}-ours.log`). **Pinned the conformant
on-wire `Property`/`BinaryProperty` layout the T13 closeout flagged as the explicit Slice-5 carry.** Sources
consulted for understanding only (clean-room; no code copied). **RTI Connext source NEVER read.**

- **OMG (normative IDL, newly obtained)** — `dds_security_plugins_spis.idl` (DDS-SECURITY/20170901), fetched
  from `https://www.omg.org/spec/DDS-SECURITY/20170901/dds_security_plugins_spis.idl`: `Property_t {string
  name; string value; boolean propagate;}`, `BinaryProperty_t {string name; OctetSeq value; boolean
  propagate;}`, `DataHolder {string class_id; @optional PropertySeq properties; @optional BinaryPropertySeq
  binary_properties;}`. `propagate` is a **plain boolean with NO `@non-serialized` annotation** — the IDL-
  literal reading (what our codec did) would emit it; the spec text + both implementations treat it as a
  *local* flag, never serialized. This is the root-cause tension. (The DDS-Security 1.1 PDF is still absent
  from `docs/specs/`; the IDL is the OMG-published normative artifact used in its place.)
- **Fast DDS (Apache-2.0)** — NEW files/lines beyond the T12 `CDRMessage.cpp:828-906` entry:
  - `include/fastdds/rtps/common/Property.hpp:174-191` `PropertyHelper::serialized_size` — `name`+`value`
    sizes only `if (propagate())`, else `return 0`; no byte for `propagate`.
  - `include/fastdds/rtps/common/BinaryProperty.hpp:172-189` `BinaryPropertyHelper::serialized_size` — same
    (octet-seq value).
  - `src/cpp/rtps/messages/CDRMessage.cpp:908-929` `addPropertySeq` — wire count = `number_to_serialize` =
    count of `propagate==true` properties only.
  - `src/cpp/rtps/messages/CDRMessage.cpp:602-638` `addOctetVector` — `add_final_padding` controls the
    octet-seq trailing pad (the hash path passes `false`).
  - `src/cpp/security/authentication/PKIDH.cpp:1396-1410` — hash_c1/c2 = `SHA256` over
    `addBinaryPropertySeq(&msg, …, /*add_final_padding=*/false)` with **`msg.msg_endian = BIGEND`**:
    confirms the challenge-hash input is the same no-`propagate` serialization, **Big-Endian** (so our
    `handshake.lisp` BE endianness is already correct — only the propagate byte must drop).
- **Eclipse Cyclone DDS (EPL-2.0, GitHub)** — `src/security/core/src/dds_security_serialize.c`
  (`eclipse-cyclonedds/cyclonedds`, raw.githubusercontent.com): `DDS_Security_Serialize_Property` writes
  `name`+`value` only; `DDS_Security_Serialize_BinaryProperty` writes `name`+`OctetSeq value` only — no
  `propagate` field. Independent corroboration of the Fast DDS finding.

Resolution PINNED (T1 consumes): EMIT `name`+`value` only (drop the 4-octet `propagate`+pad) at the 3 codec
sites (`wire.lisp %cdr-binary-property-le`, `identity.lisp %cdr-property-le`, `handshake.lisp
%cdr-binary-property-be`) + the matching decode skips + the token corpus regen; `keyexchange.lisp` inherits
the fix via the shared `handshake-token->dataholder`. Decode-tolerance is NOT cleanly implementable (the
trailing field is not self-describing) → match conformant on decode too, flag "verify Connext at 5b". Full
analysis: `docs/superpowers/spikes/2026-06-28-dds-security-fastdds-interop.md`.

## WP-DDS-SECURITY-FASTDDS-INTEROP T2 — the reply-blocker CHAIN (Slice 5, 2026-06-29)

T1 dropped the propagate byte and the live handshake reached HANDSHAKING, but Fast DDS (the replier) sent
no HandshakeReply. Diagnosed by (a) reading the Fast DDS replier path and (b) TEMPORARILY instrumenting the
Fast DDS peer (clean-room; Apache-2.0 read only; **RTI Connext source NEVER read**): set
`Log::SetVerbosity(Warning)` in `examples/cpp/security/main.cpp` (the example only does `Log::Reset()` →
Error, suppressing every security warning) and added DIAG `EPROSIMA_LOG_WARNING`s in
`SecurityManager::process_participant_stateless_message` (the SecurityManager.cpp DIAG edits were REVERTED
after diagnosis; the one-line example SetVerbosity is kept as legitimate diagnostic config). This revealed a
CHAIN of FOUR silent blockers, each masking the next (all on INFO/no-log paths):

1. **PSM writer sequence number = 0** (RTPS layer). Our `%send-stateless-message` sent the DATA with
   writerSN 0. `MessageReceiver.cpp:814` rejects `sequenceNumber <= 0` → "Invalid message received, bad
   sequence Number" → the DATA is dropped before the security layer. RTPS 2.5 §8.3.5.4/§8.4.2: a valid
   writerSN is >= 1. Fix: monotonic `psm-writer-sn` from 1 (`disc.lisp` + `stateless-message.lisp`).
2. **`source_endpoint_key` != GUID_UNKNOWN** (PSM envelope). `SecurityManager.cpp:1506` DROPS the message
   (INFO, compiled out) unless `source_endpoint_key == GUID_t::unknown()`; `generate_authentication_message`
   (1373-1388) leaves the endpoint keys unknown (§7.4.4). We set it to our participant GUID. Fix: emit
   GUID_UNKNOWN (`auth-manager.lisp %am-send-handshake`).
3. **DataHolder octet-vector missing 4-byte alignment padding** (CDR). The WIRE DataHolder is CDR-aligned:
   `CDRMessage.cpp:1096` calls `addBinaryPropertySeq(..., add_final_padding=true)` and `readOctetVector`
   (`:432`) advances `pos = (pos+3)&~3` after each value. Our `%cdr-binary-property-le` wrote the value with
   NO post-pad → `readDataHolderSeq` misaligns → "Cannot deserialize ParticipantGenericMessage". Fix: pad
   the wire octet-vector to 4 + skip it on decode (`wire.lisp`). WIRE-ONLY — the §8.7 hash/Sign
   BinaryPropertySeq uses `add_final_padding=false` (T1) and stays UNpadded, so `handshake.lisp` is untouched.
4. **c.pdata stub + non-§9.3.2.1 GUID** (security layer — the innermost blocker, reached only after 1-3).
   `begin_handshake_reply` reads `c.pdata` as a BE ParameterList and rejects unless `PID_PARTICIPANT_GUID`'s
   first 48 bits are the §9.3.2.1 adjusted GUID. Fix: real c.pdata (`%build-c-pdata`) + adjusted GUID
   (`%adjust-guid-prefix`), below.

After all four, the live Fast DDS now: deserializes the request, `found=1`, calls `on_process_handshake` →
`begin_handshake_reply` with NO PKIDH rejection, and SENDS a reply. Our peer advances HANDSHAKING → REJECTED
(it receives the reply but reply-verification fails = the T3 blocker). Source citations:

- **Fast DDS (Apache-2.0)** — `/Users/frgo/gbt Dropbox/gbt/projects/fastdds/src/fastdds`:
  - `src/cpp/rtps/messages/MessageReceiver.cpp:814-818` — DATA `sequenceNumber <= 0` → drop (blocker 1).
  - `src/cpp/rtps/security/SecurityManager.cpp:1495-1510` — destination_participant_key/endpoint-key/
    source_endpoint_key preconditions; `:1373-1388` `generate_authentication_message` leaves endpoint keys
    unknown (blocker 2). `:1455-1485` readParticipantGenericMessage deserialize (blocker 3 surfaces here).
  - `src/cpp/rtps/messages/CDRMessage.cpp:1096` `addBinaryPropertySeq(..., add_final_padding=true)`,
    `:416-434` `readOctetVector` pos→(pos+3)&~3, `:889-906` `readBinaryProperty` (name + octet-vector, NO
    propagate field — confirms the T1 no-propagate wire is correct) (blocker 3).
  - `src/cpp/security/authentication/PKIDH.cpp:1555-1612` `PKIDH::begin_handshake_reply` — reads `c.pdata`,
    parses it with `ParameterList::read_guid_from_cdr_msg(cdr_pdata, PID_PARTICIPANT_GUID, ...)` where
    `cdr_pdata.msg_endian = BIGEND` and `pos = 0`; then REJECTS unless `(guidPrefix[0] & 0x80) == 0x80`
    ("Bad participant_key's first bit") AND the adjusted `SHA256(subjectName)` 47-bit check matches
    ("Bad participant_key's 47bits"). A stub `c.pdata` fails the deserialize → "Cannot deserialize
    ParticipantProxyData in property c.pdata" → VALIDATION_FAILED → no reply. The hash_c1 mismatch here is
    only a WARNING (non-fatal), confirming T2 only needs a conformant c.pdata + adjusted GUID to unblock.
  - `src/cpp/security/authentication/PKIDH.cpp:503-568` `adjust_participant_key` — the §9.3.2.1 GUID bit
    layout pinned byte-for-byte: `gp[0]=0x80|(md[0]>>1)`, `gp[i]=(md[i-1]<<7)|(md[i]>>1)` for i=1..5, where
    `md=SHA256(X509_NAME of subject)`; `gp[6..11]` impl-defined uniqueness. Mirrored in
    `dds-security/auth/identity.lisp %adjust-guid-prefix` (we keep the candidate's octets 6-11 for
    uniqueness — conformant; the spec leaves them impl-defined).
  - `src/cpp/fastdds/core/policy/ParameterList.cpp:167-200` `read_guid_from_cdr_msg` — scans u16-BE
    `(pid,length)` parameters from `pos 0` with NO encapsulation-header skip (a leading PL_CDR header is
    consumed harmlessly as a zero-length pseudo-param). Pins our `c.pdata` as a raw BIG-ENDIAN ParameterList.
  - `src/cpp/rtps/builtin/discovery/participant/PDP.cpp:1417-1431` + `SecurityManager.cpp:859,870` — the
    producer side: `get_participant_proxy_data_serialized(BIGEND)` calls `write_to_cdr_message(&cdr, false)`
    (`write_encapsulation=false`) — so a conformant `c.pdata` carries NO encapsulation header. Mirrored in
    `dds-security/auth/handshake.lisp %build-c-pdata` (PID_PARTICIPANT_GUID + PID_SENTINEL, BE, no header).
- **OpenSSL 3.6.2** — `X509_NAME_digest(X509_get_subject_name(cert), EVP_sha256(), md, &len)` is the exact
  digest Fast DDS uses; wrapped as `dds.dare:x509-subject-name-sha256` (no hand-rolled crypto).
- **Eclipse Cyclone DDS (EPL-2.0)** — corroboration not re-fetched this task (Cyclone tree absent locally);
  the §9.3.2.1 adjusted-GUID rule is the same mechanism across implementations; flagged for the 5b
  Connext cross-check.

OUR-TO-OUR side effect: the adjusted (cert-derived) GUID flips the §8.7.2.4 requester/replier election off
the old creation-order heuristic, exposing that the best-effort PSM handshake had NO request retransmission
(`disc.lisp %record-participant` fired `on-participant-discovered` only on FIRST discovery). Fixed
conformantly: re-fire on SPDP re-announce for secure peers + the auth manager retransmits the request while
`:awaiting-reply` and re-sends the stored reply on a duplicate request (`auth-manager.lisp`). No spec/vendor
constant involved — best-effort retransmission is the conformant RTPS behaviour.

## WP-DDS-SECURITY-FASTDDS-INTEROP T3 — c.id credential = PEM; requester drops out-of-role tokens (Slice 5, 2026-06-29)

T2 made Fast DDS accept our request up to the credential load. T2-RESULT claimed "begin_handshake_reply
succeeds silently (sends the reply)" — that was WRONG (the honesty nit T3 corrects): the committed
`ssd-none-*-fastdds.log` show `[SECURITY Warning] Cannot load certificate -> begin_handshake_reply`, and on
VALIDATION_FAILED Fast DDS sends NOTHING. So Fast DDS never replied; the "%process-reply rejects the reply"
premise was false. T3's live diagnosis (`run-fastdds-interop.sh none`) found the real divergence and a
second, our-side false-reject.

Sources read (clean-room, **Apache-2.0 Fast DDS only; RTI never read**):
- `src/cpp/security/authentication/PKIDH.cpp:198-215` `load_certificate(const vector<uint8_t>&)` — reads
  `c.id` via `BIO_new_mem_buf` + **`PEM_read_bio_X509_AUX`**: the credential MUST be a **PEM** certificate.
- `:297-310` `store_certificate_in_buffer` — fills `cert_content_` via **`PEM_write_bio_X509`** (so the c.id
  Fast DDS EMITS is PEM too); `:1346-1350` `begin_handshake_request` and `:1716-1718`
  `begin_handshake_reply` assign `c.id = cert_content_` (the PEM bytes).
- `:1487-1508` `begin_handshake_reply` — `find_binary_property_value("c.id")` → `load_certificate(*cid)` →
  "Cannot load certificate" → VALIDATION_FAILED when the bytes are not PEM. `:1396-1410`
  `begin_handshake_request` hashes the BinaryPropertySeq (incl. c.id) via `EVP_Digest(...SHA256)` over the
  **transmitted c.id bytes** — both sides hash the same wire bytes, so hash_c matches regardless of encoding.
- `:761-867` `generate_dh_peer_key` — for `EVP_PKEY_EC` it deserializes the dh public key via
  **`o2i_ECPublicKey`** (raw uncompressed EC point), else "Cannot deserialize public key" (`:858`). Called
  from `:1706` on the request's `dh1`. This is the **NEXT (T4) blocker**: we emit dh1/dh2 as
  SubjectPublicKeyInfo DER, Fast DDS wants the raw EC point.
- `:1260-1304` `validate_remote_identity` — role = `lih->participant_key_ < remote_participant_key`
  (lower-GUID participant is the requester, §8.7.2.4); `SecurityManager.cpp:907-953` `on_process_handshake`
  only transmits a handshake message for `VALIDATION_PENDING_HANDSHAKE_MESSAGE / OK_WITH_FINAL_MESSAGE` —
  confirms VALIDATION_FAILED sends nothing.
- OpenSSL `bio.h:92` `BIO_CTRL_INFO=3`, `:615` `BIO_get_mem_data(b,pp)=BIO_ctrl(b,BIO_CTRL_INFO,0,pp)` —
  used by the new `dds.dare:x509-to-pem` to read the PEM out of the write BIO (same idiom as `cms-verify`).

Conformant fixes (this WP):
1. **c.id = PEM certificate** (DDS-Security 1.1 §9.3.2.1 credential serialization). New
   `dds.dare:x509-to-pem` (PEM_write_bio_X509) replaces `x509-to-der` for c.id at the 2 emit sites
   (`handshake.lisp` request + reply); the hash_c input uses the same PEM bytes. Decode is **tolerant**: new
   `dds.dare:x509-load-cert-auto` tries PEM then DER (no false-REJECT of a legacy DER peer). Live result:
   "Cannot load certificate" GONE — Fast DDS loads our cert and proceeds to the key-agreement stage.
2. **Requester drops out-of-role tokens** (§8.7.2.4: the requester processes ONLY the HandshakeReply).
   `auth-manager.lisp %am-drive-handshake`: a `:requester` whose handle is `:awaiting-reply` now DROPS any
   non-Reply token (new `%am-token-class` helper) instead of feeding it to `%process-reply`, which rejected
   on the class_id mismatch and latched `:rejected` — which then IGNORED the genuine Reply. The live peer
   sends us `DDS:Auth:PKI-DH:1.0+Req` tokens (Fast DDS's prefix); we now drop them and stay HANDSHAKING.
   Symmetric to the replier's existing duplicate-request guard. No wire constant.

No spec/vendor constant invented. Cyclone tree still absent locally (flagged for 5b). our-to-our green both
impls (SBCL 377 deterministic; Clasp 377 on re-run — the live-socket e2e test flakes on Clasp DOWNSTREAM of
the handshake, never in the changed path). Live: handshake ADVANCED past credential-load to the dh1 stage
(T4 = dh1/dh2 raw-EC-point format).

## WP-DDS-SECURITY-FASTDDS-INTEROP T4 — dh1/dh2 raw EC point + hash_c BinaryPropertySeq padding (Slice 5, 2026-06-29)

T3 left two linked cross-vendor divergences (Fast DDS `begin_handshake_reply` logged BOTH `Wrong hash_c1`
AND `Cannot deserialize public key (PKIDH.cpp:858)` on our request) plus a role-election watch-item. T4
diagnosed all three from the live peer + clean-room Fast DDS Apache-2.0 source (RTI never read); fixed B + C
conformant; A is a benign retransmit (no change). Source citations (Fast DDS `src/fastdds/`):

- **(A) role election = BENIGN retransmit, not a disagreement.** `PKIDH.cpp:1064-1258` `validate_local_identity`
  sets `(*ih)->participant_key_ = adjusted_participant_key` (`:1238`, the §9.3.2.1 adjusted GUID). `:1260-1304`
  `validate_remote_identity` elects requester iff `lih->participant_key_ < remote_participant_key` (`:1293`) —
  BOTH sides compare the announced adjusted GUIDs, complementary to our `auth-manager.lisp:244`
  (`disc-node-guid-prefix` = our adjusted B9… vs the remote's announced adjusted D1…). Our peer (B9…) is the
  requester, Fast DDS (D1…) the replier — they AGREE. The `+Req` Fast DDS emits is its FAILURE-RETRY:
  `SecurityManager.cpp:719-732` resets `AUTHENTICATION_FAILED → AUTHENTICATION_REQUEST_NOT_SEND` on the next
  SPDP re-announce → `on_process_handshake` (`:855` `begin_handshake_request`) re-sends a request. `:862-865`
  calls `begin_handshake_reply` ONLY from `AUTHENTICATION_WAITING_REQUEST` (the replier) — so the observed
  `begin_handshake_reply` failure proves Fast DDS is the replier, and the `+Req` are retries triggered by our
  request failing B+C. Dropping them (T3) is CORRECT; once B+C land, `begin_handshake_reply` succeeds and Fast
  DDS sends `+Reply` instead of retrying. No code change.
- **(B) dh1/dh2 = raw uncompressed EC point.** `PKIDH.cpp:680-759` `store_dh_public_key` for `EVP_PKEY_EC`
  serializes the dh public key via **`EC_POINT_point2oct(grp, pub, EC_KEY_get_conv_form(ec), …)`** (`:737-739`)
  = the raw point in the key's default UNCOMPRESSED form (`0x04||X||Y`, 65 B for P-256). `:761-867`
  `generate_dh_peer_key` reads it via **`o2i_ECPublicKey`** (`:833`), else "Cannot deserialize public key"
  (`:858`). We emitted SubjectPublicKeyInfo DER (`i2d_PUBKEY`). FFDH stays raw `BN_bn2bin` (`:708-714`) — left
  untouched.
- **(C) hash_c1/hash_c2 + Sign BinaryPropertySeq value padding.** `PKIDH.cpp:1395-1410`
  `begin_handshake_request` and `:1654-1657` / `:1764-1768` hash via `CDRMessage::addBinaryPropertySeq(&msg,
  props, [\"c.\",] false)` (BIGEND), the signature via `:1817-1843` (`addUInt32(6)` then six
  `addBinaryProperty`, the last `hash_c1` with `add_final_padding=false`). `CDRMessage.cpp:973-1050`
  `addBinaryPropertySeq` sets each property's `add_final_padding = outer || (number_to_serialize != 0)` → every
  value padded EXCEPT the last. `:867-887` `addBinaryProperty` → `:602-637` `addOctetVector` pads
  `(4 - size%4)%4` zero bytes after the value when `add_final_padding`; `:799-812` `add_string` pads the name
  to a 4-multiple (matches our `%cdr-string-be`). The `\"c.\"` filter (`:1027,1038` `name().find(\"c.\")==0`)
  selects exactly c.id/c.perm/c.pdata/c.dsign_algo/c.kagree_algo. We never padded the value → `Wrong hash_c1`.

Conformant fixes (this WP):
1. **dh1/dh2 raw EC point** — `dds.dare:ecdh-gen-keypair` now extracts the public key via
   `EVP_PKEY_get_octet_string_param` "pub" (OSSL_PKEY_PARAM_PUB_KEY, default uncompressed point = the
   `EC_POINT_point2oct` form) instead of `i2d_PUBKEY`/SPKI DER (new `%evp-pkey-ec-pub-point`).
   `dds.dare:ecdh-compute` is decode-tolerant (new `%ecdh-import-peer-pub`): a 65-byte `0x04||X||Y` point →
   `ec-p256-import-public`; any other input → `d2i_PUBKEY` SPKI DER (keeps the RFC 5903 KAT + legacy peers).
2. **hash_c/Sign value padding** — `handshake.lisp` `%cdr-octet-seq-be`/`%cdr-binary-property-be`/
   `%build-cdr-binary-property-seq-be` now 4-pad each octet value EXCEPT the last property in the sequence
   (`add_final_padding=false` at seq level), matching `addBinaryPropertySeq`. The WIRE DataHolder (`wire.lisp`)
   already pads ALL values (`add_final_padding=true`); the two paths differ only on the last property.

No spec/vendor constant invented; clean-room (Fast DDS Apache-2.0 read only, RTI never). Cyclone tree still
absent locally (flagged for 5b). our-to-our green both impls (SBCL 377 deterministic; Clasp 377 on re-run —
the two live-socket e2e flakes [SDP-BYTE-EXACT, SDP-SEC-PREFIX-ON-WIRE] are DOWNSTREAM of the handshake and
move between runs, never in the changed crypto path; the handshake/keyed e2e tests pass every run). **Live
result: the cross-vendor handshake now COMPLETES — HANDSHAKING → Reply → Final → SharedSecret → AUTHENTICATED
both directions; Fast DDS's security log is clean (`Wrong hash_c1` + `Cannot deserialize public key` GONE).
[SUPERSEDED by T5: only OUR side authenticated; Fast DDS was stuck WAITING_FINAL until the §7.4.3
related_message_identity echo — see the T5 entry]**
Next blocker (T5): the §8.5.2 crypto-token exchange over reliable ParticipantVolatileMessageSecure does not
complete cross-vendor → never `:keyed` → no endpoint match (the brief's secure-SEDP / PVMS reliable
HEARTBEAT/ACKNACK-pull candidate).

## WP-DDS-SECURITY-FASTDDS-INTEROP T5 — handshake-Final correlation + PVMS prerequisites (Slice 5, 2026-06-29)

Read-only clean-room study of eProsima Fast DDS (Apache-2.0) — RTI never read. The §8.7 handshake reached
AUTHENTICATED on OUR side (T0-T4), but Fast DDS (the replier) NEVER reached `participant_authorized` — it
sent no crypto tokens, matched no user endpoints (no "Subscriber/Publisher matched." in its log), and logged
no error: it was silently stuck. Isolated by instrumenting our PVMS path (we sent 11 tokens, received ZERO
inbound) then reading Fast DDS `SecurityManager.cpp`.

Root cause (the live blocker), `SecurityManager::process_participant_stateless_message` (the §7.4.3 PSM
correlation):
- **`:1554-1556`** — in `AUTHENTICATION_WAITING_FINAL`, a message whose `related_message_identity.source_guid
  == GUID_t::unknown()` is treated as "the reply was missed" → Fast DDS RESENDS its Reply, never processing
  the Final. We sent the Final with `related_message_identity = {GUID_unknown, 0}` (a hardcoded placeholder),
  so Fast DDS looped on resend forever and never authorized.
- **`:1582-1589`** — the conformant Final requires `related_message_identity.source_guid ==
  participant_stateless_message_writer_->getGuid()` (the replier's PSM-WRITER GUID, prefix + 0x000201C3).
- **`:1590-1597`** — and `related_message_identity.sequence_number == expected_sequence_number_` (the Reply's
  message_identity.sequence_number). Our-to-our was blind to this: our PSM dispatch keys the handshake by the
  remote 12-octet prefix and IGNORES message_identity/related (so it never needed the echo).

Conformant fix (§7.4.3 / §8.7.2.4): `auth-manager.lisp` `%am-on-stateless-message` now captures the INCOMING
message's `message_identity` (source_guid + sequence_number) and threads it through `%am-drive-handshake` →
`%am-send-handshake`, which echoes it as the response's `related_message_identity`. The first Request keeps
related = GUID_unknown/0 (it carries none, matching `:1535`). Live-verified: our Final now sends
`related = {D1437B8E..0x000201C3, 1}` (exactly Fast DDS's Reply message_identity), Fast DDS processes the
Final and reaches `participant_authorized` BOTH directions.

PVMS crypto-token prerequisites reconciled (all corroborated, now in place for the exchange once authorization
passes):
- **PVMS BuiltinEndpointSet bits 24/25** (`disc.lisp` `%node-spdp-data`): advertise
  `BUILTIN_ENDPOINT_PARTICIPANT_VOLATILE_MESSAGE_SECURE_WRITER/READER` iff the PVMS endpoint exists, mirroring
  Fast DDS `SecurityManager.cpp` `builtin_endpoints()` (`:2087-2115`); Fast DDS
  `match_builtin_key_exchange_endpoints` (`:2178-2217`) gates PVMS matching on these bits — without them no
  tokens flow either way. Live-verified advertised (`builtin-endpoint-set = #x03C0FC3F`, bits 24+25 set).
- **PVMS SerializedPayload §10.2 encapsulation** (`volatile-secure.lisp`): the PVMS DATA payload now carries
  the PLAIN_CDR_LE encapsulation header (reuses `%psm-encapsulate`, stripped on receive), required by Fast DDS
  `process_participant_volatile_message_secure` (`:1700-1718`, reads the 4-octet encap before the
  ParticipantGenericMessage) — exactly like the PSM path. PL_CDR (0x02/0x03) is silently dropped.
- **Participant crypto-token `source_endpoint_key` = GUID_unknown** (`crypto-manager.lisp`
  `cm-make-crypto-token-message`): a PARTICIPANT-class token is participant-level (OMG §8.5.2.1); Fast DDS
  `:1745-1749` drops it if `source_endpoint_key != GUID_unknown`. DW/DR tokens keep the source endpoint GUID
  (§8.5.2.2/.3).
- **Keyed-gate governance sensitivity** (`crypto-manager.lisp` `%cm-remote-keyed-ready-p`): require the
  secure-SEDP EntityCrypto tokens ONLY when discovery protection is active. Fast DDS exchanges the
  ParticipantCryptoToken unconditionally when the crypto plugin is loaded (`participant_authorized`
  `exchange_participant_crypto`, `:4099`, NOT gated on rtps_protection) but creates secure-SEDP endpoints only
  under discovery_protection — so under GOV=none, keying needs only the ParticipantCrypto.

NEXT blocker (T6), Fast DDS `Permissions.cpp`: with the handshake now completing, `participant_authorized`
fails — `[SECURITY Error] Error validating remote permissions ... Cannot read as PKCS7 the permissions file
(:593)`. Cause: our handshake sends an EMPTY `c.perm` (`handshake.lisp:359` placeholder). Fast DDS reads the
remote permissions credential via `SMIME_read_PKCS7` (`:354`) + `PKCS7_verify(... PKCS7_TEXT | PKCS7_NOVERIFY
| PKCS7_NOINTERN)` (`:406`) — it requires the S/MIME multipart form (its `.smime`), NOT our PEM PKCS7
(`-----BEGIN PKCS7-----`). T6 = plumb the local permissions document (S/MIME) into `c.perm` through the
handshake API + auth-manager. No spec/vendor constant invented; clean-room (Fast DDS Apache-2.0 read only, RTI
never). our-to-our green both impls (SBCL 377 deterministic; Clasp keyed/PVMS/secure-discovery deterministic,
the SDP-SEC-PREFIX-ON-WIRE wire-capture e2e is the known NFR-PORT live-socket flake, passes in isolation).

## WP-DDS-SECURITY-FASTDDS-INTEROP T6 — c.perm = S/MIME permissions credential (Slice 5, 2026-06-29)

Read-only clean-room study of eProsima Fast DDS (Apache-2.0) — RTI never read. With the handshake completing
both directions (T5), Fast DDS `participant_authorized` failed at permissions validation:
`[SECURITY Error] Error validating remote permissions … Cannot read as PKCS7 the permissions file`. Our
handshake `c.perm` binary_property was EMPTY (`handshake.lisp:359` placeholder).

Corroboration (the exact c.perm form Fast DDS emits + reads):
- `src/cpp/security/authentication/PKIDH.cpp:1352-1364` (`begin_handshake_request`; mirrored at `:1536-1552`
  reply, `:1722-1734` final-store, `:1960-1972`) — `c.perm` value = the `dds.perm.cert` Property of the local
  `DDS:Access:PermissionsCredential` token, assigned VERBATIM into the handshake `BinaryProperty("c.perm")`.
- `src/cpp/security/accesscontrol/Permissions.cpp:777-797` `generate_credentials_token` — `dds.perm.cert` is
  set to the RAW CONTENT of the configured permissions file (`std::ifstream … << ifs.rdbuf()`). So c.perm is
  the raw signed permissions document bytes, unaltered.
- `src/cpp/security/accesscontrol/Permissions.cpp:354,406` `load_and_verify_document`
  (`validate_remote_permissions` → `check_remote_permissions`) — the remote c.perm is parsed with
  `SMIME_read_PKCS7(in, &indata)` (NULL ⇒ "Input data has not PKCS7 S/MIME format") then verified with
  `PKCS7_verify(p7, stack, nullptr, indata, out, PKCS7_TEXT | PKCS7_NOVERIFY | PKCS7_NOINTERN)`. PKCS7_TEXT
  REQUIRES the MIME multipart/signed S/MIME container with a `Content-Type: text/plain` body part — the
  `.smime` form (`openssl smime -sign -text`, NOT `-outform PEM -nodetach`), NOT the bare-PEM
  `-----BEGIN PKCS7-----` opaque form our Slice-3 `dds.dare:cms-verify` consumed.

The bare-PEM `.p7s` and the MIME `.smime` are signed over DIFFERENT byte streams (the `.smime` content carries
a `Content-Type: text/plain\r\n\r\n` prefix; the `.p7s` does not), so the `.p7s` cannot be re-wrapped into the
`.smime` form without the Permissions-CA private key — they are two distinct signatures. Conformant resolution
(DDS-Security 1.1 §9.4.1.1 / RFC 5652 + RFC 5751; the spec form IS S/MIME):
- `dds.dare:cms-verify` (`openssl-ffi.lisp`) is now decode-tolerant: PEM_read_bio_CMS (form 1, flags=0,
  byte-identical to before) → on NULL, `SMIME_read_CMS` + `CMS_verify(…, CMS_TEXT)` (form 2, cms.h:179
  CMS_TEXT=0x1, the CMS-API analogue of Fast DDS's PKCS7 path). Pure capability ADDITION — no document
  previously accepted is now rejected. Verified in isolation: both `.p7s` and `.smime` recover the identical
  1265-byte permissions XML; garbage ⇒ NIL (fail-closed).
- The participant's configured signed permissions octets (`create-participant :permissions`) are plumbed
  through `%install-auth-manager` → the auth-manager-state `perm-credential` slot → the optional
  `perm-octets` arg of `begin-handshake-request`/`begin-handshake-reply`, emitted as c.perm (§9.3.2.1) AND
  folded into hash_c (so both ends recompute the identical hash over the transmitted bytes — the hash check is
  over the wire bytes, independent of c.perm content, which is why T5 authorized with an empty c.perm yet
  failed only the SEPARATE permissions-validation step). Default empty ⇒ byte-identical to T5 for auth-only /
  unit / structural-corpus paths. The interop harness feeds our peer the SHARED `.smime` (grants both EC
  subjects) so c.perm is the conformant form. The §8.7.2.4 PSM send buffer is now sized per-call
  (`stateless-message.lisp`) — the ~3 KiB c.perm + c.id cert exceeds the fixed 2 KiB rx-tx-msg scratch.

Live re-run (GOV=none, `run-fastdds-interop.sh none 20`, both directions): the `Cannot read as PKCS7` /
`Error validating remote permissions` log is GONE in BOTH Fast DDS logs — permissions now VALIDATE. Fast DDS
proceeds past `participant_authorized` to secure SEDP endpoint matching (`RTPS_WRITER … Attempting to add
existing reader`). Our side reaches AUTHENTICATED and drives the PVMS crypto-token exchange. NEXT blocker
(T7/next iteration): neither side reaches `:keyed` — the PVMS ParticipantCryptoToken exchange does not complete
(no inbound token observed), re-exposing the original T5/T6-candidate PVMS reliability / metatraffic-wrapping
items now that authorization passes. No spec/vendor constant invented; clean-room (Fast DDS Apache-2.0 only,
RTI never). our-to-our green both impls (SBCL 377 deterministic; Clasp security/auth/access-control/handshake
deterministic in isolation, the live-socket wire-capture e2e is the known NFR-PORT flake — it moved from
SDP-SEC-PREFIX-ON-WIRE to SDP-BYTE-EXACT across the two full-suite runs, both pass in isolation).

## WP-DDS-SECURITY-FASTDDS-INTEROP T7-PVMS — crypto-token KeyMaterial kind + protected PVMS HEARTBEAT/ACKNACK (Slice 5, 2026-06-29)

With authorization passing (T6), the live PVMS ParticipantCryptoToken exchange was diagnosed by instrumenting
our PVMS send/receive/decode/promote paths. Findings: we DO receive + decode Fast DDS's PVMS brackets (the
§9.5.3.1 bootstrap KM derive-kx-key/-salt is byte-identical cross-vendor; the §9.5.3.3.4.2 session-key KDF +
nonce match — we splice the wire session_id verbatim, Fast DDS uses the native-LE uint32 for both wire and
KDF). Fast DDS's participant-token DATA reached our hook but `cm-parse-crypto-token-message` returned NIL.
TWO conformant divergences, both corroborated CLEAN-ROOM (read-only) vs eProsima Fast DDS (Apache-2.0); RTI
NEVER read.

**(1) KeyMaterial transformation_kind AES256_GMAC {0,0,0,3} false-REJECT.** `%parse-km-cdr`
(`auth/keyexchange.lisp`) accepted `transformation_kind[3]` only in `{0x01,0x02,0x04}` — it OMITTED `0x03`.
The live participant-token KeyMaterial (88-byte form, BIG-ENDIAN seq lengths salt=32/key=32, length markers
at offsets 7/47 = 0x20 — otherwise byte-exact to our serializer) carried kind `{0,0,0,3}` (Fast DDS
`AESGCMGMAC_KeyFactory` `c_transfrom_kind_aes256_gmac` for the ParticipantKeyMaterial under the GMAC-tier
governance). DDS-Security 1.1 §9.5.2.1.1 Table 70 / dds_security_plugins_psm.idl defines four non-NONE kinds
(AES128_GMAC 0x01, AES128_GCM 0x02, AES256_GMAC 0x03, AES256_GCM 0x04); the parser now accepts all four.
Pure relaxation (nothing previously accepted is now rejected). → OUR side reaches `:keyed` both directions.

**(2) PVMS HEARTBEAT/ACKNACK must be submessage-PROTECTED (the deferred Slice-4 carry).** Fast DDS
`RTPSMessageGroup::add_heartbeat` encodes the HEARTBEAT via `encode_writer_submessage` and `add_acknack` the
ACKNACK via `encode_reader_submessage` when `endpoint.security_attributes().is_submessage_protected` (the PVMS
endpoint is IS_SUBMESSAGE_ENCRYPTED, `SecurityManager.cpp:1284-1286/1336-1338`), and `MessageReceiver` DROPS
a CLEAR submessage on a submessage-protected endpoint (`was_decoded || !is_submessage_protected`,
`MessageReceiver.cpp:135/188/1131/1182/1239/1382`). Our PVMS sent CLEAR HEARTBEAT/ACKNACK (Fast DDS dropped
them → our token never NACK-pulled) and DROPPED Fast DDS's encrypted HEARTBEAT/ACKNACK (we handled only the
inner DATA). Fix: `%pvms-emit-heartbeat` ENCRYPTs the HEARTBEAT (encode-datawriter-submessage) and the
ACKNACK in `%on-pvms-heartbeat` ENCRYPTs via encode-datareader-submessage, both under the bootstrap KM + the
per-role session_id; `%on-volatile-secure` now DECODEs the bracket then DEMUXes the inner RTPS submessage by
id (DATA → token delivery, HEARTBEAT → ACKNACK pull, ACKNACK → DATA resend, INFO_TS/other → skip); the dead
CLEAR PVMS HEARTBEAT/ACKNACK dispatch clauses were removed (`disc.lisp`). → Fast DDS's PVMS reader acks our
tokens through SN 11 (base=12, resends=0) → Fast DDS receives our participant crypto token → Fast DDS keys.

Live re-run (GOV=none, both directions): the PVMS ParticipantCryptoToken exchange now COMPLETES BOTH
directions — our side reaches `:keyed` (was NIL), Fast DDS acks all our tokens (no crypto ERROR in its log).
NEXT blocker (next iteration): no user-endpoint match (`matched=0`) — we receive NO SEDP HEARTBEAT from Fast
DDS (`%on-builtin-heartbeat` never fires) so we never discover its user endpoints, and Fast DDS's subscriber
never prints "matched". Post-keying, Fast DDS does not initiate the plain-SEDP/EDP user-endpoint exchange with
us; this is a SEDP-layer investigation distinct from the (now-resolved) PVMS crypto-token exchange. our-to-our
green: the 4 PVMS engine tests + 4 secure-discovery e2e tests pass; gate-hotpath(8)/gate-types(2030)/fuzz/
mem(0.0000) PASS.

### WP-DDS-SECURITY-FASTDDS-INTEROP — GOV=secure two-phase secure discovery: keying gate + DW/DR token destination_endpoint_key (M7/P6 Slice 5)

The headline DoD (PROTECTED user data, both directions) requires the PROTECTED governance (GOV=secure:
discovery_protection_kind=ENCRYPT, rtps_protection_kind=ENCRYPT, metadata/data_protection_kind=ENCRYPT) — the
prior PVMS work ran GOV=none (all protection NONE). Under GOV=secure the cross-vendor path was diagnosed by
instrumenting our crypto-token install + keying-gate + PVMS + secure-builtin receive/dispatch paths (temporary
`*error-output*` traces, all removed). TWO conformant divergences, both corroborated CLEAN-ROOM (read-only) vs
eProsima Fast DDS (Apache-2.0); RTI NEVER read. Fast DDS Info logging is compiled out of the prebuilt lib
(`LOG_NO_INFO=ON`), so the C++ source was read directly.

**(1) `:keyed` gate must NOT require the secure-SEDP endpoint tokens (Fast DDS two-phase secure discovery).**
Fast DDS keys a remote in TWO phases: PHASE 1 at `participant_authorized` exchanges the ParticipantCrypto +
the SPDP-secure (0xff0101) endpoint tokens and matches the secure PDP (`SecurityManager.cpp`
participant_authorized -> `exchange_participant_crypto` + `notifyAboveRemoteEndpoints` ~4098-4140;
`PDPSimple.cpp` `match_pdp_remote_endpoints` secure); PHASE 2 exchanges the secure-SEDP (0xff0003/0xff0004) +
secure-PM (0xff0200) endpoint tokens, gated on the secure-SPDP reader having matched the remote secure-SPDP
writer (`PDPSimple::assignRemoteEndpoints` ~558-574 checks `matched_writer_is_matched(remote_secure_spdp_writer)`
before `assign_low_level_remote_endpoints(notify_secure=true)` -> `EDPSimple::assignRemoteEndpoints` ~819-876
secure-endpoint crypto-token exchange). So the secure-SEDP EntityCryptos arrive AFTER the participant
secure-match — they are NOT a participant-keying precondition. Our `%cm-remote-keyed-ready-p` (added in T8) ALSO
required the remote's secure-SEDP pub-writer DW + sub-reader DR, which DEADLOCKED against the two-phase peer
(live: Fast DDS sent ONLY the 3 phase-1 tokens — participant + secure-SPDP DW 0xff0101c2 + DR 0xff0101c7 —
so our gate's `pubw`/`subr` stayed NIL and our side never left :authenticated). Fix: gate `:keyed` on the
ParticipantCrypto ALONE (identical for PLAIN and PROTECTED discovery); the endpoint-level secure-builtin
EntityCryptos install lazily as those endpoints match (the secure receive path resolves each by
transformation_key_id on arrival, fail-closed until present). -> OUR side reaches `:keyed` BOTH directions under
GOV=secure (was NIL).

**(2) DW/DR CryptoToken destination_endpoint_key must be the MATCHED REMOTE endpoint GUID, not GUID_unknown.**
Fast DDS `SecurityManager::process_participant_volatile_message_secure` validates the §7.4.4
ParticipantGenericMessage endpoint keys by message_class_id: a PARTICIPANT token requires BOTH
destination_endpoint_key AND source_endpoint_key == `GUID_t::unknown()` (rejected otherwise, ~1739/1745); a
DATAWRITER/DATAREADER token requires BOTH to be NON-unknown (rejected if `== GUID_t::unknown()` at ~1830/1835
for datareader, ~1907/1912 for datawriter) and APPLIES the token by looking up the LOCAL endpoint via
`reader_handles_.find(destination_endpoint_key)` / `writer_handles_.find(destination_endpoint_key)` (~1924/1848)
then the matched REMOTE via `associated_writers.find(source_endpoint_key)` / `associated_readers.find(...)`
(~1928/1852). We sent every DW/DR token with destination_endpoint_key = all-zero (GUID_unknown) -> Fast DDS
REJECTED ALL our endpoint tokens (live: "[SECURITY_CRYPTO] No key material yet" flood; our secure announces
undecodable) -> phase 2 never triggered. (Our OWN install keys by source_endpoint_key and ignores the
destination, so our-to-our was tolerant and masked this.) Fix: `%cm-token-dest-entity-id` maps a LOCAL endpoint
to its matched-remote COMPLEMENTARY endpoint id (builtin secure: §9.3.2 key-kind low byte writer 0xC2 <-> reader
0xC7 within the same builtin; user: writer-id <-> reader-id), and `cm-make-crypto-token-message` writes
destination_endpoint_key = GUID_unknown for a participant token, else remote-prefix + the complementary id. ->
Fast DDS APPLIES our builtin-secure tokens, proceeds to phase 2 + 3, and exchanges ALL its builtin-secure
endpoint tokens back (live CMTOK-RX after fix: participant + secure-SPDP 0xff0101 + secure-SEDP pub 0xff0003 +
secure-SEDP sub 0xff0004 + secure-PM 0xff0200, DW+DR each).

Live re-run (GOV=secure, both directions): both sides reach `:keyed` (was NIL); Fast DDS completes the FULL
builtin-secure crypto-token exchange both ways; our secure receive path now decodes Fast DDS's secure-builtin
traffic (131/131 brackets decoded). REMAINING blocker (next iteration): secure-builtin RELIABILITY — Fast DDS's
reliable secure-SEDP/SPDP writers send submessage-protected HEARTBEATs (inner id 7, x99) + ACKNACKs (inner id 6,
x32) which our `%on-secure-builtin` DROPS (it handles only inner DATA, mirroring the pre-fix PVMS bug), so we
never ACKNACK-pull Fast DDS's secure-SEDP DiscoveredReaderData -> no user-endpoint match (`matched=0`). The
conformant fix (next slice) is to demux + answer the secure-builtin HEARTBEAT/ACKNACK exactly like the PVMS
HEARTBEAT/ACKNACK (reuse `%builtin-acknack-values` + the reliable engine), plus exchange the USER-endpoint
CryptoTokens at endpoint-match time with the actual matched-remote GUID (cross-vendor user ids are not the
symmetric our-to-our ids). our-to-our green (both fixes): secure-discovery keyed/protected/protected-sign +
PVMS reliable/fail-closed e2e tests pass; make test-sbcl=377; gate-types(2031)/gate-hotpath(8)/corpus/fuzz/
mem(0.0000) PASS.

### M7/P6 Slice 5 (WP-DDS-SECURITY-FASTDDS-INTEROP) — T9: secure-SEDP RELIABILITY + user-token-at-match + NO_KEY keyed-ness (cross-vendor user-endpoint MATCH achieved both directions)

Implements the "next iteration" fixes the T8sedp entry above identified. Three corroborated divergences,
CLEAN-ROOM vs eProsima Fast DDS (`src/fastdds`, Apache-2.0) + RTPS 2.5 / DDS-Security 1.1 OMG clauses; **RTI
Connext never read**.

**(1) The secure builtin endpoints are RELIABLE — answer + emit submessage-protected HEARTBEAT/ACKNACK, not
only DATA.** A reliable Fast DDS secure-SEDP/SPDP writer drives its matched reader by submessage-PROTECTED
HEARTBEAT (RTPS 2.5 §8.3.7.5, inner submessage id 0x07) + ACKNACK (§8.3.7.1, id 0x06), never a clear one
(`RTPSMessageGroup::add_heartbeat`/`add_acknack` route through `encode_writer/reader_submessage` when the
endpoint `is_submessage_protected`; `MessageReceiver` drops a clear submessage on a protected endpoint:
`was_decoded || !is_submessage_protected`). Our `%on-secure-builtin` decoded the bracket then handled ONLY
inner DATA and DROPPED HEARTBEAT/ACKNACK (the same defect the PVMS path had pre-T8), so we never NACK-pulled
Fast DDS's secure-SEDP DiscoveredReaderData (live T8sedp: `matched=0`). Fix: `%on-secure-builtin` now DEMUXes
the recovered inner submessage by id (mirroring the PVMS `%on-volatile-secure`): inner DATA records its SN
(`%builtin-on-data`) then routes SEDP/PM/SPDP as before; inner HEARTBEAT -> `%on-secure-builtin-heartbeat`
applies the range (`%builtin-acknack-values`) and sends the computed ACKNACK submessage-PROTECTED under OUR
matched LOCAL receiving reader's EntityCrypto (`%secure-reader-eid-for-writer` maps the §9.3.2 builtin pair
0xC2 writer -> 0xC7 reader), encoded as a DataReader submessage (`encode-datareader-submessage`, §8.5.1.8/.9 —
a CLEAR ACKNACK is dropped by a conformant secure writer); inner ACKNACK -> `%on-secure-builtin-acknack`
resends each NACKed secure-SEDP DiscoveredWriter/ReaderData (`%send-secure-endpoint`, the repair). The new
`%send-secure-builtin-heartbeats` (hooked into the announce cadence in `disc.lisp` alongside
`%pvms-push-heartbeats-all`) emits NON-FINAL secure-SEDP HEARTBEATs [1,N] from each protected local secure-SEDP
writer to every :keyed peer, so Fast DDS NACK-pulls OUR DiscoveredWriter/ReaderData (RTPS 2.5 §8.4.2.2). The
PVMS HEARTBEAT/ACKNACK builders were refactored to share `%build-plain-{heartbeat,acknack}-sm` (DRY; PVMS
stays byte-identical). FAIL-CLOSED on every demux branch: an unknown inner id, a non-secure-builtin writer, a
truncated inner HEARTBEAT (`parse-heartbeat-body` -> NIL is dropped, not signaled — NFR-SEC-POSTURE), an
unresolved local EntityCrypto, or no metatraffic locator -> a silent drop. NONCE-SAFETY: the added encrypt
sites under the secure-SEDP-writer KM (HEARTBEAT + ACKNACK-driven DATA resend) and under the reader KM
(ACKNACK) all draw a UNIQUE iv_suffix from the per-KM monotonic `%km-next-iv-suffix` counter
(`KM-IV-COUNTER-LOCK`-atomic; `cm-encode-entity-km` returns the stable KM singleton, never a fresh copy), so
the announce-thread DATA+HEARTBEAT racing the receiver-thread ACKNACK-resend on the same KM cannot reuse a
(key, nonce).

**(2) USER DW/DR CryptoToken re-exchange at endpoint-MATCH time with the actual matched-remote GUID.** The
auth-time `cm-on-authenticated` set each USER DW/DR token's destination_endpoint_key = remote-prefix + OUR
symmetric-assumed complementary entity-id (correct only our-to-our). A cross-vendor peer's user entity-ids are
its own, so that key is wrong. Fix: `%on-disc-match` (the 16-octet matched-remote GUID is the handle) now calls
`%cm-user-token-at-match` -> `cm-on-endpoint-match`, which re-sends our Datawriter/DatareaderCryptoToken over
the reliable PVMS with destination_endpoint_key = the REAL matched-remote endpoint GUID learned from the
(secure or plain) SEDP Discovered{Writer,Reader}Data (DDS-Security 1.1 §8.5.2.2/.3; Fast DDS
`process_participant_volatile_message_secure` applies a DW/DR token via `*_handles_.find(dest)`). Gated on the
remote being :keyed (fail-closed no-op otherwise); idempotent our-to-our (the real GUID equals the auth-time
guess).

**(3) Interop HelloWorld endpoints declared NO_KEY.** Fast DDS's example HelloWorld has no @key member (NO_KEY,
RTPS 2.5 §9.3.1.2 Table 9.1: writer 0x03 / reader 0x04). Our interop test endpoints declared WITH_KEY, so
Fast DDS `valid_matching` rejected the user match on keyed-ness (`INCOMPATIBLE QOS keyed:1 vs keyed:0`). Fix
(test-harness only, `secure-interop.lisp`): pass `:keyed nil` — match the peer's key-ness (the oracle), not a
fixed WITH_KEY.

**Live re-run (`run-fastdds-interop.sh secure 45`, GOV=secure, both directions):** USER ENDPOINTS NOW MATCH
BOTH DIRECTIONS (`peak-matched=1` both; Fast DDS `Publisher matched.` + runs `decode_datawriter_submessage` on
our data = it matched our writer), keyed both ways — the T8sedp blocker (`matched=0`) is CLOSED. **Protected
user DATA does NOT yet flow either direction** (`peak-samples=0` both): Fast DDS reports `89× Key material not
found -> decode_datawriter_submessage` (it lacks our user-WRITER EntityCrypto for the data decode) + `8× Not
valid SecureDataTag submessage id -> decode_rtps_message` (its rtps_protection/SRTPS whole-message decode
rejects some of our datagrams); symmetrically we decode 0 of Fast DDS's 91 sent. REMAINING blocker (next
iteration, a fresh diagnose loop): the user-DATA protection tier — the per-endpoint DatawriterCryptoToken is
not APPLIED by the peer for the data decode and/or our user-data SRTPS_PREFIX/SEC_BODY/SRTPS_POSTFIX wrap
(§8.5.1.10-.12) diverges from `AESGCMGMAC_Transform::decode_rtps_message`; the two may be linked (an
SRTPS-dropped PVMS datagram never installs the token). This tier is reached for the FIRST time because T9 made
the endpoints match; it is distinct from the T9 secure-DISCOVERY reliability + match this iteration delivers.
Connext-Security live = the Slice-5b exit gate (RTI Security Plugins absent). our-to-our green both impls:
secure-discovery keyed/protected/protected-sign/origin-auth + PVMS reliable/fail-closed pass with the new
reliability branches active; make test-sbcl=377; Clasp (`GC_DONT_GC=1`) secure e2es isolation-green (full-suite
abort only the documented `[SDP-SEC-PREFIX-ON-WIRE]` NFR-PORT live-socket flake, wanders, SBCL-clean);
gate-types(2039)/gate-hotpath(8)/corpus/fuzz/mem(0.0000) PASS. Captures:
`interop/security-secure-discovery/captures/ssd-secure-*.log` + `T9protected-RESULT.md`.

### M7/P6 Slice 5 (WP-DDS-SECURITY-FASTDDS-INTEROP) — T10: user-DATA protection tier (PROTECTED DATA ONE DIRECTION achieved, fast2ours) (2026-06-29)

Now that the user endpoints match (T9), the user-DATA protection tier is reached cross-vendor for the first
time. Three conformant divergence fixes; **clean-room, corroborated against the OMG spec + eProsima Fast DDS
(Apache-2.0); RTI Connext never read.**

**(1) Slice-1 serialized-payload AAD reconciled to EMPTY** (`transform.lisp`, `crypto.lisp`,
`crypto/submessage.lisp`). The Slice-1 serialized-payload (data_protection) tier sealed with AAD = the 20-byte
SecureDataHeader (`kind‖key_id‖session_id‖iv_suffix`). Fast DDS does NOT: `AESGCMGMAC_Transform.cpp`
`serialize_SecureDataBody` is ONE function shared by the serialized-payload AND submessage paths, and its
ENCRYPT branch calls `EVP_EncryptUpdate` for the plaintext with **no prior AAD `EVP_EncryptUpdate` call** (⇒
empty AAD); the SecureDataHeader is written as the §9.5.3.3.1 CryptoHeader on the wire but is NOT fed to
AES-GCM as AAD. OMG DDS-Security 1.1 §9.5.3.3.4.4 specifies the SecureDataHeader serialization but the
transform computes the tag over the body, not over the header-as-AAD. Reconciled ours to empty AAD
(`+empty-octets+`, hoisted to `crypto.lisp` so the payload AND submessage tiers share the one instance, DRY).
**This CHANGES the SHIPPED Slice-1 wire behavior**: the serialized fields are byte-identical, but the
GCM-authenticated bytes differ ⇒ the GCM **tag value** differs (the SecuredPayload corpus tag literals are
re-derived). Header integrity is preserved WITHOUT AAD: decode now applies the Fast DDS
`AESGCMGMAC_Transform::find_key` check (wire `transformation_kind` AND `transformation_key_id` must equal the
KeyMaterial's, else fail-closed NIL — rejects a kind/key_id tamper), and `session_id`/`iv_suffix` derive the
AES-GCM session key + nonce (tamper ⇒ GCM auth fail). Recorded as an addendum to ADR 0031.

**(2) KeyMaterial advertised transformation_kind GMAC vs GCM** (`key-material.lisp` `generate-key-material
:kind`; `crypto-manager.lisp` `cm-register-local-entity :kind` + `%cm-entity-protection-kind`). A SIGN endpoint
must advertise `CRYPTO_TRANSFORMATION_KIND_AES256_GMAC {0,0,0,3}` and an ENCRYPT endpoint
`AES256_GCM {0,0,0,4}` (OMG §9.5.2 Table 65 transformation_kind enum), because a conformant receiver's
`find_key` matches a stored token KeyMaterial to an inbound submessage on `transformation_kind` AND
`sender_key_id` together — a SIGN endpoint that advertised GCM is rejected `Key material not found`. The AES-256
master key is identical for GMAC and GCM; only the advertised kind + the SEC_BODY-vs-verbatim framing differ.
We now map each tier's governance protection_kind → the advertised kind on the local EntityCrypto.

**(3) User-DATA submessage protection (metadata_protection, §8.5.1.7-.9)** (`dataplane.lisp`
`%maybe-wrap-user-submessages`/`%wrap-one-user-submessage`/`%pad-submessage-to-4` SEND; `secure-sedp.lisp`
`%on-user-secure-submessage` RECEIVE+re-dispatch; `disc.lisp` slots; `crypto-manager.lisp` resolvers;
`entities.lisp` `%set-user-metadata-protection`). When governance `metadata_protection_kind != NONE`, each
user-plane submessage (DATA/DATA_FRAG/HEARTBEAT/GAP/HEARTBEAT_FRAG under the user-WRITER EntityCrypto;
ACKNACK/NACK_FRAG under the user-READER) is wrapped SEC_PREFIX‖CryptoHeader‖SEC_BODY(ENCRYPT)|verbatim(SIGN)‖
SEC_POSTFIX, INSIDE the rtps_protection SRTPS wrap (submessage-protect inner, whole-message outer — Fast DDS
`RTPSMessageGroup` send order payload→submessage→rtps; `%send-raw-buf` calls `%maybe-wrap-user-submessages`
THEN `%maybe-wrap-srtps`). The plaintext is 4-aligned before sealing (DDSI-RTPS 2.5 §8.3.4; Fast DDS
`predeserialize_SecureDataBody` re-aligns the SEC_BODY to 4 before the SEC_POSTFIX, so a non-4-aligned
plaintext overshoots into `Not valid SecureDataTag`). RECEIVE: a SEC_PREFIX whose key_id resolves to a remote
USER EntityCrypto (not a secure builtin) is decoded and re-dispatched with `rtps-unwrapped=t` (the AEAD already
authenticated it); fail-closed on any decode failure.

**Live re-run (`run-fastdds-interop.sh secure 45`, GOV=secure, both directions):** **PROTECTED USER DATA NOW
FLOWS ONE DIRECTION** — fast2ours `peak-samples=89` (our subscriber decodes Fast DDS's rtps+metadata+data-
protected user DATA end-to-end), was `peak-samples=0` in T9. ours2fast still 0: Fast DDS reports `217× No key
material yet → Function lookup_reader` (+ `1× Could not find key material → decode_datareader_submessage`) — it
receives our protected submessages but has not APPLIED our outbound user `DatawriterCryptoToken`. Notably the
T9 `Not valid SecureDataTag → decode_rtps_message` SRTPS-level rejection is GONE (fronts 1-3 cleared the
outer/tag framing). Residual (next loop, do not chase): the OUTBOUND user-token application at Fast DDS
(`process_participant_volatile_message_secure` → reader-handle map); the inbound path is proven. Connext-Security
live = the Slice-5b exit gate (RTI Security Plugins absent). our-to-our GREEN both impls: `make test-sbcl`=378,
`make test-clasp`=378 (full suite, no abort; a one-off stale-`perftest.fasl` FASL-loader fault on the first
attempt cleared by rebuilding the Clasp cache — not a code regression); gate-hotpath(8)/gate-types(2047)/
corpus(stub)/fuzz/mem(0.0000) PASS. tshark dissector environment-limited (macOS lo0 NULL/loopback, ADR 0036) —
the 89-sample live inbound decode is the cross-vendor wire proof. Captures:
`interop/security-secure-discovery/captures/ssd-secure-*.log` + `T10userdata-RESULT.md`.

### M7/P6 Slice 5 (WP-DDS-SECURITY-FASTDDS-INTEROP) — T10 review fixes: SEC_BODY 4-align pad placement + rtps_protection enforce-gate on bare user brackets (2026-06-29)

Code-review fixes on the T10 user-DATA protection tier (HEAD `3e92d08`). The load-bearing corroboration is for
fix-2 (the SEC_BODY 4-octet alignment pad placement); **clean-room, read-only against the OMG spec + eProsima
Fast DDS (Apache-2.0); RTI Connext NEVER read.**

**(fix-2) SEC_BODY CryptoContent 4-align pad — the pad lives in the SEC_BODY container, NOT the plaintext.**
The shipped T10 send path padded the PLAINTEXT user DATA submessage to a 4-multiple (extending octetsToNextHeader
+ appending zeros) before the §8.5.1.7-.9 submessage wrap. On receive the recovered DATA then carried a trailing
pad that inflated `parse-data-body`'s `plen`; for a user DATA whose payload is a data_protection §9.5.3.3
SecuredPayload, `parse-secured-payload`'s STRICT exact-length check rejected the over-long blob -> NIL -> the
sample was SILENTLY DROPPED (metadata_protection + data_protection + non-4-aligned payload — untested by the
green suite because the metadata test used a RAW payload and the data_protection e2e predated metadata_protection).
- **eProsima Fast DDS `src/cpp/security/cryptography/AESGCMGMAC_Transform.cpp`** at
  `/Users/frgo/gbt Dropbox/gbt/projects/fastdds/src/fastdds`:
  - `serialize_SecureDataBody` (read L1531-1706): the ENCRYPT branch (submessage=true) writes
    `SecureBodySubmessage(0x30) ‖ flags`, a dummy uint16 length, then the uint32 `cnt_length`, then the
    ciphertext; at the end it OVERWRITES the SEC_BODY length as `length = (actual_size + final_size + sizeof(uint32_t)); length = (length + 3) & ~3;` (L1677-1679) and serializes `cnt_length` (= the TRUE ciphertext length)
    BIG-ENDIAN (L1682); then `if (submessage)` "Align submessage to 4" writes `serializer.alignment(pos, sizeof(int32_t))`
    zero octets AFTER the ciphertext (L1692-1702). So: cnt_length = the TRUE ciphertext length N (NOT padded);
    SEC_BODY octetsToNextHeader = `(N + 4 + 3) & ~3` (covers cnt_length(4) + ciphertext(N) + pad); the pad is
    zero octets after the ciphertext, inside the SEC_BODY. The PLAINTEXT is never padded.
  - `deserialize_SecureDataBody` (read L1954-2064): reads the BE `protected_len` (= N, L2006), decrypts N bytes,
    sets `plain_buffer_len = N` (L2046), then "Align submessage to 4" advances `decoder.alignment(pos, sizeof(int32_t))`
    octets (L2052-2061) — skipping the pad so the SEC_POSTFIX is read 4-aligned. `predeserialize_SecureDataBody`
    (L2066-2095) computes `body_align` past the SEC_BODY.
  - `encode_rtps_message` calls `serialize_SecureDataBody(..., /*submessage=*/true)` (L554-557), so the
    whole-RTPS (SRTPS) tier uses the IDENTICAL SEC_BODY framing as the submessage tier — our shared
    `%encode-secured-region` / `%decode-secured-region` ENCRYPT branch is correct for both.
- **OMG DDS-Security 1.1 §9.5.3.3.4.4** (crypto_content) + **DDSI-RTPS 2.5 §8.3.4** (submessage 4-alignment).
- **Implemented:** `%encode-secured-region` (ENCRYPT) sets octetsToNextHeader = `crypto_content_len(4) + |ct| + pad`
  with `pad = (-|ct|) mod 4` zero octets after the ciphertext (the SEC_BODY content starts 4-aligned, so the
  position-based align reduces to `(-|ct|) mod 4`); `%decode-secured-region` (ENCRYPT) skips that pad (cursor
  align-to-4, bounds-checked via check-room — a pad overrunning the bracket fails closed -> NIL, never an OOB
  read, even at (safety 0)); `%pad-submessage-to-4` (the plaintext padder) is REMOVED — the plaintext is no
  longer padded, so the recovered submessage's octetsToNextHeader reflects its TRUE length and the inner
  SecuredPayload round-trips. **Wire impact:** byte-IDENTICAL for any 4-aligned ENCRYPT body (pad=0) — the
  shipped byte-exact corpus (T2 submessage 32-octet plaintext, T3 origin-auth 32-octet, T4 SRTPS 44-octet
  stream) is unchanged and all corpus tests pass on BOTH impls; the framing changes ONLY for a non-4-aligned
  ENCRYPT body (now Fast-DDS-conformant, was a silent-drop bug on receive). The data_protection serialized-payload
  tier (`serialize-secured-payload`, a separate function) is untouched.

**(fix-1) rtps_protection ENFORCE-gate on bare user metadata_protection brackets (§8.5.1.10-.12).** The receive
dispatch gated every PLAIN user-plane clause (DATA/HEARTBEAT/ACKNACK/GAP/*_FRAG) on `(not enforce-rtps)` but NOT
the user SEC_PREFIX bracket route, so a metadata_protection bracket arriving WITHOUT the mandated outer SRTPS wrap
was decoded + re-dispatched, bypassing the rtps_protection requirement. Fix: `%on-secure-submessage` takes
`enforce-rtps` and drops the USER-bracket route when set; the legitimate post-SRTPS re-dispatch sets
rtps-unwrapped=t so enforce-rtps is NIL there (the wrapped bracket IS delivered); BUILTIN secure brackets
(secure-SEDP/PVMS/SPDP) stay exempt (metatraffic is intentionally plain this slice — the T12 carry). OMG
§8.5.1.10-.12; no wire constant involved.

**(fix-3) empty-AAD directed-tamper coverage** (`security-test.lisp` run-security-payload-roundtrip-test): added
directed byte-flip arms for transformation_key_id (find_key reject), session_id and init_vector_suffix (nonce/KDF
-> GCM auth fail), closing the analytical-only gap left when the AAD was reconciled to EMPTY (T10).

**(fix-4) NONE-tier static-arena short-circuit** (`%maybe-wrap-user-submessages`): when
`user-submessage-protection-kind` is `:none` the function returns immediately (the encode resolver declines every
submessage anyway — see the crypto-manager install), skipping the `(+ len 8192)` static alloc + stream walk on
every keyed user-data send; wire byte-identical.

**our-to-our GREEN both impls:** `make test-sbcl`=380, `make test-clasp`=380 (full suite, no abort; +2 new tests:
`user-submessage-data-protection`, `rtps-protection-enforce-user-bracket`); gate-hotpath(8)/gate-types(2048)/
corpus(stub)/fuzz/mem(0.0000) PASS. The fuzz submessage-protection + rtps-message arms (adversarial brackets,
prod + safety-0) exercise the new decode pad-skip's bounds check. The fix-2 test was written FAILING-FIRST
(recovered payload 60 vs 57 octets -> decode NIL) then made green. tshark dissector environment-limited (ADR 0036).

## WP-DDS-SECURITY-FASTDDS-INTEROP T11reverse — ours2fast protected user DATA: data-representation match + SecureDataTag 4-align (Slice 5, 2026-06-30)

The REVERSE-direction blocker closed: cross-vendor PROTECTED USER DATA now flows BOTH ways (the DoD). Live
`run-fastdds-interop.sh secure 45` vs eProsima Fast DDS v3.6.1: ours2fast = Fast DDS RECEIVED 8/8 of our
ENCRYPT-protected `HelloWorld` ('Hello world from Lisp', index 0..7); fast2ours = we decode 88 of Fast DDS's
(unchanged). Two divergences in dependency order, each diagnosed from the live peer + the clean-room Fast DDS
source + our bytes (tshark cannot dissect lo0, ADR 0036).

- **Sources consulted — Fast DDS (Apache-2.0, eProsima) READ FOR UNDERSTANDING ONLY, no code copied; NO RTI.**
  `src/cpp/rtps/builtin/discovery/endpoint/EDP.cpp` `valid_matching` + `checkDataRepresentationQos` (the
  XTypes Table 7.57 writer/reader data-representation compatibility, enforced at match); `src/cpp/security/
  cryptography/AESGCMGMAC_Transform.cpp` `preprocess_secure_submsg`/`lookup_reader`/`decode_serialized_payload`/
  `serialize_SecureDataTag`/`serialize_SecureDataBody`/`encode_serialized_payload`; `src/cpp/rtps/security/
  SecurityManager.cpp` `set_remote_datawriter_crypto_tokens` + the discovered-writer crypto-token apply path.
  Plus the in-repo OMG specs: **DDS-XTypes 1.3 §7.6.3.1.1/.2 Table 7.57/Table 60** (data representation +
  encapsulation ids) and **DDS-Security 1.1 §9.5.3.3.3** (SecureDataTag).

- **Divergence 1 — data-representation QoS (the match, upstream of all crypto).** Our interop peer's user WRITER
  offered XCDR2 only (`make-writer-qos` default `(:xcdr2)`; it serialized D_CDR2_LE). Fast DDS's example HelloWorld
  is `@extensibility(APPENDABLE)` and its DataReader runs the default `DataReaderQos` = an EMPTY DATA_REPRESENTATION
  sequence = XCDR1 (`checkDataRepresentationQos`: an XCDR2 writer vs an empty/XCDR1 reader = false, Table 7.57), so
  Fast DDS REJECTED our writer in `valid_matching` ('Incompatible Data Representation QoS') BEFORE any crypto — the
  user writer never matched its reader, its DatawriterCryptoToken stayed in `remote_writer_pending_messages_`, and
  the persistent `No key material yet -> lookup_reader` warnings were benign builtin noise (present IDENTICALLY in
  the working fast2ours direction — the prior iteration's hypothesis that Fast DDS dropped our user token was
  WRONG). fast2ours matched because our READER accepts `(:xcdr2 :xcdr1)`. CONFORMANT FIX: the interop peer's user
  writer offers XCDR1 (PLAIN_CDR, `%hello-world-payload :xcdr1`) — the symmetric resolution already recorded for
  WP-FLATDATA-XCDR-TRANSCODE (this file, M5 2026-06-17: Fast DDS enforces §7.6.3.1.1 on the writer side and won't
  match its XCDR1-default reader unless XCDR1 is offered). Harness-only (`src/dds-tests/secure-interop.lisp`); no
  core/wire change; our stack's XCDR2 default is per-spec and unchanged.

- **Divergence 2 — data_protection SecureDataTag 4-byte alignment (the user-DATA decode, surfaced once the match
  worked).** With the match fixed, Fast DDS reached `decode_serialized_payload` and failed: 'Error in fastcdr
  trying to deserialize SecureDataTag length'. Fast DDS `serialize_SecureDataTag` aligns the
  `receiver_specific_macs` sequence length to a 4-byte boundary relative to the SecuredPayload start (AFTER the
  common_mac) — so a SecuredPayload is `header(20) ‖ ct_len(u32 BE) ‖ ciphertext(N) ‖ common_mac(16) ‖ <pad to
  4> ‖ rsm_count(u32 BE)`, always 4-aligned in total. Our `serialize-secured-payload`/`serialize-crypto-footer`
  omitted the pad, so for a non-4-aligned N (our 34-octet XCDR1 payload) Fast DDS read `rsm_count` 2 octets past
  the buffer end. fast2ours worked only because Fast DDS's own 'Hello world' payload is N=24 (already 4-aligned).
  CONFORMANT FIX (`serialize-crypto-footer`/`parse-crypto-footer` in `src/dds-security/crypto/crypto-header.lisp`,
  `serialize-secured-payload`/`parse-secured-payload` in `src/dds-security/crypto.lisp`): `(align cursor 4)` the
  `rsm_count` relative to the bracket start, exactly as Fast DDS does. PROVABLE NO-OP for the submessage/whole-RTPS
  brackets (their framing already lands the common_mac 4-aligned, pad 0 — submessage + rtps-message corpus
  UNCHANGED, byte-exact) and for the existing secured-payload corpus (its ciphertext is 4 octets, pad 0). It only
  adds the pad for a bare SecuredPayload with non-4-aligned ciphertext — the conformant Fast-DDS-faithful shape.
  `run-user-submessage-data-protection-test` updated: its pre-fix premise (a non-4-aligned SecuredPayload) was the
  non-conformance this closes, so it now asserts data_protection self-4-aligns the SecuredPayload (stronger).

**our-to-our GREEN both impls:** `make test-sbcl`=380; `make test-clasp`=380 (full suite, clean this run; the
documented NFR-PORT live-socket/threading flake is intermittent — it wanders between tests/runs, re-run not
chased; the secure suite also passes in isolation). gate-hotpath(8)/gate-types(2048)/corpus(stub)/fuzz/
mem(0.0000) PASS. Connext-Security live stays the Slice-5b exit gate (RTI Security Plugins absent).

## WP-DDS-SECURITY-CONNEXT-INTEROP — external RTI Connext secured HelloWorld publisher (M7/P6 Slice 5b Phase 5, 2026-07-02)

External interop peer, NOT part of the clean-room stack (same category as the Fast DDS security interop peer).
`interop/security-connext/HelloWorld.idl` is OUR clean-room IDL, transcribed from our interop type definition
(`src/dds-tests/secure-interop.lisp` — Fast DDS's example `@appendable struct HelloWorld { unsigned long index;
string message; }`, topic "HelloWorldTopic", type name "HelloWorld", NO_KEY, XCDR1/PLAIN_CDR); authored FROM the
type definition, never copied from RTI source or rtiddsgen output. The type support (`HelloWorld*.cxx/.hpp`) is
GENERATED by `$NDDSHOME/bin/rtiddsgen -language C++11` (RTI tooling usage, kept OUT of `src/`, git-ignored). The
publisher `interop/security-connext/hello_secure_pub.cxx` is a minimal Modern C++11 RTI Connext DomainParticipant
(`-lnddscpp2 -lnddsc -lnddscore`, built via the shared `interop/connext/common/common.mk`) that loads the
`OursConnextInterop::secure` QoS profile (our reused Identity-CA / Permissions-CA / governance-secure / S/MIME
permissions) and publishes secured HelloWorld samples for the reverse-direction (Connext=publisher → ours=sub) leg
of the Slice-5b exit gate. RTI Connext SOURCE / libnddssecurity internals were NEVER read (only rtiddsgen + the
example build makefiles — tooling). For the auth-handshake root-cause analysis below, the DDS-Security 1.1
AuthRequestMessageToken sub-protocol was corroborated against the **OpenDDS** reference implementation
(`dds/DCPS/security/AuthenticationBuiltInImpl.cpp`, OpenDDS is DDS-licensed / open source, READ FOR UNDERSTANDING
ONLY) and **Fast DDS** (Apache-2.0) `PKIDH.cpp` — no code copied; NO RTI source read. Provenance category:
identical to the Fast DDS interop peer (external, rtiddsgen-generated, not clean-room). No RTI license into `src/`.

## WP-DDS-SECURITY-CONNEXT-INTEROP — §8.7.2.3 AuthRequestMessageToken sub-protocol (M7/P6 Slice 5b, 2026-07-02)

Clean-room derivation of the DDS-Security 1.1 §8.7.2.3/§8.7.2.4/§8.7.2.5 AuthRequestMessageToken (future_challenge)
challenge-binding, to implement full-participant (RTI Connext) interop. Authority = the OMG DDS-Security 1.1 clauses;
behavioral corroboration READ FOR UNDERSTANDING ONLY (no code copied) from two independent open implementations:
- **OpenDDS** (DDS-licensed / open source), `dds/DCPS/security/AuthenticationBuiltInImpl.cpp` (master): the exact
  logic — `validate_remote_identity` mints one `future_challenge` nonce per remote (`SSL::make_nonce_256`), sending
  it iff the peer's auth_request was not yet received; `begin_handshake_request` sets `challenge1` = the local
  future_challenge VERBATIM; `begin_handshake_reply` verifies incoming `challenge1 == initiator future_challenge`
  (iff received) and sets `challenge2` = the replier's own future_challenge; `process_handshake_reply` verifies
  `reply.challenge2 == replier future_challenge` (iff received) + `reply.challenge1 == our sent challenge1`;
  `challenges_match` is a raw `memcmp` (exact byte equality, no hashing) that also rejects empty sequences. Class
  strings: `dds/DdsSecurityCore.idl` GMCLASSID_SECURITY_AUTH_REQUEST = "dds.sec.auth_request",
  `build_class_id("AuthReq")` = "DDS:Auth:PKI-DH:1.0+AuthReq", nonce binary_property name "future_challenge".
  `dds/DCPS/RTPS/Spdp.cpp`: message_identity.source_guid = participant GUID (ENTITYID_PARTICIPANT),
  sequence_number = a single monotonic per-writer counter (`++stateless_sequence_number_`) shared across
  auth_request + all handshake messages; related_message_identity = {GUID_UNKNOWN,0} originating / echo of the
  triggering message_identity when replying.
- **Fast DDS** (Apache-2.0), `src/cpp/security/authentication/PKIDH.cpp` (v3.6.1): CONFIRMS the sub-protocol is
  §8.7.2.3-OPTIONAL — begin_handshake_request uses a fresh random `challenge1` (`generate_challenge`), no
  future_challenge/auth_request exists in the file; begin_handshake_reply echoes challenge1 + fresh challenge2;
  `SecurityManager::process_participant_stateless_message` GRACEFULLY DISCARDS an unknown message_class_id
  ("Discarted ParticipantGenericMessage with class id ...") — so emitting our auth_request to a Fast DDS peer is
  a safe no-op (no false-reject). This grounds the absence-tolerance (ours↔Fast-DDS must not regress).
NO RTI Connext / libnddssecurity / rtiddsgen SOURCE was read. Fast DDS + OpenDDS read via the local checkouts /
public GitHub master for understanding only; no code copied into `src/`.

## M7/P6 — WP-SECURITY-DATA-SIGN-PAYLOAD: data_protection=SIGN payload-tier GMAC (2026-07-03)

- **OMG DDS-Security 1.1 §9.5.3.3.4 / §9.5.3.3.4.3** — primary authority for `encode_serialized_payload` and its
  GMAC (SIGN) variant (authenticate the VISIBLE serialized payload with an AES-GMAC common_mac, no encryption).
- **eProsima Fast DDS (Apache-2.0) — read for understanding only, NO code copied** (clean-room READ authorized).
  File `src/cpp/security/cryptography/AESGCMGMAC_Transform.cpp` at `/Users/frgo/gbt Dropbox/gbt/projects/fastdds/src/fastdds`:
  - `encode_serialized_payload` (read L76-177): serialize_SecureDataHeader (the 20-octet CryptoHeader) then
    `serialize_SecureDataBody(..., /*submessage=*/false)` then `serialize_SecureDataTag(..., /*submessage=*/false)`.
    The body function is the SAME one the submessage tier uses; `submessage=false` is the serialized-payload tier.
  - `serialize_SecureDataBody` (read L1531-1706): `do_encryption` is true ONLY for AES128/256-**GCM** (L1542-1543).
    The **GMAC** branch (`!do_encryption`, L1578-1606) `memcpy`s the plaintext **VERBATIM** onto the wire (L1588) and
    writes **NO `cnt_length`** (the 4-byte crypto_content.length + the submessage 4-align pad are inside the
    `else`/ENCRYPT arm, L1607+ / L1692-1703 `if (submessage)` — ENCRYPT/submessage-only). AAD = the plaintext
    (`EVP_EncryptUpdate(e_ctx, nullptr, &sz, plain_buffer, plain_buffer_len)`, L1591); the common_mac is the GMAC.
    Comment L1580 verbatim: "Auth only. SEC_BODY should not be created. Plain buffer should be copied instead."
  - `serialize_SecureDataTag` (read L1708-1735, empty `receiving_crypto_list`): writes `common_mac(16)`, aligns to 4
    (relative to the buffer origin — for a 4-aligned payload the pad is 0), then `receiver_specific_macs_count(4)`.
  - `decode_serialized_payload` (read L1329-1454): for the GMAC case (`!is_encrypted`, L1414-1420) it computes
    `body_length = encoded_payload.length − sizeof(header)(=20) − (sizeof(uint32_t)+16)(=20)` — i.e. **N = total − 40**,
    with no length prefix — then `deserialize_SecureDataBody` (L1954-2064, `!do_encryption`, L2018/L2047-2050) GMAC-
    verifies over the body and `memcpy`s it out. This is only self-consistent when N ≡ 0 mod 4 (serialized CDR
    payloads are 4-aligned in practice), matching our no-pad, no-length-prefix `40 + N` GMAC layout byte-for-byte.
  - **DECISION as implemented:** the GMAC serialized-payload SecuredPayload = `SecureDataHeader(20)` ‖ `plaintext(N
    VERBATIM)` ‖ `common_mac(16)` ‖ `receiver_specific_macs_count(4)=0`, total `40 + N`; the common_mac is a GMAC over
    the plaintext (AAD=plaintext, empty ciphertext), nonce = session_id ‖ init_vector_suffix, session key via the
    unchanged §9.5.3.3.4.2 KDF. The ENCRYPT tier (§9.5.3.3.4.4) is byte-identical + UNCHANGED. `transform.lisp`
    branches on the km's `transformation_kind`; the GMAC uses `aes-256-gcm-seal-into`/`-open-into` with `pt-len`/`ct-len`
    0 (the ZA-2 submessage-SIGN GMAC-into pattern reused at the payload tier). NO RTI Connext source consulted. CLEAN-ROOM.

## WP-DURABILITY-SQLITE (2026-07-06) — SQLite persistence backend (ADR 0049)

- **cl-sqlite (ASDF system `sqlite`, Kalyanov Dmitry, Public Domain) — USED as a dependency**
  (Quicklisp dist 2026-01-01). CFFI binding over the native `libsqlite3` — the same impl-agnostic
  native-FFI seam `dds-dare` uses for OpenSSL, so it loads + round-trips identically on Clasp and
  SBCL (verified as the mandatory first step; no reader conditionals). The durability SQLite backend
  (`src/dds-durability/store-sqlite.lisp`) is written from the OMG DDS durability contract + the
  existing in-repo `durable-store` vtable (`store.lisp`) and file-store sibling (`store-file.lisp`);
  the SQL is standard SQLite DDL/DML. Transitive dependency **iterate** (1.6.0, MIT). Native runtime
  **libsqlite3** (3.51.0 verified on this host). All three added to `sbom.spdx.json` via
  `scripts/generate-sbom.py`. **No RTI Connext source/headers/generated code consulted or copied.**
  **No other DDS implementation's persistence code read.** CLEAN-ROOM.

## ADR 0079 (2026-07-22) — Fast DDS LargeData peer (`interop/fastdds/largedata/`, DATA_FRAG leg 7)

- **Same provenance basis as the M4 Fast DDS shapes harness above.** `LargeData.idl` is COPIED from this
  repo's own `interop/connext/large-data/LargeData.idl` (our harness type: `@final`, `@key long id`,
  unbounded `sequence<octet> payload`) — our IDL, not a vendor's. `large_sub.cpp` is written against the
  public Fast DDS DDS-PIM API from its published documentation, and is structurally modelled on this repo's
  own `interop/fastdds/shapes/shapes_sub.cpp`; `participant_guard.hpp` is copied verbatim from that same
  in-repo harness.
- The `fastddsgen` output under `interop/fastdds/largedata/gen/` is **committed verbatim**, on the same
  terms as `interop/fastdds/shapes/gen/` (see the M4 entry): it is generated FROM OUR OWN IDL by the
  vendor's generator, it is harness-only, and **no part of it is read into or reused by `src/`**.
- **No RTI Connext source/headers/generated code consulted or copied. No Fast DDS library source read** —
  only its public API documentation. CLEAN-ROOM.

## ADR 0081 (2026-07-22) — RTI Connext shared-memory Locator_t recognition

- **Public sources only.** The locator kind value is RTI's **published** constant
  `NDDS_TRANSPORT_CLASSID_SHMEM` (`include/ndds/transport/transport_common_user.h`), also exposed in their
  public API as `rti::core::Locator::Kind::SHMEM`. Addressing facts (segment named from the port number,
  the port→key mappings, port a function of `domain_id` and `participant_id`) come from RTI's **shipped
  public API documentation** (`doc/api/connext_dds/api_c/group__NDDS__Transport__Shmem__Plugin.html`) and
  from the **shipped public header** `include/ndds/transport/transport_shmem.h`.
  > **CORRECTION (2026-07-22, ADR 0081 §4).** This entry originally recorded "segment key `0x800000 + port`,
  > mutex/semaphore keys `0xb00000 + port`". That is **wrong**. `transport_shmem.h:50-66` declares the fields
  > in the order `segmentKey`, `semaphoreKey`, `mutexKey` and the default initializer at `:194-199` supplies
  > `0x400000, 0x800000, 0xB00000` respectively. The correct mapping is **segment `0x400000 + port`**,
  > semaphore `0x800000 + port`, mutex `0xB00000 + port`, confirmed against live `ipcs` output.
- **Cross-checked against the ordinary RTPS wire.** A live Connext 7.3.1 participant with
  `transport_builtin` mask `UDPv4 | SHMEM` was observed via **standard SPDP discovery**, which this stack
  already parses. It advertised kind `#x01000000` alongside its UDPv4 locators, with `port` equal to the
  ordinary RTPS port and an address of 12 significant octets then 4 zeros. Two participants on the SAME
  machine advertised the SAME 12 octets with DIFFERENT ports, establishing host-vs-participant split; 96
  bits = 12 octets matches the published `NDDS_TRANSPORT_SHMEM_ADDRESS_BIT_COUNT` of -96.
- **NOT consulted:** no RTI source, no disassembly, no decompilation, and no inspection of shared-memory
  segment contents. Nothing beyond published headers, published API documentation, and public RTPS
  discovery traffic. **The on-segment format is NOT documented in either source and is NOT implemented
  here** — this ADR covers locator RECOGNITION only.

## ADR 0081 slice 2 (2026-07-22) — RTI Connext shared-memory segment layout, established by observation

- **Owner decision, on the record.** Three routes were identified and put to the owner explicitly *before*
  any was built: (A) drive RTI's own SHMEM transport through their published `NDDS_Transport_Plugin` C API;
  (B) ship a transport plugin loaded into Connext through the documented `dds.transport.load_plugins`
  mechanism; (C) reconstruct the segment layout by observation. Each was presented with its cost. **The
  owner — who is the licensee — chose route C.** Routes A and B are recorded in ADR 0081 §3 so the decision
  can be revisited without re-deriving the analysis.
- **Sources used, exhaustively:**
  1. **Shipped public headers** — `include/ndds/transport/transport_shmem.h`, `transport_interface.h`,
     `transport_interface_user.h`, `transport_common_user.h`. These are the headers a customer compiles
     against.
  2. **Shipped public documentation** — the Connext 7.3.1 User's Manual and Properties Reference under
     `doc/manuals/`, for `dds.transport.shmem.builtin.*` property semantics, defaults and ranges.
  3. **The exported-symbol table of the shipped libraries** (`nm -gU libnddscore.dylib`), read to establish
     which documented entry points are externally linkable. This is the dynamic export table any linker
     reads; no code was disassembled or decompiled.
  4. **Ordinary RTPS SPDP discovery traffic**, parsed by this stack's existing discovery path.
  5. **Live shared-memory segments** created by RTI's own shipped tools (`rtiddsping`, and the harness's
     `shapes_pub`) running on the owner's licensed installation, **attached read-only** (`SHM_RDONLY`)
     through the operating system's System V IPC API.
- **Method — controlled variation, not inference from a dump.** Documented properties
  (`received_message_count_max`, `receive_buffer_size`, `parent.message_size_max`, `host_id`) were set to
  distinctive values through Connext's own QoS XML, and the resulting segments were compared. A field is
  recorded as identified **only** where a chosen value appeared at a predicted location; every entry in
  ADR 0081 §5 is labelled with how it was established, and fields that merely varied are recorded as *not
  identified* rather than guessed.
- **NOT done:** no RTI source code read or copied; no disassembly; no decompilation; no static analysis of
  their binaries beyond the exported-symbol table above; no modification of any RTI library or tool; no
  writes to any RTI-created shared-memory segment. Segments created by the probe runs were removed
  afterwards; segments belonging to other processes were left untouched.
- **Scope limit.** The layout is valid for shmem protocol `majorVersion` 2, Connext 7.3.1,
  `arm64Darwin20clang12.0`. ADR 0081 §7 requires an implementation to refuse a segment whose `majorVersion`
  it has not been validated against, rather than misparse it.

## M4 — Connext 7.3.1 MUTABLE wire capture (2026-07-25, ADR 0086)

- **Purpose:** FR-CDR-8's last uncovered dimension. The byte-exact corpus covered FINAL and APPENDABLE;
  MUTABLE — the encoding with a header on every member — had never been checked against an external
  encoder, so its framing rested entirely on our own reading of DDS-XTypes 1.3 rules (21)–(25).
- **Sources consulted:** the OMG specifications (`docs/specs/xtypes-1_3.pdf` §7.4.1.2.1, §7.4.3.4.2,
  §7.4.3.5 rules (21)–(25), Table 34; `docs/specs/rtps-2_5.pdf` §9.4.2.11) and **the octets a live RTI
  Connext 7.3.1 DataWriter transmitted** on the owner's licensed installation, received by this stack's
  own subscriber. Nothing else.
- **Artifacts tracked:** `interop/connext/mutable/MutableData.idl`, the hand-written
  `mutable_pub.cxx` driver, its `Makefile` and `README.md`, and the captured payload
  `corpus/xcdr2/mutabledata-connext.bin` (72 octets). **Not tracked:** all `rtiddsgen` output, the
  `mutable_pub` binary, and the RTI dylib symlinks — git-ignored, produced at build time (NFR-IP).
- **Why the octets are not RTI's expression of the encoding.** The vector is a SerializedPayload: the
  OMG-specified byte layout for a sample whose field values are fixed by rule in
  `dds.bench::%corpus-mutable-sample`. It contains no RTI code, no generated code, and no RTI-authored
  text; a conformant implementation of the cited clauses must produce the same octets.
- **NOT done:** no RTI source, headers or `rtiddsgen` output read or copied; no disassembly; no
  decompilation. `rti::topic::to_cdr_buffer` was deliberately **not** used — it returns a local CDR
  buffer that is neither padded nor carries the OPTIONS pad bits, and a corpus built from it would once
  have certified bytes ADR 0061 proved malformed. The oracle is the wire.
- **What it corrected.** Three details of our XCDR1 encoder, each derived from the clause and each
  wrong: the parameter length is padded to a multiple of 4; the list terminator carries
  FLAG_MUST_UNDERSTAND (`0x7F02`); and Connext sends `@mutable` as PL_CDR (XCDR1), not PL_CDR2 — so the
  parameter-list framing, not the EMHEADER framing, is what interoperates with it. See ADR 0086 §A5.

## M4 — Fast DDS 3.6.1 MUTABLE peer + second-vendor vector (2026-07-25, ADR 0086 §A7)

- **Purpose:** settle whether a SECOND vendor emits `PL_CDR2` for `@mutable`, which RTI Connext does
  not — leaving the XCDR2 length-code choice with no external encoder behind it. Answer: **no**, Fast
  DDS also emits `PL_CDR` (`0x0003`). The experiment instead established that the two vendors **disagree
  with each other** on three fields of the XCDR1 parameter framing (declared lengths padded to 4 vs
  exact; terminator `0x7F02` vs `0x3F02`), both defensibly — see ADR 0086 §A7.
- **Sources consulted:** the OMG specifications, and the octets a live Fast DDS DataWriter transmitted,
  received by this stack's own subscriber. No Fast DDS source was read or copied into the harness.
- **Artifacts tracked:** `interop/fastdds/mutable/MutableData.idl`, the hand-written `mutable_pub.cpp`,
  its `Makefile`, `profiles.xml`, `participant_guard.hpp`, the captured payload
  `corpus/xcdr2/mutabledata-fastdds.bin` (72 octets), **and `gen/`**.
- **On `gen/` being committed — the licence distinction, stated because it is the opposite of the
  Connext rule and the two are easy to conflate.** `fastddsgen` output is **Apache-2.0** and is
  committed verbatim, exactly as `interop/fastdds/shapes/gen/` and `largedata/gen/` already are (see
  `interop/fastdds/README.md`). RTI `rtiddsgen` output is **proprietary and is never committed** —
  `interop/connext/mutable/` therefore tracks only the IDL, the two hand-written drivers, the Makefile
  and the README, with all generated files git-ignored. Both peers in this work package follow their
  respective rule.
  *(Correction to the record: the commit message for `6914459` states "fastddsgen output and the binary
  git-ignored". That is wrong on the first half — the generated sources are committed, by the policy
  above — and was wrong on the second half until the ignore rule was added here. The tree is correct;
  the message was not.)*
- **NOT done:** no vendor source read or copied; no disassembly. The vector is a SerializedPayload —
  the OMG-specified byte layout for a sample whose values are fixed by rule in
  `dds.bench::%corpus-mutable-sample`.

## 2026-07-26 — RTI Connext PUBLIC API documentation consulted for extension-listener semantics

**What was consulted, and why.** The owner asked for parity with six RTI Connext DataWriterListener
extension callbacks, and then asked precisely when Connext fires two of them. Answering from memory would
have been guesswork, so RTI's **public online API reference and User's Manual** on `community.rti.com`
were read:

- `.../7.3.0/doc/api/connext_dds/api_cpp/classDDSDataWriterListener.html` — the callback list and each
  callback's firing condition and argument type.
- `.../current/doc/api/connext_dds/api_c/group__DDSDataWriterResourceLimitsQosModule.html` and
  `.../structDDS__DataWriterResourceLimitsQosPolicy.html` — `instance_replacement`,
  `replace_empty_instances`, and the replaceability precondition.
- `.../current/doc/manuals/.../RTPS_Locators.htm` — the locator REACHABILITY PING mechanism.

**Scope of the reading — deliberately narrow.** PUBLIC DOCUMENTATION ONLY: no RTI header, no shipped
source, no `rtiddsgen` output, and no disassembly. Nothing was copied. What was taken is *behavioural
description* — when a callback fires and what it is handed — which is the same class of information a
published specification provides and is what any interoperating implementation must know.

**Why this is not a clean-room problem, and where the line is.** The operating contract forbids copying
RTI source, headers or generated output; it does not forbid reading a vendor's published description of
observable behaviour. These are VENDOR-EXTENSION statuses with no OMG clause behind them, so there is no
specification to implement from — the public documentation *is* the only citable source, and the
alternative is inventing semantics and calling them parity.

**What it changed.** Three corrections, all in our favour for honesty:
1. `on_sample_removed` fires in Connext only for samples written **with a cookie or under Zero
   Copy/FlatData**, and is handed a `DDS_Cookie_t`. It is NOT a general "a sample left the cache" event.
2. `on_reliable_writer_cache_changed` is **watermark-driven** (empty / full / high- and low-watermark
   crossings), not per-change.
3. **`on_destination_unreachable` does not appear in the 7.3 DataWriterListener at all.** It had been
   listed from memory; Connext's actual answer to an unreachable destination is the internal locator
   REACHABILITY PING (5.3.0+), which stops using the locator rather than notifying the application.

Any callback we ship under a Connext name must match the semantics above or be documented as
deliberately different — a familiar name with different firing rules is worse than a new name.

## 2026-07-26 (addendum) — the RTI status FIELD SET, and one default deliberately not adopted

**What was consulted.** Two further pages of the same **public** RTI Connext API reference, to settle the
field set of the status this stack was about to define rather than invent one:

- `.../7.3.0/doc/api/connext_dds/api_cpp/structDDS__ReliableWriterCacheChangedStatus.html` — the seven
  fields and what each counts.
- `.../7.3.0/doc/api/connext_dds/api_cpp/structDDS__RtpsReliableWriterProtocol__t.html` — the
  `high_watermark` / `low_watermark` fields: their unit, their documented defaults, and which QoS policy
  carries them.

Same narrow scope as the 2026-07-26 entry above: **public documentation only**, no header, no shipped
source, no generated output, no disassembly, nothing copied. What was taken is *behavioural description* —
what a status counts and when a threshold crossing is reported.

**What it changed, and one thing it deliberately did not.**

1. The status carries **four** event counts, not two: empty, full, **low watermark** and **high
   watermark**. Our first cut had only empty and full, which is why it had no way to be anything but
   level-triggered.
2. It carries `replaced_unacknowledged_sample_count`. That is where RTI puts the "a sample was overwritten
   while still unacknowledged" fact — so this stack puts it there too, which is what allowed the separate
   `SAMPLE_REMOVED` status to be withdrawn rather than renamed (ADR 0089 §5).
3. The watermarks live in the **DataWriterProtocol** QoS, are measured in unacknowledged samples, and are
   documented with defaults `low_watermark = 0`, `high_watermark = 1`.

**The defaults were read and then NOT adopted, on purpose.** In Connext the pair primarily drives an
internal mechanism — the switch to `fast_heartbeat_period` — and the status change is a by-product. This
stack has no such mechanism, so here the pair drives an application callback, and at `{0, 1}` an ordinary
reliable exchange with one sample in flight fires twice per sample. Copying the number while omitting the
mechanism it was chosen for would be parity in appearance only. Both watermarks therefore default to
disabled here, and the divergence is documented at the QoS slot, in `docs/wiki/dcps.md` and in ADR 0089
§4.2 rather than left for someone to discover. Reading a vendor's published defaults tells you what they
chose; it does not tell you it is right for a different design.

## 2026-07-27 — the Wireshark RTPS dissector + RTI public API docs, for APP-ACK (ADR 0090)

**What was consulted, and why.** Application acknowledgment is an RTI vendor extension with **no OMG
clause at all** — verified, not assumed: an exhaustive search of `docs/specs/rtps-2_5.pdf` (11 088
extracted lines) and `rtps-2_5-xmi.xml` returns **zero** occurrences of application acknowledgment in any
phrasing, and `dds_rtf2_dcps.idl` mentions only `wait_for_acknowledgments`, which is protocol-level. With
no specification to implement from, two external sources were read:

1. **RTI's public API reference** (`community.rti.com/.../7.3.0/...`) — `DDS_ReliabilityQosPolicy`,
   `DDS_ReliabilityQosPolicyAcknowledgmentModeKind` and `DDS_AcknowledgmentInfo`: the four acknowledgment
   modes, what causes a sample to become acknowledged in each, and the four fields of the info struct.
   Same narrow scope as the 2026-07-26 entries: **public documentation only**, no header, no shipped
   source, no `rtiddsgen` output, no disassembly, nothing copied.

2. **The Wireshark RTPS dissector**, via the *installed binary's own metadata* — `tshark -G values` and
   `tshark -G fields` on Wireshark 4.6.6. This yields the submessage-id table (`APP_ACK 0x1c`,
   `APP_ACK_CONF 0x1d`) and the dissector's field names for their structure (`virtualWriterCount`,
   `octetsToNextVirtualWriter`, `intervalCount`, `intervalFlags`, `intervalPayloadLength`, `count`).

**Why the Wireshark reading is sound, and where its line is.** Wireshark is **GPL** — the operating
contract permits reading open source *for understanding* while forbidding copying, because copying imports
the licence (NFR-IP, IMPLEMENTATION-PLAN §11). Nothing was copied: what was taken is a **field-name
inventory produced by running the shipped tool's own introspection flags**, which is the same class of
information a protocol-analyser UI displays to any user. No dissector source was read or adapted, and none
will be — if a codec is written it will be written from a **live capture** validated byte-for-byte, the
method ADR 0086 used for MUTABLE, with the dissector serving only as a labelled view of those bytes.

**What it changed — two findings that reshaped the ADR before a line of code existed.**
1. **`APP_ACK` 0x1c / `APP_ACK_CONF` 0x1d sit in the OMG protocol-reserved range 0x00–0x7f**, not the
   vendor range 0x80–0xff that RTPS 2.5 §9.4.5.1.1 sets aside for exactly this purpose. RTI occupies a
   whole cluster there (0x14, 0x17–0x1e) while using the vendor range elsewhere (`DATA_FRAG_SESSION 0x81`).
   Anything we emit at 0x1c would squat on space the OMG may assign, and is interpretable only under a
   VendorId gate.
2. **The format is built on RTI's *virtual writer* abstraction** (the outer loop is `virtualWriterCount`;
   `HEARTBEAT_VIRTUAL 0x1e` is its sibling) — an identity model this stack does not have. So "APP-ACK
   interop with Connext" is materially larger than the feature name suggests, which is precisely the kind
   of thing that is invisible until someone looks at the wire.

Both are recorded in ADR 0090 §3, and they are why that ADR asks the owner a scope question instead of
proposing an implementation.

## 2026-07-27 (slice A3b) — RTI Connext SEDP vendor PID 0x800b, identified by controlled experiment

**Source consulted.** No new document and no new tool. The **live RTI Connext 7.3.1 wire**, via the
capture harness already committed at `interop/connext/appack/` — peers written here against RTI's public
API, no `rtiddsgen` output or RTI source read into the tree.

**What was done.** Slice A3b needed `acknowledgment_kind` on the SEDP wire (without it the ADR 0090 A3a
RxO gate compares every peer against `:protocol` and an application-acknowledgment pair can never match).
Rather than invent a ParameterId or guess RTI's, the harness was run **three times** with the single value
`acknowledgment_kind` changed in `USER_QOS_PROFILES.xml`, capturing loopback UDP with `tcpdump` (classic
pcap, so no `editcap` step) and comparing the SEDP publication and subscription ParameterLists with a
short ad-hoc parser over the framing this stack already implements:

| `acknowledgment_kind` | SEDP publication 0x800b | SEDP subscription 0x800b |
|---|---|---|
| `PROTOCOL` (the default) | absent | absent |
| `APPLICATION_AUTO` | `01 00 00 00` | `01 00 00 00` |
| `APPLICATION_EXPLICIT` | `03 00 00 00` | `03 00 00 00` |

`0x800b` was the **only** field that moved; every other vendor PID (`0x8000` product version, `0x8002`
entity virtual GUID, `0x8021` compressed TypeObject, and the reader-only `0x8015`) was byte-identical
across all three runs. The values agree with the published `DDS_ReliabilityQosPolicyAcknowledgmentModeKind`
ordering (PROTOCOL 0, APPLICATION_AUTO 1, APPLICATION_ORDERED 2, APPLICATION_EXPLICIT 3), so the reading
rests on **two independent sources**, not on one observation.

**Why this is clean-room (NFR-IP).** What was taken is a **wire value observed from a running product** —
the same class of artefact as `PID_TYPE_OBJECT_LB` (0x8021) and `PID_ENTITY_VIRTUAL_GUID` (0x8002), both
identified the same way and already shipped. No RTI source, header, or generated code was read, decompiled
or adapted; the octets are the interoperability contract, not RTI's expression of it.

**One observation deliberately NOT acted on.** Vendor PID `0x8009` appeared on the **subscription record
only**, reading 1 whenever `acknowledgment_kind` was an APPLICATION kind and 0 under PROTOCOL. Being
reader-only it cannot be the RxO-paired policy, and no published explanation of it was found, so it is
neither emitted nor interpreted. Naming a field we have not identified is what ADR 0089 §5 forbids.
