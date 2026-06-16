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
