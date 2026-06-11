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
