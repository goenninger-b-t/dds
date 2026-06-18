# PID_DATA_REPRESENTATION (0x0073) — pinned wire format

The wire-is-oracle pin for WP-DATA-REPRESENTATION Task 1. The `DataRepresentationId_t`
enum values and the `sequence<DataRepresentationId_t>` encoding are pinned from the
**normative DDS-XTypes 1.3 §7.6.3.1.1 clause** (the bundled
`docs/specs/xtypes-1_3-discovery-builtin-topic.idl`) AND verified byte-exact against a
**live RTI Connext 7.3.1** SEDP capture (tshark 4.6.6 RTPS dissector). A live **Fast DDS
3.6.1** capture is the cross-check on the absent-PID path.

## Clause (authoritative): `docs/specs/xtypes-1_3-discovery-builtin-topic.idl`

```idl
typedef short DataRepresentationId_t;                                 // L169
const DataRepresentationId_t XCDR_DATA_REPRESENTATION  = 0;           // L171
const DataRepresentationId_t XML_DATA_REPRESENTATION   = 1;           // L172
const DataRepresentationId_t XCDR2_DATA_REPRESENTATION = 2;           // L173
typedef sequence<DataRepresentationId_t> DataRepresentationIdSeq;     // L175
const QosPolicyId_t DATA_REPRESENTATION_QOS_POLICY_ID = 23;           // L177
@extensibility(APPENDABLE) @nested
struct DataRepresentationQosPolicy { DataRepresentationIdSeq value; };// L180-183
@id(0x0073) DataRepresentationQosPolicy representation;               // L227 (Reader), L261/L293 (Writer/Topic)
```

The IDL header (L3-4) declares this file is serialized with **XCDR version 1**, so the
SEDP ParameterList carries the value in PL_CDR (PL_CDR_LE on the captured wire). The
`DataRepresentationQosPolicy` is **APPENDABLE** — a peer MAY append trailing members after
the sequence, and a reader ignores trailing bytes it does not understand. RTI exploits this
(see below). `DataRepresentationId_t` is a `short` (signed 16-bit); the three defined
values 0/1/2 are all positive so the on-the-wire octets are endianness-direction-identical
to an unsigned 16-bit read.

VERIFIED values: `:xcdr1` <-> 0 (XCDR_DATA_REPRESENTATION), `:xml` <-> 1
(XML_DATA_REPRESENTATION), `:xcdr2` <-> 2 (XCDR2_DATA_REPRESENTATION). These are DISTINCT
from the 16-bit RTPS encapsulation identifiers in `+representation-ids+` (cdr.lisp, Table 60:
PLAIN_CDR_LE=0x0001, CDR2_LE=0x0007) — do not conflate the two namespaces.

## RTI Connext 7.3.1 capture — `connext-sedp-lo0.pcap`

Two Connext participants (`interop/connext/shapes-{pub,sub}`) discovering on loopback
(domain 0, the `interop/connext/liveliness` loopback `USER_QOS_PROFILES.xml` pinning
`allow_interfaces=127.0.0.1`, SHMEM dropped). Captured on `lo0`,
`udp portrange 7400-7460`, clean `WIRESHARK_CONFIG_DIR` (the host's default Wireshark
profile disables the lo0 dissectors).

- **Frame 56 = DiscoveredReaderData** (DATA(r), subscription writer EntityId 0x000004c2)
  carries PID_DATA_REPRESENTATION. **Frame 62 = DiscoveredWriterData** (DATA(w),
  publication writer 0x000003c2) does NOT — RTI elides the default-valued PID for the
  writer (its writer-offered default = XCDR, value 0), exactly as it elides a default
  PID_RELIABILITY.

tshark dissection of frame 56:
```
PID_DATA_REPRESENTATION
    parameterId: PID_DATA_REPRESENTATION (0x0073)
    parameterLength: 12
    Data Representation Sequence[1]
        [0]: XCDR_DATA_REPRESENTATION (0x0)
    Compression Id Mask: 0x00000007, LZ4, BZIP2, ZLIB     <-- RTI vendor trailing extension
```

Raw octets (frame 56, the parameter, little-endian wire):
```
73 00 0c 00   parameterId=0x0073, parameterLength=12  (LE u16 each)
01 00 00 00   sequence count = 1                       (CDR u32 LE)
00 00         value[0] = 0 = XCDR_DATA_REPRESENTATION   (short LE)
00 00         pad to 4-byte alignment
07 00 00 00   RTI Compression Id Mask = 0x00000007      (APPENDABLE trailing member; vendor)
```

So the **conformant `sequence<short>` portion** is `count(u32) + count*short`, then padded
to a 4-byte boundary. RTI appends a 4-byte compression mask (legal under APPENDABLE); a
conformant reader reads the sequence and ignores the trailing bytes. Our parse is
count-driven (reads exactly `count` shorts after the count) so it consumes only the
sequence and ignores any trailing extension — and bounds-checks `count` against the
parameter length first (NFR-SEC-POSTURE).

## Fast DDS 3.6.1 capture — `fastdds-sedp-lo0.pcap`

Two Fast DDS participants (`interop/fastdds/shapes`, loopback `profiles.xml`, UDPv4-only)
discovering on loopback, captured the same way. **Fast DDS emits NO PID_DATA_REPRESENTATION
(0x0073) at all** in its default SEDP — neither DATA(w) nor DATA(r) (zero matches across the
whole capture). Its default representation is XCDR1 (value 0) and it elides the
default-valued PID, like RTI. This pins the **absent-PID path**: a peer that omits 0x0073
defaults to `(:xcdr1)`, which the parse must honor (leave the role default) — never reject.

## What we emit

We emit the bare conformant `DataRepresentationIdSeq`: `count(u32 LE) + count*short(LE)`,
padded to 4. For the reader default `(:xcdr2 :xcdr1)` (Task 2) the value is
`02 00 00 00 | 02 00 | 00 00` = count 2, then shorts 2 (XCDR2) and **0** (XCDR1) — 8 octets, no
pad needed (already 4-aligned). (XCDR1's `DataRepresentationId_t` is **0**, not 1 — id 1 is XML;
see L32. This was verified byte-exact on the live wire in Task 4, `../README.md` §Step 1.) We do
NOT emit the RTI vendor compression mask (clean-room; not a spec member). A peer that reads our
PID gets the standard sequence and ignores nothing.

## Reproduce

```sh
# Connext (two loopback participants):
WORK=/tmp/cap && mkdir -p "$WORK" && cp interop/connext/liveliness/USER_QOS_PROFILES.xml "$WORK/"
ARCH=arm64Darwin20clang12.0
export NDDSHOME=/Applications/rti_connext_dds-7.3.1 \
       DYLD_LIBRARY_PATH="/Applications/rti_connext_dds-7.3.1/lib/$ARCH"
WIRESHARK_CONFIG_DIR=$(mktemp -d) /Applications/Wireshark.app/Contents/MacOS/tshark \
   -i lo0 -f "udp portrange 7400-7460" -w connext-sedp-lo0.pcap &
( cd "$WORK" && "$PWD/interop/connext/shapes-pub/shapes_pub" 0 BLUE 30 ) &
( cd "$WORK" && "$PWD/interop/connext/shapes-sub/shapes_sub" 0 ) &   # ~8 s, then kill all

# Fast DDS (two loopback participants):
( cd interop/fastdds/shapes && ../../../scripts/with-fastdds.sh ./shapes_sub 12 ) &
( cd interop/fastdds/shapes && ../../../scripts/with-fastdds.sh ./shapes_pub GREEN 80 ) &

# Inspect:
WIRESHARK_CONFIG_DIR=$(mktemp -d) tshark -r connext-sedp-lo0.pcap \
   -Y "rtps.param.id == 0x0073" -V
```
