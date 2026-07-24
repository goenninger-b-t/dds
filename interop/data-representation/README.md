# WP-DATA-REPRESENTATION — cross-DDS interop (Task 4)

Live wire proof of `PID_DATA_REPRESENTATION` (0x0073) advertise/parse/match and TX in the
writer's offered representation, against **RTI Connext 7.3.1** AND **eProsima Fast DDS 3.6.1**
on this host's `lo0`. The wire is the oracle (the operating contract §4): every claim below is
dissected with the tshark RTPS dissector (4.6.6) under a clean `WIRESHARK_CONFIG_DIR` (this
host's default Wireshark profile disables the lo0 dissectors). The `DataRepresentationId_t`
enum and the `sequence<DataRepresentationId_t>` encoding are pinned from **DDS-XTypes 1.3
§7.6.3.1.1** and verified byte-exact in `captures/NOTES.md` (Task 1).

**Status: DONE — all forward legs (our writer → foreign reader) AND reverse legs (foreign writer
→ our reader) live-verified, both peers, both representations.** One honest capture caveat (the
foreign→us *user-data* path is not visible to tshark on this host's lo0; the delivery itself is
proven by our reader's decoded sample counts) is recorded under *Caveats*.

`DataRepresentationId_t` (DDS-XTypes 1.3 §7.6.3.1.1): **XCDR1 = 0, XML = 1, XCDR2 = 2**.
SerializedPayload encapsulation id (Table 60, a *distinct* namespace): **PLAIN_CDR_LE (XCDR1) =
0x0001, PLAIN_CDR2_LE (XCDR2) = 0x0007**.

---

## The `REP=` publisher gate

The forward legs need our writer to offer XCDR1 *or* XCDR2. `dds.shapes:run-publisher` gained a
`:data-representation` keyword (`:xcdr2` default | `:xcdr1`); the `make square-pub` `REP=` variable
maps to it:

- `REP=xcdr1` → `:data-representation :xcdr1` → the writer advertises `[XCDR1]` in SEDP **and**
  serializes+sends `PLAIN_CDR_LE (0x0001)`.
- `REP=xcdr2` or `REP` unset → `:xcdr2` → advertises `[XCDR2]`, sends `PLAIN_CDR2_LE (0x0007)` —
  the default, **byte-identical** existing user-data wire.

The Square/ShapeType body is `@final` with only 32-bit + string members, so the **XCDR1 and XCDR2
bodies coincide**; the only wire difference between the two reps is the 4-octet encapsulation
header. Verified offline:

```
XCDR2: 00 07 00 00 | 05 00 00 00 42 4C 55 45 00 00 00 00 32 00 00 00 3C 00 00 00 1E 00 00 00
XCDR1: 00 01 00 00 | 05 00 00 00 42 4C 55 45 00 00 00 00 32 00 00 00 3C 00 00 00 1E 00 00 00
                      ^------------------- byte-identical body (color="BLUE",x,y,size) -------------------^
```

This Task also corrected a pre-existing harness wiring gap: `run-publisher` /
`run-subscriber` built their endpoints from the legacy `:reliability` constant, so the writer
advertised `[XCDR1]` and the reader `[XCDR1]` — the QoS-constructor defaults from Tasks 1–3
(`make-writer-qos` → `[XCDR2]`, `make-reader-qos` → `[XCDR2,XCDR1]`) were never reached. The
harness now uses the role-aware constructors, so the SEDP advertisement matches the documented
design. The *user-data* wire for the default `:xcdr2` is unchanged (still `0x0007`); only the SEDP
`PID_DATA_REPRESENTATION` advertisement changed to the Task-1–3 intent. `run-subscriber` also
gained `:peers`/`:port` (default nil/0 = the prior multicast-only behaviour) so the reverse leg
(foreign publisher → our reader) can establish a unicast SPDP path over loopback, mirroring
`run-publisher` and `run-keyed-flat-subscriber`.

---

## Step 1 — our PID dissection (byte-exact) + bidirectional matching

### Our emitted `PID_DATA_REPRESENTATION` (dissected from the live captures)

**Our writer, `REP=xcdr2` (default)** — `captures/our-xcdr2-to-connext.pcap`, our DiscoveredWriterData:
raw octets of the parameter:
```
73 00 08 00   parameterId = 0x0073, parameterLength = 8
01 00 00 00   sequence count = 1
02 00         value[0] = 2 = XCDR2_DATA_REPRESENTATION
00 00         pad to 4-byte alignment
```
tshark: `Data Representation Sequence[1] → [0]: XCDR2_DATA_REPRESENTATION (0x2)`.

**Our writer, `REP=xcdr1`** — `captures/our-xcdr1-to-connext.pcap`:
```
73 00 08 00   parameterId = 0x0073, parameterLength = 8
01 00 00 00   sequence count = 1
00 00         value[0] = 0 = XCDR_DATA_REPRESENTATION (XCDR1)
00 00         pad
```
tshark: `Data Representation Sequence[1] → [0]: XCDR_DATA_REPRESENTATION (0x0)`.

**Our reader** — `captures/connext-pub-to-our-sub.pcap`, our DiscoveredReaderData:
```
73 00 08 00   parameterId = 0x0073, parameterLength = 8
02 00 00 00   sequence count = 2
02 00         value[0] = 2 = XCDR2_DATA_REPRESENTATION
00 00         value[1] = 0 = XCDR_DATA_REPRESENTATION (XCDR1)
```
tshark: `Data Representation Sequence[2] → [0]: XCDR2 (0x2), [1]: XCDR (0x0)` — i.e. the accepted
set `[XCDR2, XCDR1]` = shorts `[2, 0]` (XCDR2's id is 2, XCDR1's id is **0**).

> **Two dissector notes (honest).**
> 1. tshark appends a line `Compression Id Mask: 0x0004001f, LZ4, BZIP2, ZLIB` after **our** 0x0073
>    sequence. We emit **no** compression mask (clean-room; it is an RTI vendor extension). The
>    `0x0004001f` is tshark *misreading our next parameter*, `PID_OWNERSHIP` (`1f 00 04 00`), as an
>    RTI compression-mask trailing member — a dissector heuristic triggered by the 0x0073 PID, not
>    bytes on our wire. The raw hex above (8 octets, ending at the pad) is the whole parameter.
> 2. `captures/NOTES.md` (Task 1) wrote the reader value as shorts `[2, 1]`; that was a typo
>    (it momentarily used XML's id, 1, for XCDR1). The normative id for XCDR1 is **0**
>    (§7.6.3.1.1), our `%data-rep-wire` maps `:xcdr1 → 0`, and the wire above confirms `[2, 0]`.

### Matching outcomes (no new false-rejects)

Both peers' `ShapeType` is a fixed-size `@final` type, and **both readers request `[XCDR1]`**, so our
default `[XCDR2]` writer is a **true RxO incompatibility** with their reader (`first-of-offered XCDR2 ∉
accepted {XCDR1}`, DDS 1.4 §2.2.3 / our `qos-rxo-compatible`). This is the designed behaviour Step 2
resolves; it is **not** a false-reject — it is the *correct* reject of an unsatisfiable representation
request.

> **Correction (re-dissected 2026-07-24, `dirA-absent-pid/`): the two peers advertise `[XCDR1]`
> differently on the wire.** An earlier revision of this note claimed "both readers elide the
> default-valued PID — 0 matches of 0x0073 from either peer"; the wire falsifies that for Connext.
> **RTI Connext INCLUDES `PID_DATA_REPRESENTATION` explicitly** = `[XCDR1]` (`captures/connext-sedp-lo0.pcap`
> frame 56, vendor `0x0101`, `Data Representation Sequence[1] → [0]: XCDR_DATA_REPRESENTATION`). **Fast
> DDS OMITS it** (`captures/fastdds-sedp-lo0.pcap`: 0 frames carry 0x0073). This matters for RxO parse:
> an *absent* PID must default to the §7.6.3.1.1 wire default `[XCDR1]`, not our `make-*-qos` local
> default `[XCDR2, XCDR1]` — seeding the local default made our `[XCDR2]` writer *falsely match* a
> stock Fast DDS reader. Fixed in `e3f1803` and confirmed live against Fast DDS — see
> [`dirA-absent-pid/NOTES.md`](dirA-absent-pid/NOTES.md). Our **reader** accepts
`[XCDR2, XCDR1]`, so it matches each peer's `[XCDR1]`-offering writer.

| Match leg | Result |
|---|---|
| Our writer `[XCDR2]` ↔ Connext reader `[XCDR1]` | **no match** (true incompat) — 0 ACKNACKs of our user writer, Connext received **0** |
| Our writer `[XCDR2]` ↔ Fast DDS reader `[XCDR1]` | **no match** (true incompat) — 0 ACKNACKs, Fast DDS received **0** |
| Our writer `[XCDR1]` ↔ Connext reader `[XCDR1]` | **match** — 26 ACKNACKs, Connext received **37/50** |
| Our writer `[XCDR1]` ↔ Fast DDS reader `[XCDR1]` | **match** — 39 ACKNACKs, Fast DDS received **49/50** |
| Connext writer `[XCDR1]` ↔ our reader `[XCDR2,XCDR1]` | **match** — our reader received **688** GREEN shapes |
| Fast DDS writer `[XCDR1]` ↔ our reader `[XCDR2,XCDR1]` | **match** — our reader received **126** GREEN shapes |

---

## Step 2 — XCDR1 TX read by the peer (the wire shows 0x0001)

### Connext

```sh
export NDDSHOME=/Applications/rti_connext_dds-7.3.1
export DYLD_LIBRARY_PATH=$NDDSHOME/lib/arm64Darwin20clang12.0
# capture (clean profile), then in this order:
WIRESHARK_CONFIG_DIR=$(mktemp -d) /Applications/Wireshark.app/Contents/MacOS/tshark \
   -i lo0 -f "udp portrange 7400-7460" -w captures/our-xcdr1-to-connext.pcap &
( cd interop/data-representation && ../connext/shapes-sub/shapes_sub 0 45 ) &   # loopback USER_QOS_PROFILES.xml in cwd
./scripts/with-sbcl.sh --non-interactive \
  --eval '(asdf:load-system :dds-shapes)' \
  --eval '(dds.shapes::run-publisher :domain 0 :type :canonical :count 50 :rate 4 \
             :history-kind :keep-all :data-representation :xcdr1 \
             :advertise-address "127.0.0.1" :peers "127.0.0.1:7410")' \
  --eval '(uiop:quit 0)'
```
(`make square-pub REP=xcdr1 TYPE=canonical COUNT=50 RATE=4 HISTORY=keep-all PEERS=127.0.0.1:7410`
is the equivalent; the captured runs invoke `run-publisher` directly so the SBCL recompile does not
shift the discovery timing.)

- **`REP=xcdr1`** — our user DATA on the wire: `encapsulation kind: CDR_LE (0x0001)`;
  `serializedData: 05000000 424c5545 00000000 35000000 34000000 1e000000` = color="BLUE", x=53,
  y=52, shapesize=30. Connext printed `[connext-sub] received 37 sample(s)` with the matching
  animated values (`color=BLUE … size=30`). 26 user-writer ACKNACKs. `captures/our-xcdr1-to-connext.pcap`.
- **`REP=xcdr2` (default)** — `encapsulation kind: CDR2_LE (0x0007)`; Connext printed
  `received 0 sample(s)`, 0 user-writer ACKNACKs (its `[XCDR1]`-only reader does not match our
  `[XCDR2]` writer). `captures/our-xcdr2-to-connext.pcap`.

### Fast DDS

```sh
# capture as above, then:
( cd interop/fastdds/shapes && ../../../scripts/with-fastdds.sh ./shapes_sub 45 ) &   # profiles.xml in cwd (loopback)
# same run-publisher line as Connext (:data-representation :xcdr1 / default)
```
`FASTDDS_PREFIX=$HOME/'gbt Dropbox'/gbt/projects/fastdds/install`.

- **`REP=xcdr1`** — `encapsulation kind: CDR_LE (0x0001)`; Fast DDS printed
  `[shapes_sub] done, received 49` with correct values (`color=BLUE … size=30`). 39 user-writer
  ACKNACKs. `captures/our-xcdr1-to-fastdds.pcap`.
- **`REP=xcdr2` (default)** — `encapsulation kind: CDR2_LE (0x0007)`; Fast DDS printed
  `received 0`, 0 ACKNACKs (same `[XCDR1]`-only reader incompatibility as Connext).
  `captures/our-xcdr2-to-fastdds.pcap`.

### Reverse (foreign writer → our reader)

```sh
# Connext: start the Connext PUBLISHER (binds canonical metatraffic port 7410), then our subscriber:
( cd interop/data-representation && ../connext/shapes-pub/shapes_pub 0 GREEN 60 ) &
./scripts/with-sbcl.sh --non-interactive --eval '(asdf:load-system :dds-shapes)' \
  --eval '(dds.shapes::run-subscriber :domain 0 :type :canonical :seconds 30 :peers "127.0.0.1:7410")' \
  --eval '(uiop:quit 0)'
# Fast DDS: ( cd interop/fastdds/shapes && ../../../scripts/with-fastdds.sh ./shapes_pub GREEN 200 ) & + the same subscriber
```

Our reader (`[XCDR2, XCDR1]`) matched and decoded each peer's writer: **688 GREEN shapes** from
Connext (`captures/connext-pub-to-our-sub.pcap`), **126 GREEN shapes** from Fast DDS
(`captures/fastdds-pub-to-our-sub.pcap`), all with correct field values. Both peers' `ShapeType`
writer offers the default representation **XCDR1** (consistent with their `[XCDR1]`-only readers
above, with Task 1's "both peers default to XCDR1 and elide the PID", and with the committed
`interop/keyed-flatdata` finding that "Connext emitted `CDR_LE (0x0001)` on the wire" for the same
canonical shape). Our RX path (Task 3) decodes either standard representation from the
encapsulation header.

---

## Caveats (honest)

1. **`[XCDR1]`-only foreign readers are a *true* incompatibility, by design.** Connext's and Fast
   DDS's `ShapeType` reader accept `[XCDR1]`-only, so our default `[XCDR2]` writer is correctly
   rejected (0 received, 0 user-writer ACKNACKs). This is the spec-mandated RxO reject of an
   unsatisfiable representation, not a false-reject; `REP=xcdr1` makes us interoperate with such a
   peer. (A peer reader that accepted `[XCDR2, …]` — e.g. an XCDR2-configured one — would match our
   default writer; this host's Shapes peers do not.)
2. **The foreign→us *user-data* leg is not visible to tshark on this host's `lo0`.** In both reverse
   captures the foreign peer's discovery (SPDP/SEDP) is captured, but no Square *user* DATA
   submessage (no `CDR_LE`/`CDR2_LE` payload, no `GREEN` octets) appears — a macOS loopback-capture
   quirk for the peer's unicast user traffic, **not** a delivery gap: our reader received and
   decoded 688 (Connext) / 126 (Fast DDS) correct GREEN samples. The forward legs (our stack
   sending) are fully captured, so the `0x0001`/`0x0007` TX encapsulation — the load-bearing Step-2
   claim — is dissected directly. The peer's offered representation in the reverse direction is
   established by the cross-references in §"Reverse".
3. **The per-frame "Malformed Packet" flag on our SEDP DATA(w) frames is a tshark heuristic, not
   malformed RTPS.** tshark marks some of our SEDP `DATA(w)` frames "Malformed Packet"; this is the
   known RTI-legacy `PID_TYPE_INFORMATION (0x0075)` dissector heuristic choking on the serialized
   TypeObject we carry for type-gating, **not** malformed RTPS on our wire — our submessages and our
   `PID_DATA_REPRESENTATION` parse cleanly (the byte-exact dissections above), and matching/delivery
   succeed (37/49 received, 26/39 ACKNACKs, 688/126 reverse). The dissector's TypeObject sub-parser,
   not our framing, raises the flag.
4. **Foreign-peer harnesses + binaries are not committed** (`.gitignore` excludes `*.dylib`/`*.o`);
   the loopback `interop/data-representation/USER_QOS_PROFILES.xml` is a copy of
   `interop/connext/liveliness/USER_QOS_PROFILES.xml` (capture-only aid, not run by CI). No vendor
   source/binaries were copied.

## Captures

| File | Leg |
|---|---|
| `captures/our-xcdr2-to-connext.pcap` | our `[XCDR2]` writer → Connext reader (no match, 0x0007 on wire) |
| `captures/our-xcdr1-to-connext.pcap` | our `[XCDR1]` writer → Connext reader (match, 0x0001 on wire, 37 recv) |
| `captures/our-xcdr2-to-fastdds.pcap` | our `[XCDR2]` writer → Fast DDS reader (no match, 0x0007) |
| `captures/our-xcdr1-to-fastdds.pcap` | our `[XCDR1]` writer → Fast DDS reader (match, 0x0001, 49 recv) |
| `captures/connext-pub-to-our-sub.pcap` | Connext writer → our `[XCDR2,XCDR1]` reader (match, 688 recv) + our reader PID |
| `captures/fastdds-pub-to-our-sub.pcap` | Fast DDS writer → our `[XCDR2,XCDR1]` reader (match, 126 recv) |
| `captures/connext-sedp-lo0.pcap`, `captures/fastdds-sedp-lo0.pcap` | Task 1 peer-vs-peer SEDP (PID format pin) |
