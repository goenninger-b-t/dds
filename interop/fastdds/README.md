# eProsima Fast DDS live-test harness

Fast DDS-side test apps that act as the **standards-conformant interop peer** for this
stack (REQUIREMENTS §8, FR-IO-2, NFR-IP). Unlike Connext (`interop/connext/`, the gold
oracle that does **not** speak the standard TypeLookup service — ADR 0010), Fast DDS
implements XTypes 1.3 `PID_TYPE_INFORMATION` + the builtin TypeLookup request/reply
endpoints, so this peer is the oracle for our TypeLookup CONFIRM-VS-PEER path and the
provisional EK_MINIMAL/EK_COMPLETE `EquivalenceHash` values.

They build against the Fast DDS **public API** (+ an IDL you control); the
`fastddsgen`-generated type support under `shapes/gen/` is **committed verbatim**
(Apache-2.0 output of the pinned generator; see `docs/provenance.md`). No Fast DDS
source is copied into the hand-written harness files.

> These apps are **not built or run by this repo's CI** — they require the pinned
> Fast DDS toolchain below, which lives in your environment, not here.

## The toolchain pin

Everything runs through `scripts/with-fastdds.sh`, which exports `FASTDDS_PREFIX`
(install prefix), `FASTDDSGEN`, `DYLD_LIBRARY_PATH`, and a JDK `PATH`. The toolchain is
built from these pinned sources (4 repos, exact tags + commits):

| Repo | Tag | Commit |
|---|---|---|
| Fast-DDS | v3.6.1 | `4e81e8b71bcd6e7c5213c000503cba8e49d6022a` |
| Fast-CDR | v2.3.5 | `7d33a3b51a1585f5631b0a8d905bcc4f249d0f34` |
| foonathan_memory_vendor | v1.4.1 | `347cb67581e51273a612780eb256a3c134c10bae` |
| Fast-DDS-Gen | v4.3.0 | `cc0072b8849b35c67bd7e187990efad58e2871ae` |

## Layout

```
interop/fastdds/
  shapes/ShapeType.idl     the type, defined to MATCH this stack's shape-type exactly
  shapes/gen/              fastddsgen 4.3.0 output, committed verbatim
  shapes/shapes_pub.cpp    Fast DDS publishes ShapeType  -> this stack's `make square-sub`
  shapes/shapes_sub.cpp    Fast DDS subscribes ShapeType <- this stack's `make square-pub`
  shapes/profiles.xml      UDPv4-only transport + explicit TypeLookup (see below)
```

## The ShapeType definition

`shapes/ShapeType.idl` mirrors **this stack's** `shape-type` (`@final`; `@key string
color`; three `long`s; sequential member ids 0..3) — and, unlike `rtiddsgen` (which
silently bounds an unbounded string at 255, ADR 0009), `fastddsgen` keeps `color`
truly **unbounded**, so this peer's TypeObject/TypeInformation is the apples-to-apples
oracle for our unbounded-`color` type. The generated code registers the type name
**`ShapeType`** (verified in `gen/ShapeTypePubSubTypes.cxx`: `set_name("ShapeType")`),
which is what our stack expects on the wire.

## profiles.xml (IMPORTANT — edit per machine)

Both apps load `profiles.xml` from their **cwd**:

- **UDPv4 only** (`useBuiltinTransports=false` + a single UDPv4 `userTransport`): no
  SHMEM, no data-sharing, so every byte is observable on `lo0`/`en*` with tshark.
- **`interfaceWhiteList` — EDIT per machine**: it pins the interfaces Fast DDS binds
  (currently `127.0.0.1` + this host's LAN address `192.168.2.148`). If discovery
  fails on your machine, fix these addresses first (keep `127.0.0.1` first for
  same-host runs).
- **TypeLookup client+server explicitly on.** Fast DDS 3.x removed the 2.x
  `<typelookup_config>` element; the TypeLookup request **and** reply endpoints are
  created whenever the participant property `fastdds.type_propagation` is `enabled`
  (the 3.x default). The profile pins it explicitly so the harness intent survives
  any future default change.

## Build & run

```sh
# build (from the repo root; the wrapper provides FASTDDS_PREFIX):
./scripts/with-fastdds.sh make -C interop/fastdds

# run via the top-level targets (cd into shapes/ for profiles.xml, then exec):
make fastdds-sub SECONDS=15            # 0 = forever
make fastdds-pub COLOR=GREEN COUNT=50  # 0 = forever, ~10 samples/s

# or directly:
cd interop/fastdds/shapes
../../../scripts/with-fastdds.sh ./shapes_sub 15
../../../scripts/with-fastdds.sh ./shapes_pub GREEN 50
```

Regenerate the type support after any IDL change (commit the output verbatim):

```sh
cd interop/fastdds/shapes
../../../scripts/with-fastdds.sh bash -c '"$FASTDDSGEN" -replace -d gen ShapeType.idl'
```

## Capturing the wire with tshark

This host's Wireshark profile disables the link/net dissectors by default
(`disabled_protos`), so re-enable them explicitly or the RTPS heuristic never fires:

```sh
tshark -i lo0 --enable-protocol null --enable-protocol ip --enable-protocol udp -w <file>.pcap
```

## Smoke run (Task 0.7, S0 exit gate — 2026-06-11, same host, lo0)

```sh
make fastdds-sub SECONDS=15 &
sleep 2 && make fastdds-pub COLOR=GREEN COUNT=50
wait
```

Publisher (trimmed):

```
[shapes_pub] sent 1 x=50 y=50
[shapes_pub] sent 2 x=51 y=57
[shapes_pub] matched change: 1 total: 1
[shapes_pub] sent 3 x=52 y=64
...
[shapes_pub] sent 50 x=99 y=93
[shapes_pub] done, sent 50
```

Subscriber (trimmed):

```
[shapes_sub] matched change: 1 total: 1
[shapes_sub] 1: color=GREEN x=52 y=64 size=30
[shapes_sub] 2: color=GREEN x=53 y=71 size=30
...
[shapes_sub] 48: color=GREEN x=99 y=93 size=30
[shapes_sub] matched change: -1 total: 0
[shapes_sub] done, received 48
```

Received 48/50 (≥ 40 required): the first two samples pre-date the endpoint match and
are not delivered under the default VOLATILE durability — expected. The shipped
`interfaceWhiteList` worked unmodified.

## S1 discovery census (Task 1.1, FR-IO-2 — 2026-06-11, same host, lo0)

Mutual SPDP/SEDP discovery vs Fast DDS 3.6.1, both directions, from the wire.
Captures + run logs are archived under `captures/` (carved out of this directory's
`.gitignore` — pcaps here are the recorded evidence, not transient probe output).
An `en7` capture was taken alongside each run and contained **zero** RTPS frames:
on this host every RTPS packet (multicast SPDP included) rides `lo0`, so only the
`lo0` pcaps are archived.

| Run | Peers | Capture | Result |
|---|---|---|---|
| forward | `fastdds-pub COLOR=GREEN COUNT=200` → our `run-subscriber` (`:canonical`, 45 s) | `captures/s1-forward-lo0.pcap` | matched; **194/200** delivered, zero Lisp warnings/errors (`captures/s1-forward-oursub.out`) |
| reverse | our `run-publisher` (ORANGE, 250) → `fastdds-sub SECONDS=45` | `captures/s1-reverse-lo0.pcap` | `matched change: 1`; **250/250** delivered, 428 ACKNACKs consumed by our writer (`captures/s1-reverse-fastsub.out`, `-ourpub.out`) |

GuidPrefixes: ours `474253aa…` (fwd sub) / `47425013…` (rev pub); Fast DDS
`010f5493af30cb08…` (fwd) / `010f5493a1311f93…` (rev).

### What Fast DDS announces

| Item | Observed | Evidence (pcap, frame) |
|---|---|---|
| VendorId | **`01.0f`** (eProsima — Fast-RTPS); RTPS protocol version **2.2** | forward fr 168 (first SPDP, `127.0.0.1:65343 → 239.255.0.1:7400`); every header |
| Product version (vendor PID `0x8000`) | `03 06 01 00` = **3.6.1.0** — confirms the pinned toolchain on the wire | forward fr 168 |
| `PID_BUILTIN_ENDPOINT_SET` (0x0058) | **`0x0000fc3f`**. XTypes 1.3 Table 62 TypeLookup bits **12–15 all set**: Request DataWriter (1<<12), Request DataReader (1<<13), Reply DataWriter (1<<14), Reply DataReader (1<<15); plus the RTPS Table 9.4 SPDP/SEDP bits 0–5 and ParticipantMessage bits 10–11 | forward fr 168 |
| SPDP extras | `PID_DOMAIN_ID` 0; lease 20 s; metatraffic `192.168.2.148:7410`, user `…:7411`; entityName `RTPSParticipant`; property list `PARTICIPANT_TYPE=SIMPLE` + `fastdds.physical_data.{host,user,process}`; vendor PIDs `0x8003` (44 B host GUID string), `0x8007` (4 B `01000000`) | forward fr 168 |
| SEDP publication carries **`PID_TYPE_INFORMATION` (0x0075)** | **YES, parameterLength 92** (the Stage-S3 input). Mutable `TypeInformation` with BOTH members: `0x1001` minimal **and** `0x1002` complete, each `EMHEADER1 LC=5` (NEXTINT doubles as the member DHEADER, XTypes 1.3 §7.4.3.4.2), `dependent_typeid_count = -1` ("not provided", §7.6.3.2.1), empty dependent list | forward fr 236/237 (SEDP `DATA(w)`, writer `…00000102`, seq 1, topic `Square`, type `ShapeType`, TRANSIENT_LOCAL) |
| — minimal TypeIdentifier | `EK_MINIMAL (0xf1)`, EquivalenceHash **`bfe2a62ed811ac463c40c97d30ee`**, `typeobject_serialized_size` **87** | forward fr 236 |
| — complete TypeIdentifier | `EK_COMPLETE (0xf2)`, EquivalenceHash `4945808c7622315d6220054f6aad`, size 132 | forward fr 236 |
| SEDP subscription carries 0x0075 too | YES, parameterLength 92, same two hashes; reader `…00000107`, RELIABLE + VOLATILE | reverse fr 213/214 (SEDP `DATA(r)`) |
| TypeLookup_Request traffic | **NONE in either direction** — no `DATA` ever flows on the TL writers (`0x000300c3`/`0x000301c3`), so no `instanceName` was observable. Fast DDS *does* create the endpoints: it HEARTBEATs its empty TL request writer (first=1, last=0) and our stack ACKNACKs it. Expected: both sides' 0x0075 hashes resolve locally (identical type), so `getTypes`/`getTypeDependencies` is never needed | forward fr 206 (their HB), fr 210 (our ACKNACK); reverse fr 185/186 |

### Mutual-discovery evidence (the S1 exit gate)

- **Forward:** Fast DDS processed our SPDP — its SEDP toward us is unicast with
  `INFO_DST` = our guidPrefix (fr 236); we matched its writer and ACKNACK its user
  DATA (fr 240/241); first user `DATA` at fr 224/225; 194/200 samples delivered (the
  first ~6 pre-date the match; our reader is VOLATILE).
- **Reverse:** Fast DDS unicast its SEDP `DATA(r)` at our prefix (fr 213/214) and
  ACKNACKed our user writer `…00000102` from fr 211/212 on (428 total); its
  `shapes_sub` printed `matched change: 1` and received **250/250** (RELIABLE).
- **Data plane already flows in both directions** — Stage S2 is de-risked to QoS/edge
  cases.

### Our 0x0075 vs theirs (S3 input)

Our SEDP (e.g. forward fr 201, 52 B) and Fast DDS's (fr 236, 92 B) encode the same
`TypeInformation` type with three deliberate differences, all spec-legal:

| | ours | Fast DDS 3.6.1 |
|---|---|---|
| members | minimal (`0x1001`) only | minimal + complete |
| EMHEADER length code | `LC=4` + explicit member DHEADER (§7.4.3.4.2: "serialized member length is NEXTINT") | `LC=5` (NEXTINT reused as the member's leading DHEADER, saves 4 B) |
| `dependent_typeid_count` | 0 (+ empty list) | −1 = not provided (legal per §7.6.3.2.1) |

**The EK_MINIMAL EquivalenceHash and serialized size agree exactly** — Fast DDS
independently computes `bfe2a62ed811ac463c40c97d30ee` / 87 B for the same IDL our
serializer produces. That is the live foreign-vendor confirmation of our provisional
minimal TypeObject serializer + hash (FR-TYPE-2/3) that the stock Connext wire could
not provide (ADR 0009/0010); the byte-level S3 pass locks it in the matrix.

**S3 DONE (2026-06-12):** the 92-octet fr 236/237 parameter value (byte-identical in
`s2-forward-lo0.pcap` fr 68) is locked as the regression vector in test
`fastdds-type-information-vector`; `deserialize-type-information-hash` was extended
(failing-test-first) to consume the `LC=5` NEXTINT-reuse framing alongside our `LC=4`,
and our own ShapeType serializer reproduces the hash + size 87 byte-for-byte. The
`verification.csv` FR-TYPE-2/3 PROVISIONAL caveat is narrowed to the unexercised
serialization-VM edges. Suite: **92 green on SBCL and on Clasp** (`GC_DONT_GC=1`) —
a Clasp crash first seen at this test was root-caused to the runtime's unmanaged-free
heap corruption, not the test (see the NFR-PORT row in `docs/verification.csv`).

**Not a bug:** Wireshark 4.6.x renders our `LC=4` TypeInformation as garbage (it only
understands the `LC=5` DHEADER-reuse layout) while decoding Fast DDS's cleanly. The
encoding is conformant per §7.4.3.4.2 and Fast DDS consumed it — it matched our
endpoints and delivered 250/250 against the very announcement carrying it. Cosmetic
dissector limitation only.

Our parser handled every Fast DDS announcement cleanly: no Lisp error, warning, or
mis-parse in either run (`captures/*-oursub.out` / `*-ourpub.out`).

## S2 data plane (FR-IO-2 DoD — 2026-06-11, same host, lo0)

Formal bidirectional **RELIABLE** ShapeType exchange vs Fast DDS 3.6.1, dedicated
runs, tshark-validated. Captures + logs under `captures/` (`s2-*`). Each leg was
driven by one orchestrating shell: tshark first, the subscriber side next, the
publisher only after the subscriber's ready line, so the receive window always
covers the whole send.

| Run | Peers | Capture | Result |
|---|---|---|---|
| forward | `fastdds-pub COLOR=GREEN COUNT=100` → our `run-subscriber` (`:canonical`, 45 s) | `captures/s2-forward-lo0.pcap` (723 pkts, 528 RTPS) | **95/100** delivered; head-of-stream sns 1–5 declared unavailable pre-match (see below), zero post-match loss; no Lisp warning/error (`s2-forward-oursub.out`) |
| reverse | our `run-publisher` (BLUE, 250, 30/s) → `fastdds-sub SECONDS=40` | `captures/s2-reverse-lo0.pcap` (2854 pkts) | **250/250** delivered incl. full pre-match recovery from sn 1; our writer consumed 368 ACKNACKs (`s2-reverse-fastsub.out`, `-ourpub.out`) |

GuidPrefixes: Fast DDS `010f9bd79842ef6e…` (fwd pub); ours `474253e7a8d5ed00…`
(fwd sub) / `47425030a9d5ed00…` (rev pub). User endpoints both legs: writer
`…00000102`, reader `…00000107`.

### tshark evidence — forward (their writer, our reader)

| Item | Observed | Evidence (frame) |
|---|---|---|
| ShapeType payload decodes | `DATA` sn 60: encapsulation **CDR_LE (0x0001)**, serializedData `06000000 "GREEN\0" 6d000000 3f000000 1e000000` = color "GREEN", x=109, y=63, size=30 — printed verbatim by our sub (`x=109 y=63 size=30`, once) | fr 341 |
| HEARTBEAT from the writer | 98 frames on wr `…00000102` | first fr 50 (t=2.75 s), last fr 507 |
| ACKNACK from our reader | 96 frames, rd `…00000107` → wr `…00000102` (e.g. sn-state base 8) | first fr 72 (t=2.89 s), last fr 509 |
| GAP | exactly 2 frames (same submessage out both interfaces): the writer declares **sns 1–5** unavailable pre-match under VOLATILE — GAP of sn 5 only (gapStart=5, numBits=0); sns 1–4 are excluded by the same frame's HEARTBEAT firstAvailableSeqNumber=5 — so 95/100 is the spec-correct count, first delivered `DATA` is sn 6 | frs 50/51; first user `DATA` fr 56 (t=2.78 s) |
| Retransmit profile | 95 unique sns (6–100), each `DATA` submessage exactly ×2 = one per whitelisted interface (both ride lo0) — **zero true retransmits**, 190 user `DATA` submessages total | — |

### tshark evidence — reverse (our writer, their reader)

| Item | Observed | Evidence (frame) |
|---|---|---|
| ShapeType payload decodes | `DATA` sn 200: encapsulation **CDR2_LE (0x0007)**, serializedData `05000000 "BLUE\0" a8000000 1e000000 1e000000` = color "BLUE", x=168, y=30, size=30 | fr 2420 |
| HEARTBEAT from our writer | 218 frames on wr `…00000102` | first fr 94 (t=3.64 s), last fr 2635 |
| ACKNACK from their reader | 370 frames (×2 interfaces), rd `…00000107` → wr `…00000102`, first with sn-state base 67 | first fr 1830 (t=5.03 s), last fr 2637 |
| GAP | **0** | — |
| Pre-match recovery | their SEDP `DATA(r)` frs 59/60 (t=3.63 s); our first user `DATA` fr 61 (t=3.64 s); their sub still delivered **sample 1 (x=53)** — the RELIABLE machinery recovered every pre-ACKNACK sample | `s2-reverse-fastsub.out` line 1 |

### Anomalies (noted, non-blocking)

- **Our writer's pre-first-ACKNACK repair is aggressive:** between the first user
  `DATA` (t=3.64 s) and Fast DDS's first ACKNACK (t=5.03 s) our writer re-sent the
  whole unacked history every send cycle — sn 1 went out 34×, 1867 `DATA` frames
  total for 250 sns. It is self-limiting (185 sns sent exactly once after the first
  ACKNACK landed; zero redundant traffic thereafter) and Fast DDS deduplicated
  cleanly to 250/250, but a HEARTBEAT-paced repair would cut the burst ~7×. Filed
  as a perf observation, not a correctness issue.
- **Everything from Fast DDS arrives twice on lo0:** it emits each submessage once
  per `interfaceWhiteList` entry (`127.0.0.1` + `192.168.2.148`, both looped back
  on this host). Benign; explains all ×2 counts above.

## S4 leg A: TypeLookup live — our getTypes client (FR-IO-2 — 2026-06-12, same host, lo0)

Our XTypes 1.3 TypeLookup **client** (`dds.disc:type-lookup-query`, complete offline per
ADR 0010) exchanged its first live frames with a conformant peer: `run-typelookup-probe`
(`make fastdds-tl-probe`) discovers the Fast DDS participant, takes the EK_MINIMAL hash
from its SEDP `PID_TYPE_INFORMATION`, sends a **getTypes** `TypeLookup_Request` to its
metatraffic locator, and verifies the returned TypeObject parses and re-hashes to the
queried hash.

| Run | Peers | Capture | Result |
|---|---|---|---|
| 1 (diagnosis) | `fastdds-pub COLOR=GREEN COUNT=1000` + `make fastdds-tl-probe SECONDS=30` | `captures/s4-ourclient-run1-lo0.pcap` | **FAIL (by design of the run)** — their server answered `REMOTE_EX_OK` with 1 pair, but keyed by the **EK_COMPLETE** TypeIdentifier (`s4-ourclient-run1-probe.out`); reply locked as the regression vector, client extended (below) |
| 2 (PASS) | same | `captures/s4-ourclient-lo0.pcap` | **PASS** — `[tl-probe] PASS getTypes reply: TypeObject 87 octets parses and re-hashes to bfe2a62ed811ac463c40c97d30ee` (`s4-ourclient-probe.out`) |

### Evidence frames (run 2, `s4-ourclient-lo0.pcap`)

| Item | Observed | Evidence (frame) |
|---|---|---|
| Their TL builtin endpoints | HEARTBEATs on their empty TL request/reply writers from discovery on; our builtin ACKNACKs answer | frs 53–62 |
| Our `TypeLookup_Request` DATA | writer `{00,03,00}c3` → their request reader `{00,03,00}c4`, sn 1, 191 B, unicast to their metatraffic locator `:7410`; carries the §7.6.3.3.4 `instanceName` (24-char prefix hex — **accepted**, see reply) | **fr 85** (t=5.872 s) |
| Their `TypeLookup_Reply` DATA | writer `{00,03,01}c3` → our reply reader `{00,03,01}c4`, sn 1, 420 B, `REMOTE_EX_OK`, relatedRequestId = our request writer GUID + sn 1 | **frs 86/87** (×2 interfaces) |
| Probe verdict | reply consumed live: TypeObject parses (87-octet reconstructed MINIMAL) and re-hashes to the queried `bfe2a62ed811ac463c40c97d30ee` | `s4-ourclient-probe.out` |

### The client finding (fixed failing-locked-vector-test-first)

Queried for a **MINIMAL** TypeIdentifier, Fast DDS 3.6.1 answers with the **COMPLETE**
TypeObject keyed by the EK_COMPLETE TypeIdentifier (`4945808c7622315d6220054f6aad`), plus
the `complete_to_minimal` member mapping it back to the queried EK_MINIMAL hash — exactly
the XTypes 1.3 §7.6.3.3.4.2 latitude ("the types may contain either MINIMAL or COMPLETE
TypeObjects"; the mapping "makes it possible for the receiver to reconstruct the MINIMAL
TypeObject"). Our minimal-only client dropped the pair as unknown. The 256-octet run-1
reply payload (`s4-ourclient-run1-lo0.pcap` fr 61) is locked as the regression vector in
test `fastdds-typelookup-reply-vector`; `parse-type-lookup-reply` now parses
`complete_to_minimal` (new 7th value) and the new
`dds.types:complete-to-minimal-type-object` reconstructs the MINIMAL model (member
NameHashes recomputed per §7.3.4.5; `@optional` details ride as `<is_present>` booleans
per §7.4.3.5.2; EK_COMPLETE member TypeIdentifiers remapped via the mapping; anything
unmodeled degrades `:unsupported`, fail-open). The discovery client delivers a
`(minimal-hash . minimal-octets)` pair only when the reconstruction's own EquivalenceHash
equals the mapped hash — for ShapeType the reconstructed MinimalTypeObject is
**byte-identical to our own** (87 octets). Suite: **93 green SBCL**.

Remaining S4 leg B: their client against our TypeLookup server (Fast DDS resolves
identical types locally, so leg B needs a deliberately differing type or a hash probe).
