# Interop with RTI Connext (and other DDS)

Common Lisp DDS is built to **interoperate on the wire with RTI Connext 7.x** and at least
one open-source DDS (FR-IO). Three assets support that: the **Connext oracle/interop harness**
under [`interop/connext/`](../../interop/connext/), the **Fast DDS peer harness** under
[`interop/fastdds/`](../../interop/fastdds/), and the standalone **Shapes harness**
(`dds-shapes`, the `make square-*` targets). Wire correctness is judged with the Wireshark/
tshark RTPS dissector — the same dissector `make wire` uses — not by eye.

## The interop gate (`make interop`)

`make interop` runs `make wire` (our emitted RTPS validated against the tshark RTPS dissector) and then
**four live legs, both vendors, both directions**:

| leg | direction | notes |
|---|---|---|
| Connext -> us | inbound | the STRICT oracle |
| Fast DDS -> us | inbound | LENIENT peer — proves strictly less (it accepted the ADR 0061 malformed payload Connext rejected) |
| us -> Connext | **outbound** | the direction that hid ADR 0057 |
| us -> Fast DDS | **outbound** | |
| us -> Connext, `LargeData` | outbound | **DATA_FRAG**; 8000-octet payload verified octet-by-octet |
| Connext -> us, `LargeData` | inbound | **DATA_FRAG reassembly**; independent of our own fragment size |
| us -> Fast DDS, `LargeData` | outbound | **DATA_FRAG** vs the second vendor (`interop/fastdds/largedata/`) |

The two large-data legs are the only fragmentation legs against a foreign stack, and their absence let
ADR 0079 ship: Shapes samples sit far below any MTU, so no Shapes leg can exercise the emitted datagram
size. Falsified — with `*fragment-size*` back at its pre-ADR-0079 value the outbound large leg reports
`only 0 verified sample(s)` and the gate goes red.

Two properties of this gate are load-bearing and easy to lose:

- **A gate that cannot run must FAIL, not print green.** If a vendor is missing the gate fails and names it.
  Opt out deliberately and visibly with `INTEROP_ALLOW_MISSING=connext|fastdds|both`.
- **`MIN_SAMPLES` (default 5) is a floor, not a formality.** ">0 samples" is nearly vacuous — one sample can
  come from a stale peer or a single lucky datagram. A leg that moves fewer than the floor fails.

**The outbound legs need `REP=xcdr1`, and that is a protocol fact rather than a tuning knob.** A stock
foreign Shapes `DataReader` advertises **XCDR1 only**, and `DATA_REPRESENTATION` is an **RxO** policy, so an
XCDR2-default writer **silently does not match** — no error, just `matched=0`. Verified by falsifying the
gate: publishing the identical stream as XCDR2 gets **0** samples accepted by Connext where XCDR1 gets 253.
That silent-non-match is exactly the ADR 0057 failure mode, in which our `DataWriter` matched no foreign
`DataReader` for six slices because every live leg had exercised our *reader*.

**Every peer runs in its own process group and the gate kills the group.** Killing only the direct child
leaks the real binary whenever the child is a wrapper (`with-fastdds.sh` -> `bash` -> `shapes_pub`); the
grandchild is reparented to init and **keeps publishing on the domain forever**. That is not hypothetical —
a leaked `shapes_pub RED` once fed 358 phantom samples into a later leg and made an outbound test look like
it was receiving its own traffic, and it depressed a Fast DDS inbound leg to a single sample.

**Peers must be allowed to exit on their own.** A foreign peer writing to a file has fully-buffered stdout,
so a peer SIGKILLed the moment its publisher finishes leaves an **empty log** and scores zero however many
samples it really received — a false RED that looks exactly like a peer that never started. Every peer here
takes a `<seconds>` argument; `wait_peer` waits for that, and `stop_peer` is only the backstop for a hang.
The Shapes legs had been escaping this by accident (249 lines overflow the 4 KB buffer and force a flush);
the large-data legs, at ~15 lines, did not.

The Fast DDS `LargeData` peer lives in `interop/fastdds/largedata/` (build:
`./scripts/with-fastdds.sh bash -c 'cd interop/fastdds/largedata && make'`). It verifies the payload
octet-by-octet like the Connext peer, and it needs a **unicast** SPDP announce — its profile whitelists
127.0.0.1 only, so it never sees LAN multicast; `run-large-publisher` therefore takes `:peers`.

Not covered: Shapes and large-data only, and DATA_FRAG **reassembly** is gated against Connext only (there
is no Fast DDS `LargeData` publisher). Per-feature legs (keyed/nokey,
TypeLookup, keyed FlatData, liveliness, deadline, durability, security) have drivers under `scripts/` and
`interop/` but are not gated yet — the gate says so on every run rather than letting a green line read as
"interop is covered".

## The Shapes harness (this stack)

`dds-shapes` is a self-contained Square/ShapeType publisher + subscriber on multicast
discovery, intended to interop with RTI `rtishapesdemo` / DDSSpy and with other DDS Shapes
demos.

```sh
make square-pub COLOR=BLUE     # publish an animated Square (ShapeType)
make square-sub                # subscribe + print received shapes
make square-spy                # discovery diagnostic: discovered participants + locators
make gated-sub                 # DCPS-level type-GATED subscriber (FR-TYPE-4): the assignability
                               # gate fires on a stock Connext peer's PID_TYPE_OBJECT_LB (0x8021)
make square-pub DURABILITY=transient-local   # TRANSIENT_LOCAL writer: retain + replay to a late-joiner
make square-sub DURABILITY=transient-local PEERS=127.0.0.1:7410   # TL late-joiner: pull the retained history
```

The `DURABILITY=transient-local` gate (DDS 1.4 §2.2.3.4; default `volatile` = byte-identical wire) makes
the writer RETAIN its history + replay it to a late-joining reader (forcing HISTORY KEEP_ALL), and the
reader REQUEST a matched retaining writer's pre-join history. See
[`interop/durability-transient-local/`](../../interop/durability-transient-local/) for the live
late-joiner interop (both directions, both peers).

`make gated-sub` builds a **DCPS** participant (whose `create-participant` installs the
FR-TYPE-4 assignability gate — the standalone `square-sub` is a bare `dds.disc` node with no
gate) and binds a local type under a chosen wire topic/type-name. Override
`LOCALTYPE=shape-type` (the compatible C_Shape; matches + delivers) or
`LOCALTYPE=shape-mismatch` (`shapesize` retyped i64; the gate rejects → INCONSISTENT_TOPIC, no
data), with `TYPENAME=C_Shape TOPIC=Square` to face the Connext legacy-TypeObject corpus
(below). It sets `*type-compat-log*` to stdout so the gate verdict line is visible.

The publisher/subscriber also advertise the canonical ShapeType `PID_TYPE_INFORMATION` on
SEDP (see [Type system](type-system.md) and [Discovery](discovery.md)), so a peer can read
our type identity off the wire.

## The Connext harness (`interop/connext/`)

Connext-side C++ test apps built against the **Connext public API + your own IDL** — this is
the allowed clean-room, behavioural-reference-via-interop use; **no Connext source is
copied**, and the `rtiddsgen`-generated type support is produced at build time and
git-ignored (see [`docs/provenance.md`](../provenance.md)). It requires a Connext install and
is **not** part of this repo's CI.

| App | Purpose |
|---|---|
| `typeobject-probe` | puts a ShapeType writer/reader on the wire + idles, so its SEDP `PID_TYPE_INFORMATION` can be tshark-captured — the **oracle for our EquivalenceHash** |
| `shapes-pub` | Connext publishes ShapeType → this stack's `make square-sub` (interop OUT) |
| `shapes-sub` | Connext subscribes ShapeType ← this stack's `make square-pub` (interop IN) |
| `cdr-capture` | publishes one fixed sample → a byte-exact XCDR payload reference (FR-CDR-8) |

```sh
export NDDSHOME=/path/to/rti_connext_dds-7.x   CONNEXTDDS_ARCH=<your-arch>
make -C interop/connext                        # build all apps
./interop/connext/typeobject-probe/typeobject_probe 0
tshark -i lo -O rtps -V | grep -A60 PID_TYPE_INFORMATION   # lo0 on macOS
```

See [`interop/connext/README.md`](../../interop/connext/README.md) for the full guide.

## The Fast DDS harness (`interop/fastdds/`, FR-IO-2)

eProsima Fast DDS-side C++ test apps (pinned **Fast DDS 3.6.1** toolchain via
`scripts/with-fastdds.sh`). Where Connext is the gold oracle that does **not** speak the
standard TypeLookup service (ADR 0010), Fast DDS implements XTypes 1.3
`PID_TYPE_INFORMATION` + the builtin TypeLookup endpoints — this peer is the oracle for our
TypeLookup CONFIRM-VS-PEER path and the provisional EquivalenceHash values. The apps run
RELIABLE `ShapeType` on topic `Square`, UDPv4-only (tshark-observable; no SHMEM), with
TypeLookup client+server pinned on via `fastdds.type_propagation=enabled`, and — unlike
`rtiddsgen` — with `color` truly **unbounded**, matching our local type exactly.

```sh
./scripts/with-fastdds.sh make -C interop/fastdds   # build (pinned toolchain)
make fastdds-sub SECONDS=15                         # subscribe + print samples (0 = forever)
make fastdds-pub COLOR=GREEN COUNT=50               # publish ~10 samples/s (0 = forever)
make fastdds-tl-probe SECONDS=30                    # TypeLookup live leg A: our getTypes client
                                                    # queries the peer's TypeLookup server (S4)
make fastdds-type-probe SECONDS=40                  # TypeLookup leg B harness: a type-blind
                                                    # Fast DDS subscriber resolving the topic's
                                                    # type via TypeLookup + DynamicType
```

`make fastdds-tl-probe` runs `dds.shapes:run-typelookup-probe` (FR-IO-2 S4): it discovers one
remote `Square` writer, takes the EK_MINIMAL EquivalenceHash from its SEDP
`PID_TYPE_INFORMATION` (0x0075), issues a TypeLookup **getTypes** request toward that
participant (XTypes 1.3 §7.6.3.3) via `dds.disc:type-lookup-query`, and verifies the returned
TypeObject both parses (`parse-minimal-type-object`) and re-hashes (`equivalence-hash`) to the
queried value — printing `[tl-probe] PASS/FAIL` and returning `T` on PASS.

**S4 leg A is ACHIEVED (2026-06-12):** the probe PASSes live against Fast DDS 3.6.1 — our
request DATA on their TypeLookup request reader and their `REMOTE_EX_OK` reply are frames
85 / 86-87 of `interop/fastdds/captures/s4-ourclient-lo0.pcap`. The run surfaced (and locked,
test `fastdds-typelookup-reply-vector`) the conformant reply shape our client had never seen:
asked for a MINIMAL TypeIdentifier, Fast DDS returns the **COMPLETE** TypeObject plus the
`complete_to_minimal` mapping (XTypes 1.3 §7.6.3.3.4.2), which the client now reconstructs
into the MINIMAL TypeObject (`dds.types:complete-to-minimal-type-object` — see
[Type system](type-system.md)). See the S4 section of
[`interop/fastdds/README.md`](../../interop/fastdds/README.md) for the run table + evidence.

**S4 leg B (their client vs our TypeLookup server) is blocked by a Fast DDS vendor gate
(finding, 2026-06-12):** the leg-B harness (`interop/fastdds/type_probe/`,
`make fastdds-type-probe`) is a type-blind Fast DDS subscriber that resolves a remote
type via Fast DDS's own TypeLookup client + `create_type_w_type_object` DynamicType —
proven end-to-end against an eProsima publisher (type resolved, RELIABLE reader, 233
JSON-printed samples). Against our publisher it can never fire: Fast DDS 3.6.1
**ignores `PID_TYPE_INFORMATION` from every non-eProsima vendorId**
(`WriterProxyData.cpp`/`ReaderProxyData.cpp`, the "Ignore this PID when coming from
other vendors" branch), so our 0x0075 — delivered and acknowledged on the wire (frames
389 / 120-123 of `s4-theirclient-lo0.pcap`) — is stripped before their EDP, the probe
sees `type_information.assigned=0`, and zero TypeLookup requests appear on the wire.
No configuration disables the gate. The
run also surfaced an environmental trap — this host's macOS firewall/local-network
layer silently drops LAN-sourced UDP for unapproved freshly-built binaries — answered
by a loopback-only probe profile plus the new `run-publisher :peers` unicast-SPDP
option (`make square-pub PEERS=127.0.0.1:7410`). Full evidence in the S4 leg B section
of [`interop/fastdds/README.md`](../../interop/fastdds/README.md).

**S4 leg B-patched (NON-STOCK diagnostic, 2026-06-12):** the one direction the stock gate
blocks — our `TypeLookup_Reply` consumed by their client — was verified live by
neutralizing the vendor gate in a local Fast DDS build (a one-line bypass in both proxy
parsers; the SEDP gate sits outside the TypeLookup engine, so the TL traffic itself is
stock): their probe then saw our 0x0075 (`assigned=1`), sent getTypeDependencies and
getTypes to our server, consumed both replies, **built its DynamicType from our 87-octet
MINIMAL TypeObject**, and took **600/600** RELIABLE samples (frames 2494-2500 of
`s4-theirclient-patched-lo0.pcap`); their per-sample JSON-dump failures were root-caused
to a Fast DDS defect (member names synthesized from raw MINIMAL `NameHash` bytes are not
UTF-8), not to our framing. The stock build was restored, rebuilt, and re-proven
(`assigned=0`). With leg A this closes the TypeLookup **CONFIRM-VS-PEER walk** — framing
peer-confirmed in both directions; only the non-OK-reply Return-arm omission and
non-CDR2_LE encapsulations remain self-pinned. Walk table + the exact patch + caveats in
[`interop/fastdds/README.md`](../../interop/fastdds/README.md) (explicitly NOT a
stock-peer result; the stock verdict stands above).

Same-host Fast DDS↔Fast DDS smoke is green (S0 gate; 48/50 over `lo0`), mutual SPDP/SEDP
discovery is proven from the wire (S1 census), and the **FR-IO-2 data-plane DoD is met**
(S2): dedicated bidirectional RELIABLE runs — Fast DDS → our subscriber **95/100** (the
head-of-stream sns 1-5 declared unavailable pre-match under VOLATILE (HB first=5 + GAP of sn 5), zero post-match loss) and our
publisher → Fast DDS **250/250** (full pre-match recovery from sequence number 1) — with
HEARTBEAT/ACKNACK verified on the user endpoints in both directions and the ShapeType
payloads tshark-decoded field-by-field. Captures + run logs are archived under
`interop/fastdds/captures/`. See [`interop/fastdds/README.md`](../../interop/fastdds/README.md)
for the toolchain pin, the per-machine `profiles.xml` `interfaceWhiteList` note, and the
frame-level evidence tables.

## Live Connext legacy-TypeObject type-gating (ACHIEVED 2026-06-11, ADR 0011)

RTI Connext announces its type only through the vendor `PID_TYPE_OBJECT_LB` (0x8021), never
the standard `PID_TYPE_INFORMATION` / TypeLookup (ADR 0010). The FR-TYPE-4 gate's fail-open
legacy rung — which parses that 0x8021 TypeObject and decides the match by structural
assignability — was proven against **live RTI Connext 7.3.1**:

```sh
# terminal 1 (from interop/connext/typeobject-corpus, with the RTI env + dylib symlinks):
./corpus_pub 0 Square C_Shape                       # Connext writes C_Shape on topic Square
# terminal 2 (repo root) — compatible local type:
make gated-sub TOPIC=Square TYPENAME=C_Shape LOCALTYPE=shape-type     SECONDS=25
# terminal 2 — incompatible local type (shapesize i64):
make gated-sub TOPIC=Square TYPENAME=C_Shape LOCALTYPE=shape-mismatch SECONDS=25
```

Compatible → `type-gate[...]: COMPATIBLE`, the endpoints match and C_Shape samples are
delivered. Incompatible → `type-gate[...]: INCOMPATIBLE`, INCONSISTENT_TOPIC is raised and no
samples are delivered. Re-running the compatible case after the incompatible one still matches:
a genuinely compatible Connext peer is never false-rejected. See
[`interop/connext/typeobject-corpus/README.md`](../../interop/connext/typeobject-corpus/README.md)
and [DCPS → Assignability-gated matching](dcps.md) for the full evidence.

## The XTypes wire bytes (CONFIRMED — FR-IO-2 S3, 2026-06-12)

The XCDR2 TypeObject serializer + EquivalenceHash and the TypeInformation codec are
**externally confirmed** for the exercised path (FINAL struct + `i32` + unbounded
`string8`): live Fast DDS 3.6.1 independently computes the identical EK_MINIMAL hash and
serialized size for the same IDL, and its 92-octet SEDP `PID_TYPE_INFORMATION` is locked
as a regression vector (test `fastdds-type-information-vector` — see
[Type system](type-system.md)). Connext could never provide this oracle: stock RTI emits
no 0x0075 at all (ADR 0009/0010).

```
ShapeType  (@final; @key unbounded string color; long x,y,shapesize; ids 0..3)
both: EquivalenceHash = BF E2 A6 2E D8 11 AC 46 3C 40 C9 7D 30 EE   (TypeObject = 87 bytes, no encap header)
```

Still provisional: the unexercised serialization-VM edges (unions, MUTABLE structs,
`TK_NONE` base, sequence-member TIs, nested-dependency hashes).

## Status

- **Shapes wire format**: validated against the tshark RTPS dissector (`make wire`).
- **Bidirectional Connext interop**: **achieved 2026-06-09** against live RTI Connext 7.3.1
  over UDP (reliable, both directions: forward Connext → our `square-sub` 251 ShapeType
  samples; reverse our `square-pub` → Connext `shapes_sub` 228 samples, tshark-validated);
  **fragmented (DATA_FRAG) interop achieved 2026-06-10** (8000-octet LargeData byte-exact
  both ways, 15/15 + 25/25, incl. forced-fragment-loss NACK_FRAG recovery 12/12); **live
  legacy-TypeObject type-gating achieved 2026-06-11** (ADR 0011, section above). Full
  DCPS/content-filter interop beyond what reliable shapes exercises remains open.
- **Open peer (Fast DDS) — FR-IO-2 MET, closed (ADR 0012, 2026-06-12)**: bidirectional
  reliable ShapeType exchange vs **stock** Fast DDS 3.6.1 (forward 95/100, reverse 250/250,
  HEARTBEAT/ACKNACK live both directions, tshark-validated — the FR-IO-2 data-plane DoD,
  S2); the **EquivalenceHash is externally confirmed** (S3, locked vector); the
  **TypeLookup getTypes client leg is live vs stock** (S4 leg A: our client consumes their
  server's reply, frames 85/86-87 of `s4-ourclient-lo0.pcap`); S4 leg B's **stock verdict**
  is the documented vendor-gate finding — Fast DDS discards `PID_TYPE_INFORMATION` from
  non-eProsima vendors, so no foreign announcement can trigger its TypeLookup client — and
  the one direction that gate blocks (our `TypeLookup_Reply` consumed by their client,
  600/600 samples via a DynamicType built from our MINIMAL TypeObject) is verified only
  under the clearly-labeled **NON-STOCK** diagnostic (vendor gate bypassed locally, stock
  restored + re-proven). The CONFIRM-VS-PEER walk is closed: 5 of 6 items peer-confirmed;
  the non-OK Return-arm omission stays self-pinned. ADR 0012 records the feature, the three
  peer findings, and the two own-stack fixes.
- **Keyed FlatData cross-DDS interop (WP-KEYED-FLATDATA F1, FR-PF-4, RTPS 2.5 §9.6.4.8;
  [`interop/keyed-flatdata/`](../../interop/keyed-flatdata/))** — the per-feature DoD gate
  (owner directive 2026-06-17: every feature verifies interop with both RTI Connext **and**
  Fast DDS). The conformance crux is the **keyhash / per-key instance identity** on the
  **UDP/copy path** (the same-host Zero-Copy loan path is not wire-interoperable, out of scope).
  The shared type is `KeyedFlat { @key long id; long x; long y; }` (== this stack's
  `keyed-flat`); our side is `make keyed-flat-pub` / `keyed-flat-sub`. An offline cross-impl
  test (`keyed-flat-interop-keyhash`) asserts our `key-hash-keyed-flat-fd` equals an
  **independently-derived** standards-conformant peer keyhash (RTPS 2.5 §9.6.4.8) — green both
  impls. **Connext 7.3.1: PASS, live in-session (2026-06-17, loopback)** — our keyed FlatData
  publisher → a Connext subscriber that grouped 30/30 samples into exactly **3 per-key
  instances** with the keyhash `00000000…`/`00000001…`/`00000002…` **byte-identical to ours**
  (the crux proven on the wire), and our **dispose-by-key** resolved to the correct instance on
  Connext; tshark confirms our user DATA is `CDR2_LE (0x0007)` with the i32 `@key` in the
  payload (no `PID_KEY_HASH` on alive DATA) and the dispose DATA carries
  `PID_KEY_HASH (0x0070)` + `PID_STATUS_INFO (0x0071) Disposed`
  (`interop/keyed-flatdata/captures/`). **Fast DDS 3.6.1: PASS, live in-session** (2026-06-17,
  loopback; `fastddsgen` v4.3.0 output committed) — the reverse leg matched the Connext result
  (30/30 into exactly 3 per-key instances, the keyhash `00000000…`/`00000001…`/`00000002…`
  byte-identical to ours and to Connext's, dispose-by-key resolved; `kflat-reverse-fastdds.pcap`).
  **Forward leg (peer pub → our FlatData sub) now PASS via the transcode** (WP-FLATDATA-XCDR-TRANSCODE,
  2026-06-17, FR-PF-4, DDS-XTypes 1.3 §7.6.3.1.2): both Connext and Fast DDS emit `PLAIN_CDR_LE`
  (0x0001, XCDR1-LE) on the wire, and our `:flatdata t` reader **transcodes** it into its canonical
  XCDR2-LE buffer (decode via the sibling struct codec + re-serialize XCDR2-LE) — 29/30 into exactly
  3 instances, keyhashes byte-identical, dispose-by-key resolved (`kflat-forward-connext.pcap` +
  `kflat-forward-fastdds.pcap`). This **closes the earlier forward-leg false-REJECT** (the reader used
  to read only `PLAIN_CDR2_LE` 0x0007 and rejected a foreign rep — false-REJECT-safe, never mis-read).
  The `PID_DATA_REPRESENTATION`-on-our-SEDP item (advertise our offered/accepted representations, and
  TX in the offered one) is delivered by **WP-DATA-REPRESENTATION** (below).

- **Sender-thread emit-fault resilience cross-DDS interop (WP-SENDER-ERROR-RESILIENCE, FR-PF-2, RTPS
  2.5 §8.4; [`interop/sender-resilience/`](../../interop/sender-resilience/))** — the per-feature DoD
  gate for the sender-thread emit guard. The Shapes publisher (`make square-pub` / `run-publisher`)
  gains `FAULT=k@j` (drive exactly k synthetic emit faults onto the async sender thread after the
  j-th publish), `HISTORY=keep-all`, and `PORT=` knobs (all inert when unset; byte-identical wire).
  **Connext 7.3.1 + Fast DDS 3.6.1: PASS, live in-session (2026-06-17, loopback)** — the async sender
  thread caught **3/3** injected faults and stayed alive + publishing, the peer stayed matched and
  receiving (Connext 24/30, Fast DDS 29/30), user DATA `CDR2_LE (0x0007)` SN 1→30 across the fault
  window — the faulted SNs reappear as the writer's **proactive re-push of unacked samples**
  (pushMode=true, RTPS 2.5 §8.4.2.2; the HEARTBEAT keeps advertising and ACKNACK-repair is the
  fallback), not via a peer NACK (the ACKNACKs in the captures — Connext 45, Fast DDS 25 — are the
  peers' **builtin discovery**; **zero** target our user writer `0x00000102`)
  (`captures/sender-resilience-{connext,fastdds}.pcap`). **Honest framing:** a reliable writer
  delivers regardless of the guard (the proactive re-push + HEARTBEAT advertisement run on threads
  that do not die with the guarded sender thread), so the interop proves *sender-thread survival +
  wire validity + delivery preservation* (the Fast DDS fault run delivered exactly as many as its
  no-fault baseline, 29/30); the **guard-vs-no-guard** discrimination is the UNIT mutation tests
  (`run-async-emit-fault-survives-test`, `run-flow-emit-fault-no-spin-test`), not this interop. The
  few-sample tail gap is a harness teardown-drain artifact (present in the no-fault baseline too),
  not a guard or wire defect.

- **DATA_REPRESENTATION cross-DDS interop (WP-DATA-REPRESENTATION, DDS-XTypes 1.3 §7.6.3.1.1;
  [`interop/data-representation/`](../../interop/data-representation/))** — emit/parse
  `PID_DATA_REPRESENTATION (0x0073)` in SEDP (byte-exact vs the live oracle), role-aware advertising
  (our reader accepts `[XCDR2, XCDR1]` = shorts `[2, 0]`, our writer offers `[XCDR2]`), spec-strict
  RxO, and TX in the writer's offered representation. The Shapes publisher (`make square-pub` /
  `run-publisher`) gains a **`REP=xcdr1|xcdr2`** knob (writer's offered representation; unset/`xcdr2`
  = the default `PLAIN_CDR2_LE 0x0007`, byte-identical user-data wire; `xcdr1` = `PLAIN_CDR_LE
  0x0001`), and `run-subscriber` gains `:peers`/`:port` for the reverse leg. **Connext 7.3.1 + Fast
  DDS 3.6.1: PASS, live in-session (2026-06-17, loopback).** Forward: with `REP=xcdr1` our user DATA
  is `CDR_LE (0x0001)` on the wire and both peers received + decoded it (Connext 37, Fast DDS 49);
  with the default `REP=xcdr2` (`CDR2_LE 0x0007`) both peers' `[XCDR1]`-only `ShapeType` reader
  correctly does **not** match (0 received, 0 user-writer ACKNACKs) — the spec-mandated RxO reject of
  an unsatisfiable representation, **not** a false-reject. Reverse: our reader (`[XCDR2, XCDR1]`)
  matched each peer's `[XCDR1]` writer and decoded its samples (Connext 688, Fast DDS 126). Honest
  caveat: the foreign→us *user-data* path is not visible to tshark on this host's lo0 (a macOS
  loopback-capture quirk, not a delivery gap — proven by the decoded sample counts); the forward-leg
  `0x0001`/`0x0007` TX encapsulation is dissected directly (`captures/our-xcdr{1,2}-to-{connext,fastdds}.pcap`,
  `captures/{connext,fastdds}-pub-to-our-sub.pcap`).

- **TRANSIENT_LOCAL durability + late-joiner cross-DDS interop (WP-DURABILITY-TRANSIENT-LOCAL, M6/P5,
  DDS 1.4 §2.2.3.4; [`interop/durability-transient-local/`](../../interop/durability-transient-local/))**
  — the per-feature DoD gate for TRANSIENT_LOCAL + the late-joiner, both directions, both peers. Both
  halves of the Shapes harness gain a **`DURABILITY=transient-local`** gate (`run-publisher` /
  `run-subscriber`; default `volatile` = byte-identical wire): the TL writer retains its history (forcing
  HISTORY KEEP_ALL) + replays it to a late-joining reader, and the TL reader requests a retaining writer's
  pre-join history. The foreign peers are made TL via QoS XML (Connext) and an inert C++ `DURABILITY` env
  gate (Fast DDS). **Connext 7.3.1 + Fast DDS 3.6.1: PASS, live in-session (2026-06-18, loopback)** — all
  four directional legs delivered the late-joiner the RETAINED pre-join history (the animation's first
  low-coordinate sample, published before the late side joined): forward (our TL writer → a late foreign
  TL reader) Connext received 63 from `x=53 y=52`, Fast DDS 60 from `x=53 y=52`; reverse (a foreign TL
  writer → our late TL reader) we received Connext's 902 incl. `x=53 y=52` and Fast DDS's 200 incl.
  `x=50 y=50`. The **VOLATILE-reader contrast** against each foreign TL writer correctly received ONLY
  post-join samples (Connext 425 from `x=68 y=106`, Fast DDS 93 from `x=57 y=99`; the pre-join first
  sample NOT received) — the behaviour-defining branch. Forward legs are fully wire-captured (our
  HEARTBEAT `firstAvailableSeqNumber=1` retained, 95 / 89 **retransmits** of the retained range answering
  the late reader's NACK, `CDR_LE 0x0001`); the reverse legs rest on the decoded application receipt + our
  outbound ACKNACKs on the wire, because the macOS lo0 BPF under-captures the foreign→us user-DATA
  direction (the same documented quirk, stated plainly). Our-to-our the feature is also covered by the
  unit test `run-dcps-durability-latejoiner-test` (green SBCL + Clasp).

Cross-links: [Type system](type-system.md) · [Discovery](discovery.md) · [DCPS](dcps.md) ·
[CDR & memory](cdr-and-memory.md).
