# Interop with RTI Connext (and other DDS)

Common Lisp DDS is built to **interoperate on the wire with RTI Connext 7.x** and at least
one open-source DDS (FR-IO). Three assets support that: the **Connext oracle/interop harness**
under [`interop/connext/`](../../interop/connext/), the **Fast DDS peer harness** under
[`interop/fastdds/`](../../interop/fastdds/), and the standalone **Shapes harness**
(`dds-shapes`, the `make square-*` targets). Wire correctness is judged with the Wireshark/
tshark RTPS dissector — the same dissector `make wire` uses — not by eye.

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
```

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

## Confirming the XTypes wire bytes (the current open item)

The XCDR2 TypeObject serializer + EquivalenceHash and the TypeInformation codec are
**PROVISIONAL** — spec-faithful but unconfirmed against a conformant peer (see
[Type system → Notes](type-system.md)). To lock them, compare Connext's `ShapeType` hash
(from `typeobject-probe` + tshark, or a `rtiddsgen` reference run) against ours:

```
ShapeType  (@final; @key unbounded string color; long x,y,shapesize; ids 0..3)
ours: EquivalenceHash = BF E2 A6 2E D8 11 AC 46 3C 40 C9 7D 30 EE   (TypeObject = 87 bytes, no encap header)
```

If they match, the serializers lock and hash-based match enforcement can be enabled; if not,
the diff isolates one of three one-line knobs (encapsulation-header / `struct_flags` /
`member_flags`) in `src/dds-types/typeobject-cdr.lisp`.

## Status

- **Shapes wire format**: validated against the tshark RTPS dissector (`make wire`).
- **Bidirectional Connext interop**: staged (the harness exists) but **not yet run** — needs
  a Connext install. Same gate applies to full DCPS/content-filter interop.
- **Open peer (Fast DDS)** interop: **bidirectional reliable ShapeType exchange achieved**
  vs Fast DDS 3.6.1 (forward 95/100, reverse 250/250, HEARTBEAT/ACKNACK live both
  directions, tshark-validated — the FR-IO-2 data-plane DoD, S2); the **EquivalenceHash is
  externally confirmed** (S3, locked vector) and the **TypeLookup getTypes client leg is
  live** (S4 leg A: our client consumes their server's reply, frames 85/86-87 of
  `s4-ourclient-lo0.pcap`); the remaining FR-IO-2 step is S4 leg B (their client against
  our TypeLookup server).

Cross-links: [Type system](type-system.md) · [Discovery](discovery.md) · [DCPS](dcps.md) ·
[CDR & memory](cdr-and-memory.md).
