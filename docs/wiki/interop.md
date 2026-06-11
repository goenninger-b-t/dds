# Interop with RTI Connext (and other DDS)

Common Lisp DDS is built to **interoperate on the wire with RTI Connext 7.x** and at least
one open-source DDS (FR-IO). Two assets support that: the **Connext oracle/interop harness**
under [`interop/connext/`](../../interop/connext/) and the standalone **Shapes harness**
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
- **Open peer (Fast DDS / Cyclone / OpenDDS)** interop: planned (FR-IO-2).

Cross-links: [Type system](type-system.md) · [Discovery](discovery.md) · [DCPS](dcps.md) ·
[CDR & memory](cdr-and-memory.md).
