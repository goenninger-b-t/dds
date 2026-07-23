# Appendable extensibility — cross-DDS interop (Leg 1)

Live wire proof that NeoDDS's `:appendable` extensibility (DDS-XTypes 1.3 §7.4.3.5 rules 29/30,
Table 60 §7.6.3.1.2) is on the wire correctly, against **RTI Connext 7.3.1**. The wire is the
oracle: every claim below is dissected with the tshark RTPS dissector under a clean
`WIRESHARK_CONFIG_DIR` (this host's default Wireshark profile disables the lo0 dissectors).

## What the spec says (read from `docs/specs/xtypes-1_3.pdf`, not from memory)

- Rule **(30)** — `XCDR[2] << {O : APPENDABLE_TYPE} = { DHEADER(O):UInt32 } { O : AsFinal }`. Under
  encoding version 2 an appendable type is a **DHEADER** (the serialized size of the content that
  follows, *excluding the DHEADER itself*, §7.4.3.4.1) then the members as if final.
- Rule **(29)** — `XCDR[1] << {O : APPENDABLE_TYPE} = { O : AsFinal }`. Under version 1 an
  appendable type is serialized **exactly as final — no DHEADER** (nothing for a distinct id to
  delimit).
- **Table 60** keys the encapsulation id on extensibility *and* version: `FINAL`+v2+LE = `CDR2_LE`
  **0x0007**, but `APPENDABLE`+v2+LE = `D_CDR2_LE` **0x0009**; `APPENDABLE`+v1+LE = `CDR_LE`
  **0x0001** (same as final, per rule 29).

## Status

| leg | writer | reader | result |
|---|---|---|---|
| self | NeoDDS (XCDR2) | NeoDDS | ✅ **rule (30)** — `D_CDR2_LE 0x0009` + `DHEADER=24`, wire-dissected |
| B (foreign → ours) | Connext (XCDR1) | NeoDDS | ✅ **rule (29)** — `CDR_LE 0x0001`, no DHEADER, wire-dissected; 476 samples decoded |
| A (ours → foreign) | NeoDDS (XCDR2) | Connext | ⏳ blocked on a host reachability issue **unrelated to appendable** (see below) |
| Connext emits 0x0009 | Connext (XCDR2) | — | ⏳ not run — Connext defaults to XCDR1 for appendable; needs a DataRepresentation=XCDR2 QoS on its writer |
| Fast DDS | — | — | ⏳ not started |

Both extensibility rules and both encapsulation ids are therefore **observed on a real wire**, one
of them (rule 29) driven end-to-end by an independent vendor. The remaining legs are open.

## Self leg — NeoDDS writer, rule (30), `0x0009` + DHEADER

```sh
# our subscriber (a writer with no matched reader emits no DATA, so run our own reader too)
make square-sub TYPE=appendable PEERS=127.0.0.1:7410 &
# our publisher
make square-pub TYPE=appendable COUNT=10 PEERS=127.0.0.1:7410
# capture lo0 under a clean profile:  tshark -i lo0 -w cap.pcap
```

Dissected payload of an appendable DATA:

```
encapsulation kind: D_CDR2_LE (0x0009)
serializedData: 18000000 05000000 424c5545 00 000000 35000000 34000000 1e000000
                └DHEADER┘ └─len 5─┘ └"BLUE\0"┘ └pad─┘ └x=53──┘ └y=52──┘ └size=30┘
                  = 24      4    +    5     +   3   +   4    +   4    +   4  = 24
```

`DHEADER = 24` = the content size excluding the DHEADER itself (§7.4.3.4.1). Discovery traffic
correctly stayed `PL_CDR_LE (0x0003)` and participant messages `CDR_LE (0x0001)` — the
extensibility-keyed id selection did not leak into paths it must not touch.

## Leg B — Connext writer → NeoDDS reader, rule (29), `0x0001` no DHEADER

```sh
export NDDSHOME=/Applications/rti_connext_dds-7.3.1
export CONNEXTDDS_ARCH=arm64Darwin20clang12.0        # ls $NDDSHOME/lib
make                                                 # -> appendable_pub appendable_sub
export NDDS_QOS_PROFILES=$PWD/../perftest/connext/udp_only.xml   # force UDP so nothing hides in SHMEM
./appendable_pub 0 GREEN 40                          # Connext publishes @appendable ShapeType
# in the repo:  make square-sub TYPE=appendable ADVERTISE=127.0.0.1 PEERS=127.0.0.1:7410
```

Our reader decoded **476** samples. The lo0 capture shows Connext chose **XCDR1** for the appendable
type, and the body carries **no DHEADER**:

```
encapsulation kind: CDR_LE (0x0001)
issueData: 06000000 475245454e00 0000 08000000 3e000000 28000000
           └─len 6─┘ └"GREEN\0"─┘ └pad┘ └x=8──┘ └y=62─┘ └size=40┘
```

24 body octets, no `18000000` DHEADER prefix — rule (29). Our appendable deserializer reads a
DHEADER only `(when (eq mode :xcdr2) ...)`, so under the XCDR1 encapsulation it correctly expects
none; the 476 clean decodes are the proof.

## Open: our writer → Connext reader (a host reachability issue, NOT appendable)

`./appendable_sub` receives **0** from `make square-pub TYPE=appendable ADVERTISE=192.168.2.148`.
**Control run: the known-good `@final` `TYPE=canonical` publisher against the Connext `shapes_sub`
also receives 0**, same signature — our side sees `peers=1` (participant discovered) but
`ACKNACKs received=0` (the reliable reader never matched). Connext's verbose log even shows it
accepted our type (`assertRemoteEndpointEx:TypeObject successfully stored (topic:'Square',
type:'ShapeType')`). So this is a general our-pub → Connext-sub discovery/reachability problem on
this host, **not** an appendable defect — debug it as a discovery issue against a known-green
recipe, not as a wire-format bug.

## Type definition

`AppendableShape.idl` defines an `@appendable struct ShapeType` — identical field shape and the same
registered type name (`ShapeType`) as the `@final` type in `../connext/common/ShapeType.idl`, so the
**only** intended difference is the extensibility. rtiddsgen output and the built binaries are
git-ignored (clean-room: generated locally, never checked in).
