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
