# RTI Connext live-test harness

Connext-side test apps that act as the **gold interop oracle** for this stack
(REQUIREMENTS §8, FR-IO-1, NFR-IP). They build against the RTI Connext **public API**
(+ an IDL you control); **no Connext source is copied**, and the `rtiddsgen`-generated
type support is produced at build time and git-ignored. Treating Connext as a behavioral
reference via its API/wire is exactly the allowed clean-room use.

> These apps are **not built or run by this repo's CI** — they require a Connext install,
> which lives in your environment, not here. Build them where Connext is installed.

## Why this exists (the immediate job)

Several XTypes wire artifacts in this stack are **PROVISIONAL** — spec-faithful but
unconfirmed against a conformant peer (see `docs/verification.csv` FR-TYPE-2/3 and the
`typeobject-cdr.lisp` header). This harness produces the reference bytes to **lock or
correct** them.

> **Finding (2026-06-08, ADR 0009).** `typeobject-probe` was driven against live RTI
> Connext 7.3.1. **Default Connext (RTI↔RTI, same host) does not emit
> `PID_TYPE_INFORMATION` (0x0075) at all** — it advertises the type via the vendor
> parameter **`PID_TYPE_OBJECT_LB` (0x8021)**, a ZLIB-compressed **complete** TypeObject
> (540 B uncompressed). **The EK_MINIMAL `EquivalenceHash` is therefore not on this wire**,
> so it cannot be read back to confirm our minimal serializer here. Separately,
> `rtiddsgen` bounds the unbounded `string color` at **255** (`string_255_character`), so
> Connext's `ShapeType` is structurally different from our unbounded-`color` type — our
> committed `87 B` / `BF E2 A6 2E …` values describe a different type. Consequence:
> minimal-hash equality must **not** be a hard endpoint-match gate (it would false-reject
> every stock Connext peer); matching is by type-name + structural assignability,
> consuming `PID_TYPE_OBJECT_LB` / TypeLookup. The provisional minimal serializer stays
> gated; "b2b = enforce hash equality" is retired (ADR 0009).

What the capture **can** confirm (oracle still useful):

| Target | How | Status |
|---|---|---|
| `ShapeType` **complete** TypeObject structure (extensibility, member ids, key, kinds) | `typeobject-probe` → decompress `PID_TYPE_OBJECT_LB` + tshark | ✅ confirms `@final`, ids 0..3, `@key color`, three `INT_32` |
| `ShapeType` **minimal** TypeObject (87 B) + EquivalenceHash | needs a peer that emits `0x0075` (foreign-vendor, or a larger type) | ⛔ not on the default RTI↔RTI wire |
| `serialize-type-information` (PID_TYPE_INFORMATION) bytes | `typeobject-probe` vs our `make square-pub` capture | blocked on the above |
| XCDR2 ShapeType payload (FR-CDR-8) | `cdr-capture` + tshark | pending |
| Bidirectional Shapes interop (FR-IO-1) | `shapes-pub` / `shapes-sub` ↔ our `make square-pub/sub` | pending |

## Prerequisites

```sh
export NDDSHOME=/path/to/rti_connext_dds-7.x.y          # your Connext install
export CONNEXTDDS_ARCH=x64Linux4gcc7.3.0                # ls $NDDSHOME/lib to find yours
#   (macOS example: x64Darwin20clang12.0)
# optional: RTI_BUILD=debug    (default: release)
```
`tshark`/`wireshark` (with the RTPS dissector, as already used by `make wire`) is the
authoritative way to read the on-the-wire TypeObject/TypeInformation bytes.

**Runtime (macOS).** RTI's dylibs use `@loader_path` install names, so the built apps
need the lib dir on the loader path at run time:

```sh
export DYLD_LIBRARY_PATH="$NDDSHOME/lib/$CONNEXTDDS_ARCH"
```

## Layout

```
interop/connext/
  common/ShapeType.idl     the type, defined to MATCH this stack's shape-type exactly
  common/common.mk         shared build rules (NDDSHOME / CONNEXTDDS_ARCH / rtiddsgen)
  typeobject-probe/        prints discovered type + idles so its SEDP can be captured (the hash oracle)
  shapes-pub/              Connext publishes ShapeType  -> this stack's `make square-sub`
  shapes-sub/              Connext subscribes ShapeType <- this stack's `make square-pub`
  cdr-capture/             publishes one fixed sample for a byte-exact XCDR payload capture
  large-data/              LargeData pub+sub under forced fragmentation (the DATA_FRAG oracle)
```

## Build & run

```sh
make            # from interop/connext: build every app (each in its own subdir)
make -C shapes-pub      # or build one app
./shapes-pub/shapes_pub 0 BLUE         # domain 0, color BLUE
```
Per-app usage is in each subdirectory's `README.md`.

## The ShapeType definition (IMPORTANT — and a correction)

`common/ShapeType.idl` is written to mirror **this stack's** `shape-type` (`@final`;
`@key string color`; three `long`s; sequential member ids 0..3).

**Correction (2026-06-08):** the original intent — *"keep `color` UNBOUNDED so the
EquivalenceHash is an apples-to-apples comparison"* — does **not** hold. `rtiddsgen`
maps an unbounded `string` to a **255-bounded** string by default (`string_255_character`,
Bound 255), so Connext's TypeObject is **not** the unbounded-`color` type this stack
generates, and the hashes cannot match by construction. For any future byte-exact
comparison, first **align the type**: either bound our `color` at 255 to match
`rtiddsgen`'s default, or generate Connext truly-unbounded (`-unboundedSupport` /
explicit bound). The bound difference does **not** change the XCDR wire payload, so live
pub/sub interop (absorbed by `ignore_string_bounds` during coercion) still works.

## LargeData under forced fragmentation (the DATA_FRAG oracle)

`large-data/` builds **both** `large_pub` and `large_sub` (one dir, one IDL, shared
generated type — `common.mk` supports multi-binary dirs via `APPS`). The type mirrors
this stack's `large-data` (`@final`; `@key long id`; unbounded `sequence<octet> payload`;
`make large-pub`/`make large-sub` on our side). Its `USER_QOS_PROFILES.xml` forces the
fragmented wire: UDPv4-only (same-host SHMEM would bypass `lo0`), builtin-UDPv4
`message_size_max = 1400` (an 8000-octet sample → 7 DATA_FRAGs of `fragmentSize=1288`),
and **asynchronous publish mode** (Connext refuses reliable fragmented data on a
synchronous writer). Two `rtiddsgen` traps recorded in `large-data/README.md`: the
unbounded sequence is silently bounded at **100** without `-unboundedSupport` (the
ShapeType string-255 finding again, ADR 0009), and lossless RTI↔RTI loopback shows
DATA_FRAG + plain HEARTBEAT but **no HEARTBEAT_FRAG/NACK_FRAG**.

```sh
make -C large-data
# terminal 1 (run from inside large-data/ — Connext loads USER_QOS_PROFILES.xml from the cwd):
cd large-data && ./large_sub 0 20        # domain, seconds (0 = forever)
# terminal 2:
cd large-data && ./large_pub 0 8000 15   # domain, octets, count (0 = forever)
```

## Capturing the SEDP TypeObject with tshark

```sh
# 1. force discovery onto loopback UDP so SEDP is on the wire (default same-host
#    Connext prefers SHMEM, which tshark cannot see). typeobject-probe/USER_QOS_PROFILES.xml
#    already sets UDPv4-only + loopback peers + no multicast; Connext auto-loads it from CWD.
# 2. capture while the probe runs (lo on Linux, lo0 on macOS):
tshark -i lo0 -w probe.pcap -a duration:18 -f "udp"   &
DYLD_LIBRARY_PATH="$NDDSHOME/lib/$CONNEXTDDS_ARCH" ./typeobject_probe 0
# 3. decode. NOTE: if this host's Wireshark profile disables link/net dissectors
#    (disabled_protos), re-enable them explicitly or the RTPS heuristic never fires:
tshark -r probe.pcap --enable-protocol null --enable-protocol ip --enable-protocol udp -V \
  | less
```

In the SEDP `DATA(w)` look for the type parameters. **As of Connext 7.3.1 (default,
RTI↔RTI) you will find `PID_TYPE_OBJECT_LB` (0x8021) — a ZLIB-compressed _complete_
TypeObject — and NO `PID_TYPE_INFORMATION` (0x0075)**; the dissector decompresses it under
`[Uncompressed type object] → Type Object`. The EK_MINIMAL `EquivalenceHash` is **not on
this wire** (see the Finding above and ADR 0009). To obtain a minimal hash you need a peer
that emits `0x0075` — test a **foreign-vendor** subscriber (our `make square-sub`) or a
type past Connext's inline-TypeObject size threshold.
