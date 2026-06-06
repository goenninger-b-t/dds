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
correct** them:

| Our value (committed) | Confirm with |
|---|---|
| `ShapeType` MinimalTypeObject = **87 bytes** (no encap header) | `typeobject-probe` + tshark |
| `ShapeType` EquivalenceHash = **`BF E2 A6 2E D8 11 AC 46 3C 40 C9 7D 30 EE`** | `typeobject-probe` + tshark |
| `serialize-type-information` (PID_TYPE_INFORMATION) bytes | `typeobject-probe` vs our `make square-pub` capture |
| XCDR2 ShapeType payload (FR-CDR-8) | `cdr-capture` + tshark |
| Bidirectional Shapes interop (FR-IO-1) | `shapes-pub` / `shapes-sub` ↔ our `make square-pub/sub` |

If Connext's bytes match ours → the serializers lock and `(b2b)` hash-based match
enforcement unblocks. If they differ, the diff points at exactly one of three one-line
knobs in `src/dds-types/typeobject-cdr.lisp` (encapsulation-header / `struct_flags` /
`member_flags`).

## Prerequisites

```sh
export NDDSHOME=/path/to/rti_connext_dds-7.x.y          # your Connext install
export CONNEXTDDS_ARCH=x64Linux4gcc7.3.0                # ls $NDDSHOME/lib to find yours
#   (macOS example: x64Darwin20clang12.0)
# optional: RTI_BUILD=debug    (default: release)
```
`tshark`/`wireshark` (with the RTPS dissector, as already used by `make wire`) is the
authoritative way to read the on-the-wire TypeObject/TypeInformation bytes.

## Layout

```
interop/connext/
  common/ShapeType.idl     the type, defined to MATCH this stack's shape-type exactly
  common/common.mk         shared build rules (NDDSHOME / CONNEXTDDS_ARCH / rtiddsgen)
  typeobject-probe/        prints discovered type + idles so its SEDP can be captured (the hash oracle)
  shapes-pub/              Connext publishes ShapeType  -> this stack's `make square-sub`
  shapes-sub/              Connext subscribes ShapeType <- this stack's `make square-pub`
  cdr-capture/             publishes one fixed sample for a byte-exact XCDR payload capture
```

## Build & run

```sh
make            # from interop/connext: build every app (each in its own subdir)
make -C shapes-pub      # or build one app
./shapes-pub/shapes_pub 0 BLUE         # domain 0, color BLUE
```
Per-app usage is in each subdirectory's `README.md`.

## The ShapeType definition (IMPORTANT)

`common/ShapeType.idl` is deliberately written to match **this stack's** `shape-type`
(`@final`; `@key` **unbounded** `string color`; three `long`s; sequential member ids
0..3) so the EquivalenceHash is an apples-to-apples comparison. RTI's `rtishapesdemo`
uses `string<128> color`; that bound difference changes the TypeObject/hash but **not**
the wire payload, and is absorbed by `ignore_string_bounds` (default) during type
coercion — so live pub/sub interop with `rtishapesdemo` still works.

## Extracting the EquivalenceHash with tshark

```sh
# capture loopback discovery while typeobject-probe (or shapes-pub) runs:
tshark -i lo -f "udp" -O rtps -V | less     # Linux loopback; use lo0 on macOS
# look in DATA(w) -> PID_TYPE_INFORMATION -> TypeIdentifier (EK_MINIMAL) -> the 14-byte hash
```
Compare those 14 bytes to `BF E2 A6 2E D8 11 AC 46 3C 40 C9 7D 30 EE` and the serialized
TypeObject length to 87. Report back the diff and I'll lock or correct the serializer.
