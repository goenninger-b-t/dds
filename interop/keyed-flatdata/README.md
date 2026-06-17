# Keyed FlatData cross-DDS interop (WP-KEYED-FLATDATA + WP-FLATDATA-XCDR-TRANSCODE, FR-PF-4)

The per-feature interop Definition-of-Done gate (owner directive 2026-06-17: every feature
verifies interop with **both** RTI Connext **and** eProsima Fast DDS) for the keyed FlatData
feature. The conformance crux is the **keyhash / per-key instance identity** (RTPS 2.5
§9.6.4.8): a keyed FlatData type's instance identity must equal what a standards-conformant
peer computes for the same key value, so keyed matching + dispose-by-key interoperate on the
**wire**.

**Status: all four legs LIVE-verified in-session (2026-06-17), both peers, both directions.**
WP-KEYED-FLATDATA proved the reverse legs (the keyhash crux); WP-FLATDATA-XCDR-TRANSCODE then
closed the **forward** legs — both peers default a `@final` fixed-size primitive type to XCDR1 on
the wire, and our `:flatdata t` reader now **transcodes** that foreign representation into its
canonical XCDR2-LE buffer (it previously rejected it). Captures under `captures/`.

This is the **UDP/copy path** — the same-host Zero-Copy LOAN path is **not** wire-interoperable
and is out of scope here. No `*zerocopy-enabled*`; the keyed FlatData type is `:flatdata t`
(R6-gated) but the wire/copy path needs no Zero-Copy.

## The type

The shared interop type (`KeyedFlat.idl`), defined to match this stack's keyed FlatData type
exactly:

```idl
@final
struct KeyedFlat { @key long id; long x; long y; };
```

```lisp
(define-dds-type keyed-flat (:flatdata t) (id :i32 :key t) (x :i32) (y :i32))   ; dds.shapes:keyed-flat
```

- `id` is a fixed-size scalar `@key` (the only `@key` kind a `:flatdata t` type admits, ADR 0015).
- Its keyhash takes the `<=16` direct/zero-padded path (RTPS 2.5 §9.6.4.8 Example 1):
  **the i32 big-endian, right-zero-padded to 16**. For `id=N`: `00 00 00 0N 00 …`.
- The registered type name is pinned to **`keyed-flat`** at every peer's Topic constructor so it
  is byte-identical to this stack's registered type-name (discovery matches on topic + type name).

## Layout

```
interop/keyed-flatdata/
  KeyedFlat.idl                  the type (peers + this stack agree on it byte-for-byte)
  connext/                       RTI Connext peer (clean-room: our IDL, rtiddsgen output git-ignored)
    keyed_flat_pub.cxx/_sub.cxx  Connext WITH_KEY pub/sub; the sub prints each instance's keyhash hex
    Makefile USER_QOS_PROFILES.xml
  fastdds/                       Fast DDS peer (gen/ fastddsgen output committed by the owner once generated, Apache-2.0)
    keyed_flat_pub.cpp/_sub.cpp  Fast DDS WITH_KEY pub/sub; the sub prints each instance's keyhash hex
    Makefile profiles.xml participant_guard.hpp gen/
  captures/                      archived loopback proof pcaps
```

Our side is `make keyed-flat-pub` / `make keyed-flat-sub` (the DCPS COPY/UDP harness,
`dds.shapes:run-keyed-flat-{publisher,subscriber}`): the pub cycles `id` over `KEYS` keys and
prints each sample's keyhash; the sub prints each delivered sample's SampleInfo per-key instance
handle (computed by `%instance-handle` → `key-hash-keyed-flat-fd` off the deserialized FlatData
buffer) and tracks distinct instances — so a foreign peer's samples group into the correct
per-key instances iff our keyhash matches the peer's.

## What the keyhash conformance proof rests on

| Evidence | Where | Status |
|---|---|---|
| Our `-fd` keyhash == an INDEPENDENTLY-derived standards-conformant peer keyhash (RTPS 2.5 §9.6.4.8), incl. a pinned `id=1 -> #(00 00 00 01 0..0)` vector, a negative id, and `id` (not x/y) drives identity | offline test `keyed-flat-interop-keyhash` (`src/dds-tests/rtps-test.lisp`); runs on both impls | **PASS in suite** |
| Our `-fd` keyhash == our struct `key-hash-keyed-flat` (FlatData == non-FlatData, our side) | same test + `keyed-flatdata-keyhash` | **PASS in suite** |
| Keyed FlatData full keyed copy-path behaviour (per-key instance handle, view-state, KEEP_LAST, dispose-by-key) | `keyed-flatdata-copy-behavior` / `-dispose` (`integration-test.lisp`) | **PASS in suite** |
| Connext computes the SAME per-key keyhash for our samples (live, REVERSE) | "Connext leg" below | **PASS, in-session (2026-06-17)** |
| Fast DDS computes the SAME per-key keyhash for our samples (live, REVERSE) | "Fast DDS leg" below | **PASS, in-session (2026-06-17)** |
| Our FlatData reader reads a foreign rep via the TRANSCODE (live, FORWARD) — Connext + Fast DDS | "Forward leg" below | **PASS, in-session (2026-06-17)** |

The offline test derives the expected peer keyhash **from first principles** (`%expected-i32-keyhash`,
not via our own serializer), so it is a genuine cross-impl oracle, not a tautology.

## Connext leg (RTI Connext 7.3.1) — built + live, in-session

### Build & run (LOOPBACK — the proven recipe)

`USER_QOS_PROFILES.xml` is pinned **loopback-only** (`allow_interfaces=127.0.0.1`, UDPv4 only) and
the Lisp side reaches Connext with **unicast SPDP to `127.0.0.1:7410`** (`PEERS=127.0.0.1:7410`),
so everything rides `lo0` (sidesteps the macOS LAN-UDP firewall gate for the freshly built
`keyed_flat_*` binaries; loopback is exempt — same recipe as `interop/connext/nokey`). UDPv4-only
also exercises the copy path (not data-sharing/SHMEM).

**FIRST: kill any stale DDS process on the discovery ports** (`lsof -nP -iUDP:7400-7420`) — a
leftover binds participant index 1 (`7412`) and the unicast SPDP misses it.

```sh
export NDDSHOME=/Applications/rti_connext_dds-7.3.1
export CONNEXTDDS_ARCH=arm64Darwin20clang12.0
export DYLD_LIBRARY_PATH=$NDDSHOME/lib/$CONNEXTDDS_ARCH
make -C connext                         # builds keyed_flat_pub + keyed_flat_sub
lsof -nP -iUDP:7400-7420                 # confirm NOTHING else holds these ports

# REVERSE leg (this stack -> Connext): Connext sub binds 7410, prints each instance's keyhash:
./connext/keyed_flat_sub 0 0             # domain, seconds (0 = forever)
make -C ../.. keyed-flat-pub DOMAIN=0 COUNT=30 KEYS=3 DISPOSE_AFTER=4 ADVERTISE=127.0.0.1 PEERS=127.0.0.1:7410

# FORWARD leg (Connext -> this stack): Connext pub binds 7410 (publishes XCDR2 — see the note):
make -C ../.. keyed-flat-sub DOMAIN=0 SECONDS=35 ADVERTISE=127.0.0.1 PEERS=127.0.0.1:7410
DISPOSE_AFTER=5 ./connext/keyed_flat_pub 0 30 3
```

### Live results (2026-06-17, this host, lo0)

| Leg | Setup | Result |
|---|---|---|
| **Reverse** (our pub -> Connext sub) | `make keyed-flat-pub PEERS=127.0.0.1:7410` | **`matched=1`; Connext received 30/30 in EXACTLY 3 instances, keyhash per key = `00000000…` / `00000001…` / `00000002…`** — byte-identical to our keyhash. |
| **Reverse dispose-by-key** | `DISPOSE_AFTER=4` on the same pub | **Connext logged `INSTANCE_STATE change` for each of `00000000…` / `00000001…` / `00000002…`** — our dispose DATA's `PID_KEY_HASH` resolved to the correct per-key instance. |
| **Forward** (Connext pub -> our sub) | `keyed_flat_sub` + `keyed_flat_pub 0 30 3` | **`matched=1`; our FlatData reader RECEIVED 29/30 in EXACTLY 3 instances via the TRANSCODE** — Connext emitted `CDR_LE (0x0001)` (XCDR1-LE) on the wire (e.g. `serializedData: 020000003400000040000000` = id=2,x=52,y=64), and our `:flatdata t` reader transcoded it into its XCDR2-LE buffer (WP-FLATDATA-XCDR-TRANSCODE); keyhashes `00000000…`/`00000001…`/`00000002…`, all 3 dispose-by-key transitions resolved. **This is the forward leg that previously REJECTED — it now WORKS.** Archived `captures/kflat-forward-connext.pcap`. |

The **reverse leg is the keyhash conformance crux and it PASSES live**: Connext, a non-FlatData peer,
computes the SAME 16-octet per-key instance identity from our keyed FlatData samples as our offline
test pins, and our dispose-by-key keyhash resolves to the right instance on Connext. Archived:
`captures/kflat-reverse-loopback.pcap`.

### Wire (tshark RTPS dissector) — in-session

`captures/kflat-reverse-loopback.pcap` (reverse leg, our pub -> Connext) dissects under the tshark
RTPS dissector:

- **Our user DATA** (writer `…0x00000102`): `encapsulation kind: CDR2_LE (0x0007)` and
  `serializedData: 010000003300000039000000` for `id=1,x=51,y=57` — the i32 `@key id` little-endian
  in the XCDR2 payload, **no `PID_KEY_HASH` on alive DATA** (the receiver derives the key from the
  payload, RTPS 2.5 §8.4.5.4 / §9.6.4.8). Connext reads id/x/y and the keyhash correctly (table above).
- **Our dispose DATA**: 3 DATA submessages with `Inline QoS: Set`, `PID_KEY_HASH (0x0070)` +
  `PID_STATUS_INFO (0x0071) Disposed` — the conformant dispose-by-key wire form (§9.6.4.8/§9.6.4.9).
- The only `Malformed` markers are the SEDP `PID_TYPE_INFORMATION (0x0075)` payload — a **known
  tshark TypeObject dissector limitation** (Connext itself parsed our SEDP and matched), not a wire
  defect. The engine-codec gate `make wire` is **green** independently.

### Forward leg (peer pub -> our sub) — the transcode (WP-FLATDATA-XCDR-TRANSCODE)

The forward leg is the FlatData reader reading a **foreign on-wire representation**. This stack's
`:flatdata t` reader keeps a 0-alloc read-in-place fast path for its native `PLAIN_CDR2_LE (0x0007)`
(XCDR2-LE) and, since WP-FLATDATA-XCDR-TRANSCODE, **transcodes** a foreign transcodable rep
(`PLAIN_CDR_BE 0x0000`, `PLAIN_CDR_LE 0x0001`, `PLAIN_CDR2_BE 0x0006`) into its canonical XCDR2-LE
buffer via the sibling struct codec (DDS-XTypes 1.3 §7.6.3.1.2), then writes each field through the
`-fd` setters; a non-PLAIN/DELIMITED/XML rep is still a clean false-REJECT (no OOB even at
`(safety 0)`). Both peers default a `@final` fixed-size primitive type to XCDR1 on the wire, so the
forward leg exercises exactly the transcode:

| Peer | On-wire rep (tshark) | Result |
|---|---|---|
| **Connext 7.3.1** | `CDR_LE (0x0001)` (XCDR1-LE) | **29/30 in 3 instances via the transcode**; keyhashes byte-identical; dispose-by-key OK. `captures/kflat-forward-connext.pcap`. |
| **Fast DDS 3.6.1** | `CDR_LE (0x0001)` (XCDR1-LE) | **29/30 in 3 instances via the transcode**; keyhashes byte-identical; dispose-by-key OK. `captures/kflat-forward-fastdds.pcap`. |

(The ~1/30 not delivered is the first sample sent in the pre-match window, normal for a freshly
matched reliable pair; it is not a transcode miss.) The earlier "forward leg REJECTS an XCDR1
payload" limitation is **closed** by the transcode. A residual production-side XTypes nicety —
advertising `PID_DATA_REPRESENTATION` in our SEDP so a peer can also pick XCDR2 — is tracked
separately and is not required for the copy-path forward read.

## Fast DDS leg (eProsima Fast DDS 3.6.1) — built + live, in-session

Fast DDS needs `scripts/with-fastdds.sh` (`FASTDDS_PREFIX` + the pinned `fastddsgen`; toolchain pin in
`interop/fastdds/README.md`). The `fastddsgen` type support under `fastdds/gen/` is **committed
verbatim** (Apache-2.0, Fast-DDS-Gen v4.3.0 — see `docs/provenance.md`); regenerate after an IDL change:

```sh
./scripts/with-fastdds.sh bash -c 'cd interop/keyed-flatdata/fastdds && "$FASTDDSGEN" -replace -d gen ../KeyedFlat.idl'
./scripts/with-fastdds.sh make -C interop/keyed-flatdata/fastdds      # build keyed_flat_pub + keyed_flat_sub
```

`profiles.xml` `interfaceWhiteList` is pinned **`127.0.0.1` only** for the same-host loopback rendezvous
(with a LAN address also whitelisted, Fast DDS routes the user dataflow off `lo0` and the samples miss our
loopback reader — discovery still matches but no data flows). Edit per machine if running across hosts.

### Run (LOOPBACK)

```sh
# REVERSE leg (this stack -> Fast DDS): the Fast DDS sub prints each instance's keyhash hex:
make fastdds-keyed-flat-sub SECONDS=40 &
sleep 6 && make keyed-flat-pub DOMAIN=0 COUNT=30 KEYS=3 DISPOSE_AFTER=5 ADVERTISE=127.0.0.1 PEERS=127.0.0.1:7410
wait

# FORWARD leg (Fast DDS -> this stack): the Fast DDS pub offers XCDR1+XCDR2; our reader transcodes:
make keyed-flat-sub DOMAIN=0 SECONDS=45 ADVERTISE=127.0.0.1 PEERS=127.0.0.1:7410 &
sleep 11 && DISPOSE_AFTER=5 make fastdds-keyed-flat-pub COUNT=30 KEYS=3
wait
```

### Live results (2026-06-17, this host, lo0)

| Leg | Setup | Result |
|---|---|---|
| **Reverse** (our pub -> Fast DDS sub) | `make fastdds-keyed-flat-sub` + `make keyed-flat-pub` | **Fast DDS received 30/30 in EXACTLY 3 instances**, per-key handle `00000000…`/`00000001…`/`00000002…` — byte-identical to our keyhash and to Connext's; all 3 dispose-by-key `INSTANCE_STATE` transitions resolved. Archived `captures/kflat-reverse-fastdds.pcap` (our user DATA = `CDR2_LE (0x0007)`, e.g. `serializedData: 010000003300000039000000` for id=1,x=51,y=57, no `PID_KEY_HASH` on alive DATA; dispose DATA carries `PID_KEY_HASH (0x0070)` + `PID_STATUS_INFO (0x0071) Disposed`). |
| **Forward** (Fast DDS pub -> our sub) | `make keyed-flat-sub` + `make fastdds-keyed-flat-pub` | **Our FlatData reader received 29/30 in EXACTLY 3 instances via the TRANSCODE**; Fast DDS emitted `CDR_LE (0x0001)` (XCDR1-LE, `serializedData: 020000003400000040000000` = id=2,x=52,y=64), our reader transcoded it into its XCDR2-LE buffer; keyhashes byte-identical; dispose-by-key OK. Archived `captures/kflat-forward-fastdds.pcap`. |

This **closes the Fast DDS leg** (was owner-pending): the reverse leg is the Fast DDS half of the keyhash
conformance crux — an independent standards-conformant peer computes the SAME 16-octet per-key identity for
our keyed FlatData samples — and the forward leg is the transcode reading Fast DDS's XCDR1-LE body.

### Harness note (the Fast DDS forward-leg writer)

`keyed_flat_pub.cpp` offers BOTH `XCDR_DATA_REPRESENTATION` (XCDR1) and `XCDR2_DATA_REPRESENTATION` on the
writer. Fast DDS enforces the DDS-XTypes 1.3 §7.6.3.1.1 data-representation compatibility **on the writer
side**: with an XCDR2-only writer it refused to match our reader (whose SEDP advertises no
`PID_DATA_REPRESENTATION`, i.e. the XCDR1 default) and so sent nothing (discovery matched one-way; no user
DATA on the wire). Offering XCDR1 too makes the match symmetric; Fast DDS then publishes the common rep
(XCDR1-LE), which our reader transcodes. (Connext is more lenient — its XCDR2-requested writer matched our
reader and fell back to emitting XCDR1-LE directly.) The production-side fix that would let either peer also
pick XCDR2 — advertising `PID_DATA_REPRESENTATION` in our SEDP — is tracked separately; it is not a
transcode or keyhash defect.

## Clean-room / provenance

Clean-room: our `KeyedFlat.idl`. Connext `rtiddsgen` output is produced at build time and
**git-ignored** (`.gitignore`); Fast DDS `fastddsgen` output under `fastdds/gen/` is **committed
verbatim** (Apache-2.0 output of the pinned generator — record the generator pin + licence in
`docs/provenance.md`, mirroring `interop/fastdds/README.md`). No RTI/Fast DDS **source** is copied
into any hand-written file. The keyhash is pinned from RTPS 2.5 §9.6.4.8.
