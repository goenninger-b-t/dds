# Keyed FlatData cross-DDS interop (WP-KEYED-FLATDATA, FR-PF-4)

The per-feature interop Definition-of-Done gate (owner directive 2026-06-17: every feature
verifies interop with **both** RTI Connext **and** eProsima Fast DDS) for the keyed FlatData
feature. The conformance crux is the **keyhash / per-key instance identity** (RTPS 2.5
§9.6.4.8): a keyed FlatData type's instance identity must equal what a standards-conformant
peer computes for the same key value, so keyed matching + dispose-by-key interoperate on the
**wire**.

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
| Connext computes the SAME per-key keyhash for our samples (live) | "Connext leg" below | **PASS, in-session (2026-06-17)** |
| Fast DDS computes the SAME per-key keyhash for our samples (live) | "Fast DDS leg" below | **owner-pending** |

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
| **Forward** (Connext pub -> our sub) | `keyed_flat_pub` (XCDR1 default) | `matched=1`, but our XCDR2-only FlatData reader **rejects** the XCDR1-BE payload (see the representation note). With `keyed_flat_pub` requesting XCDR2 writer-QoS, Connext on this host still emitted XCDR1 on the wire (the reader-side request governs the actual encapsulation, and our SEDP advertises no `PID_DATA_REPRESENTATION`). |

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

### Representation note (XCDR1 vs XCDR2) — the forward-leg limitation

This stack's `:flatdata t` reader is **XCDR2-LE only** by design: it read-in-place block-copies the
payload body, valid only for a `PLAIN_CDR2_LE (0x0007)` payload of the exact FlatData layout. A
foreign **XCDR1 / big-endian** payload is correctly **rejected** (false-REJECT-safe, no OOB,
no silent mis-read), not read. Connext defaults a `@final` primitive type to XCDR1 unless steered to
XCDR2. This does **not** affect the keyhash conformance (proven by the reverse leg + offline), but it
means the **forward-leg FlatData copy-path read** does not yet accept an XCDR1/BE peer. Closing it is
a follow-up: either advertise `PID_DATA_REPRESENTATION = XCDR2` in our SEDP (so a peer publishes XCDR2
to our reader) and/or teach the FlatData reader to transcode a foreign XCDR1/BE body into the XCDR2-LE
buffer. The non-FlatData struct codec already honours the encapsulation header (it reads XCDR1-BE),
so a non-FlatData reader of the same type interoperates both directions today.

## Fast DDS leg (eProsima Fast DDS) — built + handed over to the owner

Fast DDS runs **only in the owner's environment** (`scripts/with-fastdds.sh` + `FASTDDS_PREFIX`; the
pinned toolchain is in `interop/fastdds/README.md`). The peer apps + a one-command run target are
provided; **the owner executes this leg.**

### Owner steps

```sh
# 1. Generate the type support (committed verbatim once generated, Apache-2.0 — see fastdds/gen/GENERATE.md + docs/provenance.md):
cd interop/keyed-flatdata/fastdds
../../../scripts/with-fastdds.sh bash -c '"$FASTDDSGEN" -replace -d gen ../KeyedFlat.idl'
git add gen && rm gen/GENERATE.md          # commit the generated type support

# 2. Build (from the repo root; the wrapper provides FASTDDS_PREFIX):
./scripts/with-fastdds.sh make -C interop/keyed-flatdata/fastdds

# 3a. REVERSE leg (this stack -> Fast DDS): the Fast DDS sub prints each instance's keyhash hex:
make fastdds-keyed-flat-sub SECONDS=35 &
sleep 3 && make keyed-flat-pub DOMAIN=0 COUNT=30 KEYS=3 DISPOSE_AFTER=4 ADVERTISE=127.0.0.1
wait

# 3b. FORWARD leg (Fast DDS -> this stack): the Fast DDS pub requests XCDR2 (our FlatData reader needs it):
make keyed-flat-sub DOMAIN=0 SECONDS=35 ADVERTISE=127.0.0.1 &
sleep 8 && DISPOSE_AFTER=5 make fastdds-keyed-flat-pub COUNT=30 KEYS=3
wait
```

Edit `fastdds/profiles.xml` `interfaceWhiteList` per machine (keep `127.0.0.1` first for same-host).

### Expected result the owner must see

- **Reverse leg (PRIMARY — the keyhash crux):** the Fast DDS subscriber receives all 30 samples and
  groups them into **exactly 3 distinct instances**, with the per-key instance handle hex
  **`00000000000000000000000000000000`** (id=0), **`00000001000000000000000000000000`** (id=1),
  **`00000002000000000000000000000000`** (id=2) — byte-identical to this stack's keyhash and to what
  Connext computed in-session. With `DISPOSE_AFTER=4`, the Fast DDS sub prints an `INSTANCE_STATE`
  change for each of those three keyhashes (our dispose-by-key resolves to the right instance). This
  is the Fast DDS half of the cross-DDS conformance gate.
- **Forward leg:** because `keyed_flat_pub` requests XCDR2 writer-QoS, Fast DDS should publish
  `PLAIN_CDR2_LE`, which this stack's FlatData reader accepts; our `keyed-flat-sub` then prints the
  same three per-key keyhashes and groups into 3 instances. If Fast DDS still emits XCDR1 on the wire
  (the reader governs the actual encapsulation, same root cause as the Connext forward leg), our
  XCDR2-only FlatData reader will reject it — that is the documented forward-leg representation
  limitation above, **not** a keyhash defect; capture the wire and report.

## Clean-room / provenance

Clean-room: our `KeyedFlat.idl`. Connext `rtiddsgen` output is produced at build time and
**git-ignored** (`.gitignore`); Fast DDS `fastddsgen` output under `fastdds/gen/` is **committed
verbatim** (Apache-2.0 output of the pinned generator — record the generator pin + licence in
`docs/provenance.md`, mirroring `interop/fastdds/README.md`). No RTI/Fast DDS **source** is copied
into any hand-written file. The keyhash is pinned from RTPS 2.5 §9.6.4.8.
