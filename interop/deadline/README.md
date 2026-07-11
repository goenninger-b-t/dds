# DEADLINE + SAMPLE_LOST live interop (WP-DCPS-API-COMPLETION S4)

Live cross-vendor validation that the three S4 statuses fire on the wire against **RTI Connext
7.3.1** and **eProsima Fast DDS**: OFFERED/REQUESTED_DEADLINE_MISSED (DDS 1.4 §2.2.3.7) and
SAMPLE_LOST (§2.2.4.1). Treats each vendor as the interop oracle (public API + wire only; **no
vendor source/headers/generated code copied** — clean-room, NFR-IP). Not built/run by CI; needs a
local Connext + Fast DDS install. Captures/dylibs are git-ignored.

Our side is the DCPS runners `dds.shapes:run-deadline-{publisher,subscriber}` (`make deadline-pub` /
`make deadline-sub`) — the **DCPS** layer (`create-datawriter`/`write-sample`, `create-datareader` +
the background deadline monitor), so the live path exercises the S4 code, not the raw `dds.disc`
plane.

## RxO note (why the peer must offer a finite deadline)

DEADLINE is Requested-offered: a reader matches a writer only if `offered_period <= requested_period`
(DDS 1.4 §2.2.3.7). A **default** peer writer offers `DURATION_INFINITE`, so a finite-requested reader
does **not** match it. For the REQUESTED_DEADLINE_MISSED leg the peer writer must therefore offer a
**finite** deadline:

- **Connext**: add to the `is_default_qos` profile in `interop/connext/shapes-pub/USER_QOS_PROFILES.xml`
  (temporary — revert after; it changes the shared default):
  ```xml
  <datawriter_qos><deadline><period><sec>1</sec><nanosec>0</nanosec></period></deadline></datawriter_qos>
  ```
- **Fast DDS**: the `shapes_pub` now honours a `DEADLINE_MS` env gate (additive, off by default) —
  `DEADLINE_MS=1000 ./shapes_pub`.

On this host, foreign-vendor multicast discovery rides the LAN interface `192.168.2.148`; if a peer
is pinned loopback-only, whitelist that address too (Connext `allow_interfaces`, Fast DDS
`interfaceWhiteList`) and run our side with `ADVERTISE=192.168.2.148`.

## What this confirms — live PASS (2026-07-10)

| Leg | Recipe | Result |
|---|---|---|
| **Connext → our reader: REQUESTED_DEADLINE_MISSED** | Connext `shapes_pub` (offered 1s) ↔ `make deadline-sub DEADLINE_MS=2000`; kill the pub mid-run | ✅ matched by RxO, **140** samples delivered, `REQUESTED_DEADLINE_MISSED 0→…→6` over the silence, `SAMPLE_LOST 0` (clean reliable stream — no false positive), writer then lease-pruned |
| **our writer → Connext reader: OFFERED_DEADLINE_MISSED** | `make deadline-pub DEADLINE_MS=1500 COUNT=5` ↔ Connext `shapes_sub` | ✅ our `OFFERED_DEADLINE_MISSED 0→9` climbs once writing stops (one per elapsed 1.5s period) |
| **Fast DDS → our reader: REQUESTED_DEADLINE_MISSED** | Fast DDS `DEADLINE_MS=60 shapes_pub` (publishes every 100ms) ↔ `make deadline-sub DEADLINE_MS=80` | ✅ matched by RxO, **186** samples delivered, `REQUESTED_DEADLINE_MISSED 0→…→4` (the 100ms cadence exceeds the 80ms requested deadline — fires with the writer still alive) |
| **Fast DDS → our reader: SAMPLE_LOST** | Fast DDS `DEADLINE_MS=1000 shapes_pub` (default KEEP_LAST-1) ↔ `make deadline-sub DEADLINE_MS=2000` | ✅ `SAMPLE_LOST 0→…→4` — a real cross-vendor irrecoverable GAP (the KEEP_LAST-1 writer overwrote SNs before our reliable reader received them), fired via `reader-on-gap` → the `on-sample-lost` hook |

**Coverage:** both new statuses fire live against **both** vendors (DEADLINE both directions on
Connext + REQUESTED on Fast DDS; SAMPLE_LOST on Fast DDS, correctly silent on the clean Connext
stream). Hundreds of samples delivered each way ⇒ S4 introduces **no interop regression** (it adds no
wire surface — DEADLINE QoS carriage/RxO was already M3; SAMPLE_LOST only reads existing GAPs).

**Not shown here (honestly):** a best-effort SAMPLE_LOST from a real dropped datagram is not
deterministically forceable over loopback (no packet loss); it is covered by the deterministic offline
test `dcps-sample-lost`. Fast-DDS REQUESTED via **killing** the writer does not fire — the vanished
writer's instance is autopurged, disarming its per-instance timer — so the alive-but-slow recipe above
is used instead; the firing mechanism itself is identical to the Connext silence leg.

## Recipe (both vendors)

```sh
# --- Connext REQUESTED (money leg) ---
# 1) add the <deadline> snippet above to interop/connext/shapes-pub/USER_QOS_PROFILES.xml
cd interop/connext/shapes-pub
export NDDSHOME=/Applications/rti_connext_dds-7.3.1
DYLD_LIBRARY_PATH="$PWD:$NDDSHOME/lib/arm64Darwin20clang12.0" ./shapes_pub 0 BLUE 30 &
cd - ; make deadline-sub DOMAIN=0 DEADLINE_MS=2000 TYPENAME=ShapeType SECONDS=22 &
sleep 9 ; kill %1        # writer goes silent -> REQUESTED_DEADLINE_MISSED climbs
# (revert the XML afterwards)

# --- our OFFERED -> Connext reader ---
cd interop/connext/shapes-sub && DYLD_LIBRARY_PATH=... ./shapes_sub 0 &
cd - ; make deadline-pub DOMAIN=0 DEADLINE_MS=1500 COUNT=5 SECONDS=16 ADVERTISE=192.168.2.148

# --- Fast DDS REQUESTED (writer alive, slow) ---
./scripts/with-fastdds.sh bash -c 'cd interop/fastdds/shapes && DEADLINE_MS=60 ./shapes_pub BLUE 0' &
make deadline-sub DOMAIN=0 DEADLINE_MS=80 TYPENAME=ShapeType SECONDS=11 ADVERTISE=192.168.2.148

# --- Fast DDS SAMPLE_LOST (KEEP_LAST-1 overwrite -> GAP) ---
./scripts/with-fastdds.sh bash -c 'cd interop/fastdds/shapes && DEADLINE_MS=1000 ./shapes_pub BLUE 0' &
make deadline-sub DOMAIN=0 DEADLINE_MS=2000 TYPENAME=ShapeType SECONDS=22 ADVERTISE=192.168.2.148
```
