# Autonomous-discovery (zero-spin) live interop — WP-DCPS-API-COMPLETION S7

Live cross-vendor validation that a participant in **autonomous mode** (ADR 0056) discovers, matches
and exchanges data with **RTI Connext 7.3.1** and **eProsima Fast DDS** while the application calls
**no `spin` at all** — a background announcer thread drives every SPDP/SEDP announce and every
lease/liveliness/autopurge sweep, on the `DISCOVERY_CONFIG` announce-period cadence.

Treats each vendor as the interop oracle (public API + wire only; **no vendor source/headers/generated
code copied** — clean-room, NFR-IP). Not built/run by CI; needs a local Connext + Fast DDS install.

Our side is the DCPS runners `dds.shapes:run-deadline-{publisher,subscriber}` in autonomous mode —
`make autodisc-pub` / `make autodisc-sub`. They pass `:autonomous t` and set `DEADLINE_MS=0`
(DURATION_INFINITE → DEADLINE imposes no RxO constraint, so a stock vendor shapes peer matches with no
QoS tweak). The loop calls **no** `spin`; the announcer thread is the only announce driver.

## Two things a stock vendor peer needs from us (neither is an S7 concern; both bit here)

1. **`REP=xcdr1` for the outbound legs.** A stock Connext/Fast DDS shapes `DataReader` advertises
   **XCDR1 only**, and DATA_REPRESENTATION *is* an RxO policy (XTypes 1.3 §7.6.3.1.1). Our writer
   defaults to offering XCDR2, so it correctly does **not** match — `OFFERED_INCOMPATIBLE_QOS` fires
   with `last_policy_id = 23`. Offer XCDR1 and it matches. (Same knob `run-publisher` has always had.)
2. **`PEERS=127.0.0.1:7410` for Fast DDS.** The Fast DDS interop profile (`interop/fastdds/shapes/
   profiles.xml`) whitelists **127.0.0.1 only**, so it never sees multicast SPDP sent on the LAN
   interface. Its builtin metatraffic unicast port is `127.0.0.1:7410` — announce there directly
   (FR-DISC-4 unicast peers, layered on top of multicast). Connext, by contrast, is pinned to the LAN
   interface (`192.168.2.148`), so its legs want `ADVERTISE=192.168.2.148`.

## Recipes

```sh
# --- Connext (pinned to the LAN iface by interop/connext/shapes-*/USER_QOS_PROFILES.xml) ---
# our zero-spin reader  <-  Connext writer
(cd interop/connext/shapes-pub && NDDSHOME=/Applications/rti_connext_dds-7.3.1 \
   DYLD_LIBRARY_PATH=$PWD:$NDDSHOME/lib/arm64Darwin20clang12.0 ./shapes_pub) &
make autodisc-sub SECONDS=14 ADVERTISE=192.168.2.148 ANNOUNCE_MS=500

# our zero-spin writer  ->  Connext reader   (shapes_sub takes: <domain> <seconds>; it must exit
#                                             normally to flush its stdout — do not SIGINT it)
make autodisc-pub SECONDS=45 COUNT=400 REP=xcdr1 ADVERTISE=192.168.2.148 ANNOUNCE_MS=500 &
(cd interop/connext/shapes-sub && NDDSHOME=/Applications/rti_connext_dds-7.3.1 \
   DYLD_LIBRARY_PATH=$PWD:$NDDSHOME/lib/arm64Darwin20clang12.0 ./shapes_sub 0 15)

# --- Fast DDS (loopback-only profile -> unicast SPDP peer) ---
# our zero-spin reader  <-  Fast DDS writer
./scripts/with-fastdds.sh bash -c 'cd interop/fastdds/shapes && ./shapes_pub' &
make autodisc-sub SECONDS=14 PEERS=127.0.0.1:7410 ANNOUNCE_MS=500

# our zero-spin writer  ->  Fast DDS reader
make autodisc-pub SECONDS=40 COUNT=400 PEERS=127.0.0.1:7410 REP=xcdr1 ANNOUNCE_MS=500 &
make fastdds-sub SECONDS=15
```

## What this confirms — live PASS (2026-07-11)

| Leg | Result |
|---|---|
| **Connext writer → our autonomous reader** | ✅ `MATCHED 0→1`, **252 samples**, `SAMPLE_LOST 0` — no spin anywhere |
| **our autonomous writer → Connext reader** | ✅ `MATCHED 0→1`, Connext received **27 samples** |
| **Fast DDS writer → our autonomous reader** | ✅ `MATCHED 0→1`, **131 samples** (source_timestamp parsed from their INFO_TS) |
| **our autonomous writer → Fast DDS reader** | ✅ `MATCHED 0→1`, Fast DDS received **29 samples** |

**Coverage:** both directions against **both** vendors, entirely announcer-driven. S7 adds **no wire
surface** — the SPDP/SEDP announce *content* is byte-unchanged from the spin path; only the cadence
*driver* moved from the app thread to a background thread. What these runs prove is that a real foreign
stack discovers, matches, ages and exchanges data with a participant whose announces come off that
thread, at a configured cadence (500 ms here) and with the configured announced leaseDuration.

## What these legs found (and why the outbound legs are new)

The two **outbound** legs (our writer → a vendor reader) had never passed — `matched=0`, zero samples,
against **both** vendors — because the FR-TYPE-4 type gate **false-rejected every stock vendor
`DataReader`**: it judged a peer's type by bounds that `rtiddsgen` invents (an unbounded `@key string`
announced as 255-bounded), under an equivalence test and the key sub-bound rule. Not an S7 regression —
the spin-driven path reproduced it identically. Root-caused and fixed in-slice: **ADR 0057**, regression
test `dcps-type-gate-legacy-reader` (pinned to the live captured Connext `PID_TYPE_OBJECT_LB`).

Every previous live leg exercised our *reader*, which is why no earlier slice caught it.
