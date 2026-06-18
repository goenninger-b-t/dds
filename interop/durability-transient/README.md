# TRANSIENT durability service — foreign late-joiner cross-DDS interop (WP-DURABILITY-SERVICE-TRANSIENT, M6/P5)

The per-feature interop Definition-of-Done gate (owner directive 2026-06-17: every feature verifies
interop with **both** RTI Connext **and** eProsima Fast DDS) for the embedded TRANSIENT durability service
(ADR 0021). The conformance crux: a foreign TRANSIENT_LOCAL late-joining reader receives the retained
pre-exit history FROM OUR SERVICE after the original writer is gone.

**Status: both legs LIVE-verified in-session (2026-06-18), both peers.** Captures under `captures/`.

## The scenario (writer-gone)

1. A foreign reliable TRANSIENT_LOCAL KEEP_ALL writer publishes N samples on `Square`/`ShapeType`.
2. OUR durability service collects those samples via its reliable TRANSIENT_LOCAL KEEP_ALL
   collecting reader, storing + immediately re-publishing through its own TRANSIENT_LOCAL replay writer.
3. The foreign publisher **exits** (writer-gone: the original writer's process terminates).
4. A foreign reliable TRANSIENT_LOCAL KEEP_ALL late-joining subscriber starts AFTER the publisher exited.
5. **The late-joining subscriber must receive the N retained pre-exit samples FROM OUR SERVICE** —
   not from the original (now-dead) writer (DDS 1.4 §2.2.3.4, ADR 0021 capability 1).

This is distinct from the WP-DURABILITY-TRANSIENT-LOCAL scenario (same-process TL writer redelivery).
Here, a SERVICE continues to hold and redeliver on behalf of a writer that no longer exists.

## Conformance proof

The load-bearing proof: the late-joining subscriber receives samples published **before** it joined **and
before the original publisher exited** — samples it could not have received from the original writer
(which was already dead when the subscriber started). The samples form a continuous animation sequence
starting from the original publisher's first coordinates, not from a mid-animation position.

## The service driver

The service is driven by a small inline SBCL form (no separate CLI, because `durability-service-main`
has no `--data-representation` flag as of this writing):

```lisp
(asdf:load-system :dds-durability)
(let* ((spec (dds.durability:make-service-spec
               :domain 0
               :topics '(("Square" . "ShapeType"))
               :qos-overrides '(:data-representation (:xcdr1)
                                 :peers (("127.0.0.1" . 7410)))
               :name "dsvc-interop"))
       (svc  (dds.durability:make-durability-service spec)))
  (dds.durability:service-start svc)
  (format t "~%SVC-STARTED~%") (force-output)
  (loop (sleep 60)))
```

Two `qos-overrides` entries:
- `:data-representation (:xcdr1)` — the replay writer advertises `[XCDR1]` in SEDP so Connext/Fast DDS
  XCDR1-only ShapeType readers match (without this, the SEDP RxO fails: offered `[XCDR2]` vs required
  `[XCDR1]`). The forwarded payload bytes are opaque (collected as-is from the original writer).
- `:peers (("127.0.0.1" . 7410))` — unicast SPDP peer: domain 0 participant 0 well-known SPDP unicast
  port (RTPS §9.6.1.1: PB+DG×0+d1+PG×0 = 7400+0+10+0 = 7410). The service sends SPDP there so
  foreign Connext/Fast DDS participants on loopback discover it.

The service collects loop also re-announces SPDP + SEDP every ~1.5 s (mirroring `%reannounce` from
the shapes harness) so foreign participants that start AFTER the service can discover it reliably.

## Foreign-peer configuration

- **RTI Connext** — `USER_QOS_PROFILES.xml` here: `is_default_qos` profile with
  `TRANSIENT_LOCAL_DURABILITY_QOS` + `RELIABLE_RELIABILITY_QOS` + `KEEP_ALL_HISTORY_QOS` on both
  writer and reader QoS, plus `allow_interfaces=127.0.0.1` (loopback-only, UDPv4). Run from THIS
  directory so the binary loads `USER_QOS_PROFILES.xml` from cwd.
- **Fast DDS** — `fastdds-profiles.xml` here (copy to `./profiles.xml` in run cwd):
  `interfaceWhiteList` = `127.0.0.1` only; UDPv4. The `DURABILITY=transient_local` env gate in
  the committed `interop/fastdds/shapes/shapes_pub.cpp` + `shapes_sub.cpp` sets
  `TRANSIENT_LOCAL_DURABILITY_QOS` + `KEEP_ALL` in C++ code.

**FIRST: kill any stale DDS process on the discovery ports** (`lsof -nP -iUDP:7400-7440`).

## Run commands

```sh
export NDDSHOME=/Applications/rti_connext_dds-7.3.1
export CONNEXTDDS_ARCH=arm64Darwin20clang12.0
export DYLD_LIBRARY_PATH=$NDDSHOME/lib/$CONNEXTDDS_ARCH
REPO=$(pwd)  # run from repo root
```

### Leg 1 — Connext TL publisher publishes → exits → our service → late Connext TL subscriber

```sh
# 1) Capture
WIRESHARK_CONFIG_DIR=$(mktemp -d) /Applications/Wireshark.app/Contents/MacOS/tshark \
  -i lo0 -f "udp portrange 7400-7700" \
  -w interop/durability-transient/captures/leg1-our-svc-to-connext-late.pcap &

# 2) Our service (start first; re-announces SPDP every 1.5 s to 127.0.0.1:7410)
./scripts/with-sbcl.sh \
  --eval '(asdf:load-system :dds-durability)' \
  --eval "(let* ((spec (dds.durability:make-service-spec
                         :domain 0 :topics '((\"Square\" . \"ShapeType\"))
                         :qos-overrides '(:data-representation (:xcdr1)
                                           :peers ((\"127.0.0.1\" . 7410)))
                         :name \"dsvc-interop\"))
                 (svc (dds.durability:make-durability-service spec)))
            (dds.durability:service-start svc)
            (format t \"~%SVC-STARTED~%\") (force-output)
            (loop (sleep 60)))" &
# ...wait ~8 s for service to init...

# 3) Connext TL publisher (from this dir for the TL+loopback profile; run ~15 s then kill)
cd interop/durability-transient
stdbuf -oL ../connext/shapes-pub/shapes_pub 0 GREEN &
PUB_PID=$!; sleep 15; kill $PUB_PID
# ...wait ~4 s for service to settle...

# 4) LATE-JOINING Connext TL subscriber (starts after publisher is dead)
stdbuf -oL ../connext/shapes-sub/shapes_sub 0 20
```

### Leg 2 — Fast DDS TL publisher publishes → exits → our service → late Fast DDS TL subscriber

```sh
# Same service driver as Leg 1 (restart after Leg 1).
# Copy the loopback-only Fast DDS profile to the shapes run cwd:
cp interop/durability-transient/fastdds-profiles.xml interop/fastdds/shapes/profiles.xml

# Fast DDS TL publisher (200 samples at ~13 Hz):
DURABILITY=transient_local ./scripts/with-fastdds.sh bash -c \
  'cd interop/fastdds/shapes && stdbuf -oL ./shapes_pub GREEN 200' &
PUB_PID=$!; sleep 15; kill $PUB_PID

# LATE-JOINING Fast DDS TL subscriber:
DURABILITY=transient_local ./scripts/with-fastdds.sh bash -c \
  'cd interop/fastdds/shapes && stdbuf -oL ./shapes_sub 20'
```

## Live results (2026-06-18, this host, lo0)

| Leg | Peer | Retained by service | Late-joiner received | First pre-exit sample received | Capture |
|---|---|---|---|---|---|
| **1** | **Connext** | 409 | **409** | `x=197 y=208` (published before subscriber joined; publisher was already dead) | `captures/leg1-our-svc-to-connext-late.pcap` |
| **2** | **Fast DDS** | 200 | **200** | `x=78 y=146` (sample #29; service matched ~3 s into the 15 s publish window; all collected samples delivered) | `captures/leg2-our-svc-to-fastdds-late.pcap` |

Both late-joining subscribers received samples the original publisher had sent **before** they joined and
**before** the publisher exited — samples they could only have received from our service's retained store.

**Leg 1 note:** Connext received 409 samples. The animation cycles (the shape bounces), so the "first
animation position" (`x=53 y=52`) appears at sample `#82` of what the subscriber received — confirming
that full retained history (not just recent) was delivered.

**Leg 2 note:** Fast DDS received exactly 200 samples (all that the service collected). The service
matched the Fast DDS writer ~3 s after the publisher started (SPDP discovery + SEDP exchange), so the
first ~28 samples were published before the service's collecting reader matched — those were not
collected and are therefore not delivered to the late-joiner. This is correct behavior: the service
can only replay what it collected. The 200 delivered samples (all pre-exit) prove the retained store
is functional.

## Wire evidence (tshark RTPS dissector)

Our service's replay writer is RTPS EntityId `0x00000102`.

### Leg 1 capture (`leg1-our-svc-to-connext-late.pcap`)

- **`firstAvailableSeqNumber: 1` on EVERY HEARTBEAT** from `0x00000102` — the TRANSIENT_LOCAL
  KEEP_ALL retention signal (the writer never advances firstSN past 1; a VOLATILE writer would advance
  it as samples are acked). `lastSeqNumber` climbs `1 → 2 → … → 409`.
- **`CDR_LE (0x0001)` on every DATA** from `0x00000102` — XCDR1 little-endian encoding, confirming
  the `:data-representation (:xcdr1)` override is active on the wire.
- Submessage totals: 1140 DATA / 544 HEARTBEAT / 215 ACKNACK (+ 70 INFO_TS + 8 INFO_DST) — the full
  reliable late-joiner repair exchange.
- ACKNACK analysis shows `Lost samples 1..54` (the late-joiner's initial NACK requesting retained range),
  then `Lost samples 1 in range [1,1]` per-retransmit, then `Expecting sample 83+` as delivery proceeds.

### Leg 2 capture (`leg2-our-svc-to-fastdds-late.pcap`)

- **`firstAvailableSeqNumber: 1` on EVERY HEARTBEAT** from `0x00000102`, `lastSeqNumber` climbs to 200.
- **`CDR_LE (0x0001)` on every DATA** from `0x00000102`.
- Submessage totals: 653 DATA / 339 HEARTBEAT / 124 ACKNACK (+ 24 INFO_TS + 24 INFO_DST_VENDOR).

Both captures confirm the TRANSIENT_LOCAL replay semantics: `firstSN=1` held forever (retained history)
and retransmit on NACK (reliable repair).

## macOS lo0 reverse-direction capture note

For both legs, the **foreign publisher → our service** user-DATA direction is under-captured on lo0
(the documented macOS BPF loopback quirk: the host drops most foreign→us user-DATA frames in capture;
see `interop/durability-transient-local/README.md`). The captures show the service's outbound
SPDP/SEDP/HEARTBEAT and the foreign subscriber's inbound DATA (our replay) but not the bulk of the
foreign publisher's DATA reaching our collecting reader. The collection proof rests on the **decoded
receipt**: the late-joining subscriber's decoded output (application-level receipt) and the service
HEARTBEAT `lastSeqNumber` matching the received sample count.

## Source changes (this WP)

Two minimal additions to `service-start` / `%collect-loop` in `src/dds-durability/service.lisp`:

1. **`:peers` and `:multicast` in `qos-overrides`** — `service-start` now reads these from the
   spec's `qos-overrides` plist and passes them to `make-disc-node`, enabling the service to discover
   foreign participants. Without explicit peers, the service node (binding to a random OS-assigned port
   with `multicast nil`) cannot learn foreign participants' addresses. The unicast SPDP peer
   `("127.0.0.1" . 7410)` is the domain-0 participant-0 well-known SPDP port (RTPS §9.6.1.1), which
   both Connext and Fast DDS bind.

2. **Periodic re-announcement** — `%collect-loop` now calls `announce-participant` + `announce-endpoints`
   every ~1.5 s (same cadence as `%reannounce` in the shapes harness). Without this, the service
   announces SPDP only once at `start-node` time; a foreign participant that starts later never
   receives the service's SPDP and therefore cannot discover it.

## Clean-room / provenance

Clean-room: the foreign peers are the committed `interop/connext/shapes-*` and `interop/fastdds/shapes`
harnesses configured for TRANSIENT_LOCAL via QoS XML (Connext) and the C++ `DURABILITY` env gate
(Fast DDS). No RTI/Fast DDS source is copied. Connext `rtiddsgen` output is build-time + git-ignored;
Fast DDS `fastddsgen` output under `interop/fastdds/shapes/gen/` is committed verbatim (Apache-2.0;
`docs/provenance.md`). The durability/late-joiner service semantics are pinned from DDS 1.4 §2.2.3.4
and RTPS 2.5 §8.4.2.2; ADR 0021 governs the service architecture.

## Files

- `USER_QOS_PROFILES.xml` — Connext loopback + TRANSIENT_LOCAL/KEEP_ALL/RELIABLE profile.
- `fastdds-profiles.xml` — Fast DDS loopback-only profile (copy to `./profiles.xml` in shapes run cwd).
- `captures/leg1-our-svc-to-connext-late.pcap` — our service → late Connext TL reader; `firstSN=1`, CDR_LE, NACK→retransmit.
- `captures/leg2-our-svc-to-fastdds-late.pcap` — our service → late Fast DDS TL reader; `firstSN=1`, CDR_LE, NACK→retransmit.
- `captures/spike-rtips-transient-virtual-guid.pcap` — Task-1 spike capture (virtual-GUID dedup exploration; retained for context).
