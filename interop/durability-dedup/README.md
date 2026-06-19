# WP-DURABILITY-DEDUP — Interop: PID_ORIGINAL_WRITER_INFO on relayed DATA

## Scenario

A durability service collects samples from a TRANSIENT_LOCAL publisher and replays
them to late-joining subscribers.  The relay writer attaches
`PID_ORIGINAL_WRITER_INFO` (PID `0x0061`, RTPS 2.5 §8.3.5.4) as inline-QoS on
every relayed DATA submessage, carrying the **original** (not relay) writer's GUID
and sequence number.  Receivers can use this to de-duplicate against samples
already received directly.

Two legs were run:
- **Leg A**: Connext 7.3.1 publisher → our service → Connext late-joiner
- **Leg B**: Fast DDS 3.6.1 publisher → our service → Fast DDS late-joiner

---

## Wire Constants

| Symbol | PID | Size | RTPS 2.5 clause |
|---|---|---|---|
| PID_ORIGINAL_WRITER_INFO | 0x0061 | 28 bytes (pid+len+24-byte body) | §8.3.5.4 |
| PID_SENTINEL | 0x0001 | 4 bytes | §9.4.5.4 |

Inline-QoS block: 32 octets total (PID_ORIGINAL_WRITER_INFO=28 + PID_SENTINEL=4).
Q-bit (bit 1) of DATA flags is set when inline-QoS is present (RTPS 2.5 §9.4.5.4).

---

## Leg A — Connext 7.3.1

**Setup:**
- Topic: `Square`, type `ShapeType`, TL/KEEP_ALL/RELIABLE on domain 0
- Our relay writer entity: prefix `44:53:5e:ba:69:a1:c5:8b:df:ed:00:00`, entityId `0x00000102`
- Connext late-joiner: received **190 samples** from our relay

**Wire evidence (`leg1-dedup-connext.pcap`):**
- 530 of ~783 total submessages carry `PID_ORIGINAL_WRITER_INFO` on relayed user-data DATA frames.
  The remaining frames are discovery/SEDP DATA and non-DATA submessages (HEARTBEAT, ACKNACK, INFO_TS);
  every relayed user-data DATA submessage carries `PID_ORIGINAL_WRITER_INFO`.
- Original Connext writer GUID: `01:01:93:bb:4d:4e:9f:a4:ac:3c:26:96:80:00:00:02`
- Example: relay SN 1 → original SN 76, relay SN 2 → original SN 77
  (service matched at ~sample 76 of the live Connext publisher stream)

**QoS profiles:** `USER_QOS_PROFILES.xml` (loopback + TL/KEEP_ALL/RELIABLE)

---

## Leg B — Fast DDS 3.6.1

**Setup:**
- Topic: `Square`, type `ShapeType`, TL/KEEP_ALL/RELIABLE on domain 0
- Fast DDS publisher: 100 samples; Fast DDS late-joiner: received **465 samples**
  (service held both the Connext history [265 samples] and the Fast DDS history [100])

**Wire evidence (`leg2-dedup-fastdds.pcap`):**
- 665 of 1274 total submessages carry `PID_ORIGINAL_WRITER_INFO` on relayed user-data DATA frames.
  The remaining frames are discovery/SEDP DATA and non-DATA submessages (HEARTBEAT, ACKNACK, INFO_TS);
  every relayed user-data DATA submessage carries `PID_ORIGINAL_WRITER_INFO`.
- Two distinct original-writer GUIDs in the relay stream:
  - `01:0f:5e:4b:25:91:fc:8c:00:00:00:00:00:00:01:02` — Fast DDS writer, SN 1..100
  - `01:01:93:bb:4d:4e:9f:a4:ac:3c:26:96:80:00:00:02` — Connext writer, SN 1..265
- Each OWI block carries the **original** writer's GUID+SN byte-exact; the relay
  writer's own GUID/SN are in the normal DATA header fields

**QoS profiles:** `fastdds-profiles.xml` (loopback-only)

---

## macOS lo0 caveat

macOS uses DLT_NULL (loopback) framing, not DLT_EN10MB.  tshark/Wireshark may
not auto-identify RTPS inside UDP/loopback unless the RTPS dissector preference
"Enable heuristic" is on.  The captures were analyzed with a Python script using
`tshark -T json -x` to extract raw bytes and manual RTPS submessage parsing.

---

## Commands used

```sh
# Start tshark capture (leg A — swap interface/file for leg B)
tshark -i lo0 -f "udp" -w interop/durability-dedup/captures/leg1-dedup-connext.pcap &

# Run our durability service (domain 0, TL/KEEP_ALL/RELIABLE)
sbcl --non-interactive \
  --eval '(asdf:load-system :dds-durability)' \
  --eval '(dds.durability:durability-service-main)' &

# Run Connext publisher (100 samples, ShapeType GREEN Square)
$CONNEXTDDS_DIR/bin/rtiddsspy -domainId 0 &   # or shapes_demo

# After publisher exits, run late-joining subscriber
NDDSHOME=$CONNEXTDDS_DIR ./interop/connext/shapes_sub 190

# Fast DDS leg
DURABILITY=transient_local ./scripts/with-fastdds.sh bash -c \
  'cd interop/fastdds/shapes && ./shapes_pub 100'
DURABILITY=transient_local ./scripts/with-fastdds.sh bash -c \
  'cd interop/fastdds/shapes && ./shapes_sub 20'
```

---

## Leg C — RTI Persistence Service + our service coexistence (CLOSED_WITH_FINDINGS)

See `coexistence/README.md` for the full procedure, evidence, and honest caveats.

**Prior run result (pre-Task-8):** Both relay writers emit `PID_ORIGINAL_WRITER_INFO (0x0061)` with
the original-writer GUID + SN on their relayed DATA submessages (664 OWI-carrying frames out of
2917 total in `coexistence/coexistence-run.pcap`). Connext late-joiner received ~3558 samples
(additive, not deduplicated) — root cause: Connext gates receiver-side dedup on
`PID_SERVICE_KIND (0x8003) = PERSISTENCE_SERVICE_QOS` in the relay writer's SEDP announcement,
which our relay was not emitting.

**Task-8 fix (2026-06-19):** `PID_SERVICE_KIND = PERSISTENCE_SERVICE_QOS` now emitted in our relay
writer's SEDP ParameterList (`src/dds-durability/service.lisp`). Unit test `run-vendor-sedp-pid-test`
confirms byte-exact emission (275 green SBCL+Clasp).

**Post-Task-8 live re-run finding (2026-06-19):** RTI Persistence Service v7.3.1 does NOT relay
TRANSIENT_LOCAL data. RTI PS only handles TRANSIENT (and PERSISTENT) durability. For a
TRANSIENT_LOCAL topic, RTI PS is inert as a relay — it contributes zero samples. Our service
collected and replayed correctly. The prior ~3558 additive count was from our service's accumulated
history across multiple test runs (different publisher GUIDs), not from RTI PS. A true dual-relay
coexistence run with RTI PS requires a TRANSIENT topic (Phase 3). Capture: `coexistence-run-task8.pcap`.

The principal proof of no-double-delivery is the code proof: `run-durability-no-double-delivery-test`
(275 green SBCL+Clasp) + ADR 0024 sec Decision.

---

## Capture file index

| File | Leg | Frames | DATA w/ OWI |
|---|---|---|---|
| `captures/leg1-dedup-connext.pcap` | Leg A: Connext 7.3.1 | ~783 | 530 |
| `captures/leg2-dedup-fastdds.pcap` | Leg B: Fast DDS 3.6.1 | ~1274 | 665 |
| `coexistence/coexistence-run.pcap` | Leg C: RTI PS + our service, pre-Task-8 | 2917 | 664 |
| `coexistence/coexistence-run-task8.pcap` | Leg C: RTI PS + our service, post-Task-8 | — | — |
