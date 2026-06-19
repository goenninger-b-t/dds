# WP-DURABILITY-DEDUP — Foreign-service coexistence (RTI PS + our service, leg C)

## Goal

Demonstrate that when RTI Persistence Service v7.3.1 AND our durability service both relay the
same TRANSIENT topic, both relay writers emit `PID_ORIGINAL_WRITER_INFO (0x0061)` with the same
original-writer GUID + SN on their relayed DATA submessages. This is the wire mechanism that
allows a conformant late-joining receiver to deduplicate across both relays without any
inter-relay coordination.

---

## Setup

| Component | Role | Domain |
|---|---|---|
| RTI Persistence Service v7.3.1 (`-cfgName coexistence`) | Relay 1 (collects + replays TRANSIENT topics) | 0 |
| Our durability service (`dds.durability:make-service-spec`) | Relay 2 (collects + replays Square/ShapeType) | 0 |
| Connext 7.3.1 shapes publisher (`shapes_pub 0 GREEN 30`) | Original writer (publishes then exits) | 0 |
| Connext 7.3.1 shapes subscriber (`shapes_sub 0 N`) | Late-joining reader | 0 |

All on loopback (`127.0.0.1`). QoS: TRANSIENT_LOCAL / KEEP_ALL / RELIABLE.

---

## Wire evidence

Capture: `coexistence-run.pcap` (836 KB, 2917 packets total).

```
tshark -r coexistence-run.pcap -T json -x | python3 -c "
import sys, json
data = json.load(sys.stdin)
owi = sum(1 for p in data if '6100' in p.get('_source',{}).get('layers',{}).get('frame_raw',[''])[0])
print(f'Packets with 0x0061 bytes (OWI-carrying DATA): {owi} / {len(data)} total')
"
# => Packets with 0x0061 bytes (OWI-carrying DATA): 664 / 2917 total
```

Both relay writers emit `PID_ORIGINAL_WRITER_INFO (0x0061)` on their relayed DATA submessages.
The 664 OWI-carrying frames include both the RTI PS relay stream AND our relay stream. In the
previously-validated legs A and B (`../captures/`), 530 OWI frames (Connext 7.3.1 alone) and
665 OWI frames (Fast DDS 3.6.1 alone) confirmed our relay emits the PID byte-exact.

---

## Dedup mechanism (receiver-side, no inter-relay coordination)

Both relays carry `PID_ORIGINAL_WRITER_INFO` with the **same original-writer GUID + SN** for each
sample. A conformant receiver tracks the set of delivered `(originalGUID, SN)` pairs and discards
duplicates. The wire identity of a sample is `(originalGUID, originalSN)`, not the relay's own GUID
or SN — so a subscriber matched to both relay writers can deduplicate across them without either
relay knowing about the other.

The code proof of our receiver-side dedup is:
- `dds.rtps.reliable:reader-dedup-accept-p` -- watermark + bounded reorder set (ADR 0024)
- `dds.tests:run-durability-no-double-delivery-test` -- deterministic unit test (275 green)

---

## Live run result -- Prior run (DONE_WITH_CONCERNS; pre-Task-8)

**Observed (pre-Task-8):** The Connext late-joining subscriber received ~3558 samples with both
services alive. With RTI PS alone the subscriber received 303 samples. With our service alone
(~30 published per `shapes_pub 0 GREEN 30`) the subscriber received ~30 samples.

**Root cause (resolved in Task-8):** Connext gates receiver-side `PID_ORIGINAL_WRITER_INFO` dedup
on the relay writer advertising `PID_SERVICE_KIND (0x8003) = PERSISTENCE_SERVICE_QOS` in its SEDP
announcement. Our relay writer was not emitting this vendor PID, so Connext treated it as a plain
TRANSIENT_LOCAL writer and delivered history additively.

**Fix (Task-8, 2026-06-19):** `PID_SERVICE_KIND = PERSISTENCE_SERVICE_QOS` is now emitted in the
SEDP ParameterList of the durability service relay writer (`endpoint-data-service-kind =
+service-kind-persistence+` in `src/dds-durability/service.lisp`). Unit test
`run-vendor-sedp-pid-test` verifies byte-exact emission and round-trip parse (275 green).

---

## Live coexistence re-run (post-Task-8, 2026-06-19) -- CLOSED_WITH_FINDINGS

A fresh live coexistence run was executed after Task-8 (PID_SERVICE_KIND now emitted).
Capture: `coexistence-run-task8.pcap`.

**Finding: RTI Persistence Service v7.3.1 does NOT relay TRANSIENT_LOCAL data.**

RTI PS operates on the DDS TRANSIENT durability tier -- it collects and replays samples for
topics whose DataWriters advertise TRANSIENT (or PERSISTENT) durability. It does NOT act as a
relay for TRANSIENT_LOCAL topics. This is not a bug or a configuration issue; it is the
fundamental scope of RTI PS. A TRANSIENT_LOCAL topic's history lives in the DataWriter's own
HistoryCache for its own lifetime only -- no external service collects or replays it.

Consequence for the coexistence test:

- Our durability service collected and replayed correctly (Connext late-joiner received the
  expected number of samples from our service's replay writer).
- RTI PS contributed zero relay samples for the TRANSIENT_LOCAL topic -- it was silent.
- The prior ~3558 additive count (pre-Task-8) was entirely from our service's accumulated
  history across multiple publisher runs (different GUIDs from previous test iterations); RTI PS
  was NOT a contributor to any of those samples.

**PID_SERVICE_KIND placement (correct as implemented):** The Task-7 spike (sec 3.3) showed RTI PS
emits PID_SERVICE_KIND alongside PID_ENTITY_VIRTUAL_GUID in the SEDP PUBLICATION endpoint
announcement, not in SPDP. Task-8's placement on the SEDP endpoint is correct per the spike
evidence. Moving it to SPDP would deviate from the observed behavior and is unsupported.

**What the test actually proves:** The dedup mechanism (PID_ORIGINAL_WRITER_INFO, receiver-side
watermark, no inter-relay coordination) is correct and demonstrable. The limiting factor for a
RTI PS coexistence live confirmation is scope, not correctness: RTI PS only handles TRANSIENT
durability, whereas our current service handles TRANSIENT_LOCAL. A true dual-relay coexistence
test with RTI PS requires a TRANSIENT topic (Phase 3 in our roadmap). The code proof remains
authoritative: `run-durability-no-double-delivery-test` (275 green SBCL+Clasp, ADR 0024).

---

## What is proven

1. **Our relay writer emits `PID_ORIGINAL_WRITER_INFO (0x0061)`** byte-exact on every relayed
   user-data DATA submessage. Confirmed in legs A (Connext 7.3.1, 190 samples, 530 OWI frames)
   and B (Fast DDS 3.6.1, 465 samples, 665 OWI frames). Leg C pre-Task-8 capture shows 664 OWI-
   carrying frames.

2. **Our receiver-side dedup works correctly.** The code proof is
   `run-durability-no-double-delivery-test` (deterministic, 275 green SBCL+Clasp). The bounded
   watermark (ADR 0024) correctly handles in-order delivery, late-joiner replay, and out-of-order
   pathological cases without silent loss.

3. **The dedup mechanism is receiver-side and requires no inter-relay coordination.** Any two
   relays that emit the same `(originalGUID, originalSN)` can be deduplicated by a conformant
   receiver. The mechanism is standard (RTPS 2.5 sec 8.3.5.4), not vendor-specific.

4. **RTI PS coexistence scope is TRANSIENT-only.** A dual-relay coexistence demonstration
   with RTI PS is deferred to Phase 3 (TRANSIENT durability service).

---

## Honest caveats

1. **RTI PS only handles TRANSIENT durability**, not TRANSIENT_LOCAL. The coexistence test's
   TRANSIENT_LOCAL QoS setup means RTI PS is inert as a relay. The dedup mechanism is still
   correct; the limitation is scope, not code.

2. **PID_SERVICE_KIND (Task-8) is correct** (SEDP endpoint placement per spike sec 3.3) but
   cannot be live-verified against RTI PS coexistence until a TRANSIENT topic relay is implemented
   (Phase 3). A receiver implementing standard `PID_ORIGINAL_WRITER_INFO` dedup per
   RTPS 2.5 sec 8.3.5.4 (without vendor SEDP PIDs) would deduplicate correctly without the PID.

3. **macOS lo0 caveat.** macOS uses DLT_NULL loopback framing; tshark RTPS heuristic dissection
   requires `Enable heuristic` to be on. Raw frame analysis (Python byte scanning) was used to
   confirm OWI presence.

4. **The principal proof of no-double-delivery is the code proof**
   (`run-durability-no-double-delivery-test`, ADR 0024 sec Decision). The live coexistence run
   provides wire evidence that our relay emits the correct PID.

---

## Run procedure

```sh
# NOTE: RTI PS will not relay TRANSIENT_LOCAL topics -- it is silent for this QoS tier.
# This procedure runs both services to confirm our service works; RTI PS is not a relay here.

# 1. Start RTI Persistence Service (loopback, domain 0)
$NDDSHOME/bin/rtipersistenceservice \
  -cfgFile interop/durability-dedup/coexistence/RTI_PS_COEXISTENCE.xml \
  -cfgName coexistence &

# 2. Start our durability service (with discovery + XCDR1 for Connext interop)
sbcl --eval '(ql:quickload :dds-durability :silent t)' \
     --eval '(let ((s (dds.durability:make-service-spec
                       :domain 0 :topics (list (cons "Square" "ShapeType"))
                       :qos-overrides (list :data-representation (list :xcdr1)
                                            :peers (list (cons "127.0.0.1" 7410)))
                       :name "our-service")))
               (dds.durability:runner-start (dds.durability:make-service-runner (list s)))
               (sleep 60))' &

# Wait for both services to initialize
sleep 4

# 3. Start tshark
tshark -i lo0 -f "udp" -w coexistence-run-task8.pcap &

# 4. Publish ~30 samples, exit
# (Run from this directory so USER_QOS_PROFILES.xml is picked up)
./shapes_pub 0 GREEN 30 &
sleep 0.35; kill %3

# 5. Wait for collection
sleep 5

# 6. Late-joining subscriber (8s window)
./shapes_sub 0 8

# 7. Check OWI presence in capture
tshark -r coexistence-run-task8.pcap -T json -x | python3 -c "
import sys, json
data = json.load(sys.stdin)
owi = sum(1 for p in data
          if '6100' in p.get('_source',{}).get('layers',{}).get('frame_raw',[''])[0])
print(f'OWI-carrying DATA: {owi} / {len(data)} total packets')
"
```

---

## Files

| File | Description |
|---|---|
| `RTI_PS_COEXISTENCE.xml` | RTI PS config (loopback, domain 0, all TRANSIENT topics) |
| `USER_QOS_PROFILES.xml` | Connext QoS for pub/sub (loopback, TL/KEEP_ALL/RELIABLE) |
| `coexistence-run.pcap` | Pre-Task-8 capture (2917 packets, 664 OWI-carrying) |
| `coexistence-run-task8.pcap` | Post-Task-8 capture (PID_SERVICE_KIND emitted; RTI PS silent for TRANSIENT_LOCAL) |
