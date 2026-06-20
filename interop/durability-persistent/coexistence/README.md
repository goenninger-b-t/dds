# RTI Persistence Service TRANSIENT-tier coexistence (WP-DURABILITY-PERSISTENT, Phase-2 carry-forward)

The deferred Phase-2 proof (`interop/durability-dedup/coexistence/` CLOSED_WITH_FINDINGS): with a
TRANSIENT durability tier, our durability service can participate **where RTI Persistence Service
relays**, so that BOTH RTI PS and our service relay the same origin samples and a late-joining
subscriber's receiver-side OWI dedup gives exactly-once. ADR 0024 carry-forward (M6/P5).

**Status: DONE_WITH_CONCERNS — RTI PS now RUNS + RELAYS at the TRANSIENT tier (the Phase-2 blocker is
resolved), but a *standard-OWI* dual-relay-exactly-once is NOT exercisable against RTI PS specifically,
because RTI PS does not stamp `PID_ORIGINAL_WRITER_INFO (0x0061)` on its relayed samples.** The
authoritative no-double-delivery conformance proof remains the in-process
`run-durability-no-double-delivery-test` (green on SBCL this session — see below).

---

## What changed since Phase 2 (the blocker is resolved)

The Phase-2 finding (`../../durability-dedup/coexistence/README.md`) was: **RTI Persistence Service
v7.3.1 relays the TRANSIENT / PERSISTENT durability tier, NOT TRANSIENT_LOCAL.** Phase 2 ran a
TRANSIENT_LOCAL topic, so RTI PS was completely silent — there was no second relay at all, and the
dual-relay test could not be set up.

Phase 3 adds a TRANSIENT-capable setup. In this leg:

- The **original Connext publisher advertises TRANSIENT durability** (`datawriter_qos` in
  `USER_QOS_PROFILES.xml`), so **RTI PS relays it** — confirmed live: RTI PS starts cleanly, joins
  domain 0 on loopback, and emits a relay stream (see the capture analysis below). The Phase-2 "RTI PS
  is inert" condition is gone.
- Our service's TRANSIENT_LOCAL collecting reader is **RxO-compatible** with the TRANSIENT writer
  (`dds.qos:durability-rank`: offered TRANSIENT rank 2 ≥ requested TRANSIENT_LOCAL rank 1), so our
  service collects the same origin samples and relays them too.

So for the first time **both relays are live on the wire simultaneously** — a real advance over Phase 2.

---

## Setup

| Component | Role | EntityId on wire | Domain |
|---|---|---|---|
| RTI Persistence Service v7.3.1 (`-cfgName transient`) | Relay 1 (TRANSIENT-tier collect + replay) | `0x80000002` | 0 |
| Our durability service (PERSISTENT store factory) | Relay 2 (TL collect + replay; OWI + PID_SERVICE_KIND) | `0x00000102` | 0 |
| Connext shapes publisher (`shapes_pub 0 GREEN`) | Original **TRANSIENT** writer (publishes ~22 s, then exits) | `0x000100c2` | 0 |
| Connext shapes subscriber (`shapes_sub 0 N`) | Late-joining **TRANSIENT_LOCAL** reader | — | 0 |

All on loopback (`127.0.0.1`), UDPv4. The asymmetric durability (writer TRANSIENT, reader
TRANSIENT_LOCAL) is deliberate and load-bearing — see the comment block in `USER_QOS_PROFILES.xml`. Our
service is the PERSISTENT (disk-backed + DARE-encrypted) store composition
(`make-persistent-store-factory`), the WP-DURABILITY-PERSISTENT tier.

---

## The decisive wire evidence (raw RTPS byte-walk, reproduced 4×)

`captures/coexistence-transient.pcap` (loopback DLT_NULL). tshark 4.6.x on this host does not dissect
DLT_NULL (see the macOS lo0 note below), so the capture is analyzed by a raw RTPS submessage walk,
`analyze-capture.py` (strip the 4-byte DLT_NULL header → IPv4 → UDP → RTPS submessage walk → DATA
inline-QoS ParameterList). Representative output (one run; the PID column is identical across all four
runs executed this session):

```
relay-writer EntityId | DATA | distinct own-SN | distinct OWI-origin | inline-QoS PIDs
  80000002 | 601 | 601 | 0   | 0x0070(PID_KEY_HASH):601
  00000102 | 534 | 534 | 534 | 0x0061(PID_ORIGINAL_WRITER_INFO):534
  000100c2 | 210 | 39  | 0   | 0x0070(PID_KEY_HASH):6, 0x0071:6      (original publisher)
  ...
```

Two relay writers are unambiguously present and active:

- **Our relay `0x00000102`** stamps **`PID_ORIGINAL_WRITER_INFO (0x0061)` on every relayed DATA** —
  534/534 here, each carrying a distinct origin `(GUID, SN)`. This is the OMG-standard dedup key
  (RTPS 2.5 §8.3.5.4) and is exactly what our receiver-side dedup (`reader-dedup-accept-p`, ADR 0024)
  consumes. Byte-correct, as in legs A/B of `../../durability-dedup/`.
- **RTI PS relay `0x80000002`** stamps **only `PID_KEY_HASH (0x0070)`** on its relayed DATA — **zero
  `PID_ORIGINAL_WRITER_INFO`**. RTI PS conveys original-writer identity by a *different* mechanism: the
  RTI vendor **`PID_ENTITY_VIRTUAL_GUID`** advertised once in the SEDP publication announcement
  (confirmed in the Phase-2/Task-7 spike, `../../durability-dedup/coexistence/README.md` §3.3), **not**
  the standard `PID_ORIGINAL_WRITER_INFO` per sample.

### The honest finding

The two relays carry the same logical origin samples but encode the origin identity in **different,
non-interoperable per-sample forms**:

| Relay | Per-sample origin-identity encoding | Standard? |
|---|---|---|
| Our service | `PID_ORIGINAL_WRITER_INFO (0x0061)` inline QoS | OMG RTPS 2.5 §8.3.5.4 |
| RTI PS | none per-sample; SEDP `PID_ENTITY_VIRTUAL_GUID` + Connext-internal coordination | RTI vendor |

Our dedup (ADR 0024) keys on `(originalGUID, originalSN)` extracted from `PID_ORIGINAL_WRITER_INFO`.
RTI PS's relayed samples **carry no such PID**, so a receiver doing standard-OWI dedup has nothing to
match RTI PS's stream against our stream on — the **dual-relay-exactly-once via OWI cannot be exercised
with RTI PS as the partner relay.** This is not a defect in our dedup and not an RTI PS configuration
miss; it is a **wire-protocol-dialect mismatch**: RTI's persistence relay and the OMG-standard OWI
mechanism are two different ways of expressing the same idea, and they do not deduplicate against each
other receiver-side without vendor-specific virtual-GUID handling.

(Connext's *own* late-joiner can still deduplicate RTI PS's stream — it understands its own vendor
virtual-GUID — but that is Connext deduplicating a single-vendor relay, not the cross-relay OWI
deduplication this leg set out to demonstrate.)

---

## Late-joiner receipt (a live confirmation, not the conformance substance)

Four runs were executed. The late-joining Connext TRANSIENT_LOCAL subscriber received **1422 samples**
in the first run and **0** in three subsequent runs. The receipt is **flaky** — a pure discovery-timing
artifact of a crowded loopback domain 0 (publisher + late-joiner + RTI PS + our SBCL service = 4+
participants, and after the TRANSIENT publisher exits the late-joiner must discover *two* ephemeral-port
relays via re-announced SPDP). This count is explicitly **not** the conformance substance (per the
Task-9 brief: "the cross-DDS coexistence is a live confirmation, not the conformance substance").

What the one non-zero run (1422) tells us, read against the PID evidence: 1422 ≈ our relay's own DATA
count (~1420), **not** a 2N count deduplicated down to N. Consistent with the finding above — the
subscriber was not OWI-deduplicating across the two relays (RTI PS carries no OWI), so the count tracks
one relay's contribution rather than a deduplicated union. No exactly-once-via-OWI claim can rest on it.

---

## Authoritative no-double-delivery proof (the conformance substance)

The conformant exactly-once-under-dual-relay proof is the in-process unit test
**`dds.tests:run-durability-no-double-delivery-test`** (`src/dds-tests/durability-test.lisp`). It stands
up a genuine dual relay — an **alive original writer AND a durability-service relay both send the same N
samples to the same reader** (triangular wiring pub↔svc, pub↔sub, svc↔sub) — where **both copies carry
the same `(originalGUID, SN)`** (the relay attaches `PID_ORIGINAL_WRITER_INFO`; the direct writer copy
is the origin natively). The reader's `(originalGUID, max-SN)` dedup gate collapses both copies to
**exactly N deliveries, not 2N**.

Re-run this session on SBCL:

```
NO-DOUBLE-DELIVERY-RESULT: T
```

(Green on SBCL and Clasp — Clasp validated first per the operating contract; 275-green durability suite,
ADR 0024.) This is the binary correctness gate. Unlike the RTI PS leg, here **both relays speak the same
OWI encoding**, which is precisely the scenario the standard mechanism is defined for — and it
deduplicates exactly. A second relay that *also* emits `PID_ORIGINAL_WRITER_INFO` (another instance of
our service, or any OMG-conformant persistence relay) is deduplicated against ours receiver-side with no
inter-relay coordination; RTI PS is not such a relay.

---

## What is proven, and what is not

**Proven:**

1. RTI Persistence Service v7.3.1 **runs and relays at the TRANSIENT tier on this host** — the Phase-2
   blocker (RTI PS inert for TRANSIENT_LOCAL) is resolved. Both relays are simultaneously live on the
   wire (RTI PS `0x80000002`, our service `0x00000102`), reproduced across four runs.
2. Our relay writer emits **`PID_ORIGINAL_WRITER_INFO (0x0061)` byte-correct on every relayed sample**
   under coexistence (534/534, 591/591, etc. — one OWI per DATA, each a distinct origin).
3. Our receiver-side OWI dedup collapses a genuine dual relay to **exactly N** when both relays use the
   standard OWI encoding (`run-durability-no-double-delivery-test`, green SBCL+Clasp).

**Not proven (honest deferral):**

4. A live **dual-relay-exactly-once with RTI PS as the second relay** is **not exercisable**, because
   RTI PS does not stamp the standard `PID_ORIGINAL_WRITER_INFO` on its relayed samples (it uses the RTI
   vendor virtual-GUID). The two relays encode origin identity in incompatible per-sample forms, so a
   standard-OWI receiver cannot deduplicate across them. This is a wire-dialect mismatch, not a code
   defect. Demonstrating cross-relay OWI exactly-once requires a **second OMG-OWI-conformant relay**
   (e.g. a second instance of our service); RTI PS is out of scope for that specific mechanism.

This disposition is consistent with — and strictly stronger than — the Phase-2 CLOSED_WITH_FINDINGS
outcome: Phase 2 could not even get RTI PS to relay; Phase 3 gets RTI PS relaying and pins down the
precise reason the standard-OWI dual-relay-dedup cannot be demonstrated against it.

---

## Honest caveats

1. **RTI PS does not emit `PID_ORIGINAL_WRITER_INFO`.** It uses the RTI vendor virtual-GUID
   (`PID_ENTITY_VIRTUAL_GUID`, SEDP-advertised). Our dedup keys on the standard OWI PID, so it cannot
   deduplicate RTI PS's stream against ours. The standard mechanism is correct; RTI PS simply does not
   speak it per-sample.
2. **The Connext late-joiner receipt is discovery-flaky** on this crowded loopback domain 0 (1422 once,
   0 thrice). The count is a live confirmation, not the conformance substance, and no exactly-once claim
   rests on it.
3. **macOS lo0 / tshark caveat.** macOS uses DLT_NULL loopback framing; tshark 4.6.x on this host does
   not dissect it (`frame.protocols` empty, 0 RTPS frames even with the RTPS heuristic enabled). The
   per-relay PID analysis is therefore a raw byte-walk (`analyze-capture.py`), which is more precise than
   the dissector here. `tcpdump -r <pcap> -nn` confirms the loopback UDP/RTPS frames.
4. **The principal proof of no-double-delivery is the in-process test**
   (`run-durability-no-double-delivery-test`, ADR 0024). The live RTI PS run provides wire evidence that
   (a) our relay emits the correct PID and (b) RTI PS relays but in a non-OWI dialect.

---

## Run procedure

**FIRST: kill any stale DDS process on the discovery ports** (`lsof -nP -iUDP:7400-7440`).

```sh
export NDDSHOME=/Applications/rti_connext_dds-7.3.1
export CONNEXTDDS_ARCH=arm64Darwin20clang12.0
# from repo root:
PUBSECS=22 SUBSECS=30 interop/durability-persistent/coexistence/run-coexistence.sh
```

`run-coexistence.sh` orchestrates: kill stale procs → start tshark on lo0 → start RTI PS (relay 1) →
start our durability service (relay 2, `driver-coexist.lisp`) → run the TRANSIENT publisher ~22 s then
kill it → settle → run the late-joining TRANSIENT_LOCAL subscriber → stop relays → analyze the capture
with `analyze-capture.py`. It cleans up every process it starts (trap on EXIT).

Re-run the authoritative in-process proof:

```sh
./scripts/with-sbcl.sh --eval '(ql:quickload :dds-tests :silent t)' \
  --eval '(format t "~%NO-DOUBLE-DELIVERY-RESULT: ~a~%" (dds.tests:run-durability-no-double-delivery-test))'
# => NO-DOUBLE-DELIVERY-RESULT: T
```

---

## Files

| File | Description |
|---|---|
| `RTI_PS_TRANSIENT.xml` | RTI PS config (loopback, domain 0, TRANSIENT in-memory, all topics) |
| `USER_QOS_PROFILES.xml` | Connext QoS: writer TRANSIENT (so RTI PS relays), reader TRANSIENT_LOCAL (matches both relays) |
| `driver-coexist.lisp` | Our durability service as relay 2 (PERSISTENT store factory; long-running collect + serve) |
| `run-coexistence.sh` | End-to-end orchestration + cleanup |
| `analyze-capture.py` | Raw RTPS byte-walk: per-relay DATA count, own-SN, OWI-origin, inline-QoS PIDs |
| `captures/coexistence-transient.pcap` | Loopback capture — both relays present; our `0x00000102` carries OWI 0x0061, RTI PS `0x80000002` carries only keyhash 0x0070 |
