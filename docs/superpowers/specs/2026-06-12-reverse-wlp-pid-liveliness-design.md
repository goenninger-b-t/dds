# Reverse WLP direction — Fast DDS accepts our ParticipantMessageData (+ PID_LIVELINESS in SEDP)

**Goal:** Prove the conformant peer Fast DDS ACCEPTS our emitted `ParticipantMessageData`
(RTPS §8.4.13) — the not-yet-done reverse half. The forward half (we parse Fast DDS's bytes
byte-exact) is done.

## Blocking finding (why this is more than a capture)

Our SEDP does **not** emit `PID_LIVELINESS` (0x001b) — `serialize-endpoint-data`
(`src/dds-rtps/discovery.lisp:437-474`) emits GUID/topic/type/reliability/durability/
type-information only; `message.lisp` has no `+pid-liveliness+`. So a remote reader never
learns our writer offers LIVELINESS, can't RxO-match on it, and **won't track our writer's
liveliness** — the strong proof (Fast DDS `on_liveliness_changed`) is impossible without it.

This is a genuine conformance gap: a conformant writer advertises its LIVELINESS QoS in SEDP
(DiscoveredWriterData) so readers can RxO-evaluate and track it. Adding it is correct and
required for this task.

## PID_LIVELINESS wire format (pinned from the oracle + spec)

From a live Fast DDS SEDP publication (`/tmp/fddswlp/wlp2.pcap` frame 67, an AUTOMATIC writer,
1 s lease):

```
1b 00 0c 00              parameterId 0x001b, parameterLength 12
00 00 00 00              kind  (long LE)  AUTOMATIC=0 / MANUAL_BY_PARTICIPANT=1 / MANUAL_BY_TOPIC=2
01 00 00 00 00 00 00 00  lease_duration  {seconds:i32 LE = 1, nanosec:u32 LE = 0}
```

The wire `kind` long equals our existing `dds.qos:liveliness-rank` (`:automatic` 0 <
`:manual-by-participant` 1 < `:manual-by-topic` 2 — `qos.lisp:41`). `lease_duration` is a DDS
Duration_t `{sec, nanosec}` (our `qos-duration`); for the integer-second leases we test,
nanosec=0 → byte-exact vs the oracle. (The RTPS Duration_t fraction-vs-nanosec subtlety only
affects sub-second leases; document the choice, cite the DDS PSM LivelinessQosPolicy mapping.)

## Plan

**A. Emit + parse PID_LIVELINESS in SEDP (conformance).**
- `+pid-liveliness+` 0x001b in `message.lisp` (cite the clause).
- `serialize-endpoint-data`: emit `{ liveliness-rank(kind) LE, lease.sec i32 LE, lease.nanosec u32 LE }`
  len 12, from the writer's `qos-liveliness` + `qos-liveliness-lease`.
- `parse-endpoint-data`: parse PID_LIVELINESS into the endpoint's `qos` (so inbound writers'
  liveliness is known — also feeds our reader-side liveliness tracking + RxO).
- Locked byte-vector test vs the Fast DDS oracle bytes (AUTOMATIC + 1 s = the 16 octets above).
- Guard: emitting for default writers (AUTOMATIC + infinite lease) must not break existing
  interop — a default reader requests AUTOMATIC+infinite, offered infinite ≤ requested infinite
  → still compatible. Re-run the data-plane suite.

**B. Thread finite-lease liveliness through `run-publisher` (harness).**
- `run-publisher` gains `:liveliness` (kind) + `:liveliness-lease-seconds`, passed to
  `add-local-writer :qos (make-qos :reliability :reliable :liveliness K :liveliness-lease ...)`.
  `add-local-writer` already takes `:qos`; `assert-participant-liveliness` already picks the
  kind from local writers' QoS. Makefile `run-publisher LIVELINESS= LEASE=`.

**C. Fast DDS `shapes_sub` (C++).** Add an env-gated reader LIVELINESS QoS + an
`on_liveliness_changed` listener logging alive/not_alive counts (mirrors the `WLP_LEASE_MS`
pattern on the pub).

**D. Live strong proof.** Our `run-publisher` (finite-lease liveliness, asserting on the
announce cadence) ↔ Fast DDS `shapes_sub` (requesting matching liveliness). Capture lo0;
confirm Fast DDS `on_liveliness_changed` reports our writer ALIVE while we assert. Stop our
assertions; confirm NOT_ALIVE. Record provenance + flip verification.csv.

### Proof-strength choice — DECIDED: MANUAL_BY_PARTICIPANT + AUTOMATIC (owner, 2026-06-12; amended to add AUTOMATIC)
Cover BOTH kinds in the live proof and harness: AUTOMATIC as the baseline alive-confirmation,
MANUAL_BY_PARTICIPANT as the isolated alive→not_alive transition. The Fast DDS `shapes_sub`
liveliness kind + lease and our `run-publisher` liveliness kind are both selectable, so each
kind is run end-to-end. Detail of the MANUAL isolation:

Our writer offers MANUAL_BY_PARTICIPANT + a finite lease (~5 s); Fast DDS `shapes_sub` requests
MANUAL_BY_PARTICIPANT + a larger lease (~10 s). RxO: offered rank 1 ≥ requested rank 1, offered
lease 5 s ≤ requested 10 s → compatible (`qos-rxo-compatible`, `qos.lisp:140`). Our
`assert-participant-liveliness` sends MANUAL `ParticipantMessageData` on the ~1.5 s announce
cadence (beats the lease). Fast DDS reports our writer ALIVE while we assert, and NOT_ALIVE when
we stop — even though our SPDP stays current — isolating our `ParticipantMessageData` as the
liveliness signal. The AUTOMATIC and "both" variants were declined.

## Out of scope
Per-writer liveliness assertion timer (we use the announce cadence); MANUAL_BY_TOPIC carriage.
