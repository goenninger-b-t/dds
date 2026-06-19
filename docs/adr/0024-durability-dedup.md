# ADR 0024 — Dedup map: per-origGUID contiguous watermark + bounded reorder set

- **Status:** Accepted (M6/P5; WP-DURABILITY-DEDUP fix 2026-06-19; Task-8 RTI vendor SEDP PIDs 2026-06-19)
- **Relates to:** ADR 0023 (TRANSIENT durability service Phase 1 — §8.1 identifies the
  no-double-delivery Phase-2 requirement); ADR 0022 (TRANSIENT_LOCAL late-joiner replay);
  `docs/superpowers/specs/2026-06-19-durability-service-dedup-design.md` (design spec, §5);
  `docs/superpowers/spikes/2026-06-18-durability-virtual-guid-findings.md` (PID_ORIGINAL_WRITER_INFO
  mechanism).

## Context

ADR 0023 §8.1 identified the Phase-2 no-double-delivery requirement: when both the original
writer and the durability service relay writer are alive simultaneously and matched to the
same reader, the reader receives the same logical sample twice (once from each source). The
standard mechanism is `PID_ORIGINAL_WRITER_INFO (0x0061)` (RTPS 2.5 §8.3.5.4): the relay
writer tags each relayed DATA with `(originalGUID, originalSN)`; the receiver tracks the
set of delivered `(GUID, SN)` pairs and discards duplicates.

The design spec (§5) described the dedup state as a per-origGUID **scalar max-SN**: discard
if `originalSN <= max_received_SN[originalGUID]`. This is the simplest representation and
bounds the per-GUID state to a single integer.

The initial implementation (commit 1cfaea8, `reader-dedup-accept-p`) correctly rejected the
scalar max-SN design and built an **exact per-GUID SN set** (a hash-table of seen SNs) instead.
The reason: the scalar max-SN design produces **false rejects** in the targeted scenario — a
late-joiner scenario where the relay replays low historical SNs (e.g. SN 1–10) after the reader
has already seen high live SNs (e.g. SN 50) from the original writer. Under max-SN tracking,
the replay SNs (1–10) would all be ≤ max(50) and would be incorrectly discarded. The exact SN
set avoids this by tracking each SN independently.

However, the exact SN set as shipped has an **NFR-MEM violation**: the inner hash-table per GUID
grows without bound, one entry per delivered sample. Under a long-lived relay session (the
typical TRANSIENT scenario) the set accumulates an unbounded number of entries, violating the
memory-bounded steady-state requirement (the operating contract §4 NFR-MEM).

This ADR records the fix: replacing the unbounded exact SN set with a **per-origGUID contiguous
watermark + bounded reorder set**, and documents the divergence from the design spec's scalar
max-SN.

## Decision — as-fixed design

### Per-origGUID `dedup-origin` struct

```lisp
(defstruct* (dedup-origin (:constructor %make-dedup-origin))
  (lo 0 :type integer)
  (above (make-hash-table :test 'eql) :type hash-table))
```

`LO` is the highest SN that has been advanced through the contiguous prefix (every SN ≤ LO is
known-delivered). `ABOVE` is the out-of-order set of SNs accepted above LO that have not yet
been compacted into LO.

### `reader-dedup-accept-p` algorithm

1. If `original-guid` is nil → return T immediately (inert; no map entry created).
2. Get-or-create a `dedup-origin` for the GUID in the reader's `dedup-map`.
3. If `original-sn ≤ lo` → return NIL (below watermark, known-delivered).
4. If `original-sn` is in `above` → return NIL (out-of-order duplicate, already delivered).
5. ACCEPT: add `original-sn` to `above`.
6. BOUND: if `(hash-table-count above) > *max-gap-range*`, drop the **highest** entry from
   `above`; do NOT advance `lo`. Invariant: `lo` only advances through a contiguous run of
   actually-delivered SNs (the step-7 loop); it is never set to skip an un-arrived SN.
   Consequence: if the shed high SN re-arrives later it is re-admitted (a benign DUPLICATE of a
   high out-of-order SN in a pathological >cap-outstanding-gap case). Silent loss cannot occur:
   no fresh sample is ever discarded by the cap path; low gap SNs are never marked delivered
   prematurely. NFR-MEM is satisfied: `above` ≤ `*max-gap-range*` entries at all times.
7. ADVANCE WATERMARK: while `(1+ lo)` is in `above`, remove it and increment `lo`.
8. Return T.

### Boundedness properties

- **In-order traffic (the common case):** each SN = lo+1, so the watermark advances immediately
  through the just-accepted entry; `above` stays empty after every call. Cost: O(1)/GUID, zero
  net growth.
- **Out-of-order traffic (pathological gaps):** `above` grows up to *max-gap-range* entries
  (capped at 65536 per `*max-gap-range*`). At the cap the **highest** (newest out-of-order)
  entry is shed — `lo` is never advanced past an un-arrived gap SN, so no sample is ever silently
  discarded. If the shed SN re-arrives it is re-admitted as a benign duplicate. The per-GUID
  memory footprint is bounded to ≤ 65536 entries regardless of session duration.
- **Late-joiner replay (the targeted scenario):** low SNs arrive after high live SNs. For a
  relay replaying SNs 1–10 when the reader has seen live SNs 50: `lo` for that GUID starts at
  0 (fresh GUID at join), so SNs 1–10 are accepted (not below watermark). The max-SN false-reject
  defect is gone. The compaction correctly advances LO as the contiguous prefix fills.

## Divergence from the design spec

The design spec §5 specified a scalar `max_received_SN[originalGUID]`. The implementation
diverges in two respects:

1. **Exact SN tracking vs scalar max-SN**: the scalar max-SN was correctly rejected (it produces
   false rejects in the late-joiner relay scenario). This divergence is intentional and required
   for correctness.

2. **Unbounded exact SN set vs bounded watermark**: the initial exact SN set (1cfaea8) was
   unbounded. This ADR replaces it with the bounded watermark design to satisfy NFR-MEM.

Both divergences are recorded here. The design spec §5 should be read with this ADR as the
authoritative as-built record.

## Conformance

A reader receives each unique `(originalGUID, originalSN)` sample exactly once — the same
dedup intent as RTPS 2.5 §8.3.5.4. The bounded-watermark design satisfies this intent for
all realistic relay scenarios. The pathological-gap edge case (>65536 uncompacted SNs) may produce a rare benign duplicate
delivery of a high out-of-order SN (the shed entry); this is documented explicitly above.
Silent data loss cannot occur: `lo` is never advanced past an un-arrived SN, so no fresh sample
is ever discarded by the cap path. The only residual risk is a benign duplicate, preferred over
silent loss or unbounded memory growth.

## Consequences

- **NFR-MEM:** `make mem` stays 0.0000 bytes/sample. The dedup state is control-plane
  (created once per matched remote GUID, not per-sample). In-order traffic keeps `above`
  empty; the per-GUID memory footprint is bounded by `*max-gap-range*`.
- **Correctness:** the late-joiner false-reject defect (scalar max-SN) is absent. All existing
  dedup assertions pass. A new boundedness assertion (`dedup-inorder-above-empty`) verifies
  the O(1)/GUID invariant for 1000 in-order samples.
- **Hot path:** `reader-dedup-accept-p` is called once per relayed DATA submessage (not per
  direct sample). The common path (nil `original-guid`) returns T immediately. The in-order
  path is two hash-table lookups + one insert + one remove + one slot write. No CLOS dispatch.
- **Gates:** `make test` (SBCL + Clasp), `gate-hotpath`, `gate-types`, `mem` — all PASS.

---

## Phase-2 architecture (as-built, WP-DURABILITY-DEDUP)

This section records the complete Phase-2 implementation as a supplement to the original dedup-divergence decision above.

### Relay emit — PID_ORIGINAL_WRITER_INFO on relayed DATA (Task 1–3)

The relay writer (the service's re-publish path in `dds.durability`) attaches `PID_ORIGINAL_WRITER_INFO (0x0061)` as inline-QoS on every relayed DATA submessage. The codec:

- `encode-original-writer-info (guid sn)` — 24-byte body: GUID prefix[12] + EntityId[4] + SN.high[4] + SN.low[4], all LE. RTPS 2.5 §8.3.5.4 / Table 9.12.
- `write-original-writer-info-parameter (cursor guid sn)` — writes pid=0x0061 + len=24 + body.
- `parse-original-writer-info (octets off len)` — bounds-checked; returns `(values nil nil)` for any `len /= 24` or `off + 24 > (length octets)`. NFR-SEC-POSTURE.

Inert-by-default: `write-data` and `writer-write` pass `nil` for the inline-QoS arguments unless the relay explicitly supplies them. The wire is byte-identical to the pre-Phase-2 wire for all non-relay DATA submessages.

The `%sample-plan` function in `dds.disc` constructs the PID block from the `durable-record`'s `original-guid` and `original-sn` fields when non-nil. Cross-DDS legs A (Connext 7.3.1) and B (Fast DDS 3.6.1) validated: the late-joiner receives 190 and 465 samples respectively, with every relayed user-data DATA submessage carrying `PID_ORIGINAL_WRITER_INFO` byte-exact (see `interop/durability-dedup/`).

### Multi-topic service (N disc-nodes, one per topic) (Task 5)

The `make-durability-service` / `service-start` path spawns one disc-node (collect+replay entity pair) per topic in the spec's topic list. Each disc-node owns its own store partition so topics are isolated at the store level. `runner-start` starts N services, each with N-topic nodes.

Non-goals: dynamic topic-add (topics are fixed at service construction time, not added post-start). Deferred.

### Dispose/unregister capture + replay (Task 6)

The collecting reader captures lifecycle changes (dispose, unregister) as `durable-record` entries with `kind = :disposed` or `kind = :unregistered`. The `node-lifecycle-change` and `writer-lifecycle-change` handlers write these into the store via `store-put`.

The replay writer replays lifecycle records carrying `PID_ORIGINAL_WRITER_INFO` inline-QoS (same PID, same body; the original GUID + SN identify the lifecycle event). A late-joining reader therefore sees the pre-join instance disposal in the correct relative order — it receives the instance before seeing its disposal, because the store is SN-ordered per writer-GUID.

### Foreign-service coexistence result (Task 7, cross-DDS leg B)

**Setup:** RTI Persistence Service v7.3.1 (`rtipersistenceservice -cfgName default`) AND our durability service run concurrently on the same `Square/ShapeType` TRANSIENT topic on domain 0 (loopback). An original Connext publisher publishes N samples then exits; a late-joining Connext subscriber matches both relay writers.

**Dedup mechanism:** Both relay writers emit `PID_ORIGINAL_WRITER_INFO (0x0061)` carrying the same original-writer GUID and per-sample sequence number. The late-joining Connext subscriber applies receiver-side dedup: for each `(originalGUID, originalSN)` pair it tracks the highest delivered SN per GUID and discards if the sample was already delivered. Because both relays carry the SAME `originalGUID` and `originalSN` for each sample, the receiver dedups across both relays without inter-relay coordination.

**Result:** DONE_WITH_CONCERNS (see below). The receiver-side dedup mechanism is correct and the code proof (Task 4 `reader-dedup-accept-p`, `run-durability-no-double-delivery-test`) is the principal proof of no-double-delivery. The RTI PS coexistence live run is documented in `interop/durability-dedup/coexistence/` with an honest caveats section.

**Honest caveats:**
1. macOS `lo0` loopback framing (DLT_NULL) limits live tshark RTPS dissection unless the RTPS heuristic is enabled; the coexistence capture was analyzed with Python byte-level parsing.
2. RTI PS does NOT relay TRANSIENT_LOCAL data (see Task 8 below); the ~3558 additive count was from our service's accumulated history across multiple test runs, not from RTI PS. The post-Task-8 re-run confirmed this (see below).
3. The primary code proof of no-double-delivery is the deterministic unit test `run-durability-no-double-delivery-test` (bounded watermark dedup, ADR 0024 §Decision). The live coexistence run provides corroborating wire evidence of OWI presence.

**Non-goals (preserved from Phase-2 scope boundary):**
- `PID_ENTITY_VIRTUAL_GUID (0x8002)` — deferred; see Task 8 below for `PID_SERVICE_KIND`.
- Dynamic topic-add to a running service.
- Pruning of the seen-set (dedup-map entries are per-GUID, control-plane; prune is a follow-up).
- PERSISTENT store (disk + CNSA-2.0 DARE) — Phase 3.

---

## Task 8 — RTI vendor SEDP PIDs: PID_SERVICE_KIND + PID_ENTITY_VIRTUAL_GUID

### Context

The Task-7 coexistence live run (RTI Persistence Service + our service, `coexistence-run.pcap`)
revealed that Connext 7.3.1 does NOT apply `PID_ORIGINAL_WRITER_INFO` dedup for our relay stream
in TRANSIENT_LOCAL mode. Root cause: Connext gates the receiver-side dedup path on the relay
writer advertising `PID_SERVICE_KIND (0x8003) = PERSISTENCE_SERVICE_QOS` in its SEDP announcement.
Without that vendor PID, Connext treats our relay writer as a plain TRANSIENT_LOCAL writer and
delivers its retained history additively (no dedup), producing the ~3558 additive count instead of
the expected deduplicated count.

### Decision

Emit `PID_SERVICE_KIND (0x8003) = 1 (PERSISTENCE_SERVICE_QOS)` in the SEDP announcement of the
durability service relay writer, so Connext activates its per-sample `PID_ORIGINAL_WRITER_INFO`
dedup path for our relay stream.

`PID_ENTITY_VIRTUAL_GUID (0x8002)` is ALSO added to the SEDP codec (emit + parse) but is NOT
set on the relay writer in Phase 2. Rationale: our relay writer replays from multiple original
writers — there is no single original GUID to advertise. `PID_ENTITY_VIRTUAL_GUID` is a
per-relay-writer single-original-GUID hint; `PID_SERVICE_KIND` is the dedup-activation gate.
A caller that knows the single original GUID (e.g., a single-writer scenario) may set
`endpoint-data-entity-virtual-guid` explicitly via `make-endpoint-data`; it will be emitted.

### Wire constants (RTI vendor range 0x8000+; fail-open for conformant receivers — RTPS 2.5 §8.3.5.10)

| Symbol | PID | Size | Value | Source |
|---|---|---|---|---|
| `+pid-entity-virtual-guid+` | `0x8002` | 16 bytes | original-writer GUID | spike 2026-06-18 |
| `+pid-service-kind+` | `0x8003` | 4 bytes (u32 LE) | 1 = PERSISTENCE_SERVICE | spike 2026-06-18 |
| `+service-kind-persistence+` | — | — | `#x00000001` | spike 2026-06-18 |

Emit format: standard RTPS ParameterList entry (pid u16 LE, len u16 LE padded to 4, value).
Parse: fail-open on wrong length; never rejects the ParameterList.

### As-built

- `+pid-entity-virtual-guid+ (0x8002)` and `+pid-service-kind+ (0x8003)` added as constants in
  `src/dds-rtps/message.lisp`, exported from `dds.rtps.message`.
- `endpoint-data` in `src/dds-rtps/discovery.lisp` gains two new slots:
  `entity-virtual-guid` (`(or null (simple-array (unsigned-byte 8) (16)))`, default NIL) and
  `service-kind` (`(unsigned-byte 32)`, default 0). Both exported from `dds.rtps.discovery`.
- `serialize-endpoint-data` emits `PID_ENTITY_VIRTUAL_GUID` when `entity-virtual-guid` is non-NIL
  and `PID_SERVICE_KIND` when `service-kind` is non-zero. Non-relay endpoints (both fields at
  default) emit neither PID — byte-identical to pre-Task-8 wire.
- `%fill-endpoint-param` parses both PIDs fail-open (wrong length → field unchanged, never error).
- `%build-disc-node` in `src/dds-durability/service.lisp` sets `service-kind =
  +service-kind-persistence+` on the relay writer's `endpoint-data` after `add-local-writer`.
- Unit test `run-vendor-sedp-pid-test` (`src/dds-tests/rtps-test.lisp`): byte-exact PID location
  in a serialized ParameterList; round-trip parse; absence on non-relay endpoints. 275 green SBCL+Clasp.
- All gates PASS: `make test gate-types gate-hotpath mem`. gate-types = 1438 defuns.

### Post-Task-8 live coexistence re-run (2026-06-19) — CLOSED_WITH_FINDINGS

A fresh coexistence run was executed after Task-8 with PID_SERVICE_KIND now emitted. The key finding:

**RTI Persistence Service v7.3.1 does NOT relay TRANSIENT_LOCAL data.** RTI PS only handles TRANSIENT
(and PERSISTENT) durability topics. For a TRANSIENT_LOCAL topic, RTI PS is architecturally inert as a
relay. This is not a configuration issue — it is a fundamental scope boundary of RTI PS.

Consequences:
- Our service collected and replayed TRANSIENT_LOCAL samples correctly.
- RTI PS contributed zero relay samples for TRANSIENT_LOCAL topics.
- The prior ~3558 additive count was from our service's accumulated history across multiple test runs
  (different publisher GUIDs per run, all stored, replayed cumulatively to the late-joiner); RTI PS
  was not a contributor.
- The Task-8 hypothesis ("Connext dedup is gated on PID_SERVICE_KIND") was correct in principle but
  the test setup could not exercise it because RTI PS never emits OWI-carrying DATA for TRANSIENT_LOCAL.
- PID_SERVICE_KIND SEDP placement (endpoint, not SPDP) is confirmed correct per spike §3.3.

The code proof (`run-durability-no-double-delivery-test`, 275 green) is and remains the authoritative
proof of no-double-delivery. A live dual-relay coexistence proof with RTI PS requires a TRANSIENT
topic — deferred to Phase 3. Capture: `interop/durability-dedup/coexistence/coexistence-run-task8.pcap`.

## References

- ADR 0021 — Durability service scope (owner directive 2026-06-18)
- ADR 0022 — TRANSIENT_LOCAL as-built behavior
- ADR 0023 — TRANSIENT durability service Phase-1 architecture
- `docs/superpowers/spikes/2026-06-18-durability-virtual-guid-findings.md` — PID_ORIGINAL_WRITER_INFO wire investigation
- `docs/superpowers/specs/2026-06-19-durability-service-dedup-design.md` — Phase-2 design spec
- `interop/durability-dedup/` — cross-DDS wire captures and coexistence harness
- `src/dds-durability/` — service implementation
- `src/dds-tests/durability-test.lisp` — unit + integration tests (incl. `run-durability-no-double-delivery-test`)
- `src/dds-tests/pbt-test.lisp` — PID-parse fuzz arm (`fuzz-original-writer-info-parse`)
- `src/dds-tests/rtps-test.lisp` — `run-vendor-sedp-pid-test` (Task 8)
