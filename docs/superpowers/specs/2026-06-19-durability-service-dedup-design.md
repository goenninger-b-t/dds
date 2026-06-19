# Design — TRANSIENT durability service Phase 2: dedup + multi-topic + dispose/unregister (M6/P5)

- **Date:** 2026-06-19
- **Status:** Design approved (brainstorm); spec under owner review before the implementation plan.
- **Scope:** Phase 2 of the embedded TRANSIENT durability service (ADR 0021 slice 2). Four items in one
  spec: (1) no-double-delivery dedup via `PID_ORIGINAL_WRITER_INFO (0x0061)`; (2) foreign-durability-service
  coexistence; (3) multi-topic-per-service; (4) dispose/unregister capture + replay. The PERSISTENT slice
  (disk-backed store + always-on CNSA-2.0 DARE, ADR 0021 cap. 7) remains OUT of scope (slice 3).
- **Relates to:** ADR 0023 (Phase-1 architecture — the deferred items this spec closes); ADR 0021 (scope);
  ADR 0022 (TRANSIENT_LOCAL late-joiner foundation); the Phase-1 spike
  `docs/superpowers/spikes/2026-06-18-durability-virtual-guid-findings.md` (the dedup wire format, captured
  + byte-exact); DDS 1.4 §2.2.3.4; RTPS 2.5 §8.3.5.4 (`OriginalWriterInfo`), §9.4.5.4 (DATA InlineQos flag),
  §9.4.2.11 (ParameterList).

## 1. Goal

Phase 1 shipped the embedded TRANSIENT durability service for the WRITER-IS-GONE scenario (single source =
the service, no dedup needed). Phase 2 closes the deferred conformance gap: when the original writer is ALSO
alive, or a foreign durability service ALSO relays the same data, a TRANSIENT reader matched to multiple
sources must receive each sample EXACTLY ONCE. The Phase-1 spike established the mechanism is the standard
RTPS PID `PID_ORIGINAL_WRITER_INFO (0x0061)` carried in the inline QoS of every relayed DATA, with
receiver-side max-SN dedup keyed by the original writer's GUID. Phase 2 also adds two capability extensions
deferred from Phase 1: multi-topic-per-service and dispose/unregister capture + replay.

## 2. Owner decisions (brainstorm, 2026-06-19)

1. **Scope:** all four items in one spec (the implementation plan sequences them as thin vertical slices).
2. **Multi-topic realization:** a `durability-service` holds N disc-nodes, one per topic (reusing the shipped
   single-endpoint-per-node model — ZERO change to the dds.disc single-endpoint contract). NOT a
   multi-endpoint disc-node.
3. **Dedup emit mechanism:** extend the engine's outbound DATA path to carry per-change inline QoS from the
   `cache-change`'s existing (currently unused) `inline-qos` slot — mirroring how `write-data-dispose` already
   sets the Q-bit + writes a parameter list — rather than a durability-special-case publish path. Inert by
   default (nil inline-qos → byte-identical wire).

## 3. Engine facts grounding the design (from a code survey)

- `write-data` (`src/dds-rtps/message.lisp`) emits NO inline QoS + never sets the Q-bit
  (`+data-flag-inline-qos+ #x02`). `write-data-dispose` DOES (Q-bit + `write-parameter` PID_KEY_HASH +
  PID_STATUS_INFO + `write-parameter-sentinel`) — the template to extend. `write-parameter` /
  `write-parameter-sentinel` exist (4-octet-aligned PL_CDR).
- `cache-change` has an `inline-qos` slot `(or null (array (unsigned-byte 8) (*)))` — defined but NEVER read
  by the emit path. Phase 2 makes the emit path consult it.
- `writer-write` (`reliable.lisp`) assigns the writer's own SN; no inline-qos parameter today.
- Inbound: `parse-inline-qos-key-status` IS invoked from `parse-data-body` (extracts PID_KEY_HASH /
  PID_STATUS_INFO), but for DATA samples the parsed inline QoS is DISCARDED — `disc-node-on-data` receives
  only `(writer-id sn buf poff plen src-prefix)`. `reader-on-data` tracks `writer-proxy-received[sn]=T` +
  `last-sn` per writer; there is NO original-GUID dedup map.
- A disc-node hosts exactly ONE `user-writer` + ONE `user-reader`; the sample store is keyed GUID→SN (no
  topic). Multi-topic therefore = N nodes (decision §2.2).
- Dispose/unregister kind IS preserved + exposed on receive: `node-lifecycle-change` →
  `(kind key-hash status-flags writer-id source-guid)` via the `disc-node-on-lifecycle` hook.
  `writer-lifecycle-change` already emits a no-payload dispose/unregister DATA with inline QoS.
- `PID_ORIGINAL_WRITER_INFO (0x0061)` does NOT exist in the codebase (no constant, encoder, or parser).

## 4. Module touch-points

| Unit | File | Change |
|---|---|---|
| PID codec | `src/dds-rtps/message.lisp` | NEW `+pid-original-writer-info+` (`#x0061`); encoder for the 24-byte `OriginalWriterInfo` body (guidPrefix[12] + entityId[4] + SN.high[4] + SN.low[4], LE, RTPS 2.5 §8.3.5.4); extend the inbound inline-QoS parser to extract it (bounds-checked). |
| Outbound inline-QoS | `src/dds-rtps/message.lisp` + `reliable.lisp` | Extend `write-data` to accept optional inline-QoS bytes + set the Q-bit when present; the DATA-emit path reads `cache-change-inline-qos`. **Default nil → byte-identical wire.** A relay write path (or `writer-write` inline-qos arg) attaches the encoded PID. |
| Receiver dedup | `src/dds-rtps/reliable.lisp` + `src/dds-disc/dataplane.lisp` | A per-reader `original-guid → max-received-SN` map; on inbound DATA carrying PID_ORIGINAL_WRITER_INFO, discard if `originalSN ≤ max`. Inert when the PID is absent (normal SN tracking untouched). |
| Relay emit | `src/dds-durability/service.lisp` | The replay writer attaches PID_ORIGINAL_WRITER_INFO built from the store's recorded `(original-writer-guid, sn)` per sample (data AND lifecycle). |
| Multi-topic | `src/dds-durability/service.lisp` | A `durability-service` holds N disc-nodes, one per resolved `(topic . type)`; collect/replay fan across them; the store is per-topic. K=1 byte-identical to Phase 1. |
| Dispose/unregister | `src/dds-durability/service.lisp` + `store.lisp` | The collect loop drains `node-lifecycle-change` into the store as `kind ∈ {:dispose,:unregister}` records; replay re-emits via `writer-lifecycle-change` (with the PID attached). |

The engine changes (message.lisp/reliable.lisp) are **inert by default**: no inline QoS attached and no PID
present → byte-identical wire + unchanged SN tracking. Dedup/relay activate only for the durability path and
foreign relays.

## 5. Dedup data flow (the conformance core)

**Emit (relay writer).** The store records each sample's original `(writerGUID, SN)` at collection (Phase 1).
At replay, a relay-aware write: (1) encodes PID_ORIGINAL_WRITER_INFO from the stored `(originalGUID,
originalSN)` — the 24-byte body, LE; (2) attaches it as the new change's `inline-qos`; the extended
`write-data` sets the Q-bit and writes the parameter list (PID_ORIGINAL_WRITER_INFO [+ PID_KEY_HASH for keyed]
+ PID_SENTINEL) ahead of the payload. The relay writer still assigns its OWN SN (its HistoryCache/reliability
unchanged); the ORIGINAL identity rides in inline QoS — exactly what RTI Persistence Service emits (spike §3),
so a foreign late-joiner dedups our relayed samples against the original writer.

**Receive (dedup).** On inbound DATA, the inline-QoS parser additionally extracts PID_ORIGINAL_WRITER_INFO
when present → `(originalGUID, originalSN)`. A per-reader map tracks `max-received-SN[originalGUID]`:
- PID present → key by `originalGUID`; accept iff `originalSN > max`, else DISCARD (duplicate — a second
  relay, or the original writer + a relay both matched).
- PID absent (normal direct writer) → unchanged per-writer-GUID SN tracking; the dedup map untouched.
- The original writer's own direct samples map `writerGUID → itself`, so a relay's `originalGUID` collides on
  the same key — the max-SN check collapses both sources to one logical stream (spike §3.4).

**Conformance guardrails:**
- **No false-reject / no silent loss:** dedup discards ONLY a sample with `originalSN ≤ max` for the SAME
  `originalGUID` (a true duplicate). A malformed/short PID body is bounds-checked → treated as "no PID" (fall
  through to normal tracking), never OOB, never a dropped fresh sample.
- **Inert by default:** absent the PID, emit + receive are byte-identical to today; `make mem` stays 0.0000
  (the PID encode/parse is off the measured CDR codec, on the relay/discovery path).
- The RTI vendor SEDP PIDs (`PID_ENTITY_VIRTUAL_GUID 0x8002`, `PID_SERVICE_KIND 0x8003`, …) are NOT emitted —
  the spike confirmed they are unnecessary for correctness; a deliberate documented non-goal.

## 6. Multi-topic (N disc-nodes per service)

`make-durability-service` generalizes: a `service-spec` whose `topics` resolves to K concrete `(topic . type)`
pairs makes the service hold K disc-nodes (each the existing single-endpoint collect-reader + replay-writer),
sharing the per-topic store (each node tags its puts with its topic). `service-start` starts all K nodes + a
collect loop per node; `service-stop` joins/stops all K (the Phase-1 join-before-stop-node ordering preserved
per node). The supervisor monitors the service as a unit (a dead service restarts all its nodes — one-for-one
at service granularity, matching Phase 1). K=1 is byte-identical to Phase 1. A predicate-topic spec resolves
concrete topics matched AT/AFTER start; **dynamic topic-add after start is a documented deferral** (the
periodic re-announce + match hook already discover late peers, but spinning up a new node for a
newly-discovered topic mid-run is a Phase-2b refinement).

## 7. Dispose/unregister capture + replay

The receive path already exposes lifecycle changes (`node-lifecycle-change` → `(kind key-hash status-flags
writer-id source-guid)`, `disc-node-on-lifecycle` hook). The collect loop drains lifecycle changes into the
store as `durable-record`s with `kind ∈ {:dispose,:unregister}` keyed by the original `(writerGUID, SN,
key-hash)`. Replay re-emits them in original-SN order interleaved with data via `writer-lifecycle-change`
(which builds a no-payload dispose/unregister DATA with inline QoS — Phase 2 adds PID_ORIGINAL_WRITER_INFO to
that path too, so a disposed instance dedups identically). A late-joiner thus sees an instance was
disposed/unregistered before it joined — the correct DDS durable instance-state.

## 8. Error handling

All new parse paths bounds-checked (NFR-SEC-POSTURE): a PID_ORIGINAL_WRITER_INFO with wrong length or a body
overrunning the submessage → treated as "no PID" (fall through to normal SN tracking), never OOB, never a
dropped fresh sample; fuzzed at `(safety 0)`. The dedup map is bounded by the number of distinct original
GUIDs a reader matches (not per-sample growth). Multi-node collect/replay keeps the Phase-1 per-iteration
error guard PER node; one node's fault is counted + isolated, never kills the service.

## 9. Testing strategy

- **Unit / byte-exact:** PID encode→decode round-trip + a byte-exact vector pinned to the spike capture's hex
  (the conformance crux); the dedup max-SN logic (accept-fresh / discard-duplicate / PID-absent-untouched);
  multi-node store isolation; dispose/unregister capture+replay ordering.
- **Integration (our-stack):** the headline NO-DOUBLE-DELIVERY — the original writer stays ALIVE, the service
  relays the same samples, a reader matched to BOTH receives each sample exactly once (the Phase-1 deferral).
  Plus dispose-replay (late-joiner sees a pre-join dispose) and a 2-topic service.
- **Cross-DDS DoD (both peers):** (a) a foreign Connext/Fast DDS late-joiner receives our relayed history with
  PID_ORIGINAL_WRITER_INFO byte-exact on the wire (tshark); (b) FOREIGN-SERVICE COEXISTENCE — RTI Persistence
  Service AND our service on the same TRANSIENT topic; a late-joiner matched to both receives no duplicates
  (our `originalGUID` matches RTI's). RTI PS is runnable here (spike §1).
- **Gates:** ≥ the current 266 green SBCL+Clasp; gate-hotpath / gate-types / mem (0.0000) / fuzz (+ a PID arm)
  / wire all green; a byte-exact corpus vector for the PID if warranted.

## 10. Vertical-slice implementation ordering

1. **PID_ORIGINAL_WRITER_INFO codec** — constant + encoder + parser extension + byte-exact vector vs the spike
   hex. No behavior change.
2. **Outbound inline-QoS on `write-data`** — extend + Q-bit; default-nil byte-identical (gate: existing wire
   tests unchanged).
3. **Relay emit** — service replay attaches the PID from the store; foreign late-joiner receives it byte-exact
   (cross-DDS leg A).
4. **Receiver-side dedup** — the map + discard logic; our-stack no-double-delivery (original-alive + relay).
5. **Multi-topic (N nodes)** — K-node service; 2-topic integration test.
6. **Dispose/unregister capture + replay** — collect lifecycle → store → replay; late-joiner-sees-dispose.
7. **Foreign-service coexistence + capstone** — live RTI PS + our service no-double-delivery (cross-DDS
   leg B); ADR 0024; docs lockstep; full gate sweep; final whole-branch review.

Each slice: implement → 2 reviews/task → gates → cross-DDS where applicable → autonomous branch commits →
final whole-branch review → squash-merge presented for approval, push held.

## 11. Out of scope (this slice)

- The PERSISTENT slice: disk-backed store surviving restart + the always-on CNSA-2.0 DARE (ADR 0021 cap. 7) —
  slice 3.
- Dynamic topic-add after a multi-topic service has started (Phase-2b).
- Emitting the RTI vendor SEDP PIDs (`PID_ENTITY_VIRTUAL_GUID` etc.) — confirmed unnecessary for dedup.
- The long-running `seen`-table prune + `:process` supervisor-opt propagation (Phase-1 accept-Minors) — carry
  forward unless trivially folded.
- The rest of the Connext Professional service suite stays out (ADR 0021).
