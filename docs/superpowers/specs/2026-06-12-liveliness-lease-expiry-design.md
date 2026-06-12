# Liveliness + lease expiry (participant lease + the Writer Liveliness Protocol)

- **Date:** 2026-06-12
- **Status:** Design — approved for planning.
- **Area:** L5 discovery (`src/dds-disc/disc.lisp`, a new participant-message endpoint module), L4 RTPS (`src/dds-rtps` — the ParticipantMessageData codec + entity ids), L6 DCPS (`src/dds-dcps/{entities,statuses,listeners}.lisp`), L3 QoS (`src/dds-qos` — already has LIVELINESS), `dds-tests`, `interop/connext/`.
- **Requirements:** FR-RTPS (the M3-deferred liveliness/lease residual), FR-DCPS (LIVELINESS_CHANGED / LIVELINESS_LOST statuses + PUBLICATION/SUBSCRIPTION_MATCHED decrement), FR-IO-1 (Connext interop), the operating contract §4 (the wire is the oracle).

## 1. Goal & scope

Two distinct, both-mandatory DDS/RTPS mechanisms, neither implemented today:

1. **Participant lease expiry** (RTPS 2.5 §8.5.3.3.2): the SPDP reader removes a discovered participant whose SPDP has not been refreshed within its announced `leaseDuration`, removing it and all its endpoints. Today `disc-node-discovered` is never pruned (no last-seen timestamp, no sweep), so a vanished peer's endpoints/matches/builtin-readers leak and matched-counts never decrement.
2. **The Writer Liveliness Protocol (WLP)** (RTPS 2.5 §8.4.13 — *"All implementations must support the Writer Liveliness Protocol in order to be interoperable"*): the builtin `BuiltinParticipantMessageWriter`/`Reader` (RELIABLE) exchange `ParticipantMessageData` to assert the liveliness of a participant's AUTOMATIC and MANUAL_BY_PARTICIPANT DataWriters; a matched DataReader declares a writer not-alive (`LIVELINESS_CHANGED`) if it receives no assertion within the writer's LIVELINESS `lease_duration`, and a writer that fails to assert fires `LIVELINESS_LOST`. None of this builtin exists today.

In scope: participant-lease pruning + the unmatch/status path; the WLP builtin endpoints + `ParticipantMessageData` codec + periodic assertion + reader-side liveliness timing; the `LIVELINESS_CHANGED`/`LIVELINESS_LOST` status structs + `assert-liveliness` API; live Connext verification.

Out of scope (documented gaps): MANUAL_BY_TOPIC liveliness (RTPS §8.7.2.2.3, the inline-per-DataWriter mechanism — distinct from the BuiltinParticipantMessage WLP; the HEARTBEAT liveliness flag already exists in `dds-rtps` as the substrate but the per-topic timing is deferred); a dedicated background liveliness thread (the existing caller-driven announce cadence is the hook).

## 2. Decisions (locked during brainstorming, owner-approved)

1. **Full WLP conformance** (owner pick over the SPDP-lease-only approximation, which is non-conforming): implement RTPS §8.4.13 properly, so liveliness is interoperable + live-verifiable against Connext.
2. **Both halves**: S0 participant-lease expiry (the unmatch path) + S1 the WLP (liveliness assertion + timing) + writer self `LIVELINESS_LOST`.
3. **On the existing announce cadence** (Approach A): `%lease-sweep` and the liveliness sweeps run from `announce-endpoints`/`announce-participant` next to `tl-sweep` — no new thread. Rejected: a dedicated liveliness timer thread (lock complexity for a cadence that already exists).
4. **MANUAL_BY_TOPIC deferred** as a documented sub-gap (§8.7.2.2.3 inline mechanism, distinct from the WLP builtin).

## 3. Normative anchors (pin from `docs/specs/rtps-2_5.pdf` via pdftotext at implementation time; cite the clause in code, never from memory)

- **Participant lease**: §8.5.3.3.2 (stale-entry removal: "not refreshed for a period longer than their specified leaseDuration"); §8.5.4 (lease duration semantics); the SPDP `leaseDuration` field.
- **WLP**: §8.4.13.2 (the builtin endpoints `ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_WRITER`/`READER` — pin the EntityId octets from RTPS Table 9.4 §9.3.2); §8.4.13.3 (RELIABLE writer); §8.4.13.4 + §9.6.x (the `ParticipantMessageData` datatype: `participantGuidPrefix: GuidPrefix_t` + `kind: octet[4]` + `data: sequence<octet>`; the DDS key = participantGuidPrefix + kind); §8.4.13.5 (write one AUTOMATIC instance faster than the smallest AUTOMATIC lease; a separate MANUAL_BY_PARTICIPANT instance; the kind octets `PARTICIPANT_MESSAGE_DATA_KIND_AUTOMATIC` / `_MANUAL_BY_PARTICIPANT` — pin from §9.6.x).
- **Builtin endpoint-set bits**: the `BUILTIN_PARTICIPANT_MESSAGE_DATA_WRITER`/`READER` bits in `PID_BUILTIN_ENDPOINT_SET` (RTPS Table 9.4) — added to our SPDP announcement so peers know we run the WLP.
- **DDS statuses**: DDS 1.4 — `LivelinessChangedStatus` (alive_count, not_alive_count, *_change, last_publication_handle); `LivelinessLostStatus` (total_count, total_count_change). Pin field names from `dds_rtf2_dcps.idl`.
- All wire constants/bytes byte-verified against a live Connext 7.3.1 capture before being locked (the operating contract §4).

## 4. Architecture & components

**S0 — participant lease expiry (disc + DCPS):**
- *disc*: a per-participant last-seen stamp (a parallel `prefix → internal-real-time` hash on the disc-node, or pair the discovered value); `%record-participant` stamps `now`. `%lease-sweep node` (called from `announce-endpoints` beside `tl-sweep`) finds participants whose `last-seen + leaseDuration < now`, and under the node lock removes: the `discovered` entry, every `discovered-writers`/`discovered-readers` endpoint with that prefix, every `matches` entry with that prefix, and the `builtin-readers[prefix]` entry — collecting the removed matched endpoints, then OUTSIDE the lock invokes a new `on-unmatch` disc-node hook per removed match with `(direction remote)`.
- *DCPS*: installs `on-unmatch` → a vanished remote writer matched to a local reader decrements `SUBSCRIPTION_MATCHED` (current_count -1, current_count_change -1) + fires `on-subscription-matched`; a vanished remote reader matched to a local writer decrements `PUBLICATION_MATCHED` + fires `on-publication-matched`. (LIVELINESS_CHANGED on participant loss is folded in via S1's reader-side machinery, since participant loss ⇒ its writers are no longer alive.)

**S1 — Writer Liveliness Protocol (rtps + disc + DCPS):**
- *rtps* (`src/dds-rtps`): the `ParticipantMessageData` codec (serialize/deserialize, bounds-checked) + the `ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_WRITER`/`READER` constants + the kind octets + the endpoint-set bits.
- *disc* (`src/dds-disc/participant-message.lisp`, a new module mirroring `typelookup-endpoints.lisp`): the builtin participant-message writer/reader on the disc-node (RELIABLE writer); periodic assertion writing on the announce cadence — if the participant has ≥1 local AUTOMATIC writer, write the AUTOMATIC instance faster than the smallest AUTOMATIC lease; likewise a MANUAL_BY_PARTICIPANT instance; inbound `ParticipantMessageData` refreshes the per-remote-prefix liveliness stamp.
- *disc reader-side timing*: per matched remote writer, a last-liveliness stamp (refreshed by an inbound ParticipantMessage of the matching kind, by data from that writer, or — participant loss — pruned by S0); a `%liveliness-sweep` fires the reader-side `on-liveliness-changed` hook when `last-liveliness + writer's lease_duration < now`.
- *DCPS*: new `liveliness-changed-status` (DataReader slot) + `liveliness-lost-status` (DataWriter slot) structs (in `statuses.lisp`, mirroring the matched-status pattern); the `on-liveliness-changed` hook bumps the reader status + fires the listener; `assert-liveliness` (DataWriter API) stamps the writer's last-assertion; a writer `%liveliness-lost-sweep` fires `LIVELINESS_LOST` when `last-assertion + qos-liveliness-lease < now` (AUTOMATIC writers are stamped by the announce-cadence assertion, so they only go lost if the participant stops announcing).

## 5. Data flow

SPDP refresh → `%record-participant` stamps last-seen. WLP: the participant writes ParticipantMessageData (AUTOMATIC/MANUAL instances) on the cadence; a peer's inbound ParticipantMessage refreshes our per-remote-writer liveliness stamps. Each announce cadence runs `%lease-sweep` (participant removal → `on-unmatch` → MATCHED -1) and the two liveliness sweeps (`%liveliness-sweep` reader-side → LIVELINESS_CHANGED; `%liveliness-lost-sweep` writer-side → LIVELINESS_LOST). Table mutation under the node lock; all hooks/listeners fired outside the lock (the established discipline).

## 6. Error handling & edges

- The lease/lease_duration values are the **remote's announced** values (participant `leaseDuration` for S0; the matched writer's LIVELINESS `lease_duration` for the reader-side timing); clock = `internal-real-time`. Pruning + status firing are idempotent (a re-discovered participant re-adds; `%record-match` already fires-once).
- A participant loss (S0) implies its writers are not alive: the unmatch path also feeds the reader-side liveliness (a matched writer removed by participant loss → LIVELINESS_CHANGED not-alive) so the two halves agree.
- Bounds-check every `ParticipantMessageData` wire read (NFR-SEC-POSTURE); a malformed message is dropped, never an error escape.
- Default lease durations are long (SPDP 100 s); tests use short leases. AUTOMATIC LIVELINESS_LOST is a degenerate case (fires only if the participant stops announcing) — asserted by the cadence by construction.

## 7. Testing

- **S0 offline**: inject a discovered participant (stale last-seen) with a matched remote writer + reader; run `%lease-sweep`; assert the participant + its endpoints + matches + builtin-reader are removed AND `SUBSCRIPTION_MATCHED`/`PUBLICATION_MATCHED` decremented + the listeners fired.
- **S1 offline**: ParticipantMessageData codec round-trip + a locked byte vector; two-node UDP loopback — node A's AUTOMATIC writer asserts via the WLP, node B's reader stays alive; stop A's assertions → B's `%liveliness-sweep` fires `LIVELINESS_CHANGED` after the lease; a short-lease writer with no `assert-liveliness` fires `LIVELINESS_LOST`, and `assert-liveliness` resets it.
- **Live Connext (S2)**: (a) participant kill-test — Connext shapes_pub ↔ our sub (short lease), kill Connext, confirm our stack prunes it + `SUBSCRIPTION_MATCHED -1`; (b) WLP round-trip — we receive Connext's ParticipantMessage liveliness assertions (our reader stays alive while Connext runs; goes not-alive when Connext's writer stops asserting) and Connext receives ours (tshark shows our ParticipantMessageData on the builtin endpoint, byte-validated). Captures archived.
- Suite green SBCL per task + Clasp at stage boundaries; `make gate-types`/`gate-hotpath` green (control-plane); the `ParticipantMessageData` codec is bounds-checked + fuzzed if it joins the RTPS parser fuzz target.

## 8. Stages (commit boundaries)

- **S0 — participant lease expiry.** last-seen stamp + `%lease-sweep` + `on-unmatch` disc hook + DCPS MATCHED(-1) decrement path. Offline test. Exit: a stale participant is pruned and matched-counts decrement; suite green SBCL+Clasp.
- **S1 — Writer Liveliness Protocol.** `ParticipantMessageData` codec + entity ids + endpoint-set bits (rtps); the participant-message builtin endpoints + periodic AUTOMATIC/MANUAL_BY_PARTICIPANT assertion + reader-side liveliness timing (disc); `LIVELINESS_CHANGED`/`LIVELINESS_LOST` statuses + `assert-liveliness` + the two sweeps (DCPS). Offline codec vector + two-node liveliness tests. Exit: WLP liveliness works stack-to-stack; suite green.
- **S2 — closeout + live Connext.** The participant kill-test + the WLP liveliness round-trip vs Connext 7.3.1 (byte-validated); verification.csv FR-RTPS/FR-DCPS, wiki, README, provenance, memory. Exit: live liveliness interop both ways; docs lockstep; gates green.

## 9. Definition of Done

A vanished participant is pruned within its `leaseDuration` and the affected local endpoints' PUBLICATION/SUBSCRIPTION_MATCHED decrement + fire their listeners. The Writer Liveliness Protocol (§8.4.13) is implemented for AUTOMATIC + MANUAL_BY_PARTICIPANT: we assert our writers' liveliness via the BuiltinParticipantMessage endpoints and time matched remote writers, firing `LIVELINESS_CHANGED` (reader) and `LIVELINESS_LOST` (writer) per the LIVELINESS `lease_duration`; `assert-liveliness` resets the writer timer. Verified live vs Connext 7.3.1 both directions (participant kill + WLP liveliness round-trip, byte-validated). MANUAL_BY_TOPIC remains a documented sub-gap. Suite green SBCL+Clasp; gate-types + gate-hotpath green; docs in lockstep.
