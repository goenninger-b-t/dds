# DCPS API completion (DDS 1.4) — design

**WP family:** WP-DCPS-API-COMPLETION (S0–S7)
**Date:** 2026-07-09
**Status:** approved decomposition (owner, 2026-07-09) — proceed to implementation plan.
**Source of gaps:** the 2026-07-09 DCPS completeness audit (verified by spot-check); `docs/verification.csv` `FR-DCPS-2`/`FR-DCPS-3` = partial.

---

## 1. Problem

The stack's DCPS *application-facing* API is a thin vertical slice: the wire/RTPS/XTypes/Security/Durability layers are deep and cross-vendor-validated, but the DCPS entity/listener/QoS-management surface is materially incomplete against OMG DDS 1.4. Concretely (audit + spot-check):

- **Listeners:** only 3 of 6 interfaces exist (DataReader/DataWriter/Topic). No Subscriber/Publisher/DomainParticipant listener; `on_data_on_readers` entirely absent; no listener propagation up the containment hierarchy.
- **QoS:** no `get_qos`/`set_qos` on any entity; no `IMMUTABLE_POLICY`/`INCONSISTENT_POLICY`; no default-QoS.
- **Entity lifecycle:** no `DomainParticipantFactory` object; no `enable`/disabled-entity semantics; no `delete_datawriter/datareader/publisher/subscriber/topic` (only `delete_participant`); no `delete_contained_entities`.
- **Statuses:** OFFERED/REQUESTED_DEADLINE_MISSED and SAMPLE_LOST never fire (no deadline monitor; two have no status struct). DATA_ON_READERS absent.
- **Reader/Writer ops:** no `get_key_value`/`lookup_instance`, `read/take_instance`, `read/take_next_sample`, `get_matched_publications/subscriptions(_data)`, timestamped writes.
- **Introspection:** no `get_status_changes`, no entity-owned `get_statuscondition`, `get_listener` set-only.
- **Fenced multiplicity:** secured/ZC same-topic multi-reader/multi-writer are fail-fast-deferred; discovery is manual (`spin`), not autonomous.

This design closes **all** of these, decomposed bottom-to-top into 8 vertical slices, each independently demonstrable and testable.

## 2. What already works (reuse, do not rebuild)

- The 6 entity CLOS classes (`entities.lisp`) and create paths.
- The status *bit constants* (`statuses.lisp`) and the existing status structs for the 10 statuses that do fire; the engine trigger sites for match / incompatible-QoS / liveliness / sample-rejected / inconsistent-topic.
- Conditions/WaitSet/GuardCondition/ReadCondition/QueryCondition (`conditions.lisp` + `filter.lisp` — a real SQL-subset lexer/parser) and ContentFilteredTopics.
- The listener-mask firing pattern (`(when (and (dr-listener dr) (member :x (dr-listener-mask dr))) (on-x …))`).
- The N-user-endpoint infrastructure (ADR 0048: per-endpoint registries, per-endpoint crypto, per-reader decode pools) — S6 extends it to the fenced secured/ZC same-topic cases.
- The PAL threading primitives (`bordeaux-threads` + `dds.pal` locks/condvars, already used by receiver threads and the durability service).

## 3. Cross-cutting design decisions

1. **Reuse the status/condition machinery.** S0 formalizes the per-entity status-changes model the listener-mask + StatusCondition already half-use; the firing sites become a single shared `%notify-status` chokepoint, not a parallel system.
2. **Threading is available on both impls.** Owner directive 2026-07-09: **Clasp has no threading limitations.** So S4's deadline monitor and S7's discovery use real background threads (via `dds.pal`), not a `spin`-only workaround. (Supersedes the earlier `clasp-threading-gap` caution.)
3. **Additive, non-breaking.** Manual `spin` keeps working; S7 adds an autonomous mode alongside it (config/QoS-gated), so existing tests/harnesses are unaffected. New API is additive; existing exported symbols keep their contracts (any change → ADR).
4. **MVP-first per slice.** Each slice delivers the thinnest end-to-end increment first, then grows; each ends with a passing test on **both impls (Clasp first)** and the applicable gates green.
5. **Spec-pinned, no invented constants.** Status struct fields, QoS immutability/consistency rules, return codes, and the listener-propagation rule are pinned to the OMG DDS 1.4 clause and cited in docstrings.
6. **Hot-path untouched.** This is application-API work; the measured hot path (CDR/codec/engine per-sample) stays byte-identical and zero-alloc. `make gate-hotpath` stays green.

## 4. The 8 slices (bottom → top)

### S0 — Status & introspection foundation
Add the 3 missing status structs (`sample-lost-status`, `offered-deadline-missed-status`, `requested-deadline-missed-status`) with the exact DDS 1.4 IDL fields. Add a per-entity **status-changes bitmask** + `get_status_changes`. Make `StatusCondition` **entity-owned** (`get_statuscondition` + `set_enabled_statuses`/`get_enabled_statuses`) wired to the bitmask. Implement the **read-communication-status reset** rule (DDS §2.2.2.1.9: reading a plain-communication-status via its getter resets `total_count_change`/`current_count_change` and clears the status-changed bit). Route every existing status trigger through one `%notify-status entity status-kind status-obj` chokepoint that (a) updates the struct, (b) sets the bitmask bit, (c) triggers the StatusCondition, (d) calls the listener (per S3 once S3 lands; per the current single-entity listener until then). **Demo:** `get_status_changes` reflects a match then clears on read; an entity's StatusCondition wakes a WaitSet. **Depends on:** nothing (foundation).

### S1 — QoS get/set + consistency
`get_qos`/`set_qos` on all entities + Topic. A policy **immutability table** (DDS §2.2.3: which policies are immutable after `enable`) → `IMMUTABLE_POLICY` on a post-enable mutation. A **consistency validator** (the spec's `INCONSISTENT_POLICY` combinations: e.g. HISTORY KEEP_LAST `depth ≤ RESOURCE_LIMITS.max_samples_per_instance`, `max_samples_per_instance ≤ max_samples`, DEADLINE `period ≥ TIME_BASED_FILTER.minimum_separation`, …). Default-QoS getters/setters (`get/set_default_{datawriter,datareader,topic,publisher,subscriber,participant}_qos`). **Demo:** pre-enable set succeeds; post-enable immutable set → `IMMUTABLE_POLICY`; inconsistent combo → `INCONSISTENT_POLICY`. **Depends on:** S0 (some set_qos paths raise statuses); the immutability check needs S2's `enable` state — so S1 defines the table + validator and applies immutability using a provisional "enabled" flag that S2 formalizes.

### S2 — Entity lifecycle
`DomainParticipantFactory` singleton: `get_instance`, `create_participant`/`delete_participant`/`lookup_participant`, `get/set_default_participant_qos`, factory `set_qos` (with `ENTITY_FACTORY`). `enable()` + disabled-entity semantics (`autoenable_created_entities`; operations restricted to `NOT_ENABLED`-safe set while disabled). A **parent→children registry** (participant→{publishers,subscribers,topics}; publisher→datawriters; subscriber→datareaders). `delete_datawriter/datareader/publisher/subscriber/topic` with `PRECONDITION_NOT_MET` (non-empty publisher, still-referenced topic) and `delete_contained_entities()` (recursive teardown). **Demo:** create→enable→use→delete lifecycle; `delete_contained_entities` tears down a participant's whole tree; deleting a non-empty publisher is refused. **Depends on:** S1 (default QoS on create), S0.

### S3 — The full listener model
Add `subscriber-listener` (adds `on_data_on_readers`), `publisher-listener`, `domain-participant-listener` (aggregates all callbacks). Listener slot + `set_listener`/`get_listener` on Publisher, Subscriber, DomainParticipant; `get_listener` on Reader/Writer/Topic (currently set-only). `on_data_on_readers` + `Subscriber::get_datareaders` (readers with new data, per SampleStateMask) + `notify_datareaders` (invoke `on_data_available` on each). **Listener propagation** (DDS §2.2.4.1): the `%notify-status` chokepoint walks Entity → parent → DomainParticipant, delivering the status to the **most specific enabled** listener (mask has the bit) and stopping there; if none enabled, the status-changed bit stays set and no callback fires. `on_data_on_readers` precedence: if the Subscriber listener handles `DATA_ON_READERS`, the readers' `on_data_available` is **not** invoked. **Demo:** a participant listener catches `on_publication_matched` when the writer's listener is nil; `on_data_on_readers` fires and suppresses `on_data_available`. **Depends on:** S0 (chokepoint + bitmask), S2 (containment registry for the walk).

### S4 — Deadline monitoring + SAMPLE_LOST
A **deadline monitor** on a `dds.pal` background timer thread: per-writer-instance offered-deadline and per-reader-instance requested-deadline timers (a sorted deadline queue / timer wheel keyed by next-expiry). On expiry with no intervening write/sample for that instance, fire OFFERED/REQUESTED_DEADLINE_MISSED via the S3 chokepoint with a populated status (`total_count`, `total_count_change`, `last_instance_handle`). **SAMPLE_LOST** detection + fire: a sample determined permanently lost (KEEP_LAST overwrite-before-delivery; an unrecoverable gap under the reliability/history) → `on_sample_lost` + status. **Demo:** a writer that stops writing within its offered-deadline period fires `on_offered_deadline_missed`; a reader whose deadline elapses fires `on_requested_deadline_missed`; both statuses populate and reset per S0. **Depends on:** S3 (propagation), S0 (structs + chokepoint), S1 (DEADLINE QoS).

### S5 — Instance & sample-access + matched-entity introspection
`get_key_value(handle)→key` and `lookup_instance(key)→handle` on writer + reader (reuse the keyhash/key-field machinery). `read_instance`/`take_instance`, `read_next_instance`/`take_next_instance`, `read_next_sample`/`take_next_sample` (compose over the existing `read/take` + instance filter). `get_matched_publications`(reader)/`get_matched_subscriptions`(writer)→handles + `get_matched_publication_data`/`get_matched_subscription_data`→builtin-topic-data (from the discovery match tables). Timestamped writes: `write_w_timestamp`, `dispose_w_timestamp`, `unregister_instance_w_timestamp`, `writedispose` (thread the source_timestamp into the existing write path's `PID_...`/inline-QoS). **Demo:** `lookup_instance`→`read_instance` filters to one instance; `get_matched_subscriptions` lists the reader; a `write_w_timestamp` carries the given source timestamp on the wire. **Depends on:** S0; mostly independent of S3/S4.

### S6 — Secured / ZC same-topic multi-endpoint
Lift the fail-fast fences (`entities.lisp:1442/1448`; `verification.csv FR-DCPS-N-READERS` "Secured/ZC S3/S4 multi-reader fail-fast/deferred"): support **same-topic** multi-reader and multi-writer under `data_protection`/`rtps_protection` and under Zero-Copy/SHMEM, extending the ADR-0048 N-endpoint per-endpoint crypto + per-reader decode pools + cross-reader UAF handling to the same-topic case. Engine-level; adversarial review for the security/UAF surface. **Demo:** two secured readers on one topic in one participant each decode correctly; two ZC writers on one topic share/allocate slots without aliasing. **Depends on:** the existing N-endpoint infra; independent of S0–S5 (can proceed in parallel, sequenced here for review focus).

### S7 — Autonomous background discovery
Add an **autonomous discovery mode** (config/QoS-gated, alongside manual `spin`): a background SPDP announcer thread (periodic participant announcement + lease duration), the SEDP publication/subscription announcers, and a discovery receive/aging loop (participant lease expiry → purge). Real participant liveliness. `spin` remains for the deterministic test path. **Demo:** two participants in autonomous mode discover and match each other and exchange data with **no** app-driven `spin` call; a killed participant is aged out after its lease. **Depends on:** the discovery layer; placed last because it is an additive alternative to `spin` (lowest inversion risk) and changes harness assumptions.

## 5. Slice dependency graph

```
S0 (status/introspection)
├─ S1 (QoS) ─ S2 (lifecycle) ─ S3 (listeners) ─ S4 (deadline/sample-lost)
├─ S5 (instance ops)        ── (uses S0)
S6 (secured/ZC same-topic)  ── (uses N-endpoint infra; parallelizable)
S7 (autonomous discovery)   ── (additive; last)
```
Critical path: S0 → S1 → S2 → S3 → S4. S5 branches off S0. S6/S7 are the two heavyweights, sequenced after the API surface for review focus; S6 is independent enough to parallelize if desired.

## 6. Testing & gates (every slice)

- New unit/integration tests per slice, **both impls (Clasp first)**, non-vacuous, following the repo's `run-*-test` pattern; register in the suite.
- `make test` full-suite green; `make gate-hotpath` green (no per-sample alloc/CLOS added to the measured hot path); `make corpus` unchanged (no wire-format change except S5 timestamped-write source_timestamp and S7 SPDP/SEDP cadence, both spec-pinned and interop-checked).
- **Cross-DDS interop per the standing rule** for any slice with a wire surface: S5 timestamped writes (`PID_...`), S6 secured same-topic, S7 SPDP/SEDP cadence must be checked live vs **both** Connext 7.3.1 and Fast DDS. S0–S4 are local-API (no new wire) → interop satisfied by "no observable wire change."
- Docs lockstep: docstrings on every new exported symbol; `docs/wiki/` DCPS/API pages; `README.md` status; `docs/verification.csv` rows (flip `FR-DCPS-2/3` from partial → done as slices land); ADRs for any contract change (the new API is additive, but S2's factory/enable and S3's propagation change entity semantics → ADR).

## 7. Non-goals

- The Connext *Professional* service suite (Routing/Recording/Cloud-Discovery/Admin-Console/Monitor) — out of scope per the operating contract (durability service excepted, already built).
- QoS *policies* not already supported on the wire are not newly wire-implemented here; S1 adds get/set/validation for the policy *set the stack already models*. A policy whose runtime enforcement is absent is validated + stored, with its enforcement gap recorded (not silently claimed).
- AllegroCL PAL (3rd impl) stays out (NFR-PORT; SBCL + Clasp only).

## 8. Definition of Done (the program)

All 8 slices shipped; `FR-DCPS-*` flipped to done in `docs/verification.csv`; the DCPS audit re-run shows the enumerated gaps closed; both impls green; hot-path + corpus gates green; S5/S6/S7 live-interop-validated vs Connext + Fast DDS; ADRs + wiki + README updated; SBOM current. Each slice individually meets the §5 Definition of Done in the operating contract before the next begins.
