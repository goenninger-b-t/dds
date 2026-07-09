# DCPS API completion (DDS 1.4) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close all DDS 1.4 DCPS application-API gaps (listeners, QoS mgmt, entity lifecycle, statuses, instance ops, secured/ZC same-topic multiplicity, autonomous discovery), bottom-to-top, in 8 independently-demonstrable vertical slices.

**Architecture:** Additive, non-breaking extensions to the existing `src/dds-dcps/` CLOS entity layer. Reuse the existing status-bit/condition/waitset machinery and the ADR-0048 N-endpoint infrastructure; introduce one shared `%notify-status` chokepoint (S0) that every later slice hooks. Background threads used freely on both impls.

**Tech Stack:** Common Lisp (SBCL + Clasp), `dds.dcps` package, `dds.pal` threading/lock primitives, the existing `dds.qos`/`dds.disc`/`dds.rtps.*` layers.

**Design doc:** `docs/superpowers/specs/2026-07-09-dcps-api-completion-design.md` (approved 2026-07-09).

## Global Constraints

- **Both SBCL and Clasp validate identically, Clasp FIRST.** Clasp binary via `scripts/with-clasp.sh` / `make *-clasp`. **Clasp has NO threading limitation** (owner 2026-07-09) — background threads (`dds.pal`) are fine on both. Never call `static-vectors:make/free-static-vector` directly; always `dds.pal:alloc-static`/`free-static`.
- **`defun*` for every function with full parameter type declarations; `defstruct*` for every struct** (`dds.lang`).
- **No wire constant / status field / QoS rule invented from memory** — pin every status-struct field, StatusKind bit, QoS immutability/consistency rule, and return code to the OMG DDS 1.4 IDL/spec clause (`docs/specs/dds_rtf2_dcps.idl`) and cite it in the docstring. This is a clean-room rule.
- **Hot path untouched:** the measured per-sample CDR/codec/engine path stays byte-identical + zero-alloc; `make gate-hotpath` stays green every slice.
- **Additive / non-breaking:** manual `spin` keeps working; existing exported symbols keep their contracts. A semantics change (S2 factory/enable, S3 propagation) requires an ADR listing consumers.
- **Every added exported symbol carries a docstring;** update `docs/wiki/` + `README.md` + `docs/verification.csv` in lockstep (flip `FR-DCPS-2/3` partial→done as slices land).
- **Cross-DDS interop per feature** for any slice with a wire surface (S5 timestamped writes, S6 secured same-topic, S7 SPDP/SEDP cadence): live vs BOTH Connext 7.3.1 AND Fast DDS. S0–S4 are local-API (no new wire) → satisfied by "no observable wire change" + existing interop tests green.
- **SBOM** auto-regenerated + staged by the pre-commit hook; never hand-edit.
- **Commit messages** presented for owner approval before committing; no AI-attribution trailer; approval implies push.

## How this plan is structured

This is a **program** of 8 slices. **S0 is detailed to TDD-step level** (the immediate next work). **S1–S7 are specified to task level** — each task names its files, the interfaces it produces (exact signatures), and its test — and each slice will be **expanded to a full TDD-step plan when reached** (the same way the ZC-SHMEM-overlay WP was executed). Execute slices **in order**; each slice's exit gate must pass before the next begins (operating contract §5).

---

# Slice S0 — Status & introspection foundation

**Goal:** the missing status structs + a per-entity status-changes bitmask + entity-owned StatusCondition + read-reset semantics + one `%notify-status` chokepoint every status flows through.

**Files:**
- Modify: `src/dds-dcps/statuses.lisp` (add 3 structs)
- Modify: `src/dds-dcps/entities.lisp` (status-changes slot on each entity; `%notify-status`; refactor the ~11 firing sites; `get-status-changes`; read-reset in the status getters)
- Modify: `src/dds-dcps/conditions.lisp` (entity-owned StatusCondition; `set/get-enabled-statuses`)
- Modify: `src/dds-dcps/packages.lisp` (exports)
- Test: `src/dds-dcps/` test file (follow the repo `run-*-test` pattern; register in `src/dds-tests/echo-test.lisp`)

**Interfaces produced:**
- `sample-lost-status`, `offered-deadline-missed-status`, `requested-deadline-missed-status` structs.
- `get-status-changes entity → (unsigned-byte 32)` (StatusMask of changed-since-last-read statuses).
- `%notify-status entity status-bit status-obj → t` (internal chokepoint: update struct slot, set bitmask bit, trigger StatusCondition, fire listener).
- `get-statuscondition entity → status-condition`; `set-enabled-statuses sc mask`/`get-enabled-statuses sc`.

- [ ] **S0.T1 — Add the 3 missing status structs.** Write a failing test asserting `make-sample-lost-status` / `make-offered-deadline-missed-status` / `make-requested-deadline-missed-status` exist with their spec fields. Run Clasp-first → FAIL (undefined). Implement in `statuses.lisp` mirroring the existing `defstruct*` style, fields pinned to `dds_rtf2_dcps.idl` (SampleLostStatus: `total-count`, `total-count-change`, and the `last-reason` SampleLostStatusKind if the RTF2 IDL carries it — read the clause; DeadlineMissed: `total-count`, `total-count-change`, `last-instance-handle`). Export from `packages.lisp`. Run Clasp+SBCL → PASS. Commit.

```lisp
;; statuses.lisp — pin fields + clause from docs/specs/dds_rtf2_dcps.idl; mirror the existing structs
(defstruct* (sample-lost-status (:constructor make-sample-lost-status) (:copier copy-sample-lost-status))
  "DataReader SAMPLE_LOST status (dds_rtf2_dcps.idl §<pin>)."
  (total-count 0 :type integer)
  (total-count-change 0 :type integer))   ; + last-reason if the RTF2 IDL defines SampleLostStatusKind — read the clause
(defstruct* (offered-deadline-missed-status (:constructor make-offered-deadline-missed-status) (:copier copy-offered-deadline-missed-status))
  "DataWriter OFFERED_DEADLINE_MISSED status (dds_rtf2_dcps.idl §<pin>)."
  (total-count 0 :type integer) (total-count-change 0 :type integer)
  (last-instance-handle nil :type (or null (array (unsigned-byte 8) (*)))))
(defstruct* (requested-deadline-missed-status (:constructor make-requested-deadline-missed-status) (:copier copy-requested-deadline-missed-status))
  "DataReader REQUESTED_DEADLINE_MISSED status (dds_rtf2_dcps.idl §<pin>)."
  (total-count 0 :type integer) (total-count-change 0 :type integer)
  (last-instance-handle nil :type (or null (array (unsigned-byte 8) (*)))))
```

- [ ] **S0.T2 — Per-entity status-changes bitmask + `get-status-changes`.** Failing test: after a simulated match, `(get-status-changes reader)` has `+status-subscription-matched+` set. Add a `status-changes` slot (init 0, `(unsigned-byte 32)`) to the reader/writer/topic entity classes in `entities.lisp`; add `get-status-changes`; add internal `%set-status-changed entity bit` / `%clear-status-changed entity bit`. Export `get-status-changes`. Both impls → PASS. Commit.

- [ ] **S0.T3 — The `%notify-status` chokepoint (refactor the firing sites).** Failing test: firing a status via the engine updates (a) the status struct, (b) the bitmask bit, (c) the StatusCondition trigger, (d) the listener — all four, once. Implement `%notify-status entity bit status-obj listener listener-mask on-fn`; refactor the existing scattered sites (`entities.lisp` ~:1059, :1109, :2107, :2127, :2148, :2182, :2248, :2268, :2309, :2326, :2442 — grep `on-` firing sites) to call it (DRY; behavior-preserving for the listener call, additive for bit+condition). Both impls + `make gate-hotpath` → PASS. Commit.

- [ ] **S0.T4 — Entity-owned StatusCondition + enabled-statuses.** Failing test: `(get-statuscondition reader)` returns a StatusCondition; `set-enabled-statuses` masks which statuses trigger it; a WaitSet on it wakes when an enabled status fires and not when a disabled one does. In `conditions.lisp`, make each entity lazily own a StatusCondition bound to its `status-changes`; add `get-statuscondition`, `set-enabled-statuses`, `get-enabled-statuses`; `%status-active-p` reads the entity bitmask ∧ enabled-mask. Wire `%notify-status` to trigger it. Export. Both impls → PASS. Commit.

- [ ] **S0.T5 — read-communication-status reset.** Failing test: after reading a plain-communication status via its getter (e.g. `get-subscription-matched-status`), `total-count-change`/`current-count-change` are 0 and the status-changed bit is cleared (DDS §2.2.2.1.9). Make each `get-*-status` getter reset the `*-change` fields + `%clear-status-changed`. Both impls → PASS. Commit.

**S0 exit gate:** `get-status-changes` + entity StatusCondition + read-reset all work on both impls; every existing status still fires through `%notify-status`; `make test` + `gate-hotpath` green; verification.csv `FR-DCPS-3` note updated.

---

# Slice S1 — QoS get/set + consistency

**Goal:** `get_qos`/`set_qos` on every entity with `IMMUTABLE_POLICY`/`INCONSISTENT_POLICY`, plus default-QoS.

**Files:** `src/dds-dcps/entities.lisp` (get/set-qos per entity), a new `src/dds-dcps/qos-validate.lisp` (immutability table + consistency validator), `src/dds-qos/` (if the policy-immutability metadata belongs with the policies), `packages.lisp`, test file.

**Interfaces produced:** `get-qos entity → qos`; `set-qos entity qos → return-code` (`:ok`/`:immutable-policy`/`:inconsistent-policy`); `get/set-default-{datawriter,datareader,topic,publisher,subscriber,participant}-qos`.

**Tasks:**
- [ ] **S1.T1** — Immutability table: a data-driven map of policy→immutable-after-enable (pinned from DDS §2.2.3 per-policy "changeable" column). Test: the table classifies a known-immutable (e.g. RELIABILITY kind) and a known-mutable (e.g. LATENCY_BUDGET) correctly.
- [ ] **S1.T2** — Consistency validator `%qos-consistent-p qos → (values ok-p failing-policy-id)` (the spec's INCONSISTENT_POLICY combinations: HISTORY-vs-RESOURCE_LIMITS, DEADLINE-vs-TIME_BASED_FILTER, …). Test: each inconsistent combo returns its policy id; a valid qos returns ok.
- [ ] **S1.T3** — `get-qos`/`set-qos` on writer/reader/topic/publisher/subscriber/participant: `set-qos` runs the consistency validator (→ `:inconsistent-policy`) then, if the entity is enabled, the immutability check (→ `:immutable-policy`), else stores. Test: pre-enable set OK; post-enable immutable set rejected; inconsistent rejected; get returns the effective qos. (Uses a provisional `entity-enabled-p` that S2 formalizes.)
- [ ] **S1.T4** — Default-QoS getters/setters on the factory/publisher/subscriber/participant, applied at `create_*`. Test: a set default flows into a newly created child.

**S1 exit gate:** all set/get-qos return codes correct on both impls; create paths honor defaults; gates green; ADR if `create-*` signatures change.

---

# Slice S2 — Entity lifecycle (factory, enable, delete)

**Goal:** `DomainParticipantFactory`, `enable`/disabled-entity, child `delete_*`, `delete_contained_entities`.

**Files:** new `src/dds-dcps/factory.lisp`, `src/dds-dcps/entities.lisp` (enable + child registry + delete ops), `packages.lisp`, test file.

**Interfaces produced:** `get-participant-factory → factory`; `create-participant`/`delete-participant`/`lookup-participant` (factory methods; keep the existing free-fn as a thin shim); `enable entity → return-code`; `delete-datawriter/datareader/publisher/subscriber/topic parent child → return-code`; `delete-contained-entities entity → return-code`.

**Tasks:**
- [ ] **S2.T1** — `DomainParticipantFactory` singleton (`get_instance`, create/delete/lookup participant, default participant QoS, `ENTITY_FACTORY`). Existing `create-participant` becomes a shim over the factory. Test: factory creates/looks-up/deletes a participant; two `get_instance` calls return the same object.
- [ ] **S2.T2** — Parent→children registry: participant tracks publishers/subscribers/topics; publisher tracks datawriters; subscriber tracks datareaders (add slots + register on create). Test: after create, the parent enumerates its children.
- [ ] **S2.T3** — `enable()` + disabled-entity: `autoenable_created_entities` (ENTITY_FACTORY) gates whether create auto-enables; a disabled entity restricts operations to the NOT_ENABLED-safe set (`set_qos`, `enable`, `get_statuscondition`, `set_listener`) and returns `:not-enabled` otherwise. Test: created-disabled entity refuses `write`/`read` until `enable`; the S1 immutability check now keys on the real enabled flag.
- [ ] **S2.T4** — `delete_datawriter/datareader/publisher/subscriber/topic` with `PRECONDITION_NOT_MET` (delete a publisher with live writers → refused; delete a topic still referenced by an endpoint → refused) + resource cleanup (unregister discovery, stop engine reader/writer, free pools). Test: delete tears down + discovery reflects the removal; non-empty delete refused.
- [ ] **S2.T5** — `delete_contained_entities` (recursive). Test: one call tears down a participant's full tree; the participant is then empty and deletable.

**S2 exit gate:** full create→enable→use→delete lifecycle green both impls; discovery announces the deletions on the wire (interop-sane); gates green; **ADR** for the factory/enable/delete semantics + the create-shim.

---

# Slice S3 — The full listener model

**Goal:** all 6 listener interfaces, `on_data_on_readers`, `get_datareaders`/`notify_datareaders`, and listener propagation up the containment tree.

**Files:** `src/dds-dcps/listeners.lisp` (3 new classes + callbacks), `src/dds-dcps/entities.lisp` (listener slots + set/get-listener on pub/sub/participant; the propagation walk in `%notify-status`; `get_datareaders`/`notify_datareaders`), `packages.lisp`, test file.

**Interfaces produced:** `subscriber-listener`, `publisher-listener`, `domain-participant-listener` classes; `on-data-on-readers listener subscriber`; `set-listener`/`get-listener` on all 6 entity kinds; `get-datareaders subscriber &key sample-states → list`; `notify-datareaders subscriber`.

**Tasks:**
- [ ] **S3.T1** — The 3 listener classes + `on-data-on-readers` defgeneric + default methods; listener + mask slots on Publisher/Subscriber/Participant; `set-listener`/`get-listener` on all 6 (Reader/Writer/Topic gain `get-listener`). Test: a listener can be installed + read back at every level.
- [ ] **S3.T2** — Listener propagation in `%notify-status`: walk Entity → its parent (pub/sub) → participant, delivering to the **most-specific enabled** listener (mask has the bit) and stopping; if none, leave the status-changed bit set, no callback (DDS §2.2.4.1). Test: a participant listener catches `on_publication_matched` when the writer's listener is nil; a writer listener with the bit masked-out lets it propagate up.
- [ ] **S3.T3** — `on_data_on_readers` + `get_datareaders` + `notify_datareaders`: on data arrival, `%notify-status` for DATA_ON_READERS fires the subscriber listener's `on_data_on_readers` if enabled; if it handled it, the readers' `on_data_available` is **not** fired (precedence, DDS §2.2.4.1); `get_datareaders` returns readers with data, `notify_datareaders` invokes `on_data_available` on each. Test: `on_data_on_readers` fires + suppresses `on_data_available`; `notify_datareaders` then delivers per-reader.

**S3 exit gate:** all 6 listener levels + propagation + `on_data_on_readers` precedence green both impls; gates green; **ADR** for the propagation semantics.

---

# Slice S4 — Deadline monitoring + SAMPLE_LOST

**Goal:** the dead statuses fire. A background deadline monitor + SAMPLE_LOST detection.

**Files:** new `src/dds-dcps/deadline.lisp` (timer thread + per-instance deadline queue), `src/dds-dcps/entities.lisp` (arm/rearm deadline on write/receive; SAMPLE_LOST detection sites), `packages.lisp`, test file.

**Interfaces produced:** internal `%deadline-monitor` (a `dds.pal` background thread over a sorted next-expiry queue); `%arm-offered-deadline writer instance` / `%arm-requested-deadline reader instance` (rearm on each write/sample); fires OFFERED/REQUESTED_DEADLINE_MISSED + SAMPLE_LOST via S3's `%notify-status`.

**Tasks:**
- [ ] **S4.T1** — The deadline monitor: a `dds.pal` background thread waking on the earliest per-instance deadline; DEADLINE QoS (period) drives arming; a write (offered) / sample (requested) rearms that instance's timer. Test: with a short DEADLINE and no write, the monitor fires after ~period; a write before expiry prevents the fire.
- [ ] **S4.T2** — Fire OFFERED/REQUESTED_DEADLINE_MISSED via `%notify-status` with a populated status (`total-count`, `total-count-change`, `last-instance-handle`) and propagation. Test: `on_offered_deadline_missed` / `on_requested_deadline_missed` fire with correct fields; `get_status_changes` + read-reset behave.
- [ ] **S4.T3** — SAMPLE_LOST detection + fire (KEEP_LAST overwrite-before-delivery; an unrecoverable gap under reliability/history — pin the trigger to the spec's SampleLost definition). Test: a constructed lost-sample scenario fires `on_sample_lost` with a populated status.

**S4 exit gate:** the 3 previously-dead statuses fire correctly on both impls; the monitor thread shuts down cleanly on entity/participant delete (no strand); gates green.

---

# Slice S5 — Instance & sample-access ops + matched-entity introspection

**Goal:** the missing DataWriter/DataReader operations.

**Files:** `src/dds-dcps/entities.lisp` (the ops), `packages.lisp`, test file; the timestamped-write path threads through the existing write/inline-QoS code.

**Interfaces produced:** `get-key-value writer/reader handle → key`; `lookup-instance writer/reader key → handle`; `read-instance`/`take-instance`/`read-next-instance`/`take-next-instance`/`read-next-sample`/`take-next-sample`; `get-matched-subscriptions writer`/`get-matched-publications reader → handles` + `get-matched-subscription-data`/`get-matched-publication-data → builtin-topic-data`; `write-w-timestamp`/`dispose-w-timestamp`/`unregister-instance-w-timestamp`/`writedispose`.

**Tasks:**
- [ ] **S5.T1** — `get_key_value` + `lookup_instance` (writer + reader), reusing the keyhash/key-field machinery. Test: `lookup_instance` round-trips a key→handle; `get_key_value` recovers the key fields.
- [ ] **S5.T2** — Instance/next reads: `read/take_instance`, `read/take_next_instance`, `read/take_next_sample` composed over the existing `read/take` + an instance/order filter. Test: `read_instance` returns only the named instance; `read_next_sample` walks in order.
- [ ] **S5.T3** — `get_matched_publications`/`get_matched_subscriptions` (+ `_data`) from the discovery match tables. Test: after a match, the writer lists the reader's handle + returns its builtin-topic-data.
- [ ] **S5.T4** — Timestamped writes: `write_w_timestamp`, `dispose_w_timestamp`, `unregister_instance_w_timestamp`, `writedispose`, threading the source_timestamp into the existing DATA/inline-QoS path. Test: the given source timestamp appears on the wire; **live interop check** vs Connext + Fast DDS (source_timestamp is a wire surface).

**S5 exit gate:** all ops green both impls; timestamped-write interop-validated vs both vendors; corpus unchanged (except the pinned source_timestamp path); gates green.

---

# Slice S6 — Secured / ZC same-topic multi-endpoint

**Goal:** lift the fail-fast fences for same-topic multi-reader/multi-writer under security and Zero-Copy.

**Files:** `src/dds-dcps/entities.lisp` (the `entities.lisp:1442/1448` fences), `src/dds-disc/*` (per-endpoint crypto/decode-pool extension), test files, `docs/verification.csv` (`FR-DCPS-N-READERS`).

**Interfaces produced:** no new public API — removes the fail-fast on same-topic secured/ZC multiplicity; extends ADR-0048 per-endpoint crypto + per-reader decode pools + cross-reader UAF handling to the same-topic case.

**Tasks:**
- [ ] **S6.T1** — Same-topic multi-**reader** under `data_protection`/`rtps_protection`: per-reader decode routing + decode pools for two readers on one topic in one participant; lift the fence. Test: two secured same-topic readers each decode correctly; adversarial review of the decode-pool/UAF surface.
- [ ] **S6.T2** — Same-topic multi-**writer** under security: per-writer EntityCrypto keying (extend the ADR-0048 S3 send-crux to same-topic). Test: two secured same-topic writers each publish under their own key; a reader decodes both.
- [ ] **S6.T3** — Same-topic multi-endpoint under **Zero-Copy/SHMEM**: slot refcount/aliasing across same-topic ZC endpoints (compose with ADR-0047 multi-dest refcount + the ADR-0051 overlay). Test: two ZC same-topic endpoints share/allocate slots without aliasing or leak.

**S6 exit gate:** fences lifted, secured + ZC same-topic multiplicity correct both impls; adversarial security/UAF review clean; **live interop** vs Connext + Fast DDS for the secured same-topic case; `FR-DCPS-N-READERS` flipped; gates green.

---

# Slice S7 — Autonomous background discovery

**Goal:** an autonomous discovery mode alongside manual `spin`.

**Files:** new `src/dds-disc/autodiscovery.lisp` (announcer + aging threads), `src/dds-dcps/entities.lisp` (mode gate on participant create/enable/delete), test files.

**Interfaces produced:** an autonomous-mode gate (config/QoS) that, when set, starts a background SPDP announcer (periodic participant announcement + lease), SEDP publication/subscription announcers, and a discovery receive/aging loop (lease expiry → purge); `spin` remains for the deterministic test path.

**Tasks:**
- [ ] **S7.T1** — Background SPDP announcer + receive/aging thread (participant lease duration; periodic announce; purge on lease expiry). Test: two autonomous participants discover each other with no `spin`; a killed participant ages out after its lease.
- [ ] **S7.T2** — Background SEDP announcers wired to endpoint create/delete so autonomous participants match endpoints without `spin`. Test: autonomous end-to-end pub/sub with zero app-driven `spin`.
- [ ] **S7.T3** — Clean thread lifecycle: threads start on enable, stop on delete (join, no strand); compose with S2 delete + S4 deadline monitor. Test: create/enable/delete cycles leave no live threads.

**S7 exit gate:** autonomous discovery works both impls with no `spin`; clean thread teardown; `spin` path still deterministic; **live interop** vs Connext + Fast DDS (SPDP/SEDP cadence on the wire); gates green.

---

## Program Definition of Done

- All 8 slices shipped, each meeting the operating-contract §5 DoD before the next began.
- The 2026-07-09 DCPS audit re-run shows every enumerated gap closed; `docs/verification.csv` `FR-DCPS-*` flipped to done.
- Both impls green (Clasp first); `make gate-hotpath` + `make corpus` green throughout.
- S5/S6/S7 live-interop-validated vs Connext 7.3.1 + Fast DDS.
- ADRs for S2 (factory/enable/delete), S3 (propagation), and any other contract change; wiki + README + verification.csv + SBOM current.

## Per-slice self-review (run when expanding each slice to step level)

Before executing S1–S7, expand the slice's task list to full TDD steps (with code) exactly as S0 is detailed here, then run the writing-plans self-review (placeholder scan, spec coverage, type consistency) on the expanded slice.

---

## Self-Review (this master plan)

**Spec coverage:** every §4 slice (S0–S7) maps to a plan slice with tasks; every audit gap maps to a slice — listeners→S3, `on_data_on_readers`→S3, QoS→S1, factory/enable/delete→S2, statuses/deadline→S0+S4, instance ops→S5, secured/ZC multiplicity→S6, autonomous discovery→S7, introspection→S0. ✓
**Placeholder scan:** S0 is step-level with code; S1–S7 are intentionally task-level (named files/interfaces/tests) per the stated structure, to be expanded at execution — this is the plan's declared shape, not a gap. The one `<pin>` marker (S0.T1) is a deliberate instruction to read+cite the exact IDL clause (clean-room), not a code placeholder. ✓
**Type consistency:** `%notify-status` (S0) is the single firing chokepoint reused by S3 (propagation) and S4 (deadline fire); `get-status-changes`/status structs (S0) are consumed by S4/S5; the S1 provisional `entity-enabled-p` is formalized by S2.T3; `set/get-listener` (S3) extends the S0/existing listener slots consistently. ✓
