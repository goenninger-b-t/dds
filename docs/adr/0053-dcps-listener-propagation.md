# ADR 0053 — DCPS listener model: the 6-interface set, hierarchy propagation, on_data_on_readers precedence, and StatusChangedFlag reset on listener invocation

Status: Accepted
Date: 2026-07-09
Work package: WP-DCPS-API-COMPLETION Slice S3 (tasks S3.T1–S3.T3) — the full listener-model slice of the DCPS API-completion program (design doc `docs/superpowers/specs/2026-07-09-dcps-api-completion-design.md`; plan `docs/superpowers/plans/2026-07-09-dcps-api-completion.md`)
Relates to: ADR 0052 (entity lifecycle — S3 reuses S2's parent→children registry and the child→parent back-links for the propagation walk); the WP-DCPS-API-COMPLETION S0 slice (the single `%notify-status` chokepoint + per-entity status-changes bitmask + entity-owned StatusCondition that S3 extends)

## 1. Context

Before S3 the DCPS layer implemented only 3 of the 6 DDS 1.4 listener interfaces
(`data-reader-listener`, `data-writer-listener`, `topic-listener`, all in
`src/dds-dcps/listeners.lisp`), and a communication status fired ONLY on the source entity's own
listener (the `(when (and (dr-listener dr) (member :x (dr-listener-mask dr))) …)` pattern inside
each `%notify-status` apply-fn). Missing against DDS 1.4 §2.2.4.1:

- **SubscriberListener** (`dds_rtf2_dcps.idl §247`, adds `on_data_on_readers`), **PublisherListener**
  (§221), **DomainParticipantListener** (§253, aggregates every callback) — the three interfaces above
  the endpoint level.
- **Listener slots + set_listener/get_listener on Publisher/Subscriber/DomainParticipant**;
  `get_listener` on Reader/Writer/Topic (previously set-only).
- **`on_data_on_readers`** entirely absent, and the **DATA_ON_READERS → DATA_AVAILABLE precedence** rule
  (§2.2.4.1: if a Subscriber/Participant listener handles DATA_ON_READERS, the readers'
  `on_data_available` is not called).
- **Listener-hierarchy propagation** (§2.2.4.1): a status the source entity's listener does not handle
  must propagate to the next listener up the containment tree (endpoint → Publisher/Subscriber →
  DomainParticipant), delivered to the MOST-SPECIFIC enabled listener; if none is enabled, the status
  stays "changed" and no callback fires.
- **`Subscriber::get_datareaders` / `notify_datareaders`** (§993/§998).

An **S0-review defect** also had to be closed here: DDS §2.2.4.1 resets a plain-communication-status
StatusChangedFlag on EITHER a listener invocation OR a getter read. S0 reset the bit only on the
`get_*_status` getter, so a status watched by BOTH a listener and a StatusCondition stayed
condition-triggered after the listener already handled it.

## 2. Decision

Implement the full listener model **additively** in `src/dds-dcps/listeners.lisp` +
`src/dds-dcps/entities.lisp` + `src/dds-dcps/conditions.lisp` — no wire change, hot path untouched
(`make gate-hotpath` green), pinning every rule to its DDS 1.4 / `dds_rtf2_dcps.idl` clause.

### 2.1 The 6-interface listener set (S3.T1)

`publisher-listener`, `subscriber-listener`, `domain-participant-listener` are added as subclasses of
the base `listener`. Because every `on-*` generic dispatches on the base `listener` (base method =
no-op), a participant listener automatically inherits ALL callbacks — an application subclasses and
overrides only what it cares about, exactly as for the existing three. `on-data-on-readers` is a new
generic (SubscriberListener::on_data_on_readers, §248) with a no-op base method.

Publisher/Subscriber/DomainParticipant gain `listener` + `listener-mask` + a dedicated `listener-lock`
slot. A **uniform** `set-listener entity listener mask` / `get-listener entity` works on all six entity
kinds via a typecase (`%entity-listener` / `%set-entity-listener` / `%entity-listener-lock`):
Reader/Writer/Topic reuse their existing status-lock (their listener slots live beside the status
structs); Publisher/Subscriber/Participant use the new listener-lock. The pre-existing
`set-reader-listener` / `set-writer-listener` / `set-topic-listener` are retained unchanged (additive).

**child→parent back-links already existed** — verified, not added: `dw-publisher`→`pub-participant`
(writer→publisher→participant), `dr-subscriber`→`sub-participant` (reader→subscriber→participant),
`topic-participant`. S2's parent→children registry is untouched; the propagation walk uses these
existing back-links.

### 2.2 Hierarchy propagation in the `%notify-status` chokepoint (S3.T2)

The single `%notify-status` chokepoint is the one place propagation lives — there is no parallel path.
Its apply-fn contract changed from `(values changed-p fire-thunk)` to
**`(values changed-p snapshot reset-thunk)`**:

- `snapshot` — a fresh copy of the status struct, built **whenever CHANGED** (previously built only if
  the source entity's own listener was masked), so it is available to deliver to an ANCESTOR listener.
- `reset-thunk` — a closure that zeroes the live struct's `*_change` counters, run **only if a listener
  handles the status** (the §2.2.4.1 reset-on-invocation; previously the reset happened inside the
  own-listener gate).

`%notify-status` then, outside the lock, walks `%listener-ancestry` (entity, then its parent, then the
DomainParticipant — most-specific first) via `%find-enabled-listener`, delivering `snapshot` to the
first listener whose mask contains the status keyword and **stopping there**. The per-status on_<status>
invoker is looked up in the `*status-listener-invokers*` table (keyword → `(listener entity snapshot)`
closure), so the walk is status-generic. The callback always receives the SOURCE entity (e.g.
`on_publication_matched` receives the writer even when caught by a participant listener), per §2.2.4.1.

**Behavior-preserving:** an entity with its own enabled listener is the most-specific link, so it still
receives the exact prior callback with the exact prior snapshot. The 10 apply-fn sites (match/unmatch,
incompatible-qos, liveliness-changed/lost, sample-rejected, inconsistent-topic) were mechanically
converted to the new 3-value contract.

### 2.3 StatusChangedFlag reset on listener invocation (S3.T2, the S0-review fix)

When a listener (own OR ancestor) handles a status, `%notify-status` now runs `reset-thunk` AND
`%clear-status-changed` for that bit, under the entity's status lock, BEFORE triggering the
StatusCondition. So a status a listener consumed is no longer "changed": its StatusCondition no longer
triggers and `get_status_changes` no longer reports it (DDS §2.2.4.1 — reset on EITHER read OR listener
invocation). If NO listener is enabled up the chain, the bit stays set and the StatusCondition triggers,
exactly as before. `%status-active-p`'s docstring was updated to note the invocation-reset path.

### 2.4 on_data_on_readers + precedence + get_datareaders / notify_datareaders (S3.T3)

On data arrival the participant-coarse disc callbacks (`%on-participant-sample`, `%on-disc-lifecycle`)
route through `%deliver-data-on-readers`: for each Subscriber with DataReaders, if a listener enabled for
`:data-on-readers` exists on the Subscriber or DomainParticipant (`%find-enabled-listener`), it invokes
`on_data_on_readers` on the most-specific such listener and **suppresses** the readers'
`on_data_available` (the §2.2.4.1 precedence) — while still waking their WaitSets so a waiting reader
drains; otherwise it fires each reader's `on_data_available` (now itself propagated up the reader →
Subscriber → participant chain via `%fire-data-available`). `DATA_ON_READERS` / `DATA_AVAILABLE` are
level-based statuses (unread-sample driven, not bitmask-edge driven): `%status-active-p` now answers
`:data-on-readers` on a Subscriber (any reader with unread data) as it already answered `:data-available`
on a reader, and a Subscriber's default enabled_statuses is `(:data-on-readers)`.

`Subscriber::get_datareaders subscriber &key sample-states` (default `(:not-read)`) drains each reader
and returns those holding a matching sample; `notify_datareaders subscriber` fires `on_data_available`
on each such reader. (The DDS view_state / instance_state filters are v1-deferred; sample_state only.)

## 3. Consequences / limitations (honest gaps)

- **Coarse (participant-level) data-ready callbacks.** The disc data/lifecycle callbacks carry no reader
  identity, so `on_data_on_readers` (like the pre-existing `on_data_available`) is level-triggered per
  Subscriber and may fire when a specific reader has nothing newly pending. This mirrors the existing
  DATA_AVAILABLE behavior and is benign (the app re-checks via `get_datareaders`/read). It is NOT fired
  more spuriously than the pre-S3 `on_data_available` was.
- **No draining on the receiver thread.** `%deliver-data-on-readers` never calls `%drain` (that is
  user-thread-only state, per the `%drain` discipline). `get_datareaders`/`notify_datareaders` run on the
  app thread and therefore may drain.
- **A single StatusCondition-reset semantics change is observable.** A status handled by a listener now
  clears its StatusChangedFlag (§2.2.4.1). This corrected the S0 behavior; the S0.T3 test's
  `:notify-writer-bit` assertion (which asserted the bit stayed set after the writer listener fired) was
  updated to assert the bit is now cleared (`:notify-writer-bit-reset`). No wire or corpus impact.

## 4. Consumers (every touched interface + its migration)

- **`%notify-status` apply-fn contract** (internal, `src/dds-dcps/entities.lisp`): 10 firing sites
  migrated from `(values changed fire)` to `(values changed snapshot reset-thunk)`. No external consumer
  (internal chokepoint). S4 (deadline/SAMPLE_LOST) will fire through the same, unchanged, chokepoint.
- **New exported symbols** (`src/dds-dcps/packages.lisp`): `publisher-listener`, `subscriber-listener`,
  `domain-participant-listener`, `on-data-on-readers`, `set-listener`, `get-listener`,
  `get-datareaders`, `notify-datareaders`. Additive — no existing export changed contract.
- **Retained legacy setters** `set-reader-listener`/`set-writer-listener`/`set-topic-listener` still
  exported and behavior-identical; `set-listener` is the new uniform superset.
- **`%status-active-p` / `%default-enabled-statuses`** (`src/dds-dcps/conditions.lisp`): extended for
  `:data-on-readers`; the DataReader/DataWriter/Topic cases are unchanged.
- **Tests** (`src/dds-tests/integration-test.lisp`, registered in `src/dds-tests/echo-test.lisp`):
  `run-dcps-listener-levels-test` (S3.T1), `run-dcps-listener-propagation-test` (S3.T2),
  `run-dcps-data-on-readers-test` (S3.T3); `run-dcps-notify-status-test` updated for the §2.2.4.1
  invocation-reset.

## 5. Alternatives considered

- **A parallel propagation path outside `%notify-status`.** Rejected — it would duplicate the
  status-firing logic and risk divergence; the operating contract's S0 design mandates the single
  chokepoint every status flows through.
- **Building the snapshot lazily only when an ancestor listener exists.** Rejected — determining "an
  ancestor is enabled" already requires the walk, and the snapshot is a cheap control-plane copy off the
  hot path; unconditional-when-changed keeps the apply-fn contract simple and uniform.
- **A separate lock per listener on the entity base.** Rejected in favor of reusing the existing
  status-lock for Reader/Writer/Topic (their listener already lived under it) and one dedicated
  listener-lock for the three container entities — minimal new state, no relocation of the existing
  listener slots the firing code reads.
