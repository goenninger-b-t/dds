# ADR 0052 — DCPS entity lifecycle: DomainParticipantFactory, enable()/disabled-entity, child delete_* + delete_contained_entities

Status: Accepted
Date: 2026-07-09
Work package: WP-DCPS-API-COMPLETION Slice S2 (tasks S2.T1–S2.T5) — the entity-lifecycle slice of the DCPS API-completion program (design doc `docs/superpowers/specs/2026-07-09-dcps-api-completion-design.md`; plan `docs/superpowers/plans/2026-07-09-dcps-api-completion.md`)
Relates to: ADR 0048 (N-user-endpoint registry — S2's delete unregisters from that registry), the WP-DCPS-API-COMPLETION S0 (status/introspection) + S1 (QoS get/set) slices already landed (S1 left the provisional `entity-enabled-p` seam S2 formalizes here)

## 1. Context

The DCPS application-facing entity model (`src/dds-dcps/entities.lisp`) had create paths and a single
`delete-participant`, but no formal **entity lifecycle**: no `DomainParticipantFactory` object, no
`enable()`/disabled-entity semantics, and no way to delete a Publisher/Subscriber/Topic/DataWriter/
DataReader short of tearing down the whole participant. S1 added `get_qos`/`set_qos` with an
`IMMUTABLE_POLICY` check that keys on a **provisional** `entity-enabled-p` flag (every entity was created
`:enabled t`), explicitly deferring the real enabled-state model to S2.

DDS 1.4 §2.2.2 requires:
- **DomainParticipantFactory** (§2.2.2.2.2): a process singleton (`get_instance`) that
  creates/looks-up/deletes participants and holds the factory-scope defaults + `ENTITY_FACTORY`.
- **enable() + disabled-entity** (§2.2.2.1.1.7): `autoenable_created_entities` (§2.2.3.23) gates whether
  a child is enabled at create; a disabled entity restricts its operations to the NOT_ENABLED-safe set
  and returns `NOT_ENABLED` otherwise.
- **Containment + delete** (§2.2.2.2.1 / §2.2.2.4.1 / §2.2.2.5.1): a parent enumerates its children;
  `delete_datawriter/datareader/publisher/subscriber/topic` with `PRECONDITION_NOT_MET`; and
  `delete_contained_entities` for recursive teardown.

## 2. Decision

Implement the entity lifecycle **additively** in `src/dds-dcps/entities.lisp` (no wire change, hot path
untouched), pinning every return code / rule to its DDS 1.4 clause. The changes:

### 2.1 DomainParticipantFactory (S2.T1)

A new CLOS class `domain-participant-factory` with a live participant registry, the `ENTITY_FACTORY`
`autoenable_created_entities` flag, and a lock. A lazily-created process singleton via
`get-participant-factory` (and its spec-named alias `get-instance`), double-checked under
`*participant-factory-init-lock*`. `lookup-participant factory domain` finds a registered participant;
`participant-factory-autoenable-p` / `set-participant-factory-autoenable` read/write ENTITY_FACTORY.

**The create-participant shim.** The existing free function `create-participant` (≈200 call sites) is
**unchanged in signature and behavior** — it remains the entry point every caller uses. It is now the
factory's `create_participant` shim: after fully constructing the participant it calls
`%factory-register-participant`, and `delete-participant` calls `%factory-unregister-participant`. Because
the shim is a superset of the old behavior (same args, same returned participant, plus a registry push),
**every existing caller keeps working byte-for-byte** — verified by grepping all `create-participant` /
`delete-participant` call sites (they pass keyword args and use the returned participant; none depended on
the participant NOT being registered). The default participant QoS continues to live in
`*default-participant-qos*` (S1), which the factory logically owns; keeping that storage means the S1
`run-dcps-default-qos-test` rebinding of the special var still isolates correctly.

**Modeling note — ENTITY_FACTORY is not in `dds.qos`.** `ENTITY_FACTORY.autoenable_created_entities` is a
purely LOCAL policy (DDS 1.4 §2.2.3.23 — never propagated on the wire). `dds.qos` models only wire QoS,
so ENTITY_FACTORY is modeled here as a boolean slot (`autoenable-created-entities` on `entity`,
`autoenable` on the factory) with dedicated accessors, rather than inventing a wire QoS policy. This is
the spec-honest representation and keeps `make corpus` byte-unchanged.

**File-location note.** The plan named a new `src/dds-dcps/factory.lisp`; the factory is instead colocated
with the participant lifecycle in `entities.lisp` (the `create-participant` shim and the factory are
tightly coupled, and a separate earlier-loaded file would force forward references). No `.asd` change.

### 2.2 Parent→children containment registry (S2.T2)

Register-on-create already existed (`dp-children`, `pub-writers`, `sub-readers`). S2 adds the enumeration
accessors: `participant-publishers` / `participant-subscribers` / `participant-topics` (filtered from the
mixed `dp-children`), `publisher-datawriters`, `subscriber-datareaders` — each returns a fresh list.

### 2.3 enable() + disabled-entity (S2.T3)

- `entity` gains an `autoenable-created-entities` slot (default T = the spec default) — the entity's
  ENTITY_FACTORY governing the children IT creates.
- `%child-created-enabled-p parent` = ENTITY_FACTORY-autoenable AND parent-enabled. A child of a
  **disabled** factory-parent is ALWAYS created disabled (§2.2.2.1.1.7 — it cannot be enabled before its
  parent). Every `create_*` sets its child's `:enabled` from this. At the default (autoenable T, parent
  enabled) this is T — **byte-identical to the pre-S2.T3 always-enabled create paths.**
- `enable entity` transitions to enabled: idempotent (:ok), returns `:precondition-not-met` if the
  factory-parent is still disabled, else sets enabled.
- **Disabled-entity operation restriction (full data-operation set).** Every operation OUTSIDE the
  NOT_ENABLED-safe set returns `+retcode-not-enabled+` (:not-enabled) while the entity is disabled: on the
  DataReader `read-samples`/`take-samples`; on the DataWriter `write-sample`, `register-instance`,
  `dispose-instance`, `unregister-instance`, `loan-sample`, `write-loaned`. The NOT_ENABLED-safe set
  (`get_qos`, `set_qos`, `enable`, `get_statuscondition`, `set_listener`) keeps working. This
  **formalizes the provisional `entity-enabled-p`** S1 keyed its immutability check on — the flag is now
  the real DDS enabled state, and the S1 immutability tests + pub/sub/topic immutability test still pass
  unchanged.

### 2.4 Child delete_* (S2.T4) + delete_contained_entities (S2.T5)

- New DCPS ops `delete-datawriter` / `delete-datareader` / `delete-publisher` / `delete-subscriber` /
  `delete-topic`, each returning `:ok` or `+retcode-precondition-not-met+`. Preconditions (§2.2.2):
  the child must be contained in the parent; a Publisher/Subscriber with live endpoints is refused; a
  Topic still referenced by any DataWriter/DataReader is refused.
- **Resource cleanup discipline (mirrors `delete-participant`/`stop-node`).** `delete-datareader` unregisters
  the endpoint FIRST (`remove-local-reader` purges its delivery routes under the node lock, so the receiver
  stops demuxing new samples to it), THEN `return-all-loans` (the pool is still mapped — freed only at
  stop-node — so no use-after-free, and no held refcount pins a writer pool). This route-purge-before-loan-
  return ordering closes the window where one more demuxed sample would create a never-returned loan (a
  bounded refcount pin, not a UAF). `delete-datawriter` `discard-all-loans` (no stranded TX pool slot), then
  unregisters. The default (non-secured/non-ZC) writer HistoryCache holds its `serialized-payload` as a
  fresh **GC-heap** vector (`%serialize-sample` copies out of the static scratch, then frees it), so dropping
  the rtps-writer at delete lets GC reclaim the retained payloads — **no static/foreign leak, no `free-static`
  needed**. The only static-backed retention is the node-scoped secured payload pool / ZC slots (freed at
  stop-node), correctly not torn down at per-endpoint delete.
- Two new **disc-layer** primitives (`src/dds-disc/disc.lisp`), exported from `dds.disc`:
  `remove-local-writer` and `remove-local-reader`. Both mutate the disc-node **under the node lock** —
  the SAME lock the receiver/sender push drivers and the receive-hook demux take — so removal never races
  a live send/retransmit/deliver (no UAF). They drop the endpoint from the user-writer/reader registry
  (repointing the cached primary if it was primary), remove the SEDP `endpoint-data` from
  `disc-node-local-writers/readers` (so `announce-endpoints` stops advertising it), and (reader)
  purge the EntityId from every `disc-node-reader-routes` delivery route + its ZC-joiner watermark map.
  The DCPS writer/reader retains its SEDP `endpoint-data` (new `disc-endpoint` slot) captured at create,
  so delete can pass it to the removal primitive.
- `delete-contained-entities entity` recurses: a Publisher deletes its DataWriters; a Subscriber its
  DataReaders; a DomainParticipant empties+deletes its Publishers and Subscribers, THEN its Topics (last,
  once unreferenced, so `delete_topic`'s precondition holds). Always :ok.

## 3. Consequences / limitations (honest gaps)

- **Node-scoped shared resources are freed at `stop-node`/`delete_participant`, not per-endpoint delete.**
  The ZC pool, secured payload/decode pools, and per-node arenas are shared across a participant's N
  endpoints (ADR 0048); deleting ONE of N endpoints must not tear down a pool a sibling still uses, so
  those are released at participant teardown. Consequence: an early per-endpoint delete does not
  early-reclaim node-scoped pools — a bounded, non-leaking deferral over the participant's lifetime, not a
  UAF. Tracked as a follow-on if early reclaim is ever needed.
- **A DataWriter under an associated flow-controller** is unregistered from the controller synchronously at
  `delete_datawriter` via the new `flow-controller-remove-writer` (`src/dds-disc/flow-control.lisp`) — the
  per-writer analogue of `flow-controller-unregister`: under the controller lock it drops the writer's
  selection entry + flow-writer-state, then blocks on the per-node emit barrier so no scheduler send
  references the writer after delete returns, and releases its mid-drain step-refs. Called from
  `remove-local-writer` OUTSIDE the node lock (the barrier must not hold it — no lock-order inversion with
  the scheduler's emit path). The node keeps its flow-controller association and its OTHER writers untouched.
- **Deferred engine registration is not done.** A created-disabled endpoint still eagerly registers with
  the engine at create (the disabled state is enforced at the DCPS data ops). Since discovery is
  `spin`-driven, a disabled endpoint that is never spun never announces; true deferred-registration is a
  follow-on.

## 4. Consumers / API surface (all additive; no existing symbol's contract changes)

New exported `dds.dcps` symbols: `domain-participant-factory`, `get-participant-factory`, `get-instance`,
`lookup-participant`, `participant-factory-autoenable-p`, `set-participant-factory-autoenable`;
`participant-publishers`, `participant-subscribers`, `participant-topics`, `publisher-datawriters`,
`subscriber-datareaders`; `enable`, `entity-autoenable-created-entities`, `+retcode-not-enabled+`,
`+retcode-precondition-not-met+`; `delete-datawriter`, `delete-datareader`, `delete-publisher`,
`delete-subscriber`, `delete-topic`, `delete-contained-entities`. New exported `dds.disc` symbols:
`remove-local-writer`, `remove-local-reader`.

Behavior deltas to existing symbols (all backward-compatible): `create-participant` now registers with the
factory singleton (superset); `delete-participant` now unregisters from it; every `create-*` sets the
child's enabled state from the governing parent's ENTITY_FACTORY (default T = byte-identical); `write-sample`
gains `:not-enabled` in its return set; `read-samples`/`take-samples` may return `:not-enabled` on a disabled
reader. No wire change; `make corpus` and `make gate-hotpath` unaffected.

## 5. Verification

Five new tests (`src/dds-tests/integration-test.lisp`, registered in `src/dds-tests/echo-test.lisp`):
`dcps-factory`, `dcps-children-registry`, `dcps-enable`, `dcps-delete-child`, `dcps-delete-contained` —
all green on **Clasp and SBCL** (Clasp first). `make gate-hotpath` green; the full SBCL suite green. Each
delete/lifecycle test was verified non-vacuous (sabotage → assertion fails, then restore). S1's
immutability tests + the pub/sub/topic immutability test still pass against the now-real enabled state.
