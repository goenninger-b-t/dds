# ADR 0048 — N user DataWriters/DataReaders per participant: the endpoint registry (Slice S0) + the milestone slice plan

- **Status:** Accepted (WP-N-ENDPOINT-S0-REGISTRY, 2026-07-05). Slices S0 + **S1 (N local writers)** + **S2 (N local readers)** + **S3 (per-endpoint crypto key material — N secured writers)** + **S4 (N loan-capable readers — secured/ZC fence lift + per-reader decode tier)** + **S5 (per-endpoint status/listener dispatch — retire the DCPS back-refs)** landed. **The different-topic N-user-endpoint capability is COMPLETE** (WP-N-ENDPOINT-S5-CLEANUP, 2026-07-06): N DataWriters + N DataReaders per participant on distinct topics, incl. secured + loan-capable, each with correct per-endpoint status/listener/WaitSet delivery. **Flow-ON multi-writer (S1b) landed** (WP-N-ENDPOINT-S1B-FLOW, 2026-07-06; §9b): the flow-controller drives ALL of a participant's writers. Deferred-beyond-milestone items stay guarded (same-topic multi-endpoint; RETAINING-durability multi-writer).
- **Deciders:** A0 (integrator), A8 (DCPS), A6 (RTPS engine)
- **WP:** WP-N-ENDPOINT-S0-REGISTRY (Slice 0 of the N-user-endpoint milestone).
- **Requires:** REQUIREMENTS FR-DCPS (multiple DataWriters/DataReaders per participant), FR-LANG-8 (full type declarations), NFR-CLOS (hot-path purity — the registry is control-plane), NFR-MEM (no new hot-path allocation); the operating contract §4 (correctness/stability binary gates), §5 (Definition of Done).
- **Builds on:** ADR 0017 (single-user-endpoint dataplane), ADR 0019 (one engine writer per node shared by a publisher's DataWriters). Additive: no consumer of an existing symbol changes its contract; at N=1 the wire, the corpora/KATs, and every one of the ~163 `disc-node-user-writer`/`-reader` read sites are byte-identical.

---

## 1. Context — N-remote-ready, 1-LOCAL-bound

The stack already multiplexes N on the wire and N on the remote side:

- **SEDP announces N local endpoints** — `disc-node-local-writers` / `disc-node-local-readers` are lists; each `add-local-writer` / `add-local-reader` pushes an `endpoint-data`, and `announce-endpoints` publishes them all.
- **The reliable engine multiplexes N remote peers** — per-remote reader/writer proxies, the SN-aliasing fix, per-`(src-GUID, SN)` sample keying.
- **Crypto is already EntityId-keyed** — per-endpoint EntityCrypto key material, resolved by transformation_key_id.

The gap is **N LOCAL user DataWriters / DataReaders per participant**. Today the disc-node instantiates **exactly one** engine writer + one engine reader (`enable-publisher` / `enable-subscriber`), held in two single struct slots (`user-writer` / `user-reader`). A second `create-datawriter` / `create-datareader` re-ran `enable-publisher` / `enable-subscriber` and **silently clobbered** the first via `(setf (disc-node-user-writer node) …)`. The engine, discovery, and crypto layers are ready; the single-instance disc-node slot is the choke.

### Blast-radius summary (why this is a milestone, not a patch)

- **The two single engine-instance slots** — `disc.lisp` `user-writer` / `user-reader` (was `disc.lisp:175-176`).
- **The two clobber (register) sites** — `dataplane.lisp` `enable-publisher` and `enable-subscriber` (`(setf (disc-node-user-writer …) (make-rtps-writer …))` / the reader dual).
- **~163 read sites** of `disc-node-user-writer` / `disc-node-user-reader` (mostly `dataplane.lisp`, some `disc.lisp` / `flow-control.lisp` / `secure-sedp.lisp`) — the send path (`publish-sample`, `writer-write`), the receive path (`%on-user-data`, `%on-user-heartbeat`, the ACKNACK/GAP/FRAG handlers), durability, and batching all read "the" user writer/reader.
- **The DCPS back-refs** — `dp-user-writer` / `dp-user-reader` (`dds-dcps/entities.lisp:589` / `:626`) — a second `create-*` overwrites the single back-ref the status hooks use.
- **Node-scoped resources shared by the single endpoint** — `crypto-transform`, the ZC pool (`zc-pool` / `zc-pool-sap`), the secured payload/decode pools, the per-role protection-kind fields, the flow-controller, the samples store, async/batch state. These are all keyed to "the" one writer/reader today.

### The slice plan (S0 = this WP)

- **S0 — endpoint registry (this WP).** Convert the single writer/reader engine slots to entity-id-keyed registries; keep the compat accessors returning the primary; **zero behavior change at N=1**. De-risks everything downstream.
- **S1 — N local writers (LANDED, WP-N-ENDPOINT-S1-WRITERS).** Send-path fan-out: `publish-sample` writes into the addressed writer's own HistoryCache; the push drivers iterate the writer registry; per-writer `EntityId` on the wire; ACKNACK/NACK_FRAG retransmit routes by target writerId. See §9 (as-built).
- **S2 — N local readers (LANDED, WP-N-ENDPOINT-S2-READERS).** Delivery routing: distinct per-reader `EntityId`; a per-reader matched-writer-GUID route; the `%drain` source-GUID filter closes the cross-topic-deserialize hazard; the receive hooks demux to the engine reader matched to the source writer. See §10 (as-built).
- **S3 — per-endpoint crypto key material (LANDED, WP-N-ENDPOINT-S3-CRYPTO).** N SECURED local writers, each keyed under its OWN EntityCrypto km: the send-side encode derives the key + kind from the ACTUAL publishing writer's `EntityId` (not the node-single `user-writer-id`), the §8.5.2 token exchange enumerates all endpoints, a per-endpoint protection-kind map replaces the 2 role slots, and the payload-pool arena backref becomes a list. Secured/ZC READERS stay S4. See §11 (as-built).
- **S4 — N loan-capable readers (LANDED, WP-N-ENDPOINT-S4-POOLS).** Lift the secured/ZC-reader fence (`%register-user-reader`); KEEP the same-topic fence (the UAF-guarding invariant). The two loan-capable readers are therefore always on DIFFERENT topics → disjoint source-GUIDs → they never share a `(guid,SN)` slot or ZC marker, so the ADR-0017 cross-reader use-after-free precondition is structurally UNREACHABLE (not a UAF refactor). Correctness gate: the receive decode tier is now PER-READER (the target reader's OWN `%user-endpoint-kinds`, not the node-single slot); the ZC marker path demuxes to the matched reader. The node-shared decode pool + per-reader `dr-secured-loans` are kept (already safe for different-topic readers). See §12 (as-built).
- **S5 — per-endpoint status/listener dispatch (LANDED, WP-N-ENDPOINT-S5-CLEANUP).** Retire the `dp-user-writer` / `dp-user-reader` single DCPS back-refs (LAST-created-wins) and rewire all 9 disc→DCPS status/listener/wake hooks to resolve the endpoint the event is ABOUT: by the remote's TOPIC (the 7 match/unmatch/incompatible hooks) or by the remote writer GUID's S2 route (the liveliness hook). See §13 (as-built). **Completes the milestone's different-topic capability.**

---

## 2. Decision (Slice S0) — a registry behind a compat accessor

Replace the two single engine-instance slots with **entity-id-keyed registries**, and reimplement the existing accessors to return the **primary** (first-registered) entry — so every existing read site compiles and behaves byte-identically at N=1, with **no edit to any of the ~163 call sites**.

### 2.1 The disc-node slots (`disc.lisp`)

Removed: `user-writer` / `user-reader` (the single engine-instance slots).
Added:

- `user-writers` / `user-readers` — an alist `(EntityId u32 . engine-instance)` each. The registry.
- `primary-user-writer` / `primary-user-reader` — a cached slot holding the **first-registered** engine instance (the N=1 identity). Cached (not derived) so the compat accessor is a direct slot read — no per-call alist scan on the send/receive paths.

`user-writer-id` / `user-reader-id` are **unchanged** — they remain the node's declared user-endpoint `EntityId` (set by `add-local-writer` / `add-local-reader`) and serve as the registry key at register time.

### 2.2 The compat accessors (`disc.lisp`, now `defun*`)

`disc-node-user-writer` / `disc-node-user-reader` are no longer struct auto-accessors; they are `defun*`s that return `primary-user-writer` / `primary-user-reader`. Same name, same package-internal visibility, same return type `(or null rtps-writer/reader)`, same value at N=1 (the sole engine instance). The ~163 read sites are untouched.

### 2.3 The register / lookup / enumerate API (`disc.lisp`)

- `%register-user-writer (node entity-id writer)` / `%register-user-reader (node entity-id reader)` — install under `entity-id`; the first registered becomes primary. Consumed now only by the two enable sites.
- `%user-writer-for (node entity-id)` / `%user-reader-for (node entity-id)` — lookup by id (S1/S2 routing).
- `%all-user-writers (node)` / `%all-user-readers (node)` — enumerate, primary first (S1/S2 fan-out).

### 2.4 The two register sites (`dataplane.lisp`)

`enable-publisher` and `enable-subscriber` change **only** their one clobbering `setf`: instead of `(setf (disc-node-user-writer node) (make-rtps-writer …))` they call `(%register-user-writer node (disc-node-user-writer-id node) (make-rtps-writer …))` (and the reader dual). Every subsequent read in those functions — the ZC release-fn wiring, the secured-payload-pool carve, the hook installs — reads back via the unchanged compat accessor and is byte-identical.

### 2.5 The fail-fast (register-time guard)

Register semantics:

- **Same `EntityId` re-registered** → **replace** the entry and refresh the primary. This is exactly the pre-S0 clobber: a second `create-datawriter` re-runs `enable-publisher` with the node's fixed user-writer `EntityId` (`#x00000102` keyed / `#x00000103` no-key), so it replaces in place — byte-identical to the old `setf`.
- **A different, second `EntityId`** while a primary already exists → **`error`** with a clear "N-local user endpoints not yet supported (Slice S1 / S2)" message. This is a fail-fast that is strictly better than the pre-S0 silent clobber; it cannot be reached by today's DCPS (which never varies the id), and it protects S1/S2 from a partially-wired N-local state.

Everything else stays node-scoped (crypto-transform, ZC/secured pools, protection-kind fields, flow-controller, samples store, async/batch). Those are S1/S3/S4 and are correct at N=1.

---

## 3. Zero-behavior-change argument (N=1)

1. **Read path.** `disc-node-user-writer` / `-reader` return the primary = the sole registered instance = the value the old slot held. All ~163 read sites see the identical object.
2. **Write path.** The two enable sites register the same instance they used to `setf`; the primary cache is set to it; the compat accessor returns it.
3. **Re-enable.** A second `create-datawriter` / `-datareader` re-registers the same fixed `EntityId` → replace-in-place → identical to the old clobber.
4. **No hot-path cost.** The compat accessor is a slot read (cached primary), not an alist scan. `%register-*` is control-plane only (endpoint create/enable), never per-sample. Zero new steady-state allocation.
5. **Wire, corpora, KATs, gate-hotpath, make mem — untouched.** No serialization, no `EntityId`, no QoS, no memory-arena path changed.

Evidence: the full suite passes on both implementations — **Clasp 441 / SBCL 441** (the pre-S0 baseline of 440 plus the one new `endpoint-registry` unit test; every pre-existing test byte-identical).

---

## 4. Alternatives considered

- **Edit the 163 read sites now to take an `EntityId`.** Rejected for S0: it parallelizes churn against an interface that S1/S2 will reshape, and it is exactly the rework the operating contract §3 warns against. The compat accessor defers it to the slices that actually fan out.
- **Derive the primary by `assoc` on every accessor call (no cached slot).** Rejected: the accessor is on the per-sample send/receive path; an `assoc` (even over a 1-element alist) is a needless departure from a byte-identical slot read.
- **Silent clobber on a second distinct id (keep the old behavior).** Rejected: a fail-fast is strictly safer and surfaces the S1/S2 boundary loudly instead of corrupting state.

---

## 5. Consequences

- **Positive.** The foundational data structure for N local endpoints is in place, tested, and byte-identical at N=1. S1–S5 build on a stable register/lookup/enumerate API without touching the disc-node shape again. The second-endpoint failure mode is now an explicit error, not silent data loss.
- **Neutral.** Two extra struct slots per side (registry alist + cached primary); control-plane only.
- **Deferred (tracked by this ADR).** S1 (send fan-out), S2 (delivery routing + the `%drain` cross-topic hazard), S3 (per-endpoint crypto), S4 (N loan-capable readers — secured/ZC fence lift + per-reader decode tier + ZC marker demux), and S5 (per-endpoint status/listener dispatch — retire the `dp-user-writer` / `dp-user-reader` back-refs) have ALL LANDED — **the different-topic N-user-endpoint milestone is COMPLETE.** **Flow-controlled multi-writer (S1b) has since LANDED** (WP-N-ENDPOINT-S1B-FLOW, §9b). The following stay guarded BEYOND this milestone: **same-topic multi-endpoint** (the `add-local-reader` / `add-local-writer` same-topic fence stays — the ADR-0017 loan UAF-guard invariant; a same-topic 2nd loan-capable reader needs refcount-per-reader); **RETAINING-durability multi-writer**. Same-topic dispatch would additionally need a resolver keyed finer than topic-name.

---

## 9. Slice S1 — N local writers, send path (as-built, WP-N-ENDPOINT-S1-WRITERS)

A participant with TWO (N) non-secured user DataWriters on different topics now BOTH publish, each remote reader receives from its writer with correct attribution, and reliable retransmit repairs each writer independently. Non-secured, synchronous-send scope; flow-ON and secured multi-writer are deferred (fail-fast, below).

### 9.1 Distinct per-writer EntityId (the single load-bearing fix)

`add-local-writer` draws each user writer's entity KEY from a new per-participant counter `disc-node-user-writer-key-next` (`%alloc-user-writer-key`), starting at 1 — so the FIRST writer keeps EntityId `#x0102`/`#x0103` (byte-identical) and each subsequent DataWriter gets a distinct key → a distinct EntityId AND a distinct SEDP GUID (a remote peer now sees N distinct writers, not one aliased). Builtin/secure EntityIds are untouched (they are not drawn from this counter). This one change also fixes SEDP endpoint distinctness.

### 9.2 Registry accepts N writers; `%register-user-writer`

The S0 second-distinct-writer fail-fast is lifted FOR WRITERS: a distinct id is pushed as an N-th entry, the primary (first-registered) is preserved, and same-id re-register still replaces in place. Readers keep the S0 fail-fast (S2). `%all-user-writers` now enumerates in registration order (primary first), deterministic; the hot push paths iterate the registry alist directly (no per-push cons — NFR-MEM).

### 9.3 dw → engine-writer link + write threading

`rtps-writer` gains an `entityid` slot (set at `enable-publisher`). The DCPS `data-writer` gains an `entity-id` slot, captured at `create-datawriter` from `disc-node-user-writer-id`. `write-sample` threads it to `publish-sample` (new trailing `writer-id` arg), which resolves the addressed engine writer via `%user-writer-for` and writes into THAT writer's own HistoryCache + SN space (no aliasing to the primary). NIL `writer-id` → primary (byte-identical).

### 9.4 Send fan-out + per-writer wire stamping

`%push-data-buf` / `%push-heartbeat` iterate the writer registry, emitting each writer's own unsent changes + HEARTBEATs (`%push-one-writer-changes`). The send path binds a dynamically-scoped `*emit-writer*` (the emitting `rtps-writer`) per writer; `%emit-wid` stamps its EntityId on DATA/HEARTBEAT/GAP AND `%emit-writer` sources the DATA_FRAG **HEARTBEAT_FRAG** from its OWN HistoryCache (fix F1 — a non-primary writer's fragmented sample must draw its fragment count + `frag-hb-count` side-effect from its own HC, not the primary's; RTPS 2.5 §9.4.5.5). Unbound → primary → byte-identical. Push targets are TOPIC-FILTERED per writer (`%reader-push-targets` optional topic, `%writer-topic`): a writer reaches only the readers matched to its topic, never a sibling writer's readers.

### 9.5 ACKNACK / NACK_FRAG routing

`%on-user-acknack` / `%on-user-nack-frag` resolve the addressed local writer by the submessage's target writerId (`%user-writer-for`) and repair from THAT writer's HistoryCache under its own GUID — an ACKNACK for writer 2 never mis-repairs from the primary.

### 9.6 Deferrals (fail-fast, not half-fixed)

- **Flow-ON multi-writer → S1b (RESOLVED, WP-N-ENDPOINT-S1B-FLOW, 2026-07-06; see §9b).** ~~A 2nd writer under an associated flow-controller, or associating a flow-controller on an already-multi-writer participant, fail-fasts.~~ Both fail-fasts are LIFTED: the flow-controller now drives ALL of a participant's writers (each a per-writer selection entry). The synchronous `%push-data` path already fanned out; the flow/`%node-datagram-plan` path now does too.
- **Secured multi-writer → S3.** A 2nd writer on a secured node (`crypto-transform` installed or governance data_protection `:sign`/`:encrypt`) fail-fasts ("secured multi-writer is Slice S3"). The single-secured-writer path stays on the primary + node-global crypto, unchanged.
- **Durability multi-writer → later slice (fix F2).** A 2nd writer on a node with ANY retaining-durability (TRANSIENT_LOCAL/TRANSIENT/PERSISTENT) writer fail-fasts (`%node-has-durable-writer-p` in `%register-user-writer`). `%writer-durability-init`'s late-joiner replay (proxy-base rewind + prompt HEARTBEAT) is driven off the primary only, so a 2nd durable writer would silently miss its retained-history replay and mis-source the prompt HB; a VOLATILE writer sends no prompt HB, so 2 VOLATILE writers are unaffected. This closes the F2 cross-stamp latent as a guarded deferral (matching flow/secured), not a half-fix.
- **Multi-reader-per-participant stays S2.** Delivery routing is unchanged; a participant still has one engine reader. (The S1 writer fix unmasked a latent S2 hazard where two readers on one participant share the engine reader and cross-drain — a copy-path KEEP_LAST test was adjusted to a single reader per participant to keep its single-reader property under test without depending on the old double-clobber.)

### 9.7 Verification

Both impls green (SBCL + Clasp, 443 tests). Test `n-writer-data-over-udp` (`run-n-writer-dataplane-test`): distinct EntityIds/GUIDs (RED on pre-S1 — both `#x0102`), both writers deliver correctly-attributed with EXACT-count negative assertions (no over/under-send), independent drop→HEARTBEAT→writerId-routed-ACKNACK retransmit, and the flow-ON (S1b) / secured (S3) / durability deferral fail-fasts. Test `n-writer-frag-heartbeat` (`run-n-writer-frag-heartbeat-test`, fix F1): a non-primary writer's fragmented sample draws its HEARTBEAT_FRAG from its OWN HC — asserted via the `frag-hb-count` side-effect (RED pre-fix: non-primary=0, primary=2; GREEN: each=1), the precise observable since the coalesced regular HEARTBEAT masks end-to-end fragment delivery via the coarse ACKNACK path. N=1 byte-identical (hotpath-purity gate PASS; the whole prior suite unchanged).

---

## 9b. Slice S1b — flow-controller-ON multi-writer (as-built, WP-N-ENDPOINT-S1B-FLOW)

S1 fanned the SYNCHRONOUS send path over all local writers but DEFERRED the flow-controller-ON case: with a flow-controller associated, the scheduler drove only the PRIMARY writer's `%node-datagram-plan`, and a 2nd writer under (or an associate on) a multi-writer participant fail-fasted. S1b makes the shared flow-controller drive ALL of a participant's writers, rate-paced at the shared aggregate, with EDF/priority ordering spanning them.

**The finding (no scheduler rewrite).** The EDF/priority selector was ALREADY node-global: `%flow-policy-select` picks the global MIN-key entry across the controller's registered entries. So S1b needed NO cross-writer merge — only to change the granularity of the selection ENTRY from a node to a WRITER, and feed the existing global selector one entry per writer. The shared token bucket, the global-min EDF/priority selection, the RR tiebreak, the release-safety refs, and the teardown barrier are all REUSED unchanged.

**Per-writer flow-state (`flow-writer-state`, `disc.lisp`).** The 7 per-writer-semantic slots that were single node slots — `flow-step-state` (the send cursor), `flow-step-refs` (in-flight send-refs), `flow-pending`, `flow-head-ns`, `flow-latency-budget-ns`, `flow-transport-priority`, `flow-last-served-ns` — moved off `disc-node` into a per-writer `flow-writer-state` record (holding also the owning `node` + `writer`), keyed by writer EntityId in a new node alist `flow-writer-states`. The send cursor is THE reason it must be per-writer: one slot cannot hold two writers' in-progress draining plans. `flow-controller` stays NODE-scoped (one participant, one controller); the token **BUCKET** stays controller-shared (one controller = one participant aggregate rate — NOT per-writer).

**Selection entry = a writer.** `flow-controller-writers` now holds `flow-writer-state`s. `%flow-writer-pending-p` / `%flow-edf-key` / `%flow-priority-key` / `%flow-head-advance` / `%flow-signal` key per-writer; `%flow-cache-writer-qos` caches EACH writer's OWN advertised LATENCY_BUDGET/TRANSPORT_PRIORITY (matched by EntityId in `disc-node-local-writers`). The scheduler PICK selects a writer, BUILDs THAT writer's plan under `*emit-writer*`, and advances THAT writer's cursor. The per-node emit barrier (`current-emit-node`) stays node-grained (one emit at a time is fine; the barrier still blocks `flow-controller-unregister` until no emit is in flight on the node).

**Explicit-writer send functions.** `%node-datagram-plan` takes an explicit `writer` and returns `(values plan captured-refs)` (no node-single slot); `%flow-step-emit` / `%flow-step-advance` / `%flow-release-step-refs` take a `flow-writer-state`. All default (via `%flow-writer-state-for` → primary) so an N=1 flow-ON participant is BYTE-IDENTICAL. `publish-sample` resolves the written writer's state (`%resolve-user-writer` — the same rule the writer-write used, factored DRY) and signals it; dispose/relay signal the primary's.

**Fail-fasts lifted.** `flow-controller-associate` no longer errors on >1 writer (it registers a per-writer state for each); `%register-user-writer` no longer refuses a 2nd writer under an associated controller (it registers the new writer with the controller via `flow-controller-add-writer`, covering both associate-then-add and add-then-associate). The RETAINING-durability multi-writer fail-fast STAYS (independent deferral). The in-source assertion (`run-n-writer-dataplane-test` 4b) flipped from asserting the fail-fast to asserting associate succeeds with 2 per-writer entries.

**Correctness gates (all binary, all green).** N=1 BYTE-IDENTICAL (the sole writer's state == the old single slots; send defaults to the primary; one-entry selection == old single-node); BOTH WRITERS DRAINED, no starvation (per-writer `flow-step-state` makes plans independent — the RED, primary-only-drains, was confirmed by patching registration to primary-only and watching writer-B starve); EDF/PRIORITY ORDER ACROSS WRITERS (a tight-LATENCY_BUDGET writer ahead of a loose one on the SAME node); NO REF-LEAK/UAF (each writer's `flow-step-refs` are released when ITS plan drains, `%flow-step-advance`; **`destroy-flow-controller`'s `%flow-flush-all` drains + releases every registered writer's refs**, and — post adversarial-review FIX-1 — **`flow-controller-unregister` also releases the unregistered node's per-writer mid-drain refs** after the emit barrier, so a SHARED controller that keeps running never leaks a departed node's captured CacheChanges until stop-node); SHARED BUCKET (one controller bucket serves all writers = aggregate rate, not N×).

**Accepted control-plane cost (O(N-local-writers), opt-in flow-ON only).** The paced publish tail now resolves the written writer's flow-state via `%resolve-user-writer` (alist lookup by writer-id) + `%flow-writer-state-for` (alist lookup by EntityId) — two O(N-local-writers) alist walks per paced publish, where it was O(1). This is **allocation-free** (no cons; gate-hotpath + `make mem` confirm 0.0000 B/sample) and reached **only** on the opt-in flow-ON path — a flow-OFF (default) participant never enters this branch and is byte-identical. Accepted as within budget for the small per-participant writer counts the milestone targets; if N grew large, the alists would become hash tables (the same shape as the existing `user-writers` registry).

**Verification.** Both impls green (SBCL + Clasp, 458 tests; +3 over the 455 baseline). New tests: `flow-multiwriter-onenode` (2 writers/one participant both fully drain under one low-rate controller — SBCL, Clasp pass-skipped like the RR test), `flow-edf-across-writers` + `flow-priority-across-writers` (deterministic, both impls — tight/high selected first across one node's writers). Regenerated harness: `%flow-fake-node`→`%flow-fake-writer-state` (the selection entry is now a writer-state). No hot-path per-sample alloc (`flow-writer-state` allocated at associate/register, gate-hotpath PASS). Flow-OFF (default) entirely untouched.

---

## 10. Slice S2 — N local readers, delivery routing (as-built, WP-N-ENDPOINT-S2-READERS)

A participant with a Subscriber holding TWO (N) non-secured DataReaders on DIFFERENT topics now delivers correctly: each reader's `read`/`take` returns ONLY its own topic's samples, byte-exactly deserialized under its own type-support. This closes a real **cross-topic-deserialize data-corruption hazard** that S1 unmasked: the received-sample store is node-global (`disc-node-samples`, keyed src-GUID→SN) and pre-S2 `%drain` deserialized EVERY node-store sample with THIS reader's type-support — so two readers on different topics decoded each other's bytes (silent struct garbage or an out-of-bounds crash). Non-secured, non-ZC scope; secured/ZC multi-reader is deferred (fail-fast, below). Fix shape (b): a **drain-side source-GUID filter over the one store**, NOT a per-reader store partition (that touches the secured/ZC store contract = S4).

### 10.1 Distinct per-reader EntityId (mirrors S1)

`add-local-reader` draws each user reader's entity KEY from a new per-participant counter `disc-node-user-reader-key-next` (`%alloc-user-reader-key`), starting at 1 — so the FIRST reader keeps EntityId `#x0107`/`#x0104` (byte-identical) and each subsequent DataReader gets a distinct key → a distinct EntityId AND a distinct SEDP GUID (a remote peer sees N distinct readers). Writer and reader key counters are SEPARATE; the entity KIND (0x07/0x04 reader vs 0x02/0x03 writer) keeps their EntityIds disjoint even at the same key. Builtin/secure EntityIds are untouched. The DCPS `data-reader` gains an `entity-id` slot, captured at `create-datareader` from `disc-node-user-reader-id`.

### 10.2 Registry accepts N readers; `%register-user-reader`

The S0/S1 second-distinct-reader fail-fast is lifted: a distinct id is pushed as an N-th entry, the primary (first-registered) preserved, same-id re-register replaces in place. `enable-subscriber` registers each engine `rtps-reader` under the (now distinct) `disc-node-user-reader-id`, so N distinct engine readers register. A 2nd SECURED or ZC-loan-capable reader still fail-fasts (`%node-secured-or-zc-reader-p`; §10.6).

### 10.3 The per-reader matched-writer-GUID route

A new `disc-node-reader-routes` table (equalp: remote-writer 16-octet GUID → list of local user-reader EntityIds matched to it) is the delivery route. It is populated in `%match-remote-endpoint` at the compatible remote-WRITER match point (where it already iterates the local readers), recording (local-reader-EntityId ↔ remote-writer-GUID) BEFORE `%record-match` so the route is present the instant `%guid-matched-p` is true. It is idempotent (a re-announce never duplicates), purged by prefix on unmatch/lease-expiry (`%lease-sweep` → `%purge-prefix … #'disc-node-reader-routes`), and re-added on re-announce — the same match/unmatch discipline `%guid-matched-p` guards. `node-reader-matches-writer-p` is the lock-guarded membership peek.

### 10.4 The `%drain` source-GUID filter (the corruption fix)

`%drain` filters `node-sample-sns` (and `node-lifecycle-sns`) so a stored key survives for THIS reader ONLY when its source-writer GUID is in this reader's route (`node-reader-matches-writer-p` on `dr-entity-id`). Each reader therefore deserializes ONLY its own matched writers' bytes — no cross-topic deserialize. The filter engages only at **N≥2 readers** (`node-user-reader-count > 1`); at N≤1 it is a pass-through, so the single-reader path is byte-identical (the sole reader still drains every stored sample). A null source-GUID (never produced for a real stored data sample) is filtered out at N≥2 (fail-closed against a leak) and passes at N≤1 (unchanged). The check is take/read-time set-membership, not per-received-sample — no per-sample alloc (gate-hotpath / `make mem` unchanged).

### 10.5 Receive-hook demux (`%reader-routes-for`)

The node-wide receive hooks (`%on-user-data`/`%deliver-user-sample`, `%on-user-lifecycle`, `%on-user-heartbeat`, `%on-user-gap`, `%on-user-data-frag`, `%on-user-heartbeat-frag`) no longer drive the primary engine reader unconditionally. `%reader-routes-for` maps a source-writer GUID → the matched readers as (reader-EntityId . engine-reader) pairs; the FIRST is the CANONICAL reader that holds the single reliability truth for that writer (received-SN / dedup / reassembly). A HEARTBEAT is applied to + an ACKNACK computed from the canonical reader, then the ACKNACK/NACK_FRAG is EMITTED stamped with the matched local reader's EntityId — so the wire ACKNACK carries the id of the reader the remote writer actually matched (not the primary's). An empty route (discovery-less / pre-match / N=1) falls back to the primary under `disc-node-user-reader-id` — byte-identical to the pre-S2 hooks. The node-global store + the per-reader `%drain` filter separate app delivery; the demux keeps each reader's engine reliability state driven by only its own writers.

**Route cardinality (this slice):** the route holds **exactly one reader-EntityId per remote-writer GUID**. `%match-remote-endpoint` route-adds only the FIRST matching local reader per writer, and `%guid-matched-p` is keyed by the remote GUID (so once writer W matches reader A, a same-topic reader B gets no further match attempt). This is correct AND complete for the **different-topic** N-reader case (the shipping capability — each reader matches its OWN writer on a distinct GUID). The **same-topic** N-reader case is **NOT handled here**: it is FAIL-FAST-DEFERRED (§10.6), because a 2nd same-topic reader would be left unrouted and its `%drain` filter (N≥2) would drop ALL its own samples (a silent false-REJECT). The per-reader ACKNACK/NACK_FRAG `dolist` in the HEARTBEAT hooks therefore runs exactly once today; it anticipates the later route-add-all-matching-readers + fan-out-delivery slice, where the same-topic case is implemented for real.

### 10.6 Deferrals (fail-fast, not half-fixed)

- **Same-topic multi-reader → later slice.** A 2nd DataReader on a topic ALREADY held by a local reader on the same participant fail-fasts (`add-local-reader`, "same-topic multi-reader on one participant is a later N-user-endpoint slice"). The source-GUID route holds one reader per writer (§10.5), so a 2nd same-topic reader would be unrouted and silently receive nothing; guarded (like the secured/ZC/durability fences) rather than half-fixed. Two or more **different-topic** non-secured readers are the supported N-reader case. Implementing same-topic (route-add all matching readers + fan-out delivery) is a later slice.
- **Secured/ZC multi-reader → S3/S4.** A 2nd reader on a node that decodes a SecuredPayload on receive (`node-secured-reader-p`, or an already-armed `secured-loan-capable`) OR resolves a zero-copy loan (`zc-loan-capable`) fail-fasts ("secured/ZC multi-reader is Slice S3/S4"). The per-endpoint crypto key material, per-reader secured/loan pools, and the cross-reader use-after-free are S3/S4. The single-secured-reader / single-ZC-reader path stays on the primary + node-global crypto/pool, unchanged.
- **The S1 copy-path KEEP_LAST reader split is left as-is.** `run-keyed-flatdata-copy-behavior-test`'s KEEP_LAST reader stays on its own participant p3 — its per-instance KEEP_LAST behaviour is a single-reader property, verified cleanly there; reverting it to 2-readers-on-one-participant would add nothing S2 does not already prove and is left untouched (documented choice).

### 10.7 Verification

Both impls green (SBCL + Clasp, **445 tests**; 443 baseline + 2 new). Test `dcps-n-reader-per-participant` (`run-dcps-n-reader-test`): one participant, two DataReaders on dcps-msg + shape-type topics fed by two remote writers — each reader takes EXACTLY its own 3 samples, correct struct type + byte-exact fields, and NEVER a sibling topic's sample. **RED captured empirically** by neutralizing the `%drain` filter (`multi` → nil): reader-A deserializing reader-B's shape-type bytes as dcps-msg signals `buffer-overflow: need 12355 octet(s), 12 remaining` (the cross-topic-deserialize corruption, caught by the network-facing bounds check per NFR-SEC-POSTURE); GREEN with the filter restored. Test `n-reader-data-over-udp` (`run-n-reader-dataplane-test`): distinct reader EntityIds/GUIDs (RED on pre-S2 — both `#x0107`), correct route (reader-A↔writer-A only, no cross), the store holds one sample per writer, the route lifecycle (unmatch/lease-expiry drops the route, re-announce re-adds it), the secured / ZC 2nd-reader deferral fail-fasts, AND the same-topic 2nd-reader deferral fail-fast (a 2nd reader on an already-held topic errors deterministically). The endpoint-registry test flips to `:reg-accept-2nd-reader`. N=1 byte-identical (hotpath-purity gate PASS; the whole prior suite unchanged).

---

## 11. Slice S3 — per-endpoint crypto key material (as-built, WP-N-ENDPOINT-S3-CRYPTO)

N SECURED local DataWriters per participant (on **distinct** topics — same-topic secured multi-writer stays deferred, §11.5), each **independently keyed** — each signs/encrypts its payload under ITS OWN §8.5 EntityCrypto KeyMaterial (distinct `sender_key_id`) advertising ITS OWN topic's protection kind; a remote's `find_key`/decode resolves each by GUID/`key_id`. Secured/ZC READERS stay S4 (per-reader secured decode pools are node-scoped, untouched here). The §8.5 EntityCrypto registry was already `EntityId`-keyed (get-or-create per EntityId); only the call sites hardcoded to the single pair were fixed.

### 11.1 The send crux — per-writer key/kind derivation (`dataplane.lisp`, the crypto-correctness gate)

`publish-sample` already routes to the correct engine writer via `writer-id`/`%user-writer-for`. The §9.5.3.3.4.4 encode now derives BOTH the skip gate (data_protection `:none` → payload rides plain) AND the encode GUID from the **actual publishing writer's** `EntityId` (`rtps-writer-entityid`, threaded into `%local-writer-guid-vec`), not the node-single `user-writer-id`. So `crypto-keys` `encode-key-fn` resolves THAT writer's km — writer2 signs under writer2's km, never the primary's. Pre-S3 (with the fail-fast bypassed) both writers used the node-single (last-added) id → writer1 would sign under writer2's key; the S3 test captures this RED empirically.

### 11.2 Per-endpoint protection-kind map (`disc.lisp`), strictly finer than the 2 role slots

A new `user-endpoint-protection-kind` disc-node hash (`EntityId → (data-kind . submessage-kind)`) is populated at `add-local-{writer,reader}` (`%refine-user-protection`) from THAT endpoint's OWN topic via the existing `topic-{data,metadata}-protection-resolver`. `%user-endpoint-kinds` reads it (role-slot fallback at N=1 → byte-identical). `%cm-entity-protection-kind` (`crypto-manager.lisp`) derives each user endpoint's km kind from its map entry instead of the 2 role slots. This is strictly FINER than the ADR-0046 role slots — adding one endpoint never mutates another's entry, so the cross-role false-ACCEPT downgrade fix is preserved and generalized to N (the shared MAX-aggregate `user-{data,submessage}-protection-kind` slots stay for the participant-scope fast-skip/prescan/ZC-guard consumers).

### 11.3 Enumerate-all token exchange (`crypto-manager.lisp`)

`%cm-local-token-entities` now appends `%all-user-writer-ids` (each paired with `+gm-datawriter-crypto-tokens+`) and `%all-user-reader-ids` after the 8 secure builtins, so `cm-on-authenticated`'s register + token-send loops register + exchange ONE EntityCrypto per local endpoint. At N=1 this is exactly the pre-S3 pair in the same order → byte-identical. The match-time re-exchange (`cm-on-endpoint-match`) threads the ACTUAL matched local writer's `EntityId`, resolved by the matched remote reader's topic in `%on-disc-match` (`%local-user-writer-id-for-topic`), so each writer's token goes out keyed to the right remote (reader path stays node-single, S4).

### 11.4 Arena backref teardown reachability (`disc.lisp` / `dataplane.lisp`)

The secured-payload encode pool is already per-writer (on the writer's HistoryCache). The node arena backref `payload-arena` becomes a **list** (`%ensure-secured-payload-pool` pushes each writer's carved arena; `stop-node` frees every one), so a 2nd secured writer's carve no longer orphans the first writer's arena at teardown. The push is serialized by a dedicated leaf `payload-arena-lock` (the carve runs under the per-**writer** lock, so two writers racing their first secured publish would otherwise lost-update the shared list and orphan one arena — freed at process exit anyway, never a double-free; the dedicated lock closes it). The node-global send-scratch / submsg-scratch pools stay shared (dimensioned by threads, not writers). Not an encode-correctness change — teardown reachability only.

### 11.5 Fail-fast lift

`%register-user-writer`'s secured-writer guard is removed (secured multi-writer supported). The flow-controller (S1b) and RETAINING-durability deferral guards stay. The secured/ZC **reader** fail-fast (`%register-user-reader`) is UNCHANGED — that stays for S4. The now-unused `%node-secured-writer-p` predicate is deleted.

**Same-topic secured multi-writer stays deferred (availability guard, mirrors S2's same-topic reader guard).** N secured writers are supported on **distinct** topics. Two secured writers on the **same** topic is deferred: the §8.5.2 crypto-token destination-correction re-exchange resolves the local writer by topic (`%local-user-writer-id-for-topic`, `find … :test string=`) and holds ONE per topic, so a 2nd same-topic secured writer would miss its match-time key install at a **strict** remote (Fast DDS rejects a wrong `destination_endpoint_key`) → its samples undecodable there (a fail-closed **availability** loss, never a mis-sign/downgrade). `add-local-writer` fail-fasts a 2nd SECURED writer on an already-held topic (`%topic-secured-writer-p`, governance-scoped: a topic whose data or metadata protection resolves non-NONE), mirroring the S2 same-topic-reader guard. **Scoped to secured** — a 2nd NON-secured writer on the same topic stays allowed (S1; no token exchange involved).

### 11.6 Verification

Both impls green (SBCL + Clasp, **446 tests**; 445 baseline + 1 new). Test `security-n-secured-writer` (`run-security-n-secured-writer-test`): one participant, two SECURED writers on Circle (data=ENCRYPT) + Square (data=SIGN) → distinct EntityIds. Asserts (a) both register (the fail-fast is lifted); (b) `%cm-local-token-entities` enumerates both writers; (c) `%cm-entity-protection-kind` returns each writer's OWN topic kind (ENCRYPT vs SIGN — no PEP downgrade); (d) each writer resolves a DISTINCT km (distinct `sender_key_id`); (e) **the send-crux** — each writer's emitted DATA carries ITS OWN km `key_id` (octets 4..7), writer1 NOT under writer2's key; (f) a remote crypto-manager resolves + decodes BOTH by wire `key_id`, and a cross-key decode FAILS closed; **plus the same-topic guards** — a 2nd SECURED writer on the already-held Circle topic FAIL-FASTS, while two NON-secured writers on a `data=NONE` topic (Triangle) still register (the guard is scoped to secured topics). **RED captured empirically** by reverting the send-crux `%local-writer-guid-vec` to the node-single id: `:s3-writer1-own-key-id` fails — writer1's DATA carries writer2's `key_id` (writer1 signs under writer2's km). The `n-writer-data-over-udp` deferral test flips from asserting the secured-writer fail-fast to asserting the 2nd secured writer REGISTERS with 2 distinct EntityIds. The ADR-0046 PEP cross-role downgrade + mixed-kind-reject tests stay green. N=1 byte-identical (the token order / encode GUID / km kind for one writer == the pre-S3 node-single value); corpora/KATs/goldens untouched (this changes WHICH km a writer uses, not the AEAD/token format).

## 12. Slice S4 — N loan-capable readers (as-built, WP-N-ENDPOINT-S4-POOLS)

A participant with a Subscriber holding TWO (N) **loan-capable** (secured OR zero-copy) DataReaders on **distinct** topics with **distinct** protection kinds now works: each reader `read`/`take`s only its own topic's samples, decodes under ITS OWN protection tier, and returns its loans independently — reader-A's return-loan never frees reader-B's buffer. Pre-S4 the 2nd loan-capable reader FAIL-FASTED (`%register-user-reader`). This is a **pool-per-reader WIRING + fence lift**, NOT a use-after-free refactor.

### 12.1 The key finding — the cross-reader UAF is structurally UNREACHABLE (two separate fences)

There are TWO separate second-reader fences: (1) the **secured/ZC fence** (`%node-secured-or-zc-reader-p`, enforced in `%register-user-reader`) fires for ANY 2nd loan-capable reader regardless of topic; (2) the **same-topic fence** (`add-local-reader`) fires for a 2nd reader on an already-held topic. **S4 lifts ONLY fence (1); fence (2) STAYS.** So the two loan-capable readers S4 enables are always on DIFFERENT topics → each matches its own remote writer on a DISTINCT source-GUID (the S2 route partition) → they NEVER share a `(guid,SN)` slot or ZC marker → the ADR-0017 UAF precondition ("two loan-capable readers sharing one source-GUID→SN") is impossible by construction. The DCPS loan registries are already per-reader (`dr-loans`, `dr-secured-loans`); `%secured-loan-release` is identity-guarded + idempotent. **Do NOT lift the same-topic fence** — a 2nd SAME-topic loan-capable reader is a later slice (ADR-0017 refcount-per-reader).

### 12.2 The per-reader decode tier — the correctness gate (`dataplane.lisp`)

`%deliver-user-sample` selected the secured decode on/off from the node-SINGLE `disc-node-user-reader-data-protection-kind`. With 2 different-topic readers of different kinds this is wrong: the reader whose kind is NOT last-added would decode under the sibling's tier. FIX: resolve the target reader from the source-GUID (`%reader-routes-for`, already on this path for the S2 delivery demux) and read THAT reader's OWN kind via `%user-endpoint-kinds` (the S3 per-endpoint map). `routes`/`canon`/`rid`/`rkind` are computed ONCE at the top of the let and reused for both the tier gate and the delivery (DRY). The tier gate is binary — `(not (eq rkind :none))` — the NONE-vs-secured on/off decision (the SIGN-vs-ENCRYPT selection was already per-GUID in the resolved km, never node-single). Both bug directions matter: a plain (NONE) reader whose sample would be decode-attempted+dropped under a sibling's secured tier (false-REJECT), AND — the security-critical direction — a secured reader whose SecuredPayload would ride PLAIN (undecoded, false-ACCEPT of unauthenticated data) under a sibling's NONE tier. At N=1 `rkind` == the node-single slot → byte-identical.

### 12.3 The ZC marker demux (`dataplane.lisp`)

`%deliver-user-marker` fed `(disc-node-user-reader node)` = the PRIMARY unconditionally (the ZC path was never S2-wired because it fail-fasted at N≥2). It now mirrors `%deliver-user-sample`'s `%reader-routes-for` demux: a ZC marker from source-GUID W is delivered to the CANONICAL reader matched to W (its reliable proxy + per-reader dedup), not the primary. So each ZC reader's loan/marker state is driven only by ITS OWN writers. N=1/pre-match falls back to the primary → byte-identical to the old primary-only path.

### 12.4 The node-shared decode pool is kept (NOT partitioned)

The node-shared `decode-pool`/`decode-arena`/`secured-loan-vec` are a fixed-capacity RESOURCE pool, safe for different-topic readers: each accepted loan is a DISTINCT `secured-loan-handle` tied to a DISTINCT `(guid,SN)` slot; `%secured-loan-release` is identity-guarded (evicts only when THIS handle still occupies the slot) and idempotent. Releasing reader-A's loan cannot touch reader-B's handle/buffer. Per-reader pools are OPTIONAL isolation, NOT required for safety — deliberately out of scope (keeps the slice thin; pool exhaustion is a fail-closed SAMPLE_REJECTED, never a UAF). `node-take-loaned`'s whole-store snapshot is the low-level C-API + reader-close backstop; the DCPS path drains via the S2-filtered per-reader `%drain`→`%drain-one-secured`, already per-reader — left unchanged.

### 12.5 Fail-fast lift

`%register-user-reader`'s `%node-secured-or-zc-reader-p` guard is removed (a 2nd loan-capable reader now registers). The same-topic fence in `add-local-reader` STAYS (the sole UAF-guard). The now-unused `%node-secured-or-zc-reader-p` predicate is RETAINED (docstring updated) for the future same-topic loan-capable multi-reader slice.

### 12.6 Verification

Both impls green (SBCL + Clasp, **448 tests**; 446 baseline + 2 new). New test `n-reader-s4-decode-tier` (`run-n-reader-s4-decode-tier-test`): (1) node-single DOWNGRADED to NONE (plain reader added last) — a secured reader STILL REJECTS an unprotected sample under its OWN ENCRYPT tier (the security-critical direction; a node-single NONE would false-ACCEPT it), the coexisting plain reader still receives its plaintext; (2) node-single UPGRADED to secured (secured reader added last) — a plain reader STILL RECEIVES its plaintext under its OWN NONE tier (a node-single ENCRYPT would decode-attempt+DROP it), plus a DARE-gated live ENCRYPT-decode of the secured reader under its own tier; (d) no-cross-free — two distinct secured-loan handles in the shared registry, releasing one leaves the other's buffer + registration + stored slot intact. Also asserts both readers register with 2 distinct EntityIds and `%user-endpoint-kinds` returns each reader's OWN kind. **RED captured empirically** by reverting the tier to the node-single slot: the security-critical gate fails (the secured reader false-ACCEPTs the unprotected sample). New test `n-reader-s4-zc-marker` (`run-n-reader-s4-zc-marker-test`): 2 ZC readers on distinct topics; a marker for reader-B carrying a logical-origin `(GUID,SN)` the primary already saw is STILL accepted (reader-B's OWN dedup is fresh) and stored under reader-B's source GUID — **RED captured** by reverting `%deliver-user-marker` to primary-only (reader-A's dedup rejects the shared origin as a duplicate → reader-B loses its marker). The `n-reader-data-over-udp` deferral test flips (4)/(4b) from asserting the secured/ZC fail-fast to asserting the 2nd different-topic loan-capable reader REGISTERS with 2 distinct EntityIds; (4c) — a 2nd SAME-topic reader — STILL fail-fasts (the UAF-guarding invariant). N=1 byte-identical (the per-reader kind lookup for one reader == the node-single value; the ZC demux with one reader == the old primary path); wire unchanged (local delivery routing + decode-tier selection); corpora/KATs/goldens untouched.

## 13. Slice S5 — per-endpoint status/listener dispatch (as-built, WP-N-ENDPOINT-S5-CLEANUP)

The FINAL slice, completing the milestone's different-topic capability. It closes a SILENT correctness bug: the DCPS layer kept single participant-wide back-refs `dp-user-reader` / `dp-user-writer` (`entities.lisp`, set LAST-created-wins at `create-datareader` / `create-datawriter`), and NINE disc→DCPS hooks read them — so at N≥2 (different topics) every status counter, listener callback, and WaitSet/DATA_AVAILABLE wake was delivered to the LAST-created endpoint instead of the endpoint the event is ABOUT. Control-plane only (no wire/engine/disc-node-shape/crypto change; corpora/KATs/goldens untouched).

### 13.1 The reverse lookup (the crux — no EntityId→DCPS-object map existed)

Two resolution strategies, matching the shipped DIFFERENT-topic capability (same-topic is fail-fast-deferred, so ≤1 local endpoint per topic):

- **Topic resolution (the 7 HARD hooks — match/unmatch/incompatible).** The callback carries the remote `endpoint-data`; the local DCPS entity is resolved by `endpoint-data-topic-name` against `%participant-readers` / `%participant-writers` (matching `dr-topic` / `dw-topic` name). One shared reader-side + writer-side helper each — `%participant-reader-for-topic` / `%participant-writer-for-topic` — DRY across the 7 hooks. No match → the event is DROPPED (never mis-delivered to a wrong endpoint).
- **GUID→route resolution (the liveliness hook).** The callback carries the full 16-octet remote writer GUID; it resolves via the S2 delivery route `%reader-routes-for(guid)` → reader-EntityId(s) → the DCPS reader by `dr-entity-id` (`%participant-readers-for-writer-guid`, built on the shared `%participant-reader-by-entity-id`). Reuses the S2 route partition; ≤1 reader per writer today (same-topic fence). Empty route → drop.

### 13.2 The nine rewired hooks

Seven HARD app-visible correctness hooks (a status counter + listener for the WRONG entity): `%on-disc-match` `:remote-writer` (SUBSCRIPTION_MATCHED + durability-init + type-compat) and `:remote-reader` (PUBLICATION_MATCHED + durability-init; the S3 crypto-token writer was ALREADY per-topic via `%local-user-writer-id-for-topic` — now the `%writer-matched` status delivery is consistent with it); `%on-disc-unmatch` both directions; `%on-disc-incompatible` both directions (REQUESTED/OFFERED_INCOMPATIBLE_QOS); `%on-disc-liveliness-changed` (LIVELINESS_CHANGED + owner-takeover). Two DEGRADED-wake hooks: `%on-disc-lifecycle` (dispose/unregister DATA_AVAILABLE wake) and `%on-participant-sample` (data-ready WaitSet wake).

### 13.3 The two degraded-wake hooks — the disc callbacks carry NO routable writer identity

`%on-participant-sample` is invoked by the disc layer with NO arguments (`dataplane.lisp`), and `%on-disc-lifecycle` with only the remote writer EntityId (not a full GUID, and the disc-node-shape/callback-arity is UNCHANGED by constraint) — so neither can drive `%reader-routes-for`. Both are rewired to wake EVERY local reader (`%participant-readers`, DRY via `%wake-reader-data`). This is correct-by-superset: the actual per-reader SAMPLE delivery is already governed by the S2 source-GUID `%drain` filter (each reader deserializes only its own matched writers' bytes), so waking a reader with nothing pending is a benign spurious DATA_AVAILABLE (level-triggered, DDS 1.4 §2.2.4.1 — a WaitSet/listener must tolerate it and re-checks to find NO_DATA). It NEVER mis-delivers another endpoint's data, and it strictly IMPROVES on the retired back-ref (which woke only the LAST-created reader, so at N≥2 a reader that received data but was not last-created was NEVER woken — a real missed-wake). N=1 == the sole reader, byte-identical.

### 13.4 The slot deletion

The two slots `dp-user-reader` / `dp-user-writer` and their two `setf` sites are DELETED. Removing the slots deletes the accessors, so all 9 read sites were rewired FIRST (compilation-enforced completeness). The participant-level aggregates that legitimately iterate ALL endpoints (`%participant-writers` / `%participant-readers` driving the liveliness-sweep, autopurge, and loan-return) are LEFT ALONE — already correct.

### 13.5 Verification

Both impls green (SBCL + Clasp, **449 tests**; 448 baseline + 1 new). New test `n-endpoint-s5-status` (`run-n-endpoint-s5-status-test`): ONE participant with TWO different-topic DataReaders (A=dcps-msg, B=shape-type) + TWO DataWriters, each with its OWN capturing listener; endpoint-B is created FIRST and endpoint-A LAST, so the retired back-ref (= last-created = A) would mis-deliver every topic-B event to A. It fires all four HARD hook families (match / liveliness / incompatible-qos / unmatch) for a remote on TOPIC-B and asserts each lands on ENDPOINT-B (status counter bumps + listener fires) and NEVER on ENDPOINT-A (counter stays 0 + listener silent). **RED captured empirically** by reverting `entities.lisp` to the old back-ref (keeping the new test): the first assertion `s5-match-b-sub` fails (the topic-B match delivered to the last-created reader-A). N=1 byte-identical (the topic resolver returns the sole entity == the old back-ref; the liveliness route with one reader falls back to == the old primary); the existing single-endpoint status/liveliness tests (`dcps-matched-status`, `lease-unmatch`, `liveliness-changed`, `liveliness-lost`) stay green. Wire/engine/disc-node-shape/crypto unchanged; corpora/KATs/goldens untouched.
