# ADR 0048 — N user DataWriters/DataReaders per participant: the endpoint registry (Slice S0) + the milestone slice plan

- **Status:** Accepted (WP-N-ENDPOINT-S0-REGISTRY, 2026-07-05). Slice S0 landed; S1–S5 planned (not started).
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
- **S1 — N local writers.** Send-path fan-out: `publish-sample` / durability / batching iterate `%all-user-writers`; per-writer `EntityId` on the wire.
- **S2 — N local readers.** Delivery routing: `%on-user-data` routes by destination reader `EntityId` to the right engine reader (the `%drain` cross-topic-deserialize hazard lives here).
- **S3 — per-endpoint crypto key material.** Move `crypto-transform` / EntityCrypto resolution off node-scope to per-endpoint.
- **S4 — per-endpoint pools.** Per-writer ZC pool + per-reader secured/loan pools (the cross-reader use-after-free; converges with the ZC-loan work).
- **S5 — cleanup.** Retire the `dp-user-writer` / `dp-user-reader` single DCPS back-refs.

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
- **Deferred (tracked by this ADR).** S1 (send fan-out), S2 (delivery routing + the `%drain` cross-topic hazard), S3 (per-endpoint crypto), S4 (per-endpoint ZC/secured pools + the cross-reader UAF), S5 (retire the `dp-user-writer` / `dp-user-reader` back-refs). Until S1/S2 land, a second distinct local user endpoint fail-fasts.
