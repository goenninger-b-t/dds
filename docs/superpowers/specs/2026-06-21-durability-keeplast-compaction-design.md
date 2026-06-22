# WP-DURABILITY-KEEPLAST-COMPACTION — design

- **Status:** Approved (design), 2026-06-21. M6/P5. ADR 0026 §10 follow-on (KEEP_LAST-superseded compaction).
- **Relates to:** ADR 0026 (disk-backed PERSISTENT durability + conservative compaction-on-open), ADR 0025
  (DARE envelope), ADR 0023 (durability service). Builds on the per-sample-table pattern shipped in ADR
  0028 (logical-origin capture).
- **Standards:** DDS 1.4 §2.2.3.5 (DURABILITY_SERVICE QoS: history_kind + history_depth), §2.2.3.18 (HISTORY),
  RTPS 2.5 §9.6.4.8 (key-hash / `PID_KEY_HASH`).

---

## 1. Problem — the current state

The durability store's compaction-on-open (`%compact-topic-records`, `src/dds-durability/store-file.lisp`
~line 345) is conservative: it drops an instance only when it is **settled** (both a `:dispose` AND an
`:unregister` tombstone present, and the final lifecycle record is a tombstone), and it never drops a live
or resurrected instance. It does **not** bound per-instance sample count: a writer that updates one instance
N times leaves N retained `:data` records forever, so the store (and a late-joiner's replay) grows without
bound and re-delivers stale superseded values.

Two facts block a per-instance KEEP_LAST fix today:

1. **Data records carry no instance handle.** `%collect-loop` (`src/dds-durability/service.lisp` ~line 228)
   stores data as `(store-put store topic origin-guid origin-sn NIL :data payload)` — **key-hash = NIL**.
   Only lifecycle changes store the real key-hash (~line 249). So the store cannot group `:data` records by
   instance. The `durable-record` struct already has a `key-hash` slot (`store.lisp` ~line 12); it is simply
   never populated for data.
2. **No depth source.** The replay writer is KEEP_ALL; `service-spec` (`src/dds-durability/spec.lisp` ~line
   6) has no history field. There is nowhere to express "keep the last N per instance."
3. **The service is type-agnostic.** It forwards opaque CDR payloads and has no type knowledge, so it
   cannot *compute* a keyhash from the payload — it must read `PID_KEY_HASH` from the incoming DATA's
   inline-QoS. The reliable reader already parses it (the cache-change carries an `instance-key-hash`,
   `dataplane.lisp` ~line 423); the relay's `publish-relay-sample` already accepts a `key-hash` arg (~line
   1008) and threads it to the wire. The missing link is capturing + exposing the per-data-sample key-hash
   to the collect loop.

## 2. Goal

Bound per-instance retained sample count under a DDS-standard DURABILITY_SERVICE `KEEP_LAST(depth)` policy:
for each instance (key-hash), keep only the newest `depth` `:data` records and compact away the older
superseded ones — so a restart/late-joiner replays only the KEEP_LAST-current values per instance, never the
full superseded history — while never dropping a still-relevant sample, preserving the existing
dispose/unregister-settled compaction + resurrection safety, and keeping the cross-restart key-epoch / DARE
envelope semantics intact. Both the disk-backed file-store and the in-memory store.

## 3. Approaches considered (the per-instance compaction core)

- **A — Capture the data key-hash + per-instance KEEP_LAST (chosen).** Capture `PID_KEY_HASH` off the wire
  into the disc-node, store each `:data` record under its instance, and compact to `depth` per instance.
  The only design correct for keyed topics. Needs a small, precedented disc-node key-hash capture (mirrors
  the ADR 0028 logical-origin capture).
- **B — Global KEEP_LAST per topic (not per-instance).** No key-hash needed, but collapses distinct
  instances (e.g. different `ShapeType` colors) into one N-deep window, dropping live instances. Wrong for
  keyed topics. Rejected.
- **C — Reconstruct the instance from the payload.** The service parses the keyed payload to derive the
  instance — violates the type-agnostic boundary (no generated type knowledge in the service). Rejected.

## 4. Design (Approach A)

### 4.1 `service-spec` — DURABILITY_SERVICE QoS

Add a DURABILITY_SERVICE history config to `service-spec`: `history-kind` (`:keep-all` default | `:keep-last`)
and `history-depth` (a positive integer, used only for `:keep-last`). **Default `:keep-all` → no compaction
→ byte-identical to today.** Opt-in `:keep-last N` per service (DDS 1.4 §2.2.3.5). Plumbed to the store
factory / compaction so the store knows its policy.

### 4.2 `dds-disc` — capture the per-sample data key-hash

A per-sample `sample-key-hashes` table (outer wire-guid → SN → 16-octet key-hash), set in
`%deliver-user-sample` from the cache-change's already-parsed `instance-key-hash` (wire `PID_KEY_HASH`), via
a shared `%record-sample-key-hash` setter — recorded only when a key-hash is present (NIL otherwise →
nothing stored, byte-identical). New exported accessor `node-sample-key-hash (node key) → (or
(simple-array (unsigned-byte 8) (16)) null)`. **Structurally identical to the ADR 0028 `sample-origins`
capture** (control-plane; `gate-hotpath` + `make mem` 0.0000 unaffected).

### 4.3 `dds-durability` — store data under its instance

`%collect-loop` data drain resolves the instance once: `(node-sample-key-hash node key)` and passes it to
`store-put` (replacing the `NIL`). The file-store frame already carries an optional key-hash behind a flag
bit — no frame-format change; data frames now set the kh-present flag when a key-hash exists. NIL key-hash →
unchanged (no flag), byte-identical.

### 4.4 Compaction — per-instance KEEP_LAST

Extend `%compact-topic-records` so that, under `:keep-last depth`:
1. Run the existing dispose/unregister-settled drop + resurrection-safety FIRST (unchanged).
2. Then, for each **non-NIL-key-hash instance**, keep only the newest `depth` `:data` records, dropping the
   older superseded ones. "Newest" = the store's existing total order over `(writer-guid, sn)` records
   (`%record-guid-sn<` / the established sort): keep the `depth` records that sort highest. For the common
   single-origin instance (one publisher per key, the post-ADR-0028 convergence case) this is exactly the
   `depth` highest SNs and is unambiguous; a precise multi-writer-per-instance merge order is a documented
   follow-on. Lifecycle (`:dispose`/`:unregister`) records are never dropped by this pass.
3. **Records with a NIL key-hash are NEVER compacted** — we cannot distinguish a NO_KEY topic from a peer
   that omitted `PID_KEY_HASH`, so we never risk collapsing instances (safety over completeness). NO_KEY
   KEEP_LAST is a documented follow-on.

`:keep-all` → the function is byte-identical to today (the per-instance pass is skipped).

### 4.5 In-memory store — online eviction

The in-memory store (`%mem-put`) gains online per-instance eviction: on `put` under `:keep-last depth`, once
a non-NIL-key-hash instance exceeds `depth` `:data` records, drop its oldest — bounded steady-state growth
for the TRANSIENT tier. Same KEEP_LAST-per-instance semantics as the file-store, applied at the natural
point for a RAM store (the file-store is append-only, so it compacts on open instead).

### 4.6 Cross-restart / DARE intact

File-store compaction reuses the existing `%rewrite-topic-log` (atomic `uiop:rename-file-overwriting-target`,
re-sealing each kept record through the DARE envelope under the current epoch). The cross-restart key-epoch
semantics (ADR 0026) and the v2 envelope (ADR 0025) are untouched; the key-hash is already AAD-bound in the
v2 envelope, so storing it for data records strengthens, never weakens, the at-rest integrity binding.

### 4.7 Data flow

A keyed peer writes M samples for instance K → the collect loop stores each under K (captured key-hash) →
under `:keep-last D`, compaction (file-store on open / in-memory on put) retains instance K's newest D,
drops the older M−D → a restart or late-joiner replays D-per-instance, not the full superseded history.

## 5. Testing — Definition of Done

1. **Spike (T0):** confirm what `PID_KEY_HASH` Connext 7.3.1 and Fast DDS 3.6.1 put on keyed `ShapeType`
   **data** (not just dispose/unregister) — this gates the live per-instance DoD. Honest finding if a peer
   omits it.
2. **In-process (deterministic, both impls):** a keyed multi-sample-per-instance store under `:keep-last D`
   keeps exactly the newest D per instance, drops the older, never drops a live or
   disposed-then-resurrected instance, leaves NIL-key-hash records untouched; `:keep-all` is byte-identical
   (regression). The in-memory online-eviction path and the file-store compaction-on-open path are both
   covered, plus a cross-restart test (write M, compact to D, reopen, replay D).
3. **Cross-DDS interop (the per-feature DoD):** a Connext (and Fast DDS) publisher writing multiple samples
   per keyed instance → our service stores with captured key-hashes → `:keep-last D` → a late-joiner
   receives D-per-instance. If the spike shows a peer omits `PID_KEY_HASH` on data, that direction falls
   back to keep-all-safe and the in-process test is authoritative (documented honestly).
4. **All quality gates green both impls (Clasp first):** `make test`, `gate-hotpath`, `gate-types`, `mem`
   (0.0000), `fuzz`, `wire`.

## 6. Decomposition (subagent-driven, spike-first)

- **T0 — spike.** Capture Connext + Fast DDS keyed-`ShapeType` data on the wire; document the `PID_KEY_HASH`
  presence + value per peer. Re-plan checkpoint after T0 (mirrors the prior WP).
- **T1 — disc-node key-hash capture.** `sample-key-hashes` table + `%record-sample-key-hash` +
  `node-sample-key-hash` accessor (exported) + unit test (keyed sample → key-hash; unkeyed → NIL).
- **T2 — service-spec DURABILITY_SERVICE QoS + collect-loop stores the instance.** New history-kind/depth
  config (default `:keep-all` byte-identical) + `%collect-loop` stores data under the captured key-hash +
  test.
- **T3 — file-store per-instance KEEP_LAST compaction.** Extend `%compact-topic-records` (per-instance
  newest-D, NIL-key-hash untouched, settled/resurrection preserved) + the `%rewrite-topic-log`/DARE path +
  a cross-restart KEEP_LAST test.
- **T4 — in-memory online eviction.** `%mem-put` per-instance eviction under `:keep-last` + test.
- **T5 — capstone.** ADR + docs lockstep (README, wiki, verification.csv) + cross-DDS interop (Connext +
  Fast DDS) + final whole-branch review → squash-merge presented for owner approval (HOLD PUSH).

## 7. Risks

- **Type-agnostic key-hash dependency (moderate):** per-instance compaction needs the wire `PID_KEY_HASH`;
  the T0 spike de-risks it. The safe keep-all fallback means the WP is always correct, only the live
  per-instance demonstration is peer-dependent — escalate/document honestly, do not weaken a test.
- **NO_KEY KEEP_LAST descoped (low):** NIL-key-hash records are never compacted (safety), so a NO_KEY topic
  does not get KEEP_LAST compaction in this WP — documented follow-on.
- **Append-log growth between opens (low):** the file-store compacts on open, so steady-state on-disk size
  is bounded across restarts but can grow within one long run — online file-store compaction is a follow-on
  (the §10 item targets compaction-on-open).

## 8. Non-negotiables (inherited)

- Control-plane only (disc-node relay store + durability store, not the measured CDR hot path);
  `gate-hotpath` + `make mem` 0.0000 unaffected.
- `defun*`/`defstruct*` + full ftype declarations on every new function.
- No wire constants from memory — `PID_KEY_HASH` / key-hash rule pinned from RTPS 2.5 §9.6.4.8, reusing the
  existing parse; bounds-checked.
- No reader conditionals outside `dds-pal/`. Clasp + SBCL both validate, Clasp first.
- Default `:keep-all` is byte-identical to today; never drop a still-relevant sample (safety > completeness).
- No AI / assistant attribution in any repo file.

## 9. References

- ADR 0026 — PERSISTENT durability + conservative compaction-on-open (`%compact-topic-records`).
- ADR 0028 — logical-origin per-sample capture (the disc-node per-sample-table + accessor pattern to mirror).
- `src/dds-durability/store-file.lisp` — `%compact-topic-records`, `%rewrite-topic-log`.
- `src/dds-durability/store.lisp` — `durable-record` (key-hash slot), `store-put`, `%mem-put`.
- `src/dds-durability/spec.lisp` — `service-spec` (where the DURABILITY_SERVICE config goes).
- `src/dds-durability/service.lisp` — `%collect-loop` (the `NIL` data key-hash to fix).
- `src/dds-disc/dataplane.lisp` — `%deliver-user-sample`, the cache-change `instance-key-hash`,
  `publish-relay-sample` (the relay's `key-hash` arg).
