# ADR 0029 — Per-instance KEEP_LAST compaction in the durability service (DDS 1.4 §2.2.3.5)

- **Status:** Accepted (M6/P5; WP-DURABILITY-KEEPLAST-COMPACTION, 2026-06-22)
- **Resolves:** ADR 0026 §10 follow-on "KEEP_LAST-superseded compaction". Builds on ADR 0026
  (disk-backed PERSISTENT store, `%compact-topic-records` pass 1, cross-restart key-epoch,
  DARE delegation), ADR 0025 (CNSA-2.0 DARE envelope). The T0 spike
  (`docs/superpowers/spikes/2026-06-21-keyhash-on-keyed-data.md`) confirmed `PID_KEY_HASH`
  presence on matched Connext 7.3.1 + Fast DDS 3.6.1 ShapeType data.
  Standards: DDS 1.4 §2.2.3.5 (DURABILITY_SERVICE QoS — `history_kind` / `history_depth`),
  RTPS 2.5 §9.6.4.8 (`PID_KEY_HASH`, `0x0070`).

## Context

The ADR 0026 file-store compaction (pass 1 = dispose+unregister-settled) removed logically dead
instances across restarts, but it did not bound the on-disk record count for live instances.
Under a long-lived PERSISTENT service writing to a single keyed topic, the per-instance `:data`
count grew unboundedly. DDS 1.4 §2.2.3.5 specifies a `DURABILITY_SERVICE` QoS that lets the
writer (or a persistence service acting on its behalf) apply a `history_kind = KEEP_LAST` /
`history_depth = N` policy to bound the retained sample count per instance.

The blocking question: does the wire actually carry a per-instance handle that the service can
use to identify instances without type knowledge? A T0 spike confirmed: **both Connext 7.3.1
(767 matched samples) and Fast DDS 3.6.1 (362 matched samples) send `PID_KEY_HASH (0x0070)` on
every DATA-with-payload when there is a matched reader**. The service's collect reader IS matched
(it is the reader), so key-hashes arrive on every collected sample once the collect reader and
the publisher have discovered each other.

## Decision — as-built

### T1 — Node-gated key-hash capture (`disc-node`, `dataplane.lisp`)

The `disc-node` struct gains a `capture-data-key-hash` boolean slot (default `NIL`). When `NIL`
(the default for all existing nodes), `parse-data-body` does not materialise the wire
`PID_KEY_HASH` — the code path is **byte-identical** and adds **zero allocations**. When `T`,
the parser captures the 16-octet key-hash into the `sample-key-hashes` table
(`src-guid → SN → 16-octet array`). The durability collect disc-node opts in by passing
`:capture-data-key-hash T` to `make-disc-node`. The exported reader is:

```lisp
dds.disc:node-sample-key-hash (node key)  ; key = (writer-guid . sn)
                               ; → (simple-array (unsigned-byte 8) (16)) | NIL
```

NIL means the key-hash was absent in the wire DATA (e.g. the foreign publisher is not yet
matched, or the topic is `NO_KEY`). The collect loop stores `NIL` in that case and the compaction
pass treats NIL-key-hash records as a single un-keyed aggregate that is **never compacted**.

### T2 + T3b — Policy source: `service-spec` wired via `store-open`

`service-spec` carries two new fields:

```lisp
(history-kind  :keep-all  ; (member :keep-all :keep-last); default = :keep-all (DDS 1.4 §2.2.3.5)
 history-depth 1)         ; (integer 1); KEEP_LAST depth bound per instance
```

`make-service-spec` accepts `&key (history-kind :keep-all) (history-depth 1)`. This is the
**single functional source** of the KEEP_LAST policy for a service instance.

`store-open` signature extended:

```lisp
(dds.durability:store-open store &optional history-kind history-depth)  ; → T
```

At `service-start`, the service calls `(store-open store history-kind history-depth)` with the
values from its `service-spec`. Both stores honour the `store-open` arguments as a **runtime
override** of the factory-time default (which is always `:keep-all` by default). The factory
params (`make-file-store :history-kind …`, `make-persistent-store-factory :history-kind …`) set
the structural default for direct use without a service; `store-open` overrides them when called
by `service-start`, making the `service-spec` the authoritative source in service mode.

### T3 — File-store per-instance KEEP_LAST compaction-on-open (`%compact-topic-records` pass 2)

`%compact-topic-records` gains a second pass, run only when `history-kind = :keep-last`:

1. **Pass 1** (unconditional, unchanged): drops settled dispose+unregister instances;
   preserves resurrected instances.
2. **Pass 2** (KEEP_LAST only): for each non-NIL-key-hash instance, sorts its `:data` records
   by `(writer-guid, sn)` ascending, keeps only the newest `HISTORY-DEPTH`, drops the rest.
   **Lifecycle records (`:dispose`, `:unregister`) pass through untouched.** NIL-key-hash records
   (NO_KEY topics, or early samples before the reader-writer match) are **never touched** —
   conservative: no samples lost.

The rewrite uses an **atomic rename** (same as the existing pass-1 rewrite), so a crash during
compaction leaves the original log intact. DARE integrity is preserved — compaction re-seals
surviving records via `%rewrite-topic-log` under the current epoch's DEK.

`:keep-all` (default) skips pass 2 entirely: byte-identical to ADR 0026 behavior.

### T4 — In-memory store online eviction

The in-memory store (`make-memory-store`) reads the `store-open` policy stash and applies
**online eviction on each `store-put`**: after inserting a `:data` record for a non-NIL key-hash
under `:keep-last D`, if the instance now holds more than `D` `:data` records the lowest-SN
`:data` record is dropped. NIL-key-hash records and lifecycle records are never evicted.
`:keep-all` is the default and is byte-identical to prior behavior.

### T5a — Cross-DDS interop (the per-feature DoD)

Genuine 2-process restart on a shared PERSISTENT file-store opened with `:keep-last 2`:

| Leg | Peer | Collected M (proc 1) | After KEEP_LAST 2 (proc 2) | Late-joiner received |
|---|---|---|---|---|
| **1** | **Connext 7.3.1** | **302** | **2** | **2** |
| **2** | **Fast DDS 3.6.1** | **134** | **2** | **2** |

Both late-joiners received exactly D=2 for the GREEN ShapeType instance. Captures:
`interop/durability-keeplast/captures/`. Proc 2 printed
`DKL-SVC2-KEEPL-COMPACTION-VERIFIED: store holds exactly D=2 records` before any late-joiner
connected.

## Late-joiner semantics — the nuance (document honestly)

**KEEP_LAST via restart-seed:** the file-store compaction-on-open reduces the on-disk record
count to `D` *before* `%seed-relay-from-store` seeds the replay writer's cache. A late-joining
reader connecting to the restarted service receives exactly `D` records.

**Live late-joiner (same running process, no restart):** the replay writer is KEEP_ALL +
publish-on-collect. Its in-memory cache holds all `M` collected records; a reader connecting
while the process is running receives all `M`. KEEP_LAST does NOT retroactively evict the live
replay writer's cache. This is the correct phase-1 behavior (not a defect).

Replay-writer KEEP_LAST (reducing the live in-memory cache on a running service) is recorded as
a §10 follow-on below.

## Spike evidence — `PID_KEY_HASH` on matched DATA

`interop/durability-keeplast/spike/captures/`:
- `connext-pub-sub-matched.pcap` — 767 DATA from Connext 7.3.1; every DATA carries
  `PID_KEY_HASH (0x0070)` with the 16-octet ShapeType keyhash of the GREEN instance.
- `fastdds-pub-sub-matched.pcap` — 362 DATA from Fast DDS 3.6.1; same observation.

Both confirm the type-agnostic key-hash availability on matched pub-sub for keyed topics.

## Conformance

`DURABILITY_SERVICE` QoS is specified in DDS 1.4 §2.2.3.5 (`history_kind`, `history_depth`).
The service applies `HISTORY_DEPTH` `:data` retention per instance, which is the persistence
service's correct role. The wire surface is unchanged (compaction is at-rest-only); cross-DDS
transparency is unaffected. Clean-room: no RTI / eProsima source used; design derived from the
DDS 1.4 §2.2.3.5 spec clause and the wire observations above.

## Consequences

- **NFR-MEM:** no hot-path allocation added; `make mem` stays 0.0000. Compaction is a
  control-plane one-shot at `store-open` time.
- **DARE integrity intact:** compaction re-seals records under the current epoch's DEK; the
  AAD-bound metadata (epoch-id, key-hash, guid, sn, kind) is re-verified on the open path.
- **Byte-identical default:** `:keep-all` (the default for all stores and service-specs) skips
  pass 2 entirely. Existing code using these APIs without passing `history-kind` is unchanged.
- **NIL-key-hash safety:** records without a captured `PID_KEY_HASH` are never compacted or
  evicted, regardless of the configured policy. This is conservative: no data is lost for
  NO_KEY topics or for early samples arriving before the reader-writer match.
- **Gate results:** 307 tests SBCL + Clasp (both deterministic; Clasp validated first);
  `gate-hotpath` PASS; `gate-types` PASS; `mem` 0.0000; `fuzz` PASS; `wire` PASS.

## §10 Follow-ons (recorded, NOT built here)

- **Replay-writer KEEP_LAST for live late-joiners:** evict from the replay writer's KEEP_ALL
  in-memory cache so a same-process late-joiner also receives at most `D` records per instance.
- **NO_KEY KEEP_LAST:** compact NIL-key-hash records when the topic is provably `NO_KEY` (not
  when the key-hash was simply absent from the wire — these two cases are currently
  indistinguishable without type metadata).
- **Online / threshold compaction:** compact the file-store between opens (e.g. when a per-topic
  record count threshold is exceeded), without requiring a `store-close`/`store-open` cycle.
  **RESOLVED** — SQLite backend = **Sliver 1** (WP-DURABILITY-COMPACTION-SQLITE, ADR 0049 §10, online
  per-put eviction); file backend = **Sliver 2** (WP-DURABILITY-COMPACTION-FILE, §10.1 below).
  Encrypted-tier physical reclaim of superseded inner blobs remains **Sliver 3**.

## §10.1 Runtime file-store threshold compaction (Sliver 2, WP-DURABILITY-COMPACTION-FILE, as-built)

**The gap.** The file store compacted KEEP_LAST-superseded records **only on open** (`make-file-store`
`:open` → `%compact-topic-records` → `%rewrite-topic-log` during replay). `:put` is **pure append** —
no eviction. A continuously-open KEEP_LAST file store's per-topic log therefore grew **unboundedly**
between opens (the per-instance `:data` count grew without bound), the exact defect §T3 fixed only at
open time.

**The key difference from Sliver 1.** The file store is **APPEND-ONLY** — it cannot delete a record
in place, so the SQLite per-put `DELETE` model is impossible. Instead the store **batches**: a per-topic
counter of KEEP_LAST-superseded `:data` records, and on crossing a **threshold** it runs the *existing*
atomic `%rewrite-topic-log` **mid-run** (not just on open). Because `%rewrite-topic-log` already writes
`<log>.tmp`, fsyncs, and atomic-renames over the original (re-emitting a fresh v3 MAC chain), Sliver 2
**inherits** crash-atomicity — **no new transaction machinery** is needed (contrast Sliver 1, which had
to wrap SQLite's autocommit DELETEs in a transaction).

**As-built:**

- **O(1)-per-put supersede counter.** `make-file-store` keeps a per-topic `super-pending` count and a
  per-instance `data-counts` `:data` tally. On a `:keep-last` `:data` put with a non-NIL key-hash, the
  instance's `:data` count is bumped (O(1)); when it exceeds depth `D` the put **supersedes** an older
  record, so `super-pending` is bumped. No per-put whole-topic scan.
- **Threshold trigger.** When `super-pending` crosses **`*compaction-superseded-threshold*`** (a new,
  docstring'd special variable, default **128**, tunable) the store runs `%compact-topic-records`
  (pass-1 settled + pass-2 KEEP_LAST, **identical** to on-open) + the atomic `%rewrite-topic-log` for
  that topic **mid-run**, prunes the in-memory index + counters to the survivors, and resets the counter.
  The amortized O(topic) rewrite is spread over ~threshold puts, bounding the on-disk log to
  **`live-count + threshold`** records.
- **Append fd re-point (data-loss guard).** The store holds an open append stream per topic. The atomic
  rename unlinks the *old* inode, so a stale append fd would write to the renamed-away log and be lost on
  reopen. `%threshold-compact` therefore **closes + drops the append stream before the rewrite**; the
  next `%ensure-stream` reopens the rewritten log in `:append` mode. For a keyed store the running chain
  MAC is re-pointed to the rewrite's fresh tail so the next appended v3 frame chains correctly.
- **Crash-atomicity (inherited, verified).** A crash during the mid-run rewrite leaves **either** the old
  log (rename didn't happen) **or** the new log (rename committed) — never torn. The new
  **`*durability-debug-file-rewrite-fault*`** injects a fault after the tmp fsync, before the rename; the
  test then reopens on the intact original log, the chain verifies, the newest `D` survive, no
  false-reject. Crash recovery also **discards orphaned `<tid>.tmp.log`** files (an un-renamed temp is
  uncommitted; the original log is authoritative) so the `*.log` replay glob never mis-loads a temp as a
  bogus topic.
- **Policy consistency + exemptions.** The mid-run path uses the **same** `%compact-topic-records` and
  `%record-guid-sn<` order as on-open, the memory store, and Sliver 1. **KEEP_ALL** does no threshold
  compaction; NIL-key-hash and lifecycle (`:dispose`/`:unregister`) records are never depth-evicted; a
  below-threshold store never rewrites (append path byte-identical). The durable-store **vtable is
  unchanged** (Sliver 2 is internal to `make-file-store`; a `store-delete` slot would be Sliver 3).
- **Logical read view = exactly `D` (cross-backend consistency).** The physical batching means the log +
  in-memory index hold up to `D + threshold` records for an instance between rewrites. So that the
  *exported* `store-get-range` / per-topic `store-count` contract still returns the **logical** newest-`D`
  view — identical to the memory store and the SQLite backend (online per-put DELETE) — the file store
  applies the shared **pass-2 `%keep-last-latest`** on **read** (records sorted by `%record-guid-sn<`,
  then newest-`D` `:data` per non-NIL key-hash) under `:keep-last`; per-topic `store-count` is that
  view's length (total `store-count` stays the physical record count, matching the encrypted decorator).
  It is **depth-only** (pass 2), NOT on-open's pass-1 settled drop: the bare memory + SQLite backends
  never drop settled instances on read (their online eviction is depth-only), so `:keep-all` returns the
  raw sorted view (byte-identical) and a settled instance's lifecycle records survive until the next open
  — matching them exactly and preserving the on-open compaction demonstrated by
  `run-durability-compaction-test`. The physical log remains batched-bounded by the threshold rewrite.
  The encrypted decorator does its own both-pass `%compact-topic-records` on top of its `:keep-all` +
  NIL-key inner store (where pass-1 is a no-op), so this read view neither double-compacts nor regresses it.

**Settled-instance-churn residual — RESOLVED (WP-DURABILITY-SETTLED-RECLAIM, additive settle trigger).**
As originally shipped, `super-pending` tracked **only** `:data` supersession, so an adversarial workload of
**endless DISTINCT settling instances** (register → write-once → dispose → unregister, a NEW key-hash each,
never re-touched) stayed within depth D, never bumped the counter, and accumulated ≤ D+2 settled frames per
instance between opens — pass-1 reclaimed them only on the next `store-open`, so a continuously-open log grew
without bound (rate-bounded by instance churn, not absolutely bounded). This is now closed at runtime by a
**TRIGGER-ONLY** addition: the `:put` path folds every keyed put into a per-instance lifecycle tally
(`settle-tally`, mirroring `data-counts`) and, on the **SETTLE transition** — the *exact* pass-1 predicate
(a `:dispose` AND an `:unregister` both seen AND the final record a tombstone; order-aware, so a resurrecting
`:data` un-settles it) — charges that instance's **reclaimable frame count** into `super-pending`, firing the
**SAME** unchanged atomic `%rewrite-topic-log` (whose pass-1 reclaims the settle). Only the *counting* is new:
the rewrite / chain-MAC re-seed / `tmp+fsync+rename` crash-atomicity path is **untouched**, so a
settle-triggered compaction reopens on a valid re-seeded v3 chain and a crash mid-compaction rolls back to the
intact original log — proven by `run-durability-settled-reclaim-test` (C). Because the settle predicate equals
pass-1 exactly and the trigger only *counts* (the unchanged compaction does the reclaim), a **live** instance
(data, no settle) is **never** false-reclaimed, and a settle-then-reregister keeps its resurrected data
(test B). The on-disk frame count **and** the in-memory index now stay bounded (~ threshold) under
endlessly-distinct settling churn (test A, RED→GREEN via `*durability-debug-disable-settle-trigger*`). The
shared detector (`settle-tally` / `%settle-tally-fold` in `store.lisp`) is reused by the encrypted decorator's
RAM window reclaim (ADR 0025 §10.3), so the settle predicate is defined **once** (DRY).
- **Parent-directory fsync** for the compaction rename across a power loss (shared follow-on with
  ADR 0026 §10). **RESOLVED** (WP-DURABILITY-HARDENING-BATCH): `%rewrite-topic-log` now calls
  `dds.pal:fsync-directory` after the compaction rename (and every other create/rename dirent — see
  ADR 0026 §10.10).

## References

- ADR 0021 — Durability service scope + cap.7 (DARE)
- ADR 0025 — CNSA-2.0 DARE (KEM-DEM envelope, key-provider, fail-closed)
- ADR 0026 — Disk-backed PERSISTENT store (file-store framing, epochs, `%compact-topic-records`
  pass 1, cross-restart key-epoch, `%seed-relay-from-store`)
- DDS 1.4 §2.2.3.5 — DURABILITY_SERVICE QoS: `history_kind`, `history_depth`
- RTPS 2.5 §9.6.4.8 — `PID_KEY_HASH (0x0070)`, keyhash encoding
- `src/dds-disc/disc.lisp` — `capture-data-key-hash` slot + `sample-key-hashes` table
- `src/dds-disc/dataplane.lisp` — `%record-sample-key-hash` + exported `node-sample-key-hash`
- `src/dds-durability/spec.lisp` — `service-spec` `history-kind` / `history-depth` fields +
  `make-service-spec` / `make-persistent-store-factory`
- `src/dds-durability/store.lisp` — `store-open` optional args + memory-store online eviction
- `src/dds-durability/store.lisp` — settled-instance-churn detector (WP-DURABILITY-SETTLED-RECLAIM,
  §10.1): `settle-tally` / `%settle-tally-fold` (the shared pass-1-equal settle predicate, reused by
  ADR 0025 §10.3), `*durability-debug-disable-settle-trigger*`
- `src/dds-durability/store-file.lisp` — `%compact-topic-records` pass 2 + `make-file-store`;
  Sliver 2 (§10.1): `*compaction-superseded-threshold*`, `*durability-debug-file-rewrite-fault*`,
  `%threshold-compact` / `%init-topic-counts` (make-file-store `:put`/`:open`), `%tmp-log-name-p`
  (orphan-temp skip), the fault seam in `%rewrite-topic-log`; settle trigger: the `settle-tallies`
  map + the `:put` settle block (charges the reclaimable count into `super-pending`)
- `src/dds-durability/service.lisp` — `service-start` → `store-open (spec history-kind history-depth)`
- `src/dds-durability/store-sqlite.lisp` — Sliver 1: `%sqlite-evict-instance` online per-put eviction
  (ADR 0049 §10)
- `src/dds-tests/durability-test.lisp` — `run-durability-keeplast-compaction-test`,
  `run-durability-keeplast-cross-restart-test`, `run-durability-keeplast-service-spec-policy-test`,
  `run-durability-keeplast-memory-test`; Sliver 2: `run-durability-file-threshold-compaction-test`,
  `run-durability-file-online-chain-test`, `run-durability-file-crash-consistency-test`;
  settled-instance-churn: `run-durability-settled-reclaim-test` (bounded-on-disk RED→GREEN,
  no-false-reclaim, chain-MAC + crash-fault)
- `interop/durability-keeplast/` — cross-DDS restart-seed harness + captures (Leg 1 Connext
  M=302→2, Leg 2 Fast DDS M=134→2)
