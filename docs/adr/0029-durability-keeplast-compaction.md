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
- **Parent-directory fsync** for the compaction rename across a power loss (shared follow-on with
  ADR 0026 §10).

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
- `src/dds-durability/store-file.lisp` — `%compact-topic-records` pass 2 + `make-file-store`
- `src/dds-durability/service.lisp` — `service-start` → `store-open (spec history-kind history-depth)`
- `src/dds-tests/durability-test.lisp` — `run-durability-keeplast-compaction-test`,
  `run-durability-keeplast-cross-restart-test`, `run-durability-keeplast-service-spec-policy-test`,
  `run-durability-keeplast-memory-test`
- `interop/durability-keeplast/` — cross-DDS restart-seed harness + captures (Leg 1 Connext
  M=302→2, Leg 2 Fast DDS M=134→2)
