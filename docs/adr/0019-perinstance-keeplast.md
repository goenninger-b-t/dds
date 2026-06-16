# ADR 0019 — WP-KEEPLAST: per-instance KEEP_LAST history (HISTORY honored both sides; GAP wired)

- **Status:** **Accepted** (2026-06-16, WP-KEEPLAST Phase E / Task E1). Phases A-E delivered under this ADR —
  the HistoryCache per-instance eviction machinery (A), the keyhash threading (B), the GAP send + reader
  reception with the resource cap (C), the activation (the writer HC + reader cache honoring QoS, the
  default flip KEEP_ALL→KEEP_LAST-1, and the test migration) (D), and the gate sweep + the FR-LANG-7
  write-path bench + this finalization (E).
- **As-built (2026-06-16):** 226 tests green on SBCL + Clasp; `gate-types` (1272 defuns) / `gate-hotpath` /
  `mem` (0.0000 bytes/sample on the serialize/round-trip hot path) / `fuzz` all PASS. The honest write-path
  bench is `bench/report/2026-06-16-wp-keeplast.md` (`make bench-keeplast`): the clean per-instance-machinery
  cost (KEEP_LAST keyed vs KEEP_LAST unkeyed — same retention) is ~0 steady-state GC bytes/sample (the index
  conses are freed on evict) + the equalp-hash time; a keyed KEEP_LAST writer adds a ~16-octet (32 B/sample
  measured) keyhash above the HC; KEEP_ALL and the unkeyed path are unchanged — no 0-cost claim. **Task E1
  also found + fixed an O(N²) regression the WP introduced on the KEEP_ALL add path:** `%hc-store` appended
  to the per-instance index unconditionally via `nconc` (an O(bucket-length) tail-walk), and a KEEP_ALL
  bucket is never evicted, so it grew unbounded → O(N)/insert. FIX: the per-instance index is the KEEP_LAST
  eviction mechanism, so `%hc-index-append`/`%hc-index-drop` now no-op for KEEP_ALL — KEEP_ALL is the O(1)
  change-table insert it was pre-WP (measured flat ~70 ns/sample across N, vs ~3.6→14.1 µs/sample climbing
  before the fix). The §1-6 design (per-instance writer HC + reader cache, the additive keyhash, the
  reactive GAP both directions) ships as specified; the limitations below (one engine writer per
  disc-node, multi-writer SN-aliasing reader ordering, the loan-delivery path skipping the drop) are
  carried as recorded follow-ups.
- **Deciders:** A0 (integrator)
- **Amends:** nothing frozen — Phase A is internal to `dds.rtps.history` (the `instances` index + the single
  removal path are additions; the exported `make-history-cache` signature and the exported `hc-add-change` /
  `hc-remove-change` / `hc-purge-below` / `hc-get-change` symbols and their contracts are unchanged). The
  later-phase contract change (the additive `key-hash` parameter) is listed under *Contract-change consumers*.
- **Requires:** nothing new; the `cache-change` `instance-key-hash` slot already exists
  (`history.lisp:7-20`); the QoS HISTORY kind/depth already exist (`qos.lisp`).
- **Feature:** FR-QOS (HISTORY conformance), DDS 1.4 §2.2.3.18; RTPS 2.5 §8.3.7.4 (GAP), §8.4.1 (HistoryCache).

## Not R6

This is standard DDS QoS conformance — no patent gate, no default-off flag, no SBCL-only restriction. Both
impls (SBCL + Clasp) green. Clean-room from OMG DDS 1.4 + DDSI-RTPS 2.5; no RTI source/headers/`rtiddsgen`
output consulted.

## Context

DDS 1.4 §2.2.3.18 specifies HISTORY `KEEP_LAST` to keep "the last `depth` values **for each instance**" of
the topic key. The shipped HistoryCache (`history.lisp:123-140`) instead evicted the **global** lowest
sequence number when at depth, so a depth-N KEEP_LAST cache holding samples for two
keys retained a global last-N — starving one key whenever the other wrote faster. `history.lisp:25` flagged
per-instance KEEP_LAST as a tracked follow-up. Two further gaps compounded this into a latent reliability
bug for any KEEP_LAST reliable writer: the GAP submessage that `writer-on-acknack` already computes was
**never sent** (`%on-user-acknack` did `(declare (ignore gaps))`), and the reader datagram dispatch had no
`+submsg-gap+` case, so a received GAP was never processed. The writer HISTORY QoS was also ignored
entirely (the engine hard-codes a KEEP_ALL cache at `dataplane.lisp:1237`).

## Decision (the per-instance KEEP_LAST model)

1. **The writer HistoryCache honors the QoS HISTORY (kind + depth).** (Phase D — delivered.) The engine's
   hard-coded `make-history-cache :keep-all 1` is replaced by the writer's QoS `history-kind` + `history-depth`,
   threaded through `enable-publisher` (new `&key history-kind history-depth`, spec-defaulting to KEEP_LAST/1)
   from the creating DataWriter's QoS. A KEEP_ALL writer is unchanged (bounded only by RESOURCE_LIMITS, as
   today). LIMITATION (pre-existing, not introduced here): there is ONE engine writer per disc-node, shared by
   all of a publisher's DataWriters, so the HC honors the HISTORY QoS of the DataWriter that (re)enabled the
   publisher; a future per-DataWriter engine writer removes it.

2. **Per-instance eviction in the HistoryCache.** (Phase A — this ADR.) A secondary index maps each
   instance keyhash to the ordered sequence numbers of that instance's stored changes (oldest-first; SNs
   arrive monotonically per writer, so a per-instance append is already sorted). On a KEEP_LAST add: store
   the change, append its SN to its instance bucket; if that bucket now exceeds `depth`, evict the bucket's
   **head** — the oldest sample of **that** instance, not the global oldest. ALL change removal — the
   KEEP_LAST eviction, the shipped `writer-purge-acked` full-ACK purge (RTPS 2.5 §8.4.1), the global
   degenerate evict, and any dispose-driven removal — is centralized through one `%hc-remove-change (hc sn)`
   that updates BOTH the change table and the instance index, so the two never drift. An unkeyed change
   (HANDLE_NIL / `nil` keyhash) collapses to a single shared instance bucket = global KEEP_LAST (the prior
   behavior, preserved).

3. **The default flips KEEP_ALL → KEEP_LAST depth 1.** (Phase D — delivered.) The generic QoS default is
   already `:keep-last` depth 1 (DDS 1.4 §2.2.3 default QoS table), so an unconfigured writer/reader becomes
   KEEP_LAST-1 once the engine honors QoS. This is a deliberate conformance choice (the owner chose conformance
   over a lower-risk opt-in) and ACCEPTED the blast radius: existing tests / harnesses that write more than
   `depth` samples and expect all retained were migrated to explicit KEEP_ALL in the SAME commit, so no task
   boundary is left red. Migrated set: the DCPS multi-sample tests (instance-lifecycle, the two two-writer
   OWNERSHIP tests, querycondition, content-filtered-topic — writer AND reader to KEEP_ALL) and the
   sample-rejected test (KEEP_ALL both so the 3rd sample hits the RESOURCE_LIMITS *reject* path rather than a
   KEEP_LAST lossy drop); the disc-level fixtures that retain multiple changes via the one shared engine writer
   (the three coalesce tests, the GAP-send fixture, batch-defer, the flow step/teardown/pacing/multiwriter/
   bench/frag fixtures, the async-sender, the SHMEM + Zero-Copy e2e tests — writer-side `enable-publisher
   :history-kind :keep-all`); and the latency/throughput perftest harness (KEEP_ALL — a bench measures
   delivery, not history).

4. **The instance keyhash is threaded onto data changes.** (Phase B — delivered.) An additive optional
   `key-hash` parameter threads the instance handle DCPS `write-sample` computes (`%instance-handle`) through
   `publish-sample` (disc) → `writer-write` (engine) into `cache-change.instance-key-hash` (the slot already
   exists). NIL keeps today's behavior byte-identical. Unkeyed types pass the shared `+instance-handle-nil+`
   (no per-sample allocation; all samples collapse to one instance = global KEEP_LAST). DCPS `write-sample`
   GATES the handle computation on the writer's effective HISTORY being KEEP_LAST (`%write-key-hash` /
   `%writer-keeplast-p`): a KEEP_ALL writer never evicts per-instance, so it threads NIL and the default path
   stays 0-alloc (`make mem` 0.0000 bytes/sample — the keyhash is computed only when KEEP_LAST needs it).
   Inert until activation (Phase D): the engine writer HC is still hard-coded KEEP_ALL, so the populated
   keyhash is carried but not yet evicted-on.

5. **Interior SN holes are closed by the GAP, both directions.** (Phase C — delivered.) Per-instance eviction can
   remove an interior SN (depth 1: A@1, B@2, B@3 → evicting B's oldest SN2 leaves a hole at SN2 inside
   [firstSN, lastSN]). Two mechanisms keep a reliable reader correct: the existing HEARTBEAT firstSN advance
   (the reader compacts below it) covers low-end evictions; for an interior hole the reader's NACK reaches
   `writer-on-acknack`, which already returns the SN in `gaps` — `%on-user-acknack` must STOP ignoring `gaps`
   and SEND a GAP (`write-gap`, exists) to the NACKing reader (RTPS 2.5 §8.3.7.4). The reader side wires the
   missing `+submsg-gap+` dispatch case (`parse-gap-body` + `reader-on-gap`, both exist) so the GAP'd SNs
   are marked `:gap` and the reader stops NACKing them. This is mandatory under per-instance KEEP_LAST and
   also fixes the standalone latent "GAP never sent / never received" bug.

6. **Reader-side per-instance KEEP_LAST.** (Phase D — delivered.) In `%drain-one-sample`, when the reader
   is KEEP_LAST (`%reader-keeplast-depth`) and the sample's instance already holds `depth` valid-data samples
   in `dr-cache`, that instance's oldest (lowest-SN) cached sample is dropped before appending
   (`%reader-keeplast-drop-oldest`) — a lossy KEEP_LAST drop reusing the already-computed per-sample handle,
   touching ONLY `dr-cache` (the instance-rec / view-state survive), distinct from the RESOURCE_LIMITS reject
   (which stays). O(N) cache scan in v1 (matching the existing reject scan); per-DataReader, so it is clean.
   LIMITATION (v1): `oldest = min SN` is the true age order only for one writer per instance (multi-writer SN
   aliasing, RTPS 2.5 §8.3.5.4, and the reader has no merged cross-writer order — source-timestamp /
   DESTINATION_ORDER not implemented), lifted when DESTINATION_ORDER lands; and the loan-delivery path
   (`%drain-one-loan`) does not apply the drop — benign while ZC loan handles are per-(GUID,SN)-unique (NO_KEY
   FlatData), to revisit with keyed FlatData (WP-3b).

## Contract-change consumers (Phase B — delivered, the additive `key-hash` parameter)

The keyhash-threading phase added an additive optional parameter to two exported functions; the NIL default
keeps every existing caller byte-identical (the ftype declares the optional as `(or null (array (unsigned-byte
8) (*)))`):

- `dds.rtps.reliable:writer-write` — gained `&optional (key-hash nil)`, passed into the `make-cache-change`
  builder as `:instance-key-hash key-hash`.
- `dds.disc:publish-sample` — gained `&optional (key-hash nil)`, passed through to `writer-write`.
- `dds.disc:enable-publisher` — gained `&key history-kind history-depth` (Phase D, spec-defaulting to
  KEEP_LAST/1), threaded to `make-history-cache` so the engine writer HC honors the DataWriter's HISTORY QoS
  (additive; an existing caller that omits them gets the spec default).

(DCPS `write-sample` is the producer of the value but is not itself a contract change — it gained two internal
helpers, `%writer-keeplast-p` and `%write-key-hash`, that compute the handle via `%instance-handle` ONLY for a
KEEP_LAST writer and pass it to `publish-sample`; a KEEP_ALL writer passes NIL.)

## Consequences (Phase A — this ADR)

- No exported interface symbol changed: `make-history-cache` keeps its `(kind depth resource-limits
  type-support)` lambda list; `hc-add-change` / `hc-remove-change` / `hc-purge-below` / `hc-get-change` keep
  their signatures and contracts. The `history-cache` defstruct gains an internal `instances` slot.
- Phase A was inert (the engine still constructed a KEEP_ALL HistoryCache), exercised only by engine-level
  unit tests that build KEEP_LAST caches directly; Phase D ACTIVATED it (the engine now honors the QoS
  HISTORY on both sides), flipping the default to KEEP_LAST-1 and migrating the retention-dependent suite to
  explicit KEEP_ALL — 218 tests green on SBCL + Clasp after the migration, with no weakened assertion.
- Hot-path-adjacent (the HC add/remove path): the per-instance index is a plain `equalp` hash lookup with a
  per-instance SN list — no CLOS dispatch, no per-sample object instantiation (`make gate-hotpath` clean).
  The KEEP_LAST add appends one cons to the instance bucket (the existing change store already conses the
  `cache-change`; a pooled 0-alloc store stays the `history.lisp:25` follow-up — Phase A does not change the
  add path's 0-alloc status, and `make mem` measures the KEEP_ALL engine path, which is untouched).

## Out of scope / follow-ups

- Keyed-FlatData + per-key loan handles — WP-3b (R6), the next WP.
- LIFESPAN expiry; a pooled, 0-alloc HistoryCache change store (the `history.lisp:25` follow-ups).
- A per-instance reader index for O(1) reader eviction (the reader path is O(N) in v1, matching the existing
  RESOURCE_LIMITS reject scan).
- Proactive GAP-with-HEARTBEAT for evicted interior SNs (reactive GAP-on-NACK ships in v1).

## Conformance citations

- DDS 1.4 §2.2.3.18 — HISTORY: "KEEP_LAST … keep the last `depth` values **for each instance**."
- DDS 1.4 §2.2.3 — the generic QoS default table (HISTORY = KEEP_LAST, depth 1).
- RTPS 2.5 §8.3.7.4 — GAP submessage (irrelevant / no-longer-available SNs).
- RTPS 2.5 §8.4.1 — HistoryCache + the writer's first/last SN advertised in HEARTBEAT.
