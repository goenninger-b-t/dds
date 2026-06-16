# WP-KEEPLAST — per-instance KEEP_LAST history (writer + reader) — design

**Goal (DDS 1.4 §2.2.3.18 HISTORY, RTPS 2.5 §8.3.7.4 GAP, FR-QOS).** Make HISTORY `KEEP_LAST` depth
apply **per instance** on BOTH sides — the writer retains the last `depth` changes *of each key* (for
late-joiners / reliable retransmit) and the reader keeps the last `depth` samples *of each key* in its
cache — instead of today's global behavior. Honor the configured HISTORY QoS (today it is ignored), and
wire the GAP path so a reliable reader that NACKs an evicted sequence number receives a GAP rather than
silence. This closes a real DDS conformance gap and a latent reliability bug. Queue #3a (per-key
coalescing / keyed-FlatData → owner split into 3a per-instance KEEP_LAST, then 3b keyed-FlatData).

## Not R6
This is standard DDS QoS conformance — no patent gate, no default-off flag, no SBCL-only restriction.
Both impls (SBCL + Clasp) green. Clean-room from OMG DDS 1.4 + DDSI-RTPS 2.5.

## Grounded current state (file:line — verified, not from memory)
- `dataplane.lisp:1235` — the writer's HistoryCache is hard-coded `make-history-cache :keep-all 1`; the
  writer's QoS HISTORY is **ignored**. Effective default writer = KEEP_ALL (retain-until-acked).
- `history.lisp:7-20` — `cache-change` already carries an `instance-key-hash` slot (16 octets, nullable);
  populated today only for dispose/unregister (`writer-lifecycle-change`), NOT for data writes.
- `history.lisp:123-140` — `hc-add-change` KEEP_LAST evicts the **global** lowest SN (`%hc-evict-oldest`).
  `history.lisp:25` explicitly lists "per-instance KEEP_LAST … tracked follow-up."
- `reliable.lisp:122-132` — `writer-write (writer payload)` builds the change from SN + serialized bytes
  only; no keyhash available at that layer.
- `entities.lisp:427-442` — DCPS `write-sample` HAS the live sample + type-support; `%instance-handle ts
  sample` (`entities.lisp:448`) computes the 16-octet handle (the shared `+instance-handle-nil+` constant
  for unkeyed types → no per-sample alloc; a fresh `key-hash-<name>` array for keyed types).
- `reliable.lisp:189-207` — `writer-on-acknack` already returns `(values resends gaps)`; a `write-gap`
  builder exists (`message.lisp:353`).
- `dataplane.lisp:1137-1167` — `%on-user-acknack` does `(declare (ignore gaps))` — **the GAP is computed
  but never sent** (a standalone latent bug for any KEEP_LAST reliable writer).
- `reliable.lisp:317-326` + `message.lisp:364-375` — `reader-on-gap` + `parse-gap-body` EXIST, but
  `disc.lisp:950-972` has **no `+submsg-gap+` dispatch case** → the reader never processes a received GAP.
- `entities.lisp:1049` — the reader's `%drain-one-sample` already computes the per-sample `handle`
  (`%instance-handle ts data`) and stores it in `sample-info`; no reader-side HISTORY depth is enforced
  (only RESOURCE_LIMITS *reject* via `%resource-reject-reason`, `entities.lisp:527`).

## Decisions baked in (brainstorming 2026-06-16 — owner-chosen, confirm at spec review)
1. **Scope = writer + reader** (full §2.2.3.18), not writer-only.
2. **Default = honor the spec generic default KEEP_LAST depth 1** (not preserve today's KEEP_ALL). Fully
   conformant on the default value; ACCEPTS the blast radius — existing reliable tests/flows that write
   multiple samples and expect all retained are migrated to explicit KEEP_ALL (or sufficient depth) as
   part of this WP. (Owner explicitly chose conformance over the lower-risk opt-in.)
3. This is 3a; **keyed-FlatData is 3b** (the next WP, R6) — out of scope here.

## Design

### 1. The writer HistoryCache honors the QoS HISTORY (kind + depth)
Replace the hard-coded `make-history-cache :keep-all 1` (`dataplane.lisp:1235`) with the writer's QoS
`history-kind` + `history-depth`. The generic QoS default already is `:keep-last` depth 1 (`qos.lisp:125`),
so an unconfigured writer becomes KEEP_LAST-1 (decision 2). A KEEP_ALL writer is unchanged (bounded only by
RESOURCE_LIMITS, as today). The READER has no writer-style HistoryCache for user samples — its KEEP_LAST
depth is enforced in the DCPS `dr-cache` (§6); it reads the SAME QoS `history-kind`/`history-depth`. **ADR
0019** records this behavior change (the writer HC now reads QoS; the reader cache now enforces depth; the
default value flips KEEP_ALL → KEEP_LAST-1) + the consumer migration list.

### 2. Keyhash on data changes (writer side)
DCPS `write-sample` computes `%instance-handle ts sample` and threads it through `publish-sample` (disc)
→ `writer-write` (engine) into `cache-change.instance-key-hash` (the slot exists). Additive optional
parameter on both functions (`&optional (key-hash nil)`); NIL keeps today's behavior byte-identical.
**ADR 0019** covers the two-consumer contract change. Unkeyed types pass the shared `+instance-handle-nil+`
(no per-sample alloc; all samples collapse to one instance = global KEEP_LAST — correct).

**0-alloc (NFR-MEM):** keyed types compute a fresh 16-octet handle per write — the same per-sample handle
the reader ALREADY computes (`entities.lisp:1049`) and the dispose path already computes. The writer HC is
already non-0-alloc (`cache-change` is freshly consed; `history.lisp:25` flags pooling as a follow-up), so
this does not change the writer path's 0-alloc *status*. ACCEPTANCE: `make mem` must stay green — verify
its measured workload; if `make mem` measures a keyed KEEP_LAST writer path and regresses, add a 0-alloc
`key-hash-<name>-into (sample buf)` codegen variant (fills a caller buffer, no `make-array`) and have the
writer reuse a per-change buffer. Decide by measurement, not assumption (FR-LANG-7).

### 3. Per-instance eviction in the HistoryCache
Add a secondary index to the HC: `instances` = `keyhash (equalp) → ordered SN list` (SNs arrive
monotonically per writer, so per-instance append is already sorted; evict from the head = oldest). On a
KEEP_LAST add: store the change, append its SN to `instances[keyhash]`; if that instance's count now
exceeds `depth`, evict its **head** SN (the oldest sample of THAT instance, not the global oldest).
Centralize ALL change removal — KEEP_LAST eviction, the shipped `writer-purge-acked` full-ACK purge, and
dispose — through one `%hc-remove-change (hc sn)` that updates both `changes` and `instances` so they never
drift. Unkeyed (HANDLE_NIL) → a single instance bucket = global KEEP_LAST (the prior behavior, preserved).

### 4. Interior SN holes + the GAP (the load-bearing correctness path)
Per-instance eviction can remove an **interior** SN: e.g. depth 1, write A@1, B@2, B@3 → evicting B's
oldest (SN2) leaves the HC holding {SN1, SN3} — a hole at SN2 inside [firstSN, lastSN]. Two mechanisms
keep a reliable reader correct:
- **HEARTBEAT firstSN advance** (existing): evicting the lowest held SN advances the writer's advertised
  firstSN; the reader compacts below it (`reader-on-heartbeat`) and never NACKs below first. Covers
  low-end evictions.
- **Reactive GAP** (NEW — wire it): for an interior hole, the reader's HEARTBEAT-driven NACK for the
  evicted SN reaches `writer-on-acknack`, which already returns it in `gaps`. `%on-user-acknack` must STOP
  ignoring `gaps` and **send a GAP submessage** (`write-gap`, exists) for those SNs to the NACKing reader
  via the same per-reader destination (`%prefix-user-destination`) the resends use. This is mandatory
  under per-instance KEEP_LAST and also fixes the standalone latent "GAP never sent" bug.

(Proactive GAP-with-HEARTBEAT for evicted interior SNs is a possible optimization; reactive GAP-on-NACK is
sufficient + conformant for v1.)

### 5. Reader GAP reception (wire the existing handler)
Add the missing `+submsg-gap+` case to the reader datagram dispatch (`disc.lisp:950-972`): parse the GAP
(`parse-gap-body`, exists) and call `reader-on-gap` (exists) so the GAP'd SNs are marked `:gap` (irrelevant)
in the writer-proxy received table — the reader stops NACKing them and the ACK watermark advances. Without
this, a reader NACKs an evicted SN forever.

### 6. Reader-side per-instance KEEP_LAST
In `%drain-one-sample`, reuse the already-computed `handle`. When the reader is KEEP_LAST and instance H
already holds `depth` samples in `dr-cache`, **drop H's oldest (lowest-SN) sample before appending** — a
lossy *drop* (KEEP_LAST semantics), distinct from the RESOURCE_LIMITS *reject* path (which stays). The
drop also retires the dropped sample's instance bookkeeping consistently. O(N) cache scan in v1 (matches
the existing `%resource-reject-reason` O(N) `count`); a per-instance reader index is a noted follow-up.

## Test migration (decision 2's blast radius — an explicit phase)
Audit every test, `square-pub`, and any interop harness that writes more than `depth` samples (or relies
on late-joiner retention) under the now-default KEEP_LAST-1, and set those entities to explicit KEEP_ALL
(or a sufficient depth). A KEEP_LAST-1 reliable writer still delivers each sample to an already-matched,
keeping-up reader, but a burst-then-drain or late-joiner pattern now keeps only the latest per instance
(+ GAPs). The full suite green on SBCL + Clasp after migration is the gate that the flip is correctly
absorbed.

## Test scenarios (the acceptance — oracle = the retained set + the wire + byte-exactness)
1. **Writer per-instance retention.** KEEP_LAST depth N, keyed; write >N samples for instance A and for
   instance B; assert the HC retains exactly the last N of A AND the last N of B (per-instance, not a
   global last-N that would starve one key).
2. **Interior-hole GAP.** KEEP_LAST depth 1, keyed, RELIABLE; write A@1, B@2, B@3 (SN2 evicted, interior
   hole); a reader that missed SN2 NACKs it → assert the writer SENDS a GAP for SN2 → the reader marks it
   `:gap`, stops NACKing, the ACK advances (no hang). tshark-dissectable GAP if feasible.
3. **Low-eviction firstSN.** KEEP_LAST depth 1; write A@1, A@2 (SN1 evicted); assert the HEARTBEAT firstSN
   advanced to SN2 and a reader does not NACK SN1.
4. **Reader per-instance retention.** KEEP_LAST depth N reader; deliver >N samples per instance for two
   instances; assert `dr-cache` holds the last N of EACH instance (lossy drop of the oldest per instance,
   not a global cap).
5. **Unkeyed collapses to global.** Unkeyed KEEP_LAST depth N writer + reader = global last-N (one
   instance bucket) — byte/behavior-identical to a correct global KEEP_LAST.
6. **KEEP_ALL unchanged.** A KEEP_ALL writer + reader behaves exactly as today (RESOURCE_LIMITS-bounded;
   no per-instance eviction) — regression.
7. **Reliability composition.** purge-acked + KEEP_LAST eviction co-exist via `%hc-remove-change`: a
   fully-acked change is purged; an over-depth change is evicted; the index never drifts; no double-free,
   no orphaned index entry.
8. **Full-suite migration green.** After the test migration, the entire suite is green on SBCL + Clasp
   (the gate that decision 2 is absorbed). `make mem` + `gate-hotpath` + `gate-types` + `fuzz` PASS.

## Out of scope (follow-ups)
- **Keyed-FlatData + per-key loan handles** — WP-3b (R6), the next WP.
- LIFESPAN expiry; a pooled, 0-alloc HC change store (existing `history.lisp:25` follow-ups).
- A per-instance reader index (O(1) reader eviction) — v1 is O(N), matching the existing reject scan.
- Proactive GAP-with-HEARTBEAT for evicted interior SNs (reactive GAP-on-NACK ships in v1).
- DURABILITY / late-joiner transfer semantics (M6) — KEEP_LAST per-instance is a prerequisite, not the
  feature.

## Conformance citations
- DDS 1.4 §2.2.3.18 — HISTORY: "KEEP_LAST … keep the last `depth` values **for each instance**."
- DDS 1.4 §2.2.3 — the generic QoS default table (HISTORY = KEEP_LAST, depth 1).
- RTPS 2.5 §8.3.7.4 — GAP submessage (irrelevant/no-longer-available SNs).
- RTPS 2.5 §8.4.1 — HistoryCache + the writer's first/last SN advertised in HEARTBEAT.
