# Reliable-proxy + lifecycle GUID keying (multi-writer SN-aliasing follow-up) — design

**Goal:** Close the multi-writer SN/EntityId aliasing in the two paths the data-delivery fix left:
the RTPS reliable reader/writer **proxies** (keyed by EntityId) and the dispose/unregister
**lifecycle store** (keyed by raw SN). Two remote endpoints sharing the user EntityId (writer 0x102 /
reader 0x107) across participants currently collide their reliable state (received SNs, HEARTBEAT
range, ACKNACK/GAP, fragment reassembly) and dispose events. RTPS 2.5 §8.3.5.4: a SequenceNumber is
unique only within one writer GUID.

## The enabling idea — opaque proxy key (minimal blast radius)
The reliable engine (`src/dds-rtps/reliable.lisp`) uses the proxy key only as a hash key. Change the
key parameter type from `(unsigned-byte 32)` (EntityId) to `t` (an opaque key) and the `proxies`
tables to `:test 'equalp`. Then:
- the disc layer passes the full **16-octet source GUID** (datagram prefix + endpoint EntityId) as the
  key — distinguishing two same-EntityId endpoints;
- the value-level reliable tests keep passing integer ids (still valid, consistent-within-a-test
  equalp keys) — **no test breakage**.
This is the same wire-state-machine logic; only the key changes.

## Findings (current state)
- Reliable READER: `rtps-reader.proxies` (`:eql`, writer-id EntityId); `get-writer-proxy reader
  writer-id`; 7 fns key by it (reader-on-data/-heartbeat/-acknack/-on-gap/-complete-p/-on-data-frag/
  -frag-acknack). Two writers 0x102 → one writer-proxy → collision.
- Reliable WRITER: `rtps-writer.proxies` (`:eql`, reader-id). WORSE: `%on-user-acknack` passes
  `(disc-node-user-reader-id node)` — OUR LOCAL constant reader-id — so ALL remote readers' ACKNACKs
  map to ONE reader-proxy; the unsent-base/acked-base watermarks are shared across readers. Key it by
  the REMOTE reader's GUID (src-prefix + the ACKNACK's reader EntityId).
- Lifecycle store: `disc-node-lifecycle-changes` (`:eql`, raw SN). Value already carries the source
  GUID; the KEY is SN-only. Mirror the data store's 2-level GUID→(SN→value) via `%inner-table`.
- `src-prefix` is threaded to the DATA/DATA_FRAG/LIFECYCLE hooks but NOT to HEARTBEAT/HEARTBEAT_FRAG/
  ACKNACK (`%on-user-heartbeat`, `%on-user-heartbeat-frag`, `%on-user-acknack`) — thread it (the
  disc.lisp dispatcher already has `src-prefix`).
- The data store already uses the 2-level GUID→SN pattern (`%inner-table`, `%source-guid`) — mirror it.

## Plan (one cohesive change — the key + threading must change atomically)

**A. Reliable engine.** Change `get-writer-proxy` / `get-reader-proxy` + all reader/writer fns' key
param type `(unsigned-byte 32)` → `t`; `proxies` tables → `:test 'equalp`. No logic change. Update
the docstrings (drop the KNOWN-FOLLOW-UP note; cite §8.3.5.4 — keyed by the opaque per-endpoint key).

**B. Disc threading.** Add `src-prefix` to the `on-heartbeat` / `on-heartbeat-frag` / `on-acknack`
hooks (disc.lisp dispatch + the hook lambdas) so `%on-user-heartbeat` / `%on-user-heartbeat-frag` /
`%on-user-acknack` receive it. At EVERY reliable reader/writer call site, pass the full GUID
(`%source-guid src-prefix entity-id`) as the key instead of the bare EntityId:
- reader side: the remote WRITER GUID (src-prefix + wid) for reader-on-data/-heartbeat/-acknack/
  -on-data-frag/-frag-acknack.
- writer side: the remote READER GUID (src-prefix + the ACKNACK's rid) for writer-on-acknack /
  the unsent/data-list proxy lookups — fixing the local-reader-id-constant bug.
  NOTE: `%push-data` / `writer-unsent-list` are PROACTIVE (no inbound datagram) — they pick the
  destination per matched reader; the unsent-base must be PER REMOTE READER GUID. Resolve the matched
  reader's GUID from the disc match (the destination peer) so each reader gets send-once pacing.
  (If per-destination GUID isn't readily available in %push-data, scope this carefully — the
  send-once watermark must not regress for the single-reader common case.)

**C. Lifecycle store.** `disc-node-lifecycle-changes` → 2-level `equalp` GUID → `eql` SN → value
(via `%inner-table`). `node-lifecycle-sns` returns `(GUID . SN)` composite keys (like
`node-sample-sns`); `node-lifecycle-change` takes the composite key. Update the DCPS
`%drain-one-lifecycle` consumer (it already keys per-writer via dr-lifecycle-drained — confirm it
threads the GUID).

## Tests
- Value-level (reliable.lisp): keep the existing integer-id tests (unbroken by the opaque key). ADD a
  multi-writer aliasing test: ONE rtps-reader, TWO writer keys (two distinct GUIDs, or two integers
  standing for two GUIDs) each delivering SN 1..k — assert their received sets / HEARTBEAT ranges /
  ACKNACKs are INDEPENDENT (writer A's gap doesn't NACK writer B's SNs).
- Disc/UDP or offline: two writers sharing EntityId 0x102 (distinct prefixes) → independent reliable
  delivery AND independent dispose (writer A's dispose of instance X doesn't clobber writer B's SN-10
  lifecycle event). Build on the ownership same-EntityId test fixtures (%two-writer-guid).
- Regression: ALL reliable/dataplane/dispose/ownership/instance-lifecycle tests green.

## Out of scope
Full multi-endpoint-per-participant (many local writers/readers per node — a separate architectural
item); the writer-side per-destination send pacing is fixed only insofar as keying the proxy by the
remote reader GUID (if %push-data can't cheaply resolve per-destination GUID, keep the single-reader
behaviour correct and note the multi-reader send-pacing as a sub-follow-up).
