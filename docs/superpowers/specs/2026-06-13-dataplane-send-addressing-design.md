# User data-plane send addressing — design

**Goal:** Close the two documented, benign send-addressing residues the reliable-proxy GUID-keying
left open (see `2026-06-13-reliable-guid-keying-design.md` §"Out of scope", lines 49–53 / 74–75):

1. **ACKNACK retransmit fan-out (over-send).** `%on-user-acknack` retransmits each NACKed change to
   `(%match-destinations node t)` — EVERY matched reader destination — though an ACKNACK comes from
   exactly ONE reader (its participant prefix is in the datagram's RTPS header `src-prefix`). With R
   matched readers and a NACK of K changes the writer puts R·K resends on the wire instead of K.
   Idempotent under KEEP_ALL (a reader drops an already-received SN), so it is wasted traffic, not a
   correctness bug.

2. **Multi-reader-per-participant send-once degrade.** Two remote DataReaders in ONE participant (e.g.
   a Connext/Fast DDS app with two readers on a topic) share one unicast `(host . port)`.
   `%reader-push-targets` dedups push targets by destination (`pushnew :key #'cdr`), so only ONE of the
   co-located reader GUIDs becomes the push key. The DATA goes out with `readerId = ENTITYID_UNKNOWN`
   so it physically reaches BOTH readers (no data loss) — but only the kept reader's `unsent-base`
   watermark advances; the other reader is deduped out of the push path entirely and its proxy
   watermark stays at the initial value. The second reader still receives every sample and reconciles
   via its own ACKNACK; the defect is purely that the per-reader push accounting is dishonest.

Neither is data loss. Both make the per-reader reliable accounting truthful and cut needless traffic.

## The enabling idea — address by the reader's resolved destination

Both fixes reduce to: **resolve the single user-plane `(host . port)` for a participant GUID-prefix**,
exactly as `%remote-metatraffic` (disc.lisp:367) does for the metatraffic plane. Add a user-plane twin
`%prefix-user-destination(node, prefix)` = `gethash prefix discovered` → `%usable-destination` (port>0),
under `disc-node-lock`. Returns `(host . port)` or NIL.

## Fix 1 — ACKNACK retransmit to the NACKing reader only

`%on-user-acknack` already has `src-prefix`. Resolve the single destination with
`%prefix-user-destination node src-prefix` and send the resends ONLY there. Fall back to the existing
`(%match-destinations node t)` fan-out when the prefix does not resolve (the discovery-less unit-test
path, where ACKNACKs arrive from a static peer with no SPDP record) — preserving every current test.
A real 2-node run always has the SPDP record, so the single-destination path is taken.

## Fix 2 — per-destination push-target grouping + union-send-once

Restructure `%reader-push-targets` to return, per destination, ALL co-located matched reader GUIDs:
`((host . port) guid1 guid2 …)` instead of dropping all but one. Then in `%push-data`, for each
destination:
- call `writer-unsent-list` for EVERY co-located reader GUID — this advances EACH reader's
  `unsent-base` watermark (the function couples compute+advance, reliable.lisp:93);
- merge the returned changes by SN (co-located readers usually share an `unsent-base`, so the lists are
  identical; if they differ — staggered joins — the union from the lowest base is the correct set);
- send the merged set EXACTLY ONCE to `(host . port)` (one datagram per change, `readerId = UNKNOWN`
  fans out to all readers there), followed by one HEARTBEAT.

This keeps the send-once invariant (one DATA per change per destination per push cycle) AND advances
every co-located reader's watermark, so a subsequent write does not re-push history to that destination
(the bug that WOULD appear if a co-located reader were kept as a target without advancing its
watermark).

The static-PEERS fallback branch (no matched reader endpoint resolves to a destination — the
discovery-less test path) keeps its single stable key: one group per peer carrying the node's local
`user-reader-id`.

## Why no reliable-engine change

The reliable engine API is unchanged. `writer-unsent-list` already advances per-key watermarks and is
keyed opaquely (equalp); calling it once per co-located reader GUID is exactly the advance we need.
Both fixes live entirely in `src/dds-disc/dataplane.lisp` (internal `%`-helpers; no exported contract
changes, no ADR).

## Tests (offline, deterministic — no datagram-spy seam exists)

- **`%prefix-user-destination`**: inject an SPDP record (`disc-node-discovered`) + assert the resolved
  `(host . port)`; assert NIL for an unknown prefix.
- **Fix 1**: a writer node with TWO matched reader participants (two SPDP records + two matched reader
  endpoints). Drive an ACKNACK from reader-1's prefix; assert the resolved retransmit destination is
  reader-1's only (assert via the pure resolver + the target list the loop iterates, since sends are
  not spyable). Regression: the existing UDP-loopback repair tests (`run-repair-reliability-test`,
  `run-dispose-repair-test`) still recover.
- **Fix 2**: inject two matched reader endpoints sharing ONE participant prefix/destination. Assert
  `%reader-push-targets` returns ONE destination group carrying BOTH reader GUIDs. After a push, assert
  BOTH readers' `unsent-base` advanced (observe via `writer-unsent-list` returning empty on the second
  call for each GUID) and that a second write enqueues exactly the new change for the destination
  (no re-push of history).
- Regression: ALL reliable/dataplane/dispose/ownership/instance-lifecycle tests green on SBCL + Clasp.

## Bench (FR-LANG-7)

Datagram-count table in `bench/report/2026-06-13-dataplane-send-addressing.md`, mirroring the
writer-repair-pacing report: Fix 1 resend count before R·K vs after K for R readers / K NACKed changes;
Fix 2 DATA-per-push-cycle-per-destination stays 1 (already deduped) while both watermarks now advance —
the metric is "history re-push on the next write": before (if naively kept) O(history) vs after 0.

## Out of scope

Full multi-endpoint-per-participant (many LOCAL writers/readers per node) — a separate architectural
item. This fixes only the REMOTE-side multi-reader-per-participant accounting and the ACKNACK
addressing; our own node still has one user writer + one user reader.
