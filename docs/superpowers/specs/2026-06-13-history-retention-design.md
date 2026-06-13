# Reliable history retention — purge on full-ACK + reader compaction — design

**Context.** WP-PERFTEST's first finding: latency + bytes/sample grow O(N) because the v1 reliable engine
retains O(history) (`bench/report/2026-06-13-perftest-baseline.md`). Root cause confirmed in source:
- WRITER `HistoryCache` is KEEP_ALL and never purges acked samples (`history.lisp`; `hc-remove-change`
  exists but is never called for the writer);
- READER `writer-proxy.received` (`reliable.lisp:142/166`) maps SN → **payload** forever, and the payload
  value is **never read back** — delivery comes from the wire (`%deliver-user-sample`), and the engine
  only checks SN *presence* in `reader-acknack` / `reader-complete-p` / `reader-on-gap`.

This caps scalability and blocks the NFR-PERF-8 0-alloc target. No frozen interface signature changes.

## S1 — Writer purge on full-ACK (disc-driven)
A writer sample is safe to drop once EVERY matched reader has acknowledged it — i.e. SN < the minimum
`reader-proxy.acked-base` over all matched readers (RTPS 2.5 §8.4.1: VOLATILE writer history is bounded
by the slowest reader's ack). Disc-driven so the reliable engine stays value-level and match-unaware:
- `reliable.lisp`: `writer-purge-acked(writer, reader-keys)` — `min` of `acked-base` over each key's proxy
  (created with acked-base 1 if absent, so a matched-but-not-yet-acked reader holds the watermark at 1 and
  nothing is purged until it acks), then `hc-remove-change` every change with SN < that watermark. Returns
  the count purged.
- `dataplane.lisp`: after `%on-user-acknack` advances a reader's acked-base, call `writer-purge-acked`
  with the FULL matched-reader GUID set (from `%matched-endpoints` filtered by `%reader-guid-p`) — the same
  GUID keys `%on-user-acknack` advances (the c53127b GUID-keying). The HEARTBEAT firstSN (`hc-min-seq`)
  then advances past the purged range.
- **No GAP needed:** a NACKed sample is not fully-acked (its writer hasn't seen acked-base past it), so it
  is never purged; only fully-acked (received-by-all) samples are dropped. Late-join history (a reader
  matching after a purge) is a separate durability concern — `reader-acknack` already starts at the
  HEARTBEAT firstSN, so a late joiner asks only for the advertised range, never the purged range.

## S2 — Reader received-table compaction
- `reliable.lisp`: `reader-on-data` stores a presence marker (`t`) instead of the payload — the payload
  was never read, so this is behaviour-preserving and stops retaining N payloads.
- `reader-on-heartbeat`: when the advertised firstSN advances (the writer purged), drop `received` entries
  below it. `reader-acknack` / `reader-complete-p` already iterate `[first-sn, last-sn]`, so entries below
  first-sn are unreachable — dropping them is invisible and bounds `received` to the live window.

## Coupling
S2's compaction is driven by S1 (the writer purge advances firstSN, the HEARTBEAT carries it, the reader
drops). The presence-marker change (S2a) is independent and the single biggest reader win. Implement both
as the one WP; the perftest is the joint oracle.

## Tests (TDD)
- Value-level (reliable.lisp): `rtps-history-purge` — a writer + two reader proxies; after both ack
  through SN k, `writer-purge-acked` drops SN < min(acked-base) and leaves the rest; an unacked second
  reader holds the watermark (nothing purged); `hc-change-count` bounded. `rtps-reader-compaction` — feed
  a reader N samples + advancing HEARTBEATs; assert `writer-proxy.received` entry count stays bounded
  (≈ window), not N, and ACKNACK/complete-p unaffected.
- Integration: existing reliable/dataplane/dispose/repair tests stay green (purge only removes fully-acked
  samples; repair still works because NACKed samples are retained).
- Bench: `make bench` shows bytes/sample + latency FLAT across N (the O(N)→bounded proof), updating
  `bench/report/2026-06-13-perftest-baseline.md`.

## Thread-safety (surfaced during implementation)
The writer is driven from TWO threads — publish (caller thread) and ACKNACK/purge (receiver thread). The
purge's `maphash`/`remhash` over the HistoryCache races `writer-write`'s `setf` (SBCL's concurrent-hash
detector fires under the throughput blast). The reliable engine was lock-free (a latent pre-existing
read/read race, now made a fatal write race). Fix: a per-`rtps-writer` LOCK guarding EVERY public writer
op (write/lifecycle/heartbeat/data-list/unsent-list/on-acknack/purge-acked/frag-heartbeat/on-nack-frag/
sample-payload). Internal `get-reader-proxy`/`%changes-from` run only inside a held lock; no public op
calls another, so the non-recursive lock cannot self-deadlock. The reliable READER is receiver-thread-only
(disc delivers from `%handle-datagram` only), so it needs no lock.

## Result (perftest before → after, N = 10 000, 64 B)
bytes/sample 171 804 → 9 248 (18.6×); p50 latency 186 500 → 17 000 ns (11×); now FLAT O(1) across N;
throughput ≈ 2 900 → 5 800 samples/s. `bench/report/2026-06-13-perftest-baseline.md` updated.

## Best-effort readers (review finding)
`%matched-reader-keys` includes only RELIABLE matched readers. A BEST_EFFORT reader matches a reliable
writer under RxO but never ACKNACKs — including it would pin the purge watermark at acked-base 1 forever
(silently disabling the bound). Excluding it is also semantically correct: best-effort = no delivery
guarantee (DDS 1.4 §2.2.3.13), so the writer owes it no retransmit and may purge samples it never acked.
Test `purge-reliable-only`. (A best-effort-ONLY writer therefore does not purge via acks — it should bound
via KEEP_LAST / send-once-purge; a separate follow-up, out of scope here.)

## Out of scope
TRANSIENT_LOCAL/durability late-join history (would keep purged samples for late joiners — a P5/M6
concern); per-instance KEEP_LAST; LIFESPAN expiry. This is VOLATILE steady-state bounding only.
