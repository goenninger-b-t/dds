# Writer-repair pacing (send-once) — DATA submessage count, N=100

Date: 2026-06-12
Requirement: FR-RTPS-PUSHONCE (RTPS 2.5 §8.4.2.2, `next_unsent_change` / `unsent_changes`)
Scope: reliable user-data writer push path (`%push-data` / `writer-unsent-list`).

## The change

The reliable writer used to re-push its WHOLE unacked history on every write: each
`publish-sample` collected every change with `SN >= acked-base` (the acknowledged
watermark) and sent them all as DATA submessages. Before the first ACKNACK arrives
`acked-base` never advances, so N pre-ACKNACK writes emit `1 + 2 + ... + N = N(N+1)/2`
DATA submessages — an O(N^2) storm.

RTPS 2.5 §8.4.2.2 (`pushMode==true`) pushes the UNSENT changes once
(`next_unsent_change` = changes with `sequenceNumber > highestSentChangeSN`) and repairs
`requested_changes` ONLY on ACKNACK. The writer now tracks an UNSENT watermark
(`reader-proxy-unsent-base` = `1 + highestSentChangeSN`) distinct from the acknowledged
watermark (`acked-base`), and `%push-data` pushes `writer-unsent-list` (each change once).

## Measurement method

From `run-writer-pushonce-test` (src/dds-tests/rtps-test.lisp): a reliable writer with a
KEEP_ALL HistoryCache; loop k = 1..100 doing `writer-write` then accumulating the length of
the push list for that write; sum = the total DATA submessages the push path would emit per
matched reader over 100 pre-ACKNACK writes. `writer-data-list` (before) vs `writer-unsent-list`
(after) are summed on two separate fresh writers in the same test.

## Result (DATA submessages, N = 100, per matched reader)

| push path                       | per-write list length | total over N=100 |
| ------------------------------- | --------------------- | ---------------- |
| before (`writer-data-list`)     | 1, 2, 3, …, 100       | 5050             |
| after  (`writer-unsent-list`)   | 1, 1, 1, …, 1         | 100              |

50.5x fewer DATA submessages at N = 100; the reduction grows linearly with N
(`N(N+1)/2` -> `N`). HEARTBEAT count is unchanged (one per push).

## ACKNACK repair unchanged

The repair path (`writer-on-acknack`, bitmap-driven) is independent of the UNSENT watermark
and is left untouched. Verified in the same test: with `unsent-base` advanced to 101, an
ACKNACK NACKing exactly SNs {3, 50} still resends exactly those two changes' payloads,
byte-exact — no false GAP, no over-send.

## Gates

- `make test-sbcl`: 116 passed (was 115; +1 for `rtps-writer-pushonce`).
- `GC_DONT_GC=1 make test-clasp`: 116 passed.
- `make gate-types`: PASS. `make gate-hotpath`: PASS.
- Full reliability / GAP / DATA_FRAG / dataplane suite stayed green.
