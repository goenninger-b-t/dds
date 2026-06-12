# Writer-repair pacing (send-once push model) — design

**Status:** approved approach — Option A (owner, 2026-06-12). Supersedes the pre-spec notes
(`2026-06-12-writer-repair-pacing-notes.md`).

**Goal:** Make the reliable writer push each new sample **once** (the RTPS §8.4.2.2
`pushMode==true` model) instead of re-sending its whole unacked history on every write,
eliminating the O(N²) pre-ACKNACK burst while leaving ACKNACK-driven repair intact.

## Problem (confirmed in code)

`%push-data` (`src/dds-disc/dataplane.lisp:144-158`) sends `writer-data-list` — **every**
change with `SN >= acked-base` — followed by a HEARTBEAT, and `publish-sample`
(`dataplane.lisp:160-166`) calls it on **every** write. `%push-data` has no other caller
(no announce-cadence re-push). So writing N samples before the first ACKNACK emits
1+2+…+N = N(N+1)/2 DATA submessages. The ACKNACK repair path
(`%on-user-acknack` → `writer-on-acknack`, `reliable.lisp:64-80`) is already selective
(bitmap-only), so the waste is entirely the per-write whole-history resend.

The root cause is conflating **unacknowledged** (`SN >= acked-base`) with **unsent**. RTPS
2.5 §8.4.2.2: with `pushMode==true` the writer pushes new changes; the StatefulWriter state
machine (§8.4.9.2) distinguishes `unsent_changes` (pushed once) from `requested_changes`
(retransmitted only when a reader requests them via ACKNACK).

## Approach (Option A — RTPS push model)

1. **`reader-proxy` gains `unsent-base`** (next SN never yet sent to this reader; init 1),
   beside the existing `acked-base` (kept for its acknowledged-watermark role).
2. **New `writer-unsent-list writer reader-id`** — collects changes with
   `SN >= unsent-base` in SN order, then advances `unsent-base` to `1 + last-collected`
   (marks them sent). This is `unsent_changes()`. Factor the shared collect loop with
   `writer-data-list` into a private `%changes-from writer base` (DRY) — `writer-data-list`
   stays (it filters from `acked-base`, no side effect) for the unit tests / completeness.
3. **`%push-data` uses `writer-unsent-list`** instead of `writer-data-list`. The HEARTBEAT
   is unchanged — `writer-heartbeat` still advertises the full `[firstSN, lastSN]` available
   range, so a reader missing any earlier SN NACKs it and `%on-user-acknack` resends exactly
   those (unchanged repair path).

### Why correctness holds

- **Loss of a pushed sample:** the next HEARTBEAT advertises it in `[first,last]`; the
  reader NACKs; `writer-on-acknack` (bitmap, independent of `unsent-base`) resends it.
- **Late-joining / backlog:** a reader that needs older history NACKs the range on the next
  HEARTBEAT and is repaired from the HistoryCache — the RTPS pull-for-backlog behavior.
- **No regression vs today:** the current code also has no periodic standalone HEARTBEAT, so
  a lost *final* sample with no subsequent write already relies on an external re-announce in
  both the old and new code. A periodic-HEARTBEAT timer is a separate, out-of-scope
  enhancement (note it; do not build it here).
- `unsent-base` only ever advances; `acked-base`/`writer-on-acknack`/the reader side are
  untouched, so every existing reliability/GAP/DATA_FRAG test must stay green.

## Measurement (FR-LANG-7, mandatory)

Exact and deterministic at the reliable-API level — no perftest harness (still an M5 stub),
no hot-path counter. A test simulates N pre-ACKNACK writes and sums the push-list length:

```
for k in 1..N:  writer-write(payload);  total += (length (push-list-fn writer rid))
```

- **Before** (push-list = `writer-data-list`): total = N(N+1)/2.
- **After** (push-list = `writer-unsent-list`): total = N.

Record both numbers for a representative N (e.g. 100: 5050 → 100, a 50.5× reduction) in
`bench/report/`.

## Files

- `src/dds-rtps/reliable.lisp` — `reader-proxy` slot `unsent-base`; `%changes-from`;
  `writer-unsent-list`; keep `writer-data-list`.
- `src/dds-rtps/packages.lisp` — export `writer-unsent-list`.
- `src/dds-disc/dataplane.lisp` — `%push-data` swaps `writer-data-list` → `writer-unsent-list`.
- `src/dds-tests/rtps-test.lisp` — new `run-writer-pushonce-test` (the count assertion +
  a delivery+repair check: push once, drop one, NACK, repaired); register in echo-test.
- `bench/report/2026-06-12-writer-repair-pacing.md` — before/after counts.
- Docs: `docs/verification.csv` (FR-RTPS-8 / a new pacing row), `docs/wiki/` rtps page,
  `README.md` if status shifts.

## Out of scope

Periodic standalone HEARTBEAT timer; per-remote-reader proxies (the disc layer still uses one
proxy keyed by the local user-reader-id — unchanged); `pushMode==false` pull mode.
