# Writer-repair pacing (send-once) — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development.

**Goal:** Reliable writer pushes each new sample once (RTPS §8.4.2.2 `pushMode==true`),
not the whole unacked history per write. Repair stays ACKNACK-driven.

**Architecture:** Add a per-reader `unsent-base` watermark; `%push-data` sends
`writer-unsent-list` (changes from `unsent-base`, advancing it) instead of `writer-data-list`
(changes from `acked-base`). HEARTBEAT/ACKNACK/repair unchanged.

**Spec:** `docs/superpowers/specs/2026-06-12-writer-repair-pacing-design.md`.

---

### Task 1: send-once push + measurement (single task)

**Files:** `src/dds-rtps/reliable.lisp`, `src/dds-rtps/packages.lisp`,
`src/dds-disc/dataplane.lisp`, `src/dds-tests/rtps-test.lisp`,
`src/dds-tests/echo-test.lisp`, `bench/report/2026-06-12-writer-repair-pacing.md`,
`docs/verification.csv`, `docs/wiki/` rtps page, `README.md`.

- [ ] **Step 1 — failing test (count + repair).** In `rtps-test.lisp` add
  `run-writer-pushonce-test`: (a) a fresh `rtps-writer` with a HistoryCache; loop k=1..100
  `writer-write` then accumulate `(length (writer-unsent-list w rid))`; assert the sum = 100
  (send-once) — this FAILS to compile until `writer-unsent-list` exists; (b) assert the same
  loop with `writer-data-list` sums to 5050 (documents the before); (c) a repair check:
  after the 100 unsent pushes (unsent-base now 101), simulate a reader NACK of SNs {3,50}
  via `writer-on-acknack` and assert it returns exactly those two payloads (repair is
  independent of unsent-base). Register `writer-pushonce` in `echo-test.lisp`.
- [ ] **Step 2 — run, expect fail.** `make test-sbcl` — fails (undefined `writer-unsent-list`).
- [ ] **Step 3 — implement.** In `reliable.lisp`: add `unsent-base 1` to `reader-proxy`
  (docstring cites RTPS §8.4.2.2 unsent vs acknowledged); extract `%changes-from writer base`
  (the shared `>= base` collect loop) and rewrite `writer-data-list` to call it with
  `acked-base`; add `writer-unsent-list writer reader-id` = `%changes-from` with `unsent-base`
  then advance `unsent-base` to `1 + last-sn-collected` (no-op if empty). Full `defun*` ftypes.
  Export `writer-unsent-list` in `packages.lisp`.
- [ ] **Step 4 — wire `%push-data`.** In `dataplane.lisp:150` swap `writer-data-list` →
  `writer-unsent-list`. Update the `%push-data` docstring: "send each change ONCE (the unsent
  changes, RTPS §8.4.2.2 pushMode), followed by a HEARTBEAT; lost/late changes are repaired
  via ACKNACK (%on-user-acknack)".
- [ ] **Step 5 — green + gates.** `make test-sbcl` (expect 116), `make gate-types`,
  `make gate-hotpath` — all PASS. `GC_DONT_GC=1 make test-clasp`.
- [ ] **Step 6 — bench record.** Write `bench/report/2026-06-12-writer-repair-pacing.md`:
  the before/after DATA-submessage counts for N=100 (5050 → 100, 50.5×) measured by the test,
  the method, and the SN-set repair-intact note.
- [ ] **Step 7 — docs lockstep.** `docs/verification.csv` (extend FR-RTPS-8 or add a
  FR-RTPS-PUSHONCE row citing §8.4.2.2 + the bench number); the `docs/wiki/` rtps page;
  `README.md` P1 row if status shifts.

**Verification of intent:** the change must NOT touch `acked-base`, `writer-on-acknack`, GAP
handling, or any reader-side code; every existing reliability/GAP/DATA_FRAG test stays green.
