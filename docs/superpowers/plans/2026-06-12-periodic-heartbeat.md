# Periodic standalone HEARTBEAT — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development.

**Goal:** Periodic standalone HEARTBEAT on the announce cadence so a lost final sample (no
subsequent write) is repaired via the existing ACKNACK path. RTPS 2.5 §8.4.2.2.

**Spec:** `docs/superpowers/specs/2026-06-12-periodic-heartbeat-design.md`.

---

### Task 1: periodic HEARTBEAT + lost-final-sample recovery (single task)

**Files:** `src/dds-disc/dataplane.lisp`, `src/dds-disc/disc.lisp`,
`src/dds-disc/packages.lisp` (export the debug var), the dataplane test (find it —
`dds.disc:run-dataplane-test`), `src/dds-tests/echo-test.lisp` if a new test is registered.

- [ ] **Step 1 — failing test.** Extend/add a two-node UDP-loopback test proving recovery:
  A (writer) + B (reader) discover+match (clone `run-dataplane-test`'s setup); bind
  `dds.disc:*debug-drop-sample-numbers*` to `(1)`, A `publish-sample` sample 1 (B drops the
  DATA), unbind the drop; do NOT publish again; drive A `announce-endpoints` + B receive for a
  bounded number of iterations; assert B ultimately has sample 1 (recovered via the periodic
  HEARTBEAT → NACK → resend). It must FAIL before the implementation (no periodic HB → B never
  NACKs → never recovers). Deterministic: bounded loop, no wall-clock sleep beyond the existing
  test's socket poll.
- [ ] **Step 2 — run, expect fail.**
- [ ] **Step 3 — debug drop hook.** Add `*debug-drop-sample-numbers*` (defparameter, nil) to
  `dataplane.lisp` mirroring `*debug-drop-fragment-numbers*`; in the non-fragmented DATA send path
  (`%send-sample` or where a whole sample goes out) skip the send when the SN ∈ the list. Export it
  from `src/dds-disc/packages.lisp`. One-line docstring/comment.
- [ ] **Step 4 — `%send-user-heartbeat` (DRY).** Extract the `write-heartbeat` lambda currently
  inline in `%push-data` into `%send-user-heartbeat node buf first last count host port` and call
  it from `%push-data` (no behaviour change).
- [ ] **Step 5 — `%push-heartbeat`.** Add it: `(let ((w (disc-node-user-writer node))) (when w ...))`
  → `writer-heartbeat` → guard `(>= last first)` (non-empty) → `(dolist (peer (%match-destinations
  node t)) (%send-user-heartbeat node (disc-node-tx-msg node) first last count (car peer) (cdr peer)))`.
  Full `defun*` ftype `(function (disc-node) (eql t))`; docstring cites RTPS 2.5 §8.4.2.2 + the
  lost-final-sample rationale. Non-final HEARTBEAT (prompts ACKNACK).
- [ ] **Step 6 — wire the cadence.** In `announce-endpoints` (`disc.lisp`), add `(%push-heartbeat
  node)` after `(%liveliness-sweep node)`, before the trailing `t`. Update the `announce-endpoints`
  docstring to mention the periodic user-data HEARTBEAT.
- [ ] **Step 7 — green + gates.** `make test-sbcl` (expect prior+1), `make gate-types`,
  `make gate-hotpath`, `GC_DONT_GC=1 make test-clasp`. The existing reliability/dataplane/SEDP tests
  MUST stay green (the periodic HB must not disrupt a steady-state complete reader — its positive
  ACKNACK triggers no resend). If any regress, STOP and report.
- [ ] **Step 8 — docs.** `docs/verification.csv` (note the periodic HEARTBEAT on the reliable-writer
  row), the `docs/wiki/` discovery/rtps page (`announce-endpoints` now emits the periodic HB),
  `README.md` only if status shifts.

**Verification of intent:** the change must NOT alter the per-write `%push-data` send (still
send-once), must NOT touch the ACKNACK/repair logic, and must not cause a complete reader to
trigger resends. Steady-state cost: one HB + one ACK per matched reader per ~1.5 s cadence.
