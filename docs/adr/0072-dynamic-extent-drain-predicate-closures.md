# ADR 0072 — the drain's pending-p predicates are stack-allocated (`dynamic-extent`), so an empty drain cons zero

- **Status:** Accepted
- **Date:** 2026-07-21
- **Requirements:** NFR-MEM (0 bytes/sample), NFR-PERF-8, NFR-TEST (the mem-per-sample harness)
- **Relates to:** ADR 0062 (the allocation budget), ADR 0068 (the same `dynamic-extent` pattern on the RX handler)
- **Contract touched:** none; `%drain` internals only

## Context

Two things converged on the same defect. Task #29's `gate-mem` had been oscillating **bimodally, ~2402/2424
B/sample**, a ~22 B noise band that swamped every remaining per-slice win and made them unconfirmable (it is
why a cursor micro-slice was reverted the same day — its ~22 B win could not be told from the noise).
Separately, the take path was the joint-largest remaining phase.

The two are the same allocation. `mem-per-sample`'s timed loop polls for delivery:
`(loop repeat 200 until (take-samples dr) do (sleep 0.0002))` — so `take-samples` (hence `%drain`) runs
**~2.5× per cycle**, most of them on an *empty* cache. And `%drain` built **two fresh capturing closures per
call** — the `pending-p` predicates it hands to `node-collect-pending-samples` /
`node-collect-pending-lifecycle`, closing over `multi`/`node`/`rid`/`dr`. `bytes-consed` is monotonic, so
run-to-run variance can only come from a real allocation whose *count* varies: the variable empty-poll count
× ~96 B of closures per drain. That was both the noise and ~244 B/sample of real allocation.

## Decision

**Name the two predicates with `flet` and declare them `dynamic-extent`**, exactly as ADR 0068 did for the
RX submessage handler:

```lisp
(flet ((%data-pending-p (g sn) …) (%life-pending-p (g sn) …))
  (declare (dynamic-extent #'%data-pending-p #'%life-pending-p))
  (let* ((data-keys (node-collect-pending-samples node #'%data-pending-p …))
         (life-keys (node-collect-pending-lifecycle node #'%life-pending-p …))
         …)
    …))
```

This is sound because both `node-collect-pending-*` are **downward funargs**: their docstrings and bodies
funcall the predicate per candidate *under the node lock* and never store it (verified by reading them). A
closure that does not outlive the call is the textbook `dynamic-extent` case, and — unlike a struct passed
to a non-inlined function (which SBCL does not stack-allocate via caller `dynamic-extent`, as a cursor
attempt the same day confirmed) — a **closure passed downward does** stack-allocate. The predicate bodies,
the `-UNLOCKED`-accessor deadlock discipline, and the drain semantics are unchanged.

## Consequences

- **`gate-mem` 2424 → ~2180** (measured 2140–2250, mean ~−244 B/sample) — the largest single slice of the
  allocation campaign. arm64 ceiling 2470 → **2280**. Cumulative from the ADR 0062 baseline: **3560 → ~2180,
  ≈ −39 %**.
- **An empty `take` / `read` / `samples-available` drain now cons ZERO** (phase-split MISS: 87 B → **0.0
  B**). This is per-CALL, so it also cuts the successful take (HIT: 699 → 437) and every polling reader in a
  real application — not just the bench.
- **The mem-per-sample harness is hardened** (task #1 of the owner's sequence): with empty polls free, the
  variable poll count no longer contributes to the total. A ~65 B residual remains (a periodic HEARTBEAT
  landing 0-or-1× in the timed window — the same builder-closure pattern in `%on-user-heartbeat`, a
  follow-up), so the noise floor is materially lower but not yet zero.
- Validated where it matters: `%drain` is the hot take path, so a stack closure that escaped would be a
  use-after-return corrupting a reader's cache. **573/573 both impls** (every take/read test exercises it),
  clean-cache builds self-falsified, `gate-hotpath` / `gate-types` / `gate-nocond` / `gate-pal` / `corpus` /
  `mem` / `fuzz` all green. The paren restructure (a `let*` split into `let*` + `flet` + `let*`) was checked
  with the string/comment-aware paren checker before building.

## Not addressed

The ~65 B periodic-HEARTBEAT residual (`%on-user-heartbeat`'s ACKNACK builder closure + `reader-acknack`'s
fresh bitmap) — the next harness-hardening step, same `dynamic-extent` pattern but with per-iteration
loop-variable capture. And the x86_64 ceiling is lowered from its CI number in the usual follow-up.
