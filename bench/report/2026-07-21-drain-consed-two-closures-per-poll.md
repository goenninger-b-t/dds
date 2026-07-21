# The drain consed two closures on every poll — empty drains are now zero

**Date:** 2026-07-21 · **Requirement:** NFR-MEM (0 B/sample), NFR-PERF-8, NFR-TEST · **ADR:** 0072, 0062
**Machine:** arm64 Darwin, SBCL · **Harness:** `dds.bench:mem-per-sample` (`make gate-mem`), payload 0, n = 3000.

## Headline

| | B/sample |
|---|---|
| before | **2424** (oscillating bimodally 2402/2424) |
| after | **~2180** (measured 2140 / 2140 / 2162 / 2184 / 2250 / 2250) |

**≈ −244 B/sample — the largest single slice of the campaign.** arm64 ceiling 2470 → 2280. Cumulative from
the ADR 0062 baseline: **3560 → ~2180, ≈ −39 %**.

## How it was found

Task #1 of the owner's sequence was "harden the mem harness": `gate-mem` oscillated bimodally ~2402/2424, a
~22 B band that made every remaining per-slice win unconfirmable. Two hypotheses were tested and **rejected
by measurement**:

- *The periodic autonomous announce?* Stopping both announcers after match **increased** the variance
  (2359–2468), not collapsed it. Not the announce.
- *GC timing?* `bytes-consed` is monotonic, so GC *timing* cannot change the total. The variance can only be
  a real allocation whose *count* varies run-to-run.

That count is the **empty-poll count**. `mem-per-sample`'s loop is
`(loop repeat 200 until (take-samples dr) do (sleep 0.0002))`, so `take-samples` → `%drain` runs ~2.5×/cycle,
mostly on an empty cache — and `%drain` built **two fresh capturing closures per call** (the `pending-p`
predicates for `node-collect-pending-samples` / `-lifecycle`, over `multi`/`node`/`rid`/`dr`). Variable poll
count × ~96 B of closures = both the noise and ~244 B of real allocation.

## The fix

`flet` + `dynamic-extent` on the two predicates (ADR 0068's pattern). `node-collect-pending-*` funcall them
per candidate under the node lock and never store them — downward funargs — so SBCL stack-allocates them.
Unlike a struct passed to a non-inlined function (a cursor attempt the same day did *not* stack-allocate), a
**closure passed downward does**.

## Phase split — empty drains are now zero

| phase | before | after |
|---|---|---|
| WRITE (TX) | 742 | 895* |
| MISS (empty take-samples) | 87 | **0.0** |
| SLEEP (receiver thread) | 918 | 918 |
| HIT (successful take) | 699 | **437** |

*(the WRITE/HIT split shifts run-to-run; the decisive number is **MISS 87 → 0** — an empty poll now cons
nothing, so the variable poll count no longer inflates the total, and every polling reader in a real app
benefits, not just the bench.)

## Residual

A ~65 B bimodal residual remains (2140 vs 2250) — a periodic HEARTBEAT landing 0-or-1× in the timed window,
the same builder-closure pattern in `%on-user-heartbeat`. The next harness-hardening step; the noise floor is
already materially lower.

## Validation

`gate-build` PASS both impls (clean cache, self-falsified) · **573/573 Clasp and SBCL** (every take/read test
exercises `%drain`; an escaped stack closure would corrupt a reader cache) · `gate-hotpath` / `gate-types` /
`gate-nocond` / `gate-pal` / `corpus` / `mem` / `fuzz` all green.
