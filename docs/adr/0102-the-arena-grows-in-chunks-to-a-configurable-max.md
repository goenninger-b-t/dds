# ADR 0102 — The arena grows in configurable chunks, up to a configurable maximum

- **Status:** **Accepted** — owner requirement, implemented.
- **Date:** 2026-07-31
- **Requirements at stake:** **FR-PF-7** (all hot-path memory from the arena), **NFR-MEM**, **NFR-DET**.
- **Relates to:** ADR 0095 (the one process arena), **ADR 0101** (exhaustion rejects — this ADR is what
  makes that policy honest), ADR 0064 (exhaustion is a status).

> **Owner requirement, 2026-07-31:** *"The Arena Manager must allow for arena growth in configurable chunks
> up until a configurable max arena size."*

---

## 1. Why this comes before ADR 0101

ADR 0101 makes arena exhaustion a **RESOURCE_LIMITS reject** instead of a fallback. Against a *fixed* initial
budget that policy is brutal: the process refuses work the moment its first estimate is wrong, and the
estimate has to be right for the worst case at startup or not at all.

With growth, **exhaustion means "the configured maximum was reached", not "the initial reservation was
full"** — the difference between a ceiling an operator chose and an opening guess. That is what makes a hard
reject a defensible signal rather than a premature one.

## 2. The design, and the one property that makes it safe

Three knobs:

| | |
|---|---|
| `*static-arena-bytes*` | the **initial** reservation (unchanged meaning, new name for its role) |
| `*static-arena-growth-bytes*` | the **chunk** a miss grows by. `0` disables growth entirely |
| `*static-arena-max-bytes*` | the **hard ceiling**. Equal to the initial budget ⇒ exactly the old behaviour |

**Growth is pure accounting, and that is the whole safety argument.** The arena is a *budget*, not a slab:
every buffer is its own `dds.pal:alloc-static` region and the arena tracks only budget-versus-used. Raising
the budget therefore allocates nothing, moves nothing, and **cannot invalidate an address an earlier carve
already handed out**. The same operation on a bump allocator over one contiguous block would be a
use-after-free waiting to happen — it is safe *here* because of how this arena was built, not in general.

Growth is asked of the **budget-holder**. A sub-arena is a charge account whose real ceiling is its parent's
(ADR 0095 option (a)), so `make-buffer-pool` grows `charge-to`, never the sub-arena.

**Whole chunks, not exact fit.** Growing by precisely what the current carve needs would turn every
subsequent carve into another growth step: the budget would creep upward one allocation at a time and the
ceiling would stop being a meaningful operating signal. A chunk absorbs a burst in one move and leaves
headroom that is visible in `arena-byte-budget`. A carve larger than one chunk takes as many chunks as it
needs. Growths are **counted** (`arena-growths`), so the event is observable rather than silent.

## 3. Falsified, in four arms

`run-arena-growth-test` pins each half of the requirement, and each arm fails without the corresponding code:

| arm | asserts |
|---|---|
| GROWS | a carve over the initial budget but under max **succeeds**, the budget rose, the growth was counted |
| CEILING | the same carve with max below it is **refused**, and the budget stopped **at** max |
| DISABLABLE | chunk `0` restores the fixed-ceiling behaviour exactly — refused, budget untouched, zero growths |
| WHOLE CHUNKS | a carve just over the budget grows by a **full** chunk, not the exact shortfall |

Measured directly: initial 4096 B + a 256 KiB carve ⇒ budget 1 052 672 B, growths 1. With max 8192 ⇒
`:ARENA-EXHAUSTED`, budget stopped at 8192.

## 4. It broke two existing checks, by design — and that is the point of having them

`gate-arena` ARM 1 and `run-arena-exhaustion-test` both proved refusal by pinning a tiny
`*static-arena-bytes*`. With growth, that no longer exhausts anything — the arena simply grows past it and
both would have **silently stopped testing exhaustion while still passing**. Both now pin
`*static-arena-max-bytes*` as well.

This is exactly the failure mode the standing rule exists for: a green check that has quietly stopped
checking. The change was caught because the gates were run, not because the change looked risky.

## 5. Consequences

- Exhaustion now means the **configured maximum**, which is what ADR 0101's reject policy needs to be honest.
- An operator sizes `*static-arena-max-bytes*` from what the deployment can afford, and
  `*static-arena-bytes*` from the steady state; growth absorbs the difference.
- Setting max equal to the initial budget, or the chunk to `0`, restores the previous fixed-ceiling
  behaviour exactly — the new policy is opt-out, not imposed.
- **Any future arena that is a real slab rather than an accounting budget must not inherit this** without
  re-deriving the safety argument in §2.
