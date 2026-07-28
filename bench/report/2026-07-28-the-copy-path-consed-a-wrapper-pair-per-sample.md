# The copy path consed a wrapper pair per delivered sample

**Date:** 2026-07-28 · **Requirement:** NFR-MEM (0 B/sample), NFR-PERF-8 · **ADR:** 0093 (slice 1), 0062

## Result

**−171 B/sample** on the measured DCPS take path (arm64, SBCL, payload 0), same workload either side.

| arm | domain | B/sample (3 runs) | mean |
|---|---|---|---|
| baseline — no `return-loan` (the pre-ADR-0093 workload) | 11 | 1738.8 | 1738.8 |
| **A** application returns, wrapper pooling **OFF** | 12 / 21 / 31 | 1737.6 · 1742.3 · 1737.7 | **1739.2** |
| **B** application returns, wrapper pooling **ON** | 13 / 22 / 32 | 1569.5 · 1567.2 · 1567.6 | **1568.1** |

Ranges do not overlap remotely (A spread 4.7, B spread 2.3, gap 171). **The `return-loan` call itself is
free** — the baseline and arm A agree within noise, so the whole delta is the recycling, not the API.

## What was allocating

Per delivered copy-path sample the drain built a fresh **`cached-sample`** (3 slots) and a fresh
**`sample-info`** (13 slots), both **retained** in the reader cache and handed to the application. They
could not be pooled while the application's hold on them was implicit — which is the contract change
ADR 0093 makes: `take` hands back a pooled sample and the application `return-loan`s it.

Both are now popped from a per-reader **wrapper pool** and re-initialised in place. The pair is pooled as
**one object** — a parked wrapper keeps its `sample-info` attached — so one pop yields both and nothing is
consed to link them.

## Two findings the measurement produced, neither of which was the plan

**1. A list freelist ate a fifth of its own win.** The first cut used two list freelists (`push`/`pop`).
`push` conses, `pop` discards, so the freelist itself churned **two conses = 32 B/sample** — against a
~144 B prize. Measured 1600.1 with lists vs **1568.1** with a `simple-vector` stack. A pool whose
bookkeeping allocates is not a pool.

**2. The A/B lever leaked when it was off.** `%recycle-*` initially ran unconditionally while the acquire
side was gated, so with pooling OFF every return pushed onto a freelist nothing ever drew from: an
unbounded leak that also measured **+33.5 B/sample**. Visible only because the OFF arm was measured rather
than assumed. **A lever must be a true no-op on both ends, or it is not an A/B** — and the test now asserts
exactly that (`:adr93-off-not-parked`).

## ⚠️ The measurement that was wrong, and why

An early three-arm run put the pooled arm at **2786 B/sample against a 1739 baseline** — a 1000 B
*regression* from a change that removes allocation. I started diagnosing it as a code defect.

It was **harness cross-talk**: all three arms ran in one image on **domain 7**, so each arm's participants
discovered the previous arms' and paid for their traffic. Re-run one process per arm on distinct domains,
the same code measured 1569.5. The owner's standing order — *concurrently running tests MUST use different
DDS domain IDs* — is exactly this failure, and it cost an hour of chasing a defect that did not exist.

**When a number moves in a way the change cannot explain, suspect the harness's isolation before the code.**

## Correctness

The risk here is not the bytes, it is a **partially re-initialised recycled struct** handing the
application a *previous* sample's field — silent, and invisible to any allocation gate. There is exactly
one initialisation path, and the `rx-wrapper-pool` test poisons all 13 `sample-info` slots on a parked
struct and asserts none survives the next delivery.

That test observes the SampleInfo at **drain** time, not through `take`: `%select-samples` legitimately
re-stamps `sample_state`, `view_state` and `instance_state` at selection (DDS 1.4 §2.2.2.5.4), so testing
through `take` would have covered only 10 of 13 slots *while appearing to cover all of them*.

**Falsified, each seen red:** dropping one slot from the re-init turns `:adr93-no-stale-sn` red and nothing
else; making the acquire never recycle turns `:adr93-reused` red.

## Gate status

620/620 SBCL and Clasp · gate-build clean-cache PASS both · corpus 13+1, 0 mismatches both ·
gate-hotpath / types (3184 defuns) / pal / nocond / drivers PASS · **gate-mem unchanged at 1740**.

**The win is deliberately NOT ratcheted yet.** `gate-mem`'s default workload does not return loans, so it
cannot see this win, and flipping that default re-baselines **both** arch rows. Only arm64 was measured
here; the ceiling file's standing rule is that a row may be lowered only on the arch it was measured on,
and a predicted x86_64 number has already been 58 B wrong once. Flipping `mem-per-sample`'s `:return-loans`
default and lowering both rows is a follow-up that needs an x86_64 measurement — recorded, not done.
