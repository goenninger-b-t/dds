# The ACKNACK path built a 16-octet GUID per datagram just to index a table

**Date:** 2026-07-26 · **Requirement:** NFR-MEM (0 B/sample), NFR-PERF-3, NFR-PERF-8 · **ADR:** 0088, 0062, 0076, 0087

## What was measured first, and why the order mattered

The owner directed: **measure the rest of the receiver phase first, then implement Option B regardless of
what the measurement said** — the goal being a hazard removed *by construction*, not a byte count.

Post-ADR-0087 phase split (`mem-per-sample`, payload 0, n = 30 000; sum reconciles with `gate-mem`):

| phase | B/sample | share |
|---|---|---|
| **SLEEP window = receiver threads** | **817.8** | **46.0 %** |
| WRITE — TX, user thread | 668.4 | 37.6 % |
| HIT — the take that returns | 290.9 | 16.4 % |
| MISS — an empty take | 0.0 | 0.0 % |

TX fell 746.9 → 668.4, matching ADR 0087's −82.4 almost exactly — the win landed where the model put it.
**The receiver is now the largest phase.**

## The finding

`get-reader-proxy` / `%get-writer-proxy` retain their key **only on creation**. Measured over 3000
samples: **9901 lookups to 1 creation.** So on the control path the freshly-built GUID is pure lookup
garbage, discarded microseconds later — the ADR 0076 stable-handle shape.

## What shipped

The proxy tables now **own** their keys (`%retained-endpoint-key` copies on creation), which is what makes
it safe for a caller to hand in a cached array. The writer keeps a **bounded, write-once** cache of remote
endpoint GUIDs; every hit is **verified octet-for-octet** before it is believed.

**The safety argument is structural, not procedural.** Entries are never mutated after publication, so a
concurrent receiver thread sees a whole valid GUID or nothing, and the verify decides — a race can only
cause a *miss*, never a wrong key. No lock. No audit obligation on future callers. That is the property
the owner chose this design for over the per-thread-scratch alternative.

## Result

| arch | before | after | delta |
|---|---|---|---|
| **arm64** (Apple silicon, SBCL) | 1769.8 | **1742.1** | **−27.7** |
| **x86_64** (Ubuntu 24.04, SBCL) | 1777.4 | **1704.5** | **−72.9** |

Suite **607 passed** (606 + the new `rtps-proxy-key-retention`) on SBCL-macOS **and** SBCL-Linux.

x86_64 gained ~2.6× more than arm64 — the same materially-arch-dependent pattern as ADR 0065 (−175 vs
−708) and ADR 0087 (−82.4 vs −125.4). Ceilings lowered on **both** rows; neither is ever predicted from
the other.

## ⚠️ The first implementation won NOTHING — and only the byte measurement said so

The miss-path builder was first passed as a **closure**: `(lambda () (%source-guid src-prefix rid))`.
That closure captures the prefix and the id, so it **allocates on every call — cache hits included**.
The change swapped a 32-octet GUID for a closure of similar size and `gate-mem` moved **+1.6 B: nothing.**

Passing the *components* instead, and building the GUID inside the miss path, produced the −27.7.

**No correctness test could have caught this.** The code was right, the cache hit, every assertion passed
— the optimisation was simply absent. This is the sharpest case in the campaign for `gate-mem` being the
oracle: the *reasoning* for the slice was sound, and the first implementation of that sound reasoning
still won zero.

## Falsification

`run-proxy-key-retention-test`, five assertions, and the load-bearing one was **seen red before it was
believed**: disabling only the retention copy produces `TEST FAILED [PROXY-KEY-RETAINED]`; restoring it
turns it green. The others pin the cache — a hit is the same object, a colliding slot with a different
prefix is rejected, a different entity-id is rejected, and the cache stays bounded under 64 distinct
endpoints (a peer chooses how many readers it creates, so an unbounded cache would be remote-drivable).

## Two corrections this work forced

1. **`%source-guid` was over-reported.** Isolated: 32.1 B/call. In situ: **87.5 B/sample over 4.40 calls
   ≈ 19.9 B/call** — the isolated harness inflates by **~1.6×**, the same error class ADR 0062's own
   correction records at ~3.5×. Size candidates *in situ*; treat per-site numbers as upper bounds.
2. **`%lane-drain` is not an independent target.** The attribution table is inclusive of callees and
   `%lane-drain` calls `on-datagram` — the whole receive pipeline — so its 393.6 B/sample largely *is*
   `%handle-datagram`. Corrected ranking of the receiver phase, children subtracted from parents:

   | handler | own cost |
   |---|---|
   | `%on-user-acknack` | ~240 → **~212** after this slice |
   | `%handle-datagram` own | ~153 |
   | `%on-user-heartbeat` | ~109 |
   | `%on-user-data` own | ~66 |
   | `dispatch-message` own | ~22 (nearly pure routing) |

   The receiver phase is **the submessage handlers**, led by ACKNACK — not the SHMEM drain.

## Cumulative

arm64 **1742.1 B/sample**, from 3560 at the campaign's start — **−51.1 %**. NFR-MEM's target is 0, so this
remains open; the ranked receiver-phase table above is the next map.
