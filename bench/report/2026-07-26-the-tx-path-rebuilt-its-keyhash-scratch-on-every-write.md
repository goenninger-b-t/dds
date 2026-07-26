# The TX path rebuilt its key-hash scratch buffer on every write

**Date:** 2026-07-26 · **Requirement:** NFR-MEM (0 B/sample), NFR-PERF-3, NFR-PERF-8 · **ADR:** 0087, 0075, 0076, 0062

## What was measured first

A fresh phase split of `mem-per-sample`'s cycle, because the standing note on which phase dominates was five
days old and four slices had landed since. `bytes-consed` is whole-process, and the receiver threads do their
work while the user thread sleeps in the poll loop — so the sleep window is a clean receiver-thread probe.

| phase | B/sample | share |
|---|---|---|
| SLEEP window = receiver threads | 810.5 | 43.8 % |
| WRITE — TX, user thread | 746.9 | 40.4 % |
| HIT — the take that returns the sample | 292.7 | 15.8 % |
| MISS — an empty `take-samples` | 0.0 | 0.0 % |
| **sum** | **1850.0** | |

The split reconciles with `gate-mem`'s 1852.2 to within the session-scale spread (~3 B), and the probe control
— 3000 back-to-back `bytes-consed` calls — measured **0.0 B**, so the instrument does not perturb what it
measures. The receiver thread is still the largest phase; TX is a close second.

## The finding

An `:alloc` profile ranked `%write-key-hash` 3rd by allocation **events** (8.5 %). Events are not bytes, so it
was sized directly rather than ranked — the trap this campaign has already hit once.

`%instance-handle`'s own docstring named the defect: *"NIL allocates fresh, byte-identical (**every TX** /
register / unkeyed caller)."* The RX drain stopped allocating its key-hash scratch in ADR 0075. The TX write
path never did. A KEEP_LAST **keyed** writer therefore did, on **every** `write()`: `make-octet-buffer` (a
foreign/static alloc + zero) → build a cursor → serialize the key → `free-static`, plus a fresh 16-octet
result array.

Isolated sizing (`perf-data`, keyed `:i32`, n = 200 000 per arm):

| arm | B/call |
|---|---|
| **TX today** — no scratch | **112.0** |
| reusable cursor, fresh result array | **32.1** |
| reusable cursor **and** reusable result array | **0.0** |

One call per sample. Handles were asserted **byte-identical** across arms in the same run — the scratch path
was never assumed equivalent.

## What was changed, and what deliberately was not

The **serialization scratch** is reused; the **result array is not**. The handle is retained on three paths —
threaded onto the `CacheChange` for KEEP_LAST per-instance eviction, used as a `dw-instances` `equalp` hash
key, and (when the offered DEADLINE is finite) used as the `dw-deadline-timers` key. Recycling it would alias
every change's handle and mutate live hash keys: silent mis-attribution, not crashes. The deadline path is
the nastiest of the three because it is conditional — a recycled array would look correct until someone
configured a DEADLINE. That leaves ~32 B on the table on purpose; closing it needs the ADR 0076
stable-handle indirection ported to the writer, which is its own slice.

The scratch is guarded by a **CAS try-lock**, not a lock: a DataWriter may be written concurrently, and two
threads serializing through one buffer would interleave into a wrong instance handle. The thread that wins
`keyhash-busy` uses the scratch; a loser takes the pre-existing allocating path, byte-identical. Never
blocks, never spins, allocates nothing uncontended.

## Result — `gate-mem`, 60 000 samples, the only oracle

| arch | before | after | delta |
|---|---|---|---|
| **arm64** (Apple silicon, SBCL) | 1852.2 | **1769.8** | **−82.4** |
| **x86_64** (Ubuntu 24.04, SBCL) | 1902.8 | **1777.4** | **−125.4** |

The isolated sizing predicted −79.9 on arm64; the end-to-end gate moved −82.4. **The model held**, which is
the check that this is a real win and not a re-attribution between phases.

x86_64 was measured as a same-image A/B (shipped body measured, then `%write-key-hash` redefined to its
pre-0087 body — the function is not inlined, so the redefinition genuinely takes effect). Its larger delta
matches this codebase's established pattern of materially arch-dependent allocation: ADR 0065 moved −175 on
arm64 and −708 on x86_64.

Ceilings lowered on **both** rows (`bench/mem-ceiling.txt`): arm64 1910 → 1800, x86_64 1950 → 1810. That file
warns explicitly that banking a win on one arch while leaving the other stale makes the ratchet fail *on
improvement* in CI, so both were measured directly rather than one predicted from the other.

## Cumulative

arm64 is now **1769.8 B/sample**, from 3560 at the campaign's start — **−50.3 %**. NFR-MEM's target is 0, so
this remains an open campaign, and the receiver-thread phase (810.5 B/sample, 43.8 %) is the standing next
target.
