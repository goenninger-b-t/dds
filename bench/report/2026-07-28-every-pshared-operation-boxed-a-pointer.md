# Every pshared operation boxed a foreign pointer

**Date:** 2026-07-28 · **Requirement:** NFR-MEM (0 B/sample), NFR-PERF-8 · **ADR:** 0062

## Result

**−112 B/sample on BOTH gate-mem arms**, from one `declaim inline`.

| arm | before | after (3 runs) | ceiling |
|---|---|---|---|
| COPY | 1740.7 | 1628.3 · 1630.5 · 1628.3 | 1775 → **1660** |
| RETURN | 1534.9 | 1422.5 · 1423.7 · 1426.3 | 1570 → **1460** |

Isolated micro-measurement: a `pshared-lock` + `pshared-unlock` pair went from **31.85 B/iteration to
0.00**, against a `load-sap-u64` control on the same SAP that was 0.00 throughout.

## The cause

`%ptr+` — `(cffi:inc-pointer sap offset)`, the address arithmetic under every pshared operation — was an
out-of-line `defun*`. Out of line it must **return** a foreign pointer, and on SBCL that means **boxing a
system-area-pointer: 16 heap bytes per call.** Every `pshared-lock`, `-unlock`, `-cond-wait`, `-cond-signal`
and `-cond-broadcast` paid one.

Per SHMEM datagram that is a lock/unlock pair on the receive side plus a lock/signal/unlock on a parked
send — 32–80 B, which is where the SHMEM transport's measured **+82 B/sample over pure UDP** came from.

Inlined, the arithmetic folds into the foreign call's argument and no boxed SAP is ever materialised.

## How it was found — and three wrong turns first

The `sb-sprof :alloc` ranking put `publish-sample-into` (9.1 %), `%push-one-writer-changes` (8.3 %) and the
UDP receiver lambda (7.5 %) on top. **Two hypotheses taken straight off that ranking were false**, both
killed by measurement rather than argument:

1. *"The TX pooled path is silently degrading to its allocating fallback."* Instrumented counters over
   20 000 samples: **0 fallbacks, 0 pool-empty.** The pooled branch is taken every time.
2. *"`publish-sample-into`'s `unwind-protect` + mutable `committed` flag is the known value-cell trap."*
   A flat probe with the `unwind-protect`, the flag and the `handler-case` all removed measured
   **1530.0 vs a 1530.0 baseline** — identical. SBCL allocates no cell there.
3. `SB-THREAD::CALL-WITH-MUTEX` at 5.6 % is not a wrapper we added: `bordeaux-threads:with-lock-held`
   already expands to the native `sb-thread:with-mutex`, which uses `DX-FLET` — a stack-allocated thunk.

⚠️ **The methodological lesson: `sb-sprof :alloc` per-frame attribution could not pick this target.**
Allocation inside a callee is charged to caller frames, so the profile's top entries were pass-throughs
(`%lane-drain` "measures" 6.6 % but *calls* the whole receive pipeline). What found it was a **feature-level
bisect** — `(setf dds.disc:*shmem-enabled* nil)` sized SHMEM at +82 B/sample — followed by reading the three
candidate functions (all allocation-free) and then measuring the primitive underneath them in isolation.
**Bisect and A/B locate; the profile only enumerates.**

## Gate status

623/623 SBCL · gate-hotpath / types (3193) / pal / nocond / drivers PASS · ceilings lowered on both arm64
columns. x86_64 is **not** re-measured here and its rows are untouched — never derive one arch from the other.
