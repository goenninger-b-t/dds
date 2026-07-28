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

---

## Follow-up the same day: `static-pointer`, the same defect one level down — a further **−65 B/sample**

Generalising the finding ("any out-of-line function returning a SAP boxes it") turned up
`dds.pal:static-pointer`, an out-of-line `defun*` returning the foreign pointer of a static vector. It is
called by `sap-copy-in` / `sap-copy-out` (every SHMEM record) **and** by the raw `sendto`/`recvfrom` paths
(every UDP datagram). Same one-line fix, on both impls.

| | before | after (3 runs) | ceiling |
|---|---|---|---|
| COPY | 1628.3 | 1563.8 · 1566.8 · 1566.0 | 1660 → **1600** |
| RETURN | 1422.5 | 1358.8 · 1360.4 · 1358.5 | 1460 → **1390** |

Isolated: `sap-copy-out` / `sap-copy-in` of 64 B went **16.06 → 0.00 B/call**.

**Cumulative for the two inlines: 1740.7 → 1566 (COPY) and 1534.9 → 1360 (RETURN), −177 B/sample.**

### The sweep that found it, and what it cleared

Rather than guess again, every hot PAL primitive was measured in isolation (200 000 calls each):

```
load-sap-u8/u16/u32/u64   0.00     store-sap-u8/u64   0.00
cas-sap-u32/u64           0.00     fence :acquire/:full 0.00
sap-copy-out / -in       16.06  -> 0.00 after the fix
monotonic-ns             16.06     realtime-ns        16.06
```

So the SAP load/store/CAS/fence primitives are genuinely free, and `shm-sap` was checked separately (0.00 —
it reads an already-boxed slot). **The two clocks still box.** Counted over a real run: `monotonic-ns` is
**0.00 calls/sample** (confirming it is off the per-sample path) and `realtime-ns` **1.02** — the DDS
`source_timestamp`, one per write, so ~16 B/sample remains there. Unlike `monotonic-ns`, `realtime-ns` has
no per-thread pre-allocated `timespec` and takes `cffi:with-foreign-object` on every call; giving it the
same treatment is the next step, and is a better fix than narrowing its declared return type.
