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

---

## Third and fourth instance: both clocks — **−16 B/sample**, and zero on *any* thread

Owner directive, same day: *"preallocate / use the arena for any clock stuff."*

`realtime-ns` supplies the DDS `source_timestamp` and is **1.02 calls/sample** (measured — one per write).
`monotonic-ns` is **0.00 calls/sample**, i.e. off the per-sample path entirely. Both cost **16 B/call**. The
two fast paths that already existed — a per-thread pre-allocated `timespec` and the cached
`*clock-gettime-fp*` — had been built for the clock that does not need them.

**The fix turned out not to need preallocation at all.** Every component measured 0.00 in isolation —
`mem-ref`, the raw `clock_gettime` through the cached pointer, the `sec*1e9 + nsec` arithmetic — while the
whole function measured 16.06. `cffi:with-foreign-object` was cleared too, at 0.00 in every shape tried.
The 16 B was the scratch pointer crossing the `flet read-clock` boundary: **passing a SAP across an
out-of-line call boxes it** — the same defect as `%ptr+` and `static-pointer`, third and fourth instance.

Converting that `flet` to a **`macrolet`** in both clocks expands the read in place, so the pointer never
crosses a function boundary:

| | before | after |
|---|---|---|
| PAL-spawned thread | 16.06 | **0.00 B/call** |
| an application thread the PAL never created | 16.06 | **0.00 B/call** |

So it is zero-allocation on *any* thread — no wrapping in `call-with-thread-clock`, no per-impl
thread-local carve. End to end **−16 B/sample**: COPY 1563.9 → 1550.0 / 1553.1 / 1550.2, RETURN
1359.7 → 1343.3 / 1343.3 / 1342.2; ceilings lowered to **1585 / 1375**.

### The fix that was rejected

A **per-writer** scratch would also have removed the allocation, and was rejected: two application threads
writing one DataWriter would share one 16-octet cell and could interleave two `clock_gettime` results into
it — a torn timestamp, seconds from one read with nanoseconds from another. That is the
shared-mutable-scratch hazard class. The `macrolet` fix makes the question moot.

### ⚠️ A measurement-discipline failure, recorded because it cost a false alarm

A `gate-mem` run taken **while the test suites were running in the background** read COPY **1710.8** and
FAILED the gate — 163 B above the clean maximum, a phantom regression from participant and CPU contention.
**A benchmark is an instrument; give it the machine.** Second phantom regression from harness contention in
one session.

### The sweep is now clean

Every hot PAL primitive measures **0.00 B/call**: `load-sap-u8/u16/u32/u64`, `store-sap-u8/u64`,
`cas-sap-u32/u64`, `fence :acquire/:full`, `sap-copy-in/-out`, `shm-sap`, and both clocks.
