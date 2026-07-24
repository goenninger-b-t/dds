# Async logger ring — enqueue signal reduction (and the lock-free decision)

Date: 2026-07-24
Requirement: FR-LOG-5 (the non-blocking emit ring), FR-LANG-7 ("no perf change on intuition")
Scope: `src/dds-log/emit.lisp` — `logger-emit`'s async enqueue path (`make-logger :async t`).

## Context — is a lock-free ring justified?

FR-LOG-5's ring is lock-based (correct + simple). A lock-free MPSC ring was carried as a *measured*
optimization. This is the measurement that decides it.

Micro-bench (`bench/`-style scratch, SBCL arm64): a clean **enqueue** path — worker stopped and the ring
sized well above N, so every emit enqueues (0 sheds), isolating lock + build + ring-insert from the shed
path. `us/op` is total wall-clock ÷ total ops (so for T threads it already accounts for contention).

| measurement                         | before  | after   |
|-------------------------------------|---------|---------|
| `build-log-event` alone (no ring)   | 0.238   | 0.201   |
| async ENQUEUE, 1 thread             | 0.667   | **0.484** |
| async ENQUEUE, 4 threads (contend)  | 1.342   | **1.112** |

(us/op; before = signal on every enqueue; after = signal only on the empty→non-empty transition.)

## The change

The enqueue used to `condvar-signal` the worker on **every** enqueue. But the worker `condvar-wait`s
**only when the ring is empty** — while it is draining (count > 0) it never waits, so every signal sent
during a drain is a wasted `pthread_cond_signal` syscall. The enqueue now signals **only on the
empty→non-empty transition** (`count` was 0 before this insert); the worker's 0.05 s wait timeout is the
backstop against any theoretical missed wake.

Result: single-thread enqueue **0.667 → 0.484 us/op (−27 %)**, 4-thread **1.342 → 1.112 us/op (−17 %)**.
The removed cost (~0.4 us/enqueue) was the signal syscall, which had dominated the enqueue over the
0.2 us `build-log-event`. Correctness is preserved and proven by `run-log-async-test` (the async worker
still wakes and delivers all events, both impls) — the empty→non-empty signal reaches a worker that only
ever waits while empty.

## The lock-free decision

**A lock-free ring is NOT justified by the measurement, and is not implemented.** After the signal fix,
enqueue is 0.484 us/op single-thread (~2 M enqueues/s) and 1.112 us/op under 4-thread contention — the
lock serializes, but emit is already far faster than any real logging workload needs (apps do not log
millions of times per second). Against that marginal gain, a lock-free MPSC ring carries real
memory-ordering / ABA risk that is **platform-specific** — and the operating contract's own lesson is
that "macOS cannot see platform bugs: CI/Linux is the oracle." Trading a proven, correct lock-based ring
for that risk fails the cost/benefit test. The correct lock-based ring is retained; the signal reduction
is the measured optimization that was actually warranted.
