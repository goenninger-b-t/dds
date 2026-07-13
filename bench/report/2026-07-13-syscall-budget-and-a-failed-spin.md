# The latency is SYSCALLS. A syscall-budget audit, one wasted kernel wake removed, and a spin experiment that FAILED

2026-07-13. SBCL, macOS arm64, live cross-process echo. Continuation of #23. Baseline `2bb3193`.

## The finding: our Lisp code is no longer the problem

`sb-sprof` (`:mode :cpu`, all threads) on the responder under a REAL single-in-flight echo — not a burst:

```
  Nr  Self%   Function
   1  30.0    foreign function __psynch_cvsignal     <-- condvar signal (a WAKE)
   2  28.4    foreign function __sendto
   3  10.6    foreign function __ulock_wake
   4   8.9    foreign function __psynch_cvwait
   5   6.4    foreign function __recvfrom
   6   3.4    foreign function __semwait_signal
   7   2.4    foreign function __ulock_wait2
   8   0.9    foreign function __psynch_mutexdrop
```

**~94 % of the responder's CPU is kernel primitives.** After the codec and history-cache fixes, our Lisp
code is essentially invisible in the profile. The remaining latency is the cost of syscalls and of getting a
thread *scheduled*.

## The syscall budget, counted (not guessed)

Per echoed sample, responder side:

| call | before | after |
|---|---|---|
| `%shmem-send` (the data) | 1.00 | 1.00 |
| `pshared-cond-signal` (wake the peer's receiver) | 1.00 | 1.00 |
| `udp-send-to` | 1.01 | 1.01 |
| `condvar-broadcast` (writer space-cv) | **1.00** | **0.00** |

**The UDP datagram is the ACKNACK** (decoded the submessage ids: `id=0x06 ACKNACK`, 1.002/sample). It is sent
*after* the listener has already echoed (measured: 16 999 of 17 000 samples), so it is **off the critical
path** — no reliability change is warranted, and I am not making one.

**Pre-listener cost** (datagram entry → listener entry) is only **2 292 ns p50**, so the receive-side demux
is not the problem either.

## Fix shipped — one wasted kernel wake per sample

`%writer-signal-space` broadcast the writer's `space-cv`, under the writer lock, on every ACKNACK purge —
i.e. once per sample. But a publisher only *waits* on `space-cv` when the cache is a **bounded KEEP_ALL with
`max_blocking_time` set**. On the default (unlimited / KEEP_LAST) writer **nobody can ever be waiting**, yet
macOS traps into `__psynch_cvsignal` regardless of whether a waiter exists — and that symbol was the single
largest item in the profile (30 %).

Guarded by `%writer-blockable-p`, which is exactly the condition under which `%writer-add-bounded`
`condvar-wait`s. The bounded-backpressure path is untouched.

**Verified: `condvar-broadcast` 1.00 → 0.00 per sample.** One kernel wake and one lock round-trip removed
from every sample on the default path.

**HONESTY: this does NOT show up in end-to-end latency above noise.** Five runs each, 256 B one-way p50:

```
  after:   25 812   21 458   31 875   28 750
  before:  29 166   27 812   28 250   27 625   17 270
```

Indistinguishable. And note the machine has drifted noisier across this session — identical code measured
16–32 µs at different times — so a 1–3 µs effect is simply not resolvable on this box right now. The change
is justified by the **counted syscall reduction** and by first principles (it can never do useful work on the
default path), not by a latency claim I cannot support.

## NEGATIVE RESULT — the spin-then-park experiment FAILED. Reverted.

Hypothesis: parking costs a cross-process futex round trip (sender `pthread_cond_signal` + receiver must be
*scheduled*), measured at ~6 µs of the ~17 µs one-way. A receiver still spinning when the datagram lands
skips both halves, since `%shmem-send` only signals when `parked=1`.

Implemented a bounded spin in `%rx-wait-for-work` before parking. **It made latency 7× WORSE:**

| spin iterations | 256 B one-way p50 |
|---|---|
| 0 (park immediately) | **16 187 ns** |
| 2 000 | **116 937 ns** |
| 20 000 | run never completed (hung) |

**Root cause of the failure — a real defect in the approach, not just a bad tuning number:**
`%rx-wait-for-work` runs **with the pshared mutex HELD**. A spinning receiver therefore holds the mutex for
the whole spin, and `stop-shmem-receiver` needs that same mutex to broadcast — which is why the 20 000-iter
run hung on teardown. Doing this correctly requires releasing and re-acquiring the mutex around the spin
(and re-validating the Dekker handshake around that), which is a larger restructure than the evidence
justifies right now.

Reverted in full. Recorded here so the next person does not re-run the same experiment blind: **the idea is
sound, the placement is wrong.** If revisited, the spin must sit OUTSIDE the mutex.

## Where the remaining ~17–20 µs actually sits (256 B one-way)

```
  pinger write-sample            ~5.2 us   (of which ~2.8 us is the shmem send itself)
  transport + cross-process wake ~6    us   <-- the scheduler getting the receiver onto a core
  responder pre-listener demux    2.3  us
  responder take-samples          0.9  us
  responder write-sample (echo)  ~5.2  us
```

The dominant remaining item is **the wake**, i.e. the cost of a blocking-wait design. That is the real
distance to Connext's 7 µs, and closing it means changing *when we block*, not what we compute.

## Gates

`make test` 563/563 SBCL · `make test-clasp` 563/563 Clasp · `gate-hotpath` PASS · `gate-types` PASS (2851).
