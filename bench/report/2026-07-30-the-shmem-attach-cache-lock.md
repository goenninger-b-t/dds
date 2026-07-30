# The SHMEM attach cache needed a lock, and the lock costs 18 ns

**FR-XPORT-2 / NFR-STABILITY · macOS/arm64, SBCL 2.6.5 · isolated `%shmem-send` primitive, 200 000 sends of
a 64-octet datagram, 3 runs per arm, nothing else on the machine**

This is a **correctness** change with a measured cost, not an optimisation. It is reported here because the
operating contract requires a before/after number for anything on a hot path — including when the number
goes the wrong way.

## The cost

| | ns/send | B/send |
|---|---|---|
| before — `attach-cache` unlocked | 106.1 / 106.3 / 107.6 | 0.0000 |
| after — every access under `attach-lock` | **124.2 / 124.4 / 124.6** | **0.0000** |

**+18 ns/send, ~+17 % on the primitive. Zero allocation** — `with-lock-held` conses nothing, so this is time,
not bytes, and `gate-mem` is unchanged (COPY/RETURN both inside their existing bands).

Both arms were measured in the same harness with the same warm-up (the cache is filled before the timed
loop), so the delta is one uncontended mutex acquire/release per datagram on the **cache-hit** path.

## What it buys

`%attach-for` did an unlocked `gethash` and an unlocked `(setf gethash)` on a table shared by **four
threads** (publisher, async sender, the receiver thread's ACKNACK repair, the flow scheduler), on **every**
send. Two harms, one of them silent:

- **corruption** — SBCL detected its own broken invariant: `failed AVER: (= HWM
  (HASH-TABLE-PAIRS-CAPACITY ...))`;
- **a leaked attach** — two threads racing the same new peer each `shm-attach`, one clobbers the other, the
  loser's mapping is never detached.

Both were absorbed by `%send-raw-buf`'s self-guard into a quiet UDP fallback, so SHMEM degraded with nothing
going red. See ADR 0100.

## The falsification, which is the part worth trusting

`run-shmem-attach-cache-race-test` — six threads resolving the same fresh names through one transport:

| arm | result |
|---|---|
| lock removed | **5 of 8 FAILED** — *"all threads must share ONE dest … (got 2 distinct)"* |
| lock in place | **6 of 6 PASSED** |

A green concurrency test that has never been seen red is decoration.

## Where the 18 ns goes if it ever matters

Stop calling `%attach-for` per datagram: memoise the resolved `shmem-dest` on the locator the discovery layer
already caches per peer (ADR 0067 does the analogous thing for the SAP and the lane), leaving the lock on the
cold fill path only. Deliberately not bundled with a correctness fix.
