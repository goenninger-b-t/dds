# The TX datagram-assembly buffer was per-NODE, and every application thread shared it

**Conformance / FR-QOS + NFR-SEC-POSTURE · ADR 0112 · the third and last of the three defects in the
concurrent-write workload (ADR 0108, ADR 0109 were the first two)**

---

## The finding

`%push-data` assembles the outgoing RTPS message **on the calling thread** into `disc-node-tx-msg` — one
`octet-buffer` slot on the node — through the single `disc-node-tx-cursor` paired with it. With async off
(the default), `write-sample` reaches this on the application's own thread, so **N threads calling `write`
interleave their datagram assembly into one buffer**.

⭐ **The code stated the invariant it was violating.** `%push-data-buf`: *"tx-msg on the caller thread;
async-tx-msg on the WP-ASYNC sender thread — **each thread owns its buffer**."* `tx-cursor`: *"The receiver
threads do NOT use this: each has its own in its RX-CONTEXT, **because they run concurrently with each other
and with this one**."*

One-buffer-per-thread was applied to every thread the design **enumerated** — the receiver threads, and the
async sender, which got its own `async-tx-msg` for exactly this reason. Application threads were never
enumerated. DDS 1.4 §2.2.2.4.2.11 places no single-thread restriction on `write`.

## One mechanism, every symptom

| observed across the investigation | mechanism |
|---|---|
| `unknown representation id #x5254` — `0x52 0x54` = `RT`, the RTPS magic | a second thread's message **header** written inside the first's payload |
| `#x0207`, `#x0205`, `#x0701`, `#x2800` | the same, landing at other offsets |
| `buffer-overflow: need 117440512` (`0x07000000`) | a length field read out of interleaved bytes |
| one instance delivered **twice** under two SNs, another missing | one sample's octets emitted under another sample's sequence number |
| corruption on **both** transports | upstream of the transport entirely |
| the SHMEM ring, drain window, RX store pool and TX payload pool all exonerated by measurement | correct — none is the *assembly* buffer |

## The measurement

`run-writer-handle-race-test` (4 threads × 30 writes to one DataWriter, RELIABLE + KEEP_ALL), on **Clasp**,
where it failed most readily:

| tree | result |
|---|---|
| before (and before ADR 0108 — A/B proven) | **2 of 5 FAIL** / 1 of 5 with the drain window reverted |
| **with the ADR 0112 lock** | **10 of 10 OK**, then 8 of 8 after the assertion fix |
| lock removed again (falsification) | **4 of 6 FAIL** |

The falsification run is the important one — it shows the new assertions can actually go red:

```
run 0: FAIL  CDR codec error: unknown representation id #x2800
run 2: FAIL  WHR-DISTINCT: 48 distinct of 49 delivered      <- a real duplicate
run 3: FAIL  WHR-DISTINCT: 19 distinct of 19 delivered
run 4: FAIL  CDR codec error: unknown representation id #x5254
```

## ⚠️ The falsification also found a defect in the assertion itself

Run 3 above reads **"19 distinct of 19"** under a message accusing *duplication* — but 19 = 19 is not a
duplicate, it is a pure **loss**. The check compared `distinct` against `want` rather than against `got`, so
it fired on both mechanisms while naming only one.

A diagnostic that names the wrong mechanism is worse than a silent failure: it aims the next investigation
at the wrong subsystem. Split so each check accuses exactly one thing — `WHR-DISTINCT` compares distinct to
**got** (duplication), `WHR-COMPLETE` compares got to **want** (loss). Both still go red under the sabotage.

## Why a lock, and what replaces it

A per-node TX send lock across the synchronous push. The async sender is deliberately **not** covered — it
owns `async-tx-msg` and there is one of it. Lock order is TX-OUTER / node-INNER, verified against every
caller (`flush-batch`, `announce-endpoints`, `stop-node`, `publish-relay-lifecycle`,
`%dispose-or-unregister`), none of which holds the node lock.

A per-thread buffer would remove contention but needs PAL thread-locals and makes datagram-buffer carves
proportional to an unbounded thread count against a fixed startup budget. A **pool of send contexts** is the
bounded form and the likely end state — and its blocking acquire at depth 1 *is* this lock. Correctness is a
binary gate and performance is the measured target, so: take the provably-correct version, measure it, widen
only if the measurement asks.

⚠️ **Left deliberately unfixed and named:** `(incf (disc-node-batch-pending node))` is a per-node counter
incremented by every application thread unsynchronised. A lost increment delays a batch flush by one sample;
it cannot corrupt a datagram, and the announce-cadence `flush-batch` bounds the delay.

## What this closes

All three defects in the concurrent-write workload are now fixed: ADR 0108 (the drain's high-water),
ADR 0109 (the SHMEM single-producer ring), ADR 0112 (the shared TX assembly buffer). The delivery-count and
distinctness assertions withheld from `run-writer-handle-race-test` while the defect was open are now live,
which is what makes the arm a gate rather than a record.
