# ADR 0112 — The TX datagram-assembly buffer is per-NODE, and every application thread shares it

- **Status:** Accepted
- **Date:** 2026-08-07
- **Requirement:** FR-QOS (RELIABILITY), NFR-SEC-POSTURE, DDS 1.4 §2.2.2.4.2.11 (`write` has no
  single-thread restriction)
- **Severity:** data-integrity defect, **pre-existing**
- **Evidence:** `bench/report/2026-08-07-two-defects-under-concurrent-writes.md` (§ open defect),
  `bench/report/2026-08-07-the-tx-datagram-buffer-is-shared.md`
- **Related:** ADR 0108, ADR 0109 — the other two defects in the same workload. This is the third and last.

---

## 1. The defect

`%push-data` assembles the outgoing RTPS message **on the calling thread** into
`disc-node-tx-msg` — a **single `octet-buffer` slot on the node** — through `disc-node-tx-cursor`, a single
cursor slot paired with it:

```lisp
(defun* %push-data (node)
  "Push unsent changes on the caller thread using tx-msg (the synchronous send path)."
  (%push-data-buf node (disc-node-tx-msg node)))
```

With `WRITER_DATA_LIFECYCLE` async off — the default — `write-sample` reaches this on the application's own
thread. **N application threads calling `write` therefore interleave their datagram assembly into one
buffer.**

⭐ **The code already states the invariant it is violating.** `%push-data-buf`'s docstring: *"using BUF as the
scratch message buffer (tx-msg on the caller thread; async-tx-msg on the WP-ASYNC sender thread — **each
thread owns its buffer**)."* And `tx-cursor`'s: *"The receiver threads do NOT use this: each has its own in
its RX-CONTEXT, **because they run concurrently with each other and with this one**."*

The one-buffer-per-thread discipline was applied to every thread the design **enumerated** — the receiver
threads, and the async sender, which was given its own `async-tx-msg` for precisely this reason. Application
threads were never enumerated, and DDS 1.4 §2.2.2.4.2.11 places no single-thread restriction on `write`.

## 2. One mechanism, every symptom

Every unexplained observation from the concurrent-write investigation follows from this one cause:

| observed | mechanism |
|---|---|
| `CDR codec error: unknown representation id #x5254` — `0x52 0x54` is `RT`, the **RTPS magic** | a second thread's message **header** written into the middle of the first thread's payload |
| `buffer-overflow: need 117440512 octet(s)` — `0x07000000` | a length field read out of interleaved bytes |
| one instance delivered **twice** under two SNs while another never arrives | one sample's serialized bytes emitted under another sample's sequence number |
| corruption on **both** transports | it is upstream of the transport entirely |
| the SHMEM ring, the drain window, the RX store pool and the TX payload pool were each **exonerated by measurement** | correct — none of them is the *assembly* buffer |

⚠️ **The payload-integrity assertion is structurally blind to it.** The concurrent arm writes `k = v+1`; a
mis-attributed sample is a *complete, self-consistent* sample carried under the wrong sequence number, so it
satisfies `k = v+1`. Only a distinctness check over the whole delivered set sees it — which is why this
survived a green suite for so long, and why `run-writer-handle-race-test` deliberately gained no count
assertion until now.

## 3. The decision

Take a **per-node TX send lock across the synchronous push**, inside `%push-data`, so it covers every caller
of it (the batch-size trigger, `flush-batch` on the announce cadence, `stop-node`, and the lifecycle
publish paths) rather than each caller remembering.

```lisp
(defun* %push-data (node)
  (dds.pal:with-lock ((disc-node-tx-lock node))
    (%push-data-buf node (disc-node-tx-msg node))))
```

- **The async path is untouched.** The WP-ASYNC sender thread pushes through `async-tx-msg`, its own buffer,
  and one such thread exists — so it must not contend on this lock, and does not.
- **Lock order: TX lock OUTER, node lock INNER.** `%push-data-buf` takes `disc-node-lock` internally for the
  ZC armed-change snapshot. Verified that no caller of `%push-data` holds `disc-node-lock` —
  `flush-batch`, `announce-endpoints`, `stop-node`, `publish-relay-lifecycle` and `%dispose-or-unregister`
  all call it lock-free. Same direction as the existing cache-OUTER / node-INNER order.
- **No non-local exit crosses the lock** (ADR 0098): the body is a single call.

## 4. Why a lock and not a per-thread buffer

Considered and rejected **for now**, with the reason recorded so revisiting it is a measurement question:

- **A per-thread scratch buffer** is the shape that removes contention entirely, but it needs a
  thread-local mechanism in the PAL and it makes the number of `*max-datagram-bytes*` arena carves
  proportional to the number of application threads — which is unbounded, and NFR-MEM's budget is fixed at
  startup. A thread that writes once would hold a datagram buffer forever.
- **A pool of send contexts** (buffer + cursor, acquired per push) is the bounded version of that and is the
  likely end state. It needs an exhaustion policy — and for a RELIABLE writer, blocking until a slot frees
  is what a caller wants, which is a semaphore, which at depth 1 *is* this lock.

So this lock is the depth-1 case of the design that would replace it. **Correctness is a binary gate;
performance is the measured target** — take the provably-correct version, measure it, and widen the pool
only if the measurement asks for it. Recorded as a follow-up rather than assumed unnecessary.

⚠️ **A secondary race is left deliberately unfixed and named here:** `(incf (disc-node-batch-pending node))`
is a per-node counter incremented by every application thread without synchronisation. A lost increment
delays a batch flush by one sample; it cannot corrupt a datagram, and the announce-cadence `flush-batch`
bounds the delay. Fixing it inside this ADR would conflate a correctness fix with a tuning one.

## 5. Verification

- `run-writer-handle-race-test` run **repeatedly** on **Clasp** — it is intermittently red there today,
  **2 of 5**, and was already so before ADR 0108 (A/B-proven: with the drain window reverted to a bare
  high-water it still failed 1 of 5). It must go green across many consecutive runs.
- The concurrent reproducer must show **no duplicate and no missing** instance: `got=120 distinct=120`.
- ⭐ The delivery-count and distinctness assertions withheld from `run-writer-handle-race-test` become
  assertable exactly when this lands — that arm is the falsification surface.
- `gate-mem` all three arms: this adds one uncontended lock acquire per push on the single-threaded path
  that the gate measures, and must not move it.
- Full suites on SBCL **and Clasp**, plus `gate-hotpath` / `gate-nlx` / `gate-build`.

---

## 6. As built

`disc-node-tx-lock` (a `defstruct` initform, one lock per node) and `%push-data` holding it across
`%push-data-buf`. `run-writer-handle-race-test` gains `WHR-DISTINCT` and `WHR-COMPLETE`, the two assertions
withheld while the defect was open.

Measured on **Clasp**, where the defect surfaced most readily (4 threads × 30 writes, one DataWriter):

| tree | result |
|---|---|
| before — and before ADR 0108, A/B proven | **2 of 5 FAIL** (1 of 5 with the drain window reverted) |
| with the lock | **10 of 10 OK**, then 8 of 8 after the assertion fix |
| lock removed again — falsification | **4 of 6 FAIL** |

The falsification is what makes the arm a gate rather than a record:

```
run 0: FAIL  unknown representation id #x2800
run 2: FAIL  WHR-DISTINCT: 48 distinct of 49 delivered      <- a real duplicate
run 3: FAIL  WHR-DISTINCT: 19 distinct of 19 delivered
run 4: FAIL  unknown representation id #x5254
```

### ⚠️ The falsification found a defect in the assertion, not just in the code

Run 3 reads **"19 distinct of 19"** under a message accusing duplication — but 19 = 19 is a pure **loss**.
The check compared `distinct` against `want` instead of `got`, so it fired on both mechanisms while naming
only one.

**A diagnostic that names the wrong mechanism is worse than a silent failure**: it aims the next
investigation at the wrong subsystem, and this session lost hours to exactly that class of error. Split so
each accuses one thing — `WHR-DISTINCT` compares distinct to **got** (duplication), `WHR-COMPLETE` compares
got to **want** (loss). Both still go red under the sabotage.

⭐ This is the third and last defect in the concurrent-write workload. With ADR 0108 (the drain's
high-water) and ADR 0109 (the SHMEM single-producer ring), concurrent `write` on one `DataWriter` now
delivers every sample exactly once.
