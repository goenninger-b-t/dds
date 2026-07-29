# The drain built a merged plan for one stream

**NFR-MEM / FR-PF-7 · arm64 (Apple silicon), SBCL · `make gate-mem`, 60000 samples, own process per arm**

| | before | after | delta |
|---|---|---|---|
| COPY | 719.6 | **705.4** / 705.4 / 705.4 | **−14.2** |
| RETURN | 513.3 | **496.9** / 496.9 / 495.8 | **−16.4** |

Ceilings lowered **750 → 730** (COPY) and **545 → 525** (RETURN). **The RETURN arm is under 500.**
x86_64 keeps its dash.

## Where the take path spends

The phase split after eleven slices put the receiver thread at a stable 147.5 and the main thread — write
plus take — at 376.8. The take half had never been bisected, so it was:

| | B/sample |
|---|---|
| `%drain` | 111.4 |
| `%select-samples` | 19.7 |

and inside `%drain`:

| phase | B/sample |
|---|---|
| `node-collect-pending-samples` | 36.0 |
| `node-collect-pending-lifecycle` | **0.00** |
| **the merged plan build** | **49.1** ← this slice |
| the `%drain-one-sample` loop | 95.0 |

## The defect

```lisp
(plan (let ((v (dr-drain-plan dr)))
        (setf (fill-pointer v) 0)
        (loop for k across data-keys do (vector-push-extend (cons :data k) v))       ; a cons per key
        (loop for k across life-keys do (vector-push-extend (cons :lifecycle k) v))
        (sort v #'< :key (lambda (e) (node-sample-key-sn (cdr e))))))
```

The plan exists **only to tag each key data-vs-lifecycle** so the two streams can be visited in one SN
order — a real requirement (a dispose and a revive share one writer's SN space, and applying them out of
order flips the resulting instance state). But a pending *lifecycle* change is a dispose or an unregister,
not a sample: `node-collect-pending-lifecycle` measures **0.00 B/sample** because it almost always returns
empty. So the steady-state drain merged an empty vector into a one-element vector and paid a cons per key
to do it.

With nothing to merge, `data-keys` **is** the plan. It is the reader's own reused vector, so it can be
sorted in place and drained directly — same SN ordering, same exactly-once discipline, no tagging, no
conses. The merged path is untouched and still handles cross-stream ordering whenever a lifecycle change
actually is pending.

## The window over-reported again — and the source did not

The probe attributed **49.1 B/sample** to this phase. The structural reading said one cons per pending key
per drain = **16 B**. Measured: **−14.2 / −16.4**.

That is now the pattern's clearest statement. Across twelve slices the **source-derived prediction has been
right every time bar one** (`hc-purge-below`, where SBCL had already stack-allocated a closure I assumed
was on the heap), while the probe windows have been wrong in **both** directions — under-reporting three
wins, inventing one block outright (`%write-key-hash`), and over-reporting two more (this phase, and the
purge). **Rank with the windows. Size from the source. Confirm with the gate.**

## Verification

SBCL 623/623, Clasp 623/623, `gate-hotpath` PASS, `gate-nocond` PASS, `gate-mem` PASS with both ceilings
lowered.

## Session position — twelve slices

| | start | now | total |
|---|---|---|---|
| COPY | 1550.0 | **705.4** | **−844.6 (−54.5 %)** |
| RETURN | 1342.2 | **495.8** | **−846.4 (−63.1 %)** |

## What is left in the take path

- **The `%drain-one-sample` loop (~95 by window, so treat as a rank):** deserialization into the pooled
  sample struct and the cached-sample wrapper. The decoded octet-sequence payload here is one of the
  eleven `gate-hotpath` TRACKED items and is an honest RX deserialization product — pooling it is what the
  **ECR** ("a take is not a loan") has to decide, since who owns that vector is exactly the take-vs-loan
  question.
- **`node-collect-pending-samples` (~36):** a `(cons guid sn)` per pending key, plus a `maphash` closure
  whose cost is unknown after the `hc-purge-below` lesson. The key conses are candidates for recycling
  into the reader-owned vector, but only if `%drain-one-sample` provably does not retain them.

**The arena half of the directive remains untouched.**
