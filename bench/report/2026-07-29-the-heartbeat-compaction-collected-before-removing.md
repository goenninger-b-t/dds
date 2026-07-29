# The HEARTBEAT compaction collected before removing

**NFR-MEM / FR-PF-7 · arm64 (Apple silicon), SBCL · `make gate-mem`, 60000 samples, own process per arm**

| | before | after | delta |
|---|---|---|---|
| COPY | 705.4 | **687.9** / 687.9 / 689.0 | **−17.5** |
| RETURN | 496.9 | **481.6** / 480.6 / 480.5 | **−15.3** |

Ceilings lowered **730 → 720** (COPY) and **525 → 510** (RETURN). x86_64 keeps its dash.

## The defect

`reader-on-heartbeat` compacts the writer-proxy's received-marker table when the writer's `firstSN`
advances — which, under a writer that purges as its reader acknowledges, is **every sample**:

```lisp
(let ((received (writer-proxy-received proxy)) (drop '()))     ; MUTABLE + closed over
  (maphash (lambda (sn v) (declare (ignore v)) (when (< sn new-first) (push sn drop))) received)
  (dolist (sn drop) (remhash sn received)))
```

## The fix — and the distinction from the sibling slice

It compacts **in one pass**. CLHS 18.2 permits exactly one mutation during `MAPHASH` — `REMHASH` of the key
*currently being processed* — and that is precisely what this does, so the collect-then-remove structure
bought nothing.

**This is not the same call as `hc-purge-below`**, which kept its two phases in an earlier slice and
should keep them: that one removes via `%hc-remove-change`, which maintains the per-instance KEEP_LAST
index and the stored-SN extent, runs the payload-pool and ZC-pin release gates, and itself `MAPHASH`es the
same table. Collapsing *that* one would be a correctness change dressed as an optimisation. Collapsing
*this* one is the single case the standard blesses. **The two look identical and are not, and the
difference is entirely in what the removal does** — which is why each was decided by reading its removal
rather than by pattern-matching the loop.

## The prediction, and what it teaches about SBCL closures

Predicted **~32 B/sample**: a heap value cell for the closed-over mutable `drop`, plus a cons per dropped
marker. Measured **−17.5 / −15.3** — about one cons.

Read together with the `hc-purge-below` slice (predicted ~64, measured −18/−13), the picture is consistent:
**SBCL was already stack-allocating these `MAPHASH` closures, and a value cell reachable only from a
stack-allocated closure goes on the stack with it.** The campaign's earlier closure wins all came from
closures handed to *our own* functions — `publish-sample-into`, `%writer-add-bounded`,
`node-collect-pending-*` — which the compiler cannot see through. `MAPHASH` it can.

So the refined rule: **a `lambda` passed to a standard function is probably already free; a `lambda` passed
to one of ours is probably not.** The remaining win in both these slices was the *list*, not the closure.

## Verification

SBCL 623/623, Clasp 623/623, `gate-hotpath` PASS, `gate-nocond` PASS, `gate-mem` PASS with both ceilings
lowered.

## Session position — thirteen slices

| | start | now | total |
|---|---|---|---|
| COPY | 1550.0 | **687.9** | **−862.1 (−55.6 %)** |
| RETURN | 1342.2 | **480.5** | **−861.7 (−64.2 %)** |

## What is left

- **`%drain-one-sample` (~95 by window) is BLOCKED, by owner ruling (2026-07-29)** — its decoded payload
  must not be pooled before the "a take is not a loan" ECR is decided, because *who owns that vector* **is**
  the take-vs-loan question, and pooling it would settle the API by accident.
- Unblocked: `node-collect-pending-samples`' `(cons guid sn)` per pending key (bookkeeping, not sample
  data), and whatever remains in the ACKNACK handler and the TX path — none of it re-bisected since the
  slices that changed it.
- **The arena half of the directive remains untouched.**
