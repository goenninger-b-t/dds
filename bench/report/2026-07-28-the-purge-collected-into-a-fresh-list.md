# The ACKNACK purge collected into a fresh list

**NFR-MEM / FR-PF-7 · arm64 (Apple silicon), SBCL · `make gate-mem`, 60000 samples, own process per arm**

| | before | after | delta |
|---|---|---|---|
| COPY | 820.6 | **802.6** / 801.5 / 803.7 / 796.0 | **−18.0** |
| RETURN | 607.2 | **594.1** / 594.1 / 594.1 / 594.1 | **−13.1** |

Ceilings lowered **850 → 835** (COPY) and **640 → 625** (RETURN). x86_64 keeps its dash.

## The defect

```lisp
(let ((removed '()))                                       ; MUTABLE + closed over -> value cell
  (maphash (lambda (sn ch) (declare (ignore ch)) (when (< sn base) (push sn removed)))
           (history-cache-changes hc))
  (dolist (sn removed (length removed)) (%hc-remove-change hc sn)))
```

`hc-purge-below` runs on **every inbound ACKNACK — once per sample** — and built a fresh list by pushing
onto a closed-over mutable variable, which on SBCL costs a heap value cell on top of whatever the closure
costs.

## The fix, and what stayed

It **stays a two-phase walk**, and that is deliberate: CLHS forbids mutating a hash table during `MAPHASH`
beyond `remhash`-ing the key currently being processed, and `%hc-remove-change` does far more than a
`remhash` — the per-instance KEEP_LAST index, the stored-SN extent, the payload-pool and ZC-pin release
gates, and a rescan that `MAPHASH`es the same table again. Collapsing the two phases would be a real
correctness change dressed as an optimisation.

Only the **collection** changed: into the cache's reused `purge-scratch` vector rather than a fresh list,
with the collector an `flet` declared `dynamic-extent`. `MAPHASH` does not retain its function, so that is
sound. The scratch settles at the high-water mark of one purge and allocates nothing thereafter, and it is
mutated only under the owning writer's lock — the same discipline `change-freelist` (ADR 0077) documents
one slot above it, and the sole production caller, `writer-purge-acked`, holds that lock.

## ⚠️ The prediction over-shot — the first time this campaign

Every previous slice was predicted from the source to within a few percent. This one was predicted at
**~64 B/sample** (a heap closure ≈32, a value cell 16, a cons per purged SN 16) and delivered **−18.0 /
−13.1**.

The likely reading: **SBCL was already stack-allocating the `MAPHASH` closure**, so only the value cell and
the cons were ever real. That is a useful correction to the mental model this campaign has been running on —
*a `lambda` passed to a known function is not automatically a heap closure*, and the earlier wins came from
closures passed to **our own** functions, which the compiler cannot see through.

**So: predict from the source, but size with the gate — in BOTH directions.** Nine times the gate revealed
a win at or above the prediction; once, here, below it. The rule survives; the direction of the error does
not matter to it.

## The gate earned its place too

`make gate-hotpath` **failed** on the first attempt: the new `make-array` in the `defstruct` initform
carried no `HOTPATH-ALLOC` annotation. It is a genuinely cold allocation — one vector per HistoryCache,
and the very thing that removes the per-purge allocation — but the gate is right to demand that every
allocating form in a hot-path file say so in writing. Annotated, re-run, green.

## Verification

SBCL 623/623, Clasp 623/623, `gate-hotpath` PASS (after the annotation), `gate-nocond` PASS, `gate-mem`
PASS with both ceilings lowered.

## Session position — ten slices

| | start | now | total |
|---|---|---|---|
| COPY | 1550.0 | **796.0** | **−754.0 (−48.6 %)** |
| RETURN | 1342.2 | **594.1** | **−748.1 (−55.7 %)** |

Receive pipeline: **688 → 245.7 B/sample**, fully attributed (residual 0.01), prologue now free —
ACKNACK 98.3, DATA 91.7, HEARTBEAT 55.7 before this slice.

## What is left, and its changed character

The remaining allocation on the measured paths is inside `%deliver-user-sample`'s two-level sample store,
the reader-proxy `equalp` lookups, and the drain. **That is data-structure work, not per-call fixes** — the
three shapes this session harvested (a reusable per-call object, a value rebuilt per sample that changes per
discovery event or per instance, a closure that could be stack-allocated) are exhausted on these paths.

Still untouched: **the arena half of the directive**, and the queued **ECR** ("a take is not a loan"), whose
arm — COPY — now sits ~202 B/sample above RETURN.
