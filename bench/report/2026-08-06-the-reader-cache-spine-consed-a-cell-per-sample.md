# The reader cache spine consed a cell per delivered sample

**NFR-MEM / ADR 0105 slice 1, Task 6a · macOS/arm64, SBCL · `make gate-mem`, 60 000 samples per arm, three
runs per arm**

## The number

**arm64** (re-measured on a quiet machine — the first three runs were taken while an unrelated build held a
core, and are shown because they turned out to be indistinguishable, which is itself worth knowing)

| arm | before | after (contended) | after (quiet) | delta |
|---|---|---|---|---|
| COPY (take, samples dropped) | 522.3 / 528.5 / 528.5 | 512.1 / 511.0 / 511.0 | **512.1 / 511.1 / 511.0** | **−16.9** |
| RETURN (take + `return-loan`) | 320.0 / 318.9 / 320.0 | 303.6 / 302.5 / 303.6 | **304.7 / 302.5 / 302.5** | **−16.7** |

**x86_64**, on the real box

| arm | before | after | delta |
|---|---|---|---|
| COPY | 561.3 / 562.5 | **544.8 … 545.7** | **−16.5** |
| RETURN | 369.0 / 370.9 | **353.6 … 355.0** | **−15.7** |

Predicted 16 B/sample — one spine cons per delivered sample — and all four arms landed on it. Ceilings:
arm64 `555 → 538` and `337 → 320`; x86_64 COPY `609 → 573`, RETURN stays a dash.

One of the five x86_64 runs read RETURN 964.5 and is excluded: it is the per-process intermittent
characterised in `bench/mem-ceiling.txt` (~14 % of arm-runs, either arm, ×2.4 to ×196), not a property of
this code.

## What was allocating

`dr-cache` is a list of `cached-sample` in arrival order, and every one of the four delivery paths appended
with

```lisp
(setf (dr-cache dr) (nconc (dr-cache dr) (list cs)))
```

The **wrapper** has been pooled since ADR 0093; the **cell holding it** was not — one fresh cons per
delivered sample. The take side then threw the whole spine away and rebuilt it from a `keep` list, so the
cells were allocated and discarded once per sample, forever.

Now the spine is a closed cycle. `%select-samples-unlocked` walks with a `prev` pointer and **unlinks each
selected cell in place**, parking it on a per-reader free list; the next delivery pops it straight back.
Steady state allocates no spine at all, and the un-selected samples keep their cells and their arrival order
untouched — nothing is rebuilt and nothing is reversed.

Three functions are the only places spine cells are created or released (`%cache-cell`, `%park-cache-cell`,
`%cache-append`), and the four append sites now share one appender instead of four copies of the `nconc`.

## Why only one site may park a cell

Parking a cell that something still holds is a corruption, so every holder was read:

- the two list-returning access paths build their result with `push`, so what reaches the application is a
  **fresh** list, never the spine (`%select-samples-unlocked`'s `out`, `take-loaned`'s and `read-loaned`'s
  `data` / `loans`);
- the WaitSet and ReadCondition predicates only `count-if` over the spine;
- the `delete` / `remove` sites (KEEP_LAST eviction, instance purge, return-loan invalidation) drop their
  cells to the GC rather than parking them — correct, because `delete` relinks destructively and does not
  report which cells it dropped. Those paths are rare; the delivery/take cycle is not, and it is the one
  that closes.

The free list is bounded by the reader's own peak cache length — cells enter it only by being unlinked from
the spine and leave it on the next append — so it costs at most what the spine it came from cost, and it
shrinks again as the cache refills.

## The falsification, and the sabotage that did not fail the way the others did

`run-cache-spine-unlink-test` is new, and it exists for a specific gap: **every take arm the suite had takes
a prefix** — the whole cache, or the first N of it — so unlinking only ever executed the head branch and
`(setf (cdr prev) next)`, the one branch that can corrupt a spine, was never reached. `take_instance` against
a three-instance cache reaches head, middle and tail.

| sabotage | result |
|---|---|
| unlink always as if the cell were the head | **RED** `:csu-mid-residue`, residue `(33)` — taking the middle threw away everything before it |
| never advance `prev` past an un-selected sample | **RED**, same check, same residue (two edits, one defect: `prev` stays `nil`, so every unlink takes the head branch) |
| park the cell **without** unlinking it first | **HANG**, not a red assertion |

That third one is worth keeping. `%park-cache-cell` rewrites the cell's `cdr` to the free list while the
spine still points at that cell, so the cache becomes circular and the next walk never terminates. **A
corrupted spine is likelier to cost a non-terminating drain than a wrong answer** — which is why the unlink
and the park are adjacent and ordered in the code rather than merely both present.

## What was rejected, and why

The obvious alternative is an **intrusive list**: a `next` slot on `cached-sample`, no spine cells at all.
It was rejected on a measured ground. `cached-sample` has exactly four slots, and on SBCL/arm64 a four-slot
defstruct is 47.8 B while a five-slot one is 64.2 B (measured for ADR 0105 Task 2, which is why
`data-pinned` and `was-exposed` are packed into one `flags` slot). The COPY arm allocates a wrapper **per
sample** because it never returns a loan and so never recycles, so a fifth slot would cost it +16 B/sample —
exactly cancelling the 16 B this task removes. Net zero on COPY, −16 on RETURN. Pooling the cells wins on
both arms instead.
