# ADR 0110 — The KEEP_LAST per-instance index consed a cell per write, and dropped one per write

- **Status:** Accepted
- **Date:** 2026-08-07
- **Requirement:** NFR-MEM (steady state allocates ZERO bytes/sample), FR-RTPS-5, DDS 1.4 §2.2.3.18
- **Evidence:** `bench/report/2026-08-07-the-keep-last-index-cell.md`

---

## 1. The defect

`%hc-index-append` maintained the per-instance KEEP_LAST index with

```lisp
(nconc (gethash key (history-cache-instances hc)) (list sn))
```

and `%hc-index-drop` removed the entry with `(delete sn ...)`.

Under KEEP_LAST the cache **evicts exactly as often as it appends**, so this consed one cell per write and
discarded one per write — steady-state garbage at a fixed per-sample rate, which is precisely what NFR-MEM
forbids. At depth 1 every single write pays it.

## 2. The decision

Park the dropped cell and reuse it. The free list is a slot on the `history-cache`
(`history-cache-free-cells`), the cells are linked through their own `cdr`, and two functions are the only
places the index obtains or surrenders one:

- `%hc-cell-take` — pop a parked cell and overwrite its `car`/`cdr`; cons only when the list is empty.
- `%hc-cell-park` — push an **already-unlinked** cell.

`%hc-index-drop` had to stop using `delete`: `delete` discards the cell it removes, which is the whole
resource being recovered. It now unlinks in place with a `prev`/`cell` walk and parks each removed cell,
removing *every* occurrence of the SN exactly as `delete` did.

## 3. Why this is safe

- **Same lock.** `hc-add-change` and `hc-remove-change` run under `%with-writer-lock`, which already guards
  `history-cache-instances`. The free list adds no new race class.
- **Unlink-before-park is a stated precondition** on `%hc-cell-park`. A cell parked while still reachable
  from a bucket would later be handed to an append and appear in **two** buckets at once — one instance's
  depth accounting silently driving another's eviction. That is a correctness fault, not a leak, so it is
  documented at the function rather than left to the reader.
- **Bounded.** The list holds at most the cells the cache itself evicted, so it is O(cache size), not
  O(samples). KEEP_ALL keeps no index at all and is untouched.

## 4. Cost and result

Measured on `gate-mem`, the real drained write→take workload — **not** a producer-only probe (the lesson of
the retracted ADR 0107: a probe without a consumer measures a different system).

| arm | before | after | delta |
|---|---|---|---|
| COPY | 433.6 | **415.0** | −18.6 |
| RETURN | 222.8 | **205.3** | −17.5 |
| INTO | 194.4 | **177.0** | −17.4 |

Consistent across all three arms, as a per-write cons must be. Ceilings lowered arm64 `453 236 203` →
`436 216 186`.

## 5. Verification

- `gate-mem` all three arms, both architectures.
- The full suite: the KEEP_LAST eviction arms are the falsification surface — a mis-parked cell aliases two
  buckets and breaks per-instance depth, which those arms assert directly.
- `make gate-hotpath` — the remaining `(list sn)` is the cold first-write-per-depth case and is tagged
  `HOTPATH-ALLOC(TRACKED)`.
