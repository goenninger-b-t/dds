# The reliable writer allocated a CacheChange struct per sample — it now recycles them (TASK-3)

**Date:** 2026-07-21 · **Requirement:** NFR-MEM (0 B/sample), NFR-PERF-3, NFR-PERF-8 · **ADR:** 0077, 0062
**Machine:** arm64 Darwin, SBCL · **Harnesses:** `sb-sprof :mode :alloc` (all threads) + `dds.bench:mem-per-sample`
(`make gate-mem`) + the full suite (the correctness oracle).

## How it was found

After the four RX-pooling slices (ADR 0073/0074/0075/0076) shrank the RX side, a re-profile made the TX side
dominant:

| allocator | self % |
|---|---|
| `%writer-add-bounded` (the CacheChange struct) | **30.2** |
| `dispatch-message` | 13.7 |
| SHMEM `%lane-drain` / `%rx-wait` | ~9 |
| `%on-user-heartbeat` | 5.6 |

`%writer-add-bounded` allocates a ~17-slot CacheChange per write, retained in the writer's HistoryCache until
every reader ACKs it.

## The fix

Pool the struct on a per-HistoryCache `change-freelist`, as a structural sibling of the existing T5a
pooled-buffer release — riding the **same proven gate**: recycle a change only when `evicted` **and**
`send-refcount = 0` (no send build-thunk still references it). A change evicted while send-referenced defers
its recycle to the last ref drop. ZC-armed / pooled / pinned changes are excluded (they have references beyond
`send-refcount` — the disc leak-sweep, the payload-pool, the slot); those rare paths keep allocating. The
freelist is capped at 64 so a draining backlog cannot grow it without bound.

The two `make-change` thunks now draw from the freelist (`hc-data-change` / `hc-lifecycle-change`), which fully
reset all 17 slots before filling — byte-for-byte identical to `make-cache-change`.

## Result

- **`gate-mem` floor 1922 → 1812.9** (min-of-8: `1812.9 1813.0 1834.7 1834.7 1834.8 1856.5 1856.6 1856.6`;
  a later clean run measured **1791.1**). ≈ **−109 B/sample** (the struct is the bulk of the 30.2 %; the
  residual is the changes-hash churn). Cumulative from the ADR 0062 baseline: **3560 → ~1791, ≈ −50 %.**
  **arm64 ceiling 2060 → 1900**; x86_64 set to 2090 (est ~1951, robustly-safe pending CI).

## Validation

`gate-build` PASS both impls (self-falsified). **574/574 Clasp and SBCL** (retransmit / KEEP_ALL-backpressure /
KEEP_LAST-eviction / dispose / ZC-loan / secured tests drive the capture→evict→release→recycle lifecycle). New
falsified regression `run-cache-change-recycle-test`: an evicted send-ref-free change is freelisted + reused
**eq** and fully reset; a change evicted **while send-referenced** is NOT freelisted until the ref drops —
**shown red** by removing the `releasable-p` gate, then restored. `gate-hotpath` / `gate-types` /
`gate-nocond` / `gate-pal` / `corpus` / `mem` / `fuzz` all green.
