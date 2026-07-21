# ADR 0077 — the reliable writer recycles its cache-change structs (TASK-3), riding the send-refcount release gate

- **Status:** Accepted
- **Date:** 2026-07-21
- **Requirements:** NFR-MEM (0 bytes/sample), NFR-PERF-3 (the peer GC-tail), NFR-PERF-8
- **Relates to:** ADR 0062 (the allocation budget); the operating contract §4 release-safety + WP-DDS-SECURITY-ZEROALLOC-AEAD T5a (the `evicted`+`send-refcount` gate this reuses); ADR 0044 (the pinned sibling); the RX-pooling slices ADR 0073/0075/0076 (which shrank the RX side and left this the #1 allocator)
- **Contract touched:** `history-cache` gains a `change-freelist` slot; `cache-change` is unchanged. New `dds.rtps.history` exports `hc-data-change` / `hc-lifecycle-change` (replace the two `make-cache-change` thunk call sites) and `hc-try-recycle-change`. No wire/API-visible change.

## Context

After the four RX-pooling slices, an `sb-sprof :alloc` profile (all threads, over `mem-per-sample`) put
`%writer-add-bounded` at **30.2 %** — the dominant allocator by far. It allocates the **CacheChange struct**
(a ~17-slot record) per write, held in the writer's HistoryCache until every matched reader ACKs it. The
struct's docstring already calls it "the POOLED per-sample record" — the intent was always to pool it.

The hazard is that a CacheChange is referenced by more than the cache: a captured send build-thunk holds it
(to copy its payload / resolve its slot on retransmit). Reusing the struct while such a thunk is in flight
would corrupt the wire. But the engine already tracks exactly this: **`send-refcount`** (incremented for
every change captured for a send, decremented on completion) and **`evicted`**, and the T5a secured
payload-pool release (`hc-try-release-pooled`) already recycles a *buffer* only when `evicted` **and**
`send-refcount = 0`. That gate is proven and load-bearing. The struct can ride it.

## Decision

Pool the CacheChange struct on a per-HistoryCache **`change-freelist`**, as a **structural sibling** of the
pooled/pinned release:

- **Draw:** the two `make-change` thunks (`writer-write`, `writer-lifecycle-change`) now call
  `hc-data-change` / `hc-lifecycle-change`, which `hc-take-change` — pop the freelist and **fully reset all 17
  slots** (`%reset-cache-change`) or allocate fresh — then set the sample's slots. Byte-for-byte identical to
  the `make-cache-change` they replaced. Runs under the writer lock (the thunk is funcalled inside
  `%writer-add-bounded`'s lock).
- **Recycle:** `hc-try-recycle-change` returns a change to the freelist iff **`evicted` ∧ `send-refcount = 0`**
  (the proven gate) ∧ **not ZC-armed ∧ not pooled ∧ not pinned** ∧ freelist below its cap. Called from the
  **same two triggers** as the pooled/pinned release — the eviction choke (`%hc-remove-change`) and the last
  send-ref drop (`writer-release-change-ref` / `-refs`) — so a change evicted while still send-referenced
  **defers** its recycle to the last ref drop. It clears `evicted` on push for idempotency (the struct is
  freelist-owned; the other trigger's call is then a no-op). Under the writer lock.

**Why the exclusions.** A ZC-armed change (`zc-slot ≥ 0`) is *also* held in the disc leak-sweep list
(`disc-node-zc-armed-changes`); a pooled change by its payload-pool; a pinned change by its slot — references
**beyond** `send-refcount`, which the gate does not see. Those keep allocating (they are the rare
secured/FlatData paths). The common `:data` / dispose write — the 30.2 % — is pooled. The freelist is capped
(`*hc-change-freelist-cap*` = 64) so a draining backlog cannot grow it without bound.

## Consequences

- **`gate-mem` floor 1922 → 1812.9** (min-of-8; ≈ **−109 B/sample** — the struct is the bulk of the 30.2 %;
  the residual is the changes-hash churn). Cumulative from the ADR 0062 baseline: **3560 → ~1791, ≈ −50 %.**
  **arm64 ceiling 2060 → 1900.** x86_64 is estimated ~1951 (−109 like arm64) and set to **2090** —
  robustly-safe for a floor anywhere in [1910, 2010] (above max-floor+strays, below min-floor/0.9), so CI
  neither ratchet-demands nor regresses; tightened to CI's actual number on the next slice.

## Validation

`gate-build` PASS both impls (clean cache, self-falsified). **574/574 Clasp and SBCL** — the reliable
retransmit / KEEP_ALL-backpressure / KEEP_LAST-eviction / dispose / ZC-loan / secured tests exercise the exact
capture→evict→release→recycle lifecycle; a recycle-while-referenced bug would corrupt a retransmit and fail
them. **New falsified regression `run-cache-change-recycle-test`** asserts (i) an evicted send-ref-free change
is freelisted and reused **eq**, fully reset (a prior `:dispose`+status-info reused as a clean `:data`); (ii) a
change evicted **while send-referenced** is NOT freelisted until the ref drops — **shown red** by removing the
`releasable-p` check from the gate, then restored. `gate-hotpath` / `gate-types` / `gate-nocond` / `gate-pal` /
`corpus` / `mem` / `fuzz` all green.

## Next

The changes-hash churn (the residual of `%writer-add-bounded`), the SHMEM transport (`%lane-drain` /
`%shmem-send`), and the TX key-hash (`%write-key-hash`, per-thread scratch) remain.
