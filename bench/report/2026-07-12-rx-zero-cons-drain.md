# WP-8.T3 — the zero-cons `%drain`: RX allocation and latency, before/after

2026-07-12. SBCL 2.6.5, macOS arm64, UDPv4 loopback, cross-process echo (`dds.bench:run-echo-responder`
↔ `run-echo-pinger`), 256 B payload, RELIABLE / KEEP_ALL / VOLATILE / XCDR2, 10 000 samples + 1 000 warmup,
one-way := RTT/2. Baseline = `cb08d62` (HEAD), measured in the SAME session, alternating with the change via
`git stash`, so machine state is common to both arms.

## The defect

`%drain` runs on EVERY `take_samples`. It rebuilt its pending set from the WHOLE sample store on every call:

- `node-sample-sns` consed a fresh `(GUID . SN)` key for **every stored sample**, then `remove-if-not` filtered it;
- the survivors were `mapcar`ed into 3-element `list`s (3 conses each) and `nconc`ed;
- lifecycle changes additionally went through `SET-DIFFERENCE` with an `EQUALP` test — O(stored × drained), consing
  both input lists.

So the drain allocated **O(STORED)** to deliver **O(PENDING)** samples — normally exactly one. The cost scaled with
how much was sitting in the store, not with how much work there was to do.

## The fix

`dds.disc:node-collect-pending-samples` / `node-collect-pending-lifecycle` walk the store under the node lock and
call a predicate as `(GUID SN)` — the raw hash keys, **not** a consed key — so the deciding walk allocates nothing
and a key cons is created **only for a sample that is actually pending**. Results land in reader-owned scratch
vectors (`dr-drain-data-keys` / `-life-keys` / `-plan`) that are **reused across calls**, and the merged plan is
sorted in place. Delivery order is unchanged: still ascending raw RTPS SN (§8.3.5.4 — SN is per-writer), so a
dispose/revive from one writer still lands in DDS 1.4 §2.2.2.5 order.

## Allocation (bytes consed per sample, `dds.pal:bytes-consed`, 400 round-trips)

Node store held 34–38 samples in every run below, so the O(stored) term is comparable across arms.

| | baseline `cb08d62` | with the change |
|---|---|---|
| `%drain` (1 sample pending) | 3551, 3723 B | **2583, 2899, 2745 B** (−25 %) |
| `take` after an explicit drain — **nothing pending** | 795, 472 B | **0, 0, 316 B** |

**The empty drain now allocates nothing.** That is the structurally important half: `take_samples` calls `%drain`
internally, so in the baseline every take rebuilt the entire key list from the whole store *even when there was
nothing to deliver*, and that cost grew with store occupancy.

**The drain-with-work case improved only ~25 %, not the ~100 % predicted.** The remaining ≈2 740 B/sample is NOT
key bookkeeping — it is the genuine per-sample deserialization inside `%drain-one-sample` (the decoded sample, the
`sample-info`, the `cached-sample`, the `dr-cache` cons). The earlier split that attributed 1 438 B to "the take
side" mis-located this: the allocation is real, but it lives inside the drain. That is the next lever, and it is
unchanged in size by this work.

## Latency (one-way ns, 256 B, cross-process)

| metric | baseline `cb08d62` | with the change |
|---|---|---|
| p50 | 29 500 / 28 000 | **21 000 / 21 500** (−26 %) |
| p99 | 121 500 / 79 000 | **31 500 / 37 000** (−66 %) |
| max | 13 418 500 / 13 483 500 | 9 006 000 / 13 988 000 (unchanged) |

## Two honest caveats

**1. The multi-millisecond max is PRE-EXISTING, and it contradicts the published ratio table.** Both arms show a
9–14 ms worst sample. `bench/report/2026-07-12-connext-parity-ratio-table.md` reports our 256 B p99.99 as 53.5 µs
and claims we beat Connext's tail by 2.2×. That figure does **not** reproduce today on either arm. With
`samples = 10000` the nearest-rank p99.99 IS the max, so the two are the same statistic — and it is milliseconds,
not microseconds. The tail claim in that table is therefore **not currently substantiated**; it is flagged here
rather than left standing, and re-establishing (or withdrawing) it is tracked as follow-on work. This change
neither caused nor fixed it.

**2. A deadlock was introduced and fixed during this work.** Moving the predicate INSIDE the node lock is what
makes the walk allocation-free, but the node lock is a plain non-recursive `bordeaux-threads` mutex, and the first
version's predicate called the public lock-taking accessors `node-reader-matches-writer-p` /
`node-reader-join-watermark` — self-deadlocking the drain, and with it every `take_samples` on the participant.
The suite hung deterministically at `keeplast-reader-perinstance-e2e`. Fixed by exporting the lock-free bodies
(`node-reader-matches-writer-p-unlocked`, `node-reader-join-watermark-unlocked` — the pattern the codebase already
used for `%count-eligible-drainers`) and writing the constraint into both walkers' docstrings as an explicit
DEADLOCK CONTRACT. This is a hazard the design *creates* for future callers, hence the loud documentation.

## Gates

`make test` 563/563 SBCL · `make test-clasp` 563/563 Clasp · `gate-hotpath` PASS (8 files) ·
`gate-types` PASS (2844 defuns ftype-declared) · `make mem` PASS (0 B/sample delta, no heap fallback).
