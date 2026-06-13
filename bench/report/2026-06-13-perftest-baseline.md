# dds-bench baseline — participant data plane over UDP loopback

Date: 2026-06-13
Requirement: WP-PERFTEST (M5/P4), NFR-PERF-1/4/5/8, FR-LANG-7
Harness: `dds-bench` (`make bench`), SBCL, same-host UDP loopback, RELIABLE, single in-process pair.
Method: one-way latency = RTT/2 of a single in-flight PING echoed by a second node (condvar handoff, 5 s
retry cap); the app-facing poll cache is drained each iteration (emulating `take()`); bytes/sample =
`dds.pal:bytes-consed` delta over the measured loop (whole path, all threads, SBCL-exact); clock =
`dds.pal:monotonic-ns` (~µs resolution).

## One-way latency (ns; RTT/2, 5 000 samples, 500 warmup) — AFTER the history-retention WP

| payload | p50    | p99    | p99.99    | max       | mean   | bytes/sample |
| ------- | ------ | ------ | --------- | --------- | ------ | ------------ |
| 16 B    | 14 500 | 28 500 |   814 000 |   814 000 | 15 564 | 9 158        |
| 64 B    | 15 000 | 29 500 | 4 051 000 | 4 051 000 | 16 361 | 9 234        |
| 256 B   | 17 000 | 64 000 | 4 212 000 | 4 212 000 | 22 615 | 9 616        |

## Throughput (one-way, 20 000 samples) — AFTER

| payload | received | send samples/s | delivered samples/s | send Mbps |
| ------- | -------- | -------------- | ------------------- | --------- |
| 64 B    | 20 000   | 5 796          | ~5 790              | 3.0       |

## ✅ First finding — RESOLVED by the history-retention WP

The harness's first surfaced defect: latency + bytes/sample grew O(N) because the reliable engine
retained O(history) — writer `HistoryCache` KEEP_ALL never purged on ack, and the reader
`writer-proxy.received` stored every payload by SN forever. **Fixed** (`writer-purge-acked` on full-ACK +
reader presence-markers + first-SN compaction; see `docs/superpowers/specs/2026-06-13-history-retention-design.md`).
The growth is gone — steady-state O(1) (64 B, poll cache drained):

| N      | p50 latency BEFORE → AFTER | bytes/sample BEFORE → AFTER |
| ------ | -------------------------- | --------------------------- |
| 2 000  | 48 500 ns  → ~17 000 ns    | 44 434  → ~9 200            |
| 5 000  | 113 000 ns → ~16 500 ns    | 104 976 → ~9 260            |
| 10 000 | 186 500 ns → ~17 000 ns    | 171 804 → ~9 250            |

At N = 10 000: **18.6× less alloc, 11× lower latency, and now FLAT across N** (≈ 2× throughput, 2 900 →
5 800 samples/s). The remaining ~9.2 KB/sample is the still-unoptimized v1 per-sample consing (list
churn in the push/merge/target paths, the condvar handoff) — the lever for the arena / batching WPs.

## Reading the rest of the baseline
- **p50 ~16 µs at N=5 000** is now dominated by per-round-trip thread handoffs (two receiver-thread
  wakeups + a condvar signal) + the synchronous RELIABLE handshake — not retention or serialization.
- **p99.99/max in the ms range** are GC pauses (NFR-PERF-3 tail risk, as forecast); the static-arena /
  0-alloc path shrinks them.
- **~2 900 samples/s** is the synchronous one-at-a-time reliable send rate; **batching** (WP-BATCH) +
  **async + flow control** (WP-ASYNC) are the NFR-PERF-4 levers.

## Other known harness limitations (later WP-PERFTEST increments)
- µs clock resolution (PAL `get-internal-real-time` scaled) → sub-µs percentiles need a higher-res PAL
  monotonic clock (`clock_gettime`/`mach_absolute_time` via CFFI).
- Single in-process pair on loopback; the Connext-parity cross-run on identical hardware (RTI Perftest
  side-by-side) is the increment that turns these absolutes into the NFR-PERF "within Nx" ratio gates.
- Clasp `bytes-consed` returns 0 (documented NFR-PORT gap); the alloc figure is SBCL-only.
