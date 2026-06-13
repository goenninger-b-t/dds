# dds-bench baseline — participant data plane over UDP loopback

Date: 2026-06-13
Requirement: WP-PERFTEST (M5/P4), NFR-PERF-1/4/5/8, FR-LANG-7
Harness: `dds-bench` (`make bench`), SBCL, same-host UDP loopback, RELIABLE, single in-process pair.
Method: one-way latency = RTT/2 of a single in-flight PING echoed by a second node (condvar handoff, 5 s
retry cap); the app-facing poll cache is drained each iteration (emulating `take()`); bytes/sample =
`dds.pal:bytes-consed` delta over the measured loop (whole path, all threads, SBCL-exact); clock =
`dds.pal:monotonic-ns` (~µs resolution).

## One-way latency (ns; RTT/2, 5 000 samples, 500 warmup)

| payload | p50     | p99     | p99.99    | max       | mean    | bytes/sample |
| ------- | ------- | ------- | --------- | --------- | ------- | ------------ |
| 16 B    | 116 000 | 205 500 | 4 454 000 | 4 454 000 | 115 332 | 104 850      |
| 64 B    | 112 000 | 210 500 |   690 500 |   690 500 | 113 878 | 104 976      |
| 256 B   | 115 000 | 209 500 | 3 847 000 | 3 847 000 | 116 770 | 105 403      |

## Throughput (one-way, 20 000 samples)

| payload | received | send samples/s | delivered samples/s | send Mbps |
| ------- | -------- | -------------- | ------------------- | --------- |
| 64 B    | 20 000   | 2 930          | 2 927               | 1.5       |
| 1024 B  | 20 000   | 2 880          | 2 878               | 23.6      |

## ⚠ First finding: per-sample cost grows O(N) — the v1 reliable engine retains unbounded history

The harness's first surfaced defect. Latency and bytes/sample are NOT steady-state — they grow with the
sample count N (64 B payload, poll cache drained each iteration):

| N      | p50 latency | bytes/sample |
| ------ | ----------- | ------------ |
| 2 000  | 48 500 ns   | 44 434       |
| 5 000  | 113 000 ns  | 104 976      |
| 10 000 | 186 500 ns  | 171 804      |

**Root cause (confirmed in source):** the reliable engine retains O(history), never purging on ack:
- **Writer `HistoryCache` is KEEP_ALL** and never drops acked samples (`src/dds-rtps/history.lisp`:25
  notes per-instance KEEP_LAST + LIFESPAN expiry as "tracked follow-ups"); every published sample stays
  in `history-cache-changes`.
- **Reader `writer-proxy.received`** (`src/dds-rtps/reliable.lisp`:142/166) stores every received
  sample's **payload** keyed by SN, forever — never purged.

So both sides grow to N entries; the per-sample figure is rehash + retention churn over a growing table,
and latency degrades as the structures grow. **This is a v1 data-plane characteristic, not a harness
artifact** — and exactly the kind of scalability issue a perftest harness exists to surface.

**Recommended follow-up WP (data plane, not WP-PERFTEST):** purge writer history on full-ACK and bound
the reader received-table (KEEP_LAST / RESOURCE_LIMITS), so steady-state cost is O(1) per sample. Until
then the absolute baseline numbers must be read AT A STATED N (above: N = 5 000), not as steady-state.

## Reading the rest of the baseline
- **p50 ~113 µs at N=5 000** is dominated by per-round-trip thread handoffs (two receiver-thread wakeups +
  a condvar signal) + the synchronous RELIABLE handshake + the O(N) retention above — not serialization.
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
