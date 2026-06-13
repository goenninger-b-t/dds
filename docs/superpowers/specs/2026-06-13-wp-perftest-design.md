# WP-PERFTEST (M5/P4) — perftest harness — design

**Goal.** Open M5 with the measurement capability the milestone is gated on: a `dds-bench` harness that
reports one-way latency percentiles, throughput, and bytes-consed-per-sample for the participant data
plane, so every P4 feature (batching, async, SHMEM, Zero-Copy, FlatData, LZ4) lands with a measured
before/after (NFR-PERF-1/4/5/8, FR-LANG-7). `make bench` was a stub; this is its first increment.

## Design
- **New ASDF system `dds-bench`** (src/dds-bench/, package `dds.bench`), depends on dds-pal/core/disc/rtps.
  Portable Lisp; all impl-specific primitives (clock, allocation counter) come from the PAL, so no reader
  conditionals leak out of `dds-pal/` (operating contract).
- **One-way latency = RTT/2, single in-flight PING/PONG.** Two in-process disc-nodes on UDP loopback: a
  pinger (writer PerfPing + reader PerfPong) and an echoer (reader PerfPing + writer PerfPong). The
  echoer's `disc-node-on-sample` republishes a pong; the pinger's `on-sample` stamps `monotonic-ns` and
  signals a condvar rendezvous; the main thread times send→echo. RTT/2 avoids cross-node clock sync.
  Percentiles (p50/p99/p99.99/max/mean) by nearest-rank over the sorted one-way vector.
- **Throughput.** One writer blasts N samples as fast as `write()` returns; the reader counts delivery;
  report send samples/s, delivered samples/s, send Mbps.
- **Allocation (NFR-PERF-8 oracle).** `dds.pal:bytes-consed` delta over the measured loop / N — whole
  path, all threads, SBCL-exact (Clasp returns 0, a documented NFR-PORT gap).
- **Raw octet payloads, no type-support** — the harness sweeps payload SIZE via opaque octet vectors
  through `dds.disc:publish-sample`; endpoints match by topic+type name (the type gate is fail-open).
- **`run-bench`** prints a markdown report to stdout (captured into `bench/report/`); **`run-bench-smoke`**
  is a tiny suite-registered self-check (30 latency + 50 throughput round-trips; asserts full delivery +
  positive latency) so CI catches harness breakage without a long run.

## Why a baseline (not a target) now
The v1 data plane is explicitly NOT a measured hot path; it conses per sample. The harness reports the
CURRENT numbers honestly (`bench/report/2026-06-13-perftest-baseline.md`, at a STATED N): p50 ~113 µs at
N=5 000, ms-range tail (GC), ~2 900 samples/s. That IS the deliverable: the before-numbers the P4 WPs
move. No perf claim is made beyond "this is where we start."

## First finding (the harness earned its keep)
Latency and bytes/sample are **not steady-state — they grow O(N)** (N=2 000→44 KB/48 µs,
10 000→172 KB/187 µs). Root cause confirmed in source: the reliable engine retains O(history) — the
writer `HistoryCache` is KEEP_ALL and never purges on ack (history.lisp:25), and the reader
`writer-proxy.received` stores every payload by SN forever (reliable.lisp:166). The per-sample alloc
figure is therefore retention/rehash churn over a growing table, **not** a fixed per-sample cost, and
must be cited at a stated N. **Follow-up WP (data plane, not WP-PERFTEST):** purge writer history on
full-ACK + bound the reader received-table (KEEP_LAST / RESOURCE_LIMITS) for O(1)-per-sample steady state.

## Known limitations (later WP-PERFTEST increments)
- µs clock resolution (PAL `get-internal-real-time` scaled) → sub-µs percentiles need a higher-res PAL
  monotonic clock (`clock_gettime`/`mach_absolute_time` via CFFI). Separate enhancement.
- Disc-layer receive cache grows for the run (no take) → bound `samples × payload`; a take-based consumer
  is a follow-up.
- Connext-parity cross-run (RTI Perftest side-by-side on identical HW) turns these absolutes into the
  NFR-PERF "within Nx" ratio gates — the next increment.

## Tests / gates
`perftest-smoke` registered in the suite (green SBCL+Clasp). gate-types covers the new defuns
(all `defun*`); gate-hotpath unaffected (dds-bench is not a hot-path package).
