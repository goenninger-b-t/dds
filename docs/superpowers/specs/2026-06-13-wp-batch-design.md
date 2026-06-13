# WP-BATCH — write-side sample batching — design

**Goal (FR-PF-1, NFR-PERF-4).** Amortize per-sample overhead for small samples by sending multiple
samples per packet, **size- and time-triggered**. Clean-room + wire-standard: each sample stays a normal
DATA submessage (RTPS 2.5 §9.4.5.4); batching just DEFERS the push so N accumulated samples flush
together — the existing coalescer (`%send-packed`) packs them into few datagrams with ONE trailing
HEARTBEAT, so the reliable handshake (HEARTBEAT/ACKNACK) is amortized over the batch. NO RTI-proprietary
"samples-in-one-DATA-payload" encapsulation (that needs a Connext capture to byte-validate — deferred,
"interop where applicable"). The READER is unchanged (it already accepts multi-DATA datagrams).

## Mechanism (disc layer, opt-in, default-off)
Today `publish-sample` calls `%push-data` on EVERY write → one datagram (DATA+HEARTBEAT) per sample.
Batching decouples write from push:
- `disc-node` gains `batch-max-samples` (default **1** = flush every write = current behaviour, zero
  risk) and a `batch-pending` counter.
- `publish-sample`: `writer-write` (accumulate in the HistoryCache), `incf batch-pending`; when
  `batch-pending >= batch-max-samples`, `%push-data` (sends ALL unsent changes — `writer-unsent-list` —
  coalesced) + reset the counter. The counter is a flush PACER; `%push-data` always sends whatever is
  unsent, so correctness never depends on the exact count.
- `flush-batch(node)`: force a `%push-data` + reset if `batch-pending > 0` — the TIME trigger. Called
  (a) on the periodic announce cadence (`announce-endpoints`, so a partial batch is never stranded
  beyond the cadence) and (b) by `stop-node` (drain on shutdown). A finer configurable batch-delay timer
  is a follow-up; the cadence flush bounds staleness.
- Lifecycle (dispose/unregister) FLUSHES the pending batch first (ordering: a dispose must not overtake
  batched data), then pushes immediately — lifecycle changes are not batch-delayed.

## Why this is the right scope
The throughput win is real and standard: 20 000 small writes with `batch-max-samples=100` → ~200
datagrams (100 DATA + 1 HEARTBEAT each) instead of 20 000 (1 DATA + 1 HEARTBEAT each) — ~100× fewer
syscalls + one ACKNACK cycle per 100 samples. Latency trade-off: a batched sample waits up to the
batch-fill/cadence, so batching is for THROUGHPUT (NFR-PERF-4), off by default for latency.

## Bench (FR-LANG-7)
Extend `dds-bench`: `run-throughput :batch N` sets the writer's `batch-max-samples`, blasts, `flush-batch`,
measures samples/s. Report unbatched vs batched (expect a multiple-× throughput gain). Reader still
receives all samples (reliable).

## Tests (TDD)
- `dcps-batch` / disc-level: with `batch-max-samples=5`, 4 writes do NOT push (datagrams captured via
  `*datagram-sink*` = 0 user-DATA), the 5th flushes all 5 in one cadence; `flush-batch` flushes a partial
  batch; a dispose flushes the pending batch first. Reader receives every sample.
- Regression: default `batch-max-samples=1` → every existing test unchanged (flush-per-write).

## Out of scope
RTI-proprietary batch wire format (samples in one DATA payload) — needs a Connext capture (deferred);
a fine-grained configurable batch-delay timer thread (cadence flush suffices now); recvmmsg/sendmmsg
syscall batching (FR-XPORT-6, separate).
