# WP-ASYNC — asynchronous publication (decoupled sender thread) — design

**Goal (FR-PF-2).** Decouple the network send from `write()`: a single background SENDER thread does the
push so `publish-sample` returns without blocking on the socket. Opt-in, default-off (the synchronous
path is unchanged). Conservative, lock+condvar (NOT lock-free) design — stability is a binary gate.

**Scope (v1):** the decoupled sender thread only. **Flow control / token-bucket rate shaping is a
documented follow-up** (WP-ASYNC-FLOW) — it adds a pace-sleep that must interact safely with shutdown,
which is the riskier half; keeping it out of v1 minimizes the concurrency surface.

## Mechanism
The reliable engine's unsent-list IS the queue — the sender flushes ALL unsent on each wake (so a burst
of writes between wakes coalesces adaptively; no per-sample queue needed).
- `disc-node` async slots: `async-thread` (nil = off), `async-lock`, `async-cv`, `async-pending` (work
  to flush), `async-stop` (shutdown), `async-tx-msg` (the sender's OWN scratch buffer — the app-thread
  announce path keeps `tx-msg`, the receiver keeps `rx-tx-msg`, so no buffer is shared across threads).
- `enable-async(node)`: allocate `async-tx-msg`, spawn the sender thread.
- Sender loop: under `async-lock`, `condvar-wait` (0.5 s timeout) until `async-stop` or `async-pending`;
  capture stop, clear pending, RELEASE the lock; `%push-data-buf node async-tx-msg` (flush, sender
  buffer); if stop, return. The lock is never held across the send (which takes the writer lock), so no
  nested-lock deadlock; the 0.5 s timeout means a missed signal cannot wedge shutdown.
- `publish-sample` / `%dispose-or-unregister` (async mode): `writer-write`/`writer-lifecycle-change`
  then signal (`async-pending = t` + `condvar-signal`) instead of pushing inline — write returns
  immediately. A dispose still takes a higher SN than pending data, and the sender flushes all unsent in
  SN order, so ordering holds. Async supersedes the batch-size policy (the sender's flush-all IS
  adaptive batching); `flush-batch` is a no-op signal in async mode.
- `stop-node` (async mode): set `async-stop`, signal, `join` the sender (it drains a final flush + exits)
  BEFORE closing the socket — same ordering rule as the existing receiver-thread join.

## Thread-safety
Three threads, three buffers: app (`tx-msg`, announce), sender (`async-tx-msg`, user data), receiver
(`rx-tx-msg`, ACKNACK/retransmit). The reliable writer's own lock already serializes HC/proxy access
across the app `writer-write` and the sender `writer-unsent-list`. `async-pending`/`async-stop` are
guarded by `async-lock`. The sender holds no lock during the send. `on-sample` (receiver thread) calling
`publish-sample` in async mode only signals — safe.

## %push-data-buf
`%push-data` is parameterized: `%push-data` = `%push-data-buf node (disc-node-tx-msg node)`; the sender
passes `async-tx-msg`. Pure refactor, no behaviour change for the synchronous path.

## Tests (TDD)
- `async-decoupled` (disc-level, *datagram-sink*): with async enabled + a matched reader, N publishes
  eventually produce N DATA on the sender thread (poll until the sink has them); `stop-node` drains a
  final pending batch; received count == sent. Reader receives every sample (reliability preserved).
- Regression: async off (default) → every existing test unchanged; the live Fast DDS round-trip stays
  299/300 with async enabled on our publisher.

## Out of scope (follow-ups)
Token-bucket / rate-shaped flow control (WP-ASYNC-FLOW); DATA_FRAG fragment pacing (WP-FRAGPACE, builds
on the flow controller); multiple sender threads / priority lanes.
