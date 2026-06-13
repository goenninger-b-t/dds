# Send-side submessage coalescing (change coalescing) — design

**Goal (owner-scoped 2026-06-13):** Cut the writer's datagram / `sendto` count by packing multiple DATA
submessages plus the trailing HEARTBEAT into ONE UDP datagram (RTPS 2.5 §8.3.4: a Message is a Header
followed by a sequence of Submessages). Metric (FR-LANG-7): **datagrams sent (≈ sendto syscalls)**.

Today every publish sends TWO datagrams — a DATA then a separate HEARTBEAT (`%push-data` calls
`%send-change` then `%send-user-heartbeat`, each its own `%send-msg-buf` → `dds.xport:send`). An
ACKNACK-driven retransmit of K changes sends K separate datagrams. The receiver already accepts
multi-submessage datagrams: `dispatch-message` (message.lisp:787) loops over every submessage to the
datagram boundary — so this is a pure SEND-side change, wire-safe, no reader-side change, no wire-format
invention.

## Scope (owner: "Pack DATA+HEARTBEAT per datagram")
- Coalesce **non-fragmented DATA** (payload ≤ `*fragment-size*`) and **dispose/unregister DATA**
  (no-payload, 56 octets) plus the **trailing HEARTBEAT** in `%push-data`, and the **resent DATA** in
  `%on-user-acknack`.
- Leave **DATA_FRAG** (large samples) untouched — `%send-sample` already emits one datagram per
  fragment group sized by `writer-frag-plan`; packing those would defeat the fragment-size discipline.
- Out of scope: DDS-level sample batching (one batched DATA payload, RTI-proprietary encapsulation).

## Mechanism — a generic submessage packer
`%send-packed(node, buf, host, port, builders)`: each builder is a `(lambda (cursor))` that writes ONE
submessage. Write the RTPS Header once; append each submessage; before a submessage that would push the
datagram past the budget (and the datagram already holds ≥1 submessage), FLUSH `buf[0..before]` via the
factored-out `%send-raw-buf`, then move the just-written submessage down behind the still-intact header
(`cl:replace` on the buffer vec, dest < src so the forward copy is safe) and continue. Final flush sends
the remainder. The header at `[0, hdr-end)` is never overwritten, so it is reused verbatim for each
datagram (the GUID prefix / version / vendor are constant per node).

Budget = `min(*coalesce-datagram-budget*, capacity - 64)`. `*coalesce-datagram-budget*` defaults to
**1400** — keeps a UDP datagram under the common Ethernet path MTU (1500 − 20 IP − 8 UDP = 1472) so the
coalesced datagram is not IP-fragmented (the real reliability/perf hazard). Small samples (ShapeType
~40 B) pack dozens per datagram; a single submessage larger than the budget can only be the first in a
datagram (guard `before > hdr-end` is false) and is sent alone, exactly as today.

## Builders + shared push helper (DRY)
- `%data-builder(node, ch)` → a closure writing CH's small DATA (`write-data`, D-flag, no inlineQos —
  byte-identical to `%send-sample`'s small branch) or dispose/unregister DATA (`write-data-dispose`).
- `%heartbeat-builder(node, first, last, count)` → a closure writing the non-final HEARTBEAT (`:final
  nil`), mirroring `%send-user-heartbeat`.
- `%small-change-p(ch)` → T for a no-payload lifecycle change or a data payload ≤ `*fragment-size*`.
- `%send-changes-packed(node, buf, changes, host, port, hb)`: collect a builder per SMALL change
  (skipping a SN in `*debug-drop-sample-numbers*` — loss injection preserved), send each LARGE change
  individually via `%send-sample`, append the optional HEARTBEAT builder HB, then `%send-packed`.
  `%push-data` calls it with the HB builder; `%on-user-acknack` with HB nil (a retransmit sends no
  HEARTBEAT today). The now-unused `%send-change` is removed (its data/lifecycle dispatch is
  `%data-builder` + `%small-change-p`).

## Test affordance (no production cost)
`*datagram-sink*` (default NIL): when bound to a function, `%send-raw-buf` hands it a fresh octet copy of
each outgoing datagram (then still sends). A test binds it to capture every coalesced datagram, runs
`dispatch-message` over each to assert (a) the total submessage count is preserved, (b) DATA precedes its
HEARTBEAT, (c) each datagram ≤ budget, and (d) the datagram COUNT dropped vs one-per-submessage.

## Tests
- `coalesce-pack`: a writer with one matched reader; write N=10 small samples; `%push-data` under
  `*datagram-sink*`. Assert ONE datagram captured carrying 10 DATA + 1 HEARTBEAT (11 submessages,
  parsed back via `dispatch-message`), ≤ budget; vs 11 datagrams pre-coalescing.
- `coalesce-split`: lower `*coalesce-datagram-budget*` so the same burst needs ≥2 datagrams; assert the
  submessage total is preserved across datagrams and each datagram ≤ budget (the flush/move path).
- Regression: ALL UDP-loopback dataplane tests (reliable-data-over-udp, large-data-over-udp,
  lost-final-sample-repair, dispose-over-udp, dispose-reliable-repair) green — DATA+HEARTBEAT in one
  datagram is standard RTPS and `dispatch-message` already handles it; the lost-final-sample drop hook
  still skips the DATA while the HEARTBEAT still advertises the gap.

## Bench (FR-LANG-7)
`bench/report/2026-06-13-change-coalescing.md`, datagram count: steady-state publish 2→1 (2×); a
K-change push N+1→ceil(bytes/budget) (≈1 for small samples); ACKNACK retransmit of K → ceil(bytes/budget).
Measured via `*datagram-sink*` list length; before stated analytically (= submessage count, since the
old path was one datagram per submessage).

## Conformance / interop
A DATA followed by a HEARTBEAT in one Message is ordinary RTPS writer behaviour (Connext / Fast DDS emit
multi-submessage messages routinely). No PID, EntityId, or encapsulation constant changes. The shared
header is the unmodified §9.4.4 RTPS Header. Hot-path purity unaffected (this file is the non-measured
L5/L6 bridge; `%send-packed` conses a builder list on the send path, as the prior path consed lambdas).
