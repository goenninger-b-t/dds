# ADR 0079 — the emitted datagram size is an INTEROP contract: a fixed MTU-safe fragment size, and per-transport packing

- **Status:** PARTIALLY LANDED — defect B (the fragment packing budget) is FIXED here; defect A (the `*fragment-size*` default) is an owner decision because it trades against a measured performance win
- **Date:** 2026-07-21 (revised 2026-07-22 against the RTPS 2.5 spec text)
- **Requirements:** FR-IO (interop with Connext 7.x + one open-source DDS), NFR-PERF (the large-sample throughput win this collides with)
- **Spec:** DDSI-RTPS 2.5 §8.4.14.1 (Large Data), §8.3.8.3 (DataFrag) — read from `docs/specs/rtps-2_5.pdf`, quoted below
- **Relates to:** `cb08d62` (the 2 KB ceiling lift, which raised these defaults), ADR 0016 (change coalescing), `interop/connext/large-data/README.md`

## What the spec actually requires

**RTPS 2.5 §8.4.14.1, "How to select the fragment size"** — three normative requirements:

> - "All transports available to the Writer must be able to accommodate DataFrag Submessages containing at
>   least one fragment. This means **the transport with the smallest maximum message size determines the
>   fragment size**."
> - "**The fragment size must be fixed for a given Writer and is identical for all remote Readers.** By fixing
>   the fragment size, the data a fragment number refers to does not depend on a particular remote Reader.
>   This simplifies processing negative acknowledgements (NackFrag) from a Reader."
> - "The fragment size must satisfy: fragment size <= 65536 bytes."

and, directly on the question of adapting to newly discovered peers:

> "Note the fragment size is determined by all transports available to the Writer, **not simply the subset of
> transports required to reach all currently known Readers**. This ensures **newly discovered Readers**,
> regardless of the transport they can be reached on, can be accommodated **without having to change the
> fragment size, which would violate the above requirements**."

**So a per-peer or dynamically re-negotiated fragment size is forbidden**, and the spec anticipated exactly
that design and ruled it out by name. The reason is not conformance pedantry: fragment numbers are the wire
identity of byte ranges (reassembly offset is `(fragmentStartingNum - 1) * fragmentSize`), so a `NackFrag`
naming fragment 3 must mean the same bytes to every reader, and changing the size mid-stream would
invalidate the numbering of every un-acked sample in flight.

**There is also no wire input for such a negotiation.** RTPS discovery carries *locators* — address, port,
kind — not capacities. The only `PID_TRANSPORT*` in the spec is `PID_TRANSPORT_PRIORITY` (0x0049), the
unrelated DDS scheduling QoS. A peer's `message_size_max` is invisible to us; the spec deliberately frames
the bound as *the writer's own transports*.

**What the spec does endorse is per-transport adaptation one layer up — at packing:**

> §8.3.8.3: "If some RTPS Readers can be reached across a transport that supports larger messages, the RTPS
> Writer can pack multiple fragments into a single DataFrag Submessage or may even send a regular Data
> Submessage if fragmentation is no longer required."
>
> §8.4.14.1: "Data must only be fragmented if required. If multiple transports are available to the Writer
> and some transports do not require fragmentation, a regular Data Submessage **must** be sent on those
> transports instead."
>
> §8.4.14.1: "**If a transport can accommodate** multiple fragments of the given fragment size, it is
> recommended that implementations concatenate as many fragments as possible into a single DataFrag message."

**Fragment size: fixed, small, MTU-safe. Throughput: recovered per transport, by packing.**

## The two defects this found

Measured live against RTI Connext 7.3.1, `LargeData`, 8000-octet payload. The peer is not misconfigured —
its transport sets `message_size_max = 1400`, an ordinary MTU-sized choice.

### Defect B — the fragment packing budget ignored the transport (FIXED HERE)

`%send-changes-packed` computes `budget = (%pack-budget buf)` = `min(*coalesce-datagram-budget* 1400,
capacity-64)`, uses it for small submessages, and then passed **`(- capacity 64)` = 65443** to
`%sample-plan` for the DATA_FRAG series. Its own docstring says "BUF supplies only the packing budget
(%pack-budget)" — the fragment path simply did not honour it.

The effect is self-defeating: we cut a sample into MTU-sized fragments and then **re-assembled them into one
~8 KB datagram**, which an MTU-bounded peer discards. It implements the spec's "concatenate as many
fragments as possible" while dropping the condition it hangs on — *"if a transport can accommodate"*.

**Fixed:** pass the same `budget`. Measured: 0 samples received before, **13/16 `pattern=OK` after**, with
`*max-datagram-bytes*` untouched at its 65507 default. This is nearly a no-op at our current defaults (with
`*fragment-size*` = 63000 the fragment branch only runs above 63000 octets), which is exactly why it went
unnoticed — and it means `*max-datagram-bytes*` is a *buffer size*, not a wire policy, and is now irrelevant
to interop.

### Defect A — the `*fragment-size*` default is not the minimum across our transports (OWNER DECISION)

`*fragment-size*` = 63000 means an 8000-octet sample is **never fragmented at all**: it becomes one 8 KB
`Data` submessage, sent alone in one 8 KB datagram. The coalescing budget cannot help — by design "a single
submessage larger than the budget is still sent (alone in its datagram), never truncated".

Against §8.4.14.1 requirement 1, 63000 is only defensible if every transport available to the writer can
carry a 63000-octet message. That is true for loopback and SHMEM; it is **not** true for a UDPv4 path across
an MTU-1500 link, which additionally forces IP fragmentation — the failure mode the `*coalesce-datagram-budget*`
docstring already calls "the real hazard of over-large datagrams".

| our fragment-size / max-datagram | Connext receives |
|---|---|
| **63000 / 65507 (shipped defaults)** | **0 samples** |
| 1024 / 65507, **with defect B fixed** | **13/16 `pattern=OK`** |
| 1024 / 1400 (pre-fix workaround) | 15/15 `pattern=OK` |

Discovery is not implicated: our publisher reports `peers=1`. The data is matched, sent, and dropped.

## Why it regressed silently

`interop/connext/large-data/README.md` had recorded the constraint: *"what must hold is that each side's
emitted datagrams fit the peer's message_size_max (1400), which 1024 + RTPS overhead does."* `cb08d62` then
raised `*fragment-size*` 1024 → 63000 to win large-sample throughput (4 KB 6.9×, 16 KB 4.4×) — real,
measured, owner-directed, and measured **on loopback**, where an 8 KB datagram is free and where SHMEM is
the transport anyway. Nothing re-ran the large-data interop leg, **because that leg was never gated**:
`make interop` covered the Shapes topic only, whose samples sit far below any MTU.

Second time the un-gated half of interop hid a total delivery failure; the first was ADR 0057.

## Decision needed on A

1. **Set `*fragment-size*` MTU-safe (~1024–1400) and recover throughput per transport.** Conformant reading
   of §8.4.14.1: fixed size = min across the writer's transports; then let SHMEM/loopback concatenate many
   fragments per DataFrag (now that defect B honours the per-transport budget), and send a plain `Data` when
   that transport needs no fragmentation — which §8.4.14.1 makes a **MUST**, and which we do not do today.
   The `cb08d62` wins were same-host, so they live precisely where this puts them.
2. **Keep 63000 and document the stack as high-MTU/loopback-tuned.** Keeps the number without work; leaves a
   stack that does not interoperate out of the box, which reads badly against FR-IO.
3. **Make the bound per-destination-transport.** Effectively option 1 done properly, since the "fixed size"
   requirement forbids varying the *fragment* size — the variation belongs in packing and in the
   plain-`Data`-when-unfragmented rule.

**Recommendation: option 1, growing into option 3.** A fixed MTU-safe fragment size is what the spec asks
for, and it is the only value that is correct for a writer whose transports include off-host UDPv4. The
throughput should come back through per-transport packing, not through a fragment size the network cannot
carry. **Not taken unilaterally**: the defaults came from a measured performance work-package under an
explicit owner directive.

## Regardless of the decision

- Defect B is fixed here; 574/574 both impls, gate-build/hotpath/types/nocond/corpus green.
- `make interop` gained both **outbound** Shapes legs, which is what makes this class catchable at all.
- **The large-data leg must be gated** once A is decided. It is the only DATA_FRAG / NACK_FRAG leg against a
  foreign stack, and it would have caught this the day it regressed.
