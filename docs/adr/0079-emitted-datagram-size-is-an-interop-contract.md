# ADR 0079 — the emitted datagram size is an INTEROP contract: a fixed MTU-safe fragment size, and per-transport packing

- **Status:** ACCEPTED and LANDED — both defects fixed. Owner decision on A taken 2026-07-22: interoperate across platforms and machines with both vendors; the same-host cost is accepted and is recoverable per §8.4.14.1 (see Consequences)
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

## Decision taken on A (owner, 2026-07-22): option 1

`*fragment-size*` 63000 -> **1024**, fixed per writer, MTU-derived. The derivation is in the special's own
docstring: one fragment costs 56 octets of framing (20 RTPS header + 4 submessage header + 32 DATA_FRAG
fields), an Ethernet path carries 1472, so the ceiling is 1416 and `*coalesce-datagram-budget*` (1400)
tightens it to 1344; 1024 sits under that with headroom for IPv6, VLAN tags, tunnelled paths, and the
DDS-Security SEC_PREFIX/POSTFIX wrapping.

### The options as they stood

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

## Consequences — measured, both directions, both vendors, and across machines

**Interop (the reason for the change).** Live, 8000-octet `LargeData`, `pattern=OK` verified octet-by-octet:

| leg | at 63000 (old) | at 1024 (new) |
|---|---|---|
| same host, us -> Connext | **0** | 14 |
| same host, Connext -> us | 15 | 20 |
| **cross machine**, Linux -> Connext (Mac), real Ethernet | **0** | **14** |

The cross-machine pair is the decisive one: identical setup, publisher discovers the peer (`peers=1`) and
sends 20 in both arms, and the only variable is the fragment size. Also proven cross-machine: ours (Linux)
-> ours (Mac) 13/16 `pattern=OK`, and ours (Linux) -> Fast DDS (Mac) 258 samples with 258 ACKNACKs.

**Performance (the cost, stated plainly).** Round-trip p50, same host, 4 KB payload:

| path | 63000 | 1024 |
|---|---|---|
| SHMEM available | **10.0 us** | 84.0 us |
| UDP only | 27.0 us | 69.1 us |

So ~2.7x is losing the SHMEM path and ~2.6x is genuine fragmentation overhead. **This is a real same-host
regression and it is not hidden.** Two things put it in proportion: the 27 us at 63000 is a *loopback*
number — on a 1500-MTU path a 4 KB datagram is IP-fragmented anyway, which is strictly worse (whole-datagram
loss on any fragment loss, no selective repair) — and a stack that cannot exchange a large sample with a
stock MTU-configured peer is not meeting FR-IO at any latency.

**The recovery path is the spec's, and it is now IMPLEMENTED.** §8.4.14.1: *"If multiple transports are
available to the Writer and some transports do not require fragmentation, a regular Data Submessage **must**
be sent on those transports instead."* A sample larger than `*fragment-size*` used to take a UDP-only
fragmented path unconditionally (`%sample-plan`, "large samples: UDP only (v1)"), so a 4 KB sample stopped
using shared memory at all. `%unfragmented-to-dest-p` now lets a change ride WHOLE, as one `Data`
submessage, to a destination reached over SHMEM — the fragment SIZE stays the per-writer constant the spec
requires; what varies per destination is whether fragmentation is needed at all.

It is safe because of what a SHMEM destination *is*: `%shmem-dest` resolves one only for a peer identified
as same-host through our own vendor host-UUID parameter — i.e. another node of this stack, on this machine.
A whole-sample datagram taken on that arm can never reach a foreign peer and never leaves the box, and its
one degradation path is benign (a SHMEM send that cannot proceed falls back to UDP at the same host, which
is loopback). A cross-host destination has no SHMEM dest and keeps fragmenting — which is what keeps the
wire MTU-safe.

**Measured, same host, round-trip p50:**

| payload | 63000 (pre-ADR) | 1024 alone | 1024 + the MUST |
|---|---|---|---|
| 4 KB | 10.0 us | 84.0 us | **9.0 us** |
| 16 KB | — | 192.6 us | **13.1 us** |

So the interop fix costs nothing same-host once the MUST is honoured — 4 KB is marginally *better* than the
pre-ADR default, and 16 KB is far better. Gated by `run-unfragmented-to-shmem-dest-test`, which asserts the
PLAN (the wiring), not the predicate: the same over-size change must produce a multi-datagram fragmented
plan for a UDP destination and exactly ONE datagram, carrying the SHMEM destination, for a SHMEM one.
Falsified — removing the wiring makes the SHMEM arm produce 9 datagrams and the test goes red.

## Regardless of the decision

- Defect B is fixed here; 574/574 both impls, gate-build/hotpath/types/nocond/corpus green.
- `make interop` gained both **outbound** Shapes legs, which is what makes this class catchable at all.
- **The large-data leg is now GATED**, both directions, in `make interop` (legs 5 and 6). FALSIFIED: with
  `*fragment-size*` back at 63000 the outbound leg reports `only 0 verified sample(s)` and the gate goes RED.
  Fragmentation against **Fast DDS remains untested** — there is no Fast DDS `LargeData` peer, and the gate
  says so on every run.
