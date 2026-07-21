# ADR 0079 — the emitted datagram size is an INTEROP contract, and our defaults break it

- **Status:** PROPOSED — the finding is measured and reproducible; the remedy is an owner decision because it trades against a measured performance win
- **Date:** 2026-07-21
- **Requirements:** FR-IO (interop with Connext 7.x + one open-source DDS), NFR-PERF (the large-sample throughput win this collides with)
- **Relates to:** `cb08d62` (the 2 KB send-buffer ceiling lift, which raised these defaults), ADR 0016 (change coalescing), `interop/connext/large-data/README.md` (which recorded the original constraint)

## The finding

**Our shipped defaults make us unable to talk to a peer that bounds its receive size — and 0 samples get
through, silently.** Measured today against live RTI Connext 7.3.1, `LargeData`, 8000-octet payload:

| our `*fragment-size*` / `*max-datagram-bytes*` | Connext `large_sub` received |
|---|---|
| **63000 / 65507 (the shipped defaults)** | **0 samples** |
| 1024 / 65507 | 0 samples |
| 63000 / 1400 | 0 samples (and 6 buffer-overflow errors on our own send path) |
| **1024 / 1400** | **15 / 15, `payload-len=8000 pattern=OK`** |

Discovery is **not** the problem: our publisher reports `peers=1`, so the endpoints match. The data is
matched, sent, and dropped.

The peer is not misconfigured. `interop/connext/large-data/USER_QOS_PROFILES.xml` sets
`dds.transport.UDPv4.builtin.parent.message_size_max = 1400` — an ordinary, sensible choice: it keeps every
datagram inside the Ethernet MTU and avoids IP fragmentation. Our default emits a single ~8 KB datagram for
an 8 KB sample, which such a peer will not accept, and which on any real network must be IP-fragmented to
cross an MTU-1500 link.

**The two knobs are coupled and neither alone is sufficient.** `*fragment-size*` decides how a sample is cut
up; `*max-datagram-bytes*` decides how much the send path will then COALESCE back into one datagram
(ADR 0016 packs multiple submessages per datagram). Lowering only the fragment size leaves the fragments to
be re-packed into one oversized datagram; lowering only the datagram size leaves a 63000-octet fragment that
cannot fit the buffer at all. That coupling is already documented — "a sample rides unfragmented only if
BOTH admit it" — but its interop consequence was not.

## Why it regressed silently

`interop/connext/large-data/README.md` recorded the constraint at the time the leg was last run by hand:

> what must hold is that each side's emitted datagrams fit the peer's `message_size_max` (1400), which
> 1024 + RTPS overhead does.

`cb08d62` then raised `*fragment-size*` 1024 → 63000 and `*max-datagram-bytes*` to 65507 to win large-sample
throughput (4 KB 6.9×, 16 KB 4.4× — real, measured, and driven by an explicit owner directive). Those
numbers were measured on **loopback**, where an 8 KB datagram is free. Nothing re-ran the large-data interop
leg afterwards, **because that leg was never gated** — `make interop` covered the Shapes topic only, and
Shapes samples are far below any MTU.

This is the second time in this project that the un-gated half of interop hid a total matching/delivery
failure; the first was ADR 0057, where our `DataWriter` matched no foreign `DataReader` for six slices.

## Options

1. **Lower the defaults to MTU-safe values** (`*fragment-size*` ~1024–1400, `*max-datagram-bytes*` ~1400).
   Interoperable and MTU-safe out of the box; gives back the large-sample throughput win on loopback.
2. **Keep the defaults, document them as loopback/high-MTU tuned**, and require interop deployments to set
   both knobs. Keeps the win; leaves a stack that does not interoperate out of the box, which sits badly
   against FR-IO.
3. **Derive the bound from the path** (e.g. discover the peer's advertised locators' MTU, or default to
   1400 and raise it only for same-host/SHMEM destinations). Best of both, and the most work. Note RTPS
   carries no standard "max message size" in discovery, so this cannot be negotiated on the wire — it would
   have to be inferred (same-host vs off-host) or configured.

**Recommendation: option 3 with option 1 as the immediate default.** A stack whose out-of-the-box defaults
cannot exchange a large sample with a stock, MTU-configured Connext peer is not meeting FR-IO, and
"interoperates once you tune two specials" is not a defensible reading of it. The throughput win should be
recovered by raising the bound where it is known safe (same host), not by defaulting to a size the network
cannot carry.

**This is deliberately not decided here.** The defaults were set by a measured performance work-package
under an explicit owner directive; trading that away is the owner's call, not a silent revert.

## What was done now, regardless of the decision

- The finding is recorded here with the numbers to reproduce it.
- `make interop` gained both **outbound** legs for Shapes, which is what makes this class of defect
  catchable at all.
- The large-data leg is **still not gated**, and must be — with whichever defaults the decision lands on. It
  is the only leg that exercises DATA_FRAG / NACK_FRAG against a foreign stack, and it is the leg that would
  have caught this the day it regressed.
