# ADR 0080 — anything that MATCHES must be ADDRESSABLE; a refusal is a reported status, not a log line

- **Status:** Accepted
- **Date:** 2026-07-22
- **Requirements:** FR-IO, FR-DISC, NFR-OBS; DDS 1.4 §2.2.4.1 (communication statuses)
- **Spec:** DDSI-RTPS 2.5 §7.5 / Clause 9 (UDP/IP is the one transport PSM every implementation must support, and the only one defined), §7.6 (transport model)
- **Owner directive:** 2026-07-22 — "Make matched-but-unaddressable an impossible situation: anything that matches MUST be addressable — if not, this is an ERROR that must be announced."

## The problem

A remote endpoint could be topic/type/QoS compatible, be recorded as MATCHED, be reported through
`matched_count` — and then never receive a single sample, silently, forever.

That happens when the remote's participant advertises no user-data locator this implementation can send to.
`%reader-push-targets` forms a send group only when `%usable-destination` yields a routable UDPv4
`(host . port)`; three sites gated on that with no else branch, no counter, no log. The SHMEM destination is
resolved *from* that group, so such a peer got nothing over shared memory either.

It is reachable in practice. RTI Connext supports `transport_builtin` `mask = SHMEM` (`DDS_TRANSPORTBUILTIN_SHMEM`,
with `MASK_DEFAULT = UDPv4 | SHMEM`), and its shared-memory locator carries a vendor kind
(`NDDS_TRANSPORT_CLASSID_SHMEM = 0x01000000`). RTPS 2.5 reserves only `INVALID/RESERVED/UDPv4/UDPv6`, so
every shared-memory locator kind is vendor-defined — ours included (`+locator-kind-shmem+` = `#x47420001`).
A peer doing metatraffic over UDP but user data over SHMEM only is discovered, matched, and unreachable.

This is the third instance of one failure family in this project: ADR 0057 (matched, never delivered — six
slices), ADR 0079 (sent, silently dropped). The common factor is a failure that reports success.

## Decision

**1. Refuse the match.** A new `%consult-addressable-gate` sits alongside the type / auth / permissions gates
in `%match-remote-endpoint` and is consulted *first* — there is no point deciding a peer is type-compatible
if no datagram can ever reach it. `:unaddressable` announces and parks; the match is never recorded.

The gate's predicate is deliberately **the same one the send path uses** (`%usable-destination`). That is
what makes it safe: *addressable* here is by construction identical to *would-have-formed-a-send-group*
there, so no peer that works today changes behaviour — only peers we could never have delivered to.

**UNKNOWN IS NOT UNADDRESSABLE.** If the participant's SPDP has not arrived yet (SEDP can precede it), the
gate returns `:compatible`. Refusing on absence would make matching depend on discovery ORDER, which is
fragile and is not what the directive is about. We refuse only on positive knowledge.

**2. Report it as a real status, not a log line.** The disc layer raises `ON-UNADDRESSABLE` exactly as it
raises `ON-INCONSISTENT-TOPIC` / `ON-INCOMPATIBLE-QOS`; DCPS turns it into a communication status through
the same `%notify-status` chokepoint every other status uses: status bitmask bit, StatusCondition (so a
WaitSet wakes), delivery to the most-specific enabled listener, and a `get-unaddressable-peer-status`
snapshot carrying `total_count`, the refused GUID, and the locator kinds the peer *did* offer — which is
what tells an operator what to change.

`UNADDRESSABLE_PEER` is a **vendor extension**: DDS 1.4 defines no status for this. Its bit is placed at 24,
far above the OMG range (bits 0–14, `dds_rtf2_dcps.idl` §80-92), so a future standard StatusKind cannot
collide. It is participant-scoped, because the condition is a property of a remote *participant* rather than
of any one local endpoint — so the participant gains the status lock that DDS otherwise gives only to
Topic/DataReader/DataWriter.

**A print was written first and rejected** (owner, mid-implementation). A printed line is unconsumable by an
application, untestable by a caller, and invisible in a service. A signalled condition is equally wrong here:
ADR 0064 forbids conditions in production, and this runs on a receiver thread where a `handler-bind` could
turn the warning into a non-local exit that swallowed a discovery datagram. The status machinery is the only
mechanism that is both consumable and non-unwinding.

## Consequences

- A peer that cannot be addressed is no longer counted in `matched_count`. That is the point: the count now
  means what applications assume it means.
- The condition is observable three ways: the DDS status (`get-unaddressable-peer-status`, StatusCondition,
  listener), the disc-level `disc-node-unaddressable-count`, and the `disc-node-on-unaddressable` hook for
  embedders that bypass DCPS.
- Announced ONCE per remote GUID. SEDP re-announces indefinitely; an un-deduped announcement becomes a flood
  that operators filter, which is the same as silence.
- The match is PARKED, not discarded, so a peer that later advertises a usable locator matches normally on
  re-announce (`resume-parked-matches`).
- All seven live interop legs unchanged (Connext and Fast DDS, both directions, Shapes and large-data), which
  is the evidence that no working peer was affected.

## What this does NOT do

It does not make a SHMEM-only peer reachable. It cannot: RTPS 2.5 §7.5 defines exactly one transport PSM
(UDP/IP, Clause 9) and mandates it of every implementation; every shared-memory transport is vendor-private
in its locator kind, segment layout and synchronisation. Interoperating with RTI over shared memory would
mean implementing their proprietary transport, for which no OMG specification exists and which the
clean-room rule forbids reverse-engineering from their source or headers. A peer that advertises only a
vendor transport has opted out of the standard's interoperability guarantee; the honest response is a loud,
queryable refusal — which is what this ADR delivers.
