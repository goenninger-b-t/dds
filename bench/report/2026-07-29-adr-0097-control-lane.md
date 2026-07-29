# ADR 0097 — reliability control traffic on the DATA's lane: before/after

**Date:** 2026-07-29 · **Platform:** Linux x86_64 (Ubuntu 24.04, SBCL 2.2.9.debian) under
`make linux-run` · **Requirement:** FR-XPORT-2 · **ADR:** 0097

## What was measured

One writer + one reliable reader, same host, `*shmem-enabled*` T, two bare `disc-node`s (no DCPS, no
`spin`, so nothing else emits). Publish **N = 400** samples as a burst — filling the SHMEM ring faster
than the reader drains it — then drive **N heartbeats**. Count every datagram **the writer** emits, from
every thread.

**FLOOR = 2N**: one DATA push and one HEARTBEAT per sample. Everything above the floor is a retransmit
the reader asked for, and with the reader whole and nothing dropped, **every one of those is spurious**.

## Result

| tree | writer datagrams | floor | excess | received |
|---|---|---|---|---|
| pre-ADR-0097 (HEARTBEAT + repair on UDP) | **2249** | 800 | **+1449 (+181 %)** | 400 / 400 |
| ADR 0097 (control traffic on the SHMEM lane) | **800** | 800 | **0** | 400 / 400 |

**2.81× the necessary traffic, entirely invisible.** Every sample arrived either way and no counter moved,
because a retransmit of a sample the reader is about to read is deduped on arrival: the delivery is
correct, the bandwidth is not.

## Why it happens

The SHMEM ring and the UDP socket are drained by **two different receiver threads**. A HEARTBEAT sent on
UDP announces `lastSN` to a reader whose SHMEM ring still holds most of those samples unread, so the
reader NACKs what it already has in hand, and the writer retransmits it. On the destination's own lane
the HEARTBEAT is queued *behind* the DATA it announces, so the reader has processed the samples before it
is asked to account for them.

## The measurement trap, recorded because it produced a false negative first

The first two runs of this harness reported **excess 0 in both arms** — a clean-looking negative that
would have justified not shipping the change at all. The counter was wrong: `*datagram-sink*` was
`let`-bound, and **the ACKNACK repair runs on the writer's RECEIVER thread**, which cannot see a
thread-local dynamic binding. It counted only the main thread's sends, i.e. exactly the floor, in every
configuration. Setting the sink with a global `setf` (and filtering on the RTPS header's `guidPrefix`,
octets 8..19, so the reader's ACKNACKs are not counted) is what made the 1449 visible.

A measurement that cannot see the thing it is measuring reports a clean result, not an error.

## Reproduce

```bash
make linux-image                       # once
make linux-run FORM='(dds.tests::run-shmem-control-lane-test)'
```

`run-shmem-control-lane-test` is the permanent gate: it asserts the invariant per call site (the periodic
HEARTBEAT, and the ACKNACK repair) against `disc-node-shmem-sends`, and goes RED on `CTL-LANE-HEARTBEAT`
with the ADR 0097 call sites reverted. The 400-sample traffic harness above is a one-off and is not
checked in; the numbers it produced are the table.
