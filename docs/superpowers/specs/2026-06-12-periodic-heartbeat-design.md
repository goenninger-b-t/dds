# Periodic standalone HEARTBEAT — design

**Goal:** Close the reliability edge left by the send-once writer change: a reliable writer that
wrote a sample whose DATA was lost, with no subsequent write, currently has nothing to prompt the
reader to NACK — so the sample is never repaired. Send a periodic standalone HEARTBEAT on the
announce cadence so the reader NACKs any gap and the existing ACKNACK repair recovers it.

## Background

`%push-data` (`src/dds-disc/dataplane.lisp`) sends each new sample once + a HEARTBEAT, and is
called only by `publish-sample` (on write). There is no other HEARTBEAT source. So between/after
writes the writer is silent — a lost final sample (or a late-joiner's backlog with no new writes)
is never repaired until the next write. RTPS 2.5 §8.4.2.2: a reliable StatefulWriter sends
periodic HEARTBEATs (the heartbeat period) precisely to keep reliability live without new data.

The repair path itself (`%on-user-acknack` → `writer-on-acknack`, bitmap-selective) already works;
this change only adds the periodic *prompt*.

## Design

**`%push-heartbeat node`** (new, `dataplane.lisp`): send a standalone non-final HEARTBEAT (no DATA)
advertising the writer's full available range `[firstSN, lastSN]` (`writer-heartbeat`) to each
matched reader (`%match-destinations node t`). Guards: no-op when the node has no user writer, when
the history is empty (`lastSN < firstSN`), or when there are no matched readers. Non-final so the
reader answers with an ACKNACK (positive if complete → no resend; negative → repair). DRY: factor
the `write-heartbeat` emission shared with `%push-data` into a private
`%send-user-heartbeat node buf first last count host port`.

**Wire into the cadence:** call `(%push-heartbeat node)` in `announce-endpoints`
(`src/dds-disc/disc.lisp`) beside `tl-sweep` / `%lease-sweep` / `%liveliness-sweep`, before the
trailing `t`. This is the same ~1.5 s cadence that drives SPDP/SEDP re-announce and liveliness
assertion — control plane, not a per-sample hot path (no bench required; it adds one HEARTBEAT per
matched reader per cadence + the readers' ACKNACK responses).

**Test affordance:** add `*debug-drop-sample-numbers*` (a list of SNs to drop on send, mirroring the
existing `*debug-drop-fragment-numbers*`) in `dataplane.lisp`, checked in `%send-sample`/the DATA
send path — so a test can simulate a lost non-fragmented sample.

## Test (the faithful proof)

Extend the two-node UDP-loopback dataplane test (`dds.disc:run-dataplane-test` /
`reliable-data-over-udp`): node A (writer) + node B (reader) discover + match; A writes sample 1
with `*debug-drop-sample-numbers* = (1)` so B never receives the DATA; clear the drop; A does NOT
write again; run A's `announce-endpoints` (the periodic HEARTBEAT); B NACKs SN 1, A's
`%on-user-acknack` resends, B receives sample 1. Assert B got it. Without the periodic HEARTBEAT
this hangs/fails (the pre-change behaviour). Keep it deterministic (drive the announce/receive
loop a bounded number of iterations, not a wall-clock sleep).

## Out of scope

A configurable heartbeat-period timer decoupled from the announce cadence (v1 reuses the announce
cadence, as liveliness assertion does); per-reader heartbeat suppression when all readers are
fully acked (a valid optimisation, but the positive-ACKNACK-no-resend path already makes the
steady-state cost just one HB + one ACK per reader per cadence).
