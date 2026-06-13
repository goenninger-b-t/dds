# User data-plane send addressing — datagram-count bench

Date: 2026-06-13
Requirement: FR-RTPS-PUSHONCE extension (RTPS 2.5 §8.4.2.2 push / §9.4.4 source addressing), FR-LANG-7
Scope: reliable user-data writer ACKNACK-repair + push paths (src/dds-disc/dataplane.lisp)

## Commit A — ACKNACK retransmit to the NACKing reader only

### The change
`%on-user-acknack` retransmitted each NACKed change to `(%match-destinations node t)` — EVERY matched
reader destination — though an ACKNACK originates from exactly one reader (RTPS 2.5 §9.4.4: its
participant prefix is the datagram's RTPS-header `src-prefix`). The resend is now addressed to that one
participant's resolved destination (`%prefix-user-destination`), falling back to the full set only when
the prefix is undiscovered (the discovery-less unit-test path).

### Measurement method
Analytic datagram count + the offline `acknack-addressing` test, which asserts the fan-out breadth is 2
matched readers while the targeted resolution selects exactly the originating one (a 2→1 narrowing).
With R matched readers and a NACK requesting K changes:

### Result (resend DATA submessages per ACKNACK)

| path  | resends emitted | R=3, K=10 |
| ----- | --------------- | --------- |
| before (`%match-destinations`) | R · K | 30 |
| after  (single-destination)    | K     | 10 |

R-fold reduction (here 3×); idempotent at the reader under KEEP_ALL so correctness is unchanged — the
saving is pure wire traffic. Single-reader common case: R=1, unchanged (10→10).

### Gates
139 tests pass on SBCL and Clasp (was 138; +`acknack-addressing`). gate-types PASS (912 ftype'd
defuns). gate-hotpath PASS (5 hot-path files clean).

## Commit B — per-destination push grouping + union-send-once

### The change
`%reader-push-targets` deduped push targets by destination (`pushnew :key #'cdr`), so for two
DataReaders in ONE remote participant only ONE reader's GUID became the push key — its `unsent-base`
advanced; the other was deduped out and its watermark stayed stale (its send-once "degraded" to
ACKNACK-repair). It is now restructured into per-destination groups carrying EVERY co-located reader
GUID; `%merge-unsent` calls `writer-unsent-list` for each (advancing each watermark) and sends the
SN-deduplicated union to the destination ONCE.

### Measurement method
Offline `colocated-push` test: two reader endpoints sharing one participant prefix/destination; assert
one group with both GUIDs, and that after the first push BOTH `unsent-base` watermarks advanced (each
`writer-unsent-list` empty) and a second write pushes ONLY the new SN (no history re-push).

### Result (DATA submessages per push cycle to a destination shared by R co-located readers)

| metric | before (dedup-to-one) | after (group + union-send-once) |
| ------ | --------------------- | ------------------------------- |
| datagrams per change per destination | 1 | 1 (unchanged — readerId UNKNOWN fans out) |
| co-located readers with send-once accounting | 1 of R | R of R |
| history re-push on next write | 0 (2nd reader never a push target) | 0 (both watermarks advanced) |

No extra datagrams: the fix is correctness — every co-located reader's per-reader push accounting is
now honest, so the model stays correct for any future per-reader push/HEARTBEAT pacing. The single-
reader common case takes the `%merge-unsent` fast path (no merge, no extra allocation), byte-identical
to the prior path.

### Gates
140 tests pass on SBCL and Clasp (was 139; +`colocated-push`). gate-types PASS (915 ftype'd defuns).
gate-hotpath PASS.
