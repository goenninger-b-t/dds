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

(Filled in when Commit B lands.)
