# ADR 0043 — ACKNACK match-gate: a StatefulReader answers only a MATCHED writer's HEARTBEAT (the pre-match history-replay race)

- **Status:** Accepted (WP-ACKNACK-MATCH-GATE, 2026-07-04).
- **Deciders:** A0 (integrator), A6 (RTPS engine), A8 (DCPS/disc).
- **Requires:** DDS 1.4 §2.2.3.4 (DURABILITY); DDSI-RTPS 2.5 §8.4.10.1 (the StatefulReader is defined over WriterProxies for MATCHED writers), §8.4.2.2 (reliable Writer/Reader behaviour, next_unsent_change), §8.3.7.1 (AckNack); the operating contract §4 (bounds-checked receive path, cheap hot-path check), NFR-CLOS (no CLOS / no per-sample alloc on the receive path). Standing rule: OMG conformance is non-negotiable; a false-REJECT (a TRANSIENT_LOCAL late-joiner losing history, or the discovery-less bootstrap deadlocking) is the worst failure class.
- **Amends / builds on:** ADR 0040 (the `VOLATILE-LATEJOINER-ZERO` note is corrected to RESOLVED). Root-caused by WP-RESIDUAL-FIXES-BATCH-A item A5.

---

## Context

A VOLATILE late-joining reader could receive **pre-join history** — a DDS 1.4 §2.2.3.4 DURABILITY violation (a VOLATILE reader must see only samples written after the match). Mechanism, verified in the event log and code:

1. `%on-user-heartbeat` gated only on `%user-writer-entityid-p` — **not** on the writer being matched. A user HEARTBEAT arriving BEFORE the reader processed the writer's SEDP publication created the WriterProxy on first use with `skip-history` NIL (the on-match `%reader-durability-init` had not run).
2. `reader-acknack` then NACKed the full `[1..N]` advertised pre-join range.
3. `%match-destinations-prefixed` includes the static PEERS unconditionally, so the ACKNACK reached the writer, which legitimately repaired the pre-join history, and `%on-user-data` stored it → the VOLATILE reader delivered pre-join samples.

Surfaced as the ~1-in-5 `VOLATILE-LATEJOINER-ZERO` "flake" (`src/dds-tests/durability-test.lisp`); it is a real product bug, not a test-timing artifact.

A **symmetric writer-side window** was also audited: between `%record-match` (which makes a reader visible to `%reader-push-targets`) and the on-match `%writer-durability-init` (which sets the ReaderProxy `unsent-base`), a concurrent publish on another thread would capture from the default `unsent-base` 1 and replay history to a VOLATILE reader.

## Decision

Two receive-/match-time changes; no new wire message, no changed emission format; everything the pre-WP path emitted for a MATCHED writer stays byte-identical. Interop posture is strictly **more** conformant (an unmatched writer's HEARTBEAT is no longer answered — §8.4.10.1).

1. **Reader-side HEARTBEAT match-gate.** `%on-user-heartbeat` (and `%on-user-heartbeat-frag`) apply the HEARTBEAT range and emit the ACKNACK / NACK_FRAG **only** when the writer's 16-octet GUID is a matched remote endpoint (`%guid-matched-p` — an O(1) `equalp` lookup of `disc-node-matches` under the node lock; no CLOS, no per-sample alloc). A pre-match HEARTBEAT is **dropped**; the writer's next periodic HEARTBEAT (RTPS 2.5 §8.4.2.2) re-arrives post-match, when the durability baseline is armed — a VOLATILE reader then baselines at the writer's current lastSN (no pre-join history), a TRANSIENT_LOCAL reader still requests the retained history. This is the observable used by the on-match durability gate, so the discovery-less/static-peers path — which establishes the SAME match via SEDP RxO before any user data flows (all loopback tests `%await-match` on `disc-node-matched-count`) — bootstraps unchanged.

2. **Writer-side durability pre-arm.** `%match-remote-endpoint` FUTURE-only-bases the reliable writer's ReaderProxy (`unsent-base = lastSN+1`, `%prearm-writer-future-base`) for a newly-matched remote reader **before** `%record-match` records it — i.e. before the reader becomes a `%reader-push-targets` destination — so a concurrent publish racing the match cannot replay pre-join history from the default base 1. The engine arms this itself (deadlock-proof — it never waits on the external hook); it is FIRST-match-gated (`%guid-matched-p`) so a re-announce never re-futures past unsent LIVE samples; and the durability-aware on-match hook (`%writer-durability-init`) then REFINES it (a TL↔TL match to `firstSN` for late-joiner replay — and the ACKNACK-repair path replays independently of `unsent-base`, so TL replay is intact even though the base starts future-only). The raw discovery-less/no-hook path is **not** pre-armed (the pre-arm runs only when the endpoint reaches the SEDP match-commit branch, and it is a no-op with no user writer), so it keeps the default `unsent-base` 1 push-all — byte-identical.

## Consequences

- `VOLATILE-LATEJOINER-ZERO` is deterministically green (15/15 SBCL loop, 2026-07-04); the pre-fix rate was ~1/5.
- No hot-path perf change: the added check is one `equalp` gethash on the (periodic, not per-sample) HEARTBEAT receive path and one locked `writer-heartbeat` read per match. `make gate-hotpath` / `make gate-types` stay green.
- A malformed or spoofed pre-match HEARTBEAT can no longer drive a NACK storm against an unmatched writer (a hardening side-benefit; the security receive-enforcement gate in `%handle-datagram` is unchanged).
- Live-vendor interop harnesses are not re-run for this WP: the change is receive-side gating + baseline timing; both-vendor wire surface for a MATCHED writer is unchanged, and the loopback UDP suite covers the behaviour.

## Alternatives considered

- **Gate `%on-user-data` on match** (drop pre-match DATA): rejected — larger blast radius on the per-sample path, and the writer-side pre-arm removes the source of the unsolicited pre-join push instead.
- **Reorder `%fire-match` before `%record-match`** to close the writer-side window: rejected — `%record-match`'s atomic check-and-set is the once-only-fire authority across the ≤3 receiver threads; splitting it risks double-firing SUBSCRIPTION/PUBLICATION_MATCHED. The future-only pre-arm closes the window without touching the match commit's once-ness.

## Residual — NOT closed (forward requirement)

The READER-side arming is asymmetric to the writer-side pre-arm: `skip-history` is armed
AFTER `%record-match` (in `%fire-match` → `%reader-durability-init`), so a user HEARTBEAT
processed in the window between `%record-match` (the writer now passes `%guid-matched-p`)
and the hook arming `skip-history` would recreate the original bug. This window is
UNREACHABLE today ONLY because SEDP is always unicast in this stack, so the SEDP match
commit and the user HEARTBEAT serialize on the single unicast receiver thread (only SPDP
uses the multicast thread). Closing it reader-side was judged a false-REJECT risk
(double-latch reset) for an unexercised config. **FORWARD REQUIREMENT: any WP that adds
user-data multicast, moves SEDP onto the multicast thread, or splits metatraffic onto its
own receiver thread MUST first arm the reader-side durability baseline atomically with (or
before) `%record-match`, or this DURABILITY violation reopens silently.** See also the
one-line note at the `%on-user-heartbeat` gate site.

- Determinism-proof framing: the 15/15 loop ran in one warm image; that is sufficient
  evidence here because the fix is STRUCTURAL (the gate drops a pre-match HEARTBEAT
  regardless of arrival timing), not a narrowed timing window — determinism does not rest
  on reproducing the original cold-start scheduler timing.
