# ADR 0071 — the reader-side durability baseline is armed BEFORE the match is recorded (github#2)

- **Status:** Accepted
- **Date:** 2026-07-21
- **Requirements:** FR-DCPS (durability §2.2.3.4), FR-RTPS-3/4 (reliable writer/reader), NFR-CONC, NFR-MEM
- **Relates to:** ADR 0043 (the ACKNACK match-gate + the writer-side future-base prearm), ADR 0063 (departure)
- **Fixes:** github#2 (`dcps-durability-latejoiner` `LJ-VOL-PRE` flake)
- **Contract touched:** none externally; `%match-remote-endpoint` gains a reader-side prearm + a test seam

## Symptom

`run-dcps-durability-latejoiner-test` failed intermittently under full-suite load, never in isolation:
`LJ-VOL-PRE` — a VOLATILE late reader received > 0 of the writer's 3 pre-existing samples, which it must
skip (DDS 1.4 §2.2.3.4 — a VOLATILE reader baselines at the writer's current lastSN).

## Root cause (mapped, then proven deterministically)

A VOLATILE reader skips a retaining writer's history via **two** gates, on two paths:

- **writer-side** `unsent-base` — stops the writer from ever *pushing* SN1‑3 to the reader;
- **reader-side** `skip-history` — stops the reader from *NACKing* SN1‑3 in reply to a HEARTBEAT (a NACK
  would trigger the writer's ACKNACK-repair retransmit, which replays **independently of `unsent-base`**).

In this test the writer never pushes SN1‑3 to the late reader (`spin` does not push; the only writes are the
pre-join SN1‑3 and the post-drain SN4), so the **operative vector is the reader-side gate**: a periodic
HEARTBEAT `[1,3]` → the reader NACKs `[1,3]` → the writer retransmits via ACKNACK-repair → delivered.

The two gates are armed **asymmetrically** at match time in `%match-remote-endpoint`:

- The **writer** prearm (`%prearm-writer-future-base`) runs **before** `%record-match`. `%record-match`
  writes `disc-node-matches` under the node lock, and the HEARTBEAT match-gate (`%guid-matched-p`) reads it
  under the node lock — so arming before `%record-match` is published to any HEARTBEAT thread via that
  **happens-before**. Correct by construction (ADR 0043).
- The **reader** arm (`%reader-durability-init`, which sets `skip-history`) ran only in `%fire-match` —
  **after** `%record-match`, and after the node lock was released, **with no happens-before**. At the instant
  the match became observable, the reader's WriterProxy did not yet exist (it is created inside
  `%reader-durability-init`), and once created it is momentarily armed-but-`skip-history=nil` (a TOCTOU:
  `get-writer-proxy` inserts, then `setf skip-history`).

On a single unicast receiver thread the SEDP match commit and the inbound HEARTBEAT serialize, so the arm
always completes before any HEARTBEAT is processed — the window is closed *by that invariant*, not by
construction. Under full-suite load a **second** thread reaches `%on-user-heartbeat` during the arm (the
ADR 0043 forward-requirement conditions: a SHMEM receiver, a lease-flap re-match interleaving a deferred
`writer-unmatch-reader`/re-arm, split metatraffic), NACKs `[1,3]`, and the history is pulled.

**Proven deterministically** (`run-dcps-latejoiner-reader-armed-before-match-test`): a test seam
(`*post-record-match-hook*`) captures the reader's WriterProxy arm-state at the instant `%record-match`
runs. Before the fix it is **`:no-proxy`** (not armed); after, **`:armed`**.

## Decision

**Arm the reader-side durability baseline BEFORE `%record-match`, symmetric with the writer prearm.**
`%match-remote-endpoint` now calls `%reader-durability-init` (for a first-time match of a local reader to a
remote writer) immediately after the route-add and **before** `%record-match`. The existing `%fire-match`
arm remains as a harmless re-arm (it re-sets the same `skip-history` value; at match time `lastSN` is
unchanged, so a re-applied skip keeps `first-sn = lastSN+1`) and still serves the white-box
`%on-disc-match` callers that do not go through `%match-remote-endpoint`.

Why this closes the window with no new locking: everything the SEDP thread does before `%record-match` —
now including creating the WriterProxy **and** setting `skip-history` — is published to any HEARTBEAT thread
that later observes the match, through the node lock that already guards `disc-node-matches`. The TOCTOU
inside the arm now happens **before** `%record-match`, where `%guid-matched-p` is still false, so any
racing HEARTBEAT is dropped by the fail-safe rather than answered. It is the exact mechanism that already
makes the writer prearm correct.

## Consequences

- The window is closed by construction, on **any** thread topology — it no longer depends on the
  single-unicast-receiver-thread invariant (which ADR 0043 flagged as a forward requirement that any
  multicast/SHMEM/split-metatraffic change would break). This is the robustness the fix buys.
- **No hot-path or allocation impact.** The change is on the discovery/match plane, run once per matched
  pair. `gate-mem` is unchanged (2424.5 B/sample). The added `*post-record-match-hook*` is one NIL check
  per match, inert in production.
- `run-dcps-latejoiner-reader-armed-before-match-test` guards the invariant on **both** impls (it is
  deterministic and needs no ZC/SHMEM); it is RED before the fix (`:no-proxy`) and GREEN after (`:armed`).
- 573/573 both impls; all gates green.

## Not addressed (noted, out of scope)

- A latent, separate concern the mapping surfaced: `%fire-match`'s re-arm resets the one-shot
  `durability-applied-p` latch, so a live sample published *immediately* after match whose HEARTBEAT races
  the re-arm could have its skip re-applied past it. The prearm does not worsen this (it arms earlier); the
  test publishes SN4 only after draining, so it is not exercised. If a future workload needs immediate
  post-match publication under a VOLATILE reader, the latch semantics deserve their own review.
- N≥2 same-topic readers with **mixed** durabilities matching one writer: the disc-layer prearm uses the
  node's primary user-reader durability (as `%reader-durability-init` already did). The failing case and the
  common case are N=1; a mixed-durability N≥2 refinement is a separate change.
