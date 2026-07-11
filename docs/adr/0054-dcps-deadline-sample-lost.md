# ADR 0054 — DCPS deadline monitoring + SAMPLE_LOST: the background deadline monitor and the two-site lost-sample detection

Status: Accepted
Date: 2026-07-10
Work package: WP-DCPS-API-COMPLETION Slice S4 (tasks S4.T1–S4.T3) — the deadline-monitoring + SAMPLE_LOST slice of the DCPS API-completion program (design doc `docs/superpowers/specs/2026-07-09-dcps-api-completion-design.md`; plan `docs/superpowers/plans/2026-07-09-dcps-api-completion.md`)
Relates to: WP-DCPS-API-COMPLETION S0 (the `%notify-status` chokepoint + per-entity status-changes bitmask + entity-owned StatusCondition + the three status structs, which S4 fires); ADR 0053 (S3 listener-hierarchy propagation, which S4's fires flow through unchanged); ADR 0052 (S2 delete/enable lifecycle — the monitor thread is stopped+joined on delete-participant); ADR 0019 (per-instance KEEP_LAST + the reactive GAP whose evicted SNs S4 reports as SAMPLE_LOST); ADR 0031 (secure decode-fail suppression, whose reader-suppress-sn path S4 deliberately does not count)

## 1. Context

After S0 the three "hard" DCPS statuses had structs, a firing chokepoint, and listener/StatusCondition
plumbing, but **nothing fired them** (S0 review: "deadline/liveliness/sample-lost firing still
scaffolded — need a timer / reader gap-detect — S4"). Missing against DDS 1.4 and
`dds_rtf2_dcps.idl`:

- **OFFERED_DEADLINE_MISSED** (writer, idl §131-135) / **REQUESTED_DEADLINE_MISSED** (reader,
  §137-141) — the DEADLINE QoS (§2.2.3.7): a per-instance obligation that a writer publish, or a
  reader receive, a sample for each instance at least once per DEADLINE period; a miss fires when the
  period elapses with no such write/sample.
- **SAMPLE_LOST** (reader, idl §99-102, §2.2.4.1): a sample that will never be made available to the
  DataReader. The RTF2 `SampleLostStatus` carries **no** `last_reason` (verified S0), so it is just
  `total_count` + `total_count_change`.
- The three `get_*_status` accessors (idl §131/§137/§1163) with the §2.2.2.1.9 read-communication-status
  reset.

FR-DCPS-3 ("all standard statuses with correct change/reset semantics") cannot close until these fire.
This is one of the operating contract's flagged hard sub-problems (timer state; sequence-number/GAP
edge cases), so the design was pinned to the spec clauses and the existing engine, not reconstructed.

## 2. Decision

### 2.1 Deadline monitor — one background thread per participant, lazily started (S4.T1/T2)

A new `src/dds-dcps/deadline.lisp` (control plane, **not** the measured hot path) realises the DEADLINE
QoS:

- **`deadline-timer`** — one per (endpoint, instance): the ENDPOINT (DataWriter=offered /
  DataReader=requested), the 16-octet instance HANDLE, the PERIOD (internal-time-units), and the only
  mutable field EXPIRY. Created **once** per instance and reused across every subsequent write/sample
  (NFR-MEM: no per-sample cons).
- **`deadline-monitor`** — one per participant: a background thread (`dds.pal:spawn`) that waits on a
  condition variable until the earliest armed timer's EXPIRY, fires every expired timer's miss, and
  re-arms it one period ahead (so a persistently-silent instance fires once per elapsed period). The
  armed set is a flat list scanned for the next expiry (the degenerate sorted structure; a heap is a
  documented future optimisation — control plane).
- **Arm/rearm** on the user thread: `write-sample` calls `%deadline-touch-writer` (reusing the KEEP_LAST
  keyhash it already computed — no extra instance-handle cost); the reader drain calls `%deadline-touch`.
  An already-tracked instance's rearm just pushes EXPIRY one period ahead under the monitor lock (0-alloc)
  and, since the new expiry is strictly later than any pending one, never needs to wake the monitor.
- **The default DURATION_INFINITE arms no timer** — `%endpoint-deadline-period-units` returns NIL before
  any monitor interaction, so a non-deadline participant **never spawns the thread** and its write/receive
  path is byte-identical and 0-alloc.
- **Clean shutdown**: `delete-participant` calls `%deadline-monitor-stop` which sets RUNNING NIL + signals
  the CV under the monitor lock (no lost wakeup) and **joins** the thread **before** the node/buffers are
  torn down (no strand, no use-after-free); disarm-instance (on purge) and disarm-endpoint (on
  delete_datawriter/datareader) drop timers from the armed set.
- Every miss fires through the **one `%notify-status` chokepoint** (S0), so it flows to the bitmask +
  StatusCondition + the S3 listener hierarchy — no parallel notification path.

### 2.2 SAMPLE_LOST — two detection sites, one fire path (S4.T3)

A sample is "lost" only when it is **permanently** unavailable. The two mechanisms by which this engine
learns that are handled at the two sites where the knowledge exists, and both funnel into one
DCPS-layer fire `%fire-sample-lost dr n` (→ `%notify-status`, `total_count += n`):

1. **Best-effort SN-skip — the reader drain (`%reader-advance-drained`, `entities.lisp`).** BEST_EFFORT
   (§2.2.3.14) has no retransmission, so a forward jump in the delivered per-writer sequence-number
   stream is a permanently-lost run. Detection sits on the single chokepoint every drain path (plain /
   ZC-loan / secured-loan) already advances the `dr-drained` high-water through: when the reader is
   best-effort, a prior watermark exists (the baseline sample already landed — **pre-baseline SNs are
   never counted**, matching a late-joiner that simply never wanted them), and the new SN exceeds
   PRIOR+1, fire `(SN − PRIOR − 1)`. Pure reordering (a lower SN arriving late) never jumps forward and
   is conservatively **not** counted — a false SAMPLE_LOST is the worse error (the standing false-report
   rule). Gated on best-effort: a RELIABLE drain-skip is NACK-recoverable, so it is **not** loss there.
2. **Irrecoverable reliable GAP — the engine (`reader-on-gap`, `reliable.lisp` → `%on-user-gap`,
   `dataplane.lisp`).** A reliable reader learns a sample is permanently gone when the writer sends a
   GAP for it (the writer's HistoryCache no longer holds it — a per-instance KEEP_LAST overwrite or a
   RESOURCE_LIMITS eviction, ADR 0019). `reader-on-gap` now returns the count of SNs that transition
   from **never-seen** to `:gap`: an already-RECEIVED SN (marker `t`) is preserved and not counted; an
   already-`:gap` SN is not re-counted; and the existing lower-clamp to the proxy's `first-sn` keeps a
   durability-skipped pre-match range (intentionally not-wanted, not lost) out of the tally. `%on-user-gap`
   fires SAMPLE_LOST with that count via a new `disc-node-on-sample-lost` hook → `%participant-reader-by-entity-id`
   → the matched DataReader.

**Why no content-filter false positive.** DDS elsewhere distinguishes a filter-GAP (not lost) from a
purge-GAP (lost). This engine content-filters **reader-side** (the writer sends every sample; ADR-era
M3 decision) and implements no writer-side filtering, so it **never emits a filter-GAP** — every inbound
GAP is a genuine purge/eviction and the count is exact. Should writer-side filtering ever land, the
filtered-flag (`+gap-flag-filtered+`, currently parsed-but-unused) must gate the count; recorded as a
forward requirement.

**Deliberate v1 non-trigger.** The secure receive path's `reader-suppress-sn` (a bounded run of
KM-present AES-GCM decode failures marks one SN locally `:gap`, ADR 0031) is a genuine loss but is
**not** counted as SAMPLE_LOST in v1 — it has its own decode-fail accounting and firing it here would
entangle the security-suppression semantics; recorded as a possible follow-on.

### 2.3 The fire path is unchanged plumbing

All three statuses fire through the single S0 `%notify-status` chokepoint and therefore inherit the S3
hierarchy propagation and the §2.2.4.1 StatusChangedFlag reset-on-listener-invocation for free — S4 adds
no parallel notification path. `get_offered_deadline_missed_status` / `get_requested_deadline_missed_status`
/ `get_sample_lost_status` apply the §2.2.2.1.9 read-reset (zero `total_count_change`, clear the bit;
`total_count` stays monotonic).

## 3. Consequences

- **No wire change.** S4 is a local-API + control-plane slice: no new PID, submessage, or encapsulation.
  The only engine-visible change is `reader-on-gap`'s return type (`t` → `(integer 0)`, the newly-lost
  count) and the additive `disc-node-on-sample-lost` hook slot; the sole non-test caller (`%on-user-gap`)
  is updated and the sole test caller ignores the return (side-effect call).
- **Threading on both impls.** Per the owner directive 2026-07-09 (Clasp has no threading limitation),
  the monitor uses a real background thread on Clasp and SBCL identically.
- **Cost.** A non-deadline participant spawns no monitor thread and allocates nothing new on write/receive.
  A deadline participant reuses one timer struct per instance (no per-sample cons). SAMPLE_LOST detection
  is a single integer compare on the drain path (best-effort) or inside the already-iterated GAP loop
  (reliable) — no new allocation. gate-hotpath stays green (the hot path is untouched).
- **Follow-ons (recorded):** a next-expiry heap for the monitor if instance/timer counts grow;
  writer-side filter-GAP → gate the SAMPLE_LOST count on the filtered flag; count `reader-suppress-sn`
  suppression as SAMPLE_LOST if the security semantics are reconciled.

## 4. Alternatives considered

- **Detect best-effort loss in the engine (`reader-on-data`) instead of the drain.** Rejected: the engine
  reader is reliability-agnostic and shared across builtin/relay/secure call sites, so gating on
  best-effort would mean threading reliability through all of them; the drain already knows the reader's
  QoS and its per-writer delivered high-water, so detection there is DRY and needs no engine change.
- **Detect reliable loss at the drain too (a drain-skip).** Rejected: a reliable drain-skip is usually a
  not-yet-retransmitted SN (recoverable), so firing there would be a false positive. Only the GAP tells a
  reliable reader a sample is permanently gone.
- **A timer wheel / heap from the start.** Deferred: a flat next-expiry scan is correct and simple for the
  control-plane instance counts today; the structure is documented as a future optimisation, not a
  correctness gap.
