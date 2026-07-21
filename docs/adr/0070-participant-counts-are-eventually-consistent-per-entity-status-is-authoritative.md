# ADR 0070 — participant-level discovered/matched counts are eventually-consistent; the per-entity status is authoritative (github#3)

- **Status:** Accepted
- **Date:** 2026-07-21
- **Requirements:** FR-DCPS-3 (communication statuses), FR-DISC-1/3 (lease/liveliness), NFR-CONC
- **Relates to:** ADR 0063 (departure funnels through one choke point, hooks fire outside the node lock)
- **Fixes:** github#3 (`dcps-autonomous-lease-expiry` `LEASE-UNMATCHED-STATUS` flake)
- **Contract touched:** none (a test-barrier correction + a documented ordering contract)

## Symptom

`run-dcps-autonomous-lease-expiry-test` flaked once on a full Clasp run: after killing a peer and waiting
(bounded) until the node's `matched-count` and `discovered-count` both reached 0, the test read the
DataReader's `SUBSCRIPTION_MATCHED current_count` with **no further wait** and found it still non-zero.

## Root cause (proven by construction, not guessed)

The two updates are done by the **same thread** (the autonomous announcer, in `%lease-sweep`) but under **two
different locks, in a fixed order**:

1. **Under the node lock** — `%prune-participant-locked` removes the node-level entries: `disc-node-matches`
   (matched-count, remhash `disc.lisp:1860`) and `disc-node-discovered` (discovered-count, `disc.lisp:1926`).
2. **The node lock is released.**
3. **Outside any node lock** — `%fire-participant-gone` (`disc.lisp:1913`) fires the on-unmatch hook →
   `%reader-unmatched` → decrements `SUBSCRIPTION_MATCHED current_count` under the *reader's own* status lock
   (`entities.lisp:3194`).

So the node counts reach 0 **strictly before** the reader status does. Any thread that polls the node counts
as an "am I unmatched yet?" gate and then reads the reader status can observe `matched-count == 0` with
`SUBSCRIPTION_MATCHED == 1`. The window is normally sub-millisecond; a GC/preemption of the announcer between
lock-release and hook-fire widens it — hence full-suite-only.

## Why this is NOT a stack defect to "fix" by reordering

The hooks fire outside the node lock **by design** (ADR 0063): the on-unmatch hook runs user *listener* code
(`on_subscription_matched`), and holding the node lock across user code invites deadlock (a callback that
calls a DDS API which re-takes the node lock) and lock-order inversion (node lock → reader status lock).

Forcing the node counts to flip *after* the reader status would require either:

- decrementing the reader status **before** removing the node-match entry — which breaks the cross-thread
  double-departure dedup: the lease sweep (announcer thread) and the graceful SPDP dispose (receiver thread)
  both prune the same prefix, and the **remove-under-lock is exactly what makes them idempotent**. Firing the
  unmatch before the remove lets both threads fire it → `%reader-unmatched` double-decrements
  `current_count_change` (it floors `current_count` at 0 but decrements `_change` unconditionally,
  `entities.lisp:3194`), corrupting the status; or
- decrementing the status *inside* the node lock — reintroducing the node→status-lock nesting and the
  user-listener-under-lock deadlock ADR 0063 removed.

Both destabilize a security- and correctness-critical concurrent path — the opposite of the stability goal.

**And it is not a defect.** DDS communication statuses are defined **per Entity** (§2.2.4). `matched_count` /
`discovered_count` here are participant-level *introspection helpers over the built-in discovery state*, not
standard statuses, and no spec contract binds their update ordering to a per-reader status. Real DDS
implementations (Connext, Fast DDS) do not update the two atomically either. An application that needs a
reader's match state reads **that reader's `SUBSCRIPTION_MATCHED`** (via listener, WaitSet, or polling) — not
a participant aggregate.

## Decision — the stated contract

**On endpoint/participant departure, the participant-level `discovered_count` / `matched_count` are
eventually-consistent aggregates that may briefly LEAD the per-entity status decrements. The per-entity
status (`SUBSCRIPTION_MATCHED` / `PUBLICATION_MATCHED`) is the authoritative observable for a specific
endpoint's match state — poll (or wait on) it directly.** This ordering is intentional (hooks fire outside
the node lock, ADR 0063) and is now a documented guarantee rather than an accident.

The test is corrected to wait on the **authoritative** observable: its bounded settle-loop now waits until
`matched-count`, `discovered-count`, **and** the reader's `SUBSCRIPTION_MATCHED current_count` are all 0,
exactly as it already waited on the two node counts. The two `%check`s (aged-out on the node counts;
unmatched-status on the reader status) are unchanged and now both hold reliably.

## Consequences

- The flake is eliminated by asserting via the correct barrier; no change to the discovery/teardown path,
  so no new concurrency risk and no perf/allocation impact (the departure path is discovery-plane, not hot).
- The contract above should guide any future app or test: participant counts are a coarse "peer gone" hint;
  the per-entity status is the fine-grained truth.
- **Considered and rejected:** forcing the aggregate to flip last (unsafe — breaks the double-departure
  dedup) and decrementing the status under the node lock (unsafe — reintroduces the ADR 0063 deadlock). Both
  are recorded here so the next reader does not re-derive them.

## Not addressed

Making the two observables mutually atomic. It is not required for correctness, it is not how DDS defines
statuses, and every safe way to achieve it destabilizes the departure path. If a future requirement genuinely
needs it, it belongs behind a separate, carefully-reviewed change to `%notify-status` (separating the
internal counter update from the user-listener invocation) with a full lock-ordering audit — not a quick
reorder.
