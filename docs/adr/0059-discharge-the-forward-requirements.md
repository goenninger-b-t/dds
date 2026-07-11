# ADR 0059 — Discharge the forward requirements: fix what can be fixed now, make the rest fail loudly

Status: Accepted
Date: 2026-07-11
Work package: post-WP tracked-residual close-out (owner-directed item 7)
Relates to: ADR 0038 residual (a) / ADR 0039 residual (d) (the `%km-session-key-at` two-slot publish); ADR 0031 lim.1 (decode-fail counters vs KM rotation); ADR 0043 (the ACKNACK match gate and its reader-arming residual); ADR 0045 §7.2 (the `epochs.dat` seal vs epoch-table retirement)

## 1. Context

Four ADRs each carried a **forward requirement**: a hazard that is unreachable *today* because of some
structural accident, together with an instruction that a future WP must handle it. A forward requirement is
a promise that a future engineer will read an ADR they have no reason to open. That is a weak guarantee, so
this ADR converts each one into something that does not depend on anyone remembering:

- **fix it** where the hazard can be removed by construction, or
- **make it fail loudly** where it cannot — so a future WP that reopens it trips a guard instead of shipping
  a silent regression.

**One of the four turned out not to be a forward requirement at all — it was already reachable.**

## 2. `%km-session-key-at` (ADR 0038(a) / 0039(d)) — the premise was FALSE; fixed by construction

**The recorded requirement:** *"when a future `rtps_protection` rekeying (session_id rotation) lands, it
must confirm the decode receiver stays single-threaded per km OR harden `%km-session-key-at`'s two-slot
publish against a concurrent-different-session_id tear (the fence protocol is tear-safe only while
session_id is effectively constant per km)."*

**The premise does not hold.** `start-node` spawns up to **three** receiver threads — unicast UDP,
multicast UDP, and SHMEM — and *all* feed `%handle-datagram`. They can decode datagrams from the **same**
peer under the **same** participant KM. And `session_id` is read **off the wire**: a peer — or an attacker —
may vary it per datagram (the KM docstring already noted this is "reachable pre-auth", since the lookup runs
*before* the GCM auth check). So concurrent lookups with *different* session_ids on one KM are reachable
**today**, with no rekeying feature at all.

The hazard: the discriminant and the key were published in **separate slots**. Two concurrent missers can
interleave their stores so the KM ends up advertising id `S1` alongside `key(S2)`; a subsequent hit on `S1`
returns the **wrong key**. It is fail-closed — a wrong key cannot forge a GCM tag, so the datagram is
dropped, never accepted — which is why it has not bitten: the consequence is a **silent drop**, not a
breach, and conformant peers use a fixed `session_id` so the cache never re-publishes. Safe by accident.

**Fix (by construction).** The discriminant and the key are now ONE immutable `session-cache` object,
published with a **single store**. A reader sees either the old pair or the new pair — never a mix. The tear
is impossible, for both caches: the send-side (id, key) and the receiver-specific origin-auth cache, whose
discriminant is **four** fields (key_id, master_key, session_id) and was correspondingly more tear-prone.
This also discharges the original forward requirement: a future rekeying WP inherits a tear-free cache.

**Cost, measured** (`bench/report/2026-07-11-km-session-cache-single-object.md`): the cache hit goes
6.6 ns → 7.8 ns (one extra indirection). That is **0.16 %** of the ~750 ns AEAD call the lookup feeds; the
end-to-end seal is unchanged within noise. Accepted: 1.2 ns/sample to remove a reachable hazard.

## 3. Decode-fail counters vs KM rotation (ADR 0031 lim.1) — discharged, not deferred

**The recorded requirement:** a future rekey WP *"MUST epoch-key `disc-node-decode-fail-counts` (or
invalidate a writer's counters on KM replacement) so a key change resets the classification."* Otherwise a
sample encoded under a **new** key counts failures against the **stale** KM's classification, crosses the
suppression threshold, gets suppressed — and is then **silently lost** when the retransmit finally becomes
decodable (its SN is already GAP-irrelevant).

**Discharged here instead.** Each writer's counter table is now **stamped with the identity of the KM the
failures were classified under** (its §9.5.2 `sender_key_id`) and is **reset when that identity changes**. A
new key is a new classification; the stale counts are dropped. A future rotation cannot inherit the bug by
forgetting to read this ADR. Cost: one 4-octet compare on a path that only runs when a decode has *already*
failed — never on the steady-state zero-alloc receive arm.

## 4. The ADR 0043 reader-arming window — made FAIL-SAFE (and a wrong first attempt, recorded)

**The recorded requirement:** the reader-side durability baseline (`skip-history`) is armed *after*
`%record-match`, so a user HEARTBEAT arriving in between would lazily create a WriterProxy with
`skip-history` NIL and NACK the writer's whole pre-match range — a VOLATILE reader silently pulling a
retaining writer's history (a **DURABILITY violation**). Unreachable today *only* because SEDP and user
HEARTBEATs both ride the **one** unicast receiver thread (discovery/HEARTBEAT/ACKNACK never leave UDP), so
the match commit and the HEARTBEAT serialize. *"Any WP that adds user-data multicast, moves SEDP onto the
multicast thread, or splits metatraffic onto its own receiver thread MUST first arm the reader-side
durability baseline atomically with (or before) `%record-match`, or this DURABILITY violation reopens
silently."*

**Now it cannot reopen silently.** The HEARTBEAT gate requires the baseline to be **armed** (the WriterProxy
to *exist* — `init-writer-proxy-durability` creates it at match time, before the first HEARTBEAT) as well as
matched. A matched-but-unarmed HEARTBEAT is **dropped** and **counted** (`disc-node-hb-unarmed-drops`); the
writer's next periodic HEARTBEAT re-arrives post-arm, which is the same recovery the match gate already
relies on. Fail-safe, not fail-closed: a reopened window costs one HEARTBEAT period of latency, never a
durability violation. The counter **must stay 0**; a non-zero value means a WP reopened the window and owes
the atomic arming.

**A wrong first attempt, kept here because it is instructive.** The obvious guard — "matched ⇒ the proxy
must exist" — is **wrong**, and the test suite caught it immediately (`repair-delivered` went red). A bare
`dds.disc` node (the low-level tests, the shapes runners) **never arms a baseline at all**, by design: the
DCPS layer owns that gate. Requiring "armed" unconditionally would have dropped *every* HEARTBEAT on the
disc-level path and broken reliable repair. The guard therefore applies only when the DCPS layer has taken
ownership (`disc-node-durability-gate-active`, set by `create-datareader`). A guard that fires where the
invariant it protects does not apply is worse than no guard.

## 5. The `epochs.dat` seal vs epoch-table retirement (ADR 0045 §7.2) — the error now names its own obligation

This one genuinely **cannot** be discharged early: the seal deliberately cannot distinguish an *authorized*
shrink (epoch retirement) from *rollback tampering*, and inventing a distinction now would weaken the
tamper-evidence for a feature that does not exist. So the failure is left in place — but it no longer bricks
mutely. The `:truncated` error now states the counts, says plainly that this is tampering **unless** you are
implementing epoch-table retirement, and tells that WP what it owes (rework the seal lifecycle:
invalidate-before-shrink + re-seal at clean close) — and explicitly **not** to relax the check to make
retirement pass. The next engineer to hit it gets the ADR's instruction in the error message they are
already staring at.

## 6. Consequences

- Two hazards removed **by construction** (§2, §3); one made **fail-safe + counted** (§4); one made
  **self-explanatory at the point of failure** (§5). Nothing now depends on a future engineer reading an ADR
  they have no reason to open.
- **No wire-format change.** No behavioural change on any path exercised today: the tear could not be
  observed by a conformant peer, the counter stamp only resets a classification that never rotates yet, the
  HEARTBEAT guard's condition never fires, and the epochs error text changes only the message.
- **`disc-node-hb-unarmed-drops` is a permanent invariant probe.** It must read 0. If it ever does not, ADR
  0043's forward requirement has come due.

## 7. Verification

- `km-session-cache-tear` (new): hammers one KM from 4 threads with 6 interleaved distinct `session_id`s and
  asserts every lookup returns the key for the id it *asked for*, and that every published cache object is
  self-consistent (its key is exactly what its own id derives). Both caches, including the four-field
  origin-auth discriminant.
- `repair-delivered` (existing) is what caught the wrong first guard in §4 — kept as the regression that
  pins "the disc-level path never arms, and must still repair".
- 561/561 on **both** Clasp and SBCL; `gate-hotpath` + `gate-types` green; hot-path bench in
  `bench/report/2026-07-11-km-session-cache-single-object.md`.
