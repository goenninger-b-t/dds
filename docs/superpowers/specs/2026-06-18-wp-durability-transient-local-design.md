# WP-DURABILITY-TRANSIENT-LOCAL — TRANSIENT_LOCAL durability + late-joiner delivery (M6 / P5) — design

**Goal (DDS 1.4 §2.2.3.4, M6 / P5).** A TRANSIENT_LOCAL DataWriter RETAINS its samples and REPLAYS them to a
late-joining TRANSIENT_LOCAL DataReader; a late-joining TRANSIENT_LOCAL DataReader REQUESTS + receives that
history. Both sides. The DURABILITY QoS is already advertised/parsed/RxO-matched; this WP adds the missing
BEHAVIOR. Plus an OPT-IN finalize control (an extension on top of the conformant default). Non-R6.

## Owner-confirmed decisions (brainstorm 2026-06-18)
1. **TRANSIENT_LOCAL only, BOTH sides.** TRANSIENT + PERSISTENT need a durability *service* (persistence /
   cloud-discovery) — OUT of scope per the operating contract (the service suite is not built here). VOLATILE
   is the existing default.
2. **Retention deadline / finalize** beyond the standard HISTORY/RESOURCE_LIMITS retention — as an OPT-IN
   extension ADDED ON TOP of the conformant default (standard TL retains for the writer's lifetime). Default
   off → standard TL.

## Conformance posture
DDS-standard TRANSIENT_LOCAL retains for the writer's lifetime, bounded only by HISTORY + RESOURCE_LIMITS
(per-writer lifetime control of TRANSIENT/PERSISTENT is the durability service's job — out of scope). So the
DEFAULT TL behavior is the conformant "retain for lifetime"; the finalize/deadline is an OPT-IN extension on
top (never replaces the default). The reliable HEARTBEAT/ACKNACK/retransmit machinery already exists and does
the actual replay — this WP supplies durability-aware RETENTION + the durability-aware SEQUENCE-NUMBER
INITIALIZATION on both sides that makes the existing machinery replay (or not) correctly.

## Grounded current state (file:line — verified, from the durability map)
- DURABILITY QoS: `qos.lisp:108` `(durability :volatile … (member :volatile :transient-local :transient
  :persistent))`; rank `qos.lisp:62-65`; RxO `qos.lisp:169-171` (offered-rank ≥ requested-rank). PID_DURABILITY
  (0x001d) emit/parse `discovery.lisp:444/523/592`. ADVERTISED + MATCHED today; BEHAVIOR absent.
- **Purge is durability-blind:** `reliable.lisp:220-242` `writer-purge-acked` drops below the min acked-base
  across matched readers (full-ACK purge), called from `dataplane.lisp:1273` on publish — discards history
  before a late-joiner arrives. No durability branch.
- **Reader-proxy init is hardcoded future-only:** `reliable.lisp:26-34` `reader-proxy` (acked-base 1,
  unsent-base 1); `reliable.lisp:120-127` `get-reader-proxy` creates via `make-reader-proxy` (no args → base
  1). Never consults durability → a new reader gets future-only samples.
- **Match layer (durability in scope):** `entities.lisp` `%on-disc-match` → `:remote-reader → (%writer-matched
  dw handle)` and `:remote-writer → (%reader-matched dr handle)`, with `remote` (the endpoint-data carrying the
  peer's durability QoS) in scope. This is where durability must be threaded into proxy init.
- **The reliable replay machinery EXISTS:** `reliable.lisp:161` `writer-heartbeat` (firstSN from hc-min-seq);
  `:169` `%changes-from`; `:192` `writer-unsent-list` (changes ≥ unsent-base); `:200` `writer-on-acknack`
  (resend NACKed); `dataplane.lisp:387` `%push-heartbeat`. Would replay history IF the proxy/reader expected it.
- No VOLATILE-vs-TL BEHAVIOR branch anywhere; no late-joiner test; no durability ADR.

## Design

### 1. Writer-side durability-aware retention
A TRANSIENT_LOCAL writer must NOT full-ACK-purge (it keeps acked samples for late-joiners). Gate
`writer-purge-acked` (and its `dataplane.lisp:1273` caller) on the writer's DURABILITY:
- **VOLATILE writer:** full-ACK purge as today (history bounded by the slowest reader's ACK).
- **TRANSIENT_LOCAL writer:** do NOT full-ACK-purge. Retention is bounded by HISTORY (KEEP_LAST: per-instance
  `%hc-index-drop` eviction still drops the instance's oldest beyond `depth` as new samples arrive — already
  implemented for KEEP_LAST; KEEP_ALL: all, bounded by RESOURCE_LIMITS → the existing reject/block on full).
  So a TL writer's HC is HISTORY-bounded, not ACK-bounded. Retained for the writer's lifetime (default).

### 2. Writer-side late-joiner replay (on-match proxy init)
At the match layer (`%on-disc-match` / `%writer-matched`, where `remote`'s durability is in scope): when a
**TRANSIENT_LOCAL reader** matches a **TRANSIENT_LOCAL writer**, pre-initialize that reader's proxy with
`unsent-base = (hc-min-seq writer-hc)` (= firstSN, replay ALL retained) instead of 1; then trigger a HEARTBEAT
to it. The existing `%push-data`/`%push-heartbeat` → reader NACK → `writer-on-acknack` retransmit delivers the
history. Otherwise (the reader is VOLATILE, **or** the writer itself is VOLATILE and retains nothing) → proxy
`unsent-base` = `lastSN + 1` (future-only, as effectively today). Thread the reader's durability from `remote`
(endpoint-data-qos) + read the writer's own durability; add a proxy-init entry point (e.g.
`init-reader-proxy-for-durability writer handle base`) since `get-reader-proxy` currently takes no QoS. The
proxy is keyed by the reader's GUID (`handle`).

### 3. Reader-side durability-aware history request
A late-joining reader must request history iff it is TRANSIENT_LOCAL and the matched writer is TRANSIENT_LOCAL.
On matching a writer (`%reader-matched` / the reader's writer-proxy init) + the first HEARTBEAT advertising
`[firstSN, lastSN]`:
- **TRANSIENT_LOCAL reader (matched TL writer):** expect from `firstSN` — NACK the full advertised range →
  receive the retransmitted history (the existing reader NACK path handles the gap).
- **A VOLATILE reader matched a RETAINING (non-volatile) writer → skip:** set the writer-proxy's expected base
  = `lastSN + 1` from the first HEARTBEAT → skip the retained history, NACK only future gaps. (This is the
  behavior-defining branch: a VOLATILE reader must NOT pull the retained history even though the writer
  advertises it.) **The skip is conditioned on the writer being a RETAINING writer.** *(As-built correction —
  the earlier "VOLATILE reader (or matched a VOLATILE writer) → skip" wording was WRONG: a VOLATILE writer
  RETAINS NOTHING, so everything it HEARTBEATs is LIVE; skipping to `lastSN + 1` against a VOLATILE writer
  discards live samples — T2 found this breaks reliable-zc-retransmit with silent loss. So a VOLATILE reader
  matched a VOLATILE writer must NOT skip; it behaves like any reliable reader and NACKs the live range. This
  divergence is the as-built behavior.)*
The reader's durability is its own QoS; the writer's durability comes from the matched writer's endpoint-data.

### 4. The finalize extension (OPT-IN, on top of the conformant default)
An explicit writer-side control "no more late-joiners expected" → revert the TL writer to the VOLATILE-style
full-ACK purge (drop the retained history once all current readers ACK). Primary, deterministic form:
- `durability-finalize (dw)` (DCPS) → sets a per-writer flag; `writer-purge-acked` then purges as for VOLATILE
  (the retained-for-late-joiners history is released once ACKed). Default off → standard TL (retain for
  lifetime). Docstring cites this as a non-standard extension (DDS leaves TL lifetime to the durability
  service).
- **v1-vs-defer decision (to confirm at spec review):** the explicit `durability-finalize` API is in v1
  (deterministic, no clock). The tunable retention-DURATION timer (expire retained samples by age on the
  announce-cadence sweep via `dds.pal:monotonic-ns`) is **DEFERRED to a follow-up** unless you want it in v1 —
  it adds a clock + sweep dependency for marginal extra value over the explicit finalize. (Distinct from
  LIFESPAN QoS, which remains a separate follow-up.)

## Test scenarios (oracle = the late-joiner receives exactly the retained history; both impls)
1. **Writer retention (both impls):** a TL writer publishes N; all current readers ACK; assert the HC still
   holds the samples (KEEP_ALL) / the last `depth`/instance (KEEP_LAST) — NOT purged (vs a VOLATILE writer
   whose HC purges to empty on full-ACK).
2. **Late-joiner replay our-to-our (the MVP slice, both impls):** a TL writer publishes N; THEN a TL reader
   joins; assert the late reader receives all N retained samples (via the existing HEARTBEAT/NACK/retransmit,
   driven by the firstSN proxy init). A VOLATILE late reader receives 0 of the pre-existing N (only
   future-published samples).
3. **Per-instance KEEP_LAST retention (both impls):** a TL KEEP_LAST(depth) writer; a late-joiner gets the
   last `depth` per instance, not the full history.
4. **Finalize (both impls):** after `durability-finalize`, a subsequent TL late-joiner gets NOTHING of the
   pre-finalize history (it was released on ACK); samples published AFTER finalize behave VOLATILE.
5. **RxO unchanged (regression, both impls):** a VOLATILE writer still does NOT match a TL reader (the
   existing RxO); VOLATILE default path byte-identical; `make mem` unaffected on the hot path.
6. **Cross-DDS interop (the per-feature DoD — both directions, both peers, LIVE):**
   - **Our TL writer → a late-joining Connext + Fast DDS TL reader:** start our writer, publish N, THEN start
     the foreign TL subscriber; assert it receives the N retained samples (tshark: our HEARTBEAT advertises
     [firstSN,lastSN], the foreign reader NACKs, we retransmit the history).
   - **Our late-joining TL reader ← a Connext + Fast DDS TL writer:** the foreign writer publishes N first,
     THEN our TL reader joins; assert our reader receives the N history. A VOLATILE variant receives only
     post-join samples.

## Out of scope (follow-ups)
- TRANSIENT + PERSISTENT durability (require a durability service — persistence/cloud-discovery; service suite
  out of scope).
- LIFESPAN QoS (sample expiry by age, durability-independent) — a separate follow-up (history.lisp:26 note).
- The tunable retention-DURATION timer (deferred per §4 unless pulled into v1 at spec review).

## Conformance citations
- DDS 1.4 §2.2.3.4 (DURABILITY: VOLATILE / TRANSIENT_LOCAL semantics; the writer retains + delivers to
  late-joiners for TRANSIENT_LOCAL). RTPS 2.5 §8.4.1 (writer HistoryCache), §8.4.2.2 (StatefulWriter
  push/HEARTBEAT/ACKNACK — the replay machinery). DDS 1.4 §2.2.3 (the DURABILITY RxO, already implemented).
- The finalize/deadline is a documented extension ON TOP of the conformant default (the operating contract:
  extensions only added on top, never replacing conforming behavior). The cross-DDS-interop-per-feature DoD.
- M6 exit gate: TRANSIENT_LOCAL durability + late-joiner, interop-verified both directions.
