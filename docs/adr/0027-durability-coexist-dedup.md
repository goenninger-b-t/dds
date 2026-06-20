# ADR 0027 — Cross-vendor coexistence dedup: RTI PS uses standard OWI on replay (no vendor PID needed)

- **Status:** Accepted (M6/P5; WP-DURABILITY-COEXIST-DEDUP, 2026-06-21)
- **Relates to / resolves:** ADR 0026 §10 item 1 ("cross-vendor coexistence dedup recognizing RTI's
  `PID_ENTITY_VIRTUAL_GUID`") — **this ADR resolves item 1 as *unnecessary*: the hypothesis it rested on
  is disproven on the wire.** Builds on ADR 0024 (Phase-2 dedup — standard `PID_ORIGINAL_WRITER_INFO`
  + per-origin watermark), ADR 0023 (TRANSIENT durability service). Standards: OMG DDSI-RTPS 2.5
  §8.3.5.4 (`OriginalWriterInfo`), §9.3.1.2 (EntityId kinds), DDS 1.4 §2.2.3.4 (DURABILITY RxO).
- **Spike:** `docs/superpowers/spikes/2026-06-20-rti-vendor-origin-findings.md`. **Live exercise:**
  `interop/durability-coexist-dedup/`. **Design/plan:** `docs/superpowers/specs/2026-06-20-durability-coexistence-dedup-design.md`,
  `docs/superpowers/plans/2026-06-20-durability-coexist-dedup.md`.

## Context — the hypothesis, and what the wire said

ADR 0026 §10 recorded a Phase-3b finding that "RTI Persistence Service stamps `PID_KEY_HASH` (0x0070) +
**ZERO** `PID_ORIGINAL_WRITER_INFO`" and conveys origin via its vendor `PID_ENTITY_VIRTUAL_GUID` (0x8002),
and item 1 proposed teaching our receiver dedup to recognize that vendor PID so a live dual-relay
exactly-once with RTI PS becomes exercisable.

This WP went **spike-first** to pin RTI PS's exact per-sample origin encoding before building anything.
The spike (controller-verified by independently re-decoding the captures with correct EntityId-kind
reasoning) **disproved the hypothesis**:

> **RTI PS v7.3.1 emits the OMG-standard `PID_ORIGINAL_WRITER_INFO` (0x0061), carrying the original
> Connext publisher's REAL `(GUID, SN)` — same PID, same namespace, same 24-byte LE layout our own relay
> emits and our receiver dedup already consumes — on its retained-history REPLAY to a late-joiner.**

The "ZERO OWI" Phase-3b statement was true only of RTI PS's **live-forward** path (samples it forwards
while the original writer is alive); its **retained-history replay** — the episode that matters for
dual-relay dedup — carries standard OWI. Evidence (`analyze-capture.py --owi-dump`, captures C1/C3):
RTI PS's `0x0061` origin GUID is a **captured direct user-writer** (EntityId kind `0x02` = USER_DEFINED),
i.e. the publisher itself — never a synthetic identity. The vendor `PID_ENTITY_VIRTUAL_GUID` (0x8002) and
`PID_SERVICE_KIND` (0x8003) appear once per relay endpoint in **SEDP**; they identify the relay, they are
**not** the per-sample dedup key.

## Decision — as-built

1. **No vendor per-sample PID recognition or emit is needed.** RTI PS uses the standard
   `PID_ORIGINAL_WRITER_INFO`, which our receiver dedup (`reader-dedup-accept-p`, ADR 0024) already keys on
   and which our relay already emits — **both directions**. The originally-planned `%logical-origin`
   vendor seam / vendor parse / vendor emit were **dropped as dead code** against the disproven premise.

2. **Configurable DURABILITY tiers (the one production change).** RTI PS replays its full retained history
   only to a **TRANSIENT** reader (DURABILITY RxO: offered ≥ requested; TRANSIENT rank 2 > TRANSIENT_LOCAL
   rank 1). Our durability service was TRANSIENT_LOCAL-only. Two `service-spec` `qos-overrides` were added,
   each **default `:transient-local` (byte-identical to all prior behaviour)**, opt-in `:transient`:
   - `:relay-durability` — the relay writer's DURABILITY (a TRANSIENT receiver can then match our relay).
   - `:collect-durability` — the collect reader's DURABILITY (a TRANSIENT collect reader pulls a foreign
     persistence service's OWI-stamped TRANSIENT replay and records the OWI *logical* origin, rather than
     recording the foreign relay's copies under the relay's own wire GUID).
   A durability *service* relay advertising TRANSIENT is also more semantically correct than TRANSIENT_LOCAL.

3. **Authoritative proof (deterministic, both impls).** `run-durability-no-double-delivery-test` (an alive
   writer + our relay both deliver the same N → exactly N) and the new `run-durability-multi-relay-dedup-test`
   (K standard-OWI relays of one origin `(GUID, SN)` → exactly N; distinct origin independent; reordered
   relays still exactly once). Since RTI PS is wire-proven to stamp the same standard `0x0061` tuple, to the
   dedup it is just another standard-OWI relay.

## Conformance & threat model

Standard `PID_ORIGINAL_WRITER_INFO` is the conformant and authoritative cross-relay dedup key (RTPS 2.5
§8.3.5.4); no vendor-specific behaviour was required to interoperate with RTI PS on the replay path. This
respects the OMG-conformance directive (a vendor interop behaviour would go ON TOP of, never replace,
conformant behaviour — and here none was needed). Clean-room: RTI behaviour observed on the wire only,
never its source (provenance logged).

## Live status — honest

A **live** cross-vendor dual-relay exactly-once was **not captured** in this WP. With both tiers enabled a
single TRANSIENT receiver does match **both** relays (the tier wall is gone), but the two relays' `0x0061`
origins **diverged** in the runs: RTI PS stamped the publisher's real GUID, while our relay recorded a
*different* GUID → disjoint origins → a deduping receiver saw 2N. **The divergence is on our
collect/orchestration side — it is NOT an RTI virtual-GUID wall** (RTI demonstrably uses the publisher's
real GUID) and **not a dedup-mechanism defect** (the mechanism is proven deterministically above). A
reliable live capture (one Connext publisher genuinely feeding both relays' replays + collect-origin
convergence) proved finicky to orchestrate and the residual cause was not fully pinned — recorded as a
follow-on. No false exactly-once claim is made; the authoritative proof remains the in-process tests.

## Consequences

- **NFR-MEM:** no per-sample allocation added; `make mem` stays 0.0000 (control-plane).
- **No new dependency** (SBOM dependency set unchanged); no hot-path change.
- **ADR 0026 §10 item 1 is resolved** (recognition of the vendor PID is unnecessary — RTI uses standard OWI).
- **Gates:** `make test` (SBCL + Clasp, 299 each, deterministic), `gate-hotpath`, `gate-types`, `mem`
  (0.0000), `fuzz`, `wire` — all green.

## §Follow-ons (recorded, NOT built here)

1. **Live cross-vendor exactly-once capture** — reliable one-publisher-into-both-relays orchestration +
   collect-origin convergence (our relay recording the original publisher's GUID for a foreign relay's
   OWI-stamped replay); root-cause the residual origin divergence observed in `interop/durability-coexist-dedup/`.
2. **Coexistence with a persistence service that does NOT emit standard OWI on replay** (should one exist) —
   only then would a vendor origin-id recognition (à la the original §10 item 1) be warranted.

## References

- ADR 0024 — Phase-2 dedup (standard `PID_ORIGINAL_WRITER_INFO` + bounded per-origin watermark)
- ADR 0026 — disk-backed PERSISTENT durability + §10 follow-on roadmap (item 1 resolved here)
- `docs/superpowers/spikes/2026-06-20-rti-vendor-origin-findings.md` — the spike (RTI PS uses standard OWI on replay)
- `interop/durability-coexist-dedup/` — the live coexistence exercise + the honest live status
- `src/dds-durability/{service,spec}.lisp` — `:relay-durability` / `:collect-durability` qos-overrides
- `src/dds-tests/durability-test.lisp` — `run-durability-multi-relay-dedup-test`, `run-durability-no-double-delivery-test`
