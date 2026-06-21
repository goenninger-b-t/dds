# ADR 0028 — Cross-vendor dual-relay exactly-once: live-captured convergence via logical-origin capture in the collect path

- **Status:** Accepted (M6/P5; WP-DURABILITY-COEXIST-LIVE, 2026-06-21)
- **Resolves:** ADR 0027 §follow-on 1 (live cross-vendor dual-relay exactly-once capture +
  collect-origin convergence). Builds on ADR 0027 (cross-vendor coexistence dedup — RTI PS uses
  standard `PID_ORIGINAL_WRITER_INFO`), ADR 0024 (Phase-2 dedup — standard `PID_ORIGINAL_WRITER_INFO`
  + per-origin watermark), ADR 0023 (TRANSIENT durability service). Standards: OMG DDSI-RTPS 2.5
  §8.3.5.4 (`OriginalWriterInfo` relay transparency), §9.3.1.2 (EntityId kinds), DDS 1.4 §2.2.3.4
  (DURABILITY RxO).

## Context — the divergence diagnosed in ADR 0027

ADR 0027 §follow-on 1 documented a residual origin divergence observed in the live coexistence runs:
RTI Persistence Service stamped the publisher's real GUID (EntityId kind `0x02`, USER_DEFINED) on its
retained-history replay via `PID_ORIGINAL_WRITER_INFO (0x0061)`, while **our relay recorded a
different GUID**. With divergent `(origin-GUID, SN)` pairs the receiver's dedup saw two distinct
origins and delivered 2N instead of N.

The ADR 0027 hypothesis: achieving live convergence requires (a) one publisher feeding both relays
and (b) our collect path recording the *original publisher's GUID* for a foreign relay's OWI-stamped
replay.

## Root cause

The disc-node receive path already computed the logical origin — `effective-guid` = OWI origin when
the incoming DATA carries `PID_ORIGINAL_WRITER_INFO`, else the wire sender — and the **receiver dedup
already keyed on it** (`reader-dedup-accept-p`, ADR 0024). The failure was in the collect path:

> The per-sample STORE recorded the **wire sender** (the relay's GUID), not the OWI logical origin.
> `%collect-loop` re-stamped a relayed OWI sample from the wire sender, so when RTI PS's TRANSIENT
> replay won the arrival race our relay stored RTI PS's relay GUID (`0x80000002`), not the original
> publisher's GUID. The two relays diverged by arrival order — a nondeterministic race.

The lifecycle drain path already did this correctly (`orig-guid` from `node-sample-origin-guid`).
Only the data path was wrong.

## Decision — as-built

### Data path: logical-origin capture (Task 1 + Task 2)

1. **Task 1** added a per-sample logical-origin capture to `disc-node`:
   - A `sample-origins` slot (a hash-table keyed by `(writer-guid . sn)`) records, for each received
     sample, the effective origin `(GUID, SN)` — the OWI origin when the DATA carries
     `PID_ORIGINAL_WRITER_INFO`, else the wire guid/sn. Populated by `%record-sample-origin`
     immediately on `on-data`.
   - Exported accessors: `node-sample-origin-guid (node key)` →
     `(simple-array (unsigned-byte 8) (16))` and `node-sample-origin-sn (node key)` → `integer`.
   - The default/direct path (no OWI) is byte-identical: effective = wire → no observable change for
     non-relay DATA.

2. **Task 2** made `%collect-loop` re-stamp the logical origin:
   - For each incoming sample the loop now reads `node-sample-origin-guid` / `node-sample-origin-sn`
     (the OWI logical origin when relayed, the wire guid/sn otherwise) and uses that pair as the
     `store-put` key (writer-guid + sn) AND the dedup key (`%collect-seen-p` / `%collect-mark-seen!`).
   - The control-plane (gate-hotpath + mem 0.0000) is unaffected. Mirrors the lifecycle precedent.

### In-process convergence proof (Task 2)

`run-durability-collect-origin-convergence-test` runs the convergence scenario in-process with
injected arrival orders (direct-first then relay-first, and relay-first then direct-first): in both
cases the store ends up containing exactly one record stamped with the publisher's OWI origin GUID.

### Live capture (Task 3 — the headline, ADR 0027 §follow-on 1 resolved)

With the fix in, the live cross-vendor dual-relay exactly-once **converged on the FIRST attempt
each direction**:

**Direction (a) — our-stack reader as the late-joining receiver:**
- Publisher: one Connext TRANSIENT writer (EntityId `0x80000002` — shares the EntityId value with RTI PS but a distinct GUID prefix; full GUID `0101642e5f4294116dd106b480000002`).
- Relay 1: RTI Persistence Service v7.3.1 (EntityId `0x80000002`).
- Relay 2: our durability service (EntityId `0x00000102` on the replay writer).
- Both relays stamped `PID_ORIGINAL_WRITER_INFO` with **origin GUID
  `0101642e5f4294116dd106b480000002`** (the publisher's real GUID, EntityId kind `0x02`).
- Our reader delivered **N = 545**. UNION = 545. Naïve 2-relay sum = 1090.
- Capture: `interop/durability-coexist-dedup/captures/coexist-dir-a.pcap`.

**Direction (b) — Connext `shapes_sub` as the late-joining receiver:**
- Publisher: one Connext TRANSIENT writer (EntityId `0x80000002` — shares the EntityId value with RTI PS but a distinct GUID prefix; full GUID `01017344014e53c9630ac19e80000002`).
- Relay 1: RTI Persistence Service v7.3.1 (EntityId `0x80000002`).
- Relay 2: our durability service (EntityId `0x00000102` on the replay writer).
- Both relays stamped `PID_ORIGINAL_WRITER_INFO` with **origin GUID
  `01017344014e53c9630ac19e80000002`** (the publisher's real GUID, EntityId kind `0x02`).
- Connext `shapes_sub` received **N = 550**. UNION = 550. Naïve sum = 1100.
- Capture: `interop/durability-coexist-dedup/captures/coexist-dir-b.pcap`.

`analyze-capture.py --assert-converged` exits 0 on both captures.

Both relays' wire `PID_ORIGINAL_WRITER_INFO` carry the same origin GUID (the publisher's) in both
directions, confirming the fix: the receiver's dedup collapsed the two relay streams to exactly N.

## Conformance and threat model

- Honoring incoming OWI is consistent with **ADR 0024** (the receiver dedup already trusts OWI on
  the read path; the collect path now respects the same principal). It mirrors **RTPS 2.5 §8.3.5.4**
  relay transparency: a relay MUST forward `OriginalWriterInfo` so that a downstream deduplicator
  can identify the true origin regardless of how many relay hops intervene.
- No new trust surface: the OWI parse was already bounds-checked (the `%fill-original-writer-info`
  parser, NFR-SEC-POSTURE). The logical-origin lookup is a dict read after parse; it cannot extend
  the wire-input attack surface.
- Clean-room: RTI Persistence Service observed on the wire only (provenance logged). No RTI source,
  headers, or generated code used.

## Consequences

- **NFR-MEM:** no per-sample heap allocation added; `make mem` stays 0.0000 (control-plane).
- **No new dependency** (SBOM dependency set unchanged); no hot-path change.
- **ADR 0027 §follow-on 1 is resolved**: the live cross-vendor dual-relay exactly-once is captured
  for both directions (N=545 dir-a, N=550 dir-b; `analyze-capture.py --assert-converged` exits 0).
- **ADR 0027 §follow-on 2 remains open**: coexistence with a persistence service that does NOT emit
  standard `PID_ORIGINAL_WRITER_INFO` on its retained-history replay (only then would a vendor
  origin-id recognition be warranted — this WP found no such peer; RTI PS uses standard OWI).
- **Gates:** `make test` (SBCL + Clasp, 301 each, deterministic), `gate-hotpath`, `gate-types`,
  `mem` (0.0000), `fuzz`, `wire` — all green.

## §Follow-on (recorded, NOT built here)

**Coexistence with a persistence service that does NOT emit standard OWI on replay** (ADR 0027
§follow-on 2) — if such a peer exists, a vendor origin-id recognition seam would be warranted.
No known peer of this kind has been observed; this is a contingent item.

## References

- ADR 0024 — Phase-2 dedup (standard `PID_ORIGINAL_WRITER_INFO` + bounded per-origin watermark)
- ADR 0026 — disk-backed PERSISTENT durability + §10 follow-on roadmap
- ADR 0027 — cross-vendor coexistence dedup: RTI PS uses standard OWI; honest live status;
  `:relay-durability`/`:collect-durability` tiers; §follow-on 1 = this ADR
- `docs/superpowers/spikes/2026-06-20-rti-vendor-origin-findings.md` — the spike (RTI PS uses
  standard OWI on replay)
- `interop/durability-coexist-dedup/` — live coexistence harness + captured dir-a/dir-b pcaps
- `src/dds-disc/disc.lisp` — `sample-origins` struct slot; `src/dds-disc/dataplane.lisp` — `%record-sample-origin` setter + exported accessors `node-sample-origin-guid` / `node-sample-origin-sn`
- `src/dds-durability/service.lisp` — `%collect-loop` logical-origin re-stamp
- `src/dds-tests/durability-test.lisp` — `run-durability-collect-origin-convergence-test`
