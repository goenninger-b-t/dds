# WP-DURABILITY-COEXIST-LIVE — design

- **Status:** Approved (design), 2026-06-21. M6/P5. Resolves ADR 0027 §follow-on 1.
- **Relates to:** ADR 0027 (cross-vendor coexistence dedup — RTI PS uses standard OWI on replay; the
  `:relay-durability`/`:collect-durability` tiers), ADR 0024 (Phase-2 dedup — standard
  `PID_ORIGINAL_WRITER_INFO` + per-origin watermark), ADR 0026 (PERSISTENT durability).
- **Standards:** OMG DDSI-RTPS 2.5 §8.3.5.4 (`OriginalWriterInfo` / relay transparency), §9.3.1.2
  (EntityId kinds), DDS 1.4 §2.2.3.4 (DURABILITY RxO).

---

## 1. Problem — the confirmed root cause

ADR 0027 left one honest gap: a **live** cross-vendor dual-relay exactly-once (our durability service +
RTI Persistence Service both relaying one Connext publisher to one late-joiner) was never captured because
the two relays' standard `PID_ORIGINAL_WRITER_INFO` (0x0061) origins **diverged** — RTI PS stamped the
publisher's real GUID, our relay stamped a different GUID. ADR 0027 recorded the divergence as "our
collect/orchestration side, not an RTI wall, not a dedup defect," cause not fully pinned.

It is now pinned, and it is a **real product bug on the data path** (not a harness artifact):

The disc-node receive path **already computes the logical origin**. `%deliver-user-sample` and
`%deliver-user-marker` (`src/dds-disc/dataplane.lisp`) take `effective-guid`/`effective-sn`, documented in
place as *"the logical-origin GUID+SN — orig-guid/orig-sn on the relay path; wire GUID+SN on the direct
path, per RTPS 2.5 §8.3.5.4."* The receiver-side dedup (`reader-dedup-accept-p`) is keyed on
`effective-guid`; that is why no-double-delivery already works.

**But the per-sample store tables (dataplane.lisp ~1312-1314 / ~1337-1339) record the wire sender GUID, not
`effective-guid`.** `node-sample-writer-guid` returns the wire sender. So `%collect-loop`
(`src/dds-durability/service.lisp` ~220-228) re-stamps the relayed OWI from the wire sender:

1. A logical sample is delivered once (dedup collapses the publisher-direct copy and RTI PS's relayed copy
   on `effective-guid`).
2. It is **stored under whichever wire sender arrived first.** When the collect reader runs at `:transient`
   it also matches RTI PS's TRANSIENT replay; if RTI PS's relayed copy wins the arrival race, the stored
   wire GUID is RTI PS's relay GUID → our relay re-stamps OWI under RTI PS's relay GUID, not the publisher
   → the divergence, **nondeterministic by arrival order.**

The **lifecycle path already does this correctly** — `%collect-loop`'s lifecycle drain uses `orig-guid`
(the incoming OWI origin) for re-emit. Only the **data** path uses the wire sender. So `:collect-durability
:transient` (ADR 0027) shipped as a half-fix: it made the collect reader match RTI PS but never carried the
incoming OWI through to the data-path re-stamp.

## 2. Goal

Carry the already-computed logical origin through the data path so a durability relay collecting from a
foreign OWI-stamping persistence service re-stamps the **original publisher's** logical origin, not the
foreign relay's wire GUID. Prove convergence deterministically in-process, then **capture it live
cross-vendor** (both relays' wire OWI = the publisher's GUID; the late-joiner collapses two relay streams
to exactly N).

## 3. Approaches considered

- **A — Expose + use the already-computed effective origin (chosen).** Persist `effective-guid`/
  `effective-sn` per sample, expose accessors, and have `%collect-loop` re-stamp/store/dedup from the
  effective origin. Smallest; deterministic; mirrors the lifecycle path that already does this; default/
  direct path byte-identical.
- **B — Re-parse the incoming OWI inside the durability layer.** Duplicates the inline-QoS OWI parse the
  receive path already performs (`parse-original-writer-info`, `message.lisp`) → DRY violation, more
  surface, identical result. Rejected.
- **C — Harness-only (make the publisher-direct copy always win the arrival race).** Fragile,
  nondeterministic, leaves the gap in the product. The "grind the harness" path the owner declined.
  Rejected.

## 4. Design (Approach A)

### 4.1 `dds-disc` (dataplane.lisp) — capture the logical origin per sample

The effective origin is in hand at both delivery sites. Record it **only when it differs from the wire
sender** (i.e. an OWI was present), through one shared setter, in a new per-(wire-guid → SN) inner table
`disc-node-sample-origins` alongside the existing samples / writers / writer-guids tables. Direct-path
samples (no foreign relay — the common case) store nothing extra → **byte-identical, zero extra
allocation.**

New exported accessors:
- `node-sample-origin-guid (node key) → (simple-array (unsigned-byte 8) (16))` — the **logical origin
  GUID**: the recorded effective origin when an OWI was present, else the wire guid. Always defined (never
  NIL), so callers use it directly as the logical origin.
- `node-sample-origin-sn (node key) → integer` — the logical origin SN: the effective SN when an OWI was
  present, else the wire SN.

Set symmetrically in `%deliver-user-sample` (copy path, used by durability) and `%deliver-user-marker`
(ZC-loan path) for API correctness, via one shared helper (DRY).

This is **control-plane** — the disc-node relay store, not the measured CDR hot path — so the existing
per-sample table cost applies and `gate-hotpath` is unaffected. NFR-MEM `make mem` (CDR hot path) stays
0.0000.

### 4.2 `dds-durability` (`%collect-loop`) — re-stamp from the logical origin

Data drain resolves the origin once per sample:
```
(let* ((origin-guid (dds.disc:node-sample-origin-guid node key))   ; logical origin (effective else wire)
       (origin-sn   (dds.disc:node-sample-origin-sn   node key)))
  ... use origin-guid/origin-sn for the dedup key, store-put, and publish-relay-sample ...)
```
The accessor returns the wire guid/sn when no OWI was present → byte-identical to current behaviour. This is
the data-path symmetry of the lifecycle drain that already uses `orig-guid`.

### 4.3 Harness hardening (`interop/durability-coexist-dedup`)

One Connext publisher → both relays → one late-joiner; deterministic discovery (fixed ports + SPDP peering,
settle-to-fixpoint poll). Extend `analyze-capture.py` to **assert**: both relays' replayed DATA carry wire
OWI = the publisher's GUID, and the late-joiner received exactly N distinct origins (not 2N). Flip the
harness/driver headers and README from "live not captured" to the captured result.

### 4.4 Data flow

Publisher writes N → our relay collects direct (no OWI → origin G_pub) **and** via RTI PS (OWI = G_pub →
origin G_pub), dedups to one G_pub on `effective-guid`, stores under G_pub (the fix), re-stamps OWI =
G_pub; RTI PS independently stamps OWI = G_pub → the late-joiner dedups both relay streams on G_pub →
exactly N.

## 5. Threat model & conformance

Honoring the incoming OWI is consistent with ADR 0024 (the receiver-side dedup already trusts OWI) and with
RTPS §8.3.5.4 relay transparency (`OriginalWriterInfo` identifies the original writer of a relayed sample).
No new trust surface: a durability service collecting from a foreign persistence service already trusts that
service's replay; the OWI it stamps is the origin we propagate. The OWI parse is bounds-checked (a 0x0061
body not exactly 24 octets is ignored, never trusted — `parse-original-writer-info`). Clean-room: RTI
behaviour observed on the wire only.

## 6. Testing — live-gated Definition of Done

The merge gate **requires** the live capture; the deterministic in-process tests are necessary but not
sufficient.

1. **Unit (dds-disc):** an OWI-bearing sample → `node-sample-origin-guid` returns the OWI GUID, not the
   wire sender; a direct sample (no OWI) → returns the wire GUID (byte-identical).
2. **In-process convergence (dds-durability):** drive a collect node with two wire senders carrying the
   **same** OWI origin → the relay stores **one** converged origin = the OWI GUID and re-stamps OWI = it
   (the deterministic convergence proof).
3. **Regression:** `run-durability-multi-relay-dedup-test`, `run-durability-no-double-delivery-test`,
   `run-durability-relay-tier-test`, `run-durability-collect-tier-test` stay green; the default/direct
   path is byte-identical (no OWI → effective = wire).
4. **LIVE (the gate):** `interop/durability-coexist-dedup/run-coexist-both.sh` both directions →
   the capture shows both relays' wire OWI = the publisher GUID; direction (a) our-stack reader and
   direction (b) Connext `shapes_sub` each receive exactly N; documented with the real capture figures.
5. **All quality gates green both impls (Clasp first):** `make test` (SBCL + Clasp, deterministic),
   `gate-hotpath`, `gate-types`, `mem` (0.0000), `fuzz`, `wire`.

## 7. Decomposition (subagent-driven)

- **T1 — disc-node logical-origin capture.** `disc-node-sample-origins` table + shared setter in
  `%deliver-user-sample`/`%deliver-user-marker` + `node-sample-origin-guid`/`node-sample-origin-sn`
  accessors (exported) + unit test (OWI-bearing vs direct). Control-plane; `gate-hotpath` unaffected.
- **T2 — `%collect-loop` uses the logical origin.** Origin resolution for dedup key + `store-put` +
  `publish-relay-sample`; in-process convergence test (two wire senders, same OWI → one converged origin);
  regressions green.
- **T3 — live capture (the gate).** Harness hardening (deterministic discovery, settle-to-fixpoint) +
  `analyze-capture.py` convergence assertion + the live capture both directions, with figures.
- **T4 — capstone.** ADR 0028 (data-path origin-stamping completes `:collect-durability`; resolves ADR
  0027 §follow-on 1) + docs lockstep (README P5, wiki durability, verification.csv, harness/driver headers
  flipped to captured) + final whole-branch review → squash-merge presented for owner approval (HOLD PUSH).

## 8. Risks

- **Live-gated blocking risk (moderate-to-high confidence the capture passes):** the divergence WAS this
  bug, so with the origin converged the live capture is expected to succeed; but loopback discovery on this
  host is independently flaky and tshark cannot dissect lo0 DLT_NULL (figures parsed from raw packet
  bytes). If the capture proves unreliable despite the fix, escalate to the owner — do not silently
  downgrade the gate.
- **Arrival-order independence:** the fix converges the origin regardless of which wire copy arrives first
  (RTI PS's relayed copy carries OWI = G_pub), so convergence does not depend on harness race tuning.

## 9. Non-negotiables (inherited)

- No hot-path CLOS / per-sample alloc; the change is control-plane (disc-node relay store). `gate-hotpath`
  + `make mem` 0.0000 unaffected.
- `defun*`/`defstruct*` + full ftype declarations on every new function.
- No wire constants from memory — OWI layout pinned from RTPS 2.5 §8.3.5.4, already in
  `parse-original-writer-info`.
- Bounds-check the OWI parse even at `(safety 0)` — already done; reused, not re-implemented.
- No reader conditionals outside `dds-pal/`. Clasp + SBCL both validate, Clasp first.
- No AI / assistant attribution in any repo file.

## 10. References

- ADR 0027 — cross-vendor coexistence dedup (RTI PS uses standard OWI on replay; the tiers; §follow-on 1
  resolved here).
- ADR 0024 — Phase-2 dedup (standard `PID_ORIGINAL_WRITER_INFO` + bounded per-origin watermark).
- `src/dds-disc/dataplane.lisp` — `%deliver-user-sample`/`%deliver-user-marker` (`effective-guid`/
  `effective-sn`), per-sample store tables, `node-sample-*` accessors.
- `src/dds-durability/service.lisp` — `%collect-loop` (data drain + lifecycle drain `orig-guid`
  precedent).
- `src/dds-rtps/message.lisp` — `parse-original-writer-info`, inline-QoS OWI parse.
- `interop/durability-coexist-dedup/` — the live coexistence harness + `analyze-capture.py`.
