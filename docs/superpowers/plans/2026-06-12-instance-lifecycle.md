# Instance lifecycle — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development.

**Goal:** dispose / unregister_instance + reader instance_state (ALIVE / NOT_ALIVE_DISPOSED /
NOT_ALIVE_NO_WRITERS) in SampleInfo. **Spec:**
`docs/superpowers/specs/2026-06-12-instance-lifecycle-design.md` (wire form RESOLVED vs the Fast DDS
oracle: a DATA with flags E+Q, no payload, inlineQos = PID_KEY_HASH + PID_STATUS_INFO).

Staged: S0 wire codec → S1 writer → S2 reader → S3 live interop. S1–S3 tasks are refined after S0
locks the API; the outlines below are firm on intent.

---

## Stage S0 — wire codec (foundation)

### Task S0.1: PID_STATUS_INFO + StatusInfo_t constants + inline-QoS ParameterList

**Files:** `src/dds-rtps/message.lisp`, `src/dds-rtps/packages.lisp`,
`src/dds-tests/rtps-test.lisp`, `src/dds-tests/echo-test.lisp`.

- [ ] **Step 1 — failing locked-vector test.** In rtps-test.lisp add `run-status-info-codec-test`:
  build the dispose inlineQos ParameterList for a known 16-octet key-hash + Disposed, assert the
  emitted bytes equal the oracle subsequence `70 00 10 00 <keyhash×16> 71 00 04 00 00 00 00 01
  01 00 00 00` (PID_KEY_HASH + PID_STATUS_INFO{0,0,0,1} + sentinel); parse them back → (values
  key-hash status-flags) = (keyhash, Disposed). Also the unregister `00 00 00 02` case. Register
  `status-info-codec` in echo-test.lisp.
- [ ] **Step 2 — run, expect fail.**
- [ ] **Step 3 — constants.** `+pid-status-info+` `#x0071` (cite RTPS 2.5 §9.6.3.9) +
  `+statusinfo-disposed+` `#x01` / `+statusinfo-unregistered+` `#x02` / `+statusinfo-filtered+`
  `#x04` (StatusInfo_t octet[4], flags in the last octet, big-endian like the WLP kind). Export from
  packages.lisp. `+pid-key-hash+` 0x0070 already exists.
- [ ] **Step 4 — inlineQos build/parse.** FIRST check the CURRENT inlineQos handling in
  `parse-data-body` / the disc `%handle-datagram` (commit ac780cc added keyed-sample PID_KEY_HASH
  parse — confirm what exists; do not duplicate). Add: a `build-inline-qos` that writes a
  ParameterList {PID_KEY_HASH(16), PID_STATUS_INFO(4)} + PID_SENTINEL; a `parse-inline-qos` that
  decodes a Q-flag ParameterList → (values key-hash status-flags), bounds-checked (NFR-SEC-POSTURE,
  ignore unknown PIDs, stop at sentinel). StatusInfo_t parsed big-endian octet[4].
- [ ] **Step 5 — dispose/unregister DATA.** Extend `write-data` (or a `write-data-dispose`) to emit
  the resolved form: flags E+Q, D clear, K clear, no serializedPayload, inlineQos = key-hash +
  status-info. `parse-data-body` returns the change-kind (`:data` | `:dispose` | `:unregister`,
  derived from the parsed StatusInfo flags) + the key-hash.
- [ ] **Step 6 — green + gates.** test-sbcl + gate-types + gate-hotpath + Clasp. The existing
  keyed-sample / DATA tests MUST stay green (regular keyed samples still carry PID_KEY_HASH).

### Task S0.2: byte-validate vs the Fast DDS oracle
- [ ] Lock the oracle dispose bytes (`interop/fastdds/captures/instance-dispose-lo0.pcap` frame 91)
  as a regression vector: our `parse-data-body` decodes Fast DDS's dispose DATA → :dispose +
  key-hash; our emitter reproduces the inlineQos byte-exact. Provenance entry.

---

## Stage S1 — writer side (outline; refine after S0)

- Per-writer **instance registry**: handle (16-octet key-hash) → state (alive/disposed/unregistered),
  on the `rtps-writer` or `data-writer`. `write` registers the instance ALIVE.
- DCPS API on `data-writer` (`src/dds-dcps/entities.lisp`): `register-instance sample → handle`;
  `dispose-instance dw (sample|handle)`; `unregister-instance dw (sample|handle)`. Compute the
  key-hash via the type-support key-hash (`%instance-handle`).
- Route through `CacheChange` `:dispose`/`:unregister` (kind already exists in history.lisp) → a disc
  `dispose-instance` / publish path that sends the S0 dispose/unregister DATA (key-hash +
  status-info) over the reliable writer (it occupies a real SN so it's reliable + repairable).
- Export the API; docstrings cite DDS 1.4 §2.2.2.4.2.

## Stage S2 — reader side (outline; refine after S0)

- The reader decodes an inbound dispose/unregister DATA (S0) → resolves the instance by the inbound
  PID_KEY_HASH → updates a per-instance state in the reader → sets `SampleInfo.instance_state`
  (`:not-alive-disposed` / `:not-alive-no-writers`) + bumps `disposed_generation_count` /
  `no_writers_generation_count` (DDS 1.4 §2.2.2.5). A dispose/unregister surfaces as a SampleInfo
  with `valid_data = false` (no sample payload).
- **NOT_ALIVE_NO_WRITERS:** when the last matched writer of an instance unregisters, OR all matched
  writers unmatch (tie into the on-unmatch hook from the lease-expiry feature), the instance →
  NO_WRITERS.
- Tests: a dispose DATA → reader reports `:not-alive-disposed`; an unregister → behaviour per spec.

## Stage S3 — live interop (wire-is-oracle)

- Fast DDS: `DISPOSE_AFTER`/`UNREGISTER_AFTER` (already added to shapes_pub) → our reader reports
  NOT_ALIVE_DISPOSED; our writer disposes → Fast DDS reader sees it (capture). Connext: same with a
  keyed Connext writer disposing. Lock vectors; provenance; verification.csv; README/wiki.

**Two reviews per task. S0 is the wire foundation — get it byte-exact vs the oracle before S1.**
