# OWNERSHIP — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development.

**Goal:** OWNERSHIP QoS in SEDP + EXCLUSIVE reader arbitration. **Spec:**
`docs/superpowers/specs/2026-06-13-ownership-design.md`. Wire form pinned from the Fast DDS oracle
(`interop/fastdds/captures/ownership-sedp-lo0.pcap` frame 64): PID_OWNERSHIP `1f 00 04 00 | 01 00 00
00` (kind EXCLUSIVE=1 / SHARED=0, u32 LE); PID_OWNERSHIP_STRENGTH `06 00 04 00 | 11 00 00 00`
(value 17, u32 LE). Staged S0 wire codec → S1 arbitration → S2 live.

---

### Task S0.1: PID_OWNERSHIP + PID_OWNERSHIP_STRENGTH wire codec

**Files:** `src/dds-rtps/message.lisp`, `src/dds-rtps/packages.lisp`,
`src/dds-rtps/discovery.lisp`, `src/dds-tests/rtps-test.lisp`, `src/dds-tests/echo-test.lisp`,
`docs/verification.csv`, `docs/wiki/discovery.md`.

- [ ] **Step 1 — failing locked-vector test.** `run-ownership-codec-test`: serialize an endpoint-data
  whose writer qos = (:ownership :exclusive :ownership-strength 17); assert the param list CONTAINS
  `1f 00 04 00  01 00 00 00` and `06 00 04 00  11 00 00 00` (the oracle bytes). Parse a minimal
  endpoint-data carrying those → qos-ownership :exclusive, qos-ownership-strength 17. A :shared
  endpoint → kind 0; a reader role emits PID_OWNERSHIP but NOT PID_OWNERSHIP_STRENGTH. Register
  `ownership-codec` in echo-test.lisp.
- [ ] **Step 2 — run, expect fail.**
- [ ] **Step 3 — constants.** `+pid-ownership+` `#x001f` + `+pid-ownership-strength+` `#x0006`
  (message.lisp, docstrings cite RTPS 2.5 §9.6.2.2 / DDS 1.4 §2.2.3.9-.10). Export.
- [ ] **Step 4 — serialize.** In `serialize-endpoint-data` (after PID_DURABILITY/LIVELINESS): emit
  PID_OWNERSHIP len 4 = (case (qos-ownership qos) (:exclusive 1) (t 0)) u32 LE, ALWAYS. Emit
  PID_OWNERSHIP_STRENGTH len 4 = (qos-ownership-strength qos) u32 LE ONLY for a WRITER role (strength
  is writer-only, DDS 1.4 §2.2.3.10). Determine the role: check how serialize-endpoint-data knows
  writer-vs-reader (the parser uses a role; if the serializer lacks it, thread it, or emit strength
  unconditionally and note it — but PREFER writer-only per spec).
- [ ] **Step 5 — parse.** In `parse-endpoint-data`/`%fill-endpoint-param`: PID_OWNERSHIP (len 4) →
  qos-ownership (0→:shared, 1→:exclusive, unknown→:shared, never reject); PID_OWNERSHIP_STRENGTH
  (len 4) → qos-ownership-strength. Bounds-check (NFR-SEC-POSTURE).
- [ ] **Step 6 — green + gates + RxO check.** test-sbcl + gate-types + gate-hotpath + Clasp. CONFIRM
  the existing RxO ownership-equality test still passes AND that emitting PID_OWNERSHIP for default
  :shared endpoints does not break any existing match (default reader+writer both :shared → equal →
  compatible; existing SEDP/dataplane/Connext-friendly tests green). A Fast DDS EXCLUSIVE writer vs
  our default SHARED reader will now (correctly) NOT match — that is the conformant RxO behaviour.
- [ ] **Step 7 — byte-validate vs oracle + docs.** Lock the oracle bytes; verification.csv row;
  wiki discovery.md PID list.

### Task S0.2 done when the codec byte-matches the oracle and RxO is non-regressed.

---

## Stage S1 — EXCLUSIVE reader arbitration (outline; refine after S0)
- Extend `instance-rec` with `owner-guid` + `owner-strength`. Owner = highest-strength ALIVE writer.
- Record the source GUID per sample (extend the engine's sample-writers SN→writer to carry the full
  16-octet GUID, not just the EntityId) + a helper `matched-writer-ownership node guid → (kind strength)`
  from the `matches` table.
- `%drain-one-sample` (EXCLUSIVE reader only): fetch source strength; deliver + take ownership if no
  owner or source strength > owner (tie → higher GUID wins, documented); else DROP (no enqueue).
  SHARED unchanged.
- Owner takeover: `%on-writer-vanished` (+ dispose/unregister/liveliness-loss of the owner) clears
  `owner-guid`; next sample from the highest alive writer reclaims it (lazy recompute).
- Tests: strengths 10/20 → EXCLUSIVE reader delivers only 20; kill 20 → 10 takes over; SHARED
  delivers both; RxO EXCLUSIVE-writer vs SHARED-reader no-match.

## Stage S2 — live interop
- Fast DDS two EXCLUSIVE writers (strengths) → our EXCLUSIVE reader delivers only the owner's, takeover
  on kill; our EXCLUSIVE writer+strength → Fast DDS EXCLUSIVE reader. Capture; provenance.

**Two reviews per task. Byte-validate S0 vs the oracle before S1.**
