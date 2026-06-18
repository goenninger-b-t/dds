# WP-DATA-REPRESENTATION Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** (Step 1) emit + parse PID_DATA_REPRESENTATION (0x0073) in SEDP, advertise our endpoints' true representations, match on real values via the existing RxO check. (Step 2) make the writer serialize + send in its OFFERED representation (XCDR1-LE or XCDR2-LE), not always XCDR2-LE.

**Architecture:** The QoS field (`data-representation`), the RxO rule, and the policy-id-23 INCOMPATIBLE_QOS mapping already exist. This WP adds the SEDP wire emit/parse, reconciles the role-aware QoS defaults to the truth (reader `(:xcdr2 :xcdr1)`, writer `(:xcdr2)`), and threads the writer's offered rep into the serializer. The `DataRepresentationId_t` wire values + the `sequence<short>` encoding are pinned from DDS-XTypes 1.3 §7.6.3.1.1 AND verified against a live Connext/Fast DDS SEDP capture (wire-is-oracle).

**Tech Stack:** Common Lisp (SBCL + Clasp), `dds.qos`/`dds.rtps`/`dds.disc`/`dds.gen`/`dds.dcps`, `defun*`/`defstruct*` + full types (FR-LANG-8), the interop harness (Connext rtiddsgen + Fast DDS `scripts/with-fastdds.sh`), tshark.

**Spec:** `docs/superpowers/specs/2026-06-17-wp-data-representation-design.md` (read it).

**Conventions (NON-NEGOTIABLE):** one-line code comments; full type declarations; docstrings on new exported symbols (§5.1) citing the clause; NEVER hardcode a wire value from memory — pin from §7.6.3.1.1 + a capture; bounds-check the SEDP parse even at `(safety 0)` (NFR-SEC-POSTURE); fail-open on an unknown rep (never false-REJECT the SEDP); NO `#+sbcl/#+clasp` outside `dds-pal/`; NO AI/Claude/co-author attribution; clean-room; SBOM auto-staged.

---

## Task 1: Wire-oracle + PID_DATA_REPRESENTATION emit/parse (step-1 MVP slice)

The thinnest end-to-end slice: the PID round-trips through SEDP, byte-exact against the spec clause + a real peer.

**Files:**
- Modify: `src/dds-rtps/message.lisp` (add `+pid-data-representation+`), `src/dds-rtps/packages.lisp` (export it).
- Modify: `src/dds-rtps/discovery.lisp` (the `%data-rep-wire`/`%wire-data-rep` helpers near the other wire helpers ~438-459; the emit in `serialize-endpoint-data` ~485-553; the parse in `%fill-endpoint-param` ~555-609; extend `run-sedp-test` ~646).
- Create: `interop/data-representation/captures/` + a notes file pinning the observed wire format.

- [ ] **Step 1: Capture the wire-oracle (do this FIRST).** Run a Connext participant (and a Fast DDS one) with a reader+writer on a simple type; tshark-capture the SEDP (DiscoveredReaderData/WriterData) on lo0 (clean `WIRESHARK_CONFIG_DIR=$(mktemp -d)`). Locate PID_DATA_REPRESENTATION (0x0073) and record its EXACT bytes: the u32 count, the `short` rep values, the alignment/padding, endianness (PL_CDR_LE). Confirm the `DataRepresentationId_t` enum values (XCDR/XML/XCDR2) against BOTH the §7.6.3.1.1 clause text AND the capture. Save the capture + a notes file `interop/data-representation/captures/NOTES.md` with the pinned layout. **Use these VERIFIED values in Steps 3-4 — do not trust any value from memory or this plan.**

- [ ] **Step 2: Write the failing round-trip test.** Extend `run-sedp-test` (discovery.lisp ~646) to build an endpoint-data with `data-representation '(:xcdr2 :xcdr1)`, serialize → parse, assert the list round-trips. Run `make test-sbcl` → FAIL (nothing emits/parses the PID; the parsed value is the default).

- [ ] **Step 3: Add the PID constant + helpers.** In `message.lisp` (~719): `(defconstant +pid-data-representation+ #x0073 "PID_DATA_REPRESENTATION (DDS-XTypes 1.3 §7.6.3.1.1; the DataRepresentationQosPolicy value = sequence<DataRepresentationId_t>).")`; export in `packages.lisp`. In `discovery.lisp`, add `%data-rep-wire (kw)` → the VERIFIED `short` (e.g. `:xcdr1`→0, `:xml`→1, `:xcdr2`→2 — confirm) and `%wire-data-rep (short)` → keyword (unknown → NIL), both `defun*`-typed, docstring citing §7.6.3.1.1.

- [ ] **Step 4: Emit in `serialize-endpoint-data`.** After an existing PID (e.g. PID_RELIABILITY), emit PID_DATA_REPRESENTATION as a `sequence<short>`: `%make-scratch` of `4 + 2*N` (+ pad to 4); `put-u32` the count; `put-u16`/`put-i16` each `(%data-rep-wire rep)` for rep in `(qos-data-representation (endpoint-data-qos data))`; pad; `write-parameter +pid-data-representation+`. Emit for BOTH readers and writers. Mirror the PID_RELIABILITY idiom exactly (discovery.lisp:506-511).

- [ ] **Step 5: Parse in `%fill-endpoint-param`.** On `+pid-data-representation+` with `len >= 4`: read the u32 count; **bounds-check** `(<= (+ 4 (* 2 count)) len)` (NFR-SEC-POSTURE — a forged count must not over-read; on violation skip the PID, do not error the whole SEDP); read `count` shorts; map each via `%wire-data-rep` (drop NIL/unknown — fail-open); store the non-empty list into `(qos-data-representation (endpoint-data-qos data))`. Absent PID → leave the default.

- [ ] **Step 6: Run the round-trip test → pass.** `make test-sbcl`. Fix until green.

- [ ] **Step 7: Add the byte-exact test.** A test asserting the emitted PID bytes equal the pinned §7.6.3.1.1 layout (count + shorts + pad) for `(:xcdr2 :xcdr1)`, matching the captured oracle. Register it.

- [ ] **Step 8: Both impls + commit.** `make test-sbcl` + `make test-clasp` green.
```bash
git add -A
git commit -m "feat(rtps): WP-DATA-REPRESENTATION emit + parse PID_DATA_REPRESENTATION in SEDP, byte-exact vs the live oracle (DDS-XTypes 1.3 §7.6.3.1.1)"
```

---

## Task 2: Truthful advertising (role-aware defaults) + RxO matrix + bounds

**Files:**
- Modify: `src/dds-qos/qos.lisp` (the role-aware defaults in `make-writer-qos` :142 / `make-reader-qos` :148; the `data-representation` default :122).
- Modify/Test: the dds-tests file(s) — the RxO matrix test, the malformed-PID fuzz, the default-change migration.

- [ ] **Step 1: Write the failing RxO matrix test.** Assert: a reader QoS `(:xcdr2 :xcdr1)` RxO-matches a writer offering `(:xcdr1)` AND one offering `(:xcdr2)`; a writer `(:xcdr2)` matches a reader `(:xcdr2 :xcdr1)`; an XCDR1-only reader `(:xcdr1)` does NOT match a writer `(:xcdr2)` and the failing policy is `:data-representation` (policy-id 23). Use `dds.qos:qos-rxo-compatible`. Run → it may already pass for explicit QoS; the point is to LOCK the matrix + then prove the DEFAULTS give the right behaviour.

- [ ] **Step 2: Set the role-aware defaults.** In `make-reader-qos` default `data-representation` = `(:xcdr2 :xcdr1)`; in `make-writer-qos` = `(:xcdr2)`. (Keep the raw `make-qos` default as-is or align it — verify no caller breaks.) One-line comments citing the rationale.

- [ ] **Step 3: Migrate the default-change blast radius.** Run the full suite; find tests that asserted the old `(:xcdr1)` default or relied on all-default matching; migrate them intent-preserving (set explicit QoS where a test meant a specific rep). Document each migration in the commit message. Do NOT weaken any assertion.

- [ ] **Step 4: Write the malformed-PID bounds/fuzz test.** A forged PID_DATA_REPRESENTATION (count larger than the value bytes; truncated) → `%fill-endpoint-param` skips it cleanly (the rest of the SEDP still parses), no OOB even at `(safety 0)`. Add to the SEDP/discovery fuzz arm.

- [ ] **Step 5: Run → pass, both impls.** `make test-sbcl` + `make test-clasp` green; `make fuzz` green.

- [ ] **Step 6: Commit.**
```bash
git add -A
git commit -m "feat(qos): WP-DATA-REPRESENTATION truthful role-aware advertising (reader (:xcdr2 :xcdr1), writer (:xcdr2)) + RxO matrix + parse bounds (DDS-XTypes 1.3 §7.6.3.1.1, NFR-SEC-POSTURE)"
```

---

## Task 3: Step 2 — TX in the offered representation (XCDR1-LE or XCDR2-LE)

**Files:**
- Modify: `src/dds-dcps/entities.lisp` (`%serialize-sample` ~183-189 — the hardcoded `:xcdr2` mode at :189; thread the writer's offered rep) + `write-sample` (~447-460, pass the offered rep).
- Modify: `src/dds-gen/dsl.lisp` (the encapsulation header — hardcoded `:plain-cdr2-le` at :360-362 for FlatData; find the struct path's encap header; make it rep-derived) + the FlatData TX-transcode.
- Test: TX byte-exact + round-trip in the dds-tests file.

- [ ] **Step 1: Write the failing TX-XCDR1 byte-exact test.** A non-FlatData type; a writer offering `(:xcdr1)`; serialize a sample; assert the SerializedPayload has the PLAIN_CDR_LE (0x0001) encapsulation header AND the body is the XCDR1 (8-byte-aligned) encoding — byte-exact vs an INDEPENDENT hand-built oracle (a type with an i8+i64 so the XCDR1 8-align vs XCDR2 4-align differs). Assert the `(:xcdr2)` default still emits 0x0007. Run → FAIL (TX is hardcoded XCDR2).

- [ ] **Step 2: Thread the offered rep + make the encapsulation rep-derived (non-FlatData).** In `%serialize-sample` (entities.lisp:189) replace the hardcoded `:xcdr2` with the writer's offered codec mode (`:xcdr1`/`:xcdr2`, from `(first (qos-data-representation writer-qos))`); thread it from `write-sample`. Make the serialized-size (`ssz`, entities.lisp:183) mode-aware. Make the encapsulation header rep-derived: the offered `:xcdr1` → `:plain-cdr-le` (0x0001), `:xcdr2` → `:plain-cdr2-le` (0x0007), via `representation-id-value` — replacing the hardcoded `:plain-cdr2-le` (dsl.lisp:360-362 + the struct path). Run Step-1 test → pass for non-FlatData.

- [ ] **Step 3: FlatData TX-transcode (R6).** For a FlatData writer offering `:xcdr1`: the identity-XCDR2 path stays for `:xcdr2` (0-copy); for `:xcdr1`, transcode — decode the XCDR2-LE buffer via `deserialize-<name>` (XCDR2) → struct → `serialize-<name>` `mode :xcdr1` → XCDR1-LE wire. Carry the R6 `NOT cleared for ship` marker. Add the FlatData arm to the Step-1 byte-exact test.

- [ ] **Step 4: TX→RX round-trip test.** Our `:xcdr1` writer → our reader reads it (the reader handles XCDR1 — struct codec / FlatData RX-transcode); assert field values + keyhash correct. Both non-FlatData + FlatData.

- [ ] **Step 5: mem.** Confirm `make mem` 0.0000 for the XCDR2 default path (FlatData identity unchanged); the XCDR1 TX-transcode allocs only on that fallback (state it; no bench needed — TX-XCDR1 is the opt-in fallback, off the measured default path).

- [ ] **Step 6: Both impls + commit.** `make test-sbcl` + `make test-clasp` + `make gate-hotpath` + `make mem` green.
```bash
git add -A
git commit -m "feat(gen): WP-DATA-REPRESENTATION TX in the writer's offered representation — XCDR1-LE via serialize mode + rep-derived encapsulation; FlatData TX-transcode (DDS-XTypes 1.3 §7.6.3.1.1, R6)"
```

---

## Task 4: Cross-DDS interop (the per-feature DoD — Connext + Fast DDS, both run live)

**Files:** Create `interop/data-representation/README.md` + `captures/`; reuse the existing Connext + Fast DDS harnesses (a simple type) + the publisher harness; do NOT copy vendor source / commit vendor binaries.

- [ ] **Step 1 — Step-1 interop (advertise/parse/match).** Capture a real Connext + Fast DDS SEDP (confirm/extend Task 1's oracle); confirm our emitted PID_DATA_REPRESENTATION dissects identically to theirs (tshark); confirm bidirectional MATCHING with no new false-rejects — our reader matches their writer (offering XCDR1 or XCDR2) AND our writer (offering XCDR2) matches their reader (accepting XCDR2). Record received counts + the tshark PID dissection.

- [ ] **Step 2 — Step-2 interop (TX).** Our writer offering `(:xcdr1)` → a Connext + Fast DDS reader READS the samples (PLAIN_CDR_LE 0x0001 on the wire, tshark-confirmed; correct field values). Our `(:xcdr2)` writer → their reader (unchanged, 0x0007). A foreign XCDR1-offering writer → our reader (already works via the RX transcode — re-confirm). Both peers, both directions.

- [ ] **Step 3 — README + captures + commit.** `interop/data-representation/README.md` (commands, results, tshark summary, honest caveats), captures committed.
```bash
git add -A
git commit -m "test(interop): WP-DATA-REPRESENTATION PID advertise/match + XCDR1 TX read by peer — LIVE vs Connext + Fast DDS (DDS-XTypes 1.3 §7.6.3.1.1)"
```

---

## Task 5: Gates + docs (capstone)

**Files:** `docs/adr/0020-data-representation.md` (new); `README.md`; `docs/wiki/` (the QoS/discovery/interop pages — the PID, the advertising model, the TX-rep selection, the `data-representation` QoS API + a worked example); `docs/verification.csv` (FR-QOS / DDS-XTypes §7.6.3.1.1 rows); `docs/provenance.md`.

- [ ] **Step 1: Full gate sweep, both impls.** `make build test corpus gate-types gate-hotpath mem fuzz` on SBCL + Clasp. Report each + totals. `make mem` 0.0000 for the default paths; state the no-bench justification (the PID is discovery-time; TX-XCDR1 is the opt-in fallback — no measured-default-path number changed).

- [ ] **Step 2: ADR 0020** — the decision record: PID_DATA_REPRESENTATION on the wire; truthful role-aware advertising; spec-strict RxO + interop-gate; TX in the offered rep + the FlatData TX-transcode; the pinned wire format (cite §7.6.3.1.1 + the capture); out-of-scope (per-reader encoding, XML, BE TX).

- [ ] **Step 3: Docs lockstep (§5.1)** — README status; wiki API + use-case + worked example; verification.csv rows (the emit/parse + RxO matrix + TX + the live interop); provenance (clean-room; §7.6.3.1.1; the capture as the oracle).

- [ ] **Step 4: Commit.**
```bash
git add -A
git commit -m "docs(qos): WP-DATA-REPRESENTATION ADR 0020/README/wiki/verification — PID + offered-rep TX (DDS-XTypes 1.3 §7.6.3.1.1, §5.1)"
```

---

## Self-review notes (author)
- **Spec coverage:** Task 1 = PID emit/parse + wire-oracle (step 1 wire); Task 2 = advertising defaults + RxO + bounds (step 1 matching); Task 3 = TX in offered rep + FlatData transcode (step 2); Task 4 = interop DoD (both steps); Task 5 = gates + docs. All spec sections covered.
- **Wire-is-oracle:** Task 1 Step 1 captures + pins BEFORE the emit/parse is finalized; the `{0,1,2}` values are verified, never assumed. Task 4 re-confirms vs both peers.
- **Type consistency:** the QoS field is a list of `{:xcdr1,:xcdr2,:xml}`; `%data-rep-wire`/`%wire-data-rep` are the DataRepresentationId_t (short) maps; `representation-id-value` is the DISTINCT 16-bit encapsulation map; the offered rep = `(first (qos-data-representation ...))`.
- **False-REJECT safety:** parse is fail-open (unknown rep ignored, never errors the SEDP); RxO rejects are TRUE incompatibilities only (verified by the interop gate). The reader advertising `(:xcdr2 :xcdr1)` keeps the forward-leg closed.
- **Open implementation note:** confirm where the struct (non-FlatData) encapsulation header is written (the FlatData one is dsl.lisp:360); the offered-rep threading replaces the hardcoded `:xcdr2` at entities.lisp:189 + the hardcoded `:plain-cdr2-le` at dsl.lisp:360.
