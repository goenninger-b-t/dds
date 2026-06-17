# WP-FLATDATA-XCDR-TRANSCODE Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`).

**Goal:** Make a `:flatdata t` reader transcode a foreign non-XCDR2-LE SerializedPayload (XCDR1 BE/LE, XCDR2 BE) into its canonical XCDR2-LE buffer — reusing the existing struct codec — instead of rejecting it. Closes the forward-leg false-REJECT WP-KEYED-FLATDATA surfaced; completes keyed-FlatData's bidirectional cross-DDS interop. Benefits all FlatData (keyed + unkeyed).

**Architecture:** In the FlatData deserialize, branch on the SerializedPayload rep-id: `PLAIN_CDR2_LE` (0x0007) = today's read-in-place (0-copy, unchanged); a transcodable foreign rep (PLAIN_CDR_BE/LE 0x0000/0x0001, PLAIN_CDR2_BE 0x0006) = decode the body via the sibling generated struct codec `deserialize-<name>` (mode + cursor endianness from the rep-id — it already handles XCDR1/XCDR2 × BE/LE, incl. the 8-vs-4 alignment divergence) then write the decoded field values into the canonical FlatData buffer via the `<name>-<field>-fd` setters; non-transcodable reps (PL/DELIMITED/XML) keep the existing reject. The transcode is the foreign-representation fallback (allocs the decode); the native/our-to-our path stays 0-copy.

**Tech Stack:** Common Lisp (SBCL + Clasp; copy/wire path, not ZC). `dds.gen` (`dsl.lisp` codegen), `dds.cdr` (`+representation-ids+`, the struct codec mode), `dds.core.buffer` (cursor endianness).

**Authoritative spec:** `docs/superpowers/specs/2026-06-17-wp-flatdata-xcdr-transcode-design.md`. **Conventions:** `defun*` + `defstruct*` + full ftype; ONE-LINE code comments; the rep-ids are pinned from DDS-XTypes 1.3 §7.6.3.1.2 — use `+representation-ids+`, never a constant from memory; bounds-check the untrusted foreign payload even at `(safety 0)` (NFR-SEC-POSTURE); **R6** marker (`NOT cleared for ship — pending counsel (R6); see ADR 0015`); both impls green; no reader conditionals outside `dds-pal/`; SBOM auto-staged; **no AI-assistant / co-author / Generated-with attribution**; commit each task autonomously within the branch; the squash-merge message is presented for owner approval.

## Verified grounding (file:line — from the design spec)
- `dsl.lisp:413-419` `deserialize-into-<name>-fd`: length guard then `(unless (and (= (aref src 0) #x00) (= (aref src 1) #x07)) (error 'cdr-not-implemented …))` — the reject to replace for transcodable reps. `dsl.lisp:425-440` `fd-des` (allocs `make-<name>-flatdata` then delegates to `fd-dnto`). `dsl.lisp:360` the writer sets `:plain-cdr2-le` (0x0007).
- `cdr.lisp:10-21` `+representation-ids+`: `:plain-cdr-be 0x0000`, `:plain-cdr-le 0x0001`, `:plain-cdr2-be 0x0006`, `:plain-cdr2-le 0x0007`, + PL/XML/DELIMITED.
- `dsl.lisp:209-220` `deserialize-<name> (cursor &optional (mode :xcdr2))` — the struct codec, handles `:xcdr1`/`:xcdr2`. `primitives.lisp:19-48` `cdr-align`/`%max-align` (8 for xcdr1, 4 for xcdr2). The cursor endianness is settable (`dds.core.buffer:cursor … :endianness`). The struct codec + the `<name>-<field>-fd` accessors/setters are BOTH generated for a `:flatdata t` type.
- `dsl.lisp:87-101` `%flatdata-offsets` (XCDR2 4-align) — the canonical buffer layout the `-fd` setters write.

## File structure
- **Modify:** `src/dds-gen/dsl.lisp` (the FlatData deserialize: the rep-id branch + the transcode). Possibly a small shared helper for the rep-id → (mode, endianness) map (or inline; cite §7.6.3.1.2).
- **Test:** `src/dds-tests/rtps-test.lisp` (the offline transcode unit tests) + `src/dds-tests/pbt-test.lisp` (the fuzz arm) (+ register).
- **Interop:** re-run / extend `interop/keyed-flatdata/` (the forward-leg harness from WP-KEYED-FLATDATA).
- **Docs:** ADR 0015 (a transcode note) or a short ADR; README P4; `docs/wiki/type-system.md`; `docs/verification.csv`; `docs/provenance.md`. **Bench:** none expected (the transcode is off the measured CDR path; confirm `make mem` 0.0000).

---

# Phase A — the transcode + offline tests

### Task A1: FlatData rep-id branch + transcode (decode-via-struct-codec → write canonical) + offline tests
**Files:** `src/dds-gen/dsl.lisp`; tests in `src/dds-tests/rtps-test.lisp` + `src/dds-tests/pbt-test.lisp` (+ register in `run-all-tests`).
- [ ] **Failing tests first** (register; match the existing rtps-test style): use a fixed-size-scalar type incl. an `:i64` member so the XCDR1↔XCDR2 8-vs-4 alignment divergence is exercised — reuse/define e.g. `(define-dds-type xcv (:flatdata t) (a :i8) (k :i64 :key t) (v :i32))` (a is 1 octet → forces the i64 to offset 8 in XCDR1 but 4 in XCDR2).
  - `run-flatdata-transcode-xcdr1be-test`: HAND-BUILD the SerializedPayload for known field values as PLAIN_CDR_BE (encap `00 00`, then the body XCDR1 big-endian — i8@0, pad to 8, i64@8 BE, i32@16 BE) → run the FlatData deserialize → assert the `xcv-a-fd`/`xcv-k-fd`/`xcv-v-fd` accessors read the CORRECT values AND `key-hash-xcv-fd` equals the native keyhash. (Hand-build the bytes from first principles per §7.6.3.1.2 + the XCDR1 alignment — do NOT use our serializer to build the input, so the test is a genuine oracle.)
  - `run-flatdata-transcode-xcdr1le-test`: same for PLAIN_CDR_LE (`00 01`, XCDR1 little-endian).
  - `run-flatdata-transcode-xcdr2be-test`: same for PLAIN_CDR2_BE (`00 06`, XCDR2 big-endian — i64@4).
  - `run-flatdata-transcode-native-test` (regression): a PLAIN_CDR2_LE (`00 07`) payload still reads in-place, byte-identical to today.
  - `run-flatdata-transcode-rejects-pl-test`: a PL_CDR2 / DELIMITED / XML rep-id → the clean reject (false-REJECT-safe), unchanged.
  - Run RED (the transcode doesn't exist → the foreign-rep tests error/reject).
- [ ] **Implement** (`dsl.lisp`, in `deserialize-into-<name>-fd`): read the rep-id (`aref src 0/1`). Branch:
  - `0x0007` (PLAIN_CDR2_LE) → the existing read-in-place copy (UNCHANGED).
  - `0x0000`/`0x0001`/`0x0006` (transcodable) → make a `dds.core.buffer:cursor` over `src` positioned PAST the 4-octet encap header, endianness `:big` (0x0000/0x0006) or `:little` (0x0001); call `deserialize-<name>` with `mode :xcdr1` (0x0000/0x0001) or `:xcdr2` (0x0006) → a `<name>` struct; then write each field into the TARGET canonical FlatData buffer via the `<name>-<field>-fd` setters from the struct accessors (the target is a `make-<name>-flatdata` buffer with the `0x0007` encap already set — so the body becomes the canonical XCDR2-LE layout). (Reuse — no new codec; cite §7.6.3.1.2 + the rep-id→mode/endianness map via `+representation-ids+` in a one-line comment.)
  - anything else (PL/DELIMITED/XML) → the existing reject (`cdr-not-implemented`).
  - The length guard stays (false-REJECT-safe). `defun*`/ftype on any new helper; R6 marker.
- [ ] **Run + verify:** the 5 `run-flatdata-transcode-*` tests pass SBCL + Clasp. Full suite green both impls (NO_KEY/keyed FlatData native path + non-FlatData unchanged; report totals — was 232). `make gate-types` + `gate-hotpath` PASS. **`make mem` 0.0000** (the transcode is the foreign-rep fallback, off the measured CDR path — confirm).
- [ ] **Commit:** `feat(gen): WP-FLATDATA-XCDR-TRANSCODE FlatData reader transcodes a foreign rep (XCDR1 BE/LE, XCDR2 BE) -> XCDR2-LE via the struct codec (FR-PF-4, DDS-XTypes 1.3 §7.6.3.1.2, R6)`

### Task A2: untrusted foreign-payload fuzz/bounds
**Files:** `src/dds-tests/pbt-test.lisp` (+ register).
- [ ] **Test** `run-flatdata-transcode-fuzz` (both impls): feed the FlatData deserialize a foreign rep-id (0x0000/0x0001/0x0006) with arbitrary / short / truncated bodies → assert it NEVER errors uncontrolled / no OOB even at `(safety 0)` (a clean reject/error or a bounded decode). Add to the FlatData fuzz arm. Run; if it exposes an OOB, harden the decode bounds (the struct codec cursor must bounds-check the foreign body against the SerializedPayload extent).
- [ ] **Run:** fuzz PASS both impls. Commit: `test(gen): WP-FLATDATA-XCDR-TRANSCODE fuzz the foreign-rep transcode decode (no OOB at (safety 0), NFR-SEC-POSTURE)`

---

# Phase B — cross-DDS interop forward-leg (the per-feature DoD)

### Task B1: re-run the keyed-FlatData forward leg through the transcode + Fast DDS hand-over
**Files:** `interop/keyed-flatdata/` (the WP-KEYED-FLATDATA harness) + `docs/verification.csv`.
- [ ] **Connext forward leg (attempt live in-session):** using the existing `interop/keyed-flatdata/connext/keyed_flat_pub` (which defaults to XCDR1-BE), run it against our FlatData subscriber (`make` the keyed-flat sub / the `dds.shapes` keyed-flat reader). Assert our reader now RECEIVES the samples (the transcode reads the XCDR1-BE payload) — matched, correct field values, correct per-key instance (vs the F1 result where it rejected). If live two-participant run is sandbox-blocked, capture a Connext XCDR1-BE keyed-flat frame and feed it to the FlatData deserialize offline (assert correct read) + hand the live run to the owner with the expected result.
- [ ] **Offline confirm:** the A1 transcode tests already prove the keyhash/values on a hand-built XCDR1-BE payload; reference them as the offline conformance.
- [ ] **Fast DDS forward leg (owner-pending):** update `interop/keyed-flatdata/README.md` — the forward leg (Fast DDS pub → our FlatData sub) is now EXPECTED to work via the transcode; give the owner the run command + the expected result.
- [ ] **Document** `docs/verification.csv` (the FR-PF-4 interop row: forward-leg via transcode — Connext result + Fast DDS owner-pending). Commit: `test(interop): WP-FLATDATA-XCDR-TRANSCODE keyed-FlatData forward leg via the transcode (Connext + offline; Fast DDS owner-pending) (FR-PF-4)`

---

# Phase C — docs

### Task C1: docs + gate sweep
- [ ] **Gates:** `make build test corpus gate-types gate-hotpath mem fuzz` green both impls. No bench (the transcode is off the measured path — state `make mem` 0.0000 explicitly).
- [ ] **Docs (§5.1):** ADR 0015 (a transcode note — the FlatData reader now reads any standard representation via decode-then-reserialize; the native path stays 0-copy; PID_DATA_REPRESENTATION advertisement is the noted follow-up) — or a short ADR-0020 if cleaner. README P4 (FlatData reads foreign XCDR1/XCDR2 BE/LE via the transcode; forward-leg interop). `docs/wiki/type-system.md` (the transcode model + the rep-id branch + that the native path stays read-in-place). `docs/verification.csv` (FR-PF-4 transcode row). `docs/provenance.md` (clean-room — §7.6.3.1.2; no new external source). Grep for any now-false "FlatData reader is XCDR2-LE-only / rejects foreign reps" claim and update it (incl. the WP-KEYED-FLATDATA docs that flagged the forward-leg gap — now fixed).
- [ ] **Commit:** `docs(types): WP-FLATDATA-XCDR-TRANSCODE ADR/README/wiki/verification — FlatData reads any standard representation (FR-PF-4, §5.1)`

---

## Self-review
- **Spec coverage:** the transcode + rep-id branch → A1; the offline oracle tests (XCDR1-BE/LE, XCDR2-BE, native, non-transcodable) → A1; the untrusted fuzz → A2; the forward-leg interop DoD → B1; gates + docs → C1. All covered.
- **Placeholder scan:** the transcode tests HAND-BUILD the foreign payloads from first principles (a genuine oracle, not our serializer); the i64-member type forces the alignment-divergence path; the rep-id map is concrete (0x0000/0x0001/0x0006 → mode+endian). No vague steps.
- **Green-per-task:** A1 adds the transcode (the native + non-FlatData paths unchanged → suite green); A2 is fuzz; B1 re-runs interop (+ updates docs); C1 docs. No red boundary.
- **Type/name consistency:** the transcode reuses `deserialize-<name>` (the struct codec, A1) + the `<name>-<field>-fd` setters (A1); the rep-ids come from `+representation-ids+` (cdr.lisp). The keyhash `key-hash-<name>-fd` (from WP-KEYED-FLATDATA) reads the post-transcode buffer (A1 test). Consistent A→C.
- **Binary gates:** conformance (the transcoded values + keyhash are correct — the hand-built-oracle tests; the forward-leg interop vs a real peer); no-regression (native 0x0007 read-in-place byte-identical; `make mem` 0.0000); security (the untrusted foreign payload bounds-checked + fuzzed, no OOB at (safety 0)). R6 throughout.
- **Order:** A (the transcode + offline proof) → B (the live forward-leg interop DoD) → C (docs). The transcode precedes its interop verification.
