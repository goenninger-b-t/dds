# WP-KEYED-FLATDATA Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`).

**Goal:** Lift FlatData v1's NO_KEY restriction. Codegen a buffer-reading keyhash (`key-hash-<name>-fd`, big-endian, byte-identical to the spec keyhash), wire it into `type-support`, and let full keyed behavior follow: real per-key loan handles, NEW/NOT_NEW view-state + instance-recs, dispose/unregister, and the loan-path per-instance KEEP_LAST drop (closing the WP-KEEPLAST follow-up gap). Queue #3b; closes the FlatData v1 NO_KEY deviation (ADR 0015).

**Architecture:** The keyhash is the linchpin — once `key-hash-<name>-fd` exists and `type-support` carries `:keyed-p t` + `:key-hash`, the reader's existing `%instance-handle` machinery (copy path) and the loan-handle / loan-drop wiring (loan path) all start treating a keyed FlatData type like any keyed type. The `-fd` keyhash reuses the struct keyhash's BE serialization, only sourcing values from the `<name>-<field>-fd` accessors (which dual-dispatch owned-buffer/flatdata-view), so one function serves the write/wire path and the loan path; FlatData has no struct, so there is no struct case.

**Tech Stack:** Common Lisp (SBCL both; the ZC loan path is SBCL-only). `dds.gen` (`dsl.lisp` codegen), `dds.types` (`type-support`), `dds.dcps` (`entities.lisp`: `%loan-instance-handle`, `%drain-one-loan`, `%instance-handle`, dispose/unregister).

**Authoritative spec:** `docs/superpowers/specs/2026-06-17-wp-keyed-flatdata-design.md` (the model + the 6 scenarios + the conformance crux + the decisions). **Conventions:** `defun*` + `defstruct*` + full ftype (FR-LANG-8); ONE-LINE code comments (rationale in commit messages); the keyhash is pinned from RTPS 2.5 §9.6.4.8 — REUSE the existing `key-hash-<name>` serialization logic, never re-derive the rule or a constant from memory; **R6** — gated behind `:flatdata t` + (loan) `dds.disc:*zerocopy-enabled*` + the `NOT cleared for ship — pending counsel (R6); see ADR 0015/0017` marker on the new codegen; loan path SBCL-only, copy/wire path both impls; no reader conditionals outside `dds-pal/`; SBOM auto-staged; **no AI-assistant / co-author / Generated-with attribution** anywhere; commit each task autonomously within the branch; the squash-merge message is presented to the owner for approval.

## Verified grounding (file:line — from the design spec)
- `dsl.lisp:185` FlatData FINAL+fixed-size-scalar check (KEEP — constrains `@key` to fixed-size scalars). `dsl.lisp:189-191` the `keys → error` NO_KEY check (LIFT this). `dsl.lisp:168-195` `define-dds-type` expansion — `parsed`, `keys` (filtered `@key`), `fd-offs` (`%flatdata-offsets`) all available at compile time.
- `dsl.lisp:257-277` `key-hash-<name>` (struct keyhash): a 256-octet scratch buffer + a `:big` cursor, `,(getf m :put)` per key member with `,(acc m)` (struct accessor) as the value, ≤16 → `replace out` / >16 → `md5`; returns a 16-octet array; `free-static`s the scratch. REUSE this shape, swapping `(acc m)` → `(fd-acc m)` (the `-fd` accessor).
- `dsl.lisp:294-312` `(fd-acc m)` = `<name>-<slot>-fd` (LE, dual-dispatch owned-buffer/`flatdata-view`). `dsl.lisp:417-428` the `register-type`/`make-type-support` call — `:keyed-p (and keys t)`, `:key-hash (when keys #'<khf>)`, `:flatdata-offset ...`.
- `type-support.lisp:19-46` `type-support` `keyed-p` + `key-hash` slots. `entities.lisp:470-475` `%instance-handle (ts sample)` → `(if kh (funcall kh sample) +instance-handle-nil+)`.
- `entities.lisp:936-954` `%loan-instance-handle (ts view sn sguid)` (the SN+GUID fold; ts/view ignored). `entities.lisp:976` call site. `entities.lisp:~980` the "skipped per-instance drop" comment. `entities.lisp:~1126` the copy-path `(when depth (%reader-keeplast-drop-oldest dr handle depth))`. `entities.lisp:752-781` `%reader-keeplast-depth` + `%reader-keeplast-drop-oldest`.
- `entities.lisp:489-547` dispose/unregister + `%resolve-handle` (handle-passthrough else `%instance-handle`).

## File structure
- **Modify:** `src/dds-gen/dsl.lisp` (lift the check; emit `key-hash-<name>-fd`; wire type-support), `src/dds-dcps/entities.lisp` (`%loan-instance-handle` keyed branch; `%drain-one-loan` per-instance drop). Possibly `src/dds-gen/packages.lisp` (no new exports likely — `key-hash-<name>-fd` is referenced via the type-support function pointer).
- **Test:** `src/dds-tests/integration-test.lisp` + `src/dds-tests/rtps-test.lisp` (a keyed FlatData test type + the keyhash byte-exact vector) (+ register in `run-all-tests`).
- **Docs:** ADR 0015 (close the NO_KEY deviation — a note that keyed FlatData landed) or a short ADR-0020 if cleaner; README P4 (FlatData keyed); `docs/wiki/` (FlatData keyed + keyhash); `docs/verification.csv` (FR-PF-4 / FR-TYPE-5 rows); `docs/provenance.md`. **Bench** only if a hot-path number changed (the keyhash is off the measured CDR path; likely none — confirm).

---

# Phase A — the buffer-reading keyhash + lift NO_KEY + type-support wiring

### Task A1: `key-hash-<name>-fd` + lift the NO_KEY check + wire type-support
**Files:** `src/dds-gen/dsl.lisp`; tests in `src/dds-tests/rtps-test.lisp` (+ `run-all-tests`).
- [ ] **Failing tests** (register): define a keyed FlatData test type, e.g. `(define-dds-type keyed-fd-i32 (:flatdata t) (k :int32 :key t) (v :int32))` (a ≤16 direct key) and a wider/multi-key type forcing the MD5 path (e.g. several fixed-size scalar `@key` members totalling >16 octets). `run-keyed-flatdata-keyhash-test`: (a) the type COMPILES (the NO_KEY error is lifted); (b) `key-hash-keyed-fd-i32-fd` over an owned octet-buffer holding known key values equals a PINNED 16-octet BE keyhash vector (compute the expected bytes by hand from the §9.6.4.8 rule for the chosen key value — the @key member big-endian, zero-padded to 16); (c) the MD5-path type's `-fd` keyhash equals its pinned MD5 vector; (d) if a struct keyhash is also generated for the type, cross-check `-fd` == struct for the same values; (e) a `:flatdata t` type with a `string`/variable-size `@key` member still raises the compile error. Run RED.
- [ ] **Implement** (in `dsl.lisp`): remove the `keys → error` check at `:189-191` (keep the FINAL+fixed-size-scalar check at `:185`). In the FlatData branch, when `keys`, emit `key-hash-<name>-fd (x)` — mirror `key-hash-<name>` (`:257-277`) exactly: a 256-octet arena scratch + a `:big` cursor, `,(getf m :put) wc (,(fd-acc m) x) :xcdr2` for each key member (sourcing the value from the `-fd` accessor instead of the struct accessor), the same ≤16-direct/MD5 branch (reuse `key-direct-p`/`keymax`), `free-static` the scratch, return the 16-octet array. `defun*` + ftype `((or dds.core.buffer:octet-buffer dds.types:flatdata-view) → (simple-array (unsigned-byte 8) (16)))`. In `register-type`/`make-type-support` (`:417-428`): for a keyed FlatData type set `:keyed-p t` and `:key-hash #'key-hash-<name>-fd` (the FlatData variant), not the struct `khf`. One-line R6 marker comment on the new codegen.
- [ ] **Run + verify:** `run-keyed-flatdata-keyhash-test` passes SBCL + Clasp (the keyhash + compile checks are impl-independent — both run). Full suite green both impls (NO_KEY FlatData + non-FlatData keyed unchanged; report totals). `make gate-types` + `gate-hotpath` PASS. `make mem` 0.0000 unaffected (the `-fd` keyhash is computed only for keyed FlatData, off the measured CDR path — confirm).
- [ ] **Commit:** `feat(gen,types): WP-KEYED-FLATDATA key-hash-<name>-fd buffer keyhash + lift FlatData NO_KEY (fixed-size scalar keys) + wire type-support (FR-PF-4, RTPS 2.5 §9.6.4.8, R6)`

---

# Phase B — real per-key loan handle

### Task B1: `%loan-instance-handle` keyed branch
**Files:** `src/dds-dcps/entities.lisp`; test in `src/dds-tests/integration-test.lisp` (+ register).
- [ ] **Failing test** `run-keyed-flatdata-loan-handle-test` (SBCL; pass-skip Clasp — ZC loan is SBCL-only): a loan-capable reader of a keyed FlatData type (`*zerocopy-enabled*` on, `:flatdata t`). Loan two samples of DIFFERENT key values → assert the two SampleInfo `instance-handle`s are DISTINCT and each equals that sample's keyhash; loan two samples of the SAME key → assert the SAME handle (no SN-fold aliasing). Field reads via `-fd` still byte-correct. Run RED (today the fold gives per-sample-unique handles → same-key samples get DIFFERENT handles → the SAME-key assertion fails).
- [ ] **Implement:** `%loan-instance-handle (ts view sn sguid)` — when `(dds.types:type-support-key-hash ts)` is non-NIL (keyed), return `(funcall (type-support-key-hash ts) view)` (the real per-key handle read from the loaned view); else keep the SN+GUID fold (NO_KEY, unchanged). Stop `(declare (ignore ts view))` for the keyed branch; update the docstring (the per-key follow-up is now delivered; R6 marker stays). The keyhash allocates the same 16-octet handle the fold did — note in the commit (no 0-alloc regression; `make mem` measures the CDR path).
- [ ] **Run:** test passes SBCL (pass-skip Clasp); full suite green both impls (NO_KEY loan path unchanged). `gate-types`/`gate-hotpath`/`mem` PASS. Commit: `feat(dcps): WP-KEYED-FLATDATA real per-key loan handle — %loan-instance-handle uses the FlatData keyhash for keyed types (FR-PF-4, ADR 0017, R6)`

---

# Phase C — loan-path per-instance KEEP_LAST drop (close the WP-KEEPLAST gap)

### Task C1: wire `%reader-keeplast-drop-oldest` into `%drain-one-loan`
**Files:** `src/dds-dcps/entities.lisp`; test in `src/dds-tests/integration-test.lisp` (+ register).
- [ ] **Failing test** `run-keyed-flatdata-loan-keeplast-test` (SBCL; pass-skip Clasp): a KEEP_LAST depth-2 loan-capable reader of a keyed FlatData type; loan 3 samples of instance A + 3 of B → assert `dr-cache` holds the last 2 of EACH instance (the loan path now applies the per-instance drop). A NO_KEY FlatData KEEP_LAST loan reader is unaffected (its per-(GUID,SN)-unique handles mean the cap never fires — assert the NO_KEY loan stream is unchanged). Run RED (today `%drain-one-loan` skips the drop → all 6 retained).
- [ ] **Implement:** in `%drain-one-loan`, after `%loan-instance-handle` returns the (now real for keyed) handle and BEFORE the cache append, add `(let ((depth (%reader-keeplast-depth dr))) (when depth (%reader-keeplast-drop-oldest dr handle depth)))` — mirroring the copy path (`:~1126`). Replace the "skipped for NO_KEY v1" comment with a one-line as-built note. (For NO_KEY the per-(GUID,SN)-unique handle means each is its own instance, so the depth cap never fires — behaviour unchanged.)
- [ ] **Run:** test passes SBCL (pass-skip Clasp); full suite green both impls. `gate-types`/`gate-hotpath`/`mem` PASS. Commit: `feat(dcps): WP-KEYED-FLATDATA apply per-instance KEEP_LAST drop on the ZC loan path for keyed FlatData (closes the WP-KEEPLAST follow-up, DDS 1.4 §2.2.3.18, R6)`

---

# Phase D — keyed-behavior validation (copy-path view-state/instance-recs + dispose/unregister)

### Task D1: keyed FlatData copy-path behavior + dispose/unregister tests
**Files:** Tests in `src/dds-tests/integration-test.lisp` (+ register); fix `entities.lisp` ONLY if a test exposes a gap.
- [ ] **Failing/validation test** `run-keyed-flatdata-copy-behavior-test`: a keyed FlatData reader WITHOUT ZC (copy path) gets a real per-key `instance-handle` in SampleInfo; first sample of a key → `view-state :new`, a repeat of that key → `:not-new`; a second instance is independent; a KEEP_LAST depth-2 keyed FlatData reader holds last-2 per instance on the copy path. (Expected GREEN with no code change — proves the keyhash wiring lit the existing machinery; if RED, the gap is in how the copy path computes/threads the FlatData handle — fix minimally.)
- [ ] **Validation test** `run-keyed-flatdata-dispose-test`: a keyed FlatData writer disposes an instance by sample (the FlatData octet-buffer) → a matched reader sees `instance-state :not-alive-disposed` for that instance; unregister likewise (with autodispose). (Expected GREEN via `%resolve-handle`→`%instance-handle`→`key-hash-<name>-fd`; if RED — e.g. `%resolve-handle` mis-detects a FlatData buffer as a handle via `%handle-p`, or dispose-by-sample needs the buffer — root-cause + minimal fix.)
- [ ] **Run:** both tests pass SBCL + Clasp (copy path is both-impl); full suite green; report totals. If any minimal fix was needed, note it. `gate-types`/`gate-hotpath`/`mem` PASS. Commit: `test(dcps): WP-KEYED-FLATDATA keyed copy-path view-state/instance-recs + dispose/unregister of a keyed FlatData instance (DDS 1.4 §2.2.2.5, FR-PF-4)` (+ a `fix(...)` commit if a gap was hardened).

---

# Phase E — gates, bench, docs

### Task E1: full gate sweep + bench-if-hotpath + docs
- [ ] **Gates:** `make build test corpus gate-types gate-hotpath mem fuzz` green both impls (or a documented Clasp NFR-PORT note for the SBCL-only loan tests — pass-skip). If the keyhash changed any measured hot-path number, **bench** before/after (FR-LANG-7) → `bench/report/2026-06-17-wp-keyed-flatdata.md`; expected NONE (the `-fd` keyhash is off the CDR path + gated to keyed) — state that explicitly if so.
- [ ] **Docs (§5.1 lockstep):** ADR — close the FlatData NO_KEY deviation: update ADR 0015 (the deviation is now lifted for fixed-size scalar keys) + a short as-built note (or a new ADR-0020 if the keyhash design warrants its own — implementer's call; prefer extending 0015). README P4 (FlatData now supports fixed-size scalar `@key` — the buffer-reading keyhash + per-key loan handles; variable-size keys still deferred). `docs/wiki/` (the FlatData keyed model + the `-fd` keyhash + a worked keyed-FlatData example). `docs/verification.csv` (FR-PF-4 / FR-TYPE-5 rows — keyed FlatData + the keyhash byte-exactness + the tests). `docs/provenance.md` (clean-room — FR-PF-4 + RTPS 2.5 §9.6.4.8, no external source). Grep for any now-false "FlatData is NO_KEY only" claim and fix it.
- [ ] **Commit:** `docs(types): WP-KEYED-FLATDATA close the FlatData NO_KEY deviation + README/wiki/verification (FR-PF-4, ADR 0015, §5.1)`

---

## Self-review
- **Spec coverage:** keyhash + lift NO_KEY + type-support → A1; real per-key loan handle → B1; loan-path KEEP_LAST drop → C1; copy-path keyed behavior + dispose/unregister → D1; the 6 scenarios → A1 (1) + B1 (2) + C1 (3) + D1 (4,5) + E1 (6 regression/gates); conformance crux (byte-exact keyhash) → A1's pinned-vector + struct cross-check. All covered.
- **Placeholder scan:** the keyhash test uses a CONCRETE keyed FlatData type + a hand-computed pinned BE vector (both ≤16 and MD5 paths); the dispose/copy-path tests are "expected green, fix-if-RED" (validation-led, with the concrete gap named). No vague steps.
- **Green-per-task:** A1 lifts NO_KEY + adds the keyhash (NO_KEY FlatData + non-FlatData keyed untouched → suite green). B1/C1 touch only the keyed-FlatData loan branch (NO_KEY unchanged). D1 is tests (+ minimal fix only if RED). No red boundary.
- **Type/name consistency:** `key-hash-<name>-fd` (A1) is the type-support `:key-hash` (A1) consumed by `%instance-handle`/`%loan-instance-handle` (B1) and the copy path (D1); `%reader-keeplast-depth`/`%reader-keeplast-drop-oldest` (the WP-KEEPLAST helpers) reused in C1. Consistent A→E.
- **Binary gates:** conformance (the keyhash byte-exact vs the spec BE rule — A1's crux; keyed instance identity = a peer's) + no-regression (NO_KEY FlatData + non-FlatData keyed byte-identical; `make mem` 0.0000) are the gates; R6 default-off throughout; the loan path SBCL-only (pass-skip Clasp, documented).
- **Order:** A (the keyhash linchpin) → B (loan handle uses it) → C (loan drop uses the handle) → D (validate the ≈free copy-path + dispose behavior) → E (gates/bench/docs). The keyhash precedes everything that consumes it.
