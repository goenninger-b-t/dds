# WP-RELIABLE-ZC Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Prove the FlatData-over-ZC literal-0-copy loan path is correctly delivered under RELIABLE (retransmit on loss, no silent drop), fix the gaps the proof reveals, document the model. Scope A (verify+harden+test); scope B (no-HC-double-copy) deferred.

**Architecture:** Reliable ZC delivery already rides the existing reliable path (HC stores the full payload; the 16-byte ref is regenerated per-send; a NACK retransmits → re-loans a fresh slot from the retained payload or falls back to the full copy; the reader ACKs/NACKs a ZC ref as normal DATA; the loan composes via refcount, outliving the HC purge until return-loan). This WP confirms + hardens + documents it — it does not redesign it.

**Tech Stack:** Common Lisp (SBCL; ZC SBCL-only). `dds.disc` (the ZC publish/resolve/loan paths + `*debug-drop-sample-numbers*`), `dds.rtps.reliable` (writer-on-acknack/reader-acknack/writer-purge-acked), `dds.dcps` (take-loaned/return-loan), `dds.xport.zerocopy` (the pool).

**Authoritative spec:** `docs/superpowers/specs/2026-06-16-wp-reliable-zc-design.md` (the model + the 5 scenarios + the likely harden points). **Conventions:** `defun*`+full ftype; one-line comments; R6 markers (ADR 0017/0018); no reader conditionals outside `dds-pal/`; SBOM auto-staged; **no AI-assistant / co-author / Generated-with attribution**; commit autonomously.

## Verified grounding (from the grounding report — file:line)
- `dataplane.lisp:330-343` `%zc-change-item` (per-send ZC decision, called on push AND retransmit via `%changes-datagram-plan:413`), `:589-616` `%zc-ref-builder` (`%zc-loan` per-send; NIL → caller falls back to the full payload, `:413-414`), `:1079-1110` `%on-user-data` (loan-capable → `%zc-defer`→`%deliver-user-marker`; `:not-a-ref` → `%deliver-user-sample` copy), `:1043-1077` `%deliver-user-marker`/`%deliver-user-sample` (both feed `reader-on-data` so ACK bookkeeping advances), `*debug-drop-sample-numbers*` (drop a sample's DATA to force a NACK).
- `reliable.lisp:189-207` `writer-on-acknack` (resend by SN from HC), `:209-229` `writer-purge-acked` (purge-on-full-ACK; no ZC slot interaction — the slot is held by the reader refcount), `:268-278` `reader-on-data`, `:297-315` `reader-acknack`.
- `entities.lisp` `take-loaned`/`read-loaned`/`%drain-one-loan`/`return-loan` (the loan registry; a non-marker sample mixed in → must deliver copy-backed — the likely harden point).

## File structure
- **Test**: `src/dds-tests/integration-test.lisp` (the 5 reliability scenarios) + register in `run-all-tests`.
- **Possibly Modify** (only if a test exposes a gap): `src/dds-dcps/entities.lisp` (`%drain-one-loan`/`take-loaned` copy-fallback handling), `src/dds-disc/dataplane.lisp` (the retransmit/defer/fallback paths). Minimal, test-driven.
- **Docs**: ADR 0017 (or a short note in ADR 0018) + README P4 + `docs/wiki/` (the reliable-ZC model) + `docs/verification.csv` + `docs/provenance.md`.

---

# Phase A — the reliability test suite + harden

### Task A1: the 5 reliable-ZC scenarios (write each, run, fix-the-gap-if-it-fails, pass)
**Files:** `src/dds-tests/integration-test.lisp` (+ `run-all-tests`); fix `entities.lisp`/`dataplane.lisp` only if a test exposes a gap.
- [ ] **Scenario 1 — reliable retransmit of a ZC loan sample.** `run-reliable-zc-retransmit-test`: a RELIABLE writer + a same-host loan-capable ZC reader; drop the first ZC ref via `*debug-drop-sample-numbers*`; drive the HEARTBEAT cadence → the reader NACKs → the writer retransmits (re-loans a fresh slot from the retained full payload) → the reader resolves the re-loaned ref; `take-loaned` reads the fields byte-exact. Assert the sample is ultimately received (reliable, no loss). If it fails, root-cause + fix (the retransmit re-loan / the loan-capable defer of a retransmitted ref).
- [ ] **Scenario 2 — pool-full → copy-fallback to a loan-capable reader.** `run-reliable-zc-poolfull-fallback-test`: saturate the ZC pool (hold loans on all slots, or a 1-slot pool with a held loan), then publish a ZC-eligible sample → `%zc-loan` NIL → the writer sends the full payload → the loan-capable reader receives a NORMAL (non-marker) sample → `take-loaned` returns it **as a copy** byte-exact (NOT a view; NOT skipped/errored). **This is the most likely harden:** confirm `%drain-one-loan`/`take-loaned` handles a non-`zc-loan-marker` sample (delivers it copy-backed). Fix if needed (+ a regression note).
- [ ] **Scenario 3 — mixed markers + copies in one take-loaned.** `run-reliable-zc-mixed-test`: a loan-capable reader receives some ZC markers (→ views) and some fallback copies (→ copies) interleaved; one `take-loaned` returns all correctly; `return-loan` releases the views (no-op for copies); no leak.
- [ ] **Scenario 4 — the slot outlives the HC purge.** `run-reliable-zc-slot-outlives-purge-test`: a loan-capable reader `take-loaned`s a ZC sample (holds the loan); drive the ACK so the writer `writer-purge-acked`s the HC change; assert the loaned view STILL reads byte-exact (the refcount holds the slot past the purge); then `return-loan` → the slot frees (the writer can reuse it). Proves the loan↔reliability refcount composition.
- [ ] **Scenario 5 — QoS-ride + regression.** `run-reliable-zc-qos-test`: a RELIABLE writer and a BEST-EFFORT writer each deliver a ZC loan sample correctly (ZC rides the QoS; no gate). Off / non-ZC byte-identical (reuse the existing regression assertions).
- [ ] Run each on SBCL (pass-skip Clasp). For any harden, make the minimal fix + re-run. Full suite both impls → no regression (was 206; report). `make gate-types` + `gate-hotpath` + `mem` + `zc-xproc` → PASS (re-verify 0-alloc if a harden touched the loan RX path).
- [ ] **Commit** (one or split if a harden is substantive): `test(disc): WP-RELIABLE-ZC reliable loan delivery — retransmit/pool-full-fallback/mixed/slot-outlives-purge/QoS (FR-PF-3/4, R6)` (+ a `fix(...)` commit if a gap was hardened).

---

# Phase B — docs

### Task B1: document the reliable-ZC model
- [ ] ADR (extend ADR 0017 "reliable delivery" or add a short ADR-0018 §): the reliable-ZC model (HC full payload + retransmit re-loan / copy fallback; reader ACK/NACK of a ZC ref; the loan↔refcount composition outliving the purge; the writer-side double-storage as the v1 cost; scope B [no-HC-copy] deferred). README P4 (reliable ZC loan delivery works; the reader-RX+wire win; scope-B follow-up). `docs/wiki/` (the reliable-ZC behavior + the loan-under-reliable note). verification.csv (the FR-PF-3/4 reliability row + the 5 tests). provenance (no new external source). Grep: no false claim (the writer-side double-storage is honestly stated). Commit `docs(disc): WP-RELIABLE-ZC reliable-loan model + scope-B-deferred note + README/wiki/verification (FR-PF-3/4, R6, §5.1)`

---

## Self-review
- **Spec coverage:** the 5 scenarios→A1; harden (copy-fallback/take-loaned)→A1; docs (model + double-storage + scope-B-deferred)→B1. All covered.
- **Placeholder scan:** the harden points are "fix only if the test exposes them" (test-driven, not speculative); the scenarios are concrete with the exact drop/saturate mechanisms.
- **Binary gates:** reliability (no silent drop — scenario 1+2 prove retransmit re-loan + copy-fallback deliver); the loan↔reliability refcount composition (scenario 4); no regression (scenario 5 + the existing suites). If a harden touches the loan RX path, re-verify 0-alloc/no-UAF.
- **Order:** A (prove + harden — the substance) then B (document the as-confirmed model). The WP is test-led: the tests are the deliverable; the fixes are whatever they reveal.
