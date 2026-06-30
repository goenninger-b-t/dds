# WP-SHMEM-SEND-SELF-GUARD Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** A SIGNALED `%shmem-send` hard error degrades gracefully — caught on the production send path (`%send-raw-buf`), observed (a `disc-node` counter + `*sender-emit-error-hook*`), and dropped through to the EXISTING UDP fallback so the datagram still delivers over UDP.

**Architecture:** A `handler-case` around the SHMEM `dds.xport:send` in `%send-raw-buf` (dds.disc — keeps the dds.disc counter+hook in scope, no upward dds.xport→dds.disc dependency); the SHMEM `:send` lambda (dds.xport) stays unguarded so it signals up. Fault-vs-lane-full is distinguished: the `handler-case` fires only on a SIGNAL (hard fault → counter+hook); a return-0 (lane-full) falls back to UDP silently as today. Non-R6.

**Tech Stack:** Common Lisp (SBCL full SHMEM / Clasp-macOS UDP-only — the WP-SHMEM NFR-PORT gap, so the SHMEM-specific test pass-skips where SHMEM is inactive), `dds.disc`/`dds.xport.shmem`, `defun*`/`defstruct*` + full types, `make` gates.

**Spec:** `docs/superpowers/specs/2026-06-18-wp-shmem-send-self-guard-design.md` (read it).

**Conventions (NON-NEGOTIABLE):** one-line code comments; full type declarations; docstrings on the new special var + the condition + the counter slot (§5.1); the `ignore-errors` around the hook funcall (a signaling hook can't break the send); the injector inert when NIL (byte-identical production); NO `#+sbcl/#+clasp` outside `dds-pal/`; NO AI-assistant/co-author attribution; clean-room; SBOM auto-staged.

---

## Task 1: The guard + counter + hook + fault-injection + tests

**Files:**
- Modify: `src/dds-disc/disc.lisp` — add `(shmem-send-faults 0 :type fixnum)` to the `disc-node` defstruct (beside `shmem-sends` ~:134).
- Modify: `src/dds-disc/dataplane.lisp` — add `%note-shmem-send-fault` (beside the WP-SENDER-ERROR-RESILIENCE hook machinery); wrap the SHMEM send in `%send-raw-buf` (:81) in the `handler-case`.
- Modify: `src/dds-xport/shmem.lisp` — add `*debug-shmem-send-fault*` + the `shmem-send-test-fault` condition; inject at the top of `%shmem-send` (:212).
- Modify: `src/dds-xport/packages.lisp` — export `*debug-shmem-send-fault*`, `shmem-send-test-fault`.
- Test: add the 3 tests to the dds-tests file where the SHMEM loopback tests live (find it: `grep -rln 'shmem-transport\|disc-node-shmem\|shmem-sends' src/dds-tests/`); register in `run-all-tests`.

- [ ] **Step 1: Write the failing hard-fault→fallback test.** Set up a same-host SHMEM peer pair (copy the existing SHMEM loopback test setup — note SHMEM is active on SBCL; on Clasp-macOS it's UDP-only, so pass-skip there like the sibling SHMEM tests via the existing platform guard). Bind the hook to a recorder; `(setf dds.xport.shmem:*debug-shmem-send-fault* t)`; publish a user DATA to the SHMEM peer; assert: the peer RECEIVED it (via the UDP fallback), `(disc-node-shmem-send-faults node)` = 1, the hook fired with context `:shmem-send-fault`, and `(disc-node-shmem-sends node)` did NOT increment (it went UDP). Run → FAIL (undefined symbols).

- [ ] **Step 2: Run → confirm failure.** `make test-sbcl`.

- [ ] **Step 3: Implement.**
  - disc.lisp: `(shmem-send-faults 0 :type fixnum)` slot.
  - shmem.lisp: `(define-condition shmem-send-test-fault (error) () (:documentation "Test-only synthetic %shmem-send hard fault, injected by *DEBUG-SHMEM-SEND-FAULT*."))`; `(defparameter *debug-shmem-send-fault* nil "Test affordance (inert when NIL): when non-NIL, %SHMEM-SEND signals SHMEM-SEND-TEST-FAULT — exercises the %SEND-RAW-BUF self-guard → UDP fallback. Production default NIL = byte-identical.")`; at the TOP of `%shmem-send` (after the docstring/decls): `(when *debug-shmem-send-fault* (error 'shmem-send-test-fault))`.
  - packages.lisp (dds.xport.shmem): export both.
  - dataplane.lisp: `%note-shmem-send-fault`:
    ```lisp
    (defun* %note-shmem-send-fault (node condition)
        (function (disc-node condition) fixnum)
      "WP-SHMEM-SEND-SELF-GUARD: a hard %shmem-send fault was caught in %send-raw-buf and the datagram is
       falling back to UDP — bump the node's SHMEM-SEND-FAULTS counter and fire *SENDER-EMIT-ERROR-HOOK*
       (context :shmem-send-fault), the hook call IGNORE-ERRORS-guarded so a signaling hook can't break the send."
      (let ((n (incf (disc-node-shmem-send-faults node))))
        (ignore-errors (funcall *sender-emit-error-hook* condition :shmem-send-fault n))
        n))
    ```
    Then wrap the SHMEM send in `%send-raw-buf`:
    ```lisp
    (when (and shmem-dest (disc-node-shmem node))
      (when (plusp (handler-case
                       (dds.xport:send (dds.xport.shmem:shmem-transport-transport (disc-node-shmem node))
                                       shmem-dest buf 0 len)
                     (error (c) (%note-shmem-send-fault node c) 0)))   ; hard SHMEM fault → counter+hook, fall to UDP
        (incf (disc-node-shmem-sends node))
        (return-from %send-raw-buf t)))
    ```

- [ ] **Step 4: Run → pass.** `make test-sbcl`. Fix until green.

- [ ] **Step 5: Add the lane-full + no-regression tests.**
  - Lane-full (no counter/hook): if a return-0 from the SHMEM send is awkward to force, assert the distinction structurally — a no-fault SHMEM send increments `shmem-sends` (not `shmem-send-faults`) and the hook does not fire; document that a return-0 path falls back to UDP without touching the counter (the `handler-case` only catches a SIGNAL).
  - No-regression: `*debug-shmem-send-fault*` NIL → a normal SHMEM send still delivers over SHMEM (`shmem-sends` increments, faults 0); AND a `shmem-dest`-NIL send (UDP/foreign) is byte-identical (the guard is inert — the SHMEM block is skipped entirely). Reuse an existing send test for the byte-identity.

- [ ] **Step 6: Both impls + commit.** `make test-sbcl` + `make test-clasp` (the SHMEM-specific test pass-skips on Clasp-macOS; the no-regression test runs on both). `make gate-hotpath` + `make mem` 0.0000 (the guard is off the measured CDR path).
```bash
git add -A
git commit -m "feat(xport): WP-SHMEM-SEND-SELF-GUARD a hard %shmem-send fault → UDP fallback + counter + sender-error hook (FR-XPORT-2)"
```

---

## Task 2: Cross-DDS no-regression interop + gates + docs

**Files:** `interop/` (a no-regression note + optional capture, or reuse an existing SHMEM/UDP interop run); `docs/adr/0013-pal-shmem-and-m1-atomics.md` (extend); `README.md`; `docs/wiki/transports.md`; `docs/verification.csv`; `docs/provenance.md`.

- [ ] **Step 1: Cross-DDS no-regression (the per-feature DoD — minimal SHMEM wire surface).** SHMEM is ours-to-ours; a foreign peer always gets UDP (`shmem-dest` NIL → the guard is inert). Run a live Connext + Fast DDS subscriber against our publisher (reuse an existing interop harness, e.g. shapes) and confirm delivery is byte-identical to before this WP (the guard never triggers for a foreign UDP dest). tshark-spot-check + record. (The our-to-our fault→fallback is the unit test from Task 1; this step is the foreign-peer no-regression.) Document honestly: this WP has minimal wire-observable cross-DDS surface (SHMEM is same-host ours-to-ours).

- [ ] **Step 2: Full gate sweep, both impls.** `make build test corpus gate-types gate-hotpath mem fuzz` on SBCL + Clasp. Report each + totals. `make mem` 0.0000 (the guard is off the measured CDR path) — state NO bench warranted (no measured-path number moved).

- [ ] **Step 3: Docs lockstep (§5.1).** ADR 0013 as-built note (the SHMEM-send self-guard → UDP fallback + the counter/hook + the layering rationale); README (the transports/SHMEM status line); `docs/wiki/transports.md` (the self-guard behavior + the `*sender-emit-error-hook*` `:shmem-send-fault` context + the `shmem-send-faults` counter); verification.csv (FR-XPORT-2 rows: the fault→fallback + the no-regression interop); provenance (clean-room; implementation-defined local-send-error handling).

- [ ] **Step 4: Commit.**
```bash
git add -A
git commit -m "docs(xport): WP-SHMEM-SEND-SELF-GUARD ADR 0013/README/wiki/verification + cross-DDS no-regression (FR-XPORT-2, §5.1)"
```

---

## Self-review notes (author)
- **Spec coverage:** Task 1 = the guard + counter + hook + injector + the fault/lane-full/no-regression tests; Task 2 = the cross-DDS no-regression interop + gates + docs. All spec sections covered.
- **Layering:** the catch is in `%send-raw-buf` (dds.disc) — the counter (`disc-node-shmem-send-faults`) + the hook (`*sender-emit-error-hook*`) are in scope without an upward dds.xport→dds.disc dependency. The SHMEM `:send` lambda is NOT wrapped (that would catch→0 before %send-raw-buf and defeat the counter/hook).
- **Distinction:** the `handler-case` fires only on a SIGNAL (hard fault → counter+hook); a return-0 (lane-full) is the benign existing UDP-fallback path (no counter/hook).
- **NFR-PORT:** SHMEM is SBCL-full / Clasp-macOS-UDP — the SHMEM-specific fault test pass-skips where SHMEM is inactive (mirror the existing SHMEM tests); the no-regression (UDP) test runs on both.
- **Type consistency:** `%note-shmem-send-fault (node condition) → fixnum`; the hook is `(condition context count)` with context `:shmem-send-fault`; `*debug-shmem-send-fault*` inert when NIL.
