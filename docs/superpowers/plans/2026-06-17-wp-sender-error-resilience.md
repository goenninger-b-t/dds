# WP-SENDER-ERROR-RESILIENCE Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the two background sender threads (`%async-sender-loop`, `%flow-scheduler-loop`) survive a transient error raised by a per-iteration emit — catch `error`, observe it (a bindable hook + a counter), continue — instead of dying and silently stalling the writers they serve.

**Architecture:** One DRY macro `with-sender-emit-guard` wraps the emit in each loop; a bindable `*sender-emit-error-hook*` + per-thread counters give observability; a `*debug-emit-fault*` test affordance in the shared send primitive `%send-raw-buf` lets tests induce a transient fault deterministically. The flow path advances its plan cursor unconditionally (Option 1: drop + advance; reliability repairs via the existing NACK/HEARTBEAT path — the unsent watermark advances at snapshot time, so a drained faulted plan is never re-snapshotted → no spin). Non-R6; SBCL + Clasp.

**Tech Stack:** Common Lisp (SBCL + Clasp), `dds.disc` package, `defun*`/`defstruct*` + full type declarations (FR-LANG-8), the existing test framework (`run-*-test` functions registered in the suite), `make` gate targets, the interop harness (`interop/`, `scripts/with-fastdds.sh`, rtiddsgen).

**Spec:** `docs/superpowers/specs/2026-06-17-wp-sender-error-resilience-design.md` (read it; this plan implements it).

**Conventions (NON-NEGOTIABLE):** one-line code comments only (longer rationale in the commit message); every `defun*` fully type-declared; every struct `defstruct*`; docstrings on the new special var + exported symbols (operating contract §5.1); cite RTPS 2.5 §8.4 where relevant; NO `#+sbcl/#+clasp` outside `dds-pal/`; NO "Claude"/AI/co-author attribution anywhere; clean-room; SBOM auto-staged by the pre-commit hook; present no perf claim without a number (the sender threads are off the measured hot path — assert `make mem` 0.0000 unchanged, no bench needed).

---

## Task 1: Guard machinery + async path + slice tests (the MVP vertical slice)

Delivers a thin end-to-end slice: the async sender thread survives an injected emit fault, observably, with a passing test — and the inert (no-fault) path is byte-identical.

**Files:**
- Modify: `src/dds-disc/dataplane.lisp` — add the condition, `*debug-emit-fault*`, the fault injection in `%send-raw-buf` (:32), the guard macro + hook machinery (near the other test-vars at :25/:285), and wire `%async-sender-loop` (:746).
- Modify: the `disc-node` `defstruct*` (find it: `grep -n 'defstruct\* disc-node\|defstruct (disc-node' src/dds-disc/*.lisp`) — add an `async-emit-errors` slot.
- Modify: `src/dds-disc/packages.lisp` — export `*sender-emit-error-hook*`, `with-sender-emit-guard`, `*debug-emit-fault*`, `sender-emit-test-fault`.
- Test: add `run-async-emit-fault-survives-test` and `run-emit-fault-inert-test` to the dds-disc integration test file (find where async/flow tests live: `grep -rln 'enable-async\|%async-sender-loop\|flow-controller' src/dds-tests/`; likely `src/dds-tests/echo-test.lisp` or `integration-test.lisp`) and register them in the suite runner.

- [ ] **Step 1: Write the failing test (async survives + continues).**

In the chosen dds-tests file, add (adapt the loopback setup to the file's existing helpers — copy the pattern of an existing `enable-async` test in that file):

```lisp
(defun* run-async-emit-fault-survives-test ()
    (function () (eql t))
  "WP-SENDER-ERROR-RESILIENCE scenario 1: the async sender thread survives an injected transient emit
   fault and keeps sending. Inject 3 faults; assert the thread is still alive, the hook fired 3x with
   :async-sender, the counter = 3, and post-fault samples are delivered to a loopback reader."
  (let ((fired '()))
    (let ((dds.disc:*sender-emit-error-hook*
            (lambda (c ctx n) (push (list ctx n (type-of c)) fired))))
      ;; <set up a node A with enable-publisher + enable-async + a reliable user writer,
      ;;  and a loopback node B with a matched reader — copy the existing async test's setup>
      (let ((a (… set up publisher node, enable-async …))
            (b (… set up subscriber node …)))
        (unwind-protect
             (progn
               (setf dds.disc:*debug-emit-fault* 3)            ; next 3 %send-raw-buf calls signal
               (dotimes (i 6) (dds.disc:publish-sample a (… 8-octet payload i …)))
               (… drive/settle the loopback for a bounded time so the async sender runs + repairs …)
               (assert (dds.pal:thread-alive-p (dds.disc::disc-node-async-thread a)))  ; thread SURVIVED
               (assert (= 3 (dds.disc::disc-node-async-emit-errors a)))                ; counter
               (assert (= 3 (length fired)))                                           ; hook fired 3x
               (assert (every (lambda (e) (eq :async-sender (first e))) fired))
               (assert (… B received all 6 samples (reliable repair after the 3 drops) …))
               t)
          (setf dds.disc:*debug-emit-fault* nil)
          (… tear down a, b …))))))
```

Register it in the suite runner (find it: `grep -rn 'run-.*-test)' src/dds-tests/*.lisp | grep -i 'list\|deftest\|suite'`).

- [ ] **Step 2: Run it — expect failure.**

Run: `make test-sbcl` (or the file's test entry). Expected: FAIL — `*sender-emit-error-hook*`, `*debug-emit-fault*`, `disc-node-async-emit-errors`, `with-sender-emit-guard` are undefined.

- [ ] **Step 3: Add the condition, the fault injector, and the guard machinery in `dataplane.lisp`.**

Near the existing test-vars (after `*datagram-sink*` at :25 / before `%send-raw-buf` at :32) add:

```lisp
(define-condition sender-emit-test-fault (error) ()
  (:report (lambda (c s) (declare (ignore c)) (format s "synthetic sender-thread emit fault (test only)")))
  (:documentation "Test-only synthetic error injected by *DEBUG-EMIT-FAULT* to exercise the sender-thread guards."))

(defparameter *debug-emit-fault* nil
  "Test affordance (inert when NIL): a positive integer N signals SENDER-EMIT-TEST-FAULT on the next N
   %SEND-RAW-BUF calls (decrementing); :PERSISTENT signals on every call. Production default NIL =
   byte-identical, zero effect. Mirrors *DEBUG-DROP-SAMPLE-NUMBERS*.")

(defparameter *sender-emit-error-hook* #'%default-sender-emit-error-hook
  "Funcallable (CONDITION CONTEXT COUNT) invoked when a sender thread's emit signals an ERROR that
   WITH-SENDER-EMIT-GUARD caught. CONTEXT is a keyword tagging the thread (:ASYNC-SENDER / :FLOW-SCHEDULER);
   COUNT is that thread's running error count. Runs ON the sender thread — it must not block; a signaling
   hook is itself swallowed (the thread is never re-killed by the hook). Default = %DEFAULT-SENDER-EMIT-ERROR-HOOK.")
```

Add the default hook + the note helper (define `%default-sender-emit-error-hook` BEFORE the `defparameter` that references it, or use a forward `declaim`/define-it-first ordering):

```lisp
(defun* %default-sender-emit-error-hook (condition context count)
    (function (condition t (integer 0)) t)
  "Default *SENDER-EMIT-ERROR-HOOK*: clockless rate-limited WARN to *ERROR-OUTPUT* — log only when COUNT is
   1 or a power of ten, so a persistent failure logs O(log n) lines, never a flood."
  (when (or (= count 1) (zerop (mod count 10)) (%power-of-ten-p count))   ; choose a simple rate rule
    (warn "dds sender thread (~a) emit error #~d: ~a" context count condition))
  t)

(defun* %note-sender-emit-error (context count-place condition)
    (function (t (integer 0) condition) (integer 0))
  "Bump COUNT-PLACE and invoke *SENDER-EMIT-ERROR-HOOK*; the hook call is IGNORE-ERRORS-guarded so a
   signaling hook cannot re-kill the sender thread."
  (let ((n (incf count-place)))
    (ignore-errors (funcall *sender-emit-error-hook* condition context n))
    n))
```

NOTE on `count-place`: a macro can't take a place as a function arg. Implement `%note-sender-emit-error` to take the NEW count value and have the MACRO do the `incf`. Final macro:

```lisp
(defmacro with-sender-emit-guard ((context count-place) &body body)
  "Run BODY (one sender-thread emit). On a caught ERROR (not SERIOUS-CONDITION), INCF COUNT-PLACE, fire
   *SENDER-EMIT-ERROR-HOOK* (itself guarded), and return NIL; on success return BODY's value. CONTEXT is a
   keyword tagging the thread. The thread never dies from one bad emit (RTPS 2.5 §8.4: a dropped DATA is
   recovered via HEARTBEAT/ACKNACK; a best-effort drop is conformant)."
  (let ((c (gensym "C")))
    `(handler-case (progn ,@body)
       (error (,c)
         (let ((n (incf ,count-place)))
           (ignore-errors (funcall *sender-emit-error-hook* ,c ,context n)))
         nil))))
```
(Drop the separate `%note-sender-emit-error` if the macro inlines the incf+hook as above — DRY: pick ONE form. The inlined-macro form is simplest; keep `%default-sender-emit-error-hook` for the default. Define `%default-sender-emit-error-hook` BEFORE the `defparameter *sender-emit-error-hook*`.)

Add the fault injection at the TOP of `%send-raw-buf` (after the `*datagram-sink*` block, before the SHMEM/UDP send):

```lisp
  (when *debug-emit-fault*
    (unless (eq *debug-emit-fault* :persistent) (decf *debug-emit-fault*))
    (error 'sender-emit-test-fault))
```

- [ ] **Step 4: Add the `async-emit-errors` slot to `disc-node`.**

In the `disc-node` `defstruct*`, add: `(async-emit-errors 0 :type fixnum)`.

- [ ] **Step 5: Wire `%async-sender-loop` (:746).**

Replace the unguarded send:
```lisp
      (when (disc-node-user-writer node)
        (%push-data-buf node (disc-node-async-tx-msg node)))
```
with:
```lisp
      (when (disc-node-user-writer node)
        (with-sender-emit-guard (:async-sender (disc-node-async-emit-errors node))
          (%push-data-buf node (disc-node-async-tx-msg node))))
```

- [ ] **Step 6: Export the new symbols** in `src/dds-disc/packages.lisp`: `*sender-emit-error-hook*`, `with-sender-emit-guard`, `*debug-emit-fault*`, `sender-emit-test-fault`.

- [ ] **Step 7: Run the test — expect pass.** `make test-sbcl`. Expected: `run-async-emit-fault-survives-test` PASS. Fix until green.

- [ ] **Step 8: Write + run the inert/regression test.**

```lisp
(defun* run-emit-fault-inert-test ()
    (function () (eql t))
  "WP-SENDER-ERROR-RESILIENCE scenario 4: with *DEBUG-EMIT-FAULT* NIL the guard is inert — a normal async
   publish delivers byte-identically (the *DATAGRAM-SINK* capture is unchanged vs a baseline) and no error
   counter advances."
  (… publish N samples with *debug-emit-fault* NIL; assert delivery + (= 0 async-emit-errors) + the
     datagram-sink captured the same bytes as a non-async baseline …))
```
Register + run. Expected PASS.

- [ ] **Step 9: Verify both impls + commit.**

Run: `make test` (Clasp) and `make test-sbcl`. Expected: both green, suite count +2.
Commit:
```bash
git add -A
git commit -m "feat(disc): WP-SENDER-ERROR-RESILIENCE guard the async sender thread — catch/observe/continue (FR-PF-2, RTPS 2.5 §8.4)"
```

---

## Task 2: Flow scheduler path + correctness tests

Extends the guard to the second sender thread and proves the two correctness claims: NO hot-spin under a persistent fault, and reliable repair after a transient drop.

**Files:**
- Modify: `src/dds-disc/flow-control.lisp` — add an `emit-errors` slot to the `flow-controller` `defstruct*` (find it: `grep -n 'defstruct' src/dds-disc/flow-control.lisp`); wire `%flow-scheduler-loop` (:243-257).
- Test: add `run-flow-emit-fault-no-spin-test`, `run-reliable-repair-after-drop-test`, `run-hook-self-error-test` to the dds-tests flow/integration file; register them.

- [ ] **Step 1: Write the failing no-spin test.**

```lisp
(defun* run-flow-emit-fault-no-spin-test ()
    (function () (eql t))
  "WP-SENDER-ERROR-RESILIENCE scenario 2: under a PERSISTENT emit fault the flow scheduler advances its plan
   cursor (drops + moves on), does NOT hot-spin (a BOUNDED number of hook-fires ~= the pending datagram
   count, not unbounded), survives, and resumes when the fault clears."
  (let ((fired 0))
    (let ((dds.disc:*sender-emit-error-hook* (lambda (c ctx n) (declare (ignore c ctx n)) (incf fired))))
      (… set up a flow-controller + a registered writer node with K pending datagrams …)
      (setf dds.disc:*debug-emit-fault* :persistent)
      (… publish K samples; settle a bounded time …)
      (assert (<= fired (+ K 2)))                       ; BOUNDED — not a spin (no unbounded growth)
      (assert (… scheduler thread alive …))
      (setf dds.disc:*debug-emit-fault* nil)
      (… publish + settle …)
      (assert (… the writer resumes — new samples delivered …))
      t)))
```
Run: `make test-sbcl`. Expected FAIL (`flow-controller-emit-errors` undefined / the loop not yet guarded).

- [ ] **Step 2: Add the `emit-errors` slot to `flow-controller`.** `(emit-errors 0 :type fixnum)`.

- [ ] **Step 3: Wire `%flow-scheduler-loop` (:250-254).**

Replace:
```lisp
              (let ((plan (dds.disc::disc-node-flow-step-state node)))
                (when plan
                  (dds.disc::%emit-plan-entry node (flow-controller-scratch controller) (car plan)
                                              (%flow-acquire-hook controller))
                  (setf (dds.disc::disc-node-flow-step-state node) (cdr plan)))))
```
with (catch INSIDE the unwind-protect's protected `progn`; advance the cursor UNCONDITIONALLY):
```lisp
              (let ((plan (disc-node-flow-step-state node)))
                (when plan
                  (with-sender-emit-guard (:flow-scheduler (flow-controller-emit-errors controller))
                    (%emit-plan-entry node (flow-controller-scratch controller) (car plan)
                                      (%flow-acquire-hook controller)))
                  (setf (disc-node-flow-step-state node) (cdr plan)))))   ; advance whether sent or dropped (Option 1)
```
(Same package `dds.disc`, so drop the `dds.disc::` qualifiers if the surrounding code does — match the file's local style.)

- [ ] **Step 4: Run the no-spin test — expect pass.** `make test-sbcl`. Fix until green.

- [ ] **Step 5: Write + run the reliable-repair test (scenario 3).**

```lisp
(defun* run-reliable-repair-after-drop-test ()
    (function () (eql t))
  "WP-SENDER-ERROR-RESILIENCE scenario 3 (Option-1 conformance, RTPS 2.5 §8.4): a reliable writer + reader;
   drop exactly ONE DATA via *DEBUG-EMIT-FAULT* = 1; assert the reader STILL receives that sample via the
   HEARTBEAT/ACKNACK repair path (the sample stayed in the HistoryCache; the watermark was not touched)."
  (… reliable writer A + reader B loopback; publish sample s; set *debug-emit-fault* 1 around the push of s
     (or a specific sample); drive the periodic-heartbeat + ACKNACK repair; assert B eventually has s …))
```
Run. Expected PASS (proves drop-and-recover).

- [ ] **Step 6: Write + run the hook-self-error test (scenario 5).**

```lisp
(defun* run-hook-self-error-test ()
    (function () (eql t))
  "WP-SENDER-ERROR-RESILIENCE scenario 5: a *SENDER-EMIT-ERROR-HOOK* that itself signals must NOT re-kill the
   sender thread (the IGNORE-ERRORS around the hook call)."
  (let ((dds.disc:*sender-emit-error-hook* (lambda (c ctx n) (declare (ignore c ctx n)) (error "hook boom"))))
    (… enable-async; *debug-emit-fault* 2; publish; assert the async thread is STILL ALIVE …)
    t))
```
Run. Expected PASS.

- [ ] **Step 7: Both impls + commit.**

`make test` + `make test-sbcl` → both green, suite +3.
```bash
git add -A
git commit -m "feat(disc): WP-SENDER-ERROR-RESILIENCE guard the flow scheduler — cursor advances on drop, no hot-spin, reliable repair (FR-PF-2, RTPS 2.5 §8.4)"
```

---

## Task 3: Cross-DDS interop (the per-feature DoD — RTI Connext + Fast DDS, both run live)

Prove the guard on a real wire-interop path: induce a mid-stream emit fault while publishing to a live Connext and a live Fast DDS subscriber; assert our publisher process survives AND the foreign peer still receives all reliable samples.

**Files:**
- Create: `interop/sender-resilience/README.md` (the procedure + results), `interop/sender-resilience/captures/` (pcaps).
- Modify: the Lisp publisher harness — add an env gate to inject a mid-stream fault. Find the existing run-publisher entrypoint + its env gates (`grep -rn 'run-publisher\|getenv.*ASYNC\|getenv.*LIVELINESS' src/dds-bench/ src/dds-tests/ src/`). Add `FAULT=k@j` (after the j-th publish, set `*debug-emit-fault*` = k) + ensure `ASYNC=t` enables async. Reuse the existing Shapes (or the simplest existing interop topic) — do NOT invent a new type.
- Reuse: the existing Connext subscriber (`interop/connext/…`) and Fast DDS subscriber (`interop/fastdds/…`, via `scripts/with-fastdds.sh`). Do NOT copy vendor source; reuse the committed harnesses.

- [ ] **Step 1: Add the `FAULT=k@j` env gate to the publisher harness.** Mirror the existing `ASYNC=`/`LIVELINESS=` env-gate pattern in that harness; inert when unset (byte-identical). One-line comment; `defun*` typed.

- [ ] **Step 2: Connext leg.** Start the Connext Shapes subscriber (reliable); run our publisher `ASYNC=t FAULT=3@5 RELIABLE=t COUNT=30` to it; tshark-capture lo0 (clean `WIRESHARK_CONFIG_DIR`). Assert: our pub process exits cleanly (the sender thread survived), and the Connext sub received all 30 reliable samples. Save `captures/sender-resilience-connext.pcap`. Record the exact commands + counts in the README.

- [ ] **Step 3: Fast DDS leg.** Same against the Fast DDS Shapes subscriber via `scripts/with-fastdds.sh`. Assert pub survival + 30/30 received. Save `captures/sender-resilience-fastdds.pcap`. Record in the README.

- [ ] **Step 4: No-fault baseline (both peers).** `ASYNC=t` with no FAULT → confirm normal full delivery + byte-identical wire (the guard inert). Note in the README.

- [ ] **Step 5: Commit.**
```bash
git add -A
git commit -m "test(interop): WP-SENDER-ERROR-RESILIENCE sender survives a mid-stream emit fault, peer still receives all reliable samples — LIVE vs Connext + Fast DDS (FR-PF-2)"
```

---

## Task 4: Gates + docs (capstone)

**Files:**
- Modify: `docs/adr/0016-*.md` (WP-ASYNC-FLOW — this is its deferred Should-fix follow-up; add an as-built note) OR a new `docs/adr/0021-sender-error-resilience.md` (prefer extending 0016 if it cleanly fits; else 0021). `README.md` (P4/reliability status). `docs/wiki/` (the reliability/transports/async page — the guard + the hook + the §8.4 drop-and-recover rationale + the `*sender-emit-error-hook*` API). `docs/verification.csv` (FR-PF-2: the guard + the 6 tests + the interop). `docs/provenance.md` (clean-room note — no new external source; cite RTPS §8.4).

- [ ] **Step 1: Full gate sweep, both impls.** `make build test corpus gate-types gate-hotpath mem fuzz` on SBCL and Clasp (`*-clasp`/`*-all` variants per the repo's targets). Report each + totals. Confirm `make mem` 0.0000 (the guard is off the measured path) — state explicitly NO bench is warranted (no hot-path number changed; do not fabricate one).

- [ ] **Step 2: Docs lockstep (§5.1).** Docstrings already on the new symbols (Task 1); add the ADR as-built note, the README status line, the wiki API + use-case + worked example (binding `*sender-emit-error-hook*`), the verification.csv rows, the provenance note.

- [ ] **Step 3: Commit.**
```bash
git add -A
git commit -m "docs(disc): WP-SENDER-ERROR-RESILIENCE ADR/README/wiki/verification — sender-thread emit guard (FR-PF-2, §5.1)"
```

---

## Self-review notes (author)
- **Spec coverage:** Task 1 = machinery + async + scenarios 1,4; Task 2 = flow + scenarios 2,3,5; Task 3 = scenario 6 (interop DoD); Task 4 = gates + docs. All spec sections covered.
- **Type consistency:** the hook is `(condition context count)` everywhere; the macro signature is `((context count-place) &body body)`; the counters are `disc-node-async-emit-errors` / `flow-controller-emit-errors`. The `*debug-emit-fault*` semantics (integer-decrement / `:persistent`) are used consistently in Tasks 1–3.
- **DRY:** one macro, one default hook, one fault injector in the single shared send primitive (`%send-raw-buf`).
- **Open implementation choice (flag to the implementer):** pick ONE of the inlined-macro form vs the `%note-sender-emit-error` helper (the plan shows the inlined macro as the chosen form); do not ship both. Ensure `%default-sender-emit-error-hook` is defined before the `defparameter` that references it (load/define order). Verify `dataplane.lisp` precedes `flow-control.lisp` in the `.asd` so the macro is available at `flow-control.lisp` compile time (it does today — both in `dds.disc`, flow-control depends on dataplane).
