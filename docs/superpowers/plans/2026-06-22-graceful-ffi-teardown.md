# WP-GRACEFUL-FFI-TEARDOWN Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A graceful, signal-driven teardown so `kill -15` (SIGTERM) / Ctrl-C (SIGINT) of `durability-service-main` stops the service threads and frees the store/DARE/arena in order, then exits cleanly — no SIGBUS.

**Architecture:** A PAL `install-signal-handler` primitive (impl-specific → `dds-pal/`) registers a callback that sets a shutdown flag; `durability-service-main` replaces its `(loop (sleep 1))` with a flag-polling loop that, on signal, runs the existing orderly teardown (`supervisor-stop` → `runner-stop`, which `service-stop`s each service: join threads → close store) then `uiop:quit 0`. The threads are joined before the FFI/arena is freed, so nothing is mid-foreign-call at teardown.

**Tech Stack:** Common Lisp (SBCL + Clasp, full signal handling on both), `dds-pal` (the PAL), `dds-durability` (`main.lisp`, `service.lisp`), `cffi` (impl-agnostic `kill(2)`/`getpid(2)` for the test), the existing `interop/` harnesses.

## Global Constraints

- **No reader conditionals outside `dds-pal/`** — the impl-specific signal code (SBCL `sb-sys:enable-interrupt`, Clasp native) lives ONLY in `pal-sbcl.lisp`/`pal-clasp.lisp`. The test raises a signal via impl-agnostic CFFI (`kill`/`getpid`), not a reader conditional.
- **`defun*`/`defstruct*`** + **full ftype** on every new function.
- **Clasp AND SBCL both validate, Clasp first.** Clasp has full signal handling (owner-confirmed) — no NFR-PORT gap expected.
- **Control-plane only** (the shutdown path); `gate-hotpath` + `make mem` 0.0000 unaffected.
- **Scope:** the `:process` entrypoint `durability-service-main` only. The embedded/in-thread service is the host application's concern (a library must not steal the host's SIGTERM/SIGINT).
- **No AI / assistant attribution** in any repo file.

## File map

- `src/dds-pal/pal-contract.lisp` — add `#:install-signal-handler` to the `dds.pal` `:export` list.
- `src/dds-pal/pal-sbcl.lisp` — `install-signal-handler` (SBCL: `sb-sys:enable-interrupt`).
- `src/dds-pal/pal-clasp.lisp` — `install-signal-handler` (Clasp native signal facility).
- `src/dds-durability/main.lisp` — `durability-service-main` (~185): the shutdown flag + handler wiring + the flag-polling teardown loop.
- `src/dds-durability/service.lisp` — `service-stop` (~437): UNCHANGED (order already correct); covered by a T2 order test.
- `src/dds-tests/` — `pal-test.lisp` (signal-handler unit) + `durability-test.lisp` (teardown-order test) + registration.
- `interop/graceful-shutdown/` (new, T3) — the `kill -15` clean-exit harness.
- `docs/adr/0030-graceful-ffi-teardown.md` (new); `docs/wiki/durability.md`, `README.md`, `docs/verification.csv` (T3).

---

### Task 1: PAL `install-signal-handler`

**Files:**
- Modify: `src/dds-pal/pal-contract.lisp` (the `:export` list, ~line 33)
- Modify: `src/dds-pal/pal-sbcl.lisp` (new `install-signal-handler`)
- Modify: `src/dds-pal/pal-clasp.lisp` (new `install-signal-handler`)
- Test: `src/dds-tests/pal-test.lisp` (`run-pal-signal-handler-test`), registered + exported

**Interfaces:**
- Produces: `dds.pal:install-signal-handler (signals callback) → t` — `signals` is a list of `(member :term :int)`; `callback` is a 0-arg function invoked (in the signal-handler context) when one of those process signals is delivered. The callback MUST do only minimal async-signal-safe work (set a flag / wake a thread).

- [ ] **Step 1: Export the symbol.** In `src/dds-pal/pal-contract.lisp`, add `#:install-signal-handler` to the `:export` list next to the threading exports (the line with `#:spawn #:join ...`).

- [ ] **Step 2: Write the failing test.** In `src/dds-tests/pal-test.lisp` (or the existing PAL test file — match where PAL tests live; if none, create it + register in `echo-test.lisp`):

```lisp
(defun* run-pal-signal-handler-test ()
    (function () t)
  "install-signal-handler registers a non-terminating handler: raising SIGTERM to our own
   process invokes the callback (sets the flag) and we keep running (the default terminate
   is overridden). Impl-agnostic raise via CFFI kill(2)/getpid(2)."
  (let ((fired nil))
    (dds.pal:install-signal-handler '(:term) (lambda () (setf fired t)))
    (cffi:foreign-funcall "kill"
                          :int (cffi:foreign-funcall "getpid" :int)
                          :int 15 :int)
    (loop repeat 200 until fired do (sleep 0.01)) ; let the async handler run
    (%check :pal-signal-handler-fired fired
            "install-signal-handler's callback must run on SIGTERM (and we must NOT terminate)"))
  t)
```
(Use the project's `%check`/assertion helper as the other tests do.)

- [ ] **Step 3: Run it — expect FAIL** (`install-signal-handler` undefined). Clasp first:
```
./scripts/with-clasp.sh --eval '(ql:quickload :dds-tests :silent t)' --eval '(handler-case (progn (dds.tests:run-pal-signal-handler-test) (uiop:quit 0)) (error (e) (format t "~&FAIL ~a~%" e) (uiop:quit 1)))'
```
Expected: FAIL — `INSTALL-SIGNAL-HANDLER is undefined`.

- [ ] **Step 4: SBCL impl.** In `src/dds-pal/pal-sbcl.lisp` (package `dds.pal`), near `spawn`:
```lisp
(defun* install-signal-handler (signals callback)
    (function (list function) (eql t))
  "Register CALLBACK for each process signal in SIGNALS (a list of (member :term :int)) — SBCL via
   sb-sys:enable-interrupt. The handler runs CALLBACK in the signal context; CALLBACK must be minimal
   (set a flag / wake a thread), never do teardown inline. No reader conditional escapes dds-pal/."
  (dolist (s signals)
    (let ((signum (ecase s
                    (:term sb-unix:sigterm)
                    (:int  sb-unix:sigint))))
      (sb-sys:enable-interrupt
       signum
       (lambda (signo info context)
         (declare (ignore signo info context))
         (funcall callback)))))
  t)
```

- [ ] **Step 5: Clasp impl.** In `src/dds-pal/pal-clasp.lisp` (package `dds.pal`), implement the SAME contract using Clasp's native signal-handler facility (Clasp has full signal handling — owner-confirmed). Map `:term`→SIGTERM(15), `:int`→SIGINT(2); register a handler that invokes `callback`. Pin the exact Clasp symbol from the installed Clasp build's source/docs (e.g. Clasp's `core:`/`ext:` signal API or `clasp-cl`'s `sys:`); the handler must call `callback` with no args. Keep the SBCL/Clasp signatures identical.

- [ ] **Step 6: Run the test — expect PASS** (Clasp first, then SBCL). Ensure `cffi` is available in the test image (the durability/DARE systems already depend on it).

- [ ] **Step 7: Register + gate + commit.** Export `#:run-pal-signal-handler-test`; register in `echo-test.lisp`. Then:
```
make test-clasp && make test-sbcl && make gate-hotpath && make gate-types
git add src/dds-pal/pal-contract.lisp src/dds-pal/pal-sbcl.lisp src/dds-pal/pal-clasp.lisp src/dds-tests/pal-test.lisp src/dds-tests/echo-test.lisp src/dds-tests/packages.lisp
git commit -m "feat(pal): WP-GRACEFUL-FFI-TEARDOWN — dds.pal:install-signal-handler (SBCL sb-sys:enable-interrupt + Clasp native; SIGTERM/SIGINT -> callback) (M6/P5, ADR 0026 §10)"
```
Expected: both impls green (Clasp first), gate-hotpath PASS, gate-types PASS (+1 ftype'd defun). Note: the lingering flag-setting handler is benign for the rest of the test run (no further SIGTERM is raised).

---

### Task 2: `durability-service-main` graceful teardown

**Files:**
- Modify: `src/dds-durability/main.lisp` (`durability-service-main` ~185-202; a new `%graceful-shutdown` helper)
- Test: `src/dds-tests/durability-test.lisp` (`run-durability-graceful-teardown-order-test`)

**Interfaces:**
- Consumes: `dds.pal:install-signal-handler` (T1); `runner-stop (runner)`, `supervisor-stop (supervisor)`; `service-stop` (joins threads then `store-close`); `service-alive-p`.
- Produces: `durability-service-main` with `:block t` waits for a shutdown signal then tears down in order and `uiop:quit 0`s.

- [ ] **Step 1: Write the failing test.** In `src/dds-tests/durability-test.lisp`, an in-process test that the orderly teardown reaches the end state (threads stopped, store closed) — driven directly (NOT via signal, which would quit the test process):

```lisp
(defun* run-durability-graceful-teardown-order-test ()
    (function () t)
  "The graceful teardown stops the service threads and closes the store: after the orderly stop
   (supervisor-stop -> runner-stop -> service-stop), no collect thread is alive and the store is
   closed. service-stop's join-before-close order (service.lisp) is the no-thread-mid-foreign-call
   prerequisite. Domain 82, in-memory store."
  (let* ((store (dds.durability:make-memory-store))
         (spec (dds.durability:make-service-spec
                :domain 82 :topics '(("GtSquare" . "ShapeType")) :store (lambda () store)
                :name "graceful-teardown"))
         (svc (dds.durability:make-durability-service spec :store store)))
    (dds.durability:service-start svc)
    (%check :gt-alive-before (dds.durability:service-alive-p svc) "service must be alive after start")
    (dds.durability:service-stop svc)
    (%check :gt-not-alive-after (not (dds.durability:service-alive-p svc))
            "after service-stop every collect thread must be joined (not alive)"))
  t)
```
(If a public predicate for "store closed" exists, also assert it; otherwise the alive-p end state + the by-inspection order is the gate. Use the proven scaffolding from `run-durability-no-double-delivery-test`.)

- [ ] **Step 2: Run it — expect PASS already** (service-stop is correct today) — this test pins the order invariant as a regression guard. Clasp first. If it does not pass, the order is wrong and must be fixed in `service-stop` before proceeding.

- [ ] **Step 3: Add the graceful-shutdown helper + wire the handler.** In `src/dds-durability/main.lisp`, add a shutdown flag (a special variable) and a helper, and make `durability-service-main`'s block path signal-aware. Replace the `(if block (loop (sleep 1)) (cons runner sup))` tail:

```lisp
(defvar *durability-shutdown-requested* nil
  "Set by the SIGTERM/SIGINT handler installed in DURABILITY-SERVICE-MAIN; the block loop polls it.")

(defun* %graceful-shutdown (runner sup)
    (function (t t) t)
  "Orderly teardown: stop supervising (no restarts), then stop the runner (service-stop each service =
   join collect threads THEN close the store + free DARE/arena). Threads are joined before the FFI is
   freed, so nothing is mid-foreign-call at teardown (resolves the kill -15 SIGBUS, ADR 0026 §10)."
  (ignore-errors (supervisor-stop sup))
  (ignore-errors (runner-stop runner))
  t)
```
and in `durability-service-main`, the `block` branch becomes:
```lisp
        (if block
            (progn
              (setf *durability-shutdown-requested* nil)
              (dds.pal:install-signal-handler
               '(:term :int)
               (lambda () (setf *durability-shutdown-requested* t)))
              (loop until *durability-shutdown-requested* do (sleep 0.2))
              (%graceful-shutdown runner sup)
              (uiop:quit 0))
            (cons runner sup))
```

- [ ] **Step 4: Run the order test again — expect PASS** (Step 2's test still green; the main change is the signal wiring, tested live in T3).

- [ ] **Step 5: Register + gate + commit.** Export `#:run-durability-graceful-teardown-order-test`; register in `echo-test.lisp`. Then `make test-clasp && make test-sbcl && make gate-hotpath && make gate-types && make mem`; commit `feat(durability): WP-GRACEFUL-FFI-TEARDOWN — durability-service-main installs a SIGTERM/SIGINT handler + orderly teardown (supervisor-stop -> runner-stop = join threads before freeing the store/DARE) -> uiop:quit 0 (M6/P5, ADR 0026 §10)`.

---

### Task 3: LIVE `kill -15` verify + deepen-if-needed + capstone

**Files:**
- Create: `interop/graceful-shutdown/run-kill15.sh` (the clean-exit harness)
- Create: `docs/adr/0030-graceful-ffi-teardown.md`; modify `README.md`, `docs/wiki/durability.md`, `docs/verification.csv`

- [ ] **Step 1: The `kill -15` clean-exit harness.** `interop/graceful-shutdown/run-kill15.sh`: for each impl (Clasp first, then SBCL), launch a `durability-service-main` process over a PERSISTENT (DARE/file) config (reuse a `make-persistent-store-factory` config like `interop/durability-keeplast/driver-serve.lisp`, or `durability-service-main` with `:argv` selecting a file-backed tier), let it settle, `kill -15 <pid>`, wait, and assert: the process exited cleanly (no `SIGBUS`/`Bus error`/`signal 10` on its stderr; a clean exit code), within a timeout. Capture stderr to a log and grep it.

```bash
# sketch — the implementer fills the launch line + the config for a DARE/file-backed service
launch_and_kill() {  # $1 = lisp launcher (with-clasp.sh|with-sbcl.sh)
  "$1" --load interop/graceful-shutdown/driver.lisp > /tmp/gshut-$2.log 2>&1 &
  pid=$!; sleep 6
  kill -15 "$pid"
  for i in $(seq 1 50); do kill -0 "$pid" 2>/dev/null || break; sleep 0.2; done
  wait "$pid"; rc=$?
  grep -iE 'sigbus|bus error|signal 10' /tmp/gshut-$2.log && { echo "SIGBUS on $2"; return 1; }
  echo "$2: clean exit rc=$rc, no SIGBUS"; return 0
}
```

- [ ] **Step 2: Run it both impls.** `interop/graceful-shutdown/run-kill15.sh`. Expected: both Clasp and SBCL print "clean exit, no SIGBUS". The driver must start a DARE/file-backed durability service (the SIGBUS only appeared with the OpenSSL/arena FFI live).

- [ ] **Step 3: Deepen-if-needed (conditional).** If a SIGBUS still appears for a vendor/impl after Step 2, it is an OpenSSL-internal thread: add explicit OpenSSL teardown before exit — call `OPENSSL_cleanup` via the DARE FFI in the teardown path (`%graceful-shutdown`, after `runner-stop`), and/or signal-masking. Re-run Step 2. Document whichever was needed honestly in the ADR. If Step 2 was already clean, record that graceful Lisp shutdown alone sufficed (no OpenSSL cleanup needed) — do NOT add dead code.

- [ ] **Step 4: ADR 0030 + docs lockstep.** `docs/adr/0030-graceful-ffi-teardown.md` (as-built: the root cause; `install-signal-handler`; the orderly teardown; whether deepening was needed; resolves ADR 0026 §10 item 3). Mark ADR 0026 §10 item 3 RESOLVED. Update `README.md` (P5/durability-service row), `docs/wiki/durability.md` (the signal-driven shutdown + the `install-signal-handler` PAL primitive), and append a clean 6-column `P5-GRACEFUL-SHUTDOWN` row to `docs/verification.csv` (verify it parses, last row 6 cols).

- [ ] **Step 5: Full gate sweep both impls (Clasp first) + commit.**
```
make test-clasp && make test-sbcl && make gate-hotpath && make gate-types && make mem && make fuzz && make wire
git add interop/graceful-shutdown docs/adr/0030-graceful-ffi-teardown.md README.md docs/wiki/durability.md docs/verification.csv
git commit -m "test(interop)+docs: WP-GRACEFUL-FFI-TEARDOWN — kill -15 clean-exit proof both impls + ADR 0030 (resolve ADR 0026 §10 item 3) (M6/P5)"
```
Then (controller, NOT this task) the final whole-branch review → squash-merge presented for owner approval (HOLD PUSH).

---

## Self-review

**Spec coverage:** §4.1 PAL primitive → T1. §4.2 `durability-service-main` teardown → T2. §4.3 verify `service-stop` order → T2 Step 1-2 (already correct, pinned by the order test). §4.4 deepen-if-needed → T3 Step 3. §5 scope (process entrypoint) → T2 (only `durability-service-main` touched). §6 testing: unit (T1), order (T2), LIVE kill -15 (T3), gates (T3 Step 5). §7 decomposition → the 3 tasks. All covered.

**Placeholder scan:** the SBCL impl + the test + the main wiring carry complete code. The Clasp signal symbol (T1 Step 5) and the T3 driver launch line are the only "implementer pins it" points — both are impl-/environment-specific knowns (Clasp's documented signal API; the existing interop driver pattern), not vague requirements; each names exactly what to pin and where the pattern lives.

**Type consistency:** `install-signal-handler (signals callback) → t` defined in T1, consumed in T2's handler-install. `%graceful-shutdown (runner sup) → t` defined + called in T2. `*durability-shutdown-requested*` set by the handler, polled by the loop. `supervisor-stop`/`runner-stop`/`service-stop`/`service-alive-p` are existing signatures (verified in service.lisp/runner.lisp/supervisor.lisp).
