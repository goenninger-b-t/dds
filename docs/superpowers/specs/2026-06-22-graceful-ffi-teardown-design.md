# WP-GRACEFUL-FFI-TEARDOWN — design

- **Status:** Approved (design), 2026-06-22. M6/P5. Resolves ADR 0026 §10 item 3
  ("Graceful FFI teardown on signal").
- **Relates to:** ADR 0021 (durability service: `durability-service-main` CLI/process entrypoint, the
  multi-service runner, the OTP-style supervisor), ADR 0025/0026 (DARE/OpenSSL FFI + the static arena),
  the PAL contract (`dds-pal/`).
- **Constraints:** NFR-PORT (SBCL + Clasp; Clasp has full signal handling — owner-confirmed 2026-06-22);
  no reader conditionals outside `dds-pal/` (so the impl-specific signal primitive lives in the PAL).

---

## 1. Problem — the SIGBUS root cause

There is **no signal handling anywhere** in the stack. `durability-service-main` (`src/dds-durability/
main.lisp` ~line 185) starts the service and blocks for the configured lifetime. On `kill -15` (SIGTERM —
how the interop harnesses and any process supervisor stop a `:process`-mode service), SBCL's/Clasp's
default SIGTERM action tears the process down **abruptly while the service threads are still live**:

- The service runs several **Lisp threads** via `dds.pal:spawn` — the collect loop, the disc-node
  **receiver thread** (typically blocked in a foreign `recvmmsg`/`recvfrom`), the async sender, the
  supervisor watch loop — plus **OpenSSL-internal threads** from the DARE FFI.
- When the process is killed mid-foreign-call (a thread inside a `recvmmsg`/OpenSSL call), or the static
  arena / FFI state is unmapped under a still-running thread, that thread faults → the **benign SIGBUS in
  a non-Lisp thread** observed post-run in `interop/durability-persistent/` and `interop/durability-keeplast/`.

It is cosmetic/post-run (the durability work is already done + fsync'd before the kill), but it is an
unclean shutdown. ADR 0026 §10 item 3 records it verbatim and defers the fix here.

**The core issue is simply that nobody calls the orderly teardown on `kill -15` — the process just dies.**
`service-stop` already exists and stops the threads + closes the store in order; it is never invoked on a
signal.

## 2. Goal

A graceful, signal-driven teardown: SIGTERM/SIGINT stops the service threads (join), then frees the
store/DARE/arena **in order**, then exits cleanly — so no thread is mid-foreign-call when resources are
freed, and `kill -15` produces a clean exit with **no SIGBUS**, across SBCL and Clasp.

## 3. Approaches considered

- **A — Graceful signal handler → existing `service-stop` → clean quit (chosen).** Catch SIGTERM/SIGINT;
  on signal, run the orderly teardown (stop+join threads, then free store/DARE/arena), then `uiop:quit 0`.
  Minimal; reuses the existing correct teardown; fixes the actual cause (no graceful path is called).
- **B — Signal masking (a deepen-step, not a standalone fix).** Block SIGTERM/SIGINT on non-main threads
  so only the main Lisp thread handles them. Folded into "deepen if needed" (§4.4) if an OpenSSL-internal
  thread turns out to receive the signal.
- **C — Install a SIGBUS handler that swallows the fault.** Rejected — masks the symptom, hides a real
  teardown-ordering problem, and could hide a genuine memory fault elsewhere.

## 4. Design (Approach A)

### 4.1 PAL primitive `dds.pal:install-signal-handler`

A new PAL capability (the impl-specific signal API lives in `dds-pal/`, the only place reader conditionals
are allowed). Signature:

```
(install-signal-handler signals callback) -> t
```
where `signals` is a list of `(member :term :int)` and `callback` is a 0-arg function. It registers the
callback for those process signals. The callback is invoked in the signal-handler context, so it MUST do
the minimum: **set an atomic flag and wake the waiting main thread** (e.g. signal a condition variable) —
NOT the teardown itself. New symbol in `pal-contract.lisp`; SBCL impl via `sb-sys:enable-interrupt` on
`sb-unix:sigterm`/`sigint`; Clasp impl via its native signal-handler API (Clasp has full signal handling).

### 4.2 `durability-service-main` graceful teardown

`durability-service-main` currently starts the service and blocks for the lifetime. The change:
1. Create a shutdown latch (an atomic flag + a condition variable, or a PAL latch).
2. `install-signal-handler` for `:term`/`:int` → set the latch + wake.
3. Replace the lifetime block with a wait on **either** the lifetime expiry **or** the latch.
4. On wake (lifetime OR signal), run the **orderly teardown**: `service-stop` (stop+join the service
   threads) → `store-close` (fsync + free DARE secrets/arena) → `uiop:quit 0`.

The crux: **stop+join the threads BEFORE freeing the FFI/arena** so no thread is mid-foreign-call at
teardown.

### 4.3 Verify the teardown order in `service-stop`

`service-stop` (`src/dds-durability/service.lisp`) is reused as the orderly teardown. This WP MUST verify
that it (a) stops the collect/receiver/async threads and **joins** them (waits for them to exit their
foreign calls), and (b) only then closes the store. If it frees the store while a thread can still touch
it, that ordering bug is fixed here (it is the prerequisite for "no thread mid-foreign-call at free").

### 4.4 Deepen-if-needed (conditional, owner-approved)

After 4.1-4.3, re-run the interop `kill -15`. If the SIGBUS is gone → done. If it persists → it is an
OpenSSL-internal thread: add explicit OpenSSL teardown before exit (e.g. `OPENSSL_cleanup` via the DARE
FFI) and/or signal-masking (B: block SIGTERM/SIGINT on non-main threads). Document the outcome honestly.

## 5. Scope

- **In scope:** `durability-service-main` (the `:process`-mode entrypoint) + the PAL `install-signal-handler`
  primitive. This is where `kill -15` lands.
- **Out of scope:** the **embedded / in-thread** service (the host application owns its own signals — a
  library must not steal the host's SIGTERM/SIGINT). The supervisor/runner already stop child services
  via `service-stop`/process kill; they are not changed beyond what the entrypoint needs.

## 6. Testing — Definition of Done

1. **In-process unit (both impls):** (a) `install-signal-handler` registers a **non-quitting test callback**
   (sets a flag) and the test raises the signal to its own process (`kill(getpid(), SIGTERM)` via the PAL /
   `sb-unix:kill`); assert the flag is set and the process did NOT terminate (the handler caught it). (b) a
   focused test that the `durability-service-main` teardown path runs `service-stop` → `store-close` in order
   by driving the latch/teardown function directly (assert the threads are stopped + the store closed). The
   full handler→teardown→`uiop:quit` path would terminate the test process, so that end-to-end path is proven
   by the interop harness (§6.3), not a unit test.
2. **`service-stop` order (both impls):** a test asserting `service-stop` joins the threads before the store
   is closed (no thread observable after stop; store closed after).
3. **LIVE (the DoD): interop `kill -15` clean exit, no SIGBUS** — run a focused harness (or the existing
   `interop/durability-keeplast`/`-persistent` restart legs) that starts `durability-service-main`, sends
   `kill -15`, and asserts the process exits 0 (or the SIGTERM-clean code) with **no `SIGBUS`/`Bus error`**
   on stderr, on SBCL and Clasp.
4. **All quality gates green both impls (Clasp first):** `make test`, `gate-hotpath`, `gate-types`, `mem`
   (0.0000), `fuzz`, `wire`.

## 7. Decomposition (subagent-driven)

- **T1 — PAL `install-signal-handler`.** The contract symbol + the SBCL + Clasp impls + a unit test
  (raise the signal → the callback sets a flag), both impls.
- **T2 — `durability-service-main` graceful teardown.** The shutdown latch + handler wiring + the
  lifetime-or-signal wait + the orderly teardown; verify/fix `service-stop`'s stop+join-before-close
  order; in-process teardown-order test.
- **T3 — LIVE verify + capstone.** The interop `kill -15` clean-exit proof (SBCL + Clasp), deepen-if-needed
  (OpenSSL cleanup / masking) only if the SIGBUS persists, then ADR (resolve ADR 0026 §10 item 3) + docs
  lockstep + final whole-branch review → squash-merge presented for owner approval (HOLD PUSH).

## 8. Risks

- **Deepen branch (low-moderate):** the SIGBUS may be an OpenSSL-internal thread that graceful Lisp
  shutdown doesn't stop; §4.4 handles it (OpenSSL cleanup / masking) — conditional, bounded.
- **Signal-handler context limits:** the callback must do only flag-set + wake (no teardown in the handler);
  the design already enforces this.
- **Library-vs-application signal ownership:** scoping to the process entrypoint (not the embedded service)
  avoids stealing a host application's signals.

## 9. Non-negotiables (inherited)

- **No reader conditionals outside `dds-pal/`** — the signal primitive's impl-specific parts live in the PAL.
- `defun*`/`defstruct*` + full ftype on every new function.
- Clasp + SBCL both validate, Clasp first (Clasp has full signal handling — no NFR-PORT gap expected).
- Control-plane only (shutdown path); `gate-hotpath` + `make mem` 0.0000 unaffected.
- No AI / assistant attribution in any repo file.

## 10. References

- ADR 0026 §10 item 3 — the deferred "graceful FFI teardown on signal" follow-on (resolved here).
- ADR 0021 — `durability-service-main` (the `:process` entrypoint), the runner, the supervisor.
- `src/dds-durability/main.lisp` — `durability-service-main` (the block loop to make signal-aware).
- `src/dds-durability/service.lisp` — `service-stop` (the orderly teardown to reuse + verify).
- `src/dds-pal/pal-contract.lisp`, `pal-sbcl.lisp`, `pal-clasp.lisp` — where `install-signal-handler` lands.
- `interop/durability-persistent/`, `interop/durability-keeplast/` — the harnesses where the SIGBUS was
  observed (the `kill -15` clean-exit proof).
