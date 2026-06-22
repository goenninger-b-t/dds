# ADR 0030 — Graceful FFI teardown on SIGTERM/SIGINT (resolves ADR 0026 §10 item 3)

- **Status:** Accepted (M6/P5; WP-GRACEFUL-FFI-TEARDOWN, 2026-06-22)
- **Resolves:** ADR 0026 §10 item 3: "Graceful FFI teardown on signal — a benign SIGBUS in a
  non-Lisp thread was observed on `kill -15` during shutdown (cosmetic, post-run, in the FFI
  teardown of a process being killed); a clean signal-handled teardown is a follow-on."
- **Relates to:** ADR 0023 (durability service architecture — runner/supervisor/service lifecycle);
  ADR 0025 (DARE — the OpenSSL/static-arena FFI that was live at teardown time); ADR 0026
  (PERSISTENT store — group-commit fsync, store-close, DEK zeroize);
  `src/dds-pal/pal-{sbcl,clasp}.lisp` (`install-signal-handler`);
  `src/dds-durability/main.lisp` (`%graceful-shutdown`, `durability-service-main`).

## Context

After WP-DURABILITY-PERSISTENT landed (ADR 0026, 2026-06-20), killing the durability service
with `kill -15` occasionally produced a **benign SIGBUS in a non-Lisp thread** during OS
teardown of the process.  The SIGBUS was cosmetic — the program was already exiting — but its
presence was a code-quality and reliability concern: if the OS delivered SIGTERM to an OpenSSL
background thread (or to the collect thread's stack frame) while foreign memory was still being
accessed, the outcome is impl-defined.

**Root cause.**  When the OS sends SIGTERM to a process with no Lisp-level handler, the default
POSIX action is immediate process termination.  Any non-Lisp thread (an OpenSSL worker, a CFFI
callback, the kernel's UDP receive path) that is mid-foreign-call at the instant of delivery
may observe a partially-freed arena or a dangling SAP — producing an access-violation
(SIGBUS/SIGSEGV) as the OS maps out the process address space.  The SIGBUS was **not a bug in
the service logic**; it was the absence of an orderly drain before exit.

**Fix strategy (orderly drain).**  Install a Lisp-level SIGTERM/SIGINT handler that:
1. Sets a flag (`*durability-shutdown-requested*`).
2. The main blocking loop polls the flag and unblocks.
3. The teardown sequence executes **in the Lisp thread** (not the signal handler):
   `supervisor-stop` (no more restarts) → `runner-stop` (calls `service-stop` on each service,
   which in turn calls `store-close` — fsyncs + zeroizes + frees the DARE DEKs and static arena
   before `uiop:quit 0`).
4. At the point `uiop:quit 0` is called, **no foreign pointer is alive**: all collect threads
   have been joined (`runner-stop` blocks until each service's thread finishes), and all
   DARE/arena memory has been freed via `store-close`.

## Decision — as-built

### T1 — `dds.pal:install-signal-handler`

A new exported PAL function:

```
install-signal-handler (signals callback) → t
  signals  — list of (member :term :int)
  callback — 0-arg function; must be minimal (set a flag / wake a thread)
```

- **SBCL** (`pal-sbcl.lisp`): `sb-sys:enable-interrupt` for each signal
  (`sb-unix:sigterm` / `sb-unix:sigint`).  The handler lambda ignores the
  `(signo info context)` arguments and calls `callback`.
- **Clasp** (`pal-clasp.lisp`): `mp:service-interrupt :around` methods on
  `core:sigterm` / `core:sigint`.  An alist `*signal-handlers*` (guarded by
  `*signal-handler-lock*`) maps `:term`/`:int` → callback.  If a callback is
  registered the :around method calls it; otherwise `call-next-method`.
  `install-signal-handler` upserts into the alist under the lock.

No reader conditional escapes `dds-pal/` (the operating contract §4, enforced by the
reader-conditional CI lint gate).

### T2 — `durability-service-main` teardown wiring

`src/dds-durability/main.lisp` additions (`:block t` path only):

```lisp
(defvar *durability-shutdown-requested* nil)

(defun* %graceful-shutdown (runner sup) (function (t t) t)
  ;; supervisor-stop first (no restart of a stopped service),
  ;; then runner-stop (joins collect threads BEFORE store/DARE/arena freed).
  (ignore-errors (supervisor-stop sup))
  (ignore-errors (runner-stop runner))
  t)

;; Inside durability-service-main :block t:
(setf *durability-shutdown-requested* nil)
(dds.pal:install-signal-handler
 '(:term :int)
 (lambda () (setf *durability-shutdown-requested* t)))
(loop until *durability-shutdown-requested* do (sleep 0.2))
(%graceful-shutdown runner sup)
(uiop:quit 0)
```

The callback is minimal (sets one special variable); all teardown runs in the
blocking Lisp thread after the poll loop exits — never in the signal context.

### T3 — LIVE `kill -15` proof + harness

**Harness.** `interop/graceful-shutdown/driver.lisp` starts a PERSISTENT (DARE/file-backed)
durability service directly — `make-service-spec` with `make-persistent-store-factory` — so
OpenSSL is loaded, DEKs are derived, the static arena is allocated, and the collect thread is
live in a foreign `recvmmsg` when the kill arrives.  This is the exact FFI exposure scenario
the SIGBUS required.

`interop/graceful-shutdown/run-kill15.sh` (Clasp first, then SBCL):
- Launches the driver, captures stderr to `/tmp/gshut-<impl>.log`.
- Sleeps 12 s (settle / store-open / OpenSSL-load).
- `kill -15 <pid>`.
- Waits up to 30 s for clean exit.
- Asserts: no `sigbus`/`bus error`/`signal 10` in the log AND process exited.

**Result (2026-06-22, both impls):**

| impl | exit code | SIGBUS in log? | result |
|------|-----------|----------------|--------|
| Clasp | 0 | no | **PASS — clean exit** |
| SBCL  | 0 | no | **PASS — clean exit** |

Output (abbreviated):
```
GSHUT-DRIVER: service started dir=/tmp/gshut-D-<impl> ...
GSHUT-DRIVER: signal handler installed; waiting for SIGTERM/SIGINT
GSHUT-DRIVER: shutdown requested; tearing down
GSHUT-DRIVER: teardown complete; exiting
```

### Deepening needed? No

The graceful Lisp shutdown (T1 + T2) sufficed: **no OPENSSL_cleanup call, no signal masking**.
By the time `uiop:quit 0` is called, the collect thread has been joined, the store is closed,
all DEKs are freed, and there is no live foreign pointer.  OpenSSL's own teardown (invoked by
the OS after Lisp process exit) sees a clean state and produces no SIGBUS.

No dead code was added.  The ADR records the as-built result honestly.

## Consequences

- `kill -15` / `kill -2` of a running durability service now exits cleanly with status 0, no
  SIGBUS, on both SBCL and Clasp.
- The teardown order is fixed: supervisor-stop → runner-stop (join collect threads) →
  store-close (fsync + free DARE/arena) → uiop:quit 0.  Foreign memory is never accessed after
  `uiop:quit 0`.
- The `install-signal-handler` PAL primitive is now available to any durability service
  entrypoint (or any other process-mode Lisp program that needs POSIX signal handling without
  impl-specific reader conditionals in application code).
- `*durability-shutdown-requested*` is a special variable, not an atomic — safe because only
  the signal handler writes it and only the blocking loop reads it, with 0.2 s polling.

## NFR impact

- **NFR-PORT:** the SBCL / Clasp divergence is fully encapsulated in `dds-pal/`.
- **NFR-MEM:** no new allocation on the hot path.  Teardown is control-plane.
- **NFR-SEC-POSTURE:** the orderly join ensures no thread is mid-foreign-call at exit; DARE
  DEKs are zeroized+freed by `store-close` before exit (the same path as a planned shutdown).

## References

- ADR 0026 §10 item 3 — the original SIGBUS finding (this ADR resolves it)
- `src/dds-pal/pal-sbcl.lisp` — `install-signal-handler` (SBCL: `sb-sys:enable-interrupt`)
- `src/dds-pal/pal-clasp.lisp` — `install-signal-handler` (Clasp: `mp:service-interrupt :around`)
- `src/dds-durability/main.lisp` — `*durability-shutdown-requested*`, `%graceful-shutdown`,
  `durability-service-main` (`:block t` path)
- `interop/graceful-shutdown/driver.lisp` — the PERSISTENT service harness driver
- `interop/graceful-shutdown/run-kill15.sh` — the kill -15 proof script (Clasp first, then SBCL)
- `docs/wiki/durability.md` §5 — `durability-service-main` CLI reference (signal-driven
  shutdown + the `install-signal-handler` PAL primitive)
