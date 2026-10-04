# ADR 0121 — One way out: `exit-process`, a bounded shutdown-hook chain, then an exit that cannot hang

- **Status:** **Accepted** (2026-10-04, owner; recorded in ADR 0124). Implemented by WP-0.11 of
  `docs/plans/2026-10-03-sbcl-allegro-full-ok.md`.
- **Date:** 2026-10-04
- **Requirement:** NFR-PORT (SBCL and AllegroCL behave the same at exit), NFR-SEC-POSTURE (key material is
  wiped on every way out, not only the orderly one), FR-XPORT-2 (a SHMEM segment does not outlive its
  process), the ADR 0021 durability service (its store is flushed on every way out), NFR-TEST (a suite run
  that cannot end is not a gate), FR-LANG-6 (docstrings); the operating contract's no-conditions rule
  (ADR 0064)
- **Severity:** **hang at exit**, AllegroCL, in the test suite and in every production entry point
  (`durability-service-main`, `log-service-main`, the Shapes drivers); plus, on both implementations, an exit
  that skips cleanup whenever the orderly teardown does not run first
- **Relates to:** ADR 0030 (graceful FFI teardown on SIGTERM), ADR 0092 (bounded teardown joins), ADR 0116
  (the child-Lisp command line belongs to the PAL), ADR 0118 (Clasp withdrawn), ADR 0119 (SHMEM lane
  poisoning)

---

## 1. The defect

### 1.1 The hang

`uiop:quit` on AllegroCL calls `excl:exit` **without** `:no-unwind`. That exit unwinds every Lisp process
and waits for each to finish. A process parked in a foreign call never returns to Lisp, so it never
unwinds, and the exit waits forever. The governing plan measured the consequence on the full suite: the
summary printed, then the process sat with 10 live threads until an outer timeout killed it at 1654 s.

Reproduced on this host on 2026-10-04, AllegroCL 11.0 [64-bit Linux (x86-64) *SMP*], with one thread blocked
in `read(2)` on a pipe nobody writes:

| exit call | result |
|---|---|
| `(uiop:quit 7)` | still running when `timeout 40` killed it (rc 124, 40.0 s) |
| `(excl:exit 7 :no-unwind t :quiet t)` | rc 7 in 2.8 s |
| SBCL 2.2.9 `(uiop:quit 7)` | rc 7 in 1.4 s |
| SBCL 2.2.9 `(sb-ext:exit :code 7 :abort t)` | rc 7 in 1.3 s |

A thread sleeping in the foreign `sleep(3)` did **not** reproduce it (rc 7 in 3.1 s with `uiop:quit`):
`sleep(3)` returns early on the signal Allegro uses to interrupt it; `read(2)` on a pipe is restarted.
The suite's receivers park in `recvfrom(2)` and in `pthread_cond_wait` inside SHMEM segments, which behave
like the second case.

`uiop:quit` was called at 11 sites in `src/` (durability `main.lisp` ×6, `dds-log/service.lisp` ×2,
`dds-shapes/shapes.lisp` ×3) and in every Lisp form in the `Makefile`, including `make test`.

### 1.2 The cleanup a hard exit would lose

The obvious fix, a hard exit, skips work that the orderly teardown does and that nothing else does:

- **key material**: DARE DEKs, the ML-KEM private key, DDS-Security master keys live in foreign buffers
  that only `free-secret-octets` wipes;
- **durability stores**: the file backend's group-commit fsync runs on the collect tick and at
  `store-close`;
- **SHMEM segments**: POSIX shm objects persist in `/dev/shm` until they are unlinked or the host reboots.
  Before this change, ten `/dev/shm/dds*` objects from earlier killed runs sat on this host;
- **log sinks**: a file sink's stream is flushed per record but a borrowed stream is not closed.

`uiop:quit` did not do any of this either; it only happened to run when the code before it had already
torn everything down. Any other exit path (an error escaping to the toplevel of a `--non-interactive`
SBCL, a configuration failure after partial start) skipped it.

## 2. The decision

### 2.1 One door

`dds.pal:exit-process (&optional (code 0))` is the only way code in `src/` ends the process. It never
returns. On the first thread to call it:

1. start a **watchdog** thread (§2.4);
2. run the **shutdown-hook chain** (§2.3);
3. `finish-output` the standard streams (`*standard-output*`, `*error-output*`, `*trace-output*`,
   `*debug-io*`, `*query-io*`, `*terminal-io*`, each guarded);
4. **hard exit** with CODE (§2.2).

The protocol body is wrapped so that a non-local exit out of a hook still reaches steps 3 and 4 (the chain
is then truncated, which §2.3 counts as a failure).

A second call from **another** thread while the first is running parks that thread; the first one ends
the process. A recursive call from a hook (the **same** thread) hard-exits at once, which is how
`sb-ext:exit` treats a recursive call. It keeps its own code, except that a 0 becomes 70
(`+exit-shutdown-incomplete+`): the recursive call truncates the chain, the remaining hooks never run, and
an incomplete cleanup must never report success (§2.3).

### 2.2 The hard exit, per implementation (`%hard-exit`, in the PAL backends)

- **AllegroCL:** `(excl:exit code :no-unwind t :quiet t)`. The lambda list was read from the image on this
  host, not recalled: `(excl:arglist 'excl:exit)` → `(&optional code &key no-unwind quiet)`.
- **SBCL:** `(sb-ext:exit :code code :abort t)`, which calls `_exit(2)`: no unwind, no `*exit-hooks*`, no
  thread termination or join, no stream flush (the `sb-ext:exit` docstring of SBCL 2.2.9).

**Why `:abort t` and not the SBCL `:timeout` protocol.** A non-abort `sb-ext:exit` unwinds the calling
thread, runs `*exit-hooks*`, then `terminate-thread`s every other thread and joins them for at most
`:timeout` seconds (default `*exit-timeout*`, 60). Its docstring says the timeout "applies only to
JOIN-THREAD, not *EXIT-HOOKS*", and the unwind runs arbitrary `unwind-protect` cleanups, so two of its three
phases are unbounded, and a thread in a foreign call does not see `terminate-thread` until it returns, so
60 s is the best case for the third. `exit-process` already owns a bounded cleanup (the chain and its
watchdog); what it needs from the implementation is the one primitive that cannot wait. That is `_exit(2)`
on SBCL and `:no-unwind` on AllegroCL. Both are behind `%hard-exit`, the only implementation-specific piece,
so no reader conditional leaves `src/dds-pal/`.

### 2.3 The shutdown-hook chain

`register-shutdown-hook (name function) → name`, `unregister-shutdown-hook (name) → boolean`,
`shutdown-hook-names () → list`.

- **LIFO.** The newest hook runs first, like a stack of cleanups, so a subsystem loaded later (which may
  depend on an earlier one) is cleaned up before what it depends on. Re-registering a name replaces its
  function in place and keeps its position, so reloading a module neither duplicates nor reorders it.
- **Each hook is guarded.** A hook fails when it signals a `serious-condition` **or returns a non-NIL second
  value** (a status keyword, the repository's ADR 0064 convention, so a hook never has to signal to report a
  failure). A failure is printed on `*error-output*` with the hook's name and does not stop later hooks.
- **The contract for a hook:** it runs while other threads may still be running. It may wipe, flush, sync
  and unlink names; it must never free memory or close a resource another thread might be using.
- **The exit status.** A caller's code is passed through, except that a requested **0** becomes
  **70** when any hook failed or the watchdog fired. 70 is `EX_SOFTWARE`, "internal software error"
  (`/usr/include/sysexits.h:102`), exported as `dds.pal:+exit-shutdown-incomplete+`. An unsynced store or
  an unwiped key therefore cannot exit 0. A non-zero caller code is never replaced: it already reports a
  failure, and the more specific one.

### 2.4 Bounded time

`dds.pal:*shutdown-hook-timeout-seconds*` (default 10, read once per call) bounds the chain plus the stream
flush. The watchdog thread polls every 0.1 s (a shorter wait is unreliable on AllegroCL: waits of 0.075 s
or less return immediately, governing plan §1). When the deadline passes before the exiting thread reaches
its own hard exit, the watchdog writes one line to fd 2 with `write(2)` and hard-exits with the code (70 if
the code was 0). It bypasses every Lisp stream on purpose: it fires exactly when the exiting thread may be
wedged while holding one. `STDERR_FILENO` is 2 (`/usr/include/unistd.h:212`). If the watchdog thread cannot
be created, that is reported on fd 2 and the chain is unbounded; the Makefile's outer `timeout` (§4) still
bounds the process.

10 s is far above the measured cost of the four built-in hooks with nothing to clean up (well under a
millisecond each) and below the 60 s grace the Makefile's `--kill-after=60` gives after its own TERM.

### 2.5 The four built-in hooks

Each subsystem keeps a registry of the resources it owns, from creation to release, and registers one hook
at load time. In load order, reversed, which is the run order:

| hook | registry: added by / removed by | at exit | never |
|---|---|---|---|
| `:log-sink-flush` (dds-log) | `make-stream-sink` / `make-file-sink` → `close-sink` | `finish-output` each open stream | close it |
| `:durability-store-sync` (dds-durability) | `store-open` (clean open only) → `store-close` (before closing) | `store-sync` each store; any failure → `:fsync-failed` | close it |
| `:dare-secret-wipe` (dds-dare) | `%make-secret-octets` → `free-secret-octets` | zero each buffer, call `*secret-wipe-readback-hook*` on it | release it |
| `:pal-shm-unlink` (dds-pal) | `shm-create` (success only) → `shm-destroy` | `shm_unlink` each name | unmap it |

The "never" column is the §2.3 contract applied. A receiver thread may be in the middle of an AES-GCM call
with a key: wiping it makes that call fail closed (wrong key, tag mismatch); releasing it would be a
use-after-free. A collect loop may be in the middle of a put: the file backend's sync takes the store lock,
so a sync cannot interleave with it; a close could. Unlinking a shm name leaves every mapping valid, and the
kernel frees the object with its last mapping, which for this process is the exit itself.

All four registries are control plane: segments, secrets, stores and sinks are created at participant,
key, service and collector setup and released at teardown. None is touched per sample, and none of the
changed files is a `gate-hotpath` file, so there is no before/after bench (FR-LANG-7 applies to hot-path
changes).

**Not covered (recorded):**
- DDS-Security KxKey/KxSalt buffers (`dds.security:derive-kx-key`) are allocated with `dds.pal:alloc-static`
  directly, not through `dds-dare`, so they are not in the secret registry. `free-kx-key` stays their only
  wipe. Moving them onto `octets->secret` / `free-secret-octets` is a one-line change each, in a package
  this WP does not own.
- System V segments created for RTI Connext shared-memory interop (`sysv-shm-create`) are not tracked.
- Events still queued in an async logger's ring have not reached a sink; only `close-logger` drains them
  (it needs a DDS write).
- A SIGTERM that arrives **before** a service installs its handler gets the implementation's default
  action, not this protocol. `durability-service-main` now prints `DURABILITY-SERVICE-READY services=N` once
  its handler is installed, so a supervisor can wait for it (§6).

## 3. Routing every exit through it, and a lint

- All 11 `uiop:quit` calls in `src/` call `dds.pal:exit-process` with the same code; their docstrings say
  so.
- Every Lisp form in the `Makefile` ends with `(dds.pal:exit-process CODE)`, including the test entry
  (`make test`). `asdf:test-system`'s `test-op` itself still only runs `run-all-tests`: exiting is the
  caller's decision, and an interactive `(asdf:test-system :dds-tests)` must return.
- **`make gate-quit-lint`** (`scripts/gate-quit-lint.sh`) fails on `uiop:quit`, `uiop/image:quit`,
  `sb-ext:exit`, `sb-ext:quit`, `excl:exit`, `excl::exit` or `cl-user::quit` anywhere under `src/` outside
  `src/dds-pal/`, and in the `*.asd` files, case-insensitively, in code, strings **and** comments (a
  child-process form is a string, and prose naming the call invites it back). It also fails on the two
  indirect forms: a run-time lookup through `uiop:symbol-call` of `quit`/`exit`, and a CFFI
  `foreign-funcall` of `"exit"` or `"_exit"`. It falsifies itself on every run: a scratch tree with twelve
  banned lines (the eight direct spellings, two `symbol-call` forms, two `foreign-funcall` forms), four
  near-miss lines that must not count (`dds.pal:exit-process`, `sb-ext:*exit-hooks*`,
  `(uiop:symbol-call :dds.pal :exit-process 0)`, `foreign-funcall "atexit"`, …) and a `dds-pal/` file that
  must be exempt.
- **Not linted:** `scripts/*.sh` still pass `(uiop:quit …)` to the Lisps they start (gate-arena, gate-mem,
  gate-build, gate-interop, linux-repro). They run SBCL in practice and are bounded by the Makefile
  `timeout` (§4); moving them is follow-up work, not part of this ADR's lint.

## 4. Bounding the Makefile

Every Lisp invocation in the `Makefile`, and every script target that starts one (gate-build, gate-mem,
gate-arena, wire, interop, shmem-xproc, zc-xproc, test-linux, linux-run), runs under
`timeout --kill-after=60 N`: TERM to the run's process group at N seconds, KILL 60 s later. Defaults
`BUILD_TIMEOUT`, `TEST_TIMEOUT` and `GATE_TIMEOUT` 3600 s, `BENCH_TIMEOUT` 7200 s, each overridable per run.
The interactive participants (`square-pub`, `square-sub`, … which run until Ctrl-C) run under
`timeout --kill-after=60 --foreground $(RUN_TIMEOUT)` (default 24 h) so Ctrl-C still reaches them;
`--foreground` gives up timing out their children, which they do not have. A timeout exits 124 (137 after
the KILL), never 0, so a wedged gate is a red gate.

## 5. A leaked thread fails the suite

`exit-process` no longer waits for any thread, so the exit can no longer notice a test that left a thread
running. `run-all-tests` takes over that job: it snapshots `dds.pal:live-threads` before the first test, and
after the last one lists every thread it did not start with that is still alive after a 5 s grace period.
A thread whose name starts with `dds` (every thread this stack starts, through `dds.pal:spawn`'s default or
a `dds-*` name) **fails the run** as a `thread-leak-check` entry; any other thread (an implementation's own
finalizer, say) is listed and does not.

## 6. Two changes the test needed

- **`dds.pal:lisp-eval-command` on SBCL** now finds its own binary. `uiop:argv0` is NIL in an SBCL that was
  not dumped as an executable unless a wrapper exports `__CL_ARGV0`, and it was NIL under
  `scripts/with-sbcl.sh`, so the function answered NIL and every caller bailed. The fallback is
  `sb-ext:*runtime-pathname*` with `--core sb-ext:*core-pathname*` (measured `/usr/bin/sbcl` and
  `/usr/bin/../lib/sbcl/sbcl.core`), so the child is the same SBCL as its parent by construction. Like the
  AllegroCL arm, it also loads Quicklisp itself when the child has none (guarded, so a `~/.sbclrc` that loads
  it is not doubled). **Consequence:** the durability runner's `:process` mode now actually launches a child
  under `with-sbcl.sh` where it used to shed the spec with `:no-argv0`. No test starts a `:process` spec
  through `runner-start`, so no test result changes.
- **`durability-service-main`** prints `DURABILITY-SERVICE-READY services=N — …` on standard output once its
  SIGTERM/SIGINT handler is installed: an operator line and the readiness marker a supervisor (and the test)
  waits for before it may signal.

## 7. Verification

`run-exit-hook-chain-test` (in process):
- the chain on four synthetic hooks, one of which signals and one of which returns a status: all four run
  in order, exactly the two failures are reported by name and cause;
- registration is LIFO, re-registration replaces in place, unregister reports T then NIL;
- the four built-in hooks are registered and `:pal-shm-unlink` runs last;
- each registry tracks its resource from creation to release (a real shm object, a real secret buffer, a
  memory store, a stream sink).
It never runs a built-in hook in the suite's own image (that would wipe, sync and unlink the image's live
state).

`run-exit-process-subprocess-test` starts three children of the running Lisp, one at a time, through
`dds.pal:lisp-eval-command`, each loading `src/dds-tests/exit-child.lisp` (not an ASDF component):

| child | set-up | expected |
|---|---|---|
| DIRECT | secret and shm object planted and never released; a thread parked in `read(2)`; `(exit-process 3)` | rc 3 within 30 s; read-back `len=32 zero=T`; the object is gone |
| WEDGED | a hook that never returns, registered last; chain bounded at 2 s; `(exit-process 0)` | rc 70 within 30 s; "overran" on stderr |
| DURABILITY | secret and shm object planted; the real `durability-service-main`; SIGTERM after `DURABILITY-SERVICE-READY` | rc 0 within 60 s; read-back all-zero; the planted object and the participant's own segment are gone |

Results on this host, 2026-10-04:
- both tests in isolation: **pass on SBCL 2.2.9** and **pass on AllegroCL 11.0**;
- **SBCL full suite** (`timeout 900 make test LISP=./scripts/with-sbcl.sh`), twice: **650/650**, rc 0, 242 s
  and 224 s wall, `skipped: 0`, `threads: 0 leaked`, and `/dev/shm` identical before and after each run;
- **AllegroCL full suite** (`timeout 2400 make test LISP=./scripts/with-allegro.sh`): the process **exits by
  itself**, rc 1 from the Lisp (`make` rc 2), in **188 s** wall (the baseline run hung after its summary and
  was killed at 1654 s). **631/650**: the two new tests pass; the 19 failures are the 18 baseline failures
  still failing (`shmem-ring-drain-fuzz` from the plan's list of 19 now passes, after WP-0.7) plus
  `dcps-read-status-reset` (`RESET-BIT-BEFORE`), a pre-existing AllegroCL timing flake: its match wait is
  150 × `(sleep 0.02)`, and waits that short return immediately on AllegroCL. Measured in isolation, 270
  runs each, alternating order: **24/270 (8.9 %) failures at HEAD e6956e7** (an untouched worktree) against
  **27/270 (10.0 %)** with this change; the per-round rate (0–20 %) varies with run order, not with the tree.
  It passed in the first full AllegroCL run of this change. The run also fails `thread-leak-check` (§5):
  8 `dds-*` threads, attributed by the new first-seen report to two tests that already fail at baseline,
  `durability-supervisor` / `durability-runner-lifecycle` (`dds-durability-collect(SupSquare)`,
  `dds-durability-supervisor`, a participant's `dds-udp-rx` and `dds-shmem-rx`) and
  `dcps-autonomous-lease-expiry` (`dds-autodiscovery`, its participants' receivers). They make no difference
  to the AllegroCL exit status, which is already non-zero, and they are listed rather than hidden.
  `/dev/shm` was identical before and after the run.

A first full AllegroCL run started the three children concurrently; one failed its load with
`realpath failed: No such file or directory`: each AllegroCL child recompiles part of the tree on load, and
the three raced on the same fasl names. Why a child recompiles fasls its parent has just built is not
established here; its log shows ASDF's "Computing just-done stamp … wasn't done yet" warning and a
bordeaux-threads `impl-allegro` "compilation failed" warning before the recompiles. The children now run
one at a time.

During development the AllegroCL DIRECT child first "failed" to unlink its segment although it had: the
test's existence probe (`shm-attach`) expected `:shm-open-failed`, and on AllegroCL a failed `shm_open`'s -1
comes back from CFFI as 4294967295 (the `:int` sign-extension defect of governing plan §1, owned by another
WP), so the attach failed one step later with `:mmap-failed`. The probe now treats any attach failure as
"gone", which is sound because every object the test plants exists at 4096 octets, mode 0600, owned by the
test's uid, and so always attaches while it exists.

## 8. Consequences

- `dds.pal` exports six symbols: `exit-process`, `register-shutdown-hook`, `unregister-shutdown-hook`,
  `shutdown-hook-names`, `*shutdown-hook-timeout-seconds*`, `+exit-shutdown-incomplete+`. Nothing else in
  the frozen PAL contract changes.
- `shm-create`, `shm-destroy`, `%make-secret-octets`, `free-secret-octets`, `store-open`, `store-close`,
  `make-stream-sink` and `make-file-sink` keep their signatures and results; each now also updates its
  registry under a lock.
- An exit that used to report 0 after a failed cleanup now reports 70.
- The test count rises by two (`pal-exit-hook-chain`, `pal-exit-process-subprocess`), and a run with a
  leaked `dds-*` thread now fails even when every test passed.
