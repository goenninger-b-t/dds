# Getting started

## Prerequisites

- **SBCL** and **AllegroCL 11.0** (`alisp`), 64-bit Linux x86_64, with **Quicklisp** installed. Those
  are the two targets; Clasp was withdrawn on 2026-10-03 (ADR 0118; the last Clasp-bearing tree is the git
  tag `clasp-last`). `alisp` is the only AllegroCL image in scope: `mlisp`, `alisp8`/`mlisp8` and macOS
  arm64 are not targets (owner decision D1, 2026-10-04, ADR 0124).
- The `Makefile` drives per-implementation builds via `scripts/with-sbcl.sh` (`SBCL_BIN` overrides the
  binary) and `scripts/with-allegro.sh` (`ALISP_BIN` / `ALLEGRO_BIN`); both load Quicklisp and point ASDF at
  the repo, and both exit 127 when their binary is absent.

## Build & test

```sh
make build         # load all systems (default LISP = SBCL; override LISP=./scripts/with-allegro.sh)
make test          # run the suite once; exits with the ADR 0120 baseline verdict (ADR 0128, see below)
make build-allegro # build on AllegroCL (ALISP_BIN / ALLEGRO_BIN override the binary)
make test-allegro  # test on AllegroCL
make build-all     # build on both targets (SBCL + AllegroCL); each launcher exits 127 when absent
make test-all      # test on both — where an impl is absent, use the per-impl targets above
make gate-build    # THE build gate: clean-cache rebuild + a falsification self-test (see below)
make gate-types    # every defun has a single-line ftype declaim (FR-LANG-8)
make gate-pal      # no reader conditionals outside dds-pal/ (contract §10, NFR-PORT); no Clasp token anywhere (ADR 0118)
make gate-quit-lint # src/ exits only via dds.pal:exit-process — no uiop:quit / sb-ext:exit / excl:exit (ADR 0121)
make gate-skip-lint # a test skip goes through dds.tests:note-skip with a known capability — no bare SKIP print (ADR 0122)
make gate-hotpath  # no CLOS dispatch (NFR-CLOS) + no UNJUSTIFIED allocation (NFR-MEM) in hot-path files
make mem           # CODEC-only: 0 bytes/sample serialize + deserialize (NFR-PERF-8) — see the caveat below
make gate-mem      # NFR-MEM RATCHET: END-TO-END bytes/sample, must not regress (ADR 0062). SBCL only:
                   # a canary first proves bytes-consed moves, so it FAILS on AllegroCL (ADR 0118).
make gate-arena    # FR-PF-7: the process static-memory budget is real, charged and RETURNED (ADR 0095). SBCL only.
make wire          # validate emitted RTPS against the tshark RTPS dissector (FR-TOOL-3)
make interop       # LIVE cross-vendor interop: Connext 7.3.1 + Fast DDS (FR-IO)
```

**Every Lisp run the Makefile starts is bounded** (ADR 0121): it runs under `timeout --kill-after=60 N`,
which sends TERM to the run's whole process group at N seconds and KILL 60 s later, and exits 124 (137 after
the KILL), never 0. Defaults: `BUILD_TIMEOUT`, `TEST_TIMEOUT` and `GATE_TIMEOUT` 3600 s, `BENCH_TIMEOUT`
7200 s; the interactive participants (`square-pub` & co.) run under `--foreground` with `RUN_TIMEOUT=24h` so
Ctrl-C still reaches them. Override per run, e.g. `make test LISP=./scripts/with-allegro.sh TEST_TIMEOUT=5400`.
Every Lisp form in the Makefile ends the process with `(dds.pal:exit-process CODE)`, which cannot hang on a
thread parked in a foreign call (the AllegroCL suite used to, after printing its summary). `make test` also
**fails on a leaked `dds-*` thread**: `run-all-tests` lists every thread it started that is still alive after
the last test and a 5 s grace period.

### Skips are counted, not printed (ADR 0122)

A test that cannot run because the host lacks something does not just print `SKIP`: it calls
`dds.tests:note-skip`, naming **what** did not run (the site), **which capability** was missing, and **why**.
Until WP-0.10 about 100 tests printed a bare `SKIP` line, returned, and were reported `ok`, while the summary
said `skipped: 0 — every test ran`.

- **The capability vocabulary is closed** (`dds.tests:*skip-capabilities*`): `:openssl-pqc` (OpenSSL < 3.5
  or no ML-KEM-1024), `:libcrypto` (none loaded), `:alloc-counter` (`dds.pal:bytes-consed` does not move),
  `:zc-sap-primitives`, `:shm-attach-by-name`, `:subprocess-mode`, `:rx-store-pool`, `:static-vector-p`,
  `:carve-refusal` and `:verified-elsewhere` (a gate defers an artefact to another gate, e.g. `make corpus`'s
  LogEvent vector, which `make test` verifies). Any other keyword signals an error, which fails the test.
- **`:scope`** is `:test` (the default: the test returned without running) or `:arm` (one assertion block
  was skipped and the rest ran).
- **No dedup.** Every call is one event, charged to the test that was running (`dds.tests:*current-test*`).
- A test body in a production file reports through `dds.pal:note-test-skip`, which forwards to the harness.
  That covers every suite entry that lives outside `src/dds-tests/` (the `run-…-test` bodies and the
  `dds.bench` perftest smokes alike); `make gate-skip-lint` finds them from the `run-all-tests` registry.

```lisp
(multiple-value-bind (ok reason) (dds.dare:dare-available-p)
  (unless ok
    (note-dare-skip "my-secure-test" reason)        ; capability :openssl-pqc or :libcrypto, from DARE itself
    (return-from run-my-secure-test t)))
(if (eq (dds.pal:pal-impl-name) :sbcl)
    (%check :zero-alloc (< per 1.0) "…")
    (note-skip "my-test/zero-alloc" :alloc-counter "bytes-consed does not move here" :scope :arm))
```

`make test` (and `make fuzz`, `make mem`, `make corpus`) print a **preflight** before the first test (the OpenSSL version and
the libcrypto file the loader actually mapped, whether `bytes-consed` moves, whether a shm segment attaches by
name) and, after the last, the **accounting**. On this host with SBCL 2.2.9 and OpenSSL 3.0.13:

```
preflight (ADR 0122): SBCL 2.2.9.debian on SBCL
  openssl:            UNAVAILABLE (openssl-pqc): OpenSSL version 0x300000D0 < 3.5.0 (0x30500000); version OpenSSL 3.0.13 30 Jan 2024 (0x300000D0)
  libcrypto mapped:   /usr/lib/x86_64-linux-gnu/libcrypto.so.3
  alloc-counter:      moves (bytes-consed delta 65024 across a 4096-cons list)
  shm-attach-by-name: live probe works (ATTACHED); PAL declares reliable-p = T
…
tests: 650 passed, 0 FAILED, 650 total.
coverage: 547 FULL, 3 PARTIAL, 100 SKIPPED, 0 FAILED of 650 test(s); 106 skip event(s).
```

FULL = ran with no skip; PARTIAL = passed but skipped at least one arm; SKIPPED = returned without running;
FAILED = failed (whatever it skipped). The Lisp run itself only reports; **`make test` enforces** (step 2,
[ADR 0128](../adr/0128-make-test-enforces-the-baselines.md)): a skip event of **any** capability that the ADR
0120 skip baseline below does not list, or more events than it allows, fails `make test`. `make fuzz`,
`make mem` and `make corpus` are judged too (`scripts/test-baseline.py entry`, ADR 0128 §3): they fail when the
Lisp exits non-zero or when the run records a skip of a capability the Lisp's skip baseline excuses for no
test. On SBCL, whose skip baseline is empty, that means any skip, except the corpus's own
`:verified-elsewhere` deferral (`*corpus-verified-elsewhere*`, `make corpus` only). On AllegroCL a skip of
an already-excused capability (e.g. the `zc-sap-primitives` arm in `make fuzz`, owner WP-1.15) is printed as
KNOWN; no per-entry-point baseline exists or is added.

**`DDS_TEST_ALLOW_SKIP=<cap>[,<cap>…]`** is the only skip switch. It lets skip events of the named
capabilities (closed vocabulary, case-insensitive, colon optional; an unknown name is an error) past the skip
baseline, never a failure, and the verdict is then **exit 3, `NOT A GATE RUN`**, not 0 — even if nothing
extra skipped. It exists for the governing plan's Phase 1A exit check
(`DDS_TEST_ALLOW_SKIP=alloc-counter,zc-sap-primitives,subprocess-mode make test LISP=./scripts/with-allegro.sh`);
a run made with it is not evidence for anything else.

### The transitional ratchet: known failures and skips, listed and owned (ADR 0120)

Until the Phase 1 exit of the governing plan, AllegroCL still has known failures (short waits return
immediately there, WP-1.1) and known skips (no allocation counter, WP-1.13; Zero-Copy SAP primitives gated
off, WP-1.15; …). Instead of ignoring them, each one is a line in a committed file with the work package
that owns it:

| File | Line format |
|---|---|
| `test/baseline-<lisp>.txt` | `<test-name> <owning-WP> [note]`, and `thread-leak-check <owning-WP> <max-threads> [note]` for the leaked-thread bound |
| `test/skip-baseline-<lisp>.txt` | `<capability> <test-name> <max-events> <owning-WP> [note]` |

The rule for every commit: **a run may not fail a test, or skip, beyond what these files list**, and the
files **only shrink**. The SBCL files are empty (measured with the pinned OpenSSL), so on SBCL the rule is
already zero/zero.

```sh
. scripts/openssl-env.sh
make test LISP=./scripts/with-allegro.sh           # runs the suite, then judges its log (ADR 0128)
make baseline-check BASELINE_LISP=allegro LOG=/path/to/make-test.log   # judge a log you already have
make gate-verification                             # includes: no baseline grew against ANY committed version
```

`make test` writes the log to a fresh file `$(TEST_LOG_DIR)/neodds-test-<lisp>.XXXXXX.log` (mktemp; default
`$TMPDIR` or `/tmp`; the path is printed first) and hands it to `scripts/test-baseline.py gate`, whose verdict
is its exit status (`scripts/judged-run.sh`). If the log cannot be created or `tee` cannot write all of it
(read-only directory, full disk), the run is not judged and `make test` fails: a verdict is never about a log
an earlier run left behind.

| exit | meaning |
|---|---|
| 0 | nothing outside the baselines. Each baselined failure that fired is printed as `KNOWN failure (ADR 0120 baseline, owner WP-…)`, each baselined skip as `KNOWN skip`; the last line says "no new failure under the ADR 0120 baseline", not "all tests pass" |
| 1 | a new failure, a new or extra skip event, more leaked threads than the bound, a log of the other Lisp (the preflight line's `on SBCL` / `on ALLEGRO` must match `LISP`), or a run that cannot be judged: the Lisp timed out (124/137) or crashed, or exited 0 with failures in its log, or 1 with none |
| 3 | as 0, but `DDS_TEST_ALLOW_SKIP` was set: **NOT A GATE RUN** |

GNU make reports a failing recipe as its own exit 2; the recipe's code is in make's `Error N` line. On
AllegroCL today `make test` exits 0 while printing its 19 KNOWN failure entries and 51 KNOWN skip events by
name and owner. `make test-ratchet` is an alias of `make test`.

The verdict also prints the entries that did **not** fire in this run; when you fix one, delete its line in
the same commit. Adding a line is never the fix: `gate-verification` compares the file with every version
ever committed (not only `HEAD`), so re-adding a removed entry, raising a skip count or the leaked-thread
bound, or re-creating a deleted baseline all fail. The pre-commit hook (`make hooks`) runs the same check on
the staged copy (`test-baseline.py shrink-only --staged`), so such a commit is refused before it exists. The
log check fails closed: a log whose failures it cannot name and count against the run's own totals (no
`FAILURES` block, no `RUN-ALL-TESTS` line, counts that disagree) is rejected, never read as "no new
failure". The checker proves all of this on a scratch repository and synthetic logs before every verdict
(`python3 scripts/test-baseline.py self-test`). The ratchet is test-granular: a baselined test that fails on
a different assertion is not seen (ADR 0120 §2.2 lists the known limits). A run the baseline accepts means "no new failure", not
"green", and no milestone exit is declared while a baseline has entries (ADR 0127 §2). At the Phase 1 exit the
files are deleted and the rule becomes zero/zero on both Lisps.

### OpenSSL 3.5 for the DARE and DDS-Security tests (ADR 0123)

The CNSA-2.0 DARE and DDS-Security code needs **OpenSSL ≥ 3.5** (ML-KEM-1024). Linux distributions of this
vintage ship 3.0, so build the pinned LTS release once, into your home directory, and point the suite at it:

```sh
scripts/build-openssl.sh            # OpenSSL 3.5.9 -> ${DDS_OPENSSL_PREFIX:-$HOME/.local/opt/openssl-3.5}
. scripts/openssl-env.sh            # exports DDS_DARE_LIBCRYPTO=<prefix>/lib64/libcrypto.so.3, nothing else
make test LISP=./scripts/with-sbcl.sh
```

`build-openssl.sh` is pinned to one version and one SHA-256, checks the release's OpenPGP signature against
the OpenSSL release certificate fingerprint when `gpg` is available (`DDS_OPENSSL_REQUIRE_PGP=1` makes that
mandatory), refuses any mismatch, and is a no-op when the same pin is already installed. It never deletes a
directory it did not create: an existing, non-empty `DDS_OPENSSL_PREFIX` without the script's
`.neodds-openssl-stamp` or `.neodds-openssl-provenance` file stops the run before anything is downloaded. It
installs into a staging directory beside the prefix, swaps it in, and checks the result there: it compiles
`scripts/probes/ossl-param-layout.c` against the new headers and refuses an `OSSL_PARAM` layout that
differs from what `src/dds-dare/openssl-ffi.lisp` writes; on any failed check the previous install is put back. `openssl-env.sh` does **not** set
`LD_LIBRARY_PATH`: only NeoDDS loads the 3.5 copy, by absolute path; everything else keeps the system library.

**The loader is fail-closed.** With `DDS_DARE_LIBCRYPTO` set, that file is the only candidate. It is opened
with `dds.pal:dl-open`, every OpenSSL symbol is resolved in that file with `dds.pal:dl-sym` (CFFI's
`:library` argument is ignored on both SBCL and AllegroCL), `dladdr` must place `OpenSSL_version_num` inside
it, and `/proc/self/maps` must show exactly one libcrypto. Anything else is a rejection, reported by
`dds.dare:libcrypto-status`, and never a fallback to another copy:

```lisp
(dds.dare:libcrypto-status)
;; pinned and verified:
;; => :OK "/home/u/.local/opt/openssl-3.5/lib64/libcrypto.so.3" NIL T
;; DDS_DARE_LIBCRYPTO=/nonexistent/libcrypto.so.3:
;; => :PINNED-UNLOADABLE NIL "DDS_DARE_LIBCRYPTO=/nonexistent/libcrypto.so.3 does not exist" T
;; pinned, plus LD_PRELOAD=libcrypto.so.3 (the system copy):
;; => :MULTIPLE-LIBCRYPTO "/home/u/.local/opt/openssl-3.5/lib64/libcrypto.so.3" "2 libcrypto mappings: …" T
```

A rejected library is never called. `dare-available-p` answers NIL with capability `:libcrypto`, and code
that calls an OpenSSL primitive anyway gets an error naming the function and the status (for example
`libcrypto function EVP_Q_digest is unavailable: libcrypto pinned-unloadable …`), not a jump through a NULL
pointer; the durability service with a DARE-wrapped backend then fails its start and exits 1.

A rejection, or a second libcrypto mapped by the time the suite starts, **stops `make test`, `make fuzz`,
`make mem` and `make corpus` before the first test** with `LIBCRYPTO PREFLIGHT FAILED`, whatever the skip
mode, because a run against the wrong library is not a run of the right one. The preflight prints which
file was used and how many were mapped:

```
  libcrypto loaded:   ok /home/u/.local/opt/openssl-3.5/lib64/libcrypto.so.3 (pinned by DDS_DARE_LIBCRYPTO)
  libcrypto mappings: 1: /home/u/.local/opt/openssl-3.5/lib64/libcrypto.so.3
```

Without `DDS_DARE_LIBCRYPTO` the loader searches (Homebrew paths, then `libcrypto.so.3`), verifies what it
finds the same way, and on a 3.0 system the DARE and security tests record `:openssl-pqc` skips as before;
since ADR 0128 those skips are not in any baseline, so **`make test` fails without the pinned library**.
Source `scripts/openssl-env.sh` for every run that is meant to count. Hosted CI builds and caches the same
pin and runs the SBCL suite against it (`NEODDS_CI_OPENSSL35: 'on'` in `.github/workflows/gates.yml`).

Measured on the reference host (Linux x86_64, 2026-10-04) with the pin: SBCL 2.2.9
`tests: 652 passed, 0 FAILED` and `coverage: 652 FULL, 0 PARTIAL, 0 SKIPPED, 0 FAILED; 0 skip event(s)`;
AllegroCL 11.0 ran every DARE and security test with no `:openssl-pqc` skip and none of them failed.

### `make mem` vs `make gate-mem` — read this before trusting either

`make mem` measures the **codec in isolation** (serialize / deserialize / AEAD) and reports ~0 bytes per
iteration. That is a real assertion and it would fail if the codec regressed — but it measures **no
workload**, so it is *not* the per-sample budget it is often credited with. It stayed green while the live
DCPS path allocated ~3.9 KB per sample.

`make gate-mem` measures the **end-to-end DCPS path** — `write-sample` → engine → transport → receiver
thread → `take-samples` — which is the number NFR-MEM constrains and the one that drives the peer's GC
pause (the ~10 ms latency tail is a GC *in the peer*, fed by exactly this garbage; ADR 0062).

NFR-MEM's target is **zero**, and we are not there. A gate that failed at "anything above zero" would be
permanently red and therefore ignored, so `gate-mem` is a **ratchet** against `bench/mem-ceiling.txt`:

- measured **above** the ceiling → **FAIL** (allocation regressed);
- measured **well below** it → **FAIL**, telling you to *lower the ceiling and commit it*;
- otherwise → pass, while printing how far above zero we still are.

Failing on an *improvement* is deliberate: a ceiling that is never lowered drifts away from reality and
quietly stops constraining anything — the same slow death as a gate that cannot fail. The ratchet only
moves down, and the ceiling file is the record of how far NFR-MEM has actually got.

**Two arms since ADR 0093**, because there are now two honest workloads — each with its own ceiling on the
arch's row, and each measured in its **own process on its own domain**:

```
gate-mem: COPY   allocation = 560.2 bytes/sample (ceiling 590, NFR-MEM target 0)
gate-mem: RETURN allocation = 349.5 bytes/sample (ceiling 385, NFR-MEM target 0)
gate-mem: PASS — no regression. Returning the loan saves 210.7 B/sample; still 350 above the target of ZERO.
```

- **COPY** — the application takes samples and drops them. The legacy arm, unchanged, so every historical
  ceiling row stays comparable.
- **RETURN** — the application `return-loan`s each taken sample, honouring the [ADR 0093](../adr/0093-the-copy-path-becomes-a-loan.md)
  loan contract so the reader can recycle its delivery wrappers. **This is the only arm in which the
  recycling is visible at all**; measuring only COPY would leave that win unratcheted and free to regress
  silently.

An arch whose RETURN ceiling is `-` in `bench/mem-ceiling.txt` (not yet measured there) is still measured
and **reported, with the row to paste in** — it is simply not gated, so an unmeasured arch prints the
number it needs instead of going red. ⚠️ **Never fill a `-` from the other arch's number:** the two diverge
materially and unpredictably, and a predicted value has already been 58 B wrong once.

⚠️ **Each arm runs in its own process on its own domain, and that is load-bearing.** Two arms sharing an
image and a domain *discover each other*, so the second pays for the first's participants and reads high —
measured during ADR 0093 as a 1000 B phantom "regression" that was diagnosed as a code defect before the
harness was suspected. It is the same rule as the standing order that concurrently running tests must use
different DDS domain IDs.

### CI runs the gates now — and it did not before

Until `.github/workflows/gates.yml`, the **only** workflow in this repo was `publish-wiki.yml`. **No build,
no tests, no gates ran automatically on any push.** Every check happened only when a human remembered to run
it locally — which is how `main` went two days without compiling from a clean cache while `make test`
reported 563/563.

The operating contract asserted CI enforcement that did not exist ("the **CI** hotpath-purity-gate enforces
this"; "no reader conditionals outside `dds-pal/` — **CI lint** enforces this"). Both claims were false; the
lint had never been written. `gates.yml` and `make gate-pal` make them true.

**What CI runs for the suite:** `make test LISP=./scripts/with-sbcl.sh` against the pinned OpenSSL 3.5.9
(built from the verified tarball and cached on its version and hash), judged against the empty SBCL baselines
(ADR 0128): any failure, skip event or leaked `dds-*` thread turns the job red. `make corpus` and `make fuzz`
are judged the same way (any skip but the corpus's declared `:verified-elsewhere` turns them red). When the
job fails, the judged-run logs (`neodds-*.log`) are kept as the artifact `neodds-test-sbcl-log`.

**What CI does NOT cover — stated loudly, never silently skipped:**

- **AllegroCL.** It is commercially licensed and not on the hosted runner. The rule is that **SBCL AND
  AllegroCL must both validate** (ADR 0118), so this stays a **human step**:
  `make test-allegro && make gate-build LISP=./scripts/with-allegro.sh`.
- **Interop.** Needs licensed RTI Connext + a Fast DDS build. Human step: `make interop`.

### ⚠️ `make bench` is a REPORT, not a gate

It prints latency/throughput and **exits 0 whatever the numbers say** — no pass/fail criterion, so it cannot
go red, despite §6 listing it among the quality gates. **A green `make bench` is not evidence of anything.**

The gate that actually enforces performance is **`make gate-mem`** — an end-to-end allocation *ratchet*.
Allocation is what owns the latency tail (the ~10 ms p99.99 is a GC pause in the *peer*; ADR 0062), so that
is the number under guard. A latency ratchet is not viable on this hardware: the box measures 16–32 µs for
identical code.

### `make gate-build` — and why `make build` alone is not enough

`build` and `test` are *incremental*: ASDF skips any file whose fasl is newer than its source. That makes
them fast, but it also means **they can pass on a tree that does not compile** — a stale fasl cache will
happily satisfy a load whose sources no longer build. That is not theoretical: it let a wrong-arity call
sit in `main` for two days while `make test` reported 563/563.

`make gate-build` is the gate that can actually fail. It (1) **clears the fasl cache** and rebuilds from
scratch, and (2) **falsifies itself** first — it compiles a synthetic system containing a deliberate
wrong-arity call and aborts if the build machinery *fails to reject it*. A gate never proven able to fail
proves nothing, so the gate proves it on every run. Run it on both impls before calling work done:

```sh
make gate-build LISP=./scripts/with-sbcl.sh
make gate-build LISP=./scripts/with-allegro.sh
```

⚠️ On AllegroCL the second line is expected to **fail its own falsification step** until the plan's Phase 2
lands: ASDF's compile-failure behaviour there is `:warn`, so the wrong-arity canary is not rejected
(`docs/plans/2026-10-03-sbcl-allegro-full-ok.md` §1). That red is the honest answer, not a flake.

**No fasl in the source tree (WP-0.16).** Before building, `gate-build` fails if any `src/**/*.fasl` exists.
ASDF writes its output to the private cache (below), so a fasl beside the source can only come from a bare
`compile-file`; nothing rebuilds it, and a `(load "src/…/x")` without a type can load it instead of the
source. The check proves itself on every run (one planted `src/` fasl must be found; a `.lisp` file, a name
containing "fasl" and a fasl outside `src/` must not). `make clean` removes every compiled file in the tree
(never entering `.git`).

**The fasl cache is private to this project.** Every Lisp entry point (`scripts/with-sbcl.sh`,
`scripts/with-allegro.sh`, `scripts/gate-build.sh`) sources `scripts/lisp-cache-env.sh`, which sets
`XDG_CACHE_HOME` to `~/.cache/hofvarpnir` unless you have already exported one. This matters because
ASDF's default puts every project's fasls in one shared `~/.cache/common-lisp` keyed only by
implementation+version — so `gate-build`'s `rm -rf` would delete the fasls of any *other* project's Lisp
running at the same time, mid-run, surfacing as a failure in a project you were not even touching. A
private root also makes the clean-cache guarantee **stronger** than the wipe: nothing else writes there,
so what the gate clears is all there was. The cache lives outside the repo deliberately — this tree sits
in a synced folder, and a churning build cache must never be synced.

### `make gate-hotpath` — CLOS purity *and* allocation purity

It enforces two things over the designated hot-path files: no CLOS dispatch (NFR-CLOS), and **no
unjustified heap allocation** (NFR-MEM). The second check is new: the gate used to scan for CLOS only,
which is how `message.lisp` sat in the certified-clean list while `parse-header` allocated a 12-octet
guidPrefix on *every* inbound datagram.

Allocation is enforced by **annotation, not prohibition** — a hot-path file may allocate, but every
allocating form must say why:

```lisp
(make-array 12 :element-type '(unsigned-byte 8))   ; HOTPATH-ALLOC(COLD): teardown only, not per sample
```

Classes: `LOAD-TIME`, `COLD`, `ERROR-PATH`, `TEST`, and `TRACKED` (a **real** per-sample allocation, known
NFR-MEM debt, being driven to zero under ADR 0062). An **unmarked** allocating form fails the build — that
is the regression guard. The gate **prints the outstanding `TRACKED` set on every run**, so the remaining
debt is enumerated in the open rather than hiding in a profile nobody reruns. Like `gate-build`, it
falsifies itself on every run.

> **Never load our systems with `ql:quickload`.** It wraps the load in
> `ql-impl-util:call-with-quiet-compilation`, i.e. `(handler-bind ((warning #'muffle-warning)) ...)`, so
> `compile-file`'s `failure-p` never reaches ASDF and **no compile warning can fail the build**. Use
> `asdf:load-system`, which honours `*compile-file-failure-behaviour*`. Quicklisp is still what provides
> the dependencies — it just must not be what *gates* our code.

From a REPL:

```lisp
(ql:quickload :dds)        ; the control-plane stack
;; or a narrower system:
(ql:quickload :dds-cdr)    ; just the codec
(asdf:test-system :dds-tests)   ; run the suite
```

## Publish / subscribe in 4 steps

This is the DCPS happy path (adapted from `run-dcps-entity-test` in
`src/dds-tests/integration-test.lisp`). See [DCPS](dcps.md) for the full API.

```lisp
(ql:quickload :dds)

;; 1. Define a topic type. define-dds-type emits a defstruct + monomorphic XCDR codecs +
;;    key-hash + the XTypes TypeObject + a registered type-support, all named after the type.
(dds.gen:define-dds-type sensor (:extensibility :final)
  (id    :i32 :key t)     ; @key  -> participates in the instance key-hash
  (temp  :i32)
  (label :string))

;; 2. Two participants on domain 0; a writer and a reader on the same topic + type.
(let* ((ts  (dds.types:find-type-support "sensor"))
       (p1  (dds.dcps:create-participant :domain 0))
       (p2  (dds.dcps:create-participant :domain 0))
       (tw  (dds.dcps:create-topic p1 "Sensors" "sensor" ts))
       (tr  (dds.dcps:create-topic p2 "Sensors" "sensor" ts))
       (dw  (dds.dcps:create-datawriter (dds.dcps:create-publisher  p1) tw))
       (dr  (dds.dcps:create-datareader (dds.dcps:create-subscriber p2) tr)))
  (unwind-protect
       (progn
         ;; 3. Drive discovery until the endpoints match (caller-driven `spin` in v1).
         (loop repeat 150
               until (and (plusp (dds.dcps:matched-count p1))
                          (plusp (dds.dcps:matched-count p2)))
               do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))

         ;; 4. Write a sample; take it on the reader.
         (dds.dcps:write-sample dw (make-sensor :id 1 :temp 21 :label "rack-A"))
         (let ((got nil))
           (loop repeat 150 until got
                 do (let ((s (dds.dcps:take-samples dr)))
                      (when s (setf got (dds.dcps:cached-sample-data (first s)))))
                    (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
           (format t "~&reader got: id=~d temp=~d label=~s~%"
                   (sensor-id got) (sensor-temp got) (sensor-label got))))
    (dds.dcps:delete-participant p1)
    (dds.dcps:delete-participant p2)))
```

### What just happened

- `define-dds-type` registered a `type-support` (a `defstruct` of functions — the manual
  vtable) under the name `"sensor"`; `find-type-support` retrieves it. See
  [Type system](type-system.md).
- `create-topic` binds a topic name + type name to that `type-support`.
- Discovery (SPDP then SEDP) runs over UDP loopback; `matched-count` reflects RxO-compatible
  endpoint matches. See [Discovery](discovery.md) and [QoS](qos.md).
- `write-sample` serializes through the generated XCDR2 codec; the reliable RTPS data plane
  delivers it; `take-samples` returns `cached-sample` objects whose `cached-sample-data` is
  your `sensor` struct. See [DCPS](dcps.md) and the [RTPS engine](rtps-engine.md).

## Talk to RTI Connext / other DDS Shapes

```sh
make square-pub COLOR=BLUE     # publish ShapeType (interop with rtishapesdemo / our square-sub)
make square-sub                # subscribe
make square-spy                # discovery diagnostic
```

See [Interop](interop.md) for the Connext oracle/interop harness under `interop/connext/`.
