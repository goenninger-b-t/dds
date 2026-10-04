# ADR 0128 — `make test` exits with the ADR 0120 verdict: unlisted skips and failures fail, listed ones are KNOWN (skip channel step 2)

- **Status:** **Proposed** (2026-10-04). Implements the step 2 that ADR 0122 §2.5 and ADR 0120 §4 already
  decided (both Accepted, ADR 0124); what this ADR adds for review is the mechanism, the exit codes and the
  scope (§2–§3).
- **Date:** 2026-10-04
- **Requirement:** NFR-TEST (a pass count must not be wider than the coverage behind it), the operating
  contract §5 ("never mark work done with a red gate or a skipped interop/byte-exact check") and §6
  (`make test`), NFR-PORT (the same rule on SBCL and AllegroCL), FR-SEC-2 / ADR 0123 (the security suite runs
  against the pinned OpenSSL in hosted CI)
- **Work package:** WP-0.10 step 2 and the rest of WP-0.16 of `docs/plans/2026-10-03-sbcl-allegro-full-ok.md`
  (the governing plan)
- **Relates to:** ADR 0120 (the baselines and `scripts/test-baseline.py`), ADR 0121 (the bounded run, the
  leaked-thread check), ADR 0122 (the skip channel; this is its step 2), ADR 0123 (the pinned OpenSSL),
  ADR 0127 (no exit while a baseline is non-empty)

---

## 1. The problem

After ADR 0122 step 1 and ADR 0120, every skip and failure was named and counted, and `make test-ratchet`
could say whether a run was worse than its baseline. `make test` itself still said something else:

- On **SBCL** it exited 0 on a run with skips. In hosted CI that run used the system OpenSSL 3.0 and
  reported about 106 `:openssl-pqc` skip events (about 100 DARE / DDS-Security tests that did nothing), and
  the job was green.
- On **AllegroCL** it exited non-zero on every run (18 known failures plus `thread-leak-check`), so a new
  failure looked exactly like the old ones.

Neither exit status carried the rule the Definition of Done is measured by until the Phase 1 exit. A green
`make test` must mean "no failure and no skip outside the named, owned baseline", on both Lisps, and the
hosted run must exercise the security code it claims to cover.

## 2. Decision

### 2.1 `make test` is the ratchet

`make test` runs the suite exactly as before (bounded by `timeout --kill-after=60 $(TEST_TIMEOUT)`, ADR 0121)
through `scripts/judged-run.sh`, which tees its output to a **fresh** log
`$(TEST_LOG_DIR)/neodds-test-<lisp>.XXXXXX.log` (mktemp; default `$TMPDIR` or `/tmp`; the path is printed
first) and then exits with `python3 scripts/test-baseline.py gate <lisp> <log> <lisp-exit-status>`:

| exit | meaning |
|---|---|
| **0** | no failure and no skip event outside `test/baseline-<lisp>.txt` and `test/skip-baseline-<lisp>.txt`. Every baselined failure that fired is printed as `KNOWN failure (ADR 0120 baseline, owner WP-…)`, every baselined skip as `KNOWN skip`, and every entry that did not fire as a candidate for removal. The last line says "no new failure under the ADR 0120 baseline", never "all tests pass" (ADR 0120 §2.2). |
| **1** | a failure not in the failure baseline; more leaked `dds-*` threads than its bound; a (capability, test) skip pair not in the skip baseline, or more events than it allows; a log of the other Lisp; or a run that cannot be judged (below) |
| **3** | as 0, except that `DDS_TEST_ALLOW_SKIP` (§2.3) let skip events of the named capabilities past the baseline: **NOT A GATE RUN** |

GNU make exits 2 whenever a recipe fails; the recipe's own code is in make's `Error N` line and in the
checker's last line. `make test-ratchet` stays as an alias of `make test`; `make baseline-check` applies the
same rule (including §2.3) to an existing log.

**Which baseline.** The Lisp is read from `LISP`'s name (`*allegro*` or `*sbcl*`; anything else is refused)
and cross-checked against the run's own preflight line (`preflight (ADR 0122): … on SBCL|ALLEGRO`). A log
without that line, or of the other Lisp, fails: judging an AllegroCL run against the SBCL baselines would
pass or fail for the wrong reason.

**Which skips are "required".** Every capability of `dds.tests:*skip-capabilities*` that the suite can
record. The vocabulary is already the list of things a full run needs; a `make test` run on a host that lacks
one of them has not run the suite. The skip baseline is per (capability, test), so a required capability is
excused for a named test, a named number of times, owned by a named WP, and nowhere else.

**The log belongs to this run.** An earlier draft tee'd to a fixed name and read only the Lisp's exit
status; when `tee` could not write that file (read-only, owned by another user in a sticky `/tmp`, a full
disk), the gate judged the log an earlier run had left there, and a launcher that ran nothing passed. Now the
log is created by `mktemp` for this run, and the run is not judged (exit 1) when `mktemp` fails or `tee`
exits non-zero.

**A run that cannot be judged fails.** The suite exits 0 when nothing failed and 1 when something did. The
gate fails when the Lisp exited with anything else (124 or 137: the timeout fired; another code: a crash),
when it exited 0 but the log names failures, when it exited 1 but the log names none (the run failed for a
reason no test owns, e.g. the ADR 0123 libcrypto preflight), and whenever the ADR 0120 log parser cannot
reconcile the log with the run's own totals (unchanged from ADR 0120 §3.2: it fails closed).

### 2.2 The rule lives in one place

The rule is applied by `scripts/test-baseline.py`, not by the Lisp. `run-all-tests` still reports honestly
and still signals on any failure, so `(asdf:test-system :dds-tests)` in a REPL says exactly what happened;
`make test` judges that report. One implementation of the rule (the one ADR 0120 already proves able to fail
before every verdict) is better than two that can drift. The self-test now also plants: KNOWN failures
reported as such; a log judged against the other Lisp's baselines; a log with no preflight line;
`DDS_TEST_ALLOW_SKIP` accepting an unlisted skip of its capability (exit 3, never 0), not of another
capability, never a failure, and rejecting an unknown name; and each inconsistent exit status (124, 137, 2,
0 with failures, 1 without).

### 2.3 `DDS_TEST_ALLOW_SKIP`

The governing plan §2: "Skip control is one environment variable, fail-closed by default:
`DDS_TEST_ALLOW_SKIP=<cap,…>`. When set, the run prints 'NOT A GATE RUN' and exits with a distinct code."

- Comma-separated capability names of the closed vocabulary, case-insensitive, with or without the colon.
  A name outside it is an error (exit 1): a typo must not silently allow nothing and look like a pass.
- Skip events of those capabilities are accepted beyond the skip baseline. **Failures are never excused.**
- The verdict is exit **3** with `NOT A GATE RUN — DDS_TEST_ALLOW_SKIP=…`, even when nothing beyond the
  baseline actually skipped: a run made under the allowance is not a gate run.
- Unset or empty: no allowance. There is no other skip switch (`DDS_TESTS_FAIL_ON_SKIP` does not exist).
- Its one intended use is the governing plan's Phase 1A exit check
  (`DDS_TEST_ALLOW_SKIP=alloc-counter,zc-sap-primitives,subprocess-mode make test LISP=…with-allegro.sh`).

### 2.4 Hosted CI runs the suite against the pinned OpenSSL 3.5

`.github/workflows/gates.yml` sets `NEODDS_CI_OPENSSL35: 'on'` (workflow-level `env`) in the same change, as
ADR 0122 §2.5 and the governing plan require: the pinned 3.5.9 is built (SHA-256 and OpenPGP verified,
`scripts/build-openssl.sh`), cached on its version and hash, and exported as `DDS_DARE_LIBCRYPTO` only. The
`openssl35` input of a manual run is removed. Turning the switch off now makes `make test` fail (about 106
`:openssl-pqc` events against an empty SBCL skip baseline); that is intended. The test step's bound is
25 minutes (was 12): the ~100 security tests that returned early now run. A failing run's log is uploaded as
the artifact `neodds-test-sbcl-log`.

### 2.5 Fasl hygiene (WP-0.16)

- `make clean` removes every `*.fasl`/`*.fasp`/`*.faso`/`*.fasc` in the tree, never entering `.git`. ASDF's
  own output lives in the private cache outside the repo (`scripts/lisp-cache-env.sh`).
- `make gate-build` fails, before building, when any `src/**/*.fasl` exists. Such a file can only come from
  a bare `compile-file`, nothing rebuilds it, and a `(load "src/…/x")` without a type can pick it up. The
  check falsifies itself on every run: in a scratch tree it must find exactly one planted `src/` fasl and
  none of three near misses (a `.lisp` file, a name containing "fasl", a fasl outside `src/`).
- The eight stale in-tree fasls (three in `src/dds-dare/` from 2026-06-30, one in `src/dds-bench/`, four in
  `src/dds-tests/`, all untracked) were deleted with `make clean`. The root debris files the plan row names
  (`4294967232`, `452`, `64`, `7`, `456`, `516`, `520`, `580`, `584`) no longer exist in this tree.

## 3. `make corpus`, `make fuzz` and `make mem` are judged on their skip accounting

These entry points run outside the suite under their own names (`corpus`, `pbt-fuzz`, `mem`), through
`run-with-skip-report`, so the per-test baselines have no entries for them, and adding entries would grow a
baseline (ADR 0120 rule 4). They are judged by a capability rule that needs none:
`scripts/test-baseline.py entry <lisp> <name> <log> <exit-status>`, through the same `scripts/judged-run.sh`
(fresh log, fail on a log that was not written):

- **exit 1** when the Lisp exited non-zero (a corpus mismatch, a fuzz finding, a timeout: unchanged meaning),
  when the log is of the other Lisp or has no skip accounting, or when the run recorded a skip event of a
  capability that the Lisp's skip baseline excuses for **no** test. An entry point is a second way to
  exercise code the suite covers; a capability the suite may not skip on this Lisp, it may not skip either.
  With SBCL's empty skip baseline that means any skip event; when a capability's last baseline entry is
  removed, its skips in the entry points fail from that commit on, with no further edit.
- The one exception is `corpus` with `:verified-elsewhere`: the vectors `*corpus-verified-elsewhere*`
  (`src/dds-bench/corpus.lisp`) defers by name to another gate (today `logevent-connext.bin`, verified by
  `run-log-corpus-test` in `make test`), and `corpus-verify` itself fails on any vector neither verified nor
  listed. It is printed as `KNOWN skip (declared by the corpus entry point itself)`.
- On AllegroCL a skip of an already-excused capability is printed as `KNOWN skip (… excuses <cap>, owner
  WP-…)`; `make fuzz` there runs `run-pbt-tests`, whose loan-acquire arm records `zc-sap-primitives` (owner
  WP-1.15).
- **exit 3** under `DDS_TEST_ALLOW_SKIP` (§2.3); else **exit 0**.

The rule bounds capabilities, not event counts: a per-entry-point count would need a per-entry-point
baseline. An earlier draft of this ADR left the three targets report-only on both Lisps, giving the
shrink-only rule as the reason; that reason held for AllegroCL only, and on SBCL, the Lisp hosted CI runs,
it left a skip regression in `make corpus` or `make fuzz` green. Hosted CI runs `make corpus` and
`make fuzz` (SBCL), so both are now enforced there.

## 4. What this does not change

- The ADR 0120 rules, files, shrink-only check and expiry are unchanged. The baselines are not edited by this
  change (only their header comments point at `make test`).
- Running `run-all-tests` directly (REPL, `asdf:test-system`) is unchanged and does not consult the
  baselines.

## 5. Verification

Linux x86_64, 2026-10-04, working tree on `41082ef`, `. scripts/openssl-env.sh` (OpenSSL 3.5.9, one
libcrypto mapping), `timeout 1800 make test LISP=…`:

| Lisp | Suite | `make test` |
|---|---|---|
| SBCL 2.2.9.debian | 654 passed, 0 FAILED; coverage 654 FULL, 0 skip events; 0 leaked threads; Lisp exit 0 | **rc 0**: PASS, 0 KNOWN |
| AllegroCL 11.0 `alisp` | 636 passed, 18 FAILED; coverage 603 FULL, 15 PARTIAL, 18 SKIPPED, 18 FAILED; 51 skip events; 8 leaked `dds-*` threads; Lisp exit 1 | **rc 0**: PASS, 19 KNOWN failure entries (the 18 + `thread-leak-check`, 8 threads), 51 KNOWN skip events; `dcps-read-status-reset` and `durability-microservice-reconnect-bare` listed as "did not fail in this run" |

After the review fixes (fresh mktemp log, judged entry points), same host and environment, both Lisps
again: SBCL `make test` rc 0 (654 passed, 654 FULL, 0 skip events, 0 leaked), `make corpus` rc 0 (one
`verified-elsewhere` event, KNOWN as declared by the corpus), `make fuzz` rc 0 and `make mem` rc 0 (0 skip
events); AllegroCL `make test` rc 0 (636 passed, 18 FAILED, the same 19 KNOWN failure entries, 51 KNOWN skip
events, 8 leaked threads), `make corpus` rc 0 (the same `verified-elsewhere` event), `make fuzz` rc 0 with one
`zc-sap-primitives` event in `pbt-fuzz`, KNOWN as excused by the AllegroCL skip baseline (owner WP-1.15),
which confirms the inference this ADR's first draft recorded.

Fresh-log wiring, stand-in launchers (no Lisp): a read-only copy of a passing SBCL log at the old fixed name
`neodds-test-sbcl.log` plus a launcher that runs nothing → `Error 1` (the log judged is this run's, which has
no summary); an unwritable or missing `TEST_LOG_DIR` → `Error 1`; a `tee` that exits 1 → `Error 1`
("the run is not judged"). Entry points: the recorded SBCL corpus, fuzz and mem logs → rc 0; the corpus log
judged as `fuzz` → `Error 1` (`verified-elsewhere` is declared for `corpus` only); fuzz with Lisp exit 1 →
`Error 1`; the SBCL fuzz log under an allegro launcher → `Error 1` (WRONG LISP); a launcher that runs nothing
→ `Error 1`. The self-test plants the `entry` cases (empty baseline, a capability the baseline excuses for no
test, an excused one, exit 1, exit 124, wrong Lisp, `DDS_TEST_ALLOW_SKIP`, no accounting, unknown entry
name, `verified-elsewhere` in and outside `corpus`); disabling the exit-status check, the corpus-only scope
of the declaration, the baseline-capability check, or the allowance's scope each makes it FAIL.

The make plumbing of the first draft, with stand-in launchers that print a recorded log and exit with a chosen status (no
Lisp run): the AllegroCL log (exit 1) under an `…allegro…` launcher → rc 0; the same log under an `…sbcl…`
launcher → `Error 1` (`WRONG LISP` and `NEW SKIP`); the SBCL log with exit 0 → rc 0, with exit 124 →
`Error 1`, with exit 1 → `Error 1`; `DDS_TEST_ALLOW_SKIP=alloc-counter` → `Error 3`, NOT A GATE RUN;
`DDS_TEST_ALLOW_SKIP=bogus` → `Error 1`; a launcher named neither → exit 2 before any run.

The checker's self-test passes, and each of ten mutations of the new code makes it FAIL: the ALLOW_SKIP
verdict returning 0; the Lisp-identity check disabled; a log without a preflight line accepted; the allowance
applied to any capability; the allowance excusing a failure; Lisp exit codes other than 0/1, exit 0 with
failures, and exit 1 without failures each accepted; an unknown capability in `DDS_TEST_ALLOW_SKIP`
accepted; KNOWN failures not reported.

`make gate-build` stray-fasl stage: it failed on the tree as it was (eight fasls listed) and passed after
`make clean`; its self-falsifier finds exactly the one planted `src/` fasl. The full
`make gate-build LISP=./scripts/with-sbcl.sh` then PASSED (stray-fasl stage, canary rejected, clean-cache
build of `:dds-tests`). Not run on AllegroCL in this change (its canary step is expected to fail until
Phase 2; `docs/wiki/getting-started.md`). Static gates on the final
tree: `gate-verification`, `gate-skip-lint`, `gate-pal`, `gate-quit-lint`, `gate-types`, `gate-hotpath`,
`gate-nocond`, `gate-nlx` PASS.

Hosted CI before this change (`workflow_dispatch` of `Gates` on `41082ef` with the then-existing
`openssl35` input, run 37188859030): the pinned build on `ubuntu-latest` verified SHA-256 and OpenPGP and
passed the `OSSL_PARAM` probe; the SBCL 2.2.9.debian suite against it was 654 passed, 0 FAILED, 654 FULL,
0 skip events, 0 leaked threads; every step green. That is the run this change makes the default.

Hosted CI of this change (push of `59c2fd5`, `Gates` run 37190681940): green. `make test` (SBCL 2.2.9,
pinned OpenSSL 3.5.9 by default) 654 passed, 654 FULL, 0 skip events, 0 leaked threads, verdict PASS;
`make corpus` PASS with its one declared `verified-elsewhere` event; `make fuzz` PASS with 0 skip events.

Not a hot-path change (no file `gate-hotpath` scans is touched; the Lisp edits are docstrings and comments in
the test harness), so no bench report.

## 6. Consequences

- `make test` exits 0 on both Lisps at this commit while every known issue is printed by name and owner.
  A new failure or skip on either Lisp turns it red, in hosted CI for SBCL and locally for AllegroCL (ADR 0120
  §2.1 rule 5, until WP-3.2).
- `make test` needs `python3` and `bash`, as `make test-ratchet` and the pre-commit hook already did.
- ADR 0120's verification-matrix row stays **partial**: the shrink-only rule is not yet in hosted CI
  (`make gate-verification` joins it under WP-3.1) and AllegroCL has no hosted runner (WP-3.2).
