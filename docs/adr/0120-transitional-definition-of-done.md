# ADR 0120 — Transitional Definition of Done: a shrink-only failure and skip baseline per Lisp, until the Phase 1 exit

- **Status:** **Accepted** (2026-10-04). Approved in advance by owner decision **D31** (ADR 0124 §2: "approved,
  in the form plan WP-0.3(b) specifies"); this text is the ADR that approval was given for.
- **Enforced by `make test`:** since ADR 0128 (rules 1 and 2; `make test-ratchet` is an alias).
- **Date:** 2026-10-04
- **Requirement:** the operating contract §5 (Definition of Done: "code compiles and unit tests pass on SBCL and
  AllegroCL"; "never mark work done with a red gate"), §7 (per-task loop); NFR-TEST; NFR-PORT (SBCL and
  AllegroCL are co-equal targets)
- **Work package:** WP-0.3(b) of `docs/plans/2026-10-03-sbcl-allegro-full-ok.md` (the governing plan)
- **Expires:** at the **Phase 1 exit** of the governing plan (§5). The number was reserved for this ADR when the
  plan was written; ADRs 0121–0125 were written before it, ADRs 0126 and 0127 alongside it.
- **Relates to:** ADR 0118 (Clasp withdrawn), ADR 0121 (exit-process; the leaked-thread check), ADR 0122 (one
  skip channel; its step 2 consumes the skip baseline), ADR 0123 (the pinned OpenSSL), ADR 0124 (D31),
  ADR 0126 (milestone sequence), ADR 0127 (exit gates: no exit while a baseline is non-empty)

---

## 1. The problem

The Definition of Done says a unit of work is done only when its unit tests pass on SBCL **and** AllegroCL.
On 2026-10-04 the AllegroCL suite has 18 known failures and a leaked-thread failure, every one of them
pre-existing and owned by a Phase 1 work package. Read literally, no commit on any subject can be done until
Phase 1 ends. In practice, a rule that every commit breaks is a rule nobody reads, and the next real
regression on AllegroCL would be hidden among the 19 failures everyone has learned to ignore.

The fix is not to relax the rule silently. It is to write down exactly which failures and skips are known,
who owns each, and to make that list impossible to grow.

## 2. Decision

### 2.1 The per-commit rule until the Phase 1 exit

For each Lisp (`sbcl`, `allegro`):

1. **No new failure.** A `make test` run may fail only tests listed in `test/baseline-<lisp>.txt`. A failure
   not listed there, including `thread-leak-check` (ADR 0121) when it is not listed, fails the commit. The
   `thread-leak-check` entry carries an upper bound on the number of leaked `dds-*` threads; a run that leaks
   more fails the commit, and the bound shrinks like a skip count (rule 4).
2. **No new skip.** A run may report only the skip events listed in `test/skip-baseline-<lisp>.txt`: each
   (capability, test) pair at most the listed number of times. A pair not listed, or more events than listed,
   fails the commit.
3. **Every entry names its owning work package** of the governing plan (`WP-1.1`, `WP-1.13`, …). An entry
   without one is malformed and fails the gate.
4. **The baselines only shrink.** The file in the working tree must be a subset of **every version of it ever
   committed**, with every skip count (and the leaked-thread bound) at or below the smallest count any
   committed version allowed.
   Comparing only against `HEAD` would not do: re-adding an entry that an earlier commit removed would pass.
   Deleting a baseline is allowed; re-creating it afterwards is growth. Reassigning an entry's owning WP is
   allowed. `make gate-verification` enforces this (§3.2), and a shallow clone fails the check, because it
   cannot see the history it is asked about.
5. **Where it is checked.** Rule 4 (shrink-only): by the pre-commit hook on the staged copy
   (`scripts/git-hooks/pre-commit` runs `shrink-only --staged`; active once `make hooks` has run in the
   clone; bypassed only by `git commit --no-verify`) and on the working tree by
   `make gate-verification`. Neither is hosted CI yet: `make gate-verification` joins `.github/workflows/gates.yml`
   under WP-3.1, and that checkout needs `fetch-depth: 0`, because a shallow clone fails the check. Rules 1
   and 2 (`check-run`): SBCL on every commit, locally (`make test-ratchet`), and in hosted CI once WP-0.10
   step 2 wires it (§4). AllegroCL: **locally on every commit**, recorded in the schema of WP-3.8 (the
   signed-record fallback), until the AllegroCL runner of WP-3.2 is live. Until WP-0.10 step 2 and WP-3.1
   land, the ratchet is enforced only where someone runs it; the verification matrix row for this ADR is
   therefore **partial**, not done.

### 2.2 What this ADR does not relax

- Every other Definition-of-Done item (gates green, docs, ADRs, SBOM, bench for hot-path changes) is unchanged.
- **No milestone exit is declared while either Lisp's baselines are non-empty** (ADR 0127 §2). The ratchet is
  a per-commit device; it never stands in for an exit gate.
- A run that the baseline accepts is reported as "no new failure under the ADR 0120 baseline", never as
  "green" or "all tests pass".
- A baseline entry is not a waiver. Each one is a defect with an owner, scheduled in Phase 1, and the owning
  WP removes the line in the commit that fixes it.

**Known limits of the ratchet** (accepted; they are why §2.2's second bullet holds):

- **It is test-granular.** A baselined test may fail on **any** assertion: a new regression inside
  `dcps-type-gate`, `durability-supervisor` or another baselined test, reported under a different
  `TEST FAILED [TAG]`, is not seen for as long as that test stays in the baseline. The tag measured on
  2026-10-04 is recorded in each entry's note so a reviewer can compare, but it is not enforced: several
  baselined tests are timing-dependent and fail on different assertions from run to run (the first failing
  assertion of a cascade is not stable), so a tag check would make the ratchet itself intermittent.
- **The two intermittent entries** (`durability-microservice-reconnect-bare`, `dcps-read-status-reset`) are
  listed although they did not fail in the measuring run, which widens what a single run may hide by those
  two tests.
- **The leaked-thread bound counts threads, not which threads.** A new leak that replaces an old one at the
  same count is not seen.
- **A grown baseline committed with `--no-verify` and removed again in the next commit is not flagged
  afterwards.** Rule 4 judges the current file; a growth that no longer appears in it is history, printed as
  a note by `shrink-only` but not a failure. The pre-commit hook checks the **staged** copy
  (`shrink-only --staged`), so this needs a deliberate bypass.

The cure for all four is the same and is not this ADR's: the owning WPs empty the baseline (§5).

### 2.3 The SBCL baselines assume the pinned OpenSSL

The SBCL baselines are **empty**, measured with `. scripts/openssl-env.sh` (OpenSSL 3.5.9, ADR 0123). A run
against the system OpenSSL 3.0.13 reports about 106 `:openssl-pqc` skip events (ADR 0122 §4), and those are
**not** baselined: such a run does not exercise DARE or DDS-Security and fails rule 2. That is deliberate.
Every run meant to count sources the pinned library.

## 3. Mechanism

### 3.1 The files

`test/baseline-<lisp>.txt`, one entry per line, `#` comment lines:

```
<test-name> <owning-WP> [note …]
thread-leak-check <owning-WP> <max-threads> [note …]
```

`test-name` is the `run-all-tests` registry name. The ADR 0121 entry is `thread-leak-check`, and its third
field is the largest number of leaked `dds-*` threads a run may report (the `LEAKED THREADS: N` line).

`test/skip-baseline-<lisp>.txt`:

```
<capability> <test-name> <max-events> <owning-WP> [note …]
```

`capability` is a keyword of `dds.tests:*skip-capabilities*` (ADR 0122 §2.2) without the colon; the checker
reads the vocabulary from `src/dds-tests/test-support.lisp`, so an unknown capability is malformed.
`test-name` may be `<no test>` for an event noted outside a running test.

### 3.2 The checker: `scripts/test-baseline.py`

| Command | What it does |
|---|---|
| `shrink-only [--staged]` | Rule 4 for all four files, as in the working tree (`make gate-verification`) or, with `--staged`, as in the index, i.e. what the commit being made contains (the pre-commit hook) |
| `check-run sbcl\|allegro LOG` | Rules 1 and 2 for one `make test` log: parses the `[test]` lines, the `tests: P passed, F FAILED` summary, the `LEAKED THREADS` line, the `FAILURES` block and the ADR 0122 skip accounting; fails on a new failure, more leaked threads than allowed, a new (capability, test) pair, or more events than allowed. It also lists the entries that did not fire in this run, as candidates for removal |
| `self-test` | Proves both checks able to fail (below) |

**The log parser fails closed.** A run whose failures cannot be named and counted is rejected, never read as
"no new failure": F in the summary plus one `thread-leak-check` entry when threads leaked must equal both the
`TEST FAILED [RUN-ALL-TESTS]: N failure(s)` count and the number of names in the `FAILURES` block; a failing
run must carry both markers; a name in the block must be a test that ran or `thread-leak-check`; a run whose
summary says 0 FAILED with no leak must carry neither marker; the summary must appear exactly once.

Both `shrink-only` and `check-run` run `self-test` first and refuse to give a verdict when it fails, or when it
crashes. The
self-test plants, in a scratch git repository: an uncommitted seed (accepted); a genuine shrink (accepted); a
new failure entry, a new skip entry, and a raised skip count (each rejected); an entry re-added after an
earlier commit removed it, both uncommitted and **committed** (rejected: the check is against the history,
not only `HEAD`); a skip count raised in a committed version (rejected: the allowance is the minimum over the
history); a baseline re-created after a commit deleted it (rejected); a committed growth later removed
(accepted again); a shallow clone (rejected); and malformed lines (missing or malformed WP, duplicate, unknown
capability, zero count, a `thread-leak-check` line without a positive bound); a grown baseline staged while
the working-tree copy is reverted (rejected by `--staged`); and a leaked-thread bound
lowered (accepted) and raised back to an earlier value (rejected). For `check-run` it parses a synthetic log
with a wrapped skip list, a detail line that is not a test name and a preflight line shaped like a skip list,
and rejects a new failure, a new skip, too many events, a truncated skip list (the table and the per-test list
disagree, so the parser would be blind) and a log with no summary line. It also rejects every way the
failure block can go blind: a renamed `FAILURES` header, a missing `RUN-ALL-TESTS` line (with and without a
failure name outside the `[test]` set), a name outside that set, a summary F or a `RUN-ALL-TESTS` count that
disagrees with the block, a duplicated entry, a block with fewer names than both counts, a `FAILURES` block in
a run whose summary says 0 FAILED, a leaked thread without its entry and the reverse, and two summary lines.
It accepts a leak within its bound and rejects one above it or not listed, and it accepts, over-counts and
rejects as new a skip event under the literal `<no test>` token.

`make test-ratchet LISP=…` runs `make test` for that Lisp, keeps the log (`RATCHET_LOG`, default
`$TMPDIR/neodds-test-ratchet.log`) and runs `check-run` on it; its exit status is the ratchet's verdict.
`make baseline-check BASELINE_LISP=… LOG=…` checks an existing log.

## 4. Relation to ADR 0122 step 2

ADR 0122 is step 1: skips are counted and printed, and `make test`'s exit status is unchanged. Step 2
(WP-0.10) makes a skip of a required capability fail the run unless it is listed in the skip baseline, and
lands in the same commit that turns on the pinned OpenSSL in hosted CI (WP-0.8/0.9). It reads the same
`test/skip-baseline-<lisp>.txt` files this ADR defines. Until step 2 lands, `check-run` (through
`make test-ratchet`) is where rules 1 and 2 are applied.

## 5. Expiry

The rule expires at the **Phase 1 exit** of the governing plan, whose criterion is "the ADR 0120 baselines are
empty and deleted". The commit that declares the Phase 1 exit deletes the four files. From then on the rule
is zero/zero: `make test` on each Lisp reports `0 FAILED`, `0 SKIPPED`, `0 PARTIAL`, no leaked thread, and
exits 0. Rule 4 keeps a deleted baseline from coming back: re-creating one after a committed deletion is
growth, and `make gate-verification` fails on it (proven by the self-test, §3.2).

## 6. The baselines, as measured

Linux x86_64, 2026-10-04, at commit `767c335`, with `. scripts/openssl-env.sh` (OpenSSL 3.5.9; the preflight
shows one libcrypto mapping, `~/.local/opt/openssl-3.5/lib64/libcrypto.so.3`), `timeout 1800 make test`:

| Lisp | Result | Baselines |
|---|---|---|
| SBCL 2.2.9.debian | **654 passed, 0 FAILED**; coverage 654 FULL, 0 skip events; 0 leaked threads; rc 0 | both empty |
| AllegroCL 11.0 `alisp` | **636 passed, 18 FAILED**, 654 total; `thread-leak-check` (8 `dds-*` threads); coverage 603 FULL, 15 PARTIAL, 18 SKIPPED, 18 FAILED; 51 skip events; make rc 2 | `baseline-allegro.txt`: 21 entries; `skip-baseline-allegro.txt`: 33 entries, 51 events |

The AllegroCL failure baseline holds the 18 failures and `thread-leak-check` of that run (bound: 8 threads,
the count measured), plus two
intermittent failures that did not fire in it but were measured failing on this tree or its parent:
`durability-microservice-reconnect-bare` (1 of 4 full runs, ADR 0125 §6) and `dcps-read-status-reset`
(about 9 % of isolated runs, ADR 0121 §7). Leaving a known intermittent out would make the ratchet fail on
roughly one commit in ten for a defect nobody introduced, which teaches people to ignore it.

| Owner | Failure entries | What |
|---|---|---|
| WP-1.1 (WP-1.2 for condition-variable waits) | 19 | waits of 0.075 s or less return immediately on AllegroCL (plan §1); includes `thread-leak-check`, whose 8 threads were first seen after tests in this group, and the two intermittents |
| WP-1.5 | 1 | `typelookup-server` (`TLS-INDEX-HIT`): TypeLookup index iteration order |
| WP-1.3 | 1 | `rti-shmem-recognition` (`:SHMAT-FAILED`): `shmget`'s -1 returns as 4294967295 through CFFI `:int` without sign extension, so `(minusp id)` misses it (`src/dds-pal/pal-net.lisp`, the System V attach) |

| Owner | Skip entries | Capability |
|---|---|---|
| WP-1.13 | 12 tests, 20 events | `alloc-counter` (`dds.pal:bytes-consed` is the constant 0 on AllegroCL) |
| WP-1.15 | 18 tests, 18 events | `zc-sap-primitives` |
| WP-1.16 | 2 tests, 2 events | `subprocess-mode` |
| WP-1.19 | 1 test, 11 events | `static-vector-p` |

`check-run` against four AllegroCL logs (the three full runs of the ADR 0125 work, §6 there, and this
measurement) and this SBCL run: PASS for each. Against the SBCL baseline, the AllegroCL log FAILS (its skips are not in
the SBCL file), as it should.

## 7. Consequences

- New: `test/baseline-sbcl.txt`, `test/skip-baseline-sbcl.txt`, `test/baseline-allegro.txt`,
  `test/skip-baseline-allegro.txt`, `scripts/test-baseline.py`, `make test-ratchet`, `make baseline-check`.
  `scripts/gate-verification.sh` and the pre-commit hook (`scripts/git-hooks/pre-commit`) run
  `test-baseline.py shrink-only`.
- `make test`'s own exit status is unchanged: on AllegroCL it is still non-zero. The ratchet's verdict is
  `make test-ratchet`'s.
- The Phase 1 work packages own every entry. Phase 1 is finished when the files are gone, not when the
  entries are judged harmless.
