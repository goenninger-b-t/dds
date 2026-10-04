#!/usr/bin/env python3
"""ADR 0120: the transitional Definition-of-Done ratchet.

Until the Phase 1 exit of the governing plan (docs/plans/2026-10-03-sbcl-allegro-full-ok.md), the per-commit
test rule is "no NEW failure against test/baseline-<lisp>.txt and no NEW skip event against
test/skip-baseline-<lisp>.txt". This script holds the two halves of that rule and the proof that they can fail.

  test-baseline.py shrink-only [--staged] every baseline file in the working tree (--staged: in the index,
                                          i.e. what the commit being made contains) is a subset of EVERY
                                          version of it ever committed (counts never above the minimum).
                                          Called by `make gate-verification`; --staged by the pre-commit hook.
  test-baseline.py check-run LISP LOG     a `make test` log for LISP (sbcl | allegro) against that Lisp's two
                                          baselines: a failure or a skip event the baseline does not list,
                                          or more events than it allows, FAILS.
  test-baseline.py self-test              falsifies both checks on planted inputs (a scratch git repository
                                          and synthetic logs). shrink-only and check-run run it first.

Baseline formats (one entry per line; '#' starts a comment line; blank lines ignored):

  test/baseline-<lisp>.txt        <test-name> <owning-WP> [note ...]
                                  thread-leak-check <owning-WP> <max-threads> [note ...]
  test/skip-baseline-<lisp>.txt   <capability> <test-name> <max-events> <owning-WP> [note ...]

<owning-WP> is a work package id of the governing plan, e.g. WP-1.1 or WP-5.1b. <capability> is a keyword
of the closed ADR 0122 vocabulary, dds.tests:*skip-capabilities* (read from src/dds-tests/test-support.lisp,
without the colon). <test-name> is the run-all-tests registry name, or `thread-leak-check` for the ADR 0121
leaked-thread entry, or `<no test>` for a skip event noted outside a running test.

  test-baseline.py gate LISP LOG RC      ADR 0128 (WP-0.10 step 2): the verdict `make test` exits with. RC is
                                          the Lisp process's own exit status for the run that wrote LOG. Exit 0:
                                          no failure and no skip event outside the baselines (a baselined
                                          failure is printed as KNOWN and does not change the exit status);
                                          1: a new failure or skip, a run that did not finish (RC other than 0
                                          or 1: a timeout, a crash), an RC the log contradicts, or a log of the
                                          wrong Lisp; 3: as 0, but DDS_TEST_ALLOW_SKIP was set (NOT A GATE RUN).

  test-baseline.py entry LISP NAME LOG RC
                                          ADR 0128 section 3: the verdict of `make corpus` / `make fuzz` /
                                          `make mem` (NAME corpus, pbt-fuzz, mem), entry points that run outside
                                          the suite and so have no per-test baseline entries. Exit 1 when RC is
                                          not 0 (the entry point itself failed or did not finish), when the log
                                          is of the other Lisp or has no skip accounting, or when it records a
                                          skip event of a capability LISP's skip baseline does not already
                                          excuse for some test (with an empty baseline, as on SBCL: any skip
                                          event). The one exception is NAME corpus with :verified-elsewhere,
                                          the vectors *corpus-verified-elsewhere* defers to another gate by
                                          name. 3 under DDS_TEST_ALLOW_SKIP; else 0. No baseline entry is read
                                          or needed per entry point, so nothing grows (ADR 0120 rule 4).

DDS_TEST_ALLOW_SKIP=<cap>[,<cap>...] (ADR 0128; governing plan section 2, "one environment variable,
fail-closed by default") lets `check-run` and `gate` accept skip events of the named capabilities beyond
the skip baseline. It never excuses a failure. A run judged with it set prints NOT A GATE RUN and exits 3
(ALLOW_SKIP_RC), never 0, so it cannot be mistaken for a gate pass; the governing plan uses it only for the
Phase 1A exit check. Unset or empty: no capability is allowed beyond the baseline. A name outside the
vocabulary is an error.

The shrink-only rule compares the CURRENT file (working tree) against the running intersection of every
committed version, not only against HEAD: re-adding an entry that an earlier commit removed is growth, and so
is re-creating a baseline after a commit deleted it. A shallow clone cannot be checked and FAILS (a gate that
cannot see the history it is asked about must not report success).
"""
import os
import re
import subprocess
import sys
import tempfile

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
LISPS = ('sbcl', 'allegro')
WP_RE = re.compile(r'WP-\d+\.\d+[a-z]?\Z')
TEST_RE = re.compile(r'[^\s#]+\Z')
NO_TEST = '<no test>'
ALLOW_SKIP_ENV = 'DDS_TEST_ALLOW_SKIP'
ALLOW_SKIP_RC = 3           # a run judged with DDS_TEST_ALLOW_SKIP set: never 0, never a failure code
# The preflight's "on <IMPL>" token (dds.pal:pal-impl-name, ADR 0122 section 2.4) for each baseline name.
IMPL_TOKEN = {'sbcl': 'SBCL', 'allegro': 'ALLEGRO'}


class BaselineError(Exception):
    pass


def failure_path(lisp):
    return f'test/baseline-{lisp}.txt'


def skip_path(lisp):
    return f'test/skip-baseline-{lisp}.txt'


def read_vocabulary(repo):
    """The closed skip vocabulary, from (defparameter *skip-capabilities* '(...)) in test-support.lisp."""
    path = os.path.join(repo, 'src/dds-tests/test-support.lisp')
    text = open(path, encoding='utf-8').read()
    m = re.search(r"\(defparameter \*skip-capabilities\*\s*'\(([^)]*)\)", text)
    if not m:
        raise BaselineError(f'{path}: cannot read *skip-capabilities*')
    vocab = {k.lower() for k in re.findall(r':([a-zA-Z0-9-]+)', m.group(1))}
    if not vocab:
        raise BaselineError(f'{path}: *skip-capabilities* is empty')
    return vocab


# ---------------------------------------------------------------- parsing baseline files

def _entries(text):
    for n, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if not s or s.startswith('#'):
            continue
        yield n, line


LEAK = 'thread-leak-check'


def parse_failures(text, where):
    """{test-name: owning-WP}, except {thread-leak-check: (max-threads, owning-WP)}: the ADR 0121 leak entry
    carries an upper bound on the leaked dds-* thread count as its third field, which shrinks like a skip
    count. Raises BaselineError on a malformed or duplicate line."""
    out = {}
    for n, line in _entries(text):
        if line.startswith((' ', '\t')):
            raise BaselineError(f'{where}:{n}: an entry must start in column 0: {line!r}')
        f = line.split()
        if len(f) < 2:
            raise BaselineError(f'{where}:{n}: expected "<test-name> <owning-WP> [note]": {line!r}')
        name, wp = f[0], f[1]
        if not WP_RE.match(wp):
            raise BaselineError(f'{where}:{n}: owning WP {wp!r} is not a work-package id (WP-n.m)')
        if name in out:
            raise BaselineError(f'{where}:{n}: duplicate entry for {name!r}')
        if name == LEAK:
            if len(f) < 3 or not f[2].isdigit() or int(f[2]) < 1:
                raise BaselineError(f'{where}:{n}: expected "{LEAK} <owning-WP> <max-threads> [note]" with a '
                                    f'positive max-threads: {line!r}')
            out[name] = (int(f[2]), wp)
        else:
            out[name] = wp
    return out


def parse_skips(text, where, vocab):
    """{(capability, test-name): (max-events, owning-WP)}. '<no test>' is written as the literal token."""
    out = {}
    for n, line in _entries(text):
        if line.startswith((' ', '\t')):
            raise BaselineError(f'{where}:{n}: an entry must start in column 0: {line!r}')
        s = line.replace(NO_TEST, '<no-test>')
        f = s.split()
        if len(f) < 4:
            raise BaselineError(
                f'{where}:{n}: expected "<capability> <test-name> <max-events> <owning-WP> [note]": {line!r}')
        cap, name, count, wp = f[0], f[1], f[2], f[3]
        name = NO_TEST if name == '<no-test>' else name
        if cap not in vocab:
            raise BaselineError(f'{where}:{n}: capability {cap!r} is not in *skip-capabilities* (ADR 0122)')
        if not count.isdigit() or int(count) < 1:
            raise BaselineError(f'{where}:{n}: max-events {count!r} must be a positive integer')
        if not WP_RE.match(wp):
            raise BaselineError(f'{where}:{n}: owning WP {wp!r} is not a work-package id (WP-n.m)')
        if (cap, name) in out:
            raise BaselineError(f'{where}:{n}: duplicate entry for {cap} {name}')
        out[(cap, name)] = (int(count), wp)
    return out


# ---------------------------------------------------------------- shrink-only against git history

def git(repo, *args, check=True):
    r = subprocess.run(['git', '-C', repo, *args], capture_output=True, text=True)
    if check and r.returncode != 0:
        raise BaselineError(f'git {" ".join(args)}: {r.stderr.strip()}')
    return r


def committed_versions(repo, path):
    """[(sha, text-or-None)] oldest first: the file at every commit that touched it (None = deleted there)."""
    if git(repo, 'rev-parse', '--verify', '-q', 'HEAD', check=False).returncode != 0:
        return []                                   # no commit at all yet: nothing was ever committed
    shas = git(repo, 'log', '--reverse', '--format=%H', '--full-history', '--', path).stdout.split()
    out = []
    for sha in shas:
        r = git(repo, 'show', f'{sha}:{path}', check=False)
        out.append((sha, r.stdout if r.returncode == 0 else None))
    return out


def shrink_only_one(repo, path, parse, staged=False):
    """Problems (list of str) for one baseline file. PARSE(text, where) -> dict. STAGED: check the version in
    the index (what the commit being made will contain; the pre-commit hook) instead of the working tree."""
    problems = []
    current = None
    if staged:
        r = git(repo, 'show', f':{path}', check=False)
        text, where = (r.stdout, f'{path} (staged)') if r.returncode == 0 else (None, None)
    else:
        full = os.path.join(repo, path)
        text, where = (open(full, encoding='utf-8').read(), path) if os.path.exists(full) else (None, None)
    if text is not None:
        try:
            current = parse(text, where)
        except BaselineError as e:
            return [str(e)]
    history = committed_versions(repo, path)
    allowed = None              # running intersection; None = no committed version yet (current is the seed)
    for sha, text in history:
        if text is None:
            version = {}
        else:
            try:
                version = parse(text, f'{path}@{sha[:10]}')
            except BaselineError as e:
                problems.append(f'committed version is malformed: {e}')
                continue
        if allowed is not None:
            grew = _growth(allowed, version)
            if grew:
                print(f'  note: {path}@{sha[:10]} grew over earlier versions ({"; ".join(grew[:3])}); '
                      f'harmless only if the current file no longer carries it')
        allowed = version if allowed is None else _intersect(allowed, version)
    if current is None or allowed is None:
        return problems
    grew = _growth(allowed, current)
    for g in grew:
        problems.append(f'{path}: {g} — not in every committed version (ADR 0120: baselines only shrink)')
    return problems


def _key_count(v):
    return v[0] if isinstance(v, tuple) else None


def _intersect(a, b):
    out = {}
    for k, v in a.items():
        if k in b:
            ca, cb = _key_count(v), _key_count(b[k])
            out[k] = v if ca is None else (min(ca, cb), b[k][1])
    return out


def _growth(allowed, version):
    out = []
    for k, v in version.items():
        label = k if isinstance(k, str) else f'{k[0]} {k[1]}'
        if k not in allowed:
            out.append(f'{label} is new')
        elif _key_count(v) is not None and v[0] > allowed[k][0]:
            out.append(f'{label} allows {v[0]} event(s), history allows at most {allowed[k][0]}')
    return out


def shrink_only(repo, vocab, staged=False):
    if git(repo, 'rev-parse', '--is-shallow-repository').stdout.strip() == 'true':
        return ['shallow clone: the shrink-only rule needs the full history (checkout fetch-depth: 0)']
    problems = []
    for lisp in LISPS:
        problems += shrink_only_one(repo, failure_path(lisp), parse_failures, staged)
        problems += shrink_only_one(repo, skip_path(lisp), lambda t, w: parse_skips(t, w, vocab), staged)
    return problems


# ---------------------------------------------------------------- a run log against the baselines

def parse_run_log(text, vocab):
    """(tests, failures, skips, leaked) from a `make test` log: TESTS the set of registry names that ran
    ("[test] NAME ..."), FAILURES the set of names in the run's FAILURES block, SKIPS {(cap, test): events}
    from the ADR 0122 accounting, LEAKED the ADR 0121 leaked dds-* thread count. Raises BaselineError whenever
    the parse cannot be reconciled with the run's own totals, i.e. whenever the parser would be blind: no
    summary line; a failing run (F > 0 in "tests: P passed, F FAILED", or a leaked thread) without a FAILURES
    block or a RUN-ALL-TESTS line; those counts disagreeing with the names parsed; a FAILURES name that is not
    a test that ran; per-test skip lists that do not add up to the per-capability table."""
    lines = text.splitlines()
    tests = set()
    for ln in lines:
        m = re.match(r'\s*\[test\] (\S+) \.\.\.', ln)
        if m:
            tests.add(m.group(1))
    summary = [re.match(r'tests: (\d+) passed, (\d+) FAILED, (\d+) total\.', ln) for ln in lines]
    summary = [m for m in summary if m]
    if not summary:
        raise BaselineError('no "tests: P passed, F FAILED, T total." line: the run did not finish')
    if len(summary) != 1:
        raise BaselineError(f'{len(summary)} "tests: P passed, F FAILED, T total." lines: expected exactly one')
    n_failed = int(summary[0].group(2))
    # ADR 0121: "LEAKED THREADS: N dds-* thread(s)" adds a thread-leak-check entry to the FAILURES block; it is
    # not a test, so it is in the RUN-ALL-TESTS count but not in F.
    leak = [re.search(r'LEAKED THREADS: (\d+) dds-\* thread', ln) for ln in lines]
    leak = [m for m in leak if m]
    if len(leak) > 1:
        raise BaselineError(f'{len(leak)} "LEAKED THREADS" lines: expected at most one')
    leaked = int(leak[0].group(1)) if leak else 0
    expected = n_failed + (1 if leaked else 0)
    headers = [i for i, ln in enumerate(lines) if ln.startswith('FAILURES (the FIRST is the real one')]
    totals = [re.match(r'TEST FAILED \[RUN-ALL-TESTS\]: (\d+) failure', ln) for ln in lines]
    totals = [m for m in totals if m]
    if len(headers) > 1 or len(totals) > 1:
        raise BaselineError(f'{len(headers)} FAILURES blocks and {len(totals)} RUN-ALL-TESTS lines: expected at '
                            f'most one of each')
    if expected == 0:
        if headers or totals:
            raise BaselineError('the summary reports 0 failures and no leaked thread, but the log carries a '
                                'FAILURES block or a RUN-ALL-TESTS failure line')
        return tests, set(), _parse_skips_block(lines, vocab), 0
    # A failing run MUST carry both markers. Without them the failures cannot be named, and a run whose
    # failures cannot be named must not be read as "no new failure" (the ratchet would pass everything).
    if not headers:
        raise BaselineError(f'the summary reports {n_failed} failure(s) (+{leaked} leaked thread(s)) but the log '
                            f'has no "FAILURES (the FIRST is the real one ..." block: the failures cannot be named')
    if not totals:
        raise BaselineError(f'the summary reports {n_failed} failure(s) but the log has no "TEST FAILED '
                            f'[RUN-ALL-TESTS]: N failure(s)" line: the FAILURES block cannot be delimited')
    if int(totals[0].group(1)) != expected:
        raise BaselineError(f'the RUN-ALL-TESTS line reports {totals[0].group(1)} failure(s), the summary '
                            f'{n_failed} plus {1 if leaked else 0} thread-leak-check entry = {expected}')
    names = tests | {'thread-leak-check'}
    failures = set()
    entries = 0
    for ln in lines[headers[0] + 1:]:
        if ln.startswith('TEST FAILED [RUN-ALL-TESTS]'):
            break
        m = re.match(r'  (\S+)\Z', ln)          # a name line: exactly two spaces, one token; detail lines are deeper
        if m:
            if m.group(1) not in names:
                raise BaselineError(f'FAILURES block names {m.group(1)!r}, which is neither a test that ran '
                                    f'("[test] NAME ...") nor thread-leak-check')
            entries += 1
            failures.add(m.group(1))
    if entries != expected or len(failures) != entries:
        raise BaselineError(f'{entries} entr(y/ies) ({len(failures)} distinct) parsed from the FAILURES block, '
                            f'the summary needs {expected}: {sorted(failures)}')
    if ('thread-leak-check' in failures) != bool(leaked):
        raise BaselineError('the FAILURES block and the LEAKED THREADS line disagree on thread-leak-check')
    return tests, failures, _parse_skips_block(lines, vocab), leaked


def _parse_skips_block(lines, vocab):
    """SKIPS {(cap, test): events} from the ADR 0122 accounting block of a run log's LINES."""
    # Only the accounting block counts: the capability PREFLIGHT, printed before the first test, uses the same
    # "  <capability>: ..." shape ("  alloc-counter:      DOES NOT MOVE ...") and is not a skip list.
    try:
        acc = max(i for i, ln in enumerate(lines) if ln.startswith('skips by capability (ADR 0122'))
    except ValueError:
        raise BaselineError('no ADR 0122 "skips by capability" table in the log')
    lines = lines[acc:]
    table = {}
    for ln in lines:
        m = re.match(r'  ([a-z0-9-]+)\s+(\d+)\s+(\d+)\s+(\d+)\Z', ln)
        if m and m.group(1) in vocab:
            table[m.group(1)] = int(m.group(2))
    if not table:
        raise BaselineError('no ADR 0122 "skips by capability" table in the log')
    skips = {}
    i = 0
    while i < len(lines):
        m = re.match(r'  ([a-z0-9-]+):(.*)\Z', lines[i])
        if m and m.group(1) in vocab:
            cap, body = m.group(1), m.group(2)
            i += 1
            while i < len(lines) and lines[i].startswith('    '):
                body += ' ' + lines[i].strip()
                i += 1
            for item in (x.strip() for x in body.split(',')):
                if not item:
                    continue
                mm = re.match(r'(.+?) x(\d+)\Z', item)
                name, n = (mm.group(1), int(mm.group(2))) if mm else (item, 1)
                skips[(cap, name)] = skips.get((cap, name), 0) + n
            continue
        i += 1
    for cap, n in table.items():
        got = sum(v for (c, _), v in skips.items() if c == cap)
        if got != n:
            raise BaselineError(f'capability {cap}: the table says {n} event(s), the per-test list adds up to '
                                f'{got}: the skip list was not parsed completely')
    # An event noted outside a running test is already in the table under its capability and in the list as
    # "<no test>"; it needs a `<cap> <no test> N WP` baseline line like any other skip.
    return skips


def parse_allow_skip(value, vocab):
    """The capabilities DDS_TEST_ALLOW_SKIP names (ADR 0128), as a frozenset of vocabulary names. VALUE None or
    blank = none. Names are comma-separated, case-insensitive, with or without the leading colon. A name
    outside the closed ADR 0122 vocabulary raises BaselineError: a typo must not silently allow nothing."""
    if value is None or not value.strip():
        return frozenset()
    out = set()
    for item in value.split(','):
        cap = item.strip().lstrip(':').lower()
        if not cap:
            continue
        if cap not in vocab:
            raise BaselineError(f'{ALLOW_SKIP_ENV}: {item.strip()!r} is not in *skip-capabilities* (ADR 0122); '
                                f'known: {", ".join(sorted(vocab))}')
        out.add(cap)
    return frozenset(out)


def check_impl(log_text, lisp):
    """Problems (list of str) if the log is not a run of LISP: every ADR 0122 preflight line ends in "on <IMPL>"
    (dds.pal:pal-impl-name), and judging an AllegroCL log against the SBCL baselines, or the reverse, would
    pass or fail for the wrong reason. A log without a preflight line cannot be attributed and is rejected."""
    impls = re.findall(r'^preflight \(ADR 0122\): .* on (\S+)\s*$', log_text, re.M)
    if not impls:
        return ['no "preflight (ADR 0122): ... on <IMPL>" line: the log cannot be attributed to a Lisp']
    want = IMPL_TOKEN[lisp]
    wrong = sorted({i for i in impls if i != want})
    return [f'WRONG LISP: the log is a run on {", ".join(wrong)}, judged against the {lisp} baselines '
            f'(preflight must say "on {want}")'] if wrong else []


def check_run(repo, lisp, log_text, vocab, allow=frozenset()):
    """Rules 1 and 2 of ADR 0120 for one run log. ALLOW (ADR 0128, DDS_TEST_ALLOW_SKIP): capabilities whose
    skip events are accepted beyond the skip baseline; failures are never excused. Returns (problems,
    failures, skips, fixed, unskipped, leaked, known_failures, known_skips, allowed_skips)."""
    problems = check_impl(log_text, lisp)
    fb = os.path.join(repo, failure_path(lisp))
    sb = os.path.join(repo, skip_path(lisp))
    allowed_f = parse_failures(open(fb, encoding='utf-8').read(), failure_path(lisp)) if os.path.exists(fb) else {}
    allowed_s = parse_skips(open(sb, encoding='utf-8').read(), skip_path(lisp), vocab) if os.path.exists(sb) else {}
    _, failures, skips, leaked = parse_run_log(log_text, vocab)
    for name in sorted(failures - set(allowed_f)):
        problems.append(f'NEW FAILURE: {name} is not in {failure_path(lisp)}')
    if LEAK in failures and LEAK in allowed_f and leaked > allowed_f[LEAK][0]:
        problems.append(f'MORE LEAKED THREADS: {leaked} dds-* thread(s), {failure_path(lisp)} allows '
                        f'{allowed_f[LEAK][0]}')
    known_s, allowed_by_env = [], []
    for (cap, name), n in sorted(skips.items()):
        within = (cap, name) in allowed_s and n <= allowed_s[(cap, name)][0]
        if within:
            known_s.append(((cap, name), n, allowed_s[(cap, name)][1]))
        elif cap in allow:
            allowed_by_env.append(((cap, name), n))
        elif (cap, name) not in allowed_s:
            problems.append(f'NEW SKIP: {cap} in {name} ({n} event(s)) is not in {skip_path(lisp)}')
        else:
            problems.append(f'MORE SKIPS: {cap} in {name}: {n} event(s), {skip_path(lisp)} allows '
                            f'{allowed_s[(cap, name)][0]}')
    known_f = [(name, allowed_f[name][1] if name == LEAK else allowed_f[name])
               for name in sorted(failures & set(allowed_f))]
    fixed = sorted(set(allowed_f) - failures)
    unskipped = sorted(k for k in allowed_s if k not in skips)
    return problems, failures, skips, fixed, unskipped, leaked, known_f, known_s, allowed_by_env


# ADR 0128 section 3: the judged entry points and, per entry point, the capabilities its own source declares as
# a deliberate deferral. corpus: *corpus-verified-elsewhere* (src/dds-bench/corpus.lisp) names each vector another
# gate verifies; corpus-verify itself fails on any vector neither verified nor listed there.
ENTRIES = ('corpus', 'pbt-fuzz', 'mem')
ENTRY_DECLARED = {'corpus': frozenset({'verified-elsewhere'})}


def check_entry(repo, lisp, name, log_text, lisp_rc, vocab, allow=frozenset()):
    """ADR 0128 section 3 for one entry-point log. Returns (problems, known, allowed_by_env, skips): KNOWN is
    [((cap, test), n, why)] for accepted events, WHY naming the owning WPs of the baseline entries that already
    excuse CAP or the source declaration. A skip of a capability the Lisp's skip baseline excuses nowhere is a
    problem: the entry point is a second way to exercise code the suite covers, so a capability the suite may
    not skip on this Lisp it may not skip either. Bounding per entry point would need baseline entries under
    the entry-point name, which ADR 0120 rule 4 forbids adding; the capability rule needs none."""
    problems = check_impl(log_text, lisp)
    if name not in ENTRIES:
        raise BaselineError(f'entry point {name!r} is not one of {", ".join(ENTRIES)}')
    if lisp_rc != 0:
        what = {124: 'the timeout fired', 137: 'the timeout killed it'}.get(lisp_rc, 'it failed')
        problems.append(f'the entry point exited {lisp_rc} ({what}): see the log')
    sb = os.path.join(repo, skip_path(lisp))
    allowed_s = parse_skips(open(sb, encoding='utf-8').read(), skip_path(lisp), vocab) if os.path.exists(sb) else {}
    owners = {}
    for (cap, _), (_, wp) in allowed_s.items():
        owners.setdefault(cap, set()).add(wp)
    skips = _parse_skips_block(log_text.splitlines(), vocab)
    known, by_env = [], []
    for (cap, test), n in sorted(skips.items()):
        if cap in ENTRY_DECLARED.get(name, ()):
            known.append(((cap, test), n, f'declared by the {name} entry point itself'))
        elif cap in owners:
            known.append(((cap, test), n, f'{skip_path(lisp)} excuses {cap}, owner {", ".join(sorted(owners[cap]))}'))
        elif cap in allow:
            by_env.append(((cap, test), n))
        else:
            problems.append(f'NEW SKIP: {cap} in {name} ({n} event(s)): {skip_path(lisp)} excuses {cap} for no test')
    return problems, known, by_env, skips


def gate_rc_problems(lisp_rc, failures):
    """ADR 0128: problems with the Lisp process's own exit status RC for a run whose log names FAILURES. The
    suite exits 0 when nothing failed and 1 when something did (run-all-tests signals TEST-FAILURE, the
    Makefile's handler exits 1). Anything else (124/137: the timeout fired; another code: a crash) is a run
    that did not finish, whatever its log says; and an RC the log contradicts means the log is not the whole
    story. Either way the verdict is FAIL, never "no new failure"."""
    if lisp_rc not in (0, 1):
        what = {124: 'the timeout fired', 137: 'the timeout killed it'}.get(lisp_rc, 'it did not finish normally')
        return [f'the Lisp exited {lisp_rc} ({what}): the run is not judged']
    if lisp_rc == 0 and failures:
        return [f'the Lisp exited 0 but the log names {len(failures)} failure(s): the log and the exit disagree']
    if lisp_rc == 1 and not failures:
        return ['the Lisp exited 1 but the log names no failure: the run failed for a reason the log does not '
                'attribute to a test (see the end of the log)']
    return []


def verdict_rc(problems, allow):
    """ADR 0128: 1 on any problem; else ALLOW_SKIP_RC (3) when DDS_TEST_ALLOW_SKIP was set, so a run that
    needed an allowance is never reported as 0; else 0."""
    if problems:
        return 1
    return ALLOW_SKIP_RC if allow else 0


# ---------------------------------------------------------------- self-test

SAMPLE_LOG = """\
preflight (ADR 0122): SBCL 2.2.9.debian on SBCL
  alloc-counter:      DOES NOT MOVE (bytes-consed delta 0 across a 4096-cons list)
  [test] alpha ... ok
  [test] beta ... FAIL
           boom
  [test] gamma ... ok
  [test] delta ... FAIL
tests: 2 passed, 2 FAILED, 4 total.
coverage: 1 FULL, 1 PARTIAL, 0 SKIPPED, 2 FAILED of 4 test(s); 5 skip event(s).
skips by capability (ADR 0122; every event counted, no dedup):
  capability            events  tests  arms
  openssl-pqc                0      0     0
  alloc-counter              5      3     5
  alloc-counter: alpha, beta x3,
    gamma
threads: 0 leaked — every thread the suite started has ended.
FAILURES (the FIRST is the real one; later ones may be cascades):
  beta
    boom
  delta
    TEST FAILED [X]: detail
NIL/:WRAPPED
TEST FAILED [RUN-ALL-TESTS]: 2 failure(s) across 4 tests (a thread-leak-check entry is not a test)
"""


def self_test():
    """Returns a list of problems with the checker itself (empty = the checks are proven able to fail)."""
    bad = []
    vocab = {'openssl-pqc', 'alloc-counter'}

    def expect(label, cond):
        if not cond:
            bad.append(label)

    # -- the log parser and check-run
    with tempfile.TemporaryDirectory() as d:
        os.makedirs(os.path.join(d, 'test'))

        def put(rel, text):
            with open(os.path.join(d, rel), 'w', encoding='utf-8') as f:
                f.write(text)

        tests, fails, skips, leaked = parse_run_log(SAMPLE_LOG, vocab)
        expect('parser: no leak in the sample', leaked == 0)
        expect('parser: test names', tests == {'alpha', 'beta', 'gamma', 'delta'})
        expect('parser: failures (a wrapped detail line is not a name)', fails == {'beta', 'delta'})
        expect('parser: wrapped skip list', skips == {('alloc-counter', 'alpha'): 1,
                                                      ('alloc-counter', 'beta'): 3,
                                                      ('alloc-counter', 'gamma'): 1})
        try:
            parse_run_log(SAMPLE_LOG.replace('    gamma\n', ''), vocab)
            bad.append('parser: a truncated skip list (table 5, list 4) was ACCEPTED')
        except BaselineError:
            pass
        try:
            parse_run_log(SAMPLE_LOG.replace('tests: 2 passed', 'tests: 2 passd'), vocab)
            bad.append('parser: a log without the summary line was ACCEPTED')
        except BaselineError:
            pass
        # A run whose failures cannot be named or counted must be REJECTED, never read as "no new failure".
        hdr = 'FAILURES (the FIRST is the real one; later ones may be cascades):'
        tot = 'TEST FAILED [RUN-ALL-TESTS]: 2 failure(s) across 4 tests (a thread-leak-check entry is not a test)\n'
        blind = {
            'a renamed FAILURES header': SAMPLE_LOG.replace(hdr, 'FAILED TESTS:'),
            'a missing RUN-ALL-TESTS line': SAMPLE_LOG.replace(tot, ''),
            'a missing RUN-ALL-TESTS line and a failure name outside the [test] set':
                SAMPLE_LOG.replace(tot, '').replace('  delta\n    TEST', '  delta2\n    TEST'),
            'a failure name outside the [test] set': SAMPLE_LOG.replace('  delta\n    TEST', '  delta2\n    TEST'),
            'a summary F above the FAILURES block': SAMPLE_LOG.replace('2 passed, 2 FAILED', '1 passed, 3 FAILED'),
            'a RUN-ALL-TESTS count above the FAILURES block': SAMPLE_LOG.replace('2 failure(s) across', '3 failure(s) across'),
            'a duplicated failure entry': SAMPLE_LOG.replace('  delta\n    TEST', '  beta\n    TEST'),
            'a thread-leak-check entry without a LEAKED THREADS line':
                SAMPLE_LOG.replace('  delta\n    TEST', '  thread-leak-check\n    TEST'),
            'a FAILURES block with fewer names than both counts':
                SAMPLE_LOG.replace('  delta\n    TEST', '     delta\n    TEST'),
            'a FAILURES block in a run whose summary says 0 FAILED':
                SAMPLE_LOG.replace('2 passed, 2 FAILED', '4 passed, 0 FAILED'),
            'a leaked thread without a thread-leak-check entry':
                SAMPLE_LOG.replace('threads: 0 leaked — every thread the suite started has ended.',
                                   'LEAKED THREADS: 2 dds-* thread(s) started by the suite are still alive:'),
            'two summary lines': SAMPLE_LOG + 'tests: 4 passed, 0 FAILED, 4 total.\n',
        }
        for what, text in blind.items():
            if text == SAMPLE_LOG:
                bad.append(f'parser: the planted defect "{what}" did not apply (SAMPLE_LOG changed)')
                continue
            try:
                parse_run_log(text, vocab)
                bad.append(f'parser: a log with {what} was ACCEPTED (the ratchet would be blind)')
            except BaselineError:
                pass
        clean = (SAMPLE_LOG.replace('2 passed, 2 FAILED', '4 passed, 0 FAILED')
                 .split(hdr)[0])
        try:
            _, f0, _, l0 = parse_run_log(clean, vocab)
            expect('parser: a clean run parsed failures or leaks', f0 == set() and l0 == 0)
        except BaselineError as e:
            bad.append(f'parser: a clean run was REJECTED: {e}')
        # The ADR 0121 leak entry and its thread bound.
        leak_log = (SAMPLE_LOG
                    .replace('threads: 0 leaked — every thread the suite started has ended.',
                             '\u26a0\ufe0f LEAKED THREADS: 3 dds-* thread(s) started by the suite are still alive:\n'
                             '     dds-udp-rx (first seen after beta)')
                    .replace('NIL/:WRAPPED\n', 'NIL/:WRAPPED\n  thread-leak-check\n    3 dds-* thread(s) still alive\n')
                    .replace('2 failure(s) across', '3 failure(s) across'))
        _, lf, _, ln_ = parse_run_log(leak_log, vocab)
        expect('parser: thread-leak-check and its count', lf == {'beta', 'delta', LEAK} and ln_ == 3)
        put(skip_path('sbcl'), 'alloc-counter alpha 1 WP-1.13\nalloc-counter beta 3 WP-1.13\n'
                               'alloc-counter gamma 1 WP-1.13\n')
        put(failure_path('sbcl'), f'beta WP-1.1\ndelta WP-1.5\n{LEAK} WP-1.1 3 note\n')
        p, *_ = check_run(d, 'sbcl', leak_log, vocab)
        expect(f'check-run: a leak within its bound was REJECTED: {p}', p == [])
        put(failure_path('sbcl'), f'beta WP-1.1\ndelta WP-1.5\n{LEAK} WP-1.1 2 note\n')
        p, *_ = check_run(d, 'sbcl', leak_log, vocab)
        expect('check-run: MORE leaked threads than allowed were ACCEPTED',
               any('MORE LEAKED THREADS: 3' in x for x in p))
        put(failure_path('sbcl'), 'beta WP-1.1\ndelta WP-1.5\n')
        p, *_ = check_run(d, 'sbcl', leak_log, vocab)
        expect('check-run: a NEW thread leak was ACCEPTED', any(f'NEW FAILURE: {LEAK}' in x for x in p))
        # A skip event noted outside a running test: the literal `<no test>` token.
        nt_log = (SAMPLE_LOG.replace('  alloc-counter              5      3     5',
                                     '  alloc-counter              7      3     6')
                  .replace('    gamma\n', '    gamma, <no test> x2\n'))
        _, _, nts, _ = parse_run_log(nt_log, vocab)
        expect('parser: <no test> skip events', nts.get(('alloc-counter', NO_TEST)) == 2)
        base_s = 'alloc-counter alpha 1 WP-1.13\nalloc-counter beta 3 WP-1.13\nalloc-counter gamma 1 WP-1.13\n'
        put(skip_path('sbcl'), base_s + 'alloc-counter <no test> 2 WP-1.13 outside a test\n')
        p, *_ = check_run(d, 'sbcl', nt_log, vocab)
        expect(f'check-run: <no test> events within the baseline were REJECTED: {p}', p == [])
        put(skip_path('sbcl'), base_s + 'alloc-counter <no test> 1 WP-1.13\n')
        p, *_ = check_run(d, 'sbcl', nt_log, vocab)
        expect('check-run: MORE <no test> events than allowed were ACCEPTED',
               any(f'MORE SKIPS: alloc-counter in {NO_TEST}' in x for x in p))
        put(skip_path('sbcl'), base_s)
        p, *_ = check_run(d, 'sbcl', nt_log, vocab)
        expect('check-run: NEW <no test> events were ACCEPTED',
               any(f'NEW SKIP: alloc-counter in {NO_TEST}' in x for x in p))
        put(failure_path('sbcl'), 'beta WP-1.1\ndelta WP-1.5 note\n')
        put(skip_path('sbcl'), 'alloc-counter alpha 1 WP-1.13\nalloc-counter beta 3 WP-1.13\n'
                               'alloc-counter gamma 1 WP-1.13\n')
        p, *_ = check_run(d, 'sbcl', SAMPLE_LOG, vocab)
        expect(f'check-run: a run equal to its baseline was REJECTED: {p}', p == [])
        put(failure_path('sbcl'), 'beta WP-1.1\n')
        p, *_ = check_run(d, 'sbcl', SAMPLE_LOG, vocab)
        expect('check-run: a NEW failure was ACCEPTED', any('NEW FAILURE: delta' in x for x in p))
        put(failure_path('sbcl'), 'beta WP-1.1\ndelta WP-1.5\n')
        put(skip_path('sbcl'), 'alloc-counter alpha 1 WP-1.13\nalloc-counter beta 2 WP-1.13\n'
                               'alloc-counter gamma 1 WP-1.13\n')
        p, *_ = check_run(d, 'sbcl', SAMPLE_LOG, vocab)
        expect('check-run: MORE skip events than allowed were ACCEPTED', any('MORE SKIPS' in x for x in p))
        put(skip_path('sbcl'), 'alloc-counter alpha 1 WP-1.13\nalloc-counter beta 3 WP-1.13\n')
        p, *_ = check_run(d, 'sbcl', SAMPLE_LOG, vocab)
        expect('check-run: a NEW skip was ACCEPTED', any('NEW SKIP: alloc-counter in gamma' in x for x in p))
        # ADR 0128 (WP-0.10 step 2): the Lisp named by the log, KNOWN failures, DDS_TEST_ALLOW_SKIP, the Lisp's
        # own exit status and the verdict code.
        put(failure_path('sbcl'), 'beta WP-1.1\ndelta WP-1.5\n')
        put(skip_path('sbcl'), base_s)
        p, *rest = check_run(d, 'sbcl', SAMPLE_LOG, vocab)
        expect(f'check-run: KNOWN failures not reported: {rest}',
               p == [] and rest[5] == [('beta', 'WP-1.1'), ('delta', 'WP-1.5')] and len(rest[6]) == 3)
        p, *_ = check_run(d, 'allegro', SAMPLE_LOG, vocab)
        expect('check-run: an SBCL log judged against the allegro baselines was ACCEPTED',
               any('WRONG LISP' in x for x in p))
        p, *_ = check_run(d, 'sbcl', SAMPLE_LOG.replace('preflight (ADR 0122): SBCL 2.2.9.debian on SBCL\n', ''),
                          vocab)
        expect('check-run: a log with no preflight line (no Lisp named) was ACCEPTED',
               any('cannot be attributed' in x for x in p))
        put(skip_path('sbcl'), 'alloc-counter alpha 1 WP-1.13\nalloc-counter beta 3 WP-1.13\n')   # gamma unlisted
        p, *rest = check_run(d, 'sbcl', SAMPLE_LOG, vocab, allow=frozenset({'alloc-counter'}))
        expect(f'check-run: DDS_TEST_ALLOW_SKIP=alloc-counter did not accept an unlisted alloc-counter skip: {p}',
               p == [] and rest[7] == [(('alloc-counter', 'gamma'), 1)])
        expect('verdict: a run that needed DDS_TEST_ALLOW_SKIP exited 0 (it must be ALLOW_SKIP_RC)',
               verdict_rc(p, frozenset({'alloc-counter'})) == ALLOW_SKIP_RC)
        p, *_ = check_run(d, 'sbcl', SAMPLE_LOG, vocab, allow=frozenset({'openssl-pqc'}))
        expect('check-run: DDS_TEST_ALLOW_SKIP for ANOTHER capability accepted an unlisted skip',
               any('NEW SKIP: alloc-counter in gamma' in x for x in p))
        expect('verdict: a problem with DDS_TEST_ALLOW_SKIP set did not exit 1',
               verdict_rc(p, frozenset({'openssl-pqc'})) == 1)
        put(failure_path('sbcl'), 'beta WP-1.1\n')
        p, *_ = check_run(d, 'sbcl', SAMPLE_LOG, vocab, allow=frozenset(vocab))
        expect('check-run: DDS_TEST_ALLOW_SKIP excused a NEW FAILURE', any('NEW FAILURE: delta' in x for x in p))
        expect('verdict: a clean run did not exit 0', verdict_rc([], frozenset()) == 0)
        expect('allow-skip: names, case, colon', parse_allow_skip(' alloc-counter, :OPENSSL-PQC ,', vocab)
               == {'alloc-counter', 'openssl-pqc'})
        expect('allow-skip: unset/blank is not empty-allowed', parse_allow_skip(None, vocab) == frozenset()
               and parse_allow_skip('  ', vocab) == frozenset())
        try:
            parse_allow_skip('alloc-counter,alloc-countr', vocab)
            bad.append('allow-skip: a capability outside the vocabulary was ACCEPTED')
        except BaselineError:
            pass
        expect('gate: a timed-out Lisp (124) was judged', gate_rc_problems(124, set()) != [])
        expect('gate: a killed Lisp (137) was judged', gate_rc_problems(137, {'beta'}) != [])
        expect('gate: a crashed Lisp (2) was judged', gate_rc_problems(2, set()) != [])
        expect('gate: exit 0 with failures in the log was ACCEPTED', gate_rc_problems(0, {'beta'}) != [])
        expect('gate: exit 1 with no failure in the log was ACCEPTED', gate_rc_problems(1, set()) != [])
        expect('gate: a consistent exit status was REJECTED',
               gate_rc_problems(1, {'beta'}) == [] and gate_rc_problems(0, set()) == [])
        # ADR 0128 section 3: the entry points (corpus, pbt-fuzz, mem).
        entry_log = (SAMPLE_LOG.split('  [test] alpha')[0]
                     + 'coverage: 0 FULL, 1 PARTIAL, 0 SKIPPED, 0 FAILED of 1 test(s); 2 skip event(s).\n'
                       'skips by capability (ADR 0122; every event counted, no dedup):\n'
                       '  capability            events  tests  arms\n'
                       '  openssl-pqc                0      0     0\n'
                       '  alloc-counter              2      1     2\n'
                       '  alloc-counter: pbt-fuzz x2\n')
        clean_entry = (entry_log.replace('2 skip event(s)', '0 skip event(s)')
                       .replace('  alloc-counter              2      1     2\n  alloc-counter: pbt-fuzz x2\n',
                                '  alloc-counter              0      0     0\n'))
        put(skip_path('sbcl'), '')
        p, *_ = check_entry(d, 'sbcl', 'pbt-fuzz', clean_entry, 0, vocab)
        expect(f'entry: a clean run was REJECTED: {p}', p == [])
        p, *_ = check_entry(d, 'sbcl', 'pbt-fuzz', entry_log, 0, vocab)
        expect('entry: a skip against an EMPTY skip baseline was ACCEPTED',
               any('NEW SKIP: alloc-counter in pbt-fuzz' in x for x in p))
        put(skip_path('sbcl'), 'openssl-pqc alpha 1 WP-1.13\n')
        p, *_ = check_entry(d, 'sbcl', 'pbt-fuzz', entry_log, 0, vocab)
        expect('entry: a skip of a capability the baseline excuses for NO test was ACCEPTED',
               any('NEW SKIP: alloc-counter' in x for x in p))
        put(skip_path('sbcl'), 'alloc-counter alpha 1 WP-1.13\n')
        p, known, *_ = check_entry(d, 'sbcl', 'pbt-fuzz', entry_log, 0, vocab)
        expect(f'entry: a skip of a capability the baseline excuses was REJECTED: {p}',
               p == [] and len(known) == 1 and 'WP-1.13' in known[0][2])
        p, *_ = check_entry(d, 'sbcl', 'pbt-fuzz', clean_entry, 1, vocab)
        expect('entry: an entry point that exited 1 was ACCEPTED', any('exited 1' in x for x in p))
        p, *_ = check_entry(d, 'sbcl', 'pbt-fuzz', clean_entry, 124, vocab)
        expect('entry: an entry point that timed out was ACCEPTED', any('exited 124' in x for x in p))
        p, *_ = check_entry(d, 'allegro', 'pbt-fuzz', clean_entry, 0, vocab)
        expect('entry: an SBCL log judged as allegro was ACCEPTED', any('WRONG LISP' in x for x in p))
        put(skip_path('sbcl'), '')
        p, _, env, _ = check_entry(d, 'sbcl', 'pbt-fuzz', entry_log, 0, vocab, allow=frozenset({'alloc-counter'}))
        expect(f'entry: DDS_TEST_ALLOW_SKIP did not accept its capability: {p}', p == [] and len(env) == 1)
        try:
            check_entry(d, 'sbcl', 'pbt-fuzz', entry_log.split('skips by capability')[0], 0, vocab)
            bad.append('entry: a log without the skip accounting was ACCEPTED')
        except BaselineError:
            pass
        try:
            check_entry(d, 'sbcl', 'fuzzz', clean_entry, 0, vocab)
            bad.append('entry: an unknown entry-point name was ACCEPTED')
        except BaselineError:
            pass
        ve_vocab = vocab | {'verified-elsewhere'}
        ve_log = (clean_entry.replace('0 skip event(s)', '1 skip event(s)')
                  + '  verified-elsewhere         1      1     1\n  verified-elsewhere: corpus\n')
        p, *_ = check_entry(d, 'sbcl', 'corpus', ve_log, 0, ve_vocab)
        expect(f'entry: the corpus-declared :verified-elsewhere deferral was REJECTED: {p}', p == [])
        p, *_ = check_entry(d, 'sbcl', 'pbt-fuzz', ve_log.replace('verified-elsewhere: corpus',
                                                                   'verified-elsewhere: pbt-fuzz'), 0, ve_vocab)
        expect('entry: :verified-elsewhere outside corpus was ACCEPTED',
               any('NEW SKIP: verified-elsewhere' in x for x in p))
        for text, what in (('beta\n', 'missing WP'), ('beta WP1.1\n', 'malformed WP'),
                           ('beta WP-1.1\nbeta WP-1.2\n', 'duplicate'),
                           (f'{LEAK} WP-1.1\n', 'thread-leak-check without max-threads'),
                           (f'{LEAK} WP-1.1 eight\n', 'non-numeric max-threads'),
                           (f'{LEAK} WP-1.1 0\n', 'zero max-threads')):
            try:
                parse_failures(text, 'x')
                bad.append(f'parse: a failure baseline with a {what} was ACCEPTED')
            except BaselineError:
                pass
        for text, what in (('nosuchcap beta 1 WP-1.1\n', 'capability outside the vocabulary'),
                           ('alloc-counter beta 0 WP-1.1\n', 'zero count'),
                           ('alloc-counter beta 1\n', 'missing WP')):
            try:
                parse_skips(text, 'x', vocab)
                bad.append(f'parse: a skip baseline with a {what} was ACCEPTED')
            except BaselineError:
                pass

    # -- shrink-only against a scratch git history
    with tempfile.TemporaryDirectory() as d:
        env_git = ['-c', 'user.name=t', '-c', 'user.email=t@t', '-c', 'commit.gpgsign=false']
        subprocess.run(['git', 'init', '-q', d], check=True)
        os.makedirs(os.path.join(d, 'test'))
        fp, sp = failure_path('allegro'), skip_path('allegro')

        def put(rel, text):
            with open(os.path.join(d, rel), 'w', encoding='utf-8') as f:
                f.write(text)

        def commit(msg):
            subprocess.run(['git', '-C', d, *env_git, 'add', '-A'], check=True)
            subprocess.run(['git', '-C', d, *env_git, 'commit', '-q', '-m', msg], check=True)

        def problems():
            out = []
            out += shrink_only_one(d, fp, parse_failures)
            out += shrink_only_one(d, sp, lambda t, w: parse_skips(t, w, vocab))
            return out

        import contextlib
        import io
        quiet = contextlib.redirect_stdout(io.StringIO())
        with quiet:
            put(fp, 'a WP-1.1\nb WP-1.1\nc WP-1.5\n')
            put(sp, 'alloc-counter a 3 WP-1.13\nalloc-counter b 1 WP-1.13\n')
            expect('shrink-only: an uncommitted seed was REJECTED', problems() == [])
            commit('seed')
            put(fp, 'a WP-1.1\nc WP-1.5\n')            # b fixed
            put(sp, 'alloc-counter a 2 WP-1.13\nalloc-counter b 1 WP-1.13\n')
            commit('shrink')
            expect('shrink-only: an unchanged tree was REJECTED', problems() == [])
            put(fp, 'a WP-1.1\n')
            put(sp, 'alloc-counter a 1 WP-1.13\n')
            expect('shrink-only: a genuine shrink was REJECTED', problems() == [])
            put(fp, 'a WP-1.1\nc WP-1.5\nd WP-1.2\n')
            expect('shrink-only: a NEW failure entry was ACCEPTED', any('d is new' in x for x in problems()))
            put(fp, 'a WP-1.1\nb WP-1.1\nc WP-1.5\n')
            expect('shrink-only: re-adding an entry an earlier commit removed was ACCEPTED',
                   any('b is new' in x for x in problems()))
            put(sp, 'alloc-counter a 3 WP-1.13\nalloc-counter b 1 WP-1.13\n')   # a: 2 at HEAD, 3 in the seed
            commit('violation: b re-added and a raised, COMMITTED')   # HEAD itself now carries the growth
            expect('shrink-only: a growth already COMMITTED (working tree == HEAD) was ACCEPTED: the check '
                   'compares against HEAD only, not against the history', any('b is new' in x for x in problems()))
            expect('shrink-only: a skip count raised in a COMMITTED version was ACCEPTED: the history allowance '
                   'is not the minimum', any('history allows at most 2' in x for x in problems()))
            put(fp, 'a WP-1.1\nc WP-1.5\n')
            put(sp, 'alloc-counter a 2 WP-1.13\nalloc-counter b 1 WP-1.13\n')
            commit('b removed again, a back to 2')
            expect('shrink-only: removing a committed growth did not clear it', problems() == [])
            # --staged checks what the commit will contain: a grown baseline staged while the working-tree
            # copy is reverted must be REJECTED (the working-tree check alone would pass it).
            put(fp, 'a WP-1.1\nc WP-1.5\nnew WP-1.1\n')
            subprocess.run(['git', '-C', d, 'add', fp], check=True)
            put(fp, 'a WP-1.1\nc WP-1.5\n')
            expect('shrink-only: the working-tree check does not see the staged copy',
                   shrink_only_one(d, fp, parse_failures) == [])
            expect('shrink-only --staged: a grown baseline in the INDEX (working tree reverted) was ACCEPTED',
                   any('new is new' in x for x in shrink_only_one(d, fp, parse_failures, staged=True)))
            subprocess.run(['git', '-C', d, 'add', fp], check=True)
            expect('shrink-only --staged: a staged copy within the history was REJECTED',
                   shrink_only_one(d, fp, parse_failures, staged=True) == [])
            put(fp, 'a WP-1.1\nc WP-1.2\n')
            expect('shrink-only: reassigning the owning WP was REJECTED', problems() == [])
            put(sp, 'alloc-counter a 3 WP-1.13\nalloc-counter b 1 WP-1.13\n')
            expect('shrink-only: raising a skip count back to an EARLIER allowance was ACCEPTED',
                   any('history allows at most 2' in x for x in problems()))
            put(sp, 'alloc-counter a 2 WP-1.13\nalloc-counter b 1 WP-1.13\nopenssl-pqc a 1 WP-1.18\n')
            expect('shrink-only: a NEW skip entry was ACCEPTED', any('openssl-pqc a is new' in x for x in problems()))
            put(sp, 'alloc-counter a 2 WP-1.13\nalloc-counter b 1 WP-1.13\n')
            put(fp, 'a WP-1.1\nc WP-1.5\n')
            os.remove(os.path.join(d, fp))
            commit('expire the failure baseline')
            expect('shrink-only: deleting a baseline was REJECTED', problems() == [])
            put(fp, 'a WP-1.1\n')
            expect('shrink-only: RE-CREATING a deleted baseline was ACCEPTED', any('a is new' in x for x in problems()))
            os.remove(os.path.join(d, fp))
            put(fp, 'a WP-1.1\nc WP-1.5\n')
            commit('violation committed')             # history now carries a growth over the deletion
            os.remove(os.path.join(d, fp))
            expect('shrink-only: removing a committed violation did not clear it', problems() == [])
            # The leaked-thread bound shrinks like a skip count (a fresh file under another name: the
            # bound is in the seed, so only its count can move).
            lp = failure_path('sbcl')
            put(lp, f'z WP-1.1\n{LEAK} WP-1.1 4 seed\n')
            commit('leak seed 4')
            put(lp, f'z WP-1.1\n{LEAK} WP-1.1 3\n')
            commit('leak 3')
            put(lp, f'z WP-1.1\n{LEAK} WP-1.1 2\n')
            expect('shrink-only: lowering the leaked-thread bound was REJECTED',
                   shrink_only_one(d, lp, parse_failures) == [])
            put(lp, f'z WP-1.1\n{LEAK} WP-1.1 4\n')
            expect('shrink-only: raising the leaked-thread bound back to an EARLIER value was ACCEPTED',
                   any('history allows at most 3' in x for x in shrink_only_one(d, lp, parse_failures)))
            os.remove(os.path.join(d, lp))
            commit('drop the leak file')
            shallow = os.path.join(d, 'shallow')
            subprocess.run(['git', 'clone', '-q', '--depth', '1', f'file://{d}', shallow], check=True,
                           capture_output=True)
            expect('shrink-only: a SHALLOW clone was ACCEPTED (it cannot see the history)',
                   any('shallow clone' in x for x in shrink_only(shallow, vocab)))
    return bad


# ---------------------------------------------------------------- entry points

def main(argv):
    staged = '--staged' in argv[2:] and argv[1] == 'shrink-only'
    if staged:
        argv = [a for a in argv if a != '--staged']
    if len(argv) < 2 or argv[1] not in ('shrink-only', 'check-run', 'gate', 'entry', 'self-test'):
        print(__doc__)
        return 2
    try:
        bad = self_test()
    except Exception as e:                  # any crash means the checker is unproven, never a pass
        bad = [f'self-test crashed: {type(e).__name__}: {e}']
    if bad:
        for b in bad:
            print(f'  self-test: {b}')
        print('test-baseline: FAIL — the checker is not proven able to fail; its verdict would mean nothing.')
        return 1
    if argv[1] == 'self-test':
        print('test-baseline: self-test PASS (shrink-only, check-run, gate and entry all proven able to fail).')
        return 0
    try:
        vocab = read_vocabulary(REPO)
        if argv[1] == 'shrink-only':
            problems = shrink_only(REPO, vocab, staged)
            for p in problems:
                print(f'  {p}')
            if problems:
                print('test-baseline: FAIL — an ADR 0120 baseline is malformed or grew (see above).')
                return 1
            counts = []
            for lisp in LISPS:
                for rel, parse in ((failure_path(lisp), parse_failures),
                                   (skip_path(lisp), lambda t, w: parse_skips(t, w, vocab))):
                    if staged:
                        r = git(REPO, 'show', f':{rel}', check=False)
                        text = r.stdout if r.returncode == 0 else None
                    else:
                        full = os.path.join(REPO, rel)
                        text = open(full, encoding='utf-8').read() if os.path.exists(full) else None
                    counts.append(f'{rel}: {len(parse(text, rel))}' if text is not None else f'{rel}: absent')
            print(f'test-baseline: PASS — every ADR 0120 baseline ({"staged" if staged else "working tree"}) is '
                  f'within every committed version ({"; ".join(counts)}).')
            return 0
        if argv[1] == 'entry':
            if len(argv) != 6 or argv[2] not in LISPS or not argv[5].lstrip('-').isdigit():
                print('usage: test-baseline.py entry sbcl|allegro corpus|pbt-fuzz|mem LOG EXIT-STATUS')
                return 2
            lisp, name = argv[2], argv[3]
            allow = parse_allow_skip(os.environ.get(ALLOW_SKIP_ENV), vocab)
            log = open(argv[4], encoding='utf-8', errors='replace').read()
            problems, known, by_env, skips = check_entry(REPO, lisp, name, log, int(argv[5]), vocab, allow)
            print(f'test-baseline: {lisp} {name} run has {sum(skips.values())} skip event(s) in {len(skips)} '
                  f'(capability, test) pair(s).')
            for (cap, test), n, why in known:
                print(f'  KNOWN skip ({why}): {cap} in {test} x{n}')
            for (cap, test), n in by_env:
                print(f'  ALLOWED skip ({ALLOW_SKIP_ENV}, not excused by the baseline): {cap} in {test} x{n}')
            for p in problems:
                print(f'  {p}')
            rc = verdict_rc(problems, allow)
            if rc == 1:
                print(f'test-baseline: FAIL — {name} failed, or skipped what {skip_path(lisp)} does not excuse (ADR 0128 section 3).')
            elif rc == ALLOW_SKIP_RC:
                print(f'test-baseline: NOT A GATE RUN — {ALLOW_SKIP_ENV}={",".join(sorted(allow))} was set; exit {ALLOW_SKIP_RC} (ADR 0128).')
            else:
                print(f'test-baseline: PASS — {name} exited 0 and skipped nothing {skip_path(lisp)} does not excuse.')
            return rc
        gate = argv[1] == 'gate'
        if len(argv) != (5 if gate else 4) or argv[2] not in LISPS or (gate and not argv[4].lstrip('-').isdigit()):
            print('usage: test-baseline.py check-run sbcl|allegro LOG\n'
                  '       test-baseline.py gate sbcl|allegro LOG LISP-EXIT-STATUS')
            return 2
        lisp = argv[2]
        allow = parse_allow_skip(os.environ.get(ALLOW_SKIP_ENV), vocab)
        log = open(argv[3], encoding='utf-8', errors='replace').read()
        rc_problems = []
        try:
            problems, failures, skips, fixed, unskipped, leaked, known_f, known_s, by_env = \
                check_run(REPO, lisp, log, vocab, allow)
        except BaselineError as e:
            if gate and int(argv[4]) not in (0, 1):
                # The run did not finish: say so first; the unparseable log is the consequence, not the cause.
                rc_problems = gate_rc_problems(int(argv[4]), set())
                for p in rc_problems:
                    print(f'  {p}')
            raise e
        if gate:
            rc_problems = gate_rc_problems(int(argv[4]), failures)
        print(f'test-baseline: {lisp} run has {len(failures)} failure(s) ({leaked} leaked dds-* thread(s)), '
              f'{sum(skips.values())} skip event(s) in {len(skips)} (capability, test) pair(s).')
        for name, wp in known_f:
            extra = f', {leaked} thread(s)' if name == LEAK else ''
            print(f'  KNOWN failure (ADR 0120 baseline, owner {wp}{extra}): {name}')
        for (cap, name), n, wp in known_s:
            print(f'  KNOWN skip (ADR 0120 baseline, owner {wp}): {cap} in {name} x{n}')
        for (cap, name), n in by_env:
            print(f'  ALLOWED skip ({ALLOW_SKIP_ENV}, not in the baseline): {cap} in {name} x{n}')
        for name in fixed:
            print(f'  did not fail in this run (remove it from {failure_path(lisp)} in the commit that fixes it): {name}')
        for cap, name in unskipped:
            print(f'  not skipped in this run (remove it from {skip_path(lisp)} in the commit that fixes it): {cap} {name}')
        problems = rc_problems + problems
        for p in problems:
            print(f'  {p}')
        rc = verdict_rc(problems, allow)
        if rc == 1:
            print('test-baseline: FAIL — a new failure or skip, or a run that cannot be judged (see above; ADR 0120, ADR 0128).')
        elif rc == ALLOW_SKIP_RC:
            print(f'test-baseline: NOT A GATE RUN — {ALLOW_SKIP_ENV}={",".join(sorted(allow))} was set; no failure '
                  f'or skip outside the baseline and that allowance; exit {ALLOW_SKIP_RC} (ADR 0128).')
        else:
            print(f'test-baseline: PASS — no failure or skip event outside the ADR 0120 baseline '
                  f'({len(known_f)} KNOWN failure entr(y/ies), {sum(n for _, n, _ in known_s)} KNOWN skip event(s)); '
                  f'this is "no new failure under the ADR 0120 baseline", not "all tests pass".')
        return rc
    except BaselineError as e:
        print(f'test-baseline: FAIL — {e}')
        return 1


if __name__ == '__main__':
    sys.exit(main(sys.argv))
