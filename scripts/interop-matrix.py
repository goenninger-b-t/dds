#!/usr/bin/env python3
"""interop/matrix.csv: the interop exit-gate matrix (ADR 0127 §6, governing plan WP-0.15 / WP-4.12).

  interop-matrix.py check       the file is well-formed and complete: every required cell present exactly once,
                                every Status in the closed set, an EXCLUDED cell only where ADR 0127 §6.2 allows
                                one (a Connext shmem cell) and citing an ADR that exists. Called by
                                `make gate-verification`. It runs the self-test first.
  interop-matrix.py self-test   proves the check able to fail on planted defects.
  interop-matrix.py skeleton    prints the complete matrix with every cell NOT-RUN (how the file was made).

This checks the SHAPE of the matrix, not the interop itself: making `make interop` fail on any cell that is
not PASS (or EXCLUDED by an ADR) is WP-4.12. Until then every cell is NOT-RUN and says so.

Columns: Lisp,Peer,Feature,Direction,Status,Evidence,Notes
  Lisp       our side: sbcl | allegro (ADR 0118; AllegroCL means the alisp image, ADR 0124 D1)
  Peer       connext-7.3.1 | fastdds-3.6.1 | neodds-allegro (the cross-Lisp leg, listed once, from the SBCL side)
  Feature    be | reliable | cft | durability | evolution | frag | large-data | secure | flatdata, for every
             peer; plus shmem for connext-7.3.1 and the cross-Lisp leg (Fast DDS's shared-memory transport is
             its own, not a wire this stack claims; ADR 0127 §6)
  Direction  out (our side writes, the peer reads) | in (the peer writes, our side reads)
  Status     NOT-RUN | PASS | FAIL | EXCLUDED
  Evidence   NOT-RUN: empty. PASS / FAIL: the committed results file or capture of that leg (path must exist).
  Notes      EXCLUDED: allowed ONLY on a connext-7.3.1 shmem cell (ADR 0127 §6.2, the owner decision D20 scoping
             ADR of WP-5.9), and Notes must name that ADR ("ADR NNNN"), which must exist as docs/adr/NNNN-*.md.
"""
import csv
import glob
import io
import os
import re
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
PATH = 'interop/matrix.csv'
HEADER = ['Lisp', 'Peer', 'Feature', 'Direction', 'Status', 'Evidence', 'Notes']
LISPS = ['sbcl', 'allegro']
VENDOR_PEERS = ['connext-7.3.1', 'fastdds-3.6.1']
CROSS_PEER = 'neodds-allegro'
FEATURES = ['be', 'reliable', 'cft', 'durability', 'evolution', 'frag', 'large-data', 'secure', 'flatdata']
SHMEM_PEERS = ['connext-7.3.1', CROSS_PEER]          # peers that also get a `shmem` cell
DIRECTIONS = ['out', 'in']
STATUSES = {'NOT-RUN', 'PASS', 'FAIL', 'EXCLUDED'}
EXCLUDABLE = {('connext-7.3.1', 'shmem')}            # (peer, feature) cells an ADR may exclude (§6.2)

FEATURE_NOTE = {
    'be': 'BEST_EFFORT ShapeType both ways; includes the RxO-negative case (an incompatible QoS must NOT match '
          'and must raise the incompatible-QoS statuses)',
    'reliable': 'RELIABLE ShapeType; HEARTBEAT/ACKNACK/GAP repair observed on the wire',
    'cft': 'content-filtered topic, writer-side and reader-side filtering',
    'durability': 'TRANSIENT_LOCAL late joiner (and TRANSIENT/PERSISTENT where the peer supports them)',
    'evolution': 'XTypes appendable/mutable type evolution, assignability both ways',
    'frag': 'DATA_FRAG / NACK_FRAG / HEARTBEAT_FRAG with a sample larger than the fragment size',
    'large-data': 'large samples (64 KB to 4 MB) end to end',
    'secure': 'DDS-Security on a shared governance/permissions set: encrypt, sign and datasign variants',
    'flatdata': 'FlatData-equivalent binding on our side; the peer uses its FlatData or plain XCDR2 binding '
                '(M5 exit, where wire-compatible)',
    'shmem': 'same-host shared-memory transport incl. Zero-Copy (M5 exit, where wire-compatible); a Connext '
             'cell may be EXCLUDED only by the owner decision D20 scoping ADR (WP-5.9)',
}


def required_cells():
    cells = []
    for lisp, peer in [(l, p) for l in LISPS for p in VENDOR_PEERS] + [('sbcl', CROSS_PEER)]:
        for f in FEATURES + (['shmem'] if peer in SHMEM_PEERS else []):
            for d in DIRECTIONS:
                cells.append((lisp, peer, f, d))
    return cells


def skeleton():
    out = io.StringIO()
    w = csv.writer(out, lineterminator='\n')
    w.writerow(HEADER)
    for lisp, peer, f, d in required_cells():
        w.writerow([lisp, peer, f, d, 'NOT-RUN', '', FEATURE_NOTE[f]])
    return out.getvalue()


def check_text(text, repo):
    """Problems (list of str) with the matrix TEXT; evidence paths are resolved against REPO."""
    problems = []
    rows = list(csv.reader(io.StringIO(text)))
    if not rows:
        return ['no records']
    if rows[0] != HEADER:
        problems.append(f'header {rows[0]} is not {HEADER}')
    seen = {}
    for i, r in enumerate(rows[1:], 2):
        if len(r) != len(HEADER):
            problems.append(f'line {i}: {len(r)} fields, expected {len(HEADER)}')
            continue
        lisp, peer, feat, d, status, evidence, notes = r
        key = (lisp, peer, feat, d)
        if key in seen:
            problems.append(f'line {i}: duplicate cell {key} (first at line {seen[key]})')
        seen[key] = i
        if status not in STATUSES:
            problems.append(f'line {i}: Status {status!r} not in {sorted(STATUSES)}')
        if status == 'NOT-RUN' and evidence:
            problems.append(f'line {i}: a NOT-RUN cell carries evidence {evidence!r}')
        if status in ('PASS', 'FAIL'):
            if not evidence:
                problems.append(f'line {i}: a {status} cell has no evidence path')
            elif not os.path.exists(os.path.join(repo, evidence)):
                problems.append(f'line {i}: evidence {evidence!r} does not exist')
        if status == 'EXCLUDED':
            # ADR 0127 §6.2: only a Connext shmem cell may be EXCLUDED, and only by an ADR that exists (the
            # owner decision D20 scoping ADR, WP-5.9). Every other cell is run or the exit does not pass.
            if (peer, feat) not in EXCLUDABLE:
                problems.append(f'line {i}: cell {key} may not be EXCLUDED (ADR 0127 §6.2: only '
                                f'{sorted(EXCLUDABLE)} cells may be, by ADR)')
            m = re.search(r'\bADR (\d{4})\b', notes)
            if not m:
                problems.append(f'line {i}: an EXCLUDED cell must name its ADR in Notes ("ADR NNNN")')
            elif not glob.glob(os.path.join(repo, 'docs', 'adr', f'{m.group(1)}-*.md')):
                problems.append(f'line {i}: the excluding ADR {m.group(1)} does not exist under docs/adr/')
    required = set(required_cells())
    for key in sorted(set(seen) - required):
        problems.append(f'line {seen[key]}: cell {key} is not in the matrix definition (ADR 0127 §6)')
    for key in sorted(required - set(seen)):
        problems.append(f'missing cell {key}: a cell may be EXCLUDED by an ADR, never dropped')
    return problems


def self_test():
    bad = []
    good = skeleton()
    if check_text(good, REPO):
        bad.append(f'the generated skeleton was REJECTED: {check_text(good, REPO)[:2]}')
    lines = good.splitlines(keepends=True)
    cases = {
        'a dropped cell': ''.join(lines[:5] + lines[6:]),
        'a duplicated cell': good + lines[3],
        'an unknown Status': good.replace('NOT-RUN', 'SKIPPED', 1),
        'an EXCLUDED cell without an ADR': good.replace(',NOT-RUN,,', ',EXCLUDED,,', 1),
        'a PASS cell without evidence': good.replace(',NOT-RUN,,', ',PASS,,', 1),
        'a PASS cell whose evidence does not exist': good.replace(',NOT-RUN,,', ',PASS,interop/no/such/file,', 1),
        'a NOT-RUN cell with evidence': good.replace(',NOT-RUN,,', ',NOT-RUN,interop/matrix.csv,', 1),
        'a cell outside the definition': good + 'allegro,neodds-sbcl,be,out,NOT-RUN,,x\n',
        'a shmem cell for a peer without one': good + 'sbcl,fastdds-3.6.1,shmem,out,NOT-RUN,,x\n',
        'a shifted column': good.replace('sbcl,connext-7.3.1,be,out,NOT-RUN,,', 'sbcl,connext-7.3.1,be,out,,NOT-RUN,', 1),
        'a wrong header': good.replace('Lisp,Peer', 'Impl,Peer', 1),
    }
    for what, text in cases.items():
        if not check_text(text, REPO):
            bad.append(f'{what} was ACCEPTED')
    def set_cell(text, key, status, notes):
        """TEXT with the row for KEY rewritten to STATUS / NOTES (whole-row rewrite: Notes may be CSV-quoted)."""
        rows = list(csv.reader(io.StringIO(text)))
        hit = False
        for r in rows[1:]:
            if tuple(r[:4]) == key:
                r[4], r[5], r[6] = status, '', notes
                hit = True
        out = io.StringIO()
        csv.writer(out, lineterminator='\n').writerows(rows)
        return out.getvalue() if hit else text

    existing = sorted(glob.glob(os.path.join(REPO, 'docs', 'adr', '[0-9][0-9][0-9][0-9]-*.md')))
    if not existing:
        bad.append('no ADR under docs/adr/ to cite in the positive exclusion case')
        return bad
    real = os.path.basename(existing[-1])[:4]
    missing = next(f'{n:04d}' for n in range(9999, 0, -1)
                   if not glob.glob(os.path.join(REPO, 'docs', 'adr', f'{n:04d}-*.md')))
    shmem = ('sbcl', 'connext-7.3.1', 'shmem', 'out')
    rejected = {
        f'an EXCLUDED Connext shmem cell citing the MISSING ADR {missing}':
            set_cell(good, shmem, 'EXCLUDED', f'ADR {missing} scopes this out'),
        'an EXCLUDED Connext shmem cell citing no ADR':
            set_cell(good, shmem, 'EXCLUDED', 'scoped out'),
        f'an EXCLUDED non-shmem cell (Connext reliable) citing the existing ADR {real}':
            set_cell(good, ('sbcl', 'connext-7.3.1', 'reliable', 'out'), 'EXCLUDED', f'ADR {real} scopes this out'),
        f'an EXCLUDED cross-Lisp shmem cell citing the existing ADR {real}':
            set_cell(good, ('sbcl', CROSS_PEER, 'shmem', 'out'), 'EXCLUDED', f'ADR {real} scopes this out'),
    }
    for what, text in rejected.items():
        if text == good:
            bad.append(f'{what}: the planted defect did not apply (the skeleton changed)')
        elif not check_text(text, REPO):
            bad.append(f'{what} was ACCEPTED')
    ok_excluded = set_cell(good, shmem, 'EXCLUDED', f'ADR {real} scopes this out')
    if ok_excluded == good or check_text(ok_excluded, REPO):
        bad.append(f'an EXCLUDED Connext shmem cell citing the existing ADR {real} was REJECTED: '
                   f'{check_text(ok_excluded, REPO)[:2]}')
    return bad
    real = os.path.basename(existing[-1])[:4]
    missing = next(f'{n:04d}' for n in range(9999, 0, -1)
                   if not glob.glob(os.path.join(REPO, 'docs', 'adr', f'{n:04d}-*.md')))
    rejected = {
        'an EXCLUDED Connext shmem cell citing a MISSING ADR':
            good.replace(shmem, f'sbcl,connext-7.3.1,shmem,out,EXCLUDED,,ADR {missing} scopes this out; ', 1),
        'an EXCLUDED non-shmem cell (reliable) citing an existing ADR':
            good.replace('sbcl,connext-7.3.1,reliable,out,NOT-RUN,,',
                         f'sbcl,connext-7.3.1,reliable,out,EXCLUDED,,ADR {real} scopes this out; ', 1),
        'an EXCLUDED cross-Lisp shmem cell citing an existing ADR':
            good.replace('sbcl,neodds-allegro,shmem,out,NOT-RUN,,',
                         f'sbcl,neodds-allegro,shmem,out,EXCLUDED,,ADR {real} scopes this out; ', 1),
    }
    for what, text in rejected.items():
        if text == good:
            bad.append(f'{what}: the planted defect did not apply (the skeleton changed)')
        elif not check_text(text, REPO):
            bad.append(f'{what} was ACCEPTED')
    ok_excluded = good.replace(shmem, f'sbcl,connext-7.3.1,shmem,out,EXCLUDED,,ADR {real} scopes this out; ', 1)
    if ok_excluded == good or check_text(ok_excluded, REPO):
        bad.append(f'an EXCLUDED Connext shmem cell citing the existing ADR {real} was REJECTED')
    return bad


def main(argv):
    cmd = argv[1] if len(argv) > 1 else ''
    if cmd == 'skeleton':
        sys.stdout.write(skeleton())
        return 0
    if cmd not in ('check', 'self-test'):
        print(__doc__)
        return 2
    bad = self_test()
    if bad:
        for b in bad:
            print(f'  self-test: {b}')
        print('interop-matrix: FAIL — the check is not proven able to fail.')
        return 1
    if cmd == 'self-test':
        print('interop-matrix: self-test PASS.')
        return 0
    full = os.path.join(REPO, PATH)
    if not os.path.exists(full):
        print(f'interop-matrix: FAIL — {PATH} is missing')
        return 1
    text = open(full, encoding='utf-8', newline='').read()
    problems = check_text(text, REPO)
    for p in problems:
        print(f'  {PATH}: {p}')
    if problems:
        print('interop-matrix: FAIL — the matrix is malformed or incomplete (see above).')
        return 1
    rows = list(csv.reader(io.StringIO(text)))[1:]
    tally = {s: sum(1 for r in rows if r[4] == s) for s in sorted(STATUSES)}
    print(f'interop-matrix: PASS — {len(rows)} cells, complete and well-formed '
          f'({", ".join(f"{k} {v}" for k, v in tally.items())}); enforcement of PASS is WP-4.12.')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
