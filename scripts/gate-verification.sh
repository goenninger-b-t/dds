#!/usr/bin/env bash
# gate-verification — docs/verification.csv must be parseable CSV: every record exactly 6 fields.
#
# WHY. The verification matrix is a Definition-of-Done artifact (the operating contract §5) and the
# EU-CRA-adjacent evidence trail. It is prose-heavy, and for a long time nobody parsed it — so 36 of its
# 201 records had drifted into being unparseable: the Notes field was written UNQUOTED, so every comma
# inside it became a field separator (one record split into 79 fields). Two further records were empty,
# left by stray bare LFs in an otherwise CRLF file. A human reading the file saw nothing wrong; any tool
# reading it got garbage, and a future gate or report over this file would have been silently wrong.
#
# WHAT IT CHECKS
#   1. every record parses to EXACTLY 6 fields (Req, Method, Artifact, Gate, Status, Notes)
#   2. no empty records
#   3. the header is intact
#   4. the Gate column is a profile/milestone token (P0..P7, M0..M8, Mx-My, all, n/a). A record can have
#      exactly 6 fields and still be wrong: an unquoted comma in Artifact shifts Gate into Artifact and the
#      Status into Gate, and the last field silently absorbs "status,notes". Five records had exactly that
#      shape after the 6-field repair; a field count alone accepted them.
#   5. the file stays CRLF-terminated — git holds it as CRLF, and a line-ending flip turns a one-row
#      addition into a whole-file diff that buries the real change
#
# --self-test falsifies it: builds a file carrying each defect and asserts the checker REJECTS it, and a
# clean one and asserts it ACCEPTS. A gate never proven able to fail proves nothing.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

CSV="docs/verification.csv"

check() {  # $1 = path; prints problems, exit 1 if any
  python3 - "$1" <<'PY'
import csv, re, sys
GATE = re.compile(r'P[0-7]|M[0-8](-M[0-8])?|all|n/a')
path = sys.argv[1]
raw = open(path, 'rb').read()
problems = []
if not raw.endswith(b'\r\n'):
    problems.append("file does not end with CRLF")
rows = list(csv.reader(open(path, newline='', encoding='utf-8')))
if not rows:
    problems.append("no records at all")
else:
    if rows[0] != ['Req','Method','Artifact','Gate','Status','Notes']:
        problems.append(f"header is not the 6 expected columns: {rows[0][:8]}")
    for i, r in enumerate(rows):
        if len(r) == 0:
            problems.append(f"record {i}: EMPTY record")
        elif len(r) != 6:
            problems.append(f"record {i}: {len(r)} fields, expected 6 (Req={r[0][:40]!r})")
        elif i > 0 and not GATE.fullmatch(r[3]):
            problems.append(f"record {i}: Gate {r[3][:40]!r} is not a profile/milestone token — a shifted column? (Req={r[0][:40]!r})")
for p in problems[:20]:
    print("  " + p)
if len(problems) > 20:
    print(f"  ... and {len(problems)-20} more")
sys.exit(1 if problems else 0)
PY
}

# ---- 0. FALSIFICATION ----
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
printf 'Req,Method,Artifact,Gate,Status,Notes\r\nFR-X,m,a,P0,done,"a note, with a comma"\r\n' > "$tmp/good.csv"
if ! check "$tmp/good.csv" >/dev/null; then
  echo "gate-verification: FAIL — self-test: a WELL-FORMED file was rejected. The gate is wrong." >&2
  exit 1
fi
# the real historical defect: Notes unquoted, so its comma splits the record into 7 fields
printf 'Req,Method,Artifact,Gate,Status,Notes\r\nFR-X,m,a,P0,done,a note, with a comma\r\n' > "$tmp/bad.csv"
if check "$tmp/bad.csv" >/dev/null; then
  echo "gate-verification: FAIL — self-test: an UNQUOTED-Notes record (7 fields) was ACCEPTED." >&2
  echo "                   The gate is BLIND — a green run would prove nothing." >&2
  exit 1
fi

# a 6-field record whose Artifact held an unquoted comma: Gate/Status shift one column left
printf 'Req,Method,Artifact,Gate,Status,Notes\r\nFR-X,m,src/{a,b}.lisp,P2,"partial,a note"\r\n' > "$tmp/shifted.csv"
if check "$tmp/shifted.csv" >/dev/null; then
  echo "gate-verification: FAIL — self-test: a SHIFTED-COLUMN record (6 fields, Gate in Artifact) was ACCEPTED." >&2
  exit 1
fi

# ---- 1. THE CHECK ----
if ! check "$CSV"; then
  echo "gate-verification: FAIL — $CSV is not well-formed CSV (see above)." >&2
  echo "                   Quote any field containing a comma; keep the file CRLF." >&2
  exit 1
fi
n="$(python3 -c "import csv;print(len(list(csv.reader(open('$CSV',newline='',encoding='utf-8')))))")"
echo "gate-verification: PASS — $n records, every one exactly 6 fields with a valid Gate token (and the gate is proven able to fail)."
