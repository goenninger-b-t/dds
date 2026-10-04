#!/usr/bin/env bash
# ADR 0128: run a bounded Lisp entry point, keep its output in a log written by THIS run only, and exit with
# the verdict of scripts/test-baseline.py on that log (never the Lisp's own status).
#
#   judged-run.sh LOG-DIR STEM CHECKER-ARG... -- COMMAND...
#
# The log is a fresh file `LOG-DIR/neodds-STEM.XXXXXX.log` created by mktemp, so the verdict can never be
# about a log an earlier run left behind (a read-only or foreign-owned file of the same name, a full disk:
# each used to leave the old passing log in place and the gate judged it). COMMAND's output is tee'd to it;
# if mktemp or tee fails, the run is not judged and the exit status is 1. Otherwise the checker is called as
#   python3 scripts/test-baseline.py CHECKER-ARG... LOG COMMAND-EXIT-STATUS
# and its exit status (0 pass, 1 fail, 3 NOT A GATE RUN) is this script's.
set -u
if [ $# -lt 4 ]; then
  echo "usage: $0 LOG-DIR STEM CHECKER-ARG... -- COMMAND..." >&2
  exit 2
fi
dir=$1 stem=$2
shift 2
check=()
while [ $# -gt 0 ] && [ "$1" != "--" ]; do check+=("$1"); shift; done
if [ $# -lt 2 ] || [ ${#check[@]} -eq 0 ]; then
  echo "usage: $0 LOG-DIR STEM CHECKER-ARG... -- COMMAND..." >&2
  exit 2
fi
shift   # the --
here=$(cd "$(dirname "$0")" && pwd)

log=$(mktemp "$dir/neodds-$stem.XXXXXX.log") || {
  echo "judged-run: cannot create a fresh log in $dir: the run is not judged (ADR 0128)" >&2
  exit 1
}
echo "judged-run: $stem, log $log"
"$@" 2>&1 | tee "$log"
st=("${PIPESTATUS[@]}")
rc=${st[0]} trc=${st[1]}
if [ "$trc" -ne 0 ]; then
  echo "judged-run: tee exited $trc: the log $log is incomplete or was not written; the run is not judged (ADR 0128)" >&2
  exit 1
fi
echo "judged-run: the command exited $rc; verdict (log $log):"
python3 "$here/test-baseline.py" "${check[@]}" "$log" "$rc"
