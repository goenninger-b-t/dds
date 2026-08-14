#!/usr/bin/env bash
# AllegroCL launcher: loads Quicklisp, points ASDF at the repo tree, then evaluates the forms passed as
# arguments. Mirrors scripts/with-sbcl.sh and scripts/with-clasp.sh — and closes the follow-up ADR 0004
# named in 2026-06-04 ("scripts/with-allegro.sh remains a tracked follow-up").
#
# ⛔ IT ACCEPTS SBCL/CLASP SYNTAX AND TRANSLATES. Callers — the Makefile above all — pass `--eval FORM`,
# because that is what the other two implementations take. AllegroCL evaluates with `-e FORM` and has no
# `--eval` at all, so this script rewrites the argument vector rather than making every caller branch.
# That keeps ONE spelling in the Makefile and confines the divergence to the launcher, exactly as
# dds.pal:lisp-eval-command confines it for CHILD processes (ADR 0116).
#
# ⚠️ `-batch` is what makes AllegroCL non-interactive; there is no `--non-interactive`. Without it a form
# that errors drops into a debugger and the run hangs instead of failing.
#
# `-q` IS passed. An earlier version omitted it on the theory that the init file carries a site
# ASDF/Quicklisp bootstrap worth keeping. Measured on the CI host and false: `(find-package :ql)` and
# `(find-package :asdf)` are both NIL after startup WITH AND WITHOUT `-q` — the bootstrap does not survive
# `-batch`, and this script loads Quicklisp itself anyway. What running the init file DOES do is start a
# swank listener on a fixed port 4008, so a second concurrent run (or one leftover process) aborts startup
# with "Local socket address already in use (errno 98)". `-q` removes a reentrancy hazard and costs nothing.
set -euo pipefail

# ALLEGRO_BIN is accepted because the not-found message below names it; ALISP_BIN wins if both are set.
ALISP_BIN="${ALISP_BIN:-${ALLEGRO_BIN:-alisp}}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! command -v "$ALISP_BIN" >/dev/null 2>&1; then
  # A login shell is usually required: on the CI host alisp lives in /opt/common-lisp/allegrocl/11.0/
  # and is NOT on a non-login shell's PATH, so a bare `ssh host alisp` reports "command not found" and
  # reads exactly like a missing installation. Say so, rather than let the caller draw that conclusion.
  echo "with-allegro: '$ALISP_BIN' not found on PATH." >&2
  echo "  AllegroCL is often absent from a NON-LOGIN shell's PATH — try a login shell (bash -lc)," >&2
  echo "  or set ALLEGRO_BIN/ALISP_BIN to the absolute path (e.g. /opt/common-lisp/allegrocl/11.0/alisp)." >&2
  exit 127
fi

export CL_SOURCE_REGISTRY="${REPO}//:"
. "${REPO}/scripts/lisp-cache-env.sh"

# Translate the shared calling convention into AllegroCL's. `--eval FORM` -> `-e FORM`; anything else is
# passed through untouched so a caller can still hand this script a file with -L.
args=()
while [ $# -gt 0 ]; do
  case "$1" in
    --eval) args+=(-e "$2"); shift 2 ;;
    *)      args+=("$1");    shift   ;;
  esac
done

# PROBE both locations rather than LOAD blindly: ~/quicklisp is not universal across the Allegro hosts
# (192.168.2.113 carries only the site path), and CL:LOAD defaults :if-does-not-exist to true, so a bare
# load aborts startup with a FILE-ERROR before any caller form runs.
exec "$ALISP_BIN" -q -batch \
  -e "(let ((p (or (probe-file (merge-pathnames \"quicklisp/setup.lisp\" (user-homedir-pathname))) (probe-file \"/opt/common-lisp/quicklisp/setup.lisp\")))) (when p (load p)))" \
  "${args[@]}"
