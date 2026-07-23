#!/usr/bin/env bash
# M0 Clasp launcher: pins the boehmprecise binary, loads Quicklisp, points
# ASDF at the repo tree, then evaluates the forms passed as arguments.
set -euo pipefail

CLASP_BIN="${CLASP_BIN:-$HOME/gbt Dropbox/gbt/projects/clasp/build/boehmprecise/clasp}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ ! -x "$CLASP_BIN" ]]; then
  echo "with-clasp: clasp binary not found/executable: $CLASP_BIN" >&2
  exit 127
fi

export CL_SOURCE_REGISTRY="${REPO}//:"
. "${REPO}/scripts/lisp-cache-env.sh"

exec "$CLASP_BIN" --norc --non-interactive \
  --eval "(load (merge-pathnames \"quicklisp/setup.lisp\" (user-homedir-pathname)))" \
  "$@"
