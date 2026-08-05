#!/usr/bin/env bash
# M0 Clasp launcher: pins the clasp binary, loads Quicklisp, points
# ASDF at the repo tree, then evaluates the forms passed as arguments.
set -euo pipefail

# First existing candidate wins; CLASP_BIN overrides everything.
CLASP_CANDIDATES=(
  "/opt/clasp/bin/clasp"
  "$HOME/gbt Dropbox/gbt/projects/clasp/build/boehmprecise/clasp"
)
CLASP_BIN="${CLASP_BIN:-}"
if [[ -z "$CLASP_BIN" ]]; then
  for c in "${CLASP_CANDIDATES[@]}"; do
    if [[ -x "$c" ]]; then CLASP_BIN="$c"; break; fi
  done
fi
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ -z "$CLASP_BIN" || ! -x "$CLASP_BIN" ]]; then
  echo "with-clasp: no clasp binary found; tried CLASP_BIN and: ${CLASP_CANDIDATES[*]}" >&2
  exit 127
fi

export CL_SOURCE_REGISTRY="${REPO}//:"
. "${REPO}/scripts/lisp-cache-env.sh"

exec "$CLASP_BIN" --norc --non-interactive \
  --eval "(load (merge-pathnames \"quicklisp/setup.lisp\" (user-homedir-pathname)))" \
  "$@"
