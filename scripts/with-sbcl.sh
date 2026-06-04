#!/usr/bin/env bash
# M0 SBCL launcher: loads Quicklisp, points ASDF at the repo tree, then
# evaluates the forms passed as arguments. Mirrors scripts/with-clasp.sh.
set -euo pipefail

SBCL_BIN="${SBCL_BIN:-sbcl}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! command -v "$SBCL_BIN" >/dev/null 2>&1; then
  echo "with-sbcl: sbcl not found on PATH (set SBCL_BIN)" >&2
  exit 127
fi

export CL_SOURCE_REGISTRY="${REPO}//:"

exec "$SBCL_BIN" --noinform --no-sysinit --no-userinit --non-interactive \
  --eval "(load (merge-pathnames \"quicklisp/setup.lisp\" (user-homedir-pathname)))" \
  "$@"
