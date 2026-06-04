#!/usr/bin/env bash
# gate-types (REQUIREMENTS FR-LANG-8). Every top-level defun MUST have a
# single-line (declaim (ftype (function (<args>) <ret>) NAME)) in the same file.
# Out of scope: defmacro (not a function) and defstruct accessors (typed via slot
# :type). Keep each ftype declaim on ONE line so this lexical check is reliable.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

fail=0
missing=0
total=0
while IFS= read -r f; do
  while IFS= read -r name; do
    [[ -z "$name" ]] && continue
    total=$((total+1))
    esc=$(printf '%s' "$name" | sed 's/[.[*+?^$(){}|\\]/\\&/g')
    if ! grep -qE "\(declaim \(ftype \(function .*\) ${esc}\)\)" "$f"; then
      echo "FR-LANG-8: ${f#src/} : '${name}' has no ftype declaration"
      missing=$((missing+1))
      fail=1
    fi
  done < <(grep -oE '^\(defun +[^ (]+' "$f" | sed -E 's/^\(defun +//')
done < <(find src -name '*.lisp' | sort)

if [[ "$fail" -ne 0 ]]; then
  echo "gate-types: FAIL — ${missing}/${total} defun(s) missing an ftype."
  exit 1
fi
echo "gate-types: PASS — all ${total} defun(s) are ftype-declared."
