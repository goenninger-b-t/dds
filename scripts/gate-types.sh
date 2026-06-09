#!/usr/bin/env bash
# gate-types (REQUIREMENTS FR-LANG-8). Every top-level function MUST carry a full
# (function (<args>) <ret>) type contract. Two compliant forms:
#   (defun* NAME LAMBDA-LIST SIGNATURE DOCSTRING ...) — the preferred form (dds.lang);
#     it EMITS the ftype declaim + per-param declares, so it is contracted by construction
#     and needs no separate declaim. Counted as satisfied here.
#   (defun NAME ...) — must be paired with a single-line
#     (declaim (ftype (function (<args>) <ret>) NAME)) in the same file (keep it on ONE
#     line so this lexical check is reliable).
# Out of scope: defmacro (not a function) and defstruct accessors (typed via slot :type).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

fail=0
missing=0
total=0
while IFS= read -r f; do
  # defun*: self-contracting (the macro emits the ftype declaim) — counted, never flagged.
  while IFS= read -r _starname; do
    [[ -z "$_starname" ]] && continue
    total=$((total+1))
  done < <(grep -oE '^\(defun\* +[^ (]+' "$f")
  # plain defun: require a single-line ftype declaim for the same name.
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
