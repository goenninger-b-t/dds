#!/usr/bin/env bash
# hotpath-purity-gate (REQUIREMENTS NFR-CLOS, IMPLEMENTATION-PLAN §8).
# Fails the build if CLOS dispatch or per-sample CLOS instantiation appears in a
# designated hot-path source file. M0 uses a coarse lexical scan; an AST-aware
# check replaces it once the generator emits codecs (M1).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

HOTPATH_FILES=(
  "src/dds-core/buffer.lisp"
  "src/dds-cdr/cdr.lisp"
  "src/dds-cdr/primitives.lisp"
  "src/dds-rtps/history.lisp"
  "src/dds-rtps/message.lisp"
)
# Generated-codec output dir is scanned too, once it exists.
if [[ -d src/dds-gen/generated ]]; then
  while IFS= read -r f; do HOTPATH_FILES+=("$f"); done \
    < <(find src/dds-gen/generated -name '*.lisp')
fi

PATTERN='\((defclass|defgeneric|defmethod|make-instance)[[:space:](]'
violations=0
for f in "${HOTPATH_FILES[@]}"; do
  [[ -f "$f" ]] || continue
  if grep -nEH "$PATTERN" "$f"; then
    violations=1
  fi
done

if [[ "$violations" -ne 0 ]]; then
  echo "gate-hotpath: FAIL — CLOS dispatch/instantiation found in a hot-path file." >&2
  exit 1
fi
echo "gate-hotpath: PASS — ${#HOTPATH_FILES[@]} hot-path file(s) clean."
