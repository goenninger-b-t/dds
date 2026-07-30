#!/usr/bin/env bash
# gate-nlx — A NON-LOCAL EXIT MUST NOT CROSS A LOCK FROM INSIDE A CONDITION HANDLER (ADR 0098).
#
# THE DEFECT, measured at 16 B/call on SBCL x86_64 and worth restating because it is invisible:
#
#     (dds.pal:with-lock (...)             ; expands to UNWIND-PROTECT
#       (handler-case                       ; installs a handler CLOSURE
#           (... (return-from F nil) ...)   ; <- targets a block OUTSIDE the unwind
#         (error () nil)))
#
# The exit must be able to run through the unwind, so the handler closure loses dynamic extent and is
# heap-allocated AT FUNCTION ENTRY — charged to EVERY call, including every steady-state call that never
# enters the branch and never signals. Nine copies of that shape made four DDS-Security zero-alloc gates
# red (ADR 0098), and the fix in every case was a GUARD or a FLAG instead of the early exit.
#
# WHY THIS IS A FORM WALKER AND NOT A GREP, which is the whole point of the gate:
# NO SINGLE CONSTRUCT IS THE DEFECT. `with-lock` alone measures 0.0000 B/call; `handler-case` alone 0.0000;
# `handler-case` containing a `return-from` alone 0.0000. ONLY THE NESTING COSTS — and nesting is exactly
# what a regex cannot see. scripts/nlx-scan.py parses the forms and walks a frame stack.
#
# The scanner LEARNS this repo's own lock/borrow macros by finding every defmacro whose expansion contains
# UNWIND-PROTECT (and likewise for HANDLER-CASE), to a fixpoint — so a new `with-` macro is covered the day
# it is written, not the day someone remembers to edit a list.
#
# TWO TIERS, the shape gate-nocond established because a permanently-red gate is an ignored gate:
#   STRICT   — the per-sample engine. MUST be zero. A new violation there fails the build.
#   RATCHET  — the rest (TypeObject/TypeLookup parsing, DARE crypto primitives: cold paths where 16 B once
#              is not a per-sample cost). The count may only go DOWN (bench/nlx-ceiling.txt).
#
# SELF-FALSIFYING (the standing rule: never trust a gate you have not seen go red). It plants a violating
# form and asserts REJECT, and plants two near-misses — a handler-case + return-from with NO lock, and a
# lock + handler-case with NO exit — and asserts ACCEPT. A gate that cannot tell those apart is not
# measuring nesting, it is measuring the presence of tokens.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"
SCAN="python3 scripts/nlx-scan.py"
CEIL_FILE="bench/nlx-ceiling.txt"

RATCHET_DIRS=(src/dds-types src/dds-dare)
STRICT_DIRS=()
while IFS= read -r d; do
  skip=0
  for r in "${RATCHET_DIRS[@]}"; do [[ "$d" == "$r" ]] && skip=1; done
  [[ $skip -eq 0 ]] && STRICT_DIRS+=("$d")
done < <(find src -mindepth 1 -maxdepth 1 -type d | sort)

# ---------------------------------------------------------------- falsification, BEFORE trusting a result
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

cat > "$TMP/violation.lisp" <<'LISP'
(defun* f (node) (function (t) t) "doc"
  (dds.pal:with-lock ((lock node))
    (handler-case (progn (when node (return-from f nil)) t)
      (error () nil))))
LISP
cat > "$TMP/nearmiss-nolock.lisp" <<'LISP'
(defun* g (node) (function (t) t) "doc"
  (handler-case (progn (when node (return-from g nil)) t)
    (error () nil)))
LISP
cat > "$TMP/nearmiss-noexit.lisp" <<'LISP'
(defun* h (node) (function (t) t) "doc"
  (dds.pal:with-lock ((lock node))
    (handler-case (progn (when node nil) t)
      (error () nil))))
LISP

if $SCAN "$TMP/violation.lisp" >/dev/null 2>&1; then
  echo "gate-nlx: FAIL — the scanner ACCEPTED a planted violation. It is not measuring anything." >&2
  exit 1
fi
for nm in nearmiss-nolock nearmiss-noexit; do
  if ! $SCAN "$TMP/$nm.lisp" >/dev/null 2>&1; then
    echo "gate-nlx: FAIL — the scanner REJECTED the near-miss '$nm', which is CORRECT code." >&2
    echo "          It is matching tokens, not nesting; a false-positive gate gets disabled." >&2
    exit 1
  fi
done
echo "gate-nlx: falsified — rejects the planted nesting, accepts both near-misses."

# ---------------------------------------------------------------- tier 1: STRICT
if ! $SCAN "${STRICT_DIRS[@]}" > "$TMP/strict.out" 2>&1; then
  echo "gate-nlx: FAIL — a non-local exit crosses a lock from inside a handler, on a per-sample path:" >&2
  sed 's/^/  /' "$TMP/strict.out" >&2
  echo "          Use a GUARD or a FLAG and raise the exit OUTSIDE the unwind (ADR 0098 §5)." >&2
  exit 1
fi

# ---------------------------------------------------------------- tier 2: RATCHET
$SCAN "${RATCHET_DIRS[@]}" > "$TMP/ratchet.out" 2>&1
COUNT="$(grep -cE '^  src/' "$TMP/ratchet.out" || true)"
CEIL="$(tr -d '[:space:]' < "$CEIL_FILE" 2>/dev/null || echo 0)"
[[ -z "$CEIL" ]] && CEIL=0

if [[ "$COUNT" -gt "$CEIL" ]]; then
  echo "gate-nlx: FAIL — ratcheted count ROSE to ${COUNT} (ceiling ${CEIL}):" >&2
  grep -E '^  src/' "$TMP/ratchet.out" >&2 || true
  exit 1
fi
if [[ "$COUNT" -lt "$CEIL" ]]; then
  echo "gate-nlx: FAIL — you REMOVED $(( CEIL - COUNT )). Bank it: echo ${COUNT} > ${CEIL_FILE}" >&2
  echo "          A ceiling that is never lowered stops constraining anything. The ratchet only moves DOWN." >&2
  exit 1
fi

echo "gate-nlx: PASS — the per-sample engine is clean; ${COUNT} to go in the ratcheted set."
if [[ "$COUNT" -gt 0 ]]; then
  echo "gate-nlx: DEBT — ${COUNT} exit(s) crossing a lock in cold paths (16 B once, not per sample):"
  grep -E '^  src/' "$TMP/ratchet.out" || true
fi
