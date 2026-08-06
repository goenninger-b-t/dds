#!/usr/bin/env bash
# hotpath-purity-gate (REQUIREMENTS NFR-CLOS + NFR-MEM, IMPLEMENTATION-PLAN §8).
#
# TWO checks over the designated hot-path files:
#
#   1. CLOS PURITY (NFR-CLOS) — no defclass/defgeneric/defmethod/make-instance.
#
#   2. ALLOCATION PURITY (NFR-MEM) — no UNJUSTIFIED heap allocation. This is the check the gate was
#      SUPPOSED to make from the start ("fail if CLOS dispatch / per-sample alloc in hot-path packages",
#      operating contract §6) and never did: it scanned for CLOS only. message.lisp sat in the
#      certified-clean list while parse-header allocated a 12-octet guidPrefix on EVERY inbound datagram
#      (fixed 1801f3c) — the gate could not see it, because it was not looking.
#
# Allocation purity is enforced by ANNOTATION, not by prohibition: a hot-path file may allocate, but
# every allocating form MUST carry an explicit marker justifying it —
#
#     ...(make-array 12 ...)   ; HOTPATH-ALLOC(COLD): <why this is not on the per-sample path>
#
# on the same line or the line immediately above. Classes:
#
#     LOAD-TIME   evaluated once at load (a defparameter/defconstant initform)
#     COLD        not on the per-sample/per-datagram path (setup, teardown, error, test-only)
#     ERROR-PATH  only on the way to signalling
#     TEST        test-only helper
#     TRACKED     REAL per-sample/per-datagram allocation, KNOWN DEBT, being driven to zero (ADR 0062)
#
# An unmarked allocating form FAILS the build. That is the regression guard: a NEW allocation cannot
# enter a hot-path file unnoticed. The TRACKED set is PRINTED on every run, so the remaining NFR-MEM
# debt is enumerated in the open instead of hiding in a profile nobody reruns.
#
# --self-test falsifies the gate (the make-corpus lesson): it plants an unmarked allocation and asserts
# the scan REJECTS it. Run automatically before the real scan; a gate never proven able to fail proves
# nothing.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

HOTPATH_FILES=(
  "src/dds-core/buffer.lisp"
  "src/dds-cdr/cdr.lisp"
  "src/dds-cdr/primitives.lisp"
  "src/dds-rtps/history.lisp"
  "src/dds-rtps/message.lisp"
  "src/dds-xport/shmem.lisp"
  "src/dds-xport/zerocopy-pool.lisp"
  "src/dds-disc/flow-control.lisp"
  "src/dds-gen/runtime.lisp"
)
# Generated-codec output dir is scanned too, once it exists.
if [[ -d src/dds-gen/generated ]]; then
  while IFS= read -r f; do HOTPATH_FILES+=("$f"); done \
    < <(find src/dds-gen/generated -name '*.lisp')
fi

CLOS_PATTERN='[(](defclass|defgeneric|defmethod|make-instance)[[:space:](]'
ALLOC_PATTERN='[(](make-array|make-string|make-list|make-sequence|make-hash-table|format nil|concatenate|copy-seq|copy-list|copy-tree|subseq|append|mapcar|remove-if|remove-if-not|coerce)[[:space:](]'
MARKER='HOTPATH-ALLOC'

# scan_allocs <file> -> prints "file:line: <text>" for every UNMARKED allocating form.
# A form is marked if the marker is on its own line or on the line immediately above.
scan_allocs() {
  local f="$1"
  awk -v pat="$ALLOC_PATTERN" -v marker="$MARKER" '
    { lines[NR] = $0 }
    END {
      for (i = 1; i <= NR; i++) {
        if (lines[i] ~ pat) {
          if (lines[i] ~ marker)            continue   # justified on the line
          if (i > 1 && lines[i-1] ~ marker) continue   # justified on the line above
          printf "%s:%d: %s\n", FILENAME, i, lines[i]
        }
      }
    }' "$f"
}

# ---- 0. FALSIFICATION: the scan must REJECT an unmarked allocation. ----
selftest_dir="$(mktemp -d)"; trap 'rm -rf "$selftest_dir"' EXIT
cat > "$selftest_dir/canary.lisp" <<'EOF'
(defun* canary-marked ()
  (make-array 4 :element-type '(unsigned-byte 8)))  ; HOTPATH-ALLOC(TEST): must be ACCEPTED
(defun* canary-unmarked ()
  (make-array 4 :element-type '(unsigned-byte 8)))
EOF
# The canary has TWO allocating forms: one marked (line 2, must be ACCEPTED), one unmarked (line 4,
# must be REJECTED). Exactly one hit, and it must be the unmarked one on line 4.
hits="$(scan_allocs "$selftest_dir/canary.lisp" || true)"
n="$(printf '%s' "$hits" | grep -c . || true)"
if [[ "$n" -ne 1 || "$hits" != *":4:"* ]]; then
  echo "gate-hotpath: FAIL — self-test: the allocation scan must report EXACTLY the unmarked form" >&2
  echo "              (canary line 4) and accept the marked one (line 2). It reported ${n} hit(s):" >&2
  printf '%s\n' "$hits" >&2
  echo "              The gate is BLIND — a green run would prove nothing." >&2
  exit 1
fi

violations=0

# ---- 1. CLOS purity ----
for f in "${HOTPATH_FILES[@]}"; do
  [[ -f "$f" ]] || continue
  if grep -nEH "$CLOS_PATTERN" "$f"; then
    echo "gate-hotpath: ^^ CLOS dispatch/instantiation in a hot-path file (NFR-CLOS)." >&2
    violations=1
  fi
done

# ---- 2. Allocation purity ----
for f in "${HOTPATH_FILES[@]}"; do
  [[ -f "$f" ]] || continue
  unmarked="$(scan_allocs "$f")"
  if [[ -n "$unmarked" ]]; then
    echo "$unmarked"
    violations=1
  fi
done

if [[ "$violations" -ne 0 ]]; then
  echo "gate-hotpath: FAIL — see above. An allocating form in a hot-path file must carry a" >&2
  echo "              '; ${MARKER}(CLASS): reason' marker (LOAD-TIME|COLD|ERROR-PATH|TEST|TRACKED)." >&2
  exit 1
fi

# ---- 3. Report the TRACKED debt (NFR-MEM), so it cannot hide. ----
tracked=0
for f in "${HOTPATH_FILES[@]}"; do
  [[ -f "$f" ]] || continue
  n="$(grep -cE "${MARKER}\(TRACKED\)" "$f" || true)"
  tracked=$((tracked + n))
done

echo "gate-hotpath: PASS — ${#HOTPATH_FILES[@]} hot-path file(s): CLOS-free, every allocation justified."
if [[ "$tracked" -gt 0 ]]; then
  echo "gate-hotpath: NFR-MEM DEBT — ${tracked} TRACKED per-sample/per-datagram allocation(s) remain (ADR 0062):"
  for f in "${HOTPATH_FILES[@]}"; do
    [[ -f "$f" ]] || continue
    grep -nE "${MARKER}\(TRACKED\)" "$f" | sed "s|^|  ${f}:|" || true
  done
fi
