#!/usr/bin/env bash
# gate-mem — the NFR-MEM ALLOCATION RATCHET (0 bytes/sample steady state; ADR 0062).
#
# WHY THIS EXISTS. `make mem` (run-mem-test) measures the CODEC in isolation — serialize / deserialize /
# AEAD — and correctly reports ~0 B/iter. It is a real assertion and it would fail if the codec
# regressed. But it is NOT the per-sample budget the contract credits it with ("assert hot-path workload
# runs entirely from the static arena"): it measures no workload. That is why `make mem` was GREEN while
# the live DCPS path allocated ~3.9 KB per sample — the number that drives the peer's GC and owns the
# whole ~10 ms latency tail. A gate is only as honest as its workload.
#
# NFR-MEM's target is ZERO. We are not at zero. A gate that fails at "anything above zero" would be
# permanently red and therefore ignored — so this is a RATCHET, which is the honest enforcement:
#
#   measured > CEILING            -> FAIL. Allocation REGRESSED. This is the regression guard.
#   measured < CEILING * 0.90     -> FAIL. You IMPROVED it — now LOWER THE CEILING and commit that.
#   otherwise                     -> PASS.
#
# Failing on improvement is not pedantry: a ceiling that is never lowered drifts away from reality and
# silently stops constraining anything — the same slow death as a gate that cannot fail. The ratchet only
# moves DOWN, and the ceiling file is the record of how far NFR-MEM has actually got.
#
# The ceiling lives in bench/mem-ceiling.txt — one integer, in bytes/sample. It is REVIEWABLE IN A DIFF,
# on purpose: lowering it is a claim about the system, and it should be seen.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

CEILING_FILE=bench/mem-ceiling.txt
[[ -r "$CEILING_FILE" ]] || { echo "gate-mem: FAIL — missing $CEILING_FILE" >&2; exit 1; }
CEILING="$(tr -d '[:space:]' < "$CEILING_FILE")"
[[ "$CEILING" =~ ^[0-9]+$ ]] || { echo "gate-mem: FAIL — $CEILING_FILE must be one integer (bytes/sample), got '$CEILING'" >&2; exit 1; }

# SBCL only: dds.pal:bytes-consed returns 0 on Clasp, so a Clasp run would measure NOTHING and "pass"
# vacuously. Refuse rather than pretend (the documented NFR-PORT gap).
LISP="${LISP:-./scripts/with-sbcl.sh}"
case "$LISP" in
  *clasp*) echo "gate-mem: FAIL — Clasp cannot run this gate (dds.pal:bytes-consed returns 0 there, so it" >&2
           echo "          would measure nothing and pass vacuously). Run with LISP=./scripts/with-sbcl.sh." >&2
           exit 1 ;;
esac

out="$("$LISP" \
  --eval '(asdf:load-system :dds-bench)' \
  --eval '(handler-case
              (let ((b (dds.bench:mem-per-sample)))
                (format t "~&MEASURED ~,1f~%" b))
            (error (e) (format t "~&MEASURE-FAILED ~a~%" e)))' \
  --eval '(uiop:quit 0)' 2>&1)"

if grep -q "MEASURE-FAILED" <<<"$out"; then
  grep "MEASURE-FAILED" <<<"$out" >&2
  echo "gate-mem: FAIL — the measurement itself did not run." >&2
  exit 1
fi
MEASURED="$(grep -o 'MEASURED [0-9.]*' <<<"$out" | awk '{print $2}')"
[[ -n "$MEASURED" ]] || { echo "gate-mem: FAIL — no measurement produced." >&2; printf '%s\n' "$out" | tail -5 >&2; exit 1; }

LOWER_AT="$(awk -v c="$CEILING" 'BEGIN{printf "%.0f", c*0.90}')"

awk -v m="$MEASURED" -v c="$CEILING" -v lo="$LOWER_AT" '
BEGIN {
  printf "gate-mem: end-to-end DCPS allocation = %.1f bytes/sample (ceiling %d, NFR-MEM target 0)\n", m, c;
  if (m > c) {
    printf "gate-mem: FAIL — ALLOCATION REGRESSED. %.1f > ceiling %d.\n", m, c > "/dev/stderr";
    print  "          Every byte here feeds the PEER'"'"'s GC, which owns the whole ~10 ms tail (ADR 0062)." > "/dev/stderr";
    exit 1;
  }
  if (m < lo) {
    printf "gate-mem: FAIL — you IMPROVED it (%.1f, well under the %d ceiling). LOWER THE CEILING:\n", m, c > "/dev/stderr";
    printf "          echo %.0f > bench/mem-ceiling.txt   # and commit it\n", m > "/dev/stderr";
    print  "          A ceiling that is never lowered stops constraining anything. The ratchet only moves DOWN." > "/dev/stderr";
    exit 1;
  }
  printf "gate-mem: PASS — no regression. Still %.0f bytes/sample above the NFR-MEM target of ZERO.\n", m;
  exit 0;
}'
