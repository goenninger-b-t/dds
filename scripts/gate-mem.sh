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
# The ceilings live in bench/mem-ceiling.txt — one row PER ARCH, with TWO ceilings on it:
# "<arch> <ceiling-COPY> <ceiling-RETURN>". REVIEWABLE IN A DIFF, on purpose: lowering one is a claim
# about the system, and it should be seen.
#
# TWO ARMS SINCE ADR 0093 (2026-07-28), because there are now two honest workloads:
#
#   COPY   — the application takes samples and DROPS them. The legacy arm; every historical ceiling row
#            refers to it, so it stays comparable across the whole campaign.
#   RETURN — the application RETURN-LOANs each taken sample, honouring the ADR 0093 loan contract, so the
#            reader recycles its delivery wrappers. THIS IS THE ONLY ARM IN WHICH THE RECYCLING CAN BE
#            SEEN AT ALL: measuring only COPY would leave the −171 B/sample slice-1 win permanently
#            unratcheted and free to silently regress. A gate is only as honest as its workload — and
#            after ADR 0093, "the workload a real application runs" includes giving the sample back.
#
# An arch whose RETURN ceiling is `-` (not yet measured there) still gets MEASURED and REPORTED, with the
# row to paste in — it is simply not ratcheted. That way an unmeasured arch prints the number it needs
# rather than going red, and nobody is tempted to predict it from the other arch (they diverge: ADR 0087
# −82.4 vs −125.4, ADR 0088 −27.7 vs −72.9).
#
# ⚠️ EACH ARM RUNS IN ITS OWN PROCESS ON ITS OWN DOMAIN, and that is load-bearing, not tidiness. Two arms
# sharing one image and one domain DISCOVER EACH OTHER: the second arm pays for the first's participants
# and reads high. Measured directly while developing ADR 0093 slice 1 — three arms on one domain put the
# pooled arm at 2786 B/sample against a 1739 baseline, a 1000 B "regression" from a change that only
# REMOVES allocation, and it was diagnosed as a code defect before the harness was suspected. Owner
# standing order: concurrently running tests MUST use different DDS domain IDs.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

# THE WORKLOAD SIZE IS PART OF THE GATE. mem-per-sample defaults to 60000 samples, and this gate deliberately
# takes that default rather than pinning its own: the measured window carries a FIXED ~65 KB per-run allocation
# occurring a varying 0-3 times, so it lands as a quantum of 65700/samples B/sample. At the original 3000 that
# was ~22 B and one UNCHANGED arm measured 1791/1813/1835/1857 — a ~65 B spread, WIDER than a typical slice's
# ~35 B win, so this gate could not resolve the very changes it exists to guard. At 60000 the spread is ~0.4 B.
# Changing `samples` RE-BASELINES both rows of the ceiling file (the workload is not perfectly scale-free) —
# see mem-per-sample's docstring and the header of bench/mem-ceiling.txt before touching it.
#
# PER-ARCHITECTURE ceiling. SBCL's per-sample allocation differs materially by arch (measured: arm64 3560,
# x86_64 4674 — ~31% more), so a single shared number cannot work: at the x86_64 value the arm64 ratchet
# would never bite, and at the arm64 value x86_64 is permanently red. Same divergence flipped the FlatData
# vtable-vs-classic guard.
CEILING_FILE=bench/mem-ceiling.txt
[[ -r "$CEILING_FILE" ]] || { echo "gate-mem: FAIL — missing $CEILING_FILE" >&2; exit 1; }
ARCH="$(uname -m)"
ROW="$(awk -v a="$ARCH" '$1==a {print; exit}' "$CEILING_FILE")"
[[ -n "$ROW" ]] || {
  echo "gate-mem: FAIL — no ceiling row for arch '$ARCH' in $CEILING_FILE." >&2
  echo "          Add a row: '$ARCH <copy-bytes> <return-bytes-or-dash>'. Do NOT reuse another arch's" >&2
  echo "          numbers — they diverge materially and unpredictably." >&2
  exit 1; }
CEILING_COPY="$(awk '{print $2}'   <<<"$ROW")"
CEILING_RETURN="$(awk '{print $3}' <<<"$ROW")"
CEILING_INTO="$(awk '{print $4}'   <<<"$ROW")"
[[ -n "$CEILING_RETURN" ]] || CEILING_RETURN="-"     # a legacy two-field row = RETURN not yet measured
[[ -n "$CEILING_INTO" ]]   || CEILING_INTO="-"       # a three-field row  = INTO   not yet measured
[[ "$CEILING_COPY" =~ ^[0-9]+$ ]] || {
  echo "gate-mem: FAIL — arch '$ARCH' has no numeric COPY ceiling in $CEILING_FILE (got '$CEILING_COPY')." >&2
  exit 1; }

# ⚠️ THE EMPTY->DASH DEFAULTS ABOVE ARE LOAD-BEARING, AND SO IS THIS GUARD. Without the default, a row that
# does not yet carry the column yields an EMPTY ceiling, awk coerces it to 0, and the arm fails with a bogus
# "REGRESSED ... > ceiling 0" — a red that says nothing true. Without the guard, a typo in the column ('55O'
# for '550', a stray comma) is not a number and not a dash: awk's coercion then decides the arm's fate
# silently, and the likeliest outcome is a permanently-GREEN no-op, which is the one failure mode a ratchet
# can never notice about itself. A malformed column must stop the gate, loudly.
check_ceiling () {   # $1 = column label, $2 = the value read from the row
  [[ "$2" =~ ^([0-9]+|-)$ ]] || {
    echo "gate-mem: FAIL — arch '$ARCH' has a malformed $1 ceiling in $CEILING_FILE (got '$2')." >&2
    echo "          A column is a whole number of bytes, or '-' meaning not yet measured on this arch." >&2
    exit 1; }
}
check_ceiling RETURN "$CEILING_RETURN"
check_ceiling INTO   "$CEILING_INTO"

# SBCL only: dds.pal:bytes-consed returns 0 on Clasp, so a Clasp run would measure NOTHING and "pass"
# vacuously. Refuse rather than pretend (the documented NFR-PORT gap).
LISP="${LISP:-./scripts/with-sbcl.sh}"
case "$LISP" in
  *clasp*) echo "gate-mem: FAIL — Clasp cannot run this gate (dds.pal:bytes-consed returns 0 there, so it" >&2
           echo "          would measure nothing and pass vacuously). Run with LISP=./scripts/with-sbcl.sh." >&2
           exit 1 ;;
esac

# One arm = one FRESH PROCESS on its OWN domain (see the header: sharing either lets the arms discover
# each other and reads high). $1 = the mem-per-sample keyword arguments that DEFINE the arm, $2 = domain.
measure_arm () {
  local kwargs="$1" dom="$2" out measured
  out="$("$LISP" \
    --eval '(asdf:load-system :dds-bench)' \
    --eval "(handler-case
                 (format t \"~&MEASURED ~,1f~%\"
                         (dds.bench:mem-per-sample :domain $dom $kwargs))
               (error (e) (format t \"~&MEASURE-FAILED ~a~%\" e)))" \
    --eval '(uiop:quit 0)' 2>&1)"
  if grep -q "MEASURE-FAILED" <<<"$out"; then
    grep "MEASURE-FAILED" <<<"$out" >&2
    return 1
  fi
  measured="$(grep -o 'MEASURED [0-9.]*' <<<"$out" | awk '{print $2}')"
  [[ -n "$measured" ]] || { printf '%s\n' "$out" | tail -5 >&2; return 1; }
  printf '%s\n' "$measured"
}

# Ratchet one arm. $1 label, $2 measured, $3 ceiling (numeric or "-"), $4 the ceiling-file column name.
ratchet () {
  awk -v label="$1" -v m="$2" -v c="$3" -v col="$4" -v a="$ARCH" '
  BEGIN {
    # ONE suggestion formula, used by BOTH branches so they can never drift apart again: the measurement
    # plus 5% headroom, rounded up to the next whole byte so it is STRICTLY ABOVE the measurement.
    #
    # Both halves are load-bearing. Suggesting the measurement itself (what this used to do) sets a ceiling
    # the very next run trips as a REGRESSION — the advice broke the build in the other direction. And a
    # FIXED headroom (the old "m + 30") stops working as the number shrinks: this gate re-fires whenever
    # m < 0.90*ceiling, so any ceiling above m/0.90 = 1.111*m is immediately "too high" again. m+30 leaves
    # that window once m < 270, which loops forever demanding a lower ceiling — and the NFR-MEM target is
    # ZERO, so the numbers are heading straight through that point. 5% is proportional and always lands
    # inside (m, 1.111*m]; the ratchet workload is 60000 samples and repeats to well under 1%.
    #
    # NOTE: NO RAW APOSTROPHES ANYWHERE BELOW. This whole program is one single-quoted shell string, so a
    # stray quote silently ends it and everything after is parsed as SHELL — the failure is a bash syntax
    # error pointing at an awk line, which reads like nonsense. Use the escape the PEER line below uses.
    sug = int(m * 1.05) + 1;
    if (c == "-") {
      printf "gate-mem: %-6s allocation = %.1f bytes/sample  (NOT RATCHETED on %s — no %s ceiling yet)\n", label, m, a, col;
      printf "gate-mem:        ^ to start ratcheting it, put %d in the %s column of the %s row.\n", sug, col, a;
      exit 0;
    }
    lo = c * 0.90;
    printf "gate-mem: %-6s allocation = %.1f bytes/sample (ceiling %d, NFR-MEM target 0)\n", label, m, c;
    if (m > c) {
      printf "gate-mem: FAIL — %s ALLOCATION REGRESSED on %s. %.1f > ceiling %d.\n", label, a, m, c > "/dev/stderr";
      print  "          Every byte here feeds the PEER'"'"'s GC, which owns the whole ~10 ms tail (ADR 0062)." > "/dev/stderr";
      exit 1;
    }
    if (m == 0) {
      printf "gate-mem: %s is at ZERO — NFR-MEM'"'"'s target is MET on %s. Leave the ceiling where it is.\n", label, a;
      exit 0;
    }
    if (m < lo) {
      printf "gate-mem: FAIL — %s IMPROVED on %s: %.1f vs a ceiling of %d (%.0f%% below it). LOWER THE CEILING.\n", label, a, m, c, (1 - m / c) * 100 > "/dev/stderr";
      printf "          FIX: in bench/mem-ceiling.txt, set the %s column of the %s row to %d, then commit.\n", col, a, sug > "/dev/stderr";
      printf "          WHY %d and not %.0f: a ceiling set AT the measurement fails the NEXT run as a\n", sug, m > "/dev/stderr";
      print  "          regression. This is the measurement plus 5% headroom — above it, but still inside" > "/dev/stderr";
      print  "          the 10% band, so it does not trip this same check again." > "/dev/stderr";
      print  "          This is not a test failure. The ratchet only moves DOWN: a ceiling that is never" > "/dev/stderr";
      print  "          lowered stops constraining anything, so banking a win is how the gate keeps working." > "/dev/stderr";
      exit 1;
    }
    exit 0;
  }'
}

M_COPY="$(measure_arm ':return-loans nil' 7)"  || { echo "gate-mem: FAIL — the COPY measurement itself did not run." >&2; exit 1; }
M_RETURN="$(measure_arm ':return-loans t' 8)"  || { echo "gate-mem: FAIL — the RETURN measurement itself did not run." >&2; exit 1; }
# ADR 0105: the third access shape — take-into, application-owned storage, no loan. ⚠️ IT MEASURES A
# DIFFERENT TYPE (perf-fixed, fixed-size, 4-octet key) than COPY/RETURN do (perf-data), deliberately: a
# sequence member would give the arm a floor belonging to the TYPE and the zero target could be neither met
# nor falsified. So this number is NOT comparable to the other two and ratchets only against its own row.
M_INTO="$(measure_arm ':mode :into' 9)"        || { echo "gate-mem: FAIL — the INTO measurement itself did not run." >&2; exit 1; }

RC=0
ratchet "COPY"   "$M_COPY"   "$CEILING_COPY"   "copy"   || RC=1
ratchet "RETURN" "$M_RETURN" "$CEILING_RETURN" "return" || RC=1
ratchet "INTO"   "$M_INTO"   "$CEILING_INTO"   "into"   || RC=1

if [[ $RC -eq 0 ]]; then
  awk -v c="$M_COPY" -v r="$M_RETURN" -v i="$M_INTO" 'BEGIN {
    printf "gate-mem: PASS — no regression. Returning the loan saves %.1f B/sample; still %.0f above the NFR-MEM target of ZERO.\n",
           c - r, r;
    printf "gate-mem:        take-into (own type, not comparable to the two above) reads %.1f B/sample — ADR 0105 slice 1 did NOT reach 0.\n", i;
  }'
fi
exit $RC
