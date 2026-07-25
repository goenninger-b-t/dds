#!/usr/bin/env bash
# gate-drivers — every interop DRIVER that creates a DCPS DataWriter must be able to OFFER a
# data representation.
#
# WHY THIS EXISTS. DATA_REPRESENTATION is an RxO policy, and a stock foreign DataReader generated
# from a plain IDL advertises XCDR1 ONLY. A driver whose writer offers the XCDR2 default therefore
# SILENTLY fails to match it: matched=0, no error, no INCONSISTENT_TOPIC, no INCOMPATIBLE_QOS on
# anything anyone is watching. The leg simply reports zero samples and looks like a protocol bug.
#
# That has now happened THREE times in this repo — run-nokey-publisher, run-keyed-flat-publisher,
# and the mutable driver — each time costing a diagnosis that ended at the same one-line cause. The
# lesson did not transfer from run-publisher (which has had the parameter since ADR 0020) to the
# drivers written after it, because nothing checked.
#
# SCOPE, deliberately narrow: only drivers that call dds.dcps:create-datawriter. run-large-publisher
# is correctly exempt — it publishes through dds.disc:publish-sample, below DCPS, where no RxO
# matching happens at all and the parameter would be dead.
#
# Self-falsifying: plants a driver missing the parameter and asserts the scan rejects it.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

scan() {   # scan <file> -> "name OK|MISSING" per driver that creates a DCPS DataWriter
  python3 - "$1" <<'PYEOF'
import re, sys
src = open(sys.argv[1]).read()
# Each top-level (defun* ... extends to the next top-level ( at column 0. Blank-line heuristics are
# not reliable here — an earlier awk version silently missed two of five drivers, which is the exact
# shape of a gate that under-reports and still says PASS.
tops = [m.start() for m in re.finditer(r'^\(', src, re.M)] + [len(src)]
for i in range(len(tops) - 1):
    body = src[tops[i]:tops[i+1]]
    m = re.match(r'\(defun\*\s+(run-[a-z0-9-]*publisher)\b', body)
    if not m:
        continue
    if 'dds.dcps:create-datawriter' not in body:
        continue
    print(m.group(1), 'OK' if 'data-representation' in body else 'MISSING')
PYEOF
}

fails=0; checked=0
for f in src/dds-shapes/shapes.lisp src/dds-bench/corpus.lisp; do
  [[ -f "$f" ]] || continue
  while read -r name status; do
    [[ -z "$name" ]] && continue
    checked=$((checked + 1))
    if [[ "$status" == "MISSING" ]]; then
      echo "gate-drivers: FAIL — $f: $name creates a DCPS DataWriter but cannot offer a" >&2
      echo "              data representation. A stock foreign reader advertises XCDR1 only, so this" >&2
      echo "              driver silently will not match it (matched=0, no error). Add" >&2
      echo "              :data-representation and pass it to make-writer-qos." >&2
      fails=1
    else
      printf '  ok    %-32s %s\n' "$name" "offers a data representation"
    fi
  done < <(scan "$f")
done

if [[ "$checked" -eq 0 ]]; then
  echo "gate-drivers: FAIL — scanned NO drivers; the check would pass vacuously." >&2
  exit 1
fi

# Falsification: a driver with a DCPS writer and no representation MUST be rejected.
canary="$(mktemp -t gatedrivers.XXXXXX).lisp"
cat > "$canary" <<'CANARY'
(defun* run-canary-publisher (&key (domain 0))
    (function (&key (:domain (integer 0))) t)
  "Canary."
  (let ((dw (dds.dcps:create-datawriter pub tp :qos (dds.qos:make-writer-qos :reliability :reliable))))
    dw))

CANARY
if [[ "$(scan "$canary" | awk '{print $2}')" != "MISSING" ]]; then
  echo "gate-drivers: FAIL — self-test: the scan did NOT reject a driver missing the parameter." >&2
  echo "              A green run would prove nothing." >&2
  rm -f "$canary"; exit 1
fi
rm -f "$canary"

[[ "$fails" -eq 0 ]] || exit 1
echo "gate-drivers: PASS — $checked DCPS-writer driver(s) can offer a representation (and the gate is proven able to fail)."
