#!/usr/bin/env bash
# gate-quickload — Quicklisp may PROVIDE our dependencies; it must never GATE our own code.
#
# WHY. ql:quickload wraps the whole load in ql-impl-util:call-with-quiet-compilation, which is
# (handler-bind ((warning #'muffle-warning)) ...) — so compile-file's failure-p NEVER reaches ASDF and NO
# compile WARNING can fail anything downstream. That is the exact opposite of the operating contract's
# "fail on any warning promoted to error", and it is not hypothetical: main did not compile from a clean
# cache for TWO DAYS while `make test` reported 563/563 green (see scripts/gate-build.sh, Trap 1).
#
# The Makefile was swept for this long ago. Two SCRIPTS were missed and kept loading our systems under the
# muffler — scripts/linux-repro.sh (the Linux fallback harness, i.e. the thing you reach for when the CI
# box is unreachable, structurally unable to fail on a compile warning) and scripts/capture-corpus.sh.
# A rule enforced in one file and not the others is a rule that comes back.
#
# WHAT COUNTS. ql:quickload of one of OUR systems — `dds` or `dds-*`. Quickloading a third-party
# dependency is fine and is what Quicklisp is for; nothing here does it today, but the lint must not
# forbid it. Use asdf:load-system for our own code.
#
# --self-test falsifies it: plants a real violation and asserts the scan REJECTS it, and plants the two
# legitimate shapes (a third-party quickload, an asdf:load-system of ours) and asserts it ACCEPTS them.
# A gate never proven able to fail proves nothing (and this project has shipped three such gates).
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

# ql:quickload ... :dds or :dds-<something>. Tolerates quickload/ql:quickload, #:dds, "dds", and any
# intervening keywords (:silent t), because the offence is the pair, not the spelling.
#
# COMMENTS ARE NOT CODE. Several scripts — including this one and linux-repro.sh — NARRATE the forbidden
# shape in order to explain why it is forbidden. A lint that cannot tell narration from a call flags its
# own documentation, which is exactly what happened on the first run. Only a line in CODE position counts.
scan() {
  awk '
    {
      if ($0 ~ /^[[:space:]]*#/) next
      if ($0 ~ /(ql:)?quickload[^)]*[:"#]+dds(-[a-z]+)?/) printf "%s:%d: %s\n", FILENAME, NR, $0
    }' "$1"
}

# ---- 0. FALSIFICATION ----
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
cat > "$tmp/canary.sh" <<'EOF'
# legitimate: a third-party dependency is exactly what Quicklisp is for
sbcl --eval '(ql:quickload :static-vectors :silent t)'
# legitimate: our own code loaded the only way that can fail on a warning
sbcl --eval '(asdf:load-system :dds-tests)'
# narration only: this line says ql:quickload :dds-tests and must NOT be flagged
# VIOLATION follows: our own system under the warning-muffler
sbcl --eval '(ql:quickload :dds-tests :silent t)'
EOF
hits="$(scan "$tmp/canary.sh")"
n="$(printf '%s' "$hits" | grep -c . || true)"
if [[ "$n" -ne 1 || "$hits" != *":7:"* ]]; then
  echo "gate-quickload: FAIL — self-test: must flag EXACTLY the ql:quickload of our own system" >&2
  echo "                (canary line 7) and accept the third-party quickload (line 2), the" >&2
  echo "                asdf:load-system (line 4) and the COMMENT narrating the rule (line 5)." >&2
  echo "                Got ${n} hit(s):" >&2
  printf '%s\n' "$hits" >&2
  echo "                The gate is BLIND — a green run would prove nothing." >&2
  exit 1
fi

# ---- 1. THE SCAN ----
violations=0
while IFS= read -r f; do
  case "$f" in
    */gate-quickload.sh|*/gate-build.sh|*/wire-check.sh) continue ;;  # these DOCUMENT the rule
  esac
  out="$(scan "$f")"
  if [[ -n "$out" ]]; then printf '%s\n' "$out"; violations=1; fi
done < <(find scripts -name '*.sh' | sort; echo Makefile)

if [[ "$violations" -ne 0 ]]; then
  echo "gate-quickload: FAIL — ql:quickload of one of OUR systems above." >&2
  echo "                Quicklisp PROVIDES dependencies; it must not GATE our code. Use" >&2
  echo "                asdf:load-system, which honours *compile-file-failure-behaviour*." >&2
  exit 1
fi
echo "gate-quickload: PASS — Quicklisp gates none of our systems (and the gate is proven able to fail)."
