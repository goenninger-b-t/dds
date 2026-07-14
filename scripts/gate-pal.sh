#!/usr/bin/env bash
# gate-pal — no reader conditionals outside dds-pal/ (operating contract §10, NFR-PORT).
#
# THE CONTRACT SAID THIS WAS ALREADY ENFORCED. It was not: "(CI lint enforces this)" described a lint that
# DID NOT EXIST — and there was no CI to run it in either (the only workflow was publish-wiki). The rule
# happened to hold, by luck, not by enforcement. This is that lint.
#
# WHY THE RULE. #+sbcl / #+clasp / #+allegro outside the PAL is how a portability layer rots: the impl split
# leaks into the engine, and the "one behaviour, three impls" guarantee quietly stops being checkable.
# Everything impl-specific belongs behind dds-pal/.
#
# Docstrings and comments may MENTION the conditionals (several say "no #+sbcl/#+clasp here"), so only
# READER-CONDITIONAL FORMS count: a #+/#- at the start of a form, not inside a string or after a ';'.
#
# --self-test falsifies it: plants a real conditional and asserts the scan REJECTS it. A gate never proven
# able to fail proves nothing.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

IMPLS='sbcl|clasp|allegro|ccl|ecl|abcl|lispworks|cmu'

# A reader conditional in CODE: a #+/#- token that is NOT preceded on the line by a ';' (comment) and is
# not inside a docstring. Lexical, but sufficient: we require the #+/#- to be the first non-space token or
# to directly follow an open paren / whitespace — i.e. it is READ, not narrated.
scan() {
  local f="$1"
  awk -v impls="$IMPLS" '
    {
      line = $0
      # strip a trailing comment (naive but adequate: we only care about #+ in code position)
      semi = index(line, ";")
      if (semi > 0) line = substr(line, 1, semi - 1)
      if (line ~ ("(^|[ \t(])#[+-](" impls ")([ \t(]|$)")) printf "%s:%d: %s\n", FILENAME, NR, $0
    }' "$f"
}

# ---- 0. FALSIFICATION ----
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
cat > "$tmp/canary.lisp" <<'EOF'
;; This comment mentions #+sbcl and must be IGNORED.
(defun doc-only ()
  "A docstring that says no #+sbcl/#+clasp here — must be IGNORED.")
(defun real-violation ()
  #+sbcl (sb-ext:gc)
  nil)
EOF
hits="$(scan "$tmp/canary.lisp")"
n="$(printf '%s' "$hits" | grep -c . || true)"
if [[ "$n" -ne 1 || "$hits" != *":5:"* ]]; then
  echo "gate-pal: FAIL — self-test: must flag EXACTLY the real conditional (canary line 5) and ignore the" >&2
  echo "          comment (line 1) and the docstring (line 3). Got ${n} hit(s):" >&2
  printf '%s\n' "$hits" >&2
  echo "          The gate is BLIND — a green run would prove nothing." >&2
  exit 1
fi

# ---- 1. THE SCAN ----
violations=0
while IFS= read -r f; do
  case "$f" in src/dds-pal/*) continue ;; esac   # the PAL is where impl splits BELONG
  out="$(scan "$f")"
  if [[ -n "$out" ]]; then printf '%s\n' "$out"; violations=1; fi
done < <(find src -name '*.lisp' | sort)

if [[ "$violations" -ne 0 ]]; then
  echo "gate-pal: FAIL — reader conditional(s) outside dds-pal/ (operating contract §10, NFR-PORT)." >&2
  echo "          Everything impl-specific belongs behind the PAL." >&2
  exit 1
fi
echo "gate-pal: PASS — no reader conditionals outside dds-pal/ (and the gate is proven able to fail)."
