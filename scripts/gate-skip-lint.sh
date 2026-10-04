#!/usr/bin/env bash
# gate-skip-lint — a test reports a skip through ONE channel, dds.tests::note-skip (ADR 0122).
#
# WHY. On 2026-10-03 the SBCL suite printed "646 passed" and "skipped: 0 — every test ran" while about 100
# tests had returned early behind a bare `(format t "  [x] SKIP — ...")`. The old registry only saw the skips
# that remembered to call it; every other one was a line of scrollback. A print is not a report: nothing
# counts it, nothing names its capability, and the run summary cannot see it.
#
# THE RULES. In scope are every file under src/dds-tests/ and, in any other file under src/ except
# src/dds-pal/, every top-level form that is a test body living in a production file: a form named
# run-…-test, AND every form whose name is registered as a suite test in the run-all-tests registry
# (src/dds-tests/echo-test.lisp, entries ("name" . pkg:fn)). The registry is the authority on what the
# suite runs; the name pattern alone missed dds.bench:run-bench-shmem-smoke and run-bench-zerocopy-smoke.
#   1. No output call (a FORMAT whose destination is not NIL, WRITE-LINE, WRITE-STRING, PRINC, PRINT) may
#      print a skip: a string containing skip / skipped / skipping / skips, pass-skip, "not measurable" or
#      "not measured", in any case. A FORMAT NIL (an assertion message) is not a print and is not checked.
#   2. Every note-skip / note-test-skip / note-bench-skip call names, on its first line, at least one
#      capability keyword, and every capability keyword it names is in the closed vocabulary
#      *skip-capabilities* in src/dds-tests/test-support.lisp (so an arm that never runs on this host still
#      cannot carry a typo past the gate).
# Exempt: the forms that IMPLEMENT the channel (note-skip, note-dare-skip, note-bench-skip, %skip-hook,
# print-skip-report, capability-preflight, run-with-skip-report, %note-dare-test-skip) and src/dds-pal/.
#
# The gate falsifies itself on every run before scanning: it plants each banned spelling and each rule-2
# violation in a scratch tree, requires the scan to flag every one, to ignore the near-misses, and to exempt
# the implementing forms, a non-test production form and dds-pal/.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

VOCAB_FILE=src/dds-tests/test-support.lisp
REGISTRY_FILE=src/dds-tests/echo-test.lisp

registry() {   # $1 = run-all-tests registry file; prints every registered function name, package-stripped
  grep -oE '\("[^"]+"[[:space:]]+\.[[:space:]]+[^[:space:])]+' "$1" \
    | awk '{print $NF}' | sed -E "s/^#'//; s/^.*://" | tr 'A-Z' 'a-z' | sort -u
}

vocab() {   # $1 = test-support file; prints the *skip-capabilities* keywords, one per line
  awk '/^\(defparameter \*skip-capabilities\*/{on=1} on{print} on&&/\)$/{exit}' "$1" \
    | grep -oE ':[a-z][a-z0-9-]*' | sort -u
}

# scan <root> <vocab-file> <registry-file>: prints file:line: message for every violation under <root>/src
scan() {
  local root="$1" vfile="$2" rfile="$3" v r
  v="$(vocab "$vfile" | tr '\n' ' ')"
  [[ -n "$v" ]] || { echo "$vfile:0: cannot read *skip-capabilities*"; return; }
  r="$(registry "$rfile" | tr '\n' ' ')"
  [[ -n "$r" ]] || { echo "$rfile:0: cannot read the run-all-tests registry"; return; }
  find "$root/src" -name '*.lisp' -not -path "$root/src/dds-pal/*" -print0 | sort -z \
    | xargs -0 awk -v VOCAB="$v" -v REG="$r" -v TESTDIR="$root/src/dds-tests/" '
      BEGIN {
        n = split(VOCAB, vv, " "); for (i = 1; i <= n; i++) if (vv[i] != "") ok[vv[i]] = 1
        n = split(REG, rr, " "); for (i = 1; i <= n; i++) if (rr[i] != "") registered[rr[i]] = 1
        exempt["note-skip"]; exempt["note-dare-skip"]; exempt["note-bench-skip"]; exempt["%skip-hook"]
        exempt["print-skip-report"]; exempt["capability-preflight"]; exempt["run-with-skip-report"]
        exempt["%note-dare-test-skip"]
        word = "((^|[^a-z0-9-])skip(s|ped|ping)?([^a-z0-9-]|$)|pass-skip|not measurable|not measured)"
      }
      FNR == 1 { name = ""; pending = 0; alltest = (index(FILENAME, TESTDIR) == 1) }
      /^\(/ {
        name = ""
        if (match($0, /^\((defun\*?|defmacro|defvar|defparameter)[ \t]+[^ \t()]+/)) {
          split(substr($0, RSTART, RLENGTH), a, /[ \t]+/); name = tolower(a[2]); sub(/^.*:/, "", name)
        }
      }
      {
        line = $0
        if (line ~ /^[ \t]*;/) { pending = 0; next }
        inscope = (alltest || name ~ /^run-.*-test$/ || (name in registered)) && !(name in exempt)
        if (!inscope) { pending = 0; next }
        low = tolower(line)
        # rule 1: an output call, or the continuation line of one whose string starts on the next line
        isout = (low ~ /\((format[ \t]+[^ \t]|write-line|write-string|princ|prin1|print)/ && low !~ /\(format[ \t]+nil([ \t)]|$)/)
        if ((isout || pending) && low ~ /"/) {
          s = low; strs = ""
          while (match(s, /"([^"\\]|\\.)*"?/)) { strs = strs substr(s, RSTART, RLENGTH); s = substr(s, RSTART + RLENGTH) }
          if (strs ~ word) print FILENAME ":" FNR ": bare skip print (use note-skip, ADR 0122): " line
          pending = 0
        } else pending = isout
        # rule 2: capability keywords on a note-* call line
        if (low ~ /\((dds\.pal:)?note-(skip|test-skip|bench-skip)[ \t]/) {
          c = low; found = 0
          gsub(/"([^"\\]|\\.)*"/, "\"\"", c)   # a keyword inside a string (a reason) is not a capability
          while (match(c, /(^|[ (\t]):[a-z][a-z0-9-]*/)) {
            k = substr(c, RSTART, RLENGTH); sub(/^[ (\t]/, "", k); c = substr(c, RSTART + RLENGTH)
            if (k == ":scope" || k == ":test" || k == ":arm") continue
            found = 1
            if (!(k in ok)) print FILENAME ":" FNR ": capability " k " is not in *skip-capabilities* (ADR 0122): " line
          }
          if (!found) print FILENAME ":" FNR ": note-* call names no capability on its first line (ADR 0122): " line
        }
      }'
}

# ---- 0. FALSIFICATION ----
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/src/dds-tests" "$tmp/src/dds-x" "$tmp/src/dds-pal"
cat > "$tmp/src/dds-tests/test-support.lisp" <<'EOF'
(defparameter *skip-capabilities*
  '(:alpha :beta-gamma))
(defun* note-skip (site capability reason &key (scope :test))
  (format t "~&  [skip] ~a (~a): ~a~%" site capability reason))
EOF
cat > "$tmp/src/dds-tests/canary-test.lisp" <<'EOF'
(defun* run-a-test ()
  (format t "~&  [skip] a: no capability~%")
  (format t "~&  [a] SKIP — OpenSSL >= 3.5 not available: ~a~%" r)
  (format stream "(SHMEM unreliable — the bench pass-skipped)~%")
  (format t "~&  -- parity: ~a absent — SKIPPED~%" p)
  (format t "~&    [smoke] ~a: skipping (gap)~%" x)
  (format t "  [x] bytes-consed 0 — alloc not measurable~%")
  (write-line "RESULT: Skip")
  (format t
          "~&  [b] skips this arm~%")
  (note-skip "a" :alpha "r")
  (note-skip "a" :gamma "r")
  (dds.pal:note-test-skip "a" :alpha-beta "r" :arm)
  (note-bench-skip s "a"
                   :alpha "r")
  ;; must NOT count from here on
  (format nil "a v1 reader must skip to the end; stopped at ~d" n)
  (%check :x nil (format nil "must be SKIPPED; status ~s" s))
  (format t "skip-history armed; skipper; askip~%")
  ;; a comment: (format t "[skip] x")
  (note-skip "a" :beta-gamma "r" :scope :arm)
  (note-skip "a" :alpha "gated on pal-impl-name :SBCL")
  (dds.pal:note-test-skip (format nil "~a" l) (or c :alpha) r))
EOF
cat > "$tmp/src/dds-tests/echo-test.lisp" <<'EOF'
(defun* run-all-tests ()
  (let ((tests '(("a"                 . run-a-test)
                 ("prod-smoke"        . dds.x:run-prod-smoke))))
    tests))
EOF
cat > "$tmp/src/dds-x/prod.lisp" <<'EOF'
(defun* run-prod-thing-test ()
  (format t "~&  [p] SKIP — AES-GCM not available: ~a~%" r))
(defun* run-subscriber ()
  (format t "~&[sub] skipped unparseable sample~%"))
(defun* run-prod-smoke ()
  (format t "(SHMEM off on this platform — skipped) "))
(defun* %note-dare-test-skip (site reason)
  (dds.pal:note-test-skip site cap reason))
EOF
cat > "$tmp/src/dds-pal/pal-x.lisp" <<'EOF'
(defun* run-pal-thing-test () (format *error-output* "  [skip] ~a~%" s))
EOF
got="$(scan "$tmp" "$tmp/src/dds-tests/test-support.lisp" "$tmp/src/dds-tests/echo-test.lisp" \
       | sed -E "s#^$tmp/src/##; s#^([^:]*:[0-9]+):.*#\1#" | tr '\n' ' ')"
want="dds-tests/canary-test.lisp:2 dds-tests/canary-test.lisp:3 dds-tests/canary-test.lisp:4 dds-tests/canary-test.lisp:5 dds-tests/canary-test.lisp:6 dds-tests/canary-test.lisp:7 dds-tests/canary-test.lisp:8 dds-tests/canary-test.lisp:10 dds-tests/canary-test.lisp:12 dds-tests/canary-test.lisp:13 dds-tests/canary-test.lisp:14 dds-x/prod.lisp:2 dds-x/prod.lisp:6 "
if [[ "$got" != "$want" ]]; then
  echo "gate-skip-lint: FAIL — self-test: the scan must flag exactly the planted violations and ignore the" >&2
  echo "                near-misses, the implementing forms, a non-test production form and dds-pal/." >&2
  echo "                want: '$want'" >&2
  echo "                got:  '$got'" >&2
  echo "                The gate is BLIND or over-eager — a green run would prove nothing." >&2
  exit 1
fi

# ---- 1. THE SCAN ----
found="$(scan . "$VOCAB_FILE" "$REGISTRY_FILE")"
if [[ -n "$found" ]]; then
  printf '%s\n' "$found"
  echo "gate-skip-lint: FAIL — a skip outside the one channel, or an unknown capability (ADR 0122). Report a" >&2
  echo "                skip with (note-skip SITE CAPABILITY REASON [:scope :arm]) in src/dds-tests, or" >&2
  echo "                (dds.pal:note-test-skip SITE CAPABILITY REASON [:arm]) in a production-file test body." >&2
  exit 1
fi
echo "gate-skip-lint: PASS — every test skip goes through note-skip with a capability from the closed"
echo "                vocabulary (the gate is proven able to fail on 8 bare-print spellings, a run-…-test production"
echo "                body, a registry-only production test body, an unknown capability and a capability-less call)."
