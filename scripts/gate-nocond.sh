#!/usr/bin/env bash
# gate-nocond — NO EXCEPTIONS AT ALL IN OUR CODE
# (owner directive 2026-07-14, NON-NEGOTIABLE; refined same day from "none in the hot path" to "none at all").
#
# THE RULE
#   1. NO Lisp conditions ANYWHERE in our code. Signalling allocates and unwinds; it is control flow that
#      hides from the type system. Return STATUS VALUES.
#   2. Every condition MUST be handled at latest at the toplevel DDS API. Nothing escapes as a raw Lisp
#      condition. The public API returns DDS ReturnCode_t (:ok / :timeout / :not-enabled / :bad-parameter).
#
# THE TARGET IS ZERO AND WE ARE AT 332 (production, non-hot-path; in-file test functions excluded —
# an `assert` in a run-*-test IS the test's failure mechanism, not production control flow). A gate that fails at "anything above zero" would be
# permanently red and therefore ignored — the same trap `make mem` fell into. So this enforces the rule in
# TWO tiers:
#
#   HOT PATH  — STRICT. Every signalling form must be annotated and justified (below). Currently 0 unjustified.
#   THE REST  — RATCHETED. The count may only go DOWN (bench/nocond-ceiling.txt). A new `error` anywhere in
#               src/ fails the build; removing one lets you lower the ceiling. Monotonic march to zero.
#
# TWO CHECKS
#
#   A. SIGNALLING, by ANNOTATION (mirrors gate-hotpath's allocation scan). A hot-path file may contain a
#      signalling form, but every one MUST say why:
#
#          (error 'buffer-overflow ...)   ; HOTPATH-COND(GUARD): bounds check; cannot fire in steady state;
#                                         ; caught at the receiver boundary (start-udp-receiver)
#
#      Classes:
#        COLD    setup / teardown / config validation — not on the per-sample path
#        GUARD   a bounds/security check that CANNOT fire in steady state AND is caught at a named boundary
#        TEST    test-only
#        TRACKED a real steady-state condition — KNOWN DEBT, being driven out
#      An UNMARKED signalling form FAILS the build. The TRACKED set is PRINTED every run.
#
#   B. THE BOUNDARY HANDLERS MUST EXIST. Rule 2 is only true if the receiver threads actually catch. A
#      malformed datagram signals buffer-overflow on the receiver thread; if nothing catches it the thread
#      DIES and the node stops receiving — a remote DoS from one bad packet. This asserts the handlers are
#      still there, so nobody deletes them in a refactor.
#
# Self-falsifying: plants an unmarked signalling form and asserts the scan rejects it.
set -uo pipefail
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
)
# SIGNALLING only. `(error () ...)` / `(error (c) ...)` are handler-case CLAUSES — the opposite of a
# signal — so require the next token NOT to be an open paren.
SIGNAL_RE='[(](error|signal|cerror|warn)[ \t]+[^( \t]|[(](assert|check-type)[ \t]'
MARKER='HOTPATH-COND'
# NOCOND(MACRO) — the ONE exempt class (owner ruling 2026-07-14). A signalling form reached ONLY at
# MACROEXPANSION time (define-dds-type rejecting a malformed type spec; defun*/defstruct* rejecting a bad
# signature or a missing docstring) is a COMPILE-TIME rejection: it fails the BUILD. None of the three
# reasons for the no-conditions rule can apply to it — there is no running program, so it cannot unwind a
# thread, cannot allocate on a hot path, and cannot hide in a predicate. CL offers no other way to reject a
# malformed macro form, and forcing it to a status would only move the failure from build time to run time.
#
# The owner's OTHER ruling bounds this precisely: a macro may NEVER *EMIT* a signalling form into the code
# it generates. A condition that a macro plants in a generated codec runs at EXECUTION time and is a plain
# violation, exempt from nothing. So the marker justifies WHERE THE FORM RUNS, not who wrote it: annotate a
# form your MACRO EVALUATES; never a form your macro OUTPUTS.
MACRO_MARKER='NOCOND(MACRO)'
# NOCOND(TEST) — the SECOND (and last) exempt class (owner ruling 2026-07-14). A CRASH SIMULATOR: a
# signalling form armed ONLY by a debug special that defaults NIL, whose entire purpose is that the UNWIND
# is the thing being tested — *durability-debug-compact-fault* aborts a live SQLite transaction so the
# rollback/recovery path runs; *durability-debug-file-rewrite-fault* dies mid-rename; *durability-debug-
# start-fault* dies mid-service-start. A STATUS VALUE CANNOT SIMULATE A CRASH: the caller would carry on.
# This is the same TEST justification the hot-path tier already grants (HOTPATH-COND(TEST)), extended to
# the ratchet tier. The bar is strict and is NOT "it is only used by tests": the form must be INERT IN
# PRODUCTION (guarded by a debug special defaulting NIL) and the unwind must be the mechanism under test.
TEST_MARKER='NOCOND(TEST)'

scan() {
  awk -v pat="$SIGNAL_RE" -v marker="$MARKER" '
    { l[NR]=$0 }
    END { for (i=1;i<=NR;i++) {
            if (l[i] ~ /^[ \t]*;/) continue
            if (l[i] ~ pat) {
              if (l[i] ~ marker) continue
              if (i>1 && l[i-1] ~ marker) continue
              printf "%s:%d: %s\n", FILENAME, i, l[i]
            } } }' "$1"
}

# ---- 0. FALSIFICATION ----
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
cat > "$tmp/canary.lisp" <<'EOF'
(defun marked ()
  (error 'x))   ; HOTPATH-COND(TEST): must be ACCEPTED
(defun unmarked ()
  (error 'x))
EOF
hits="$(scan "$tmp/canary.lisp")"
n="$(printf '%s' "$hits" | grep -c . || true)"
if [[ "$n" -ne 1 || "$hits" != *":4:"* ]]; then
  echo "gate-nocond: FAIL — self-test: must flag EXACTLY the unmarked form (canary line 4). Got ${n}:" >&2
  printf '%s\n' "$hits" >&2
  echo "             The gate is BLIND — a green run would prove nothing." >&2
  exit 1
fi

violations=0

# ---- A. signalling forms must be justified ----
for f in "${HOTPATH_FILES[@]}"; do
  [[ -f "$f" ]] || continue
  out="$(scan "$f")"
  if [[ -n "$out" ]]; then printf '%s\n' "$out"; violations=1; fi
done
if [[ "$violations" -ne 0 ]]; then
  echo "gate-nocond: FAIL — unjustified condition-signalling form(s) in a hot-path file." >&2
  echo "             Mark each with '; ${MARKER}(CLASS): reason' (COLD|GUARD|TEST|TRACKED), or remove it." >&2
  echo "             Rule: the per-sample path returns STATUS VALUES, never a stack unwind." >&2
  exit 1
fi

# ---- B. the boundary handlers must still exist ----
# Each receiver thread MUST catch, or one malformed datagram kills it and the node stops receiving.
boundary() {   # boundary <file> <regex> <what>
  if grep -qE "$2" "$1"; then
    echo "  ok    $3"
  else
    echo "  FAIL  $3 — the handler is GONE. One malformed datagram would now kill the receiver thread." >&2
    violations=1
  fi
}
echo "gate-nocond: boundary handlers (rule 2 — nothing escapes to a thread's top level):"
boundary src/dds-xport/udp.lisp   'handler-case \(funcall on-datagram' 'UDP + multicast receiver catches its sink'
boundary src/dds-xport/shmem.lisp 'handler-case \(shmem-receive-drain' 'SHMEM receiver catches its drain'

[[ "$violations" -ne 0 ]] && { echo "gate-nocond: FAIL — see above." >&2; exit 1; }

# ---- C. THE REST OF src/ — a RATCHET toward zero (rule 1 applies EVERYWHERE, not just the hot path) ----
CEIL_FILE=bench/nocond-ceiling.txt
[[ -r "$CEIL_FILE" ]] || { echo "gate-nocond: FAIL — missing $CEIL_FILE" >&2; exit 1; }
CEIL="$(tr -d '[:space:]' < "$CEIL_FILE")"
# IN-FILE TEST FUNCTIONS ARE EXCLUDED. Many src/ files carry their own (defun* run-...-test ...) and an
# `assert` there IS the test's failure mechanism, not production control flow — 393 of the original 725 were
# these. The rule targets PRODUCTION code: what a user's call can hit. Everything else counts.
count_file() {
  # NOTE: the marker is matched with INDEX (a literal substring), never as a regex — "NOCOND(MACRO)" read
  # as a regex is "NOCOND" followed by the GROUP "MACRO", i.e. it matches NOCONDMACRO and never the real
  # annotation. The self-test below caught exactly that; keep it literal.
  awk -v pat="$SIGNAL_RE" -v macro="$MACRO_MARKER" -v testm="$TEST_MARKER" '
    /^\(defun\*?[ \t]+/ {
      # An in-file TEST function. The %-prefixed form (%run-secure-pm, ...) is the SAME thing as run-*:
      # a test whose ASSERT is its failure mechanism, not production control flow. The original pattern
      # missed it and silently counted 19 test asserts in secure-sedp.lisp as production debt.
      intest = ($2 ~ /-test$/ || $2 ~ /^%?run-/) ? 1 : 0
    }
    { exempt = index($0, macro) || (NR > 1 && index(last, macro)) \
             || index($0, testm) || (NR > 1 && index(last, testm))
      # a FULL-COMMENT line (first non-blank char is ;) is not code — a (error ...) MENTIONED in prose is
      # not a signalling form. Only whole-comment lines are skipped; a trailing ; after real code is not,
      # because a signalling token at start-of-form there would be real debt.
      iscomment = ($0 ~ /^[ \t]*;/)
      if (!intest && !iscomment && $0 ~ pat && !exempt) n++
      last = $0 }
    END { print n+0 }' "$1"
}

# FALSIFY THE RATCHET COUNTER *AND* THE NOCOND(MACRO) EXEMPTION. An exemption nobody has watched fail is a
# hole: if the marker silently matched everything, the count would collapse to 0 and this gate would wave
# the whole campaign through while reporting PASS. So prove BOTH directions on a canary — the annotated
# forms are skipped, the bare one is still counted, and an in-file test's assert stays excluded.
cat > "$tmp/count-canary.lisp" <<'EOF'
(defun* macro-marked ()
  (unless row   ; NOCOND(MACRO): compile-time — must NOT be counted
    (error "bad type spec"))
  ;; NOCOND(MACRO): on the PRECEDING line — must NOT be counted
  (error "also compile-time"))
(defun* counted ()
  (error "this one is production control flow — MUST be counted"))
(defun* run-something-test ()
  (assert (= 1 1)))
(defun* %run-internal-harness ()
  (assert (= 2 2)))
(defun* crash-simulator ()
  (when *debug-fault*   ; NOCOND(TEST): inert in production; the UNWIND is the mechanism under test
    (error "simulated crash")))
;;; A prose mention of (error ...) on a full-comment line must NOT be counted.
EOF
cn="$(count_file "$tmp/count-canary.lisp")"
if [[ "$cn" -ne 1 ]]; then
  echo "gate-nocond: FAIL — self-test: the ratchet counter must count EXACTLY the 1 unexempt form in the" >&2
  echo "             canary (2 NOCOND(MACRO) + 1 NOCOND(TEST) skipped, 2 in-file-test asserts skipped" >&2
  echo "             incl. the %run- form). Got ${cn}." >&2
  echo "             Either the counter is blind or NOCOND(MACRO) is over-matching — a green ratchet" >&2
  echo "             would prove NOTHING." >&2
  exit 1
fi

COUNT=0
while IFS= read -r f; do
  case "$f" in *dds-tests*) continue ;; esac
  for h in "${HOTPATH_FILES[@]}"; do [[ "$f" == "$h" ]] && continue 2; done
  COUNT=$(( COUNT + $(count_file "$f") ))
done < <(find src -name '*.lisp' | sort)

echo "gate-nocond: PRODUCTION signalling forms (non-hot-path, excl. in-file tests) = ${COUNT} (ceiling ${CEIL}, TARGET 0)"
if [[ "$COUNT" -gt "$CEIL" ]]; then
  echo "gate-nocond: FAIL — you ADDED a condition. ${COUNT} > ceiling ${CEIL}." >&2
  echo "             Rule 1: NO exceptions in our code. Return a status value." >&2
  exit 1
fi
if [[ "$COUNT" -lt "$CEIL" ]]; then
  echo "gate-nocond: FAIL — you REMOVED $(( CEIL - COUNT )). Bank it: echo ${COUNT} > ${CEIL_FILE}" >&2
  echo "             A ceiling that is never lowered stops constraining anything. The ratchet only moves DOWN." >&2
  exit 1
fi

tracked=0
for f in "${HOTPATH_FILES[@]}"; do
  [[ -f "$f" ]] || continue
  tracked=$((tracked + $(grep -cE "${MARKER}\(TRACKED\)" "$f" || true)))
done
echo "gate-nocond: PASS — hot path condition-free (every form justified), boundaries intact, ${COUNT} to go."
if [[ "$tracked" -gt 0 ]]; then
  echo "gate-nocond: DEBT — ${tracked} TRACKED steady-state condition(s) remain:"
  for f in "${HOTPATH_FILES[@]}"; do
    [[ -f "$f" ]] || continue
    grep -nE "${MARKER}\(TRACKED\)" "$f" | sed "s|^|  ${f}:|" || true
  done
fi
