#!/usr/bin/env bash
# gate-build: the build gate the operating contract §6 actually asks for —
#   "load all systems; fail on any warning promoted to error".
#
# Two defects made the old gate permanently green, and this script closes BOTH:
#
#   1. ql:quickload MUFFLED EVERY WARNING. `make build`/`make test` loaded via ql:quickload, which
#      wraps the load in ql-impl-util:call-with-quiet-compilation — (handler-bind ((warning
#      #'muffle-warning)) ...). compile-file's failure-p never reached ASDF, so no compile WARNING
#      could ever fail the gate. The Makefile now loads our systems with asdf:load-system.
#
#   2. THE FASL CACHE HID THE REBUILD. A gate that never recompiles cannot catch a compile error.
#      A stale ~/.cache/common-lisp let a genuinely uncompilable tree report 563/563 for two days
#      (%count-matching: called with 4 args against a 2-arg forward declaim). So this gate builds
#      from a CLEARED cache — that is the whole point of it, and why it is separate from the
#      incremental `make build`. What it clears is this project's PRIVATE root
#      (scripts/lisp-cache-env.sh), never the shared ~/.cache/common-lisp: clearing that would
#      delete the fasls of any other project's Lisp running at the same time.
#
# It also FALSIFIES ITSELF (the make-corpus lesson: a gate never proven to fail proves nothing):
# it compiles a synthetic system carrying a wrong-arity call and asserts the build machinery
# REJECTS it. If that synthetic build passes, the gate is blind and we exit non-zero regardless of
# how the real tree fared.
#
# Usage: scripts/gate-build.sh [LISP]        (default: ./scripts/with-sbcl.sh)
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# The cache root this clears MUST be the one the Lisp then writes to — one definition, sourced by
# this gate and by both with-*.sh launchers. See scripts/lisp-cache-env.sh.
. "$REPO/scripts/lisp-cache-env.sh"
LISP="${1:-$REPO/scripts/with-sbcl.sh}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

fail() { echo "gate-build: FAIL — $*" >&2; exit 1; }

# ---- 1. FALSIFICATION: the gate must REJECT a known-bad compile. ----
# A wrong-arity call against a declaimed ftype — the exact defect class that slipped through.
mkdir -p "$TMP/canary"
cat > "$TMP/canary/canary.asd" <<'EOF'
(defsystem "canary" :components ((:file "canary")))
EOF
cat > "$TMP/canary/canary.lisp" <<'EOF'
(defpackage #:canary (:use #:cl))
(in-package #:canary)
(declaim (ftype (function (integer integer) integer) canary-two-args))
(defun canary-two-args (a b) (+ a b))
;; Deliberately wrong: three arguments against a two-argument ftype. SBCL signals a full
;; WARNING, compile-file sets failure-p, and ASDF must raise COMPILE-FILE-ERROR.
(defun canary-caller (x) (canary-two-args x x x))
EOF

canary_out="$(CL_SOURCE_REGISTRY="$TMP/canary//:" "$LISP" \
  --eval '(handler-case (progn (asdf:load-system :canary) (format t "~&CANARY: BUILT (gate is BLIND)~%"))
            (error () (format t "~&CANARY: REJECTED~%")))' \
  --eval '(uiop:quit 0)' 2>&1)"

if ! grep -q "CANARY: REJECTED" <<<"$canary_out"; then
  echo "$canary_out" | tail -20 >&2
  fail "the gate did NOT reject a wrong-arity compile — it is blind, exactly as ql:quickload made it.
       A green build from this gate would mean nothing. Fix the gate before trusting any build."
fi
echo "gate-build: falsification OK — a wrong-arity compile IS rejected."

# ---- 2. THE REAL BUILD, from a CLEARED fasl cache. ----
# Without this the gate can pass on a tree that does not compile (that is how the bug survived).
CACHE="$XDG_CACHE_HOME/common-lisp"
echo "gate-build: clearing fasl cache ($CACHE) — a cached build proves nothing."
rm -rf "${CACHE:?}"/* 2>/dev/null || true

build_out="$(cd "$REPO" && "$LISP" \
  --eval '(handler-case (progn (asdf:load-system :dds-tests) (format t "~&BUILD: OK~%"))
            (error (e) (format t "~&BUILD: FAILED: ~a~%" e)))' \
  --eval '(uiop:quit 0)' 2>&1)"

if ! grep -q "^BUILD: OK" <<<"$build_out"; then
  grep -E "caught (WARNING|ERROR)|BUILD: FAILED" -A2 <<<"$build_out" | head -30 >&2
  fail "clean-cache build of :dds-tests failed (see above)."
fi

echo "gate-build: PASS — clean-cache build of :dds-tests is green, and the gate is proven able to fail."
