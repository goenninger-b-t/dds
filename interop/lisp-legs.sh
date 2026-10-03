# shellcheck shell=bash
# Shared "one leg per supported Lisp" runner for the in-process interop proofs (WP-0.14, ADR 0118).
#
# Source it, then call:
#
#   run_inprocess_leg LABEL LAUNCHER LOG TIMEOUT_SECS TEST-FN...
#
# LABEL         sbcl | allegro (printed, and used in the log name by the caller)
# LAUNCHER      scripts/with-sbcl.sh or scripts/with-allegro.sh
# LOG           file that receives the whole Lisp transcript
# TIMEOUT_SECS  wall-clock bound for a leg that never reaches LEG-DONE. Once LEG-DONE is in the
#               transcript the process gets LISP_LEGS_EXIT_GRACE seconds (default 30) to exit, then is
#               terminated (AllegroCL can hang at exit); the verdict is taken from the transcript markers,
#               so a hang AFTER the verdict line is reported, not mistaken for a pass)
# TEST-FN...    fully qualified test functions, e.g. dds.tests:run-security-encrypted-pubsub-test
#
# Verdict, per leg (returns 0 only for PASS):
#   PASS     every TEST-FN returned true, none printed a skip notice, and the LEG-DONE marker was seen
#   FAIL     anything else — including:
#              * the Lisp is not installed (the launcher exits 127): a missing Lisp is a FAIL, never a skip;
#              * a TEST-FN returned NIL or signalled;
#              * a TEST-FN printed "SKIP" (its proof did not run, so the leg proved nothing);
#              * the leg timed out before LEG-DONE.
#
# The two legs are SBCL and AllegroCL (ADR 0118 withdrew Clasp). Every caller runs both and fails when
# either fails.

LISP_LEGS_REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SBCL_LAUNCHER="$LISP_LEGS_REPO/scripts/with-sbcl.sh"
ALLEGRO_LAUNCHER="$LISP_LEGS_REPO/scripts/with-allegro.sh"

run_inprocess_leg() {
  local label="$1" launcher="$2" log="$3" secs="$4"
  shift 4
  local quoted="" fn
  for fn in "$@"; do quoted="$quoted \"$fn\""; done
  # One form: load the test system, then run each function with its output captured (so a printed SKIP is
  # attributable), print one LEG-RESULT line per function and a final LEG-DONE line, then exit. The names
  # travel as strings and are READ inside the image after the load, when the dds.tests package exists.
  local form="(let ((fails 0))
  (asdf:load-system :dds-tests)
  (dolist (f (mapcar (function read-from-string) (quote (${quoted}))))
    (let* ((ok nil)
           (out (with-output-to-string (*standard-output*)
                  (setf ok (handler-case (funcall f)
                             (error (e) (format t \"~&  signalled: ~a~%\" e) nil)))))
           (skipped (search \"SKIP\" (string-upcase out))))
      (write-string out)
      (format t \"~&LEG-RESULT ~(~a~) ~a~%\" f (cond (skipped \"SKIPPED\") (ok \"PASS\") (t \"FAIL\")))
      (unless (and ok (not skipped)) (incf fails))))
  (format t \"~&LEG-DONE fails=~d~%\" fails)
  (finish-output)
  (uiop:quit (if (zerop fails) 0 1)))"

  echo "=== [${label}] in-process leg: $* ==="
  # Run in the background and poll for LEG-DONE: once the verdict is in the transcript, allow
  # LISP_LEGS_EXIT_GRACE seconds for a normal exit, then end the run (AllegroCL can hang at exit, and
  # waiting out the whole TIMEOUT_SECS after a final verdict wastes the wall clock). TIMEOUT_SECS stays
  # the outer bound for a leg that never reaches LEG-DONE. timeout(1) runs its child in its own process
  # group and forwards a TERM it receives to that group (then KILL after --kill-after).
  local grace="${LISP_LEGS_EXIT_GRACE:-30}" done_at="" pid rc
  timeout --kill-after=30 "$secs" "$launcher" --eval "$form" >"$log" 2>&1 &
  pid=$!
  while kill -0 "$pid" 2>/dev/null; do
    if [ -z "$done_at" ] && grep -q '^LEG-DONE' "$log"; then done_at=$SECONDS; fi
    if [ -n "$done_at" ] && [ $((SECONDS - done_at)) -ge "$grace" ]; then
      echo "  [${label}] verdict in, process still alive ${grace}s later; terminating it"
      kill -TERM "$pid" 2>/dev/null
      break
    fi
    sleep 1
  done
  wait "$pid"
  rc=$?

  if [ "$rc" -eq 127 ] && ! grep -q "LEG-DONE" "$log"; then
    echo "  [${label}] FAIL: Lisp not available (launcher exit 127) — a missing Lisp is a FAIL, not a skip"
    sed -n '1,5p' "$log"
    return 1
  fi
  grep -E '^LEG-RESULT ' "$log" | sed "s/^/  [${label}] /"
  if ! grep -q "^LEG-DONE fails=0" "$log"; then
    if ! grep -q "^LEG-DONE" "$log"; then
      echo "  [${label}] FAIL: no LEG-DONE marker (rc=${rc}; 124/137 = timed out after ${secs}s)"
    else
      echo "  [${label}] FAIL: $(grep '^LEG-DONE' "$log")"
    fi
    echo "  [${label}] --- log tail (${log}) ---"
    tail -25 "$log"
    return 1
  fi
  if [ "$rc" -ne 0 ]; then
    # Verdict already printed and clean; only the exit was abnormal (AllegroCL's known hang at exit
    # ends in a timeout kill). Report it, but the proof itself ran and passed.
    echo "  [${label}] note: verdict complete, but the process exit was abnormal (rc=${rc})"
  fi
  echo "  [${label}] PASS"
  return 0
}
