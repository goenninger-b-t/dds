#!/usr/bin/env bash
# kill -15 clean-exit proof for WP-GRACEFUL-FFI-TEARDOWN (ADR 0030, M6/P5).
#
# For each supported Lisp (SBCL, then AllegroCL — ADR 0118):
#   1. Launch driver.lisp: starts a PERSISTENT (DARE/file-backed) durability service
#      so OpenSSL is loaded, DEKs are derived, the static arena is live, and the
#      collect thread is inside a foreign recvmmsg call when the kill arrives.
#   2. Sleep to let the service fully start (store opened = OpenSSL/arena live).
#   3. kill -15 <pid>.
#   4. Wait up to 30 s for the process to exit.
#   5. Assert: the service actually started (no RUNNER-START-FAILED — needs OpenSSL >= 3.5 for ML-KEM),
#      NO sigbus/bus-error/signal-10 in the captured stderr, the driver printed its
#      "teardown complete" marker (the handler ran and the service was torn down), and the
#      process exited within the wait window.
#
# A Lisp that is not installed is a FAIL (its launcher exits 127 before the kill), never a skip.
# Print per-impl result.  Exit 0 only when BOTH impls pass.
#
# Run from repo root:  interop/graceful-shutdown/run-kill15.sh
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HERE="$REPO/interop/graceful-shutdown"
DRIVER="$HERE/driver.lisp"
SBCL_LAUNCHER="$REPO/scripts/with-sbcl.sh"
ALLEGRO_LAUNCHER="$REPO/scripts/with-allegro.sh"

SETTLE_SECS=600 # upper bound (s) to wait for the driver's "signal handler installed" marker; the first
                # AllegroCL run compiles the system, so a fixed short sleep is not enough
SETTLE_EXTRA=3  # once the marker is seen, let the collect thread park in its foreign recv
WAIT_SECS=30    # timeout (s) waiting for the process to exit after kill -15

overall=0

launch_and_kill() {
  local label="$1"
  local launcher="$2"
  local log="/tmp/gshut-${label}.log"

  rm -f "$log"
  rm -rf "/tmp/gshut-D-${label}" "/tmp/gshut-K-${label}"

  echo "=== [$label] launching driver.lisp ==="

  GSHUT_DIR="/tmp/gshut-D-${label}" \
  GSHUT_KEYDIR="/tmp/gshut-K-${label}" \
  GSHUT_DOMAIN=0 \
    "$launcher" --eval "(load \"$DRIVER\")" >"$log" 2>&1 &
  local pid=$!

  echo "  pid=$pid; waiting up to ${SETTLE_SECS}s for the driver's handler-installed marker..."
  local settled=0
  while [ "$settled" -lt "$SETTLE_SECS" ] && kill -0 "$pid" 2>/dev/null; do
    if grep -q "GSHUT-DRIVER: signal handler installed" "$log" 2>/dev/null; then break; fi
    sleep 1
    settled=$((settled + 1))
  done
  if kill -0 "$pid" 2>/dev/null && ! grep -q "GSHUT-DRIVER: signal handler installed" "$log" 2>/dev/null; then
    echo "  [$label] FAIL: driver did not reach 'signal handler installed' within ${SETTLE_SECS}s"
    kill -9 "$pid" 2>/dev/null || true
    cat "$log"
    return 1
  fi
  sleep "$SETTLE_EXTRA"

  # Verify the process is still alive (didn't crash at startup)
  if ! kill -0 "$pid" 2>/dev/null; then
    wait "$pid" 2>/dev/null; local early_rc=$?
    if [ "$early_rc" -eq 127 ]; then
      echo "  [$label] FAIL: Lisp not available (launcher exit 127) — a missing Lisp is a FAIL, not a skip"
      cat "$log"
      return 1
    fi
    echo "  [$label] FAIL: process exited before kill -15 (startup crash? rc=$early_rc)"
    echo "  [$label] --- log ---"
    cat "$log"
    echo "  [$label] --- end log ---"
    return 1
  fi

  echo "  [$label] service alive; sending SIGTERM (kill -15 $pid)..."
  kill -15 "$pid" 2>/dev/null || true

  # Wait up to WAIT_SECS for clean exit
  local waited=0
  while kill -0 "$pid" 2>/dev/null; do
    sleep 0.5
    waited=$((waited + 1))
    if [ "$waited" -ge $((WAIT_SECS * 2)) ]; then
      echo "  [$label] FAIL: process did not exit within ${WAIT_SECS}s after SIGTERM"
      kill -9 "$pid" 2>/dev/null || true
      cat "$log"
      return 1
    fi
  done

  wait "$pid" 2>/dev/null; local rc=$?

  # Check for SIGBUS evidence
  if grep -qiE 'sigbus|bus error|signal 10' "$log" 2>/dev/null; then
    echo "  [$label] FAIL: SIGBUS detected in log"
    cat "$log"
    return 1
  fi

  # The scenario must actually have been live: if the PERSISTENT service never started (e.g. OpenSSL < 3.5,
  # so no ML-KEM and no DEK), the kill hit an idle image and a clean exit proves nothing about the FFI path.
  if grep -q "RUNNER-START-FAILED" "$log"; then
    echo "  [$label] FAIL: the durability service did not start (RUNNER-START-FAILED) — the FFI teardown"
    echo "  [$label]       scenario was never live, so a clean exit proves nothing"
    grep -A2 "RUNNER-START-FAILED" "$log" | head -6
    return 1
  fi

  # The handler must have run the teardown: without the driver's marker, the process died some other
  # way (e.g. the default SIGTERM disposition, rc=143) and nothing proves the FFI teardown path.
  if ! grep -q "GSHUT-DRIVER: teardown complete" "$log"; then
    echo "  [$label] FAIL: no 'teardown complete' marker — the graceful path did not run (rc=$rc)"
    cat "$log"
    return 1
  fi
  echo "  [$label] clean exit rc=$rc, teardown complete, no SIGBUS"
  echo "  --- log tail ---"
  tail -20 "$log"
  echo "  --- end log ---"
  return 0
}

echo ""
echo "=== WP-GRACEFUL-FFI-TEARDOWN: kill -15 clean-exit proof ==="
echo ""

if launch_and_kill "sbcl" "$SBCL_LAUNCHER"; then
  echo "SBCL: PASS (clean exit, no SIGBUS)"
else
  echo "SBCL: FAIL"
  overall=1
fi

echo ""

if launch_and_kill "allegro" "$ALLEGRO_LAUNCHER"; then
  echo "AllegroCL: PASS (clean exit, no SIGBUS)"
else
  echo "AllegroCL: FAIL"
  overall=1
fi

echo ""
if [ "$overall" -eq 0 ]; then
  echo "=== RESULT: BOTH impls: clean exit, no SIGBUS ==="
else
  echo "=== RESULT: ONE OR MORE impls FAILED ==="
fi

exit "$overall"
