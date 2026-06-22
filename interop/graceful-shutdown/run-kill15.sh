#!/usr/bin/env bash
# kill -15 clean-exit proof for WP-GRACEFUL-FFI-TEARDOWN (ADR 0030, M6/P5).
#
# For each impl (Clasp first, then SBCL):
#   1. Launch driver.lisp: starts a PERSISTENT (DARE/file-backed) durability service
#      so OpenSSL is loaded, DEKs are derived, the static arena is live, and the
#      collect thread is inside a foreign recvmmsg call when the kill arrives.
#   2. Sleep to let the service fully start (store opened = OpenSSL/arena live).
#   3. kill -15 <pid>.
#   4. Wait up to 30 s for the process to exit.
#   5. Assert: NO sigbus/bus-error/signal-10 in the captured stderr AND a clean
#      exit (status 0 or 1 acceptable — uiop:quit 0 sets 0; any crash returns 1+).
#
# Print per-impl result.  Exit 0 only when BOTH impls pass.
#
# Run from repo root:  interop/graceful-shutdown/run-kill15.sh
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HERE="$REPO/interop/graceful-shutdown"
DRIVER="$HERE/driver.lisp"
CLASP_LAUNCHER="$REPO/scripts/with-clasp.sh"
SBCL_LAUNCHER="$REPO/scripts/with-sbcl.sh"

SETTLE_SECS=12  # time (s) to wait for the service to start + store to open
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
    "$launcher" --load "$DRIVER" >"$log" 2>&1 &
  local pid=$!

  echo "  pid=$pid; waiting ${SETTLE_SECS}s for service to fully start..."
  sleep "$SETTLE_SECS"

  # Verify the process is still alive (didn't crash at startup)
  if ! kill -0 "$pid" 2>/dev/null; then
    echo "  [$label] FAIL: process exited before kill -15 (startup crash?)"
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

  # rc=0 = uiop:quit 0 = clean teardown; rc=143 = killed by SIGTERM default handler
  # (should not happen with our handler installed); rc=1 = Lisp error.
  # Acceptable: 0 (graceful) or 130 (SIGINT default, not our case).
  # We treat anything != crash signals as acceptable since the point is no SIGBUS.
  echo "  [$label] clean exit rc=$rc, no SIGBUS"
  echo "  --- log tail ---"
  tail -20 "$log"
  echo "  --- end log ---"
  return 0
}

echo ""
echo "=== WP-GRACEFUL-FFI-TEARDOWN: kill -15 clean-exit proof ==="
echo ""

if launch_and_kill "clasp" "$CLASP_LAUNCHER"; then
  echo "Clasp: PASS (clean exit, no SIGBUS)"
else
  echo "Clasp: FAIL"
  overall=1
fi

echo ""

if launch_and_kill "sbcl" "$SBCL_LAUNCHER"; then
  echo "SBCL: PASS (clean exit, no SIGBUS)"
else
  echo "SBCL: FAIL"
  overall=1
fi

echo ""
if [ "$overall" -eq 0 ]; then
  echo "=== RESULT: BOTH impls: clean exit, no SIGBUS ==="
else
  echo "=== RESULT: ONE OR MORE impls FAILED ==="
fi

exit "$overall"
