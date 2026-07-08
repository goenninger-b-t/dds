#!/usr/bin/env bash
# Live 2-PROCESS microservice durability interop (ADR 0050 §4.8 — WP-DURABILITY-MS-2PROCESS capstone).
#
# Exercises the durability MICROSERVICE backend across REAL OS PROCESSES — a server process
# (driver-ms-server.lisp) + separate client processes (driver-ms-client.lisp) — not just in one Lisp
# image. Proves, process-to-process:
#   LEG 1  PUT→GET   : a PUT client process persists N records through the DARE-wrapped microservice
#                      client to the server process; a SEPARATE GET client process recovers them
#                      BYTE-EXACT (the wire protocol + the server's persistent file inner + the DARE
#                      composition all work across processes).
#   LEG 2  RESTART   : a long-lived reconnect client opens against server v1, then the server PROCESS is
#          + RECONNECT stopped and RESTARTED on the SAME port + inner dir (v2 replays the fsync'd frames
#                      from disk); the client's next op RECONNECTS (Slice 1, ADR 0050 §4.5) to v2 and
#                      recovers BYTE-EXACT (persistent inner survived + the client DARE chain re-verifies).
#
# The server is DARE-BLIND (opaque frames; the client holds the key + chain). Always-on DARE needs
# OpenSSL >= 3.5 — if unavailable the client store-open fails and the OK line never appears (this harness
# then FAILS cleanly, it does not hang). SBCL-only driver (NFR-PORT; mirrors run-autodiscover.sh).
#
# BOUNDED: every wait has a timeout, every spawned PID + the temp tree are cleaned in a trap — it never
# hangs and exits NON-ZERO on any failure. Run from repo root: interop/durability-persistent/run-microservice.sh
# Env overrides: DPERSIST_MS_PORT, DPERSIST_N, DPERSIST_TOPIC.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HERE="$REPO/interop/durability-persistent"
SBCL="$REPO/scripts/with-sbcl.sh"
LOGS="$HERE/logs"
mkdir -p "$LOGS"

# The server driver start_server launches. LEG 1/2 use the direct-helper driver; LEG 3 swaps in the
# OPERATOR CLI driver (durability-service-main --backend server) to prove the CLI entrypoint (both go
# through the SAME shared %run-microservice-server, so both emit the MS-SERVER-* markers below).
SERVER_DRIVER="${SERVER_DRIVER:-$HERE/driver-ms-server.lisp}"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/dms-2proc.XXXXXX")"
# The store dirs are NOT pre-created: make-file-store / the encrypted epoch-dir + key-dir CREATE them
# 0700 on first open (they fail-closed ASSERT 0700 on an already-existing dir, ADR 0026 §10.12) — a
# pre-created 0755 dir would be refused. The server restart + the put→get→reconnect chain reuse them.
SRV_INNER="$WORK/server-inner"     # server-side persistent DARE-blind file inner (opaque frames on disk)
CLI_D="$WORK/client-D"             # client-local DARE epoch-dir (epochs.dat + logmac tail anchor)
CLI_K="$WORK/client-K"             # client-local DARE key-dir (ML-KEM-1024 keypair)
SIGNAL="$WORK/restarted.flag"      # reconnect-leg restart sentinel (touched after server v2 is up)

PORT="${DPERSIST_MS_PORT:-$(( 34000 + (RANDOM % 20000) ))}"
N="${DPERSIST_N:-5}"
TOPIC="${DPERSIST_TOPIC:-Square}"

SRV_PID="" ; RC_PID="" ; FAILED=0

cleanup() {
  [ -n "$RC_PID" ]  && kill "$RC_PID"     2>/dev/null || true
  [ -n "$SRV_PID" ] && kill -TERM "$SRV_PID" 2>/dev/null || true
  sleep 0.5
  [ -n "$SRV_PID" ] && kill -9 "$SRV_PID" 2>/dev/null || true
  [ -n "$RC_PID" ]  && kill -9 "$RC_PID"  2>/dev/null || true
  rm -rf "$WORK" 2>/dev/null || true
}
trap cleanup EXIT

fail() { echo "  *** FAIL: $*"; FAILED=1; }

# NOTE on marker patterns: the SBCL drivers load AS SOURCE, so on ANY driver error SBCL echoes the whole
# source form — which contains the literal marker strings inside their FORMAT templates (e.g.
# "MS-GET-OK topic=~a") — into the error backtrace in the log. A naive grep for the bare marker would
# then FALSE-MATCH a failed run. Every marker grep below therefore requires the marker followed by a REAL
# VALUE (port=<digits> / topic=<alnum>) that a FORMAT directive (port=~d / topic=~a) can never produce —
# so only genuine printed output matches, never the echoed form.
wait_for_log() {   # $1=file $2=extended-regex $3=secs  -> 0 found / 1 timeout
  local f="$1" pat="$2" i=0 max=$(( $3 * 5 ))
  while [ "$i" -lt "$max" ]; do
    [ -f "$f" ] && grep -qE "$pat" "$f" 2>/dev/null && return 0
    sleep 0.2 ; i=$(( i + 1 ))
  done
  return 1
}

wait_pid_gone() {  # $1=pid $2=secs  -> 0 gone / 1 timeout
  local pid="$1" i=0 max=$(( $2 * 5 ))
  while [ "$i" -lt "$max" ]; do
    kill -0 "$pid" 2>/dev/null || return 0
    sleep 0.2 ; i=$(( i + 1 ))
  done
  return 1
}

wait_server_listening() {  # $1=log $2=secs  -> 0 listening / 1 (timeout or the server process died early, e.g. bind fail)
  local log="$1" i=0 max=$(( $2 * 5 ))
  while [ "$i" -lt "$max" ]; do
    grep -qE "MS-SERVER-LISTENING port=[0-9]" "$log" 2>/dev/null && return 0
    kill -0 "$SRV_PID" 2>/dev/null || return 1
    sleep 0.2 ; i=$(( i + 1 ))
  done
  return 1
}

start_server() {  # $1=logfile ; sets SRV_PID + waits (bounded) for LISTENING
  local log="$1"
  DPERSIST_MS_PORT="$PORT" DPERSIST_MS_INNER="$SRV_INNER" DPERSIST_MS_HOST=127.0.0.1 \
    "$SBCL" --load "$SERVER_DRIVER" >"$log" 2>&1 &
  SRV_PID=$!
  if wait_server_listening "$log" 75; then
    echo "  server process up (pid $SRV_PID) listening on 127.0.0.1:$PORT"
    return 0
  fi
  fail "server did not reach MS-SERVER-LISTENING (bind failure or load timeout) — see $log"
  tail -5 "$log" 2>/dev/null | sed 's/^/    | /'
  return 1
}

stop_server() {   # $1=logfile ; SIGTERM + bounded wait for a clean §4.8 stop
  local log="$1"
  [ -z "$SRV_PID" ] && return 0
  kill -TERM "$SRV_PID" 2>/dev/null || true
  wait_for_log "$log" "MS-SERVER-STOPPED port=[0-9]" 30 || fail "server did not log MS-SERVER-STOPPED within 30s (stop stalled?)"
  wait_pid_gone "$SRV_PID" 15 || { echo "  server pid $SRV_PID lingering — hard kill"; kill -9 "$SRV_PID" 2>/dev/null || true; }
  local pid="$SRV_PID" ; SRV_PID=""
  echo "  server process (pid $pid) stopped cleanly"
}

run_client() {    # $1=op $2=logfile  -> runs a client process to completion (bounded), asserts nothing here
  local op="$1" log="$2"
  DPERSIST_MS_OP="$op" DPERSIST_MS_PORT="$PORT" DPERSIST_MS_HOST=127.0.0.1 \
    DPERSIST_DIR="$CLI_D" DPERSIST_KEYDIR="$CLI_K" DPERSIST_BACKEND=microservice \
    DPERSIST_N="$N" DPERSIST_TOPIC="$TOPIC" \
    "$SBCL" --load "$HERE/driver-ms-client.lisp" >"$log" 2>&1 &
  local pid=$!
  wait_pid_gone "$pid" 120 || { fail "$op client did not exit within 120s"; kill -9 "$pid" 2>/dev/null || true; }
}

echo "=== Live 2-process microservice interop (port $PORT, N=$N, topic $TOPIC) ==="
echo "    work dir: $WORK"

# ── LEG 1: PUT process → GET process, byte-exact across processes ──────────────────────────────
echo "--- LEG 1: PUT client process → GET client process (cross-process byte-exact) ---"
SRV_LOG1="$LOGS/ms-2proc-server1.log"
start_server "$SRV_LOG1" || { echo "=== ABORT (server v1 failed to start) ==="; exit 1; }

PUT_LOG="$LOGS/ms-2proc-put.log"
run_client put "$PUT_LOG"
if grep -qE "MS-PUT-DONE topic=[A-Za-z0-9]" "$PUT_LOG"; then
  echo "  PUT client persisted $N records across the process boundary"
else
  fail "PUT client did not report MS-PUT-DONE"; tail -6 "$PUT_LOG" 2>/dev/null | sed 's/^/    | /'
fi

GET_LOG="$LOGS/ms-2proc-get.log"
run_client get "$GET_LOG"
if grep -qE "MS-GET-OK topic=[A-Za-z0-9]" "$GET_LOG"; then
  echo "  *** LEG 1 PASS: GET client recovered $N records BYTE-EXACT across processes ***"
else
  fail "GET client did not report MS-GET-OK (cross-process recovery failed)"
  tail -6 "$GET_LOG" 2>/dev/null | sed 's/^/    | /'
fi

# ── LEG 2: server restart + mid-session client reconnect (Slice 1) + persistent recovery ───────
echo "--- LEG 2: server-process RESTART + client RECONNECT + persistent recovery (byte-exact) ---"
RC_LOG="$LOGS/ms-2proc-reconnect.log"
DPERSIST_MS_OP=reconnect DPERSIST_MS_PORT="$PORT" DPERSIST_MS_HOST=127.0.0.1 \
  DPERSIST_DIR="$CLI_D" DPERSIST_KEYDIR="$CLI_K" DPERSIST_BACKEND=microservice \
  DPERSIST_N="$N" DPERSIST_TOPIC="$TOPIC" DPERSIST_MS_SIGNAL="$SIGNAL" \
  "$SBCL" --load "$HERE/driver-ms-client.lisp" >"$RC_LOG" 2>&1 &
RC_PID=$!
if wait_for_log "$RC_LOG" "MS-RC-OPENED topic=[A-Za-z0-9]" 120; then
  echo "  reconnect client (pid $RC_PID) opened against server v1 + sees the records"
else
  fail "reconnect client did not reach MS-RC-OPENED"; tail -6 "$RC_LOG" 2>/dev/null | sed 's/^/    | /'
fi

echo "  stopping server v1 (the client's connection will drop)"
stop_server "$SRV_LOG1"

echo "  restarting server v2 on the SAME port + inner dir (replays the persisted frames)"
SRV_LOG2="$LOGS/ms-2proc-server2.log"
start_server "$SRV_LOG2" || echo "  (server v2 failed to restart)"

touch "$SIGNAL"    # tell the reconnect client the server is back — its next op re-dials (Slice 1)

if wait_for_log "$RC_LOG" "MS-RC-RECOVERED topic=[A-Za-z0-9]" 90; then
  echo "  *** LEG 2 PASS: client RECONNECTED to the restarted server + recovered $N records BYTE-EXACT ***"
else
  fail "reconnect client did not report MS-RC-RECOVERED (reconnect / persistent recovery failed)"
  tail -8 "$RC_LOG" 2>/dev/null | sed 's/^/    | /'
fi
wait_pid_gone "$RC_PID" 15 || { kill -9 "$RC_PID" 2>/dev/null || true; }
RC_PID=""
stop_server "$SRV_LOG2"

# ── LEG 3: server via the OPERATOR CLI entrypoint (durability-service-main --backend server) ────
# Proves the operator-runnable CLI server mode (WP-DURABILITY-MS-SERVER-CLI, ADR 0050 §4.8): the server
# is launched THROUGH durability-service-main (parse --backend server + dispatch to %run-microservice-
# server), STOPPED (SIGTERM -> MS-SERVER-STOPPED), RESTARTED on the SAME port + inner dir (persisted
# frames replay from disk), and a fresh GET client recovers them BYTE-EXACT — persistent + clean-stop +
# restart, all via the CLI entrypoint. Fresh port + inner + client dirs so it is independent of LEG 1/2.
echo "--- LEG 3: server via the CLI entrypoint (--backend server) + stop/restart + persistent recovery ---"
SERVER_DRIVER="$HERE/driver-ms-server-cli.lisp"
PORT="$(( 34000 + (RANDOM % 20000) ))"
SRV_INNER="$WORK/server-inner-cli"
CLI_D="$WORK/client-D-cli"
CLI_K="$WORK/client-K-cli"

SRV_LOG3="$LOGS/ms-2proc-server3-cli.log"
start_server "$SRV_LOG3" || echo "  (CLI-entrypoint server failed to start)"

PUT_LOG3="$LOGS/ms-2proc-put-cli.log"
run_client put "$PUT_LOG3"
if grep -qE "MS-PUT-DONE topic=[A-Za-z0-9]" "$PUT_LOG3"; then
  echo "  PUT client persisted $N records via the CLI-launched server"
else
  fail "PUT client (CLI server) did not report MS-PUT-DONE"; tail -6 "$PUT_LOG3" 2>/dev/null | sed 's/^/    | /'
fi

echo "  stopping the CLI server (SIGTERM -> clean stop), then restarting on the SAME port + inner dir"
stop_server "$SRV_LOG3"
SRV_LOG3B="$LOGS/ms-2proc-server3b-cli.log"
start_server "$SRV_LOG3B" || echo "  (CLI-entrypoint server failed to restart)"

GET_LOG3="$LOGS/ms-2proc-get-cli.log"
run_client get "$GET_LOG3"
if grep -qE "MS-GET-OK topic=[A-Za-z0-9]" "$GET_LOG3"; then
  echo "  *** LEG 3 PASS: CLI-entrypoint server persisted across stop+restart, GET client BYTE-EXACT ***"
else
  fail "GET client (CLI server restart) did not report MS-GET-OK"; tail -6 "$GET_LOG3" 2>/dev/null | sed 's/^/    | /'
fi
stop_server "$SRV_LOG3B"

echo "=== 2-PROCESS MICROSERVICE INTEROP COMPLETE ==="
if [ "$FAILED" -eq 0 ]; then
  echo "*** ALL LEGS PASS ***"; exit 0
else
  echo "*** ONE OR MORE LEGS FAILED ***"; exit 1
fi
