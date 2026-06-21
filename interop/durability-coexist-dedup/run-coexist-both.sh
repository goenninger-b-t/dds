#!/usr/bin/env bash
# WP-DURABILITY-COEXIST-DEDUP (M6/P5, ADR 0026 §10): LIVE dual-relay coexistence, BOTH directions.
#
# Topology (per direction): RTI Persistence Service v7.3.1 (RELAY 1) + our durability service
# (RELAY 2) BOTH relay a Connext TRANSIENT publisher; the publisher writes ~PUBSECS then EXITS;
# a late-joining receiver comes up while both relays hold the retained history.  Both relays replay
# all N stamping the OMG-standard PID_ORIGINAL_WRITER_INFO (0x0061).
#
#   (a) our-stack reader receiver   -> driver-our-reader.lisp  (our reader-dedup-accept-p)
#   (b) Connext shapes_sub receiver -> RTI receiver-side dedup
#
# FINDING (authoritative: captures/coexist-dir-{a,b}.pcap + ADR 0028): LIVE cross-vendor dual-relay
# exactly-once CAPTURED both directions (ADR 0028, %collect-loop origin-convergence fix).  Both RTI PS
# (relay 1, EntityId 0x80000002) and our service (relay 2, EntityId 0x00000102) stamp
# PID_ORIGINAL_WRITER_INFO 0x0061 with the SAME origin GUID — the original Connext publisher's GUID.
# UNION(GUID,SN) == N per relay == exactly N delivered (SUM==2N, dedup collapses the duplicate).
# dir-a: N=545, publisher GUID 0101642e5f4294116dd106b480000002; our-stack reader delivered 545.
# dir-b: N=550, publisher GUID 01017344014e53c9630ac19e80000002; Connext shapes_sub received 550.
# --assert-converged exits 0 on both captures (the live-gated merge gate passes).
# The in-process authoritative proof: dds.tests:run-durability-collect-origin-convergence-test.
#
# RELIABILITY FIXES vs Phase-3b: (1) RTI PS KEEP_ALL relay QoS so it retains/replays all N of the single
# animated instance; (2) the our-stack reader binds a FIXED port that relay 2 lists as an SPDP peer, so
# our relay SPDP-reaches + matches + replays to it deterministically (+ settle-to-fixpoint poll).
#
# Run from repo root:  interop/durability-coexist-dedup/run-coexist-both.sh
#   env: PUBSECS (publish window, default 14), SUBSECS (Connext sub window, default 30),
#        COEXIST_SECS (our service + our reader lifetime, default 90), DIR=a|b|both (default both)
set -uo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HERE="$REPO/interop/durability-coexist-dedup"
export NDDSHOME="${NDDSHOME:-/Applications/rti_connext_dds-7.3.1}"
export CONNEXTDDS_ARCH="${CONNEXTDDS_ARCH:-arm64Darwin20clang12.0}"
export DYLD_LIBRARY_PATH="$NDDSHOME/lib/$CONNEXTDDS_ARCH"
PUBSECS="${PUBSECS:-14}"
SUBSECS="${SUBSECS:-30}"
COEXIST_SECS="${COEXIST_SECS:-90}"
DIR="${DIR:-both}"
READER_PORT="${READER_PORT:-7600}"   # our-stack reader (dir a) binds this; relay2 lists it as an SPDP peer
TSHARK="/Applications/Wireshark.app/Contents/MacOS/tshark"
PUBDIR="$REPO/interop/connext/shapes-pub"
SUBDIR="$REPO/interop/connext/shapes-sub"
PSDIR="$HERE"   # this WP's RTI PS config (RTI_PS_TRANSIENT.xml, KEEP_ALL relay) + Connext QoS profile
mkdir -p "$HERE/captures"

# ---- QoS swap: each Connext shapes app loads USER_QOS_PROFILES.xml from its cwd. Use this WP's
# ---- TRANSIENT-loopback profile (RELIABLE/TRANSIENT/KEEP_ALL); back up + restore each app's own.
swap_qos() {
  for d in "$PUBDIR" "$SUBDIR"; do
    [ -f "$d/USER_QOS_PROFILES.xml" ] && cp "$d/USER_QOS_PROFILES.xml" "$d/USER_QOS_PROFILES.xml.coexbak"
    cp "$PSDIR/USER_QOS_PROFILES.xml" "$d/USER_QOS_PROFILES.xml"
  done
}
restore_qos() {
  for d in "$PUBDIR" "$SUBDIR"; do
    [ -f "$d/USER_QOS_PROFILES.xml.coexbak" ] && mv "$d/USER_QOS_PROFILES.xml.coexbak" "$d/USER_QOS_PROFILES.xml"
  done
}

kill_all() {
  pkill -f rtipersistenceservice >/dev/null 2>&1
  pkill -f shapes_pub >/dev/null 2>&1
  pkill -f shapes_sub >/dev/null 2>&1
  pkill -f dcoexist-relay2 >/dev/null 2>&1
  pkill -f driver-relay2 >/dev/null 2>&1
}
cleanup() {
  kill_all
  [ -n "${TSHARK_PID:-}" ] && kill "$TSHARK_PID" >/dev/null 2>&1
  [ -n "${PS_PID:-}" ]     && kill "$PS_PID" >/dev/null 2>&1
  [ -n "${SVC_PID:-}" ]    && kill "$SVC_PID" >/dev/null 2>&1
  restore_qos
}
trap cleanup EXIT
swap_qos

# ---- one direction = one full episode (fresh relays + fresh publish window + one late-joiner) ----
run_episode() {
  local label="$1"            # "a" or "b"
  local cap="$HERE/captures/coexist-dir-$label.pcap"
  echo
  echo "############################################################"
  echo "## DIRECTION ($label) — episode start"
  echo "############################################################"

  echo "== 0. kill stale DDS procs =="
  kill_all; sleep 1
  lsof -nP -iUDP:7400-7440 2>/dev/null && echo "(stale procs above)" || echo "(ports clear)"

  echo "== 1. start tshark capture (lo0) -> $cap =="
  WIRESHARK_CONFIG_DIR=$(mktemp -d) "$TSHARK" -i lo0 -f "udp portrange 7400-7700" -w "$cap" >/dev/null 2>&1 &
  TSHARK_PID=$!
  sleep 4

  echo "== 2. start RTI Persistence Service (RELAY 1, TRANSIENT, all topics) =="
  ( cd "$PSDIR" && "$NDDSHOME/bin/rtipersistenceservice" -cfgFile RTI_PS_TRANSIENT.xml -cfgName transient ) \
    > /tmp/coex-rtips-$label.log 2>&1 &
  PS_PID=$!
  sleep 4
  echo "   rtips log tail:"; tail -3 /tmp/coex-rtips-$label.log | sed 's/^/     /'

  echo "== 3. start our durability service (RELAY 2) =="
  ( cd "$REPO" && COEXIST_SECS=$COEXIST_SECS COEXIST_READER_PORT=$READER_PORT \
      ./scripts/with-sbcl.sh --load "$HERE/driver-relay2.lisp" ) \
    > /tmp/coex-svc-$label.log 2>&1 &
  SVC_PID=$!
  for i in $(seq 1 80); do
    grep -q "SVC-COEXIST-STARTED" /tmp/coex-svc-$label.log 2>/dev/null && break
    sleep 0.5
  done
  if grep -q "SVC-COEXIST-STARTED" /tmp/coex-svc-$label.log; then
    OUR_RELAY_PORT=$(grep -oE "OUR-RELAY-SPDP-PORT=[0-9]+" /tmp/coex-svc-$label.log | grep -oE "[0-9]+" | head -1)
    echo "   our service up; OUR-RELAY-SPDP-PORT=$OUR_RELAY_PORT"
  else
    echo "   our service FAILED to start:"; tail -20 /tmp/coex-svc-$label.log
    OUR_RELAY_PORT=0
  fi

  echo "== 4. let BOTH relays discover each other + the (about-to-start) publisher =="
  sleep 4

  echo "== 5. Connext TRANSIENT publisher writes ~${PUBSECS}s, then EXITS =="
  ( cd "$PUBDIR" && exec stdbuf -oL ./shapes_pub 0 GREEN ) > /tmp/coex-pub-$label.log 2>&1 &
  PUB_PID=$!
  sleep "$PUBSECS"
  kill "$PUB_PID" >/dev/null 2>&1; pkill -f shapes_pub >/dev/null 2>&1
  sleep 1
  echo "   publisher exited."

  echo "== 6. settle: both relays hold retained history with the writer GONE =="
  sleep 5
  echo "   our relay collected:"; grep "SVC-COEXIST-COLLECTED" /tmp/coex-svc-$label.log | tail -2 | sed 's/^/     /'

  if [ "$label" = "a" ]; then
    echo "== 7a. OUR-STACK reader late-joins (receiver-side OWI dedup) =="
    ( cd "$REPO" && COEXIST_SECS=$SUBSECS COEXIST_READER_PORT=$READER_PORT \
        COEXIST_SVC_PORT=${OUR_RELAY_PORT:-0} COEXIST_PEER_PS_PORT=7410 \
        ./scripts/with-sbcl.sh --load "$HERE/driver-our-reader.lisp" ) \
      > /tmp/coex-ourreader-$label.log 2>&1
    echo "   our-reader tail:"; grep -E "OUR-READER-(STARTED|MATCH|MATCHED|PROGRESS|SETTLED|RESULT)" /tmp/coex-ourreader-$label.log | tail -8 | sed 's/^/     /'
  else
    echo "== 7b. Connext shapes_sub (TRANSIENT) late-joins (RTI's own dedup) =="
    ( cd "$SUBDIR" && stdbuf -oL ./shapes_sub 0 "$SUBSECS" ) > /tmp/coex-sub-$label.log 2>&1
    echo "   subscriber tail:"; tail -3 /tmp/coex-sub-$label.log | sed 's/^/     /'
  fi

  echo "== 8. stop relays for direction ($label) =="
  kill_all
  [ -n "${TSHARK_PID:-}" ] && kill "$TSHARK_PID" >/dev/null 2>&1
  sleep 2

  echo "== 9. analyze capture ($label): per-relay DATA + OWI 0x0061 on replay =="
  python3 "$REPO/interop/durability-persistent/coexistence/analyze-capture.py" "$cap" || true
  echo "--- OWI origin cross-check ($label) ---"
  python3 "$REPO/interop/durability-persistent/coexistence/analyze-capture.py" --owi-dump "$cap" || true
  echo "--- dual-relay dedup arithmetic ($label): UNION vs SUM ---"
  python3 "$REPO/interop/durability-persistent/coexistence/analyze-capture.py" --dedup-union "$cap" || true
  echo "--- converged-exactly-once assertion ($label) ---"
  python3 "$REPO/interop/durability-persistent/coexistence/analyze-capture.py" --assert-converged "$cap" \
    && echo "   CONVERGED ($label)" || echo "   NOT-CONVERGED ($label) — see --owi-dump"
  echo "   capture: $cap ($(ls -la "$cap" | awk '{print $5}') bytes)"
}

case "$DIR" in
  a)    run_episode a ;;
  b)    run_episode b ;;
  both) run_episode a; sleep 3; run_episode b ;;
  *)    echo "DIR must be a|b|both"; exit 2 ;;
esac

echo
echo "== ALL DONE =="
