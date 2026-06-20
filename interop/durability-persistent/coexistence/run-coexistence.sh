#!/usr/bin/env bash
# TRANSIENT-tier dual-relay coexistence run (WP-DURABILITY-PERSISTENT carry-forward, ADR 0024).
#
# RELAY 1 = RTI Persistence Service v7.3.1 (relays the TRANSIENT durability tier).
# RELAY 2 = our durability service (TRANSIENT_LOCAL collect + replay, emits PID_ORIGINAL_WRITER_INFO
#           + PID_SERVICE_KIND=PERSISTENCE_SERVICE).
# A TRANSIENT Connext publisher writes N samples then exits; a late-joining TRANSIENT_LOCAL Connext
# subscriber, matched to BOTH relays, deduplicates the dual relay on (originalGUID, SN) -> exactly-once.
#
# Run from repo root:  interop/durability-persistent/coexistence/run-coexistence.sh
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
HERE="$REPO/interop/durability-persistent/coexistence"
export NDDSHOME="${NDDSHOME:-/Applications/rti_connext_dds-7.3.1}"
export CONNEXTDDS_ARCH="${CONNEXTDDS_ARCH:-arm64Darwin20clang12.0}"
export DYLD_LIBRARY_PATH="$NDDSHOME/lib/$CONNEXTDDS_ARCH"
PUBSECS="${PUBSECS:-22}"
SUBSECS="${SUBSECS:-25}"
TSHARK="/Applications/Wireshark.app/Contents/MacOS/tshark"
CAP="$HERE/captures/coexistence-transient.pcap"
mkdir -p "$HERE/captures"

cleanup() {
  pkill -f rtipersistenceservice >/dev/null 2>&1
  pkill -f rtipersistenceserviceapp >/dev/null 2>&1
  pkill -f dcoexist-relay2 >/dev/null 2>&1
  pkill -f driver-coexist >/dev/null 2>&1
  [ -n "${TSHARK_PID:-}" ] && kill "$TSHARK_PID" >/dev/null 2>&1
  [ -n "${SVC_PID:-}" ] && kill "$SVC_PID" >/dev/null 2>&1
  [ -n "${PS_PID:-}" ] && kill "$PS_PID" >/dev/null 2>&1
}
trap cleanup EXIT

echo "== 0. kill stale DDS procs =="
pkill -f rtipersistenceservice >/dev/null 2>&1; pkill -f rtipersistenceserviceapp >/dev/null 2>&1
pkill -f dcoexist-relay2 >/dev/null 2>&1; pkill -f shapes_pub >/dev/null 2>&1; pkill -f shapes_sub >/dev/null 2>&1
rm -rf /tmp/dcoexist-D /tmp/dcoexist-K
sleep 1
lsof -nP -iUDP:7400-7440 2>/dev/null && echo "(stale procs above)" || echo "(ports clear)"

echo "== 1. start tshark capture (lo0) =="
WIRESHARK_CONFIG_DIR=$(mktemp -d) "$TSHARK" -i lo0 -f "udp portrange 7400-7700" -w "$CAP" >/dev/null 2>&1 &
TSHARK_PID=$!
sleep 4

echo "== 2. start RTI Persistence Service (relay 1) =="
( cd "$HERE" && "$NDDSHOME/bin/rtipersistenceservice" -cfgFile RTI_PS_TRANSIENT.xml -cfgName transient ) \
  > /tmp/coexist-rtips.log 2>&1 &
PS_PID=$!
sleep 4
echo "   rtips log:"; sed 's/^/     /' /tmp/coexist-rtips.log

echo "== 3. start our durability service (relay 2) =="
( cd "$REPO" && DPERSIST_DIR=/tmp/dcoexist-D DPERSIST_KEYDIR=/tmp/dcoexist-K DPERSIST_SECS=70 \
    ./scripts/with-sbcl.sh --load interop/durability-persistent/coexistence/driver-coexist.lisp ) \
  > /tmp/coexist-svc.log 2>&1 &
SVC_PID=$!
# wait for SVC-COEXIST-STARTED (up to ~30s for compile+load)
for i in $(seq 1 60); do
  grep -q "SVC-COEXIST-STARTED" /tmp/coexist-svc.log 2>/dev/null && break
  sleep 0.5
done
grep -q "SVC-COEXIST-STARTED" /tmp/coexist-svc.log && echo "   our service up." || { echo "   our service FAILED to start:"; tail -20 /tmp/coexist-svc.log; }

echo "== 4. TRANSIENT publisher writes ~${PUBSECS}s of samples, then exits =="
( cd "$HERE" && exec stdbuf -oL "$REPO/interop/connext/shapes-pub/shapes_pub" 0 GREEN ) > /tmp/coexist-pub.log 2>&1 &
PUB_PID=$!
sleep "$PUBSECS"
kill "$PUB_PID" >/dev/null 2>&1; pkill -f "shapes_pub 0 GREEN" >/dev/null 2>&1
sleep 1
PUBN=$(grep -c '^' /tmp/coexist-pub.log 2>/dev/null)
echo "   publisher exited; published lines (incl header): $PUBN"
echo "   first/last pub line:"; sed -n '1p;$p' /tmp/coexist-pub.log | sed 's/^/     /'

echo "== 5. let both relays settle on collected history =="
sleep 4
echo "   our service collected so far:"; grep "SVC-COEXIST-COLLECTED" /tmp/coexist-svc.log | tail -3 | sed 's/^/     /'

echo "== 6. late-joining TRANSIENT_LOCAL subscriber (${SUBSECS}s window) =="
( cd "$HERE" && stdbuf -oL "$REPO/interop/connext/shapes-sub/shapes_sub" 0 "$SUBSECS" ) > /tmp/coexist-sub.log 2>&1
echo "   subscriber result:"; grep -E "received|#1 |#2 " /tmp/coexist-sub.log | tail -5 | sed 's/^/     /'
SUBN=$(grep -oE "received [0-9]+ sample" /tmp/coexist-sub.log | grep -oE "[0-9]+" | tail -1)
echo "   SUBSCRIBER-RECEIVED=$SUBN"

echo "== 7. stop relays =="
kill "$PUB_PID" >/dev/null 2>&1
# let our service hit its final report
sleep 4
echo "   our service final:"; grep -E "SVC-COEXIST-FINAL|SVC-COEXIST-STOPPED" /tmp/coexist-svc.log | sed 's/^/     /'
cleanup
sleep 1

echo "== 8. analyze capture: per-relay DATA + inline-QoS PID (OWI 0x0061 vs RTI keyhash) =="
python3 "$HERE/analyze-capture.py" "$CAP" || true

echo "== DONE. capture: $CAP =="
ls -la "$CAP"
