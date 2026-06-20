#!/usr/bin/env bash
# WP-DURABILITY-COEXIST-DEDUP Task-1 spike: fresh live capture of RTI Persistence Service v7.3.1
# REPLAYING its retained TRANSIENT history to a late-joining Connext reader — the episode on which
# RTI PS stamps PID_ORIGINAL_WRITER_INFO (0x0061). Confirms (on this session's wire) whether RTI's
# per-sample origin is the standard 0x0061 carrying the original writer's real (GUID, SN).
#
# Procedure (mirrors the 2026-06-18 spike that reliably yields OWI):
#   tshark on lo0 -> RTI PS (TRANSIENT, all topics) -> Connext TRANSIENT publisher ~PUBSECS then EXIT
#   -> settle -> late-joining Connext TRANSIENT reader (RTI PS replays its retained history to it).
# Run from repo root:  interop/durability-coexist-dedup/spike/run-spike.sh
set -uo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
HERE="$REPO/interop/durability-coexist-dedup/spike"
export NDDSHOME="${NDDSHOME:-/Applications/rti_connext_dds-7.3.1}"
export CONNEXTDDS_ARCH="${CONNEXTDDS_ARCH:-arm64Darwin20clang12.0}"
export DYLD_LIBRARY_PATH="$NDDSHOME/lib/$CONNEXTDDS_ARCH"
PUBSECS="${PUBSECS:-18}"
SUBSECS="${SUBSECS:-12}"
TSHARK="/Applications/Wireshark.app/Contents/MacOS/tshark"
CAP="$HERE/captures/rti-ps-replay-owi.pcap"
PUBDIR="$REPO/interop/connext/shapes-pub"
SUBDIR="$REPO/interop/connext/shapes-sub"
mkdir -p "$HERE/captures"

# Swap the spike TRANSIENT-loopback QoS into each shapes app's cwd (each app loads
# USER_QOS_PROFILES.xml from cwd), backing up the app's own profile; restored on EXIT.
swap_qos() {
  for d in "$PUBDIR" "$SUBDIR"; do
    [ -f "$d/USER_QOS_PROFILES.xml" ] && cp "$d/USER_QOS_PROFILES.xml" "$d/USER_QOS_PROFILES.xml.spikebak"
    cp "$HERE/USER_QOS_PROFILES.xml" "$d/USER_QOS_PROFILES.xml"
  done
}
restore_qos() {
  for d in "$PUBDIR" "$SUBDIR"; do
    [ -f "$d/USER_QOS_PROFILES.xml.spikebak" ] && mv "$d/USER_QOS_PROFILES.xml.spikebak" "$d/USER_QOS_PROFILES.xml"
  done
}

cleanup() {
  pkill -f rtipersistenceservice >/dev/null 2>&1
  pkill -f shapes_pub >/dev/null 2>&1
  [ -n "${TSHARK_PID:-}" ] && kill "$TSHARK_PID" >/dev/null 2>&1
  [ -n "${PS_PID:-}" ]     && kill "$PS_PID" >/dev/null 2>&1
  restore_qos
}
trap cleanup EXIT
swap_qos

echo "== 0. kill stale DDS procs =="
pkill -f rtipersistenceservice >/dev/null 2>&1; pkill -f shapes_pub >/dev/null 2>&1; pkill -f shapes_sub >/dev/null 2>&1
sleep 1
lsof -nP -iUDP:7400-7440 2>/dev/null && echo "(stale procs above)" || echo "(ports clear)"

echo "== 1. start tshark capture (lo0) =="
WIRESHARK_CONFIG_DIR=$(mktemp -d) "$TSHARK" -i lo0 -f "udp portrange 7400-7700" -w "$CAP" >/dev/null 2>&1 &
TSHARK_PID=$!
sleep 4

echo "== 2. start RTI Persistence Service (TRANSIENT, all topics) =="
( cd "$HERE" && "$NDDSHOME/bin/rtipersistenceservice" -cfgFile RTI_PS_TRANSIENT.xml -cfgName transient ) \
  > /tmp/spike-rtips.log 2>&1 &
PS_PID=$!
sleep 4
echo "   rtips log tail:"; tail -4 /tmp/spike-rtips.log | sed 's/^/     /'

echo "== 3. Connext TRANSIENT publisher writes ~${PUBSECS}s, then EXITS =="
( cd "$REPO/interop/connext/shapes-pub" && exec stdbuf -oL ./shapes_pub 0 GREEN ) > /tmp/spike-pub.log 2>&1 &
PUB_PID=$!
sleep "$PUBSECS"
kill "$PUB_PID" >/dev/null 2>&1; pkill -f shapes_pub >/dev/null 2>&1
sleep 1
echo "   publisher exited (lines: $(grep -c '^' /tmp/spike-pub.log 2>/dev/null))"

echo "== 4. settle so RTI PS holds retained history with the writer GONE =="
sleep 4

echo "== 5. late-joining Connext TRANSIENT reader (${SUBSECS}s) — RTI PS replays to it =="
( cd "$REPO/interop/connext/shapes-sub" && stdbuf -oL ./shapes_sub 0 "$SUBSECS" ) > /tmp/spike-sub.log 2>&1
echo "   subscriber tail:"; tail -4 /tmp/spike-sub.log | sed 's/^/     /'

echo "== 6. stop relay, settle =="
cleanup
sleep 1

echo "== 7. analyze: RTI PS (0x80000002) per-sample inline-QoS PIDs + OWI byte vectors =="
python3 "$REPO/interop/durability-persistent/coexistence/analyze-capture.py" "$CAP" || true
echo "--- OWI byte-vector / origin cross-check (Branch A vs B) ---"
python3 "$REPO/interop/durability-persistent/coexistence/analyze-capture.py" --owi-dump "$CAP" || true

echo "== DONE. capture: $CAP =="
ls -la "$CAP"
