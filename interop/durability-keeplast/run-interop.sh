#!/usr/bin/env bash
# KEEP_LAST per-instance compaction interop — restart-seed scenario (M6/P5, ADR 0029).
#
# Proves: per-instance KEEP_LAST(D) bounds the replay to D samples after a process restart.
# KEEP_LAST manifests via the file-store compaction-on-open (restart-seed path), NOT the
# live-late-joiner path (which replays KEEP_ALL publish-on-collect — documented nuance).
#
# Scenario:
#   Process 1 (driver-collect.lisp):  service collects M samples, persists to disk, EXITS.
#   Process 2 (driver-serve.lisp):    store-open with :keep-last D → compaction-on-open → D
#                                     newest per instance survive → %seed-relay-from-store
#                                     seeds the replay writer with D records.
#   Late-joining foreign subscriber:  receives exactly D, not M.
#
# Run from repo root:  interop/durability-keeplast/run-interop.sh
# Env: DKL_SECS (collect window), DKL_DEPTH (default 2), CONNEXTDDS_ARCH
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HERE="$REPO/interop/durability-keeplast"
TSHARK="/Applications/Wireshark.app/Contents/MacOS/tshark"
export NDDSHOME="${NDDSHOME:-/Applications/rti_connext_dds-7.3.1}"
export CONNEXTDDS_ARCH="${CONNEXTDDS_ARCH:-arm64Darwin20clang12.0}"
export DYLD_LIBRARY_PATH="$NDDSHOME/lib/$CONNEXTDDS_ARCH"
FASTDDS_LIB="${FASTDDS_LIB:-/Users/frgo/gbt Dropbox/gbt/projects/fastdds/install/lib}"

DKL_DEPTH="${DKL_DEPTH:-2}"
COLLECT_SECS="${DKL_SECS:-35}"
SERVE_SECS=60
PUB_SECS=20
SUB_SECS=25

mkdir -p "$HERE/captures"

cleanup() {
  pkill -f shapes_pub >/dev/null 2>&1 || true
  pkill -f shapes_sub >/dev/null 2>&1 || true
}
trap cleanup EXIT

# ──────────────────────────────────────────────────────────────────────────────
# LEG 1: Connext publisher → collect M → restart → KEEP_LAST D → late Connext sub
# ──────────────────────────────────────────────────────────────────────────────
echo "=== LEG 1: Connext → KEEP_LAST(D=$DKL_DEPTH) restart-seed ==="
rm -rf /tmp/dkl-D /tmp/dkl-K

CAP1="$HERE/captures/leg1-keeplast-connext.pcap"
WIRESHARK_CONFIG_DIR=$(mktemp -d) "$TSHARK" -i lo0 -f "udp portrange 7400-7700" \
  -w "$CAP1" >/dev/null 2>&1 & TSHARK1=$!
sleep 2

DKL_DIR=/tmp/dkl-D DKL_KEYDIR=/tmp/dkl-K DKL_SECS="$COLLECT_SECS" DKL_DEPTH="$DKL_DEPTH" \
  "$REPO/scripts/with-sbcl.sh" --load "$HERE/driver-collect.lisp" & PROC1=$!
sleep 8

echo "  starting Connext pub (GREEN, ~${PUB_SECS}s)"
( cd "$HERE" && stdbuf -oL ../connext/shapes-pub/shapes_pub 0 GREEN ) >/dev/null 2>&1 & PUB=$!
sleep "$PUB_SECS"
kill "$PUB" 2>/dev/null || true
wait "$PROC1" 2>/dev/null; echo "  proc1 exited"
kill "$TSHARK1" 2>/dev/null || true; sleep 1

echo "  starting proc2 (KEEP_LAST $DKL_DEPTH, compaction-on-open)..."
DKL_DIR=/tmp/dkl-D DKL_KEYDIR=/tmp/dkl-K DKL_SECS="$SERVE_SECS" DKL_DEPTH="$DKL_DEPTH" \
  "$REPO/scripts/with-sbcl.sh" --load "$HERE/driver-serve.lisp" & PROC2=$!
sleep 40

echo "  starting late Connext sub (${SUB_SECS}s)..."
( cd "$HERE" && stdbuf -oL ../connext/shapes-sub/shapes_sub 0 "$SUB_SECS" )
kill "$PROC2" 2>/dev/null || true; wait "$PROC2" 2>/dev/null || true

# ──────────────────────────────────────────────────────────────────────────────
# LEG 2: Fast DDS publisher → collect M → restart → KEEP_LAST D → late Fast DDS sub
# ──────────────────────────────────────────────────────────────────────────────
FASTDDS_SHAPES="$REPO/interop/fastdds/shapes"
if [ ! -x "$FASTDDS_SHAPES/shapes_pub" ] || [ ! -d "$FASTDDS_LIB" ]; then
  echo "=== LEG 2: SKIPPED — Fast DDS binary/libs not found (set FASTDDS_LIB) ==="
else
  echo "=== LEG 2: Fast DDS → KEEP_LAST(D=$DKL_DEPTH) restart-seed ==="
  rm -rf /tmp/dkl-D /tmp/dkl-K

  export DYLD_LIBRARY_PATH="$FASTDDS_LIB"
  cp "$HERE/fastdds-profiles.xml" "$FASTDDS_SHAPES/profiles.xml"

  CAP2="$HERE/captures/leg2-keeplast-fastdds.pcap"
  WIRESHARK_CONFIG_DIR=$(mktemp -d) "$TSHARK" -i lo0 -f "udp portrange 7400-7700" \
    -w "$CAP2" >/dev/null 2>&1 & TSHARK2=$!
  sleep 2

  DKL_DIR=/tmp/dkl-D DKL_KEYDIR=/tmp/dkl-K DKL_SECS="$COLLECT_SECS" DKL_DEPTH="$DKL_DEPTH" \
    "$REPO/scripts/with-sbcl.sh" --load "$HERE/driver-collect.lisp" & PROC1B=$!
  sleep 8

  echo "  starting Fast DDS pub (GREEN, 200 samples, TL)"
  ( cd "$FASTDDS_SHAPES" && DURABILITY=transient_local stdbuf -oL ./shapes_pub GREEN 200 ) \
    >/dev/null 2>&1 & PUB2=$!
  sleep 15; kill "$PUB2" 2>/dev/null || true
  wait "$PROC1B" 2>/dev/null; echo "  proc1b exited"
  kill "$TSHARK2" 2>/dev/null || true; sleep 1

  echo "  starting proc2b (KEEP_LAST $DKL_DEPTH, compaction-on-open)..."
  DKL_DIR=/tmp/dkl-D DKL_KEYDIR=/tmp/dkl-K DKL_SECS="$SERVE_SECS" DKL_DEPTH="$DKL_DEPTH" \
    "$REPO/scripts/with-sbcl.sh" --load "$HERE/driver-serve.lisp" & PROC2B=$!
  sleep 40

  echo "  starting late Fast DDS sub (${SUB_SECS}s)..."
  ( cd "$FASTDDS_SHAPES" && DURABILITY=transient_local stdbuf -oL ./shapes_sub "$SUB_SECS" )
  kill "$PROC2B" 2>/dev/null || true; wait "$PROC2B" 2>/dev/null || true
fi

echo "=== INTEROP COMPLETE ==="
