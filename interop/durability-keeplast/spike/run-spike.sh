#!/usr/bin/env bash
# Spike: does RTI Connext 7.3.1 (and Fast DDS 3.6.1) put PID_KEY_HASH (0x0070, 16 octets,
# RTPS 2.5 §9.6.4.8) inline on keyed ShapeType DATA-with-payload samples (not just dispose)?
# Wire-only investigation — no src/ changes.
#
# Run from repo root:  interop/durability-keeplast/spike/run-spike.sh
# Env: SECS (capture window per peer, default 8), CONNEXTDDS_ARCH (default arm64Darwin20clang12.0)
set -uo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
HERE="$REPO/interop/durability-keeplast/spike"
TSHARK="/Applications/Wireshark.app/Contents/MacOS/tshark"
export NDDSHOME="${NDDSHOME:-/Applications/rti_connext_dds-7.3.1}"
export CONNEXTDDS_ARCH="${CONNEXTDDS_ARCH:-arm64Darwin20clang12.0}"
CONNEXT_PUB="$REPO/interop/connext/shapes-pub"
FASTDDS_PUB="$REPO/interop/fastdds/shapes"
SECS="${SECS:-8}"

mkdir -p "$HERE/captures"

cleanup_pub() {
  pkill -f shapes_pub >/dev/null 2>&1 || true
}
trap cleanup_pub EXIT

# ──────────────────────────────────────────────────────────────────────────────
# LEG 1: Connext 7.3.1 — write keyed Square/ShapeType (color=BLUE), capture lo0
# ──────────────────────────────────────────────────────────────────────────────
echo "=== LEG 1: Connext 7.3.1 keyed ShapeType pub (BLUE) ==="
CAP_CONNEXT="$HERE/captures/connext-keyed.pcap"

# Use loopback-only QoS so all traffic hits lo0 regardless of LAN address.
cp "$HERE/connext-loopback-qos.xml" "$CONNEXT_PUB/USER_QOS_PROFILES.xml"
export DYLD_LIBRARY_PATH="$NDDSHOME/lib/$CONNEXTDDS_ARCH"

echo "  starting tshark on lo0 -> $CAP_CONNEXT"
WIRESHARK_CONFIG_DIR=$(mktemp -d) \
  "$TSHARK" -i lo0 -f "udp portrange 7400-7700" -w "$CAP_CONNEXT" >/dev/null 2>&1 &
TSHARK_PID=$!
sleep 2

echo "  starting Connext shapes_pub (Square, BLUE, reliable) for ${SECS}s"
( cd "$CONNEXT_PUB" && exec ./shapes_pub 0 BLUE ) >/dev/null 2>&1 &
PUB_PID=$!
sleep "$SECS"
kill "$PUB_PID" 2>/dev/null || true
sleep 1
kill "$TSHARK_PID" 2>/dev/null || true
sleep 1

# Restore original QoS file
git -C "$REPO" checkout -- "$CONNEXT_PUB/USER_QOS_PROFILES.xml" 2>/dev/null || true

echo "  capture complete ($(wc -c < "$CAP_CONNEXT" 2>/dev/null || echo '?') bytes)"
echo ""
echo "  === Connext PID_KEY_HASH decode ==="
python3 "$HERE/decode-keyhash.py" "$CAP_CONNEXT"

# ──────────────────────────────────────────────────────────────────────────────
# LEG 2: Fast DDS 3.6.1 — write keyed Square/ShapeType (color=BLUE), capture lo0
# ──────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== LEG 2: Fast DDS 3.6.1 keyed ShapeType pub (BLUE) ==="
CAP_FASTDDS="$HERE/captures/fastdds-keyed.pcap"

FASTDDS_BIN="$FASTDDS_PUB/shapes_pub"
if [ ! -x "$FASTDDS_BIN" ]; then
  echo "  SKIPPED: Fast DDS shapes_pub not found at $FASTDDS_BIN"
else
  # Check runtime shared library availability
  FASTDDS_LIB_OK=true
  if ! DYLD_LIBRARY_PATH="" "$FASTDDS_BIN" --help >/dev/null 2>&1 && \
     ! DYLD_LIBRARY_PATH="/usr/local/lib" "$FASTDDS_BIN" --help >/dev/null 2>&1; then
    FASTDDS_LIB_OK=false
  fi

  if ! "$FASTDDS_LIB_OK"; then
    echo "  SKIPPED: Fast DDS shapes_pub found but runtime libs not loadable"
  else
    echo "  starting tshark on lo0 -> $CAP_FASTDDS"
    WIRESHARK_CONFIG_DIR=$(mktemp -d) \
      "$TSHARK" -i lo0 -f "udp portrange 7400-7700" -w "$CAP_FASTDDS" >/dev/null 2>&1 &
    TSHARK_PID2=$!
    sleep 2

    echo "  starting Fast DDS shapes_pub (Square, BLUE) for ${SECS}s"
    # Fast DDS reads profiles.xml from cwd; use the loopback profile
    ( cd "$FASTDDS_PUB" && FASTRTPS_DEFAULT_PROFILES_FILE=./profiles.xml \
        exec ./shapes_pub 0 BLUE ) >/dev/null 2>&1 &
    PUB2_PID=$!
    sleep "$SECS"
    kill "$PUB2_PID" 2>/dev/null || true
    sleep 1
    kill "$TSHARK_PID2" 2>/dev/null || true
    sleep 1

    echo "  capture complete ($(wc -c < "$CAP_FASTDDS" 2>/dev/null || echo '?') bytes)"
    echo ""
    echo "  === Fast DDS PID_KEY_HASH decode ==="
    python3 "$HERE/decode-keyhash.py" "$CAP_FASTDDS"
  fi
fi

echo ""
echo "=== SPIKE COMPLETE ==="
