#!/usr/bin/env bash
# Discovery-driven dynamic-topic-add cross-vendor interop (ADR 0026 Phase-2b, :auto-discover).
#
# Proves ON THE WIRE: our durability service, started with an EMPTY topic list + :auto-discover,
# sees a FOREIGN (RTI Connext / eProsima Fast DDS) publisher for an UNCONFIGURED topic
# (Square/ShapeType), parses that vendor's SEDP DiscoveredWriterData (PID_TOPIC_NAME +
# PID_TYPE_NAME), auto-adds + collects it as opaque bytes (no type registration), then serves a
# FOREIGN late-joiner subscriber the collected history from our replay writer.
#
# Single long-running process (auto-discover needs no restart). SBCL-only driver (NFR-PORT).
# Run from repo root:  interop/durability-persistent/run-autodiscover.sh
# Env: DAD_SECS (driver up-time), DAD_PUB_SECS, DAD_SUB_SECS, DAD_BACKEND (file|sqlite|memory),
#      FASTDDS_LIB, CONNEXTDDS_ARCH, NDDSHOME.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HERE="$REPO/interop/durability-persistent"
TSHARK="/Applications/Wireshark.app/Contents/MacOS/tshark"
export NDDSHOME="${NDDSHOME:-/Applications/rti_connext_dds-7.3.1}"
export CONNEXTDDS_ARCH="${CONNEXTDDS_ARCH:-arm64Darwin20clang12.0}"
FASTDDS_LIB="${FASTDDS_LIB:-/Users/frgo/gbt Dropbox/gbt/projects/fastdds/install/lib}"

DAD_SECS="${DAD_SECS:-110}"
STARTUP_SECS="${DAD_STARTUP_SECS:-15}"
PUB_SECS="${DAD_PUB_SECS:-25}"
SUB_SECS="${DAD_SUB_SECS:-30}"
BACKEND="${DAD_BACKEND:-file}"

mkdir -p "$HERE/captures" "$HERE/logs"

DRIVER_PID="" ; PUB_PID="" ; TSHARK_PID=""
cleanup() {
  [ -n "$DRIVER_PID" ] && kill "$DRIVER_PID" 2>/dev/null || true
  pkill -f shapes_pub >/dev/null 2>&1 || true
  pkill -f shapes_sub >/dev/null 2>&1 || true
  [ -n "$TSHARK_PID" ] && kill "$TSHARK_PID" 2>/dev/null || true
}
trap cleanup EXIT

confirm_pub_gone() {  # kill any shapes_pub and wait until none remain
  pkill -f "shapes-pub/shapes_pub" >/dev/null 2>&1 || true
  pkill -f "shapes/shapes_pub"     >/dev/null 2>&1 || true
  for _ in $(seq 1 20); do
    [ "$(pgrep -f 'shapes_pub' | wc -l | tr -d ' ')" = "0" ] && return 0
    sleep 0.3
  done
  echo "  WARNING: a shapes_pub is still alive"; return 0
}

assert_leg() {  # $1=label $2=driver-log $3=sub-log
  local label="$1" dlog="$2" slog="$3" ok=1
  local added collected received
  added=$(grep -c 'DAD-AUTO-ADDED' "$dlog" 2>/dev/null || echo 0)
  collected=$(grep 'DAD-COLLECTED Square=' "$dlog" 2>/dev/null | tail -1 | sed -E 's/.*Square=([0-9]+).*/\1/' || echo 0)
  received=$(grep -iE 'received [0-9]+' "$slog" 2>/dev/null | tail -1 | sed -E 's/.*received ([0-9]+).*/\1/' || echo 0)
  [ -z "$collected" ] && collected=0
  [ -z "$received" ] && received=0
  echo "  --- $label RESULT: auto-added=$added  collected(Square)=$collected  sub-received-lines=$received"
  [ "$added" -ge 1 ] || { echo "  FAIL: auto-add did not fire (foreign SEDP not parsed into an add)"; ok=0; }
  [ "$collected" -ge 1 ] || { echo "  FAIL: nothing collected on the auto-added topic"; ok=0; }
  [ "$received" -ge 1 ] || { echo "  FAIL: foreign late-joiner received nothing from the replay writer"; ok=0; }
  [ "$ok" = 1 ] && echo "  *** $label PASS ***" || echo "  *** $label FAIL ***"
  return 0
}

# ── LEG 1: Connext ────────────────────────────────────────────────────────────
echo "=== LEG 1: Connext publisher → our :auto-discover → foreign late Connext sub (backend=$BACKEND) ==="
rm -rf /tmp/dad-D /tmp/dad-K
export DYLD_LIBRARY_PATH="$NDDSHOME/lib/$CONNEXTDDS_ARCH"
DLOG1="$HERE/logs/autodiscover-leg1-driver.log" ; SLOG1="$HERE/logs/autodiscover-leg1-sub.log"

CAP1="$HERE/captures/autodiscover-leg1-connext.pcap"
WIRESHARK_CONFIG_DIR=$(mktemp -d) "$TSHARK" -i lo0 -f "udp portrange 7400-7700" \
  -w "$CAP1" >/dev/null 2>&1 & TSHARK_PID=$!
sleep 2

DAD_DIR=/tmp/dad-D DAD_KEYDIR=/tmp/dad-K DAD_SECS="$DAD_SECS" DAD_BACKEND="$BACKEND" \
  "$REPO/scripts/with-sbcl.sh" --load "$HERE/driver-autodiscover.lisp" 2>&1 | tee "$DLOG1" & DRIVER_PID=$!
echo "  service up (EMPTY start-list, :auto-discover) — waiting ${STARTUP_SECS}s for load+start"
sleep "$STARTUP_SECS"

echo "  starting Connext pub (GREEN, TL) on Square/ShapeType — a topic the service was NOT configured for"
( cd "$HERE" && stdbuf -oL ../connext/shapes-pub/shapes_pub 0 GREEN ) >/dev/null 2>&1 & PUB_PID=$!
sleep "$PUB_SECS"
kill "$PUB_PID" 2>/dev/null || true; confirm_pub_gone
echo "  pub confirmed gone — starting late Connext sub (${SUB_SECS}s), expecting the auto-served history"
( cd "$HERE" && stdbuf -oL ../connext/shapes-sub/shapes_sub 0 "$SUB_SECS" ) 2>&1 | tee "$SLOG1"

kill "$DRIVER_PID" 2>/dev/null || true; wait "$DRIVER_PID" 2>/dev/null || true; DRIVER_PID=""
kill "$TSHARK_PID" 2>/dev/null || true; TSHARK_PID=""; sleep 1
assert_leg "LEG 1 Connext" "$DLOG1" "$SLOG1"

# ── LEG 2: Fast DDS ──────────────────────────────────────────────────────────
FASTDDS_SHAPES="$REPO/interop/fastdds/shapes"
if [ ! -x "$FASTDDS_SHAPES/shapes_pub" ] || [ ! -d "$FASTDDS_LIB" ]; then
  echo "=== LEG 2: SKIPPED — Fast DDS binary/libs not found (set FASTDDS_LIB) ==="
else
  echo "=== LEG 2: Fast DDS publisher → our :auto-discover → foreign late Fast DDS sub ==="
  rm -rf /tmp/dad-D /tmp/dad-K
  export DYLD_LIBRARY_PATH="$FASTDDS_LIB"
  cp "$HERE/fastdds-profiles.xml" "$FASTDDS_SHAPES/profiles.xml"
  DLOG2="$HERE/logs/autodiscover-leg2-driver.log" ; SLOG2="$HERE/logs/autodiscover-leg2-sub.log"

  CAP2="$HERE/captures/autodiscover-leg2-fastdds.pcap"
  WIRESHARK_CONFIG_DIR=$(mktemp -d) "$TSHARK" -i lo0 -f "udp portrange 7400-7700" \
    -w "$CAP2" >/dev/null 2>&1 & TSHARK_PID=$!
  sleep 2

  DAD_DIR=/tmp/dad-D DAD_KEYDIR=/tmp/dad-K DAD_SECS="$DAD_SECS" DAD_BACKEND="$BACKEND" \
    "$REPO/scripts/with-sbcl.sh" --load "$HERE/driver-autodiscover.lisp" 2>&1 | tee "$DLOG2" & DRIVER_PID=$!
  echo "  service up (EMPTY start-list, :auto-discover) — waiting ${STARTUP_SECS}s for load+start"
  sleep "$STARTUP_SECS"

  echo "  starting Fast DDS pub (GREEN, 200, TL) on Square/ShapeType — NOT configured at the service"
  ( cd "$FASTDDS_SHAPES" && DURABILITY=transient_local stdbuf -oL ./shapes_pub GREEN 200 ) \
    >/dev/null 2>&1 & PUB_PID=$!
  sleep "$PUB_SECS"
  kill "$PUB_PID" 2>/dev/null || true; confirm_pub_gone
  echo "  pub confirmed gone — starting late Fast DDS sub (${SUB_SECS}s), expecting the auto-served history"
  ( cd "$FASTDDS_SHAPES" && DURABILITY=transient_local stdbuf -oL ./shapes_sub "$SUB_SECS" ) 2>&1 | tee "$SLOG2"

  kill "$DRIVER_PID" 2>/dev/null || true; wait "$DRIVER_PID" 2>/dev/null || true; DRIVER_PID=""
  kill "$TSHARK_PID" 2>/dev/null || true; TSHARK_PID=""
  assert_leg "LEG 2 Fast DDS" "$DLOG2" "$SLOG2"
fi

echo "=== AUTO-DISCOVER INTEROP COMPLETE ==="
