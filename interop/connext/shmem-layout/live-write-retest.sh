#!/bin/bash
# ADR 0081 slice 7b — RING-LEVEL acceptance: does RTI's consumer drain a record this stack wrote?
#
# It stages a THROWAWAY rtiddsping pair, captures a real record out of the subscriber's ring, FREEZES the
# publisher, replays that record verbatim, and reports whether RTI's CONSUMER position and counter advance.
# That is the whole question here; application-level delivery is a different one, and a verbatim replay
# cannot answer it (the sequence number has already been delivered) — see live-userdata-retest.sh.
#
# Runs entirely in the owner's shell: writing into another process's shared memory is gated for the agent.
# NEVER point this at a production peer. It uses its own domain; only the throwaway pair is touched.
#
#   DOM=70 ./live-write-retest.sh
set -u
cd "$(dirname "$0")" || exit 1
. ./ring-lib.sh
DOM=${DOM:-70}
PUBLOG=/tmp/rt-pub.log
SUBLOG=/tmp/rt-sub.log
HEX=/tmp/rt-record.hex
make -s all || exit 1

stage_peers "$DOM" "$PUBLOG" "$SUBLOG"
sleep 6

if ! find_ring "$DOM"; then
  echo "# no ring found on domain $DOM"
  kill -9 -- -"$SUB" -"$PUB" 2>/dev/null; exit 1
fi

# While the LIVE producer still runs, map the descriptor SLOT rule: sample the counter (block A index 7 at
# 0x94) and the descriptor table (0xe8) twice, ~1.5s apart. Which slot gains an entry as the counter
# increments gives slot(counter) directly — this is how the off-by-one in the slot index was found.
slotdump() {
  local c; c=$($PROBE "$KEY" u32 0x94 1)
  echo "#   counter(0x94)=$c  descriptor slots 0..31 (first u32, signed):"
  $PROBE "$KEY" u32 0xe8 64 | awk '{for(i=1;i<=NF;i+=2){v=$i; s=(i-1)/2; d=(v>2147483647?v-4294967296:v); if(d!=0) printf "    slot%d=%d\n",s,d}}'
}
echo "# --- descriptor slot mapping (live producer) ---"; slotdump; sleep 1.5; echo "#   (1.5s later)"; slotdump

# Capture one real record. A fixed window is dumped rather than an exact length: the replay determines the
# record's exact extent from the submessage chain (RTPS is self-delimiting), which is one fewer measured
# quantity the capture has to get right.
O=$($PROBE "$KEY" find 52545053 2>/dev/null | grep '^hit' | sed -n '2p' | awk '{print $4}' | tr -d '()')
$PROBE "$KEY" dump "$O" 192 | sed -n '2,13p' | sed 's/|.*//' | awk '{$1="";print}' | tr -s ' ' | tr -d '\n' \
  | sed 's/^ //' > "$HEX"
echo "# ring 0x$KEY at RTPS port $PORT — captured the record at offset $O"

freeze_publisher "$PUB" "$PORT"
echo "# publisher FROZEN (consumer stays matched); ring mutex=$MUTEX, ring static"

RTI_MODE=replay RTI_PORT="$PORT" RTI_HEX="$HEX" "$REPO/scripts/with-sbcl.sh" --non-interactive \
  --load "$REPO/interop/connext/shmem-layout/ring-records.lisp" 2>&1 | grep '<<RT>>'

echo "# sub 'issue received' count: $(grep -c 'issue received' "$SUBLOG")"
echo "#   (a verbatim replay is a DUPLICATE sequence number, so this count is NOT expected to move —"
echo "#    live-userdata-retest.sh is the run that tests application delivery)"
kill -9 -- -"$SUB" -"$PUB" 2>/dev/null
teardown_hint "$DOM"
