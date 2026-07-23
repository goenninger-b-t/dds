#!/bin/bash
# Shared staging for the live RTI Connext shared-memory experiments (ADR 0081 slices 7b/7c).
#
# Sourced, never executed. It owns the three things every live run needs and got wrong at least once:
# the Connext environment, finding the ring, and FREEZING the publisher without killing it.
#
# NEVER point any of this at a production peer. Every function works on a throwaway domain of its own.

REPO="/Users/frgo/gbt Dropbox/gbt/projects/hofvarpnir"
export NDDSHOME=${NDDSHOME:-/Applications/rti_connext_dds-7.3.1}
ARCH=${CONNEXTDDS_ARCH:-arm64Darwin20clang12.0}
export DYLD_LIBRARY_PATH="$NDDSHOME/lib/$ARCH:${DYLD_LIBRARY_PATH:-}"
PROBE=./shmprobe

# stage_peers <domain> <pub-log> <sub-log> -> sets SUB and PUB to PROCESS GROUP ids.
#
# Each peer is launched via perl setpgrp so it leads its own process group: rtiddsping is a /bin/sh wrapper
# that SPAWNS the real arm64 binary as a child, so signalling the wrapper pid alone leaves the real
# publisher running and writing — which contaminated a whole live run before this was understood.
stage_peers() {
  local dom=$1 publog=$2 sublog=$3
  perl -e 'setpgrp(0,0); exec @ARGV' "$NDDSHOME/bin/rtiddsping" -domainId "$dom" -subscriber \
       > "$sublog" 2>&1 &  SUB=$!
  perl -e 'setpgrp(0,0); exec @ARGV' "$NDDSHOME/bin/rtiddsping" -domainId "$dom" -publisher -sendPeriod 1 \
       > "$publog" 2>&1 & PUB=$!
}

# find_ring <domain> -> sets KEY (hex segment key) and PORT, or returns 1.
#
# Scans the USER-traffic ports of participant indices 0..3 (RTPS 2.5 §9.6.1.1: PB + DG*domain + d3 + PG*index)
# and keeps the one whose segment contains RTPS records. A scan that silently finds nothing is
# indistinguishable from a system with nothing to find, so the full index range is always covered.
find_ring() {
  local dom=$1 i d p k n
  KEY=""; PORT=""
  for i in 0 1 2 3; do
    for d in 11 13; do
      p=$((7400 + 250*dom + d + 2*i)); k=$(printf '%x' $((0x400000 + p)))
      n=$($PROBE "$k" find 52545053 2>/dev/null | tail -1 | awk '{print $2}')
      [ "${n:-0}" -gt 2 ] 2>/dev/null && { KEY=$k; PORT=$p; }
    done
  done
  [ -n "$KEY" ]
}

# freeze_publisher <pub-pgid> <port>
#
# SIGSTOP, never SIGKILL. Killing the publisher makes RTI's consumer detect the writer's death and UNMATCH
# it, after which it will not consume from that source no matter how correct the record is — three live runs
# were wasted on that before it was named. Frozen, the publisher writes nothing (the ring goes static) but
# stays matched, and the consumer keeps listening on the data semaphore.
#
# Mutex safety: the freeze can (rarely — the lock is held ~210 ns per message) catch the publisher holding
# the ring mutex, which would then stay locked while it is stopped and block our write. Thaw and refreeze
# until the mutex reads free.
freeze_publisher() {
  local pub=$1 port=$2 mtxkey try
  kill -STOP -- -"$pub" 2>/dev/null; sleep 1
  mtxkey=$(printf '%x' $((0xB00000 + port)))
  MUTEX=1
  for try in 1 2 3 4 5; do
    MUTEX=$(./semprobe "$mtxkey" 2>/dev/null | awk '/\[0\]/{gsub(/[a-z=-]+/,"",$2); print $2}')
    [ "${MUTEX:-0}" = "1" ] && break
    echo "# mutex held (=$MUTEX) — thaw+refreeze (try $try)"
    kill -CONT -- -"$pub" 2>/dev/null; sleep 0.2
    kill -STOP  -- -"$pub" 2>/dev/null; sleep 0.3
  done
}

# teardown_hint <domain> — print the owner-run cleanup. System V segments OUTLIVE their process, so a run
# that is not cleaned up leaves the next one to find stale segments. Never touches domain 0's 0x00401cf*
# (the owner's production shapes_pub).
teardown_hint() {
  echo "# teardown: kill any leftover rtiddsping and remove this run's IPC:"
  echo "#   pkill -9 -f rtiddsping"
  echo "#   for id in \$(ipcs -m | awk '\$3 ~ /^0x0040/ && \$3 !~ /1cf/ {print \$2}'); do ipcrm -m \$id; done"
  echo "#   for id in \$(ipcs -s | awk '(\$3~/^0x0080/||\$3~/^0x00b0/) && \$3!~/1cf/ {print \$2}'); do ipcrm -s \$id; done"
}
