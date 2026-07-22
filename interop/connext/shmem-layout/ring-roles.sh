#!/bin/bash
# Which of the two 56-byte control blocks is the PRODUCER and which the CONSUMER?
#
# Decisive because the reader is STOPPED rather than reasoned about: SIGSTOP the subscriber so it
# cannot consume, let the publisher keep sending, and see which block still advances. Then SIGCONT
# and watch the other catch up. Observation only — nothing is written to any Connext segment.
set -u
cd "$(dirname "$0")"
export NDDSHOME=${NDDSHOME:-/Applications/rti_connext_dds-7.3.1}
export DYLD_LIBRARY_PATH="$NDDSHOME/lib/${CONNEXTDDS_ARCH:-arm64Darwin20clang12.0}:${DYLD_LIBRARY_PATH:-}"
DOM=${DOM:-21}
BLOCK_A=0x78          # ADR 0081 SS5.0 — the two control blocks, 56 bytes apart
BLOCK_B=0xb0

snap() {              # $1=key  -> "A: <8 u32s> | B: <8 u32s>"
  printf 'A: %s | B: %s\n' "$(./shmprobe "$1" u32 $BLOCK_A 8)" "$(./shmprobe "$1" u32 $BLOCK_B 8)"
}

start() {             # $1=role -> echoes the pgid
  perl -e 'setpgrp(0,0); exec @ARGV' \
      "$NDDSHOME/bin/rtiddsping" -domainId "$DOM" "-$1" -sendPeriod 1 > "ring-$1.log" 2>&1 &
  echo $!
}

PUB=$(start publisher); SUB=$(start subscriber)
trap 'kill -CONT -- -$SUB 2>/dev/null; kill -TERM -- -$PUB -$SUB 2>/dev/null; sleep 1;
      kill -KILL -- -$PUB -$SUB 2>/dev/null' EXIT
sleep 10

# The subscriber's user segment is whichever user port actually holds RTPS records.
KEY=""
for p in $((7400+250*DOM+11)) $((7400+250*DOM+13)); do
  k=$(printf '%x' $((0x400000 + p)))
  if [ "$(./shmprobe "$k" find 52545053 2>/dev/null | tail -1 | awk '{print $2}')" -gt 0 ] 2>/dev/null; then
      KEY=$k; PORT=$p
  fi
done
[ -n "$KEY" ] || { echo "no user segment carrying RTPS records — did the pair match?"; exit 1; }
echo "# subscriber user segment: port $PORT key 0x$KEY"
echo "# each line: the two control blocks at $BLOCK_A and $BLOCK_B"
echo; echo "baseline (both running):"; snap "$KEY"

echo; echo "--- SIGSTOP the subscriber: it can no longer consume ---"
kill -STOP -- -$SUB
for i in 1 2 3; do sleep 2; printf '  +%ds  ' $((2*i)); snap "$KEY"; done

echo; echo "--- SIGCONT the subscriber: it drains the backlog ---"
kill -CONT -- -$SUB
for i in 1 2; do sleep 2; printf '  +%ds  ' $((2*i)); snap "$KEY"; done

echo; echo "The block that ADVANCED while the subscriber was stopped is the PRODUCER."
