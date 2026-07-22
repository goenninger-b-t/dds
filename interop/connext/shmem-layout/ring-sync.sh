#!/bin/bash
# How does RTI signal data availability, and what guards the ring?
#
# Two System V semaphore sets accompany every segment (ADR 0081 SS4): 0x800000+port and 0xB00000+port.
# A static read shows the first at 0 with one process blocked waiting for it to increase, and the
# second at 1 with nobody waiting — which LOOKS like a counting "data available" semaphore plus a
# binary mutex. Looks-like is what the previous four corrections in this slice were made of, so it
# is tested: SIGSTOP the subscriber so nothing consumes, publish, and watch. A counting semaphore
# must climb once per message; a mutex must not.
#
# Only semctl GET* queries are issued — they read and never modify, so a live peer is not perturbed.
set -u
cd "$(dirname "$0")"
export NDDSHOME=${NDDSHOME:-/Applications/rti_connext_dds-7.3.1}
export DYLD_LIBRARY_PATH="$NDDSHOME/lib/${CONNEXTDDS_ARCH:-arm64Darwin20clang12.0}:${DYLD_LIBRARY_PATH:-}"
DOM=${DOM:-40}
WORK=$(mktemp -d)

start() { perl -e 'setpgrp(0,0); exec @ARGV' "$NDDSHOME/bin/rtiddsping" \
            -domainId "$DOM" "-$1" -sendPeriod 1 > "$WORK/$1.log" 2>&1 & echo $!; }
PUB=$(start publisher); SUB=$(start subscriber)
trap 'kill -CONT -- -$SUB 2>/dev/null; kill -TERM -- -$PUB -$SUB 2>/dev/null; sleep 1;
      kill -KILL -- -$PUB -$SUB 2>/dev/null; rm -rf "$WORK"' EXIT
sleep 10

KEY=""
for p in $((7400+250*DOM+11)) $((7400+250*DOM+13)); do
  k=$(printf '%x' $((0x400000 + p)))
  if [ "$(./shmprobe "$k" find 52545053 2>/dev/null | tail -1 | awk '{print $2}')" -gt 0 ] 2>/dev/null; then
      KEY=$k; PORT=$p
  fi
done
[ -n "$KEY" ] || { echo "no user segment carrying RTPS records"; exit 1; }
SEM=$(printf '%x' $((0x800000 + PORT))); MTX=$(printf '%x' $((0xB00000 + PORT)))
echo "# subscriber user port $PORT: segment 0x$KEY  semaphore 0x$SEM  mutex 0x$MTX"

line() {   # "<sem val> <sem waiters> | <mutex val> <mutex waiters> | cursor"
  local s m
  s=$(./semprobe "$SEM" | awk '/\[0\]/{gsub(/[a-z=-]+/,"",$2); gsub(/[a-z=-]+/,"",$3); print $2, $3}')
  m=$(./semprobe "$MTX" | awk '/\[0\]/{gsub(/[a-z=-]+/,"",$2); gsub(/[a-z=-]+/,"",$3); print $2, $3}')
  printf 'sem(val waiters)=%-8s mutex(val waiters)=%-8s cursor=%s\n' "$s" "$m" "$(./shmprobe "$KEY" u32 0x78 1)"
}

echo; echo "baseline — both running:"; for i in 1 2; do printf '  '; line; sleep 1; done
echo; echo "--- SIGSTOP the subscriber: nothing consumes ---"
kill -STOP -- -$SUB
for i in 1 2 3 4 5; do sleep 2; printf '  +%-3ds ' $((2*i)); line; done
echo; echo "--- SIGCONT: the backlog drains ---"
kill -CONT -- -$SUB
for i in 1 2 3; do sleep 2; printf '  +%-3ds ' $((2*i)); line; done
