#!/bin/bash
# Where does a record with a given cursor value actually LAND, and where does the ring wrap?
#
# The cursor is a cumulative byte count, not an offset (ADR 0081 SS5.0), so the mapping from cursor to
# write offset has to be observed rather than assumed. This snapshots the whole segment once per
# second alongside the cursor and diffs consecutive snapshots: the bytes that changed ARE the record
# just written, so each sample yields a (cursor, write-offset) pair. When the write offset jumps
# backwards, that is the wrap, and the span it covers is the ring extent.
#
# Observation only; nothing is written to any Connext segment.
set -u
cd "$(dirname "$0")"
export NDDSHOME=${NDDSHOME:-/Applications/rti_connext_dds-7.3.1}
export DYLD_LIBRARY_PATH="$NDDSHOME/lib/${CONNEXTDDS_ARCH:-arm64Darwin20clang12.0}:${DYLD_LIBRARY_PATH:-}"
DOM=${DOM:-25}
MSM=${MSM:-2048}          # must clear the ~1020-octet SPDP announcement or discovery fails outright
CNT=${CNT:-8}
RBS=${RBS:-2048}
ITERS=${ITERS:-70}
WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT

cat > extent-qos.xml <<EOF
<?xml version="1.0"?>
<dds><qos_library name="ExtLib"><qos_profile name="E">
  <domain_participant_qos>
    <transport_builtin><mask>UDPv4 | SHMEM</mask></transport_builtin>
    <property><value>
      <element><name>dds.transport.shmem.builtin.received_message_count_max</name><value>$CNT</value></element>
      <element><name>dds.transport.shmem.builtin.receive_buffer_size</name><value>$RBS</value></element>
      <element><name>dds.transport.shmem.builtin.parent.message_size_max</name><value>$MSM</value></element>
    </value></property>
  </domain_participant_qos>
</qos_profile></qos_library></dds>
EOF

start() { perl -e 'setpgrp(0,0); exec @ARGV' "$NDDSHOME/bin/rtiddsping" \
            -domainId "$DOM" "-$1" -sendPeriod 1 -qosFile ./extent-qos.xml -qosProfile ExtLib::E \
            > "$WORK/$1.log" 2>&1 & echo $!; }
PUB=$(start publisher); SUB=$(start subscriber)
trap 'kill -TERM -- -$PUB -$SUB 2>/dev/null; sleep 1; kill -KILL -- -$PUB -$SUB 2>/dev/null; rm -rf "$WORK"' EXIT
sleep 8

KEY=""
for p in $((7400+250*DOM+11)) $((7400+250*DOM+13)); do
  k=$(printf '%x' $((0x400000 + p)))
  if [ "$(./shmprobe "$k" find 52545053 2>/dev/null | tail -1 | awk '{print $2}')" -gt 0 ] 2>/dev/null; then
      KEY=$k; PORT=$p
  fi
done
[ -n "$KEY" ] || { echo "no user segment carrying RTPS records"; exit 1; }
SIZE=$(./shmprobe "$KEY" u32 0x0c 1); BASE=$(./shmprobe "$KEY" u32 0x50 1)
echo "# segment 0x$KEY port $PORT size=$SIZE  0x50=$BASE  rbs=$RBS msm=$MSM cnt=$CNT"
echo "# cursor = producer running total (0x78); changed = byte range that differs from the previous snapshot"
printf '%-6s %-10s %-18s %s\n' iter cursor 'changed bytes' note

./shmprobe "$KEY" dump 0 "$SIZE" > "$WORK/prev.txt" 2>/dev/null
prev_lo=0
for i in $(seq 1 "$ITERS"); do
  sleep 1
  cur=$(./shmprobe "$KEY" u32 0x78 1)
  ./shmprobe "$KEY" dump 0 "$SIZE" > "$WORK/now.txt" 2>/dev/null
  # Changed lines, ignoring the control region below the ring base, are the record just written.
  # perl, not awk: BSD awk on macOS has no strtonum, so hex parsing must not rely on it.
  rng=$(diff "$WORK/prev.txt" "$WORK/now.txt" | BASE="$BASE" perl -ne '
        if (/^> ([0-9a-f]+) /) { my $o = hex($1); next if $o < $ENV{BASE};
                                 $lo = $o if !defined $lo || $o < $lo;
                                 $hi = $o if !defined $hi || $o > $hi; }
        END { defined $lo ? printf("%d..%d", $lo, $hi + 15) : print "-" }')
  lo=${rng%%..*}
  note=""
  if [ "$lo" != "-" ] && [ "$lo" -lt "$prev_lo" ] 2>/dev/null; then note="<<< WRAPPED (was at $prev_lo)"; fi
  [ "$lo" != "-" ] && prev_lo=$lo
  printf '%-6s %-10s %-18s %s\n' "$i" "$cur" "$rng" "$note"
  mv "$WORK/now.txt" "$WORK/prev.txt"
done
