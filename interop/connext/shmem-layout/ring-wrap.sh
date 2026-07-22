#!/bin/bash
# Where does the ring wrap, and what does the producer position do when it does?
#
# The default ring is 1 MiB and records are ~64 bytes, so wrapping it naturally would take ~16000
# messages. Instead the ring is SHRUNK through Connext's own documented QoS until it wraps in a
# handful of messages — the same controlled-variation lever used to identify the property block.
# Observation only; nothing is written to any Connext segment.
set -u
cd "$(dirname "$0")"
export NDDSHOME=${NDDSHOME:-/Applications/rti_connext_dds-7.3.1}
export DYLD_LIBRARY_PATH="$NDDSHOME/lib/${CONNEXTDDS_ARCH:-arm64Darwin20clang12.0}:${DYLD_LIBRARY_PATH:-}"
DOM=${DOM:-22}
MSM=${MSM:-1024}          # message_size_max
CNT=${CNT:-8}             # received_message_count_max
RBS=${RBS:-2048}          # receive_buffer_size -> wraps after ~32 records of 64 bytes

cat > wrap-qos.xml <<EOF
<?xml version="1.0"?>
<dds>
  <qos_library name="WrapLib">
    <qos_profile name="W">
      <domain_participant_qos>
        <transport_builtin><mask>UDPv4 | SHMEM</mask></transport_builtin>
        <property><value>
          <element><name>dds.transport.shmem.builtin.received_message_count_max</name><value>$CNT</value></element>
          <element><name>dds.transport.shmem.builtin.receive_buffer_size</name><value>$RBS</value></element>
          <element><name>dds.transport.shmem.builtin.parent.message_size_max</name><value>$MSM</value></element>
        </value></property>
      </domain_participant_qos>
    </qos_profile>
  </qos_library>
</dds>
EOF

start() { perl -e 'setpgrp(0,0); exec @ARGV' "$NDDSHOME/bin/rtiddsping" \
            -domainId "$DOM" "-$1" -sendPeriod 1 -qosFile ./wrap-qos.xml -qosProfile WrapLib::W \
            > "wrap-$1.log" 2>&1 & echo $!; }
PUB=$(start publisher); SUB=$(start subscriber)
trap 'kill -TERM -- -$PUB -$SUB 2>/dev/null; sleep 1; kill -KILL -- -$PUB -$SUB 2>/dev/null' EXIT
sleep 8

KEY=""
for p in $((7400+250*DOM+11)) $((7400+250*DOM+13)); do
  k=$(printf '%x' $((0x400000 + p)))
  if [ "$(./shmprobe "$k" find 52545053 2>/dev/null | tail -1 | awk '{print $2}')" -gt 0 ] 2>/dev/null; then
      KEY=$k; PORT=$p
  fi
done
[ -n "$KEY" ] || { echo "no user segment carrying RTPS records"; exit 1; }

echo "# receive_buffer_size=$RBS message_size_max=$MSM count_max=$CNT"
echo "# segment 0x$KEY (port $PORT) size=$(./shmprobe "$KEY" u32 0x0c 1)  ring-base candidate 0x50=$(./shmprobe "$KEY" u32 0x50 1)"
echo "# watching the producer position (0x78) and message count (0x94) for a wrap"
prev=0
for i in $(seq 1 "${ITERS:-90}"); do
  pos=$(./shmprobe "$KEY" u32 0x78 1); cnt=$(./shmprobe "$KEY" u32 0x94 1)
  mark=""; [ "$pos" -lt "$prev" ] 2>/dev/null && mark="   <<< WRAPPED (fell from $prev)"
  printf '  t=%-3s pos=%-8s count=%-5s%s\n' "$i" "$pos" "$cnt" "$mark"
  prev=$pos
  sleep 1
done
