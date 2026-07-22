#!/bin/bash
# Sweep host_id on a FIXED domain so domain is not a confound.
# Prints host_id (dec/hex) against the 12 address bytes at segment offset 0x24.
set -u
cd "$(dirname "$0")"
export NDDSHOME=/Applications/rti_connext_dds-7.3.1
export DYLD_LIBRARY_PATH="$NDDSHOME/lib/arm64Darwin20clang12.0:${DYLD_LIBRARY_PATH:-}"

DOM=${DOM:-12}
PORT=$((7400 + 250*DOM + 10))
KEY=$(printf '%x' $((0x400000 + PORT)))

printf '# domain=%s port=%s segment key=0x%s\n' "$DOM" "$PORT" "$KEY"
printf '%-12s %-10s  %s\n' 'host_id' 'hex' 'address bytes @0x24'

for H in "$@"; do
  cat > sweep-qos.xml <<EOF
<?xml version="1.0"?>
<dds>
  <qos_library name="SweepLib">
    <qos_profile name="S">
      <domain_participant_qos>
        <transport_builtin><mask>UDPv4 | SHMEM</mask></transport_builtin>
        <property><value>
          <element><name>dds.transport.shmem.builtin.received_message_count_max</name><value>37</value></element>
          <element><name>dds.transport.shmem.builtin.receive_buffer_size</name><value>777216</value></element>
          <element><name>dds.transport.shmem.builtin.parent.message_size_max</name><value>20480</value></element>
          <element><name>dds.transport.shmem.builtin.host_id</name><value>$H</value></element>
        </value></property>
      </domain_participant_qos>
    </qos_profile>
  </qos_library>
</dds>
EOF
  perl -e 'setpgrp(0,0); exec @ARGV' \
      "$NDDSHOME/bin/rtiddsping" -domainId "$DOM" -publisher -sendPeriod 9 -verbosity 2 \
      -qosFile ./sweep-qos.xml -qosProfile "SweepLib::S" > "sweep-$H.log" 2>&1 &
  g=$!
  sleep 5
  if grep -qiE 'error|FAILED TO PARSE' "sweep-$H.log"; then
      printf '%-12s %-10s  !! QoS load error\n' "$H" ''
  else
      bytes=$(./shmprobe "$KEY" dump 0x24 12 2>/dev/null | awk 'NR==2{$1="";print}' | tr -s ' ' | cut -c2-36)
      printf '%-12s 0x%08x  %s\n' "$H" "$H" "$bytes"
  fi
  kill -TERM -- -$g 2>/dev/null; sleep 1; kill -KILL -- -$g 2>/dev/null
  sleep 1
done
