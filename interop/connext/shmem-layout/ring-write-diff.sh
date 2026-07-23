#!/bin/bash
# ADR 0081 slice 7b — the DEFINITIVE diagnostic: what does a REAL producer write to the control region that
# OUR writer does not? The consumer wakes on our SETVAL but does not consume, so a field it checks is missing
# from our write-set. This captures the whole control region (0x40..0x160, covering both blocks + the
# descriptor table's active region) at three stages and diffs them:
#
#   S0 = drained (publisher frozen)                          -> baseline
#   S1 = after exactly ONE real producer record (thaw+refreeze)  -> S1-S0 = what a REAL write changes
#   S2 = after exactly ONE of OUR writes                     -> S2-S1 = what OUR write changes
#
# Whatever S1-S0 changed that S2-S1 did not is the missing field. Owner runs it (live IPC surface).
set -u
REPO="/Users/frgo/gbt Dropbox/gbt/projects/hofvarpnir"
cd "$REPO/interop/connext/shmem-layout"
export NDDSHOME=${NDDSHOME:-/Applications/rti_connext_dds-7.3.1}
ARCH=${CONNEXTDDS_ARCH:-arm64Darwin20clang12.0}
export DYLD_LIBRARY_PATH="$NDDSHOME/lib/$ARCH:${DYLD_LIBRARY_PATH:-}"
DOM=${DOM:-75}
PROBE=./shmprobe
make -s shmprobe semprobe 2>/dev/null

perl -e 'setpgrp(0,0); exec @ARGV' "$NDDSHOME/bin/rtiddsping" -domainId "$DOM" -subscriber > /tmp/wd-sub.log 2>&1 & SUB=$!
perl -e 'setpgrp(0,0); exec @ARGV' "$NDDSHOME/bin/rtiddsping" -domainId "$DOM" -publisher -sendPeriod 1 > /tmp/wd-pub.log 2>&1 & PUB=$!
sleep 6
KEY=""; PORT=""
for i in 0 1 2 3; do for d in 11 13; do p=$((7400+250*DOM+d+2*i)); k=$(printf '%x' $((0x400000+p)))
  n=$($PROBE "$k" find 52545053 2>/dev/null | tail -1 | awk '{print $2}')
  [ "${n:-0}" -gt 2 ] 2>/dev/null && { KEY=$k; PORT=$p; }
done; done
[ -n "$KEY" ] || { echo "no ring"; kill -9 -- -$SUB -$PUB 2>/dev/null; exit 1; }
echo "# ring 0x$KEY port $PORT"

# capture one real record for our writer to replay later
O=$($PROBE "$KEY" find 52545053 2>/dev/null | grep '^hit' | sed -n '2p' | awk '{print $4}' | tr -d '()')
$PROBE "$KEY" dump "$O" 64 | sed -n '2,5p' | sed 's/|.*//' | awk '{$1="";print}' | tr -s ' ' | tr -d '\n' | sed 's/^ //' > /tmp/wd-record.hex

freeze() { kill -STOP -- -$PUB 2>/dev/null; sleep 0.6
  local mk; mk=$(printf '%x' $((0xB00000 + PORT)))
  for t in 1 2 3 4 5; do local mv; mv=$($PROBE >/dev/null 2>&1; ./semprobe "$mk" 2>/dev/null | awk '/\[0\]/{gsub(/[a-z=-]+/,"",$2);print $2}')
    [ "${mv:-1}" = "1" ] && return; kill -CONT -- -$PUB 2>/dev/null; sleep 0.2; kill -STOP -- -$PUB 2>/dev/null; sleep 0.3; done; }
thaw()  { kill -CONT -- -$PUB 2>/dev/null; }
snap()  { $PROBE "$KEY" u32 0x40 72; }   # 0x40..0x160, 72 u32s = both blocks + descriptor active region

freeze;              S0=$(snap)
thaw; sleep 1.15;    freeze; S1=$(snap)   # exactly ~1 real record
# our write (publisher stays frozen)
cat > /tmp/wd-write.lisp <<LISP
(asdf:load-system :dds-xport)
(let* ((port $PORT)
       (hex (with-open-file (f "/tmp/wd-record.hex") (read-line f)))
       (toks (remove "" (uiop:split-string hex :separator " ") :test #'string=))
       (rec (make-array (length toks) :element-type '(unsigned-byte 8)
              :initial-contents (mapcar (lambda (h) (parse-integer h :radix 16)) toks))))
  (dds.xport.rti-shmem:rti-shmem-write-record port rec (length rec)))
(finish-output)
LISP
"$REPO/scripts/with-sbcl.sh" --non-interactive --load /tmp/wd-write.lisp >/tmp/wd-write.out 2>&1
S2=$(snap)

echo "# offsets 0x40.. as u32 index i -> byte 0x$(printf '%x' $((0x40)))+4i"
echo "# REAL write (S1-S0):"
paste <(echo "$S0" | tr ' ' '\n') <(echo "$S1" | tr ' ' '\n') | awk '$1!=$2{printf "    0x%x: %s -> %s\n",0x40+4*(NR-1),$1,$2}'
echo "# OUR write  (S2-S1):"
paste <(echo "$S1" | tr ' ' '\n') <(echo "$S2" | tr ' ' '\n') | awk '$1!=$2{printf "    0x%x: %s -> %s\n",0x40+4*(NR-1),$1,$2}'
echo "# => any offset in the REAL list but NOT the OUR list is a field we are not writing."

kill -9 -- -$SUB -$PUB 2>/dev/null
