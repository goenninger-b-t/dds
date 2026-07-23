#!/bin/bash
# ADR 0081 slice 7b — live acceptance re-test, after the idx4 fix.
#
# Runs entirely in the owner's shell (the live IPC surface — writing into a Connext ring — is gated by the
# auto-mode classifier for the agent, so this is a script the owner runs). It stages a THROWAWAY rtiddsping
# subscriber, captures a real record, stops the publisher, has our writer append the record, and reports
# whether RTI's CONSUMER drains it (its counter advancing is the acceptance signal).
#
# NEVER point this at a production peer. It uses its own domain; only the throwaway subscriber is touched.
set -u
REPO="/Users/frgo/gbt Dropbox/gbt/projects/hofvarpnir"
cd "$REPO/interop/connext/shmem-layout"
export NDDSHOME=${NDDSHOME:-/Applications/rti_connext_dds-7.3.1}
ARCH=${CONNEXTDDS_ARCH:-arm64Darwin20clang12.0}
export DYLD_LIBRARY_PATH="$NDDSHOME/lib/$ARCH:${DYLD_LIBRARY_PATH:-}"
DOM=${DOM:-70}
PROBE=./shmprobe
make -s "$PROBE" 2>/dev/null || make -s shmprobe

# perl setpgrp so each peer is its own process group: rtiddsping's /bin/sh wrapper SPAWNS the real binary
# as a CHILD, so killing the wrapper pid leaves the real publisher writing. Killing the GROUP gets both.
perl -e 'setpgrp(0,0); exec @ARGV' "$NDDSHOME/bin/rtiddsping" -domainId "$DOM" -subscriber > /tmp/rt-sub.log 2>&1 &  SUB=$!
perl -e 'setpgrp(0,0); exec @ARGV' "$NDDSHOME/bin/rtiddsping" -domainId "$DOM" -publisher -sendPeriod 1 > /tmp/rt-pub.log 2>&1 & PUB=$!
sleep 6

KEY=""; PORT=""
for i in 0 1 2 3; do for d in 11 13; do p=$((7400+250*DOM+d+2*i)); k=$(printf '%x' $((0x400000+p)))
  n=$($PROBE "$k" find 52545053 2>/dev/null | tail -1 | awk '{print $2}')
  [ "${n:-0}" -gt 2 ] 2>/dev/null && { KEY=$k; PORT=$p; }
done; done
[ -n "$KEY" ] || { echo "no ring found"; kill -9 $SUB $PUB 2>/dev/null; exit 1; }

# While the LIVE producer runs, map the descriptor SLOT rule: sample the counter (A idx7 @0x94) and the
# whole descriptor table (0xe8, 8 slots) twice ~1.2s apart. Which slot gains a fresh -D as the counter
# increments tells us slot(counter) directly — the second suspect if idx4 alone does not fix acceptance.
# dump 32 descriptor slots (the active region is near the counter, not slot 0) alongside the counter,
# twice, so which slot the live producer fills as the counter increments is visible directly.
slotdump() {
  local c; c=$($PROBE "$KEY" u32 0x94 1)
  echo "#   counter(0x94)=$c  descriptor slots 0..31 (first u32, signed):"
  $PROBE "$KEY" u32 0xe8 64 | awk '{for(i=1;i<=NF;i+=2){v=$i; s=(i-1)/2; d=(v>2147483647?v-4294967296:v); if(d!=0) printf "    slot%d=%d\n",s,d}}'
}
echo "# --- descriptor slot mapping (live producer) ---"; slotdump; sleep 1.5; echo "#   (1.5s later)"; slotdump

# capture one real record + its exact length D (from the -D descriptor)
O=$($PROBE "$KEY" find 52545053 2>/dev/null | grep '^hit' | sed -n '2p' | awk '{print $4}' | tr -d '()')
NEGD=$($PROBE "$KEY" u32 0xe8 1); D=$(( (4294967296 - NEGD) % 4294967296 )); [ "$D" -gt 100000 ] && D=$(( 4294967296 - NEGD ))
$PROBE "$KEY" dump "$O" "$D" | sed -n '2,20p' | sed 's/|.*//' | awk '{$1="";print}' | tr -s ' ' | tr -d '\n' | sed 's/^ //' > /tmp/rt-record.hex
echo "# port $PORT ring 0x$KEY  captured record D=$D bytes at offset $O"

# FREEZE the publisher (SIGSTOP the group), do NOT kill it. Killing makes RTI's consumer detect the writer's
# death and UNMATCH it, after which the consumer will not consume anything from that source and its receive
# thread may stop waiting on the data semaphore — so a killed-publisher ring can never show acceptance. Frozen,
# the publisher writes nothing (ring static) but stays matched and the consumer keeps listening.
kill -STOP -- -$PUB 2>/dev/null; sleep 1
# mutex safety: if the freeze caught the publisher holding the ring mutex (value 0; it holds it ~2us/s so this
# is very rare) it stays locked while stopped and our write would block — thaw briefly and re-freeze until free.
MTXKEY=$(printf '%x' $((0xB00000 + PORT)))
MV=1
for try in 1 2 3 4 5; do
  MV=$(./semprobe "$MTXKEY" 2>/dev/null | awk '/\[0\]/{gsub(/[a-z=-]+/,"",$2); print $2}')
  [ "${MV:-0}" = "1" ] && break
  echo "# mutex held (=$MV) — thaw+refreeze (try $try)"; kill -CONT -- -$PUB 2>/dev/null; sleep 0.2; kill -STOP -- -$PUB 2>/dev/null; sleep 0.3
done
echo "# publisher FROZEN (consumer stays matched); mutex=$MV, ring static"

# build a self-contained writer script and run it through the repo SBCL (registry set)
cat > /tmp/rt-write.lisp <<LISP
(asdf:load-system :dds-xport)
(in-package :cl-user)
(defun blk (port base)
  (let ((key (dds.xport.rti-shmem:rti-shmem-segment-key port)))
    (multiple-value-bind (seg st) (dds.pal:sysv-shm-attach-readonly key 512)
      (if st (list :no-seg st)
          (unwind-protect (loop with sap = (dds.pal:sysv-shm-sap seg)
                                for i below 8 collect (dds.pal:load-sap-u32 sap (+ base (* 4 i))))
            (dds.pal:sysv-shm-detach seg))))))
(defun datasem (port)
  (multiple-value-bind (s st)
      (dds.pal:sysv-sem-open (+ dds.xport.rti-shmem:+rti-shmem-semaphore-key-base+ port))
    (if st :absent (dds.pal:sysv-sem-getval s 0))))
(let* ((port $PORT)
       (hex (with-open-file (f "/tmp/rt-record.hex") (read-line f)))
       (toks (remove "" (uiop:split-string hex :separator " ") :test #'string=))
       (rec (make-array (length toks) :element-type '(unsigned-byte 8)
                        :initial-contents (mapcar (lambda (h) (parse-integer h :radix 16)) toks))))
  (format t "~&<<RT>> BEFORE A@0x78 = ~s~%" (blk port #x78))
  (format t "<<RT>>        B@0xb0 = ~s   data-sem = ~s~%" (blk port #xb0) (datasem port))
  (multiple-value-bind (ok st) (dds.xport.rti-shmem:rti-shmem-write-record port rec (length rec))
    (format t "<<RT>> WRITE ok=~s status=~s (~d octets)  data-sem just after = ~s~%"
            ok st (length rec) (datasem port)))
  (sleep 0.6)
  (format t "<<RT>> AFTER  A@0x78 = ~s~%" (blk port #x78))
  (format t "<<RT>>        B@0xb0 = ~s   data-sem = ~s~%" (blk port #xb0) (datasem port))
  (format t "<<RT>> ACCEPTED iff a consumer field (A idx1 / idx5) advanced. data-sem after our SETVAL:~%")
  (format t "<<RT>>   1 then 1 = consumer never woke; 1 then 0 = woke but did not consume.~%"))
(finish-output)
LISP
"$REPO/scripts/with-sbcl.sh" --non-interactive --load /tmp/rt-write.lisp 2>&1 | grep '<<RT>>'

echo "# sub 'issue received' count: $(grep -c 'issue received' /tmp/rt-sub.log)"
kill -9 -- -$SUB 2>/dev/null
echo "# teardown: kill any leftover rtiddsping and remove domain-$DOM IPC:"
echo "#   for id in \$(ipcs -m | awk '\$3 ~ /^0x0040/ && \$3 !~ /1cf/ {print \$2}'); do ipcrm -m \$id; done"
echo "#   for id in \$(ipcs -s | awk '(\$3~/^0x0080/||\$3~/^0x00b0/) && \$3!~/1cf/ {print \$2}'); do ipcrm -s \$id; done"
