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

"$NDDSHOME/bin/rtiddsping" -domainId "$DOM" -subscriber > /tmp/rt-sub.log 2>&1 &  SUB=$!
"$NDDSHOME/bin/rtiddsping" -domainId "$DOM" -publisher -sendPeriod 1 > /tmp/rt-pub.log 2>&1 & PUB=$!
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
echo "# --- descriptor slot mapping (live producer) ---"
echo "#   counter(0x94)=$($PROBE "$KEY" u32 0x94 1)  table(0xe8, 8 slots first-u32):"
$PROBE "$KEY" u32 0xe8 16 | awk '{for(i=1;i<=NF;i+=2){v=$i; printf "    slot%d=%d\n",(i-1)/2,(v>2147483647?v-4294967296:v)}}' | head -8
sleep 1.2
echo "#   counter(0x94)=$($PROBE "$KEY" u32 0x94 1)  table again:"
$PROBE "$KEY" u32 0xe8 16 | awk '{for(i=1;i<=NF;i+=2){v=$i; printf "    slot%d=%d\n",(i-1)/2,(v>2147483647?v-4294967296:v)}}' | head -8

# capture one real record + its exact length D (from the -D descriptor)
O=$($PROBE "$KEY" find 52545053 2>/dev/null | grep '^hit' | sed -n '2p' | awk '{print $4}' | tr -d '()')
NEGD=$($PROBE "$KEY" u32 0xe8 1); D=$(( (4294967296 - NEGD) % 4294967296 )); [ "$D" -gt 100000 ] && D=$(( 4294967296 - NEGD ))
$PROBE "$KEY" dump "$O" "$D" | sed -n '2,20p' | sed 's/|.*//' | awk '{$1="";print}' | tr -s ' ' | tr -d '\n' | sed 's/^ //' > /tmp/rt-record.hex
echo "# port $PORT ring 0x$KEY  captured record D=$D bytes at offset $O"

kill -9 $PUB 2>/dev/null            # stop the publisher so the ring drains and the consumer parks
sleep 2

# build a self-contained writer script and run it through the repo SBCL (registry set)
cat > /tmp/rt-write.lisp <<LISP
(asdf:load-system :dds-xport)
(in-package :cl-user)
(defun a8 (port)
  (let ((key (dds.xport.rti-shmem:rti-shmem-segment-key port)))
    (multiple-value-bind (seg st) (dds.pal:sysv-shm-attach-readonly key 512)
      (if st (list :no-seg st)
          (unwind-protect (loop with sap = (dds.pal:sysv-shm-sap seg)
                                for i below 8 collect (dds.pal:load-sap-u32 sap (+ #x78 (* 4 i))))
            (dds.pal:sysv-shm-detach seg))))))
(let* ((port $PORT)
       (hex (with-open-file (f "/tmp/rt-record.hex") (read-line f)))
       (toks (remove "" (uiop:split-string hex :separator " ") :test #'string=))
       (rec (make-array (length toks) :element-type '(unsigned-byte 8)
                        :initial-contents (mapcar (lambda (h) (parse-integer h :radix 16)) toks))))
  (format t "~&<<RT>> BEFORE A@0x78 = ~s~%" (a8 port))
  (multiple-value-bind (ok st) (dds.xport.rti-shmem:rti-shmem-write-record port rec (length rec))
    (format t "<<RT>> WRITE ok=~s status=~s (~d octets)~%" ok st (length rec)))
  (sleep 0.6)
  (format t "<<RT>> AFTER  A@0x78 = ~s~%" (a8 port))
  (format t "<<RT>> ACCEPTED iff AFTER consumer counter (idx5) advanced past BEFORE's~%"))
(finish-output)
LISP
"$REPO/scripts/with-sbcl.sh" --non-interactive --load /tmp/rt-write.lisp 2>&1 | grep '<<RT>>'

echo "# sub 'issue received' delta: was $(grep -c 'issue received' /tmp/rt-sub.log)"
kill -9 $SUB 2>/dev/null
echo "# teardown: kill any leftover rtiddsping and remove domain-$DOM IPC:"
echo "#   for id in \$(ipcs -m | awk '\$3 ~ /^0x0040/ && \$3 !~ /1cf/ {print \$2}'); do ipcrm -m \$id; done"
echo "#   for id in \$(ipcs -s | awk '(\$3~/^0x0080/||\$3~/^0x00b0/) && \$3!~/1cf/ {print \$2}'); do ipcrm -s \$id; done"
