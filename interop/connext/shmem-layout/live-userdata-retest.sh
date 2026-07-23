#!/bin/bash
# ADR 0081 slice 7c — APPLICATION-LEVEL delivery of a user-data sample over an RTI Connext SHMEM ring.
#
# Slice 7b proved RING-level acceptance: RTI's consumer drained a record this stack wrote. This closes the
# remaining question — does the sample reach RTI's APPLICATION? The record RTI accepted then was already a
# user-data sample (writerId 0x80000003, user-defined per RTPS 2.5 §9.3.1.2, SN 2), so the missing piece was
# never the record's KIND: it was its SEQUENCE NUMBER. Every record still lying in the ring has already been
# delivered, so a verbatim replay is a duplicate and RTPS drops it before the application ever sees it. This
# run re-issues the newest user sample at SN+1 — the reader's next expected sequence number.
#
# The oracle is the subscriber's `issue received` counter, and the control that makes it mean something is
# that the PUBLISHER IS FROZEN: it cannot produce a sample, so any increment came from our write. The script
# verifies the freeze actually took before writing, so a still-running publisher can never be misread as
# success.
#
# Runs entirely in the owner's shell: writing into another process's shared memory is gated for the agent.
# NEVER point this at a production peer — it stages its own throwaway pair on its own domain.
#
#   DOM=78 ./live-userdata-retest.sh
set -u
cd "$(dirname "$0")" || exit 1
. ./ring-lib.sh
DOM=${DOM:-78}
PUBLOG=/tmp/rt-ud-pub.log
SUBLOG=/tmp/rt-ud-sub.log
make -s all || exit 1

issues() { grep -c 'issue received' "$SUBLOG" 2>/dev/null || echo 0; }

echo "# ADR 0081 slice 7c — user-data delivery, domain $DOM"
stage_peers "$DOM" "$PUBLOG" "$SUBLOG"
sleep 8

if ! find_ring "$DOM"; then
  echo "# FAIL: no ring found on domain $DOM (peers did not come up)"
  kill -9 -- -"$SUB" -"$PUB" 2>/dev/null; teardown_hint "$DOM"; exit 1
fi
echo "# ring 0x$KEY at RTPS port $PORT"

BEFORE=$(issues)
echo "# subscriber has received $BEFORE issue(s) with the publisher running"

freeze_publisher "$PUB" "$PORT"
echo "# publisher FROZEN (still matched, ring static); ring mutex=$MUTEX"

# CONTROL: with the publisher frozen the counter MUST stand still. If it moves, the freeze did not take
# (a wrapper-only signal leaves the real binary writing) and every later increment would be ambiguous.
FROZEN_A=$(issues); sleep 2; FROZEN_B=$(issues)
if [ "$FROZEN_A" != "$FROZEN_B" ]; then
  echo "# ABORT: counter moved $FROZEN_A -> $FROZEN_B while the publisher was supposed to be frozen."
  echo "#        The freeze did not take; a result from this run would be uninterpretable."
  kill -9 -- -"$SUB" -"$PUB" 2>/dev/null; teardown_hint "$DOM"; exit 1
fi
echo "# control OK: counter steady at $FROZEN_B across 2s frozen — nothing but our write can move it now"
LINES_BEFORE=$(wc -l < "$SUBLOG")

RTI_MODE=inject RTI_PORT="$PORT" "$REPO/scripts/with-sbcl.sh" --non-interactive \
  --load "$REPO/interop/connext/shmem-layout/ring-records.lisp" 2>&1 | grep '<<RT>>'

sleep 2
AFTER=$(issues)
echo "# subscriber issue count: before=$BEFORE frozen=$FROZEN_B after=$AFTER"
echo "# new subscriber log lines:"
tail -n +$((LINES_BEFORE + 1)) "$SUBLOG" | sed 's/^/#   /'

if [ "$AFTER" -gt "$FROZEN_B" ]; then
  echo "# ==> PASS: RTI's application received a user-data sample written by this stack into its"
  echo "#           shared-memory ring. End-to-end SHMEM transmit interoperability is proven."
else
  echo "# ==> NOT YET: the record was written but the application did not count it. Read the <<RT>> ring"
  echo "#              fields above: consumer position advancing = accepted at ring level and dropped"
  echo "#              above it (sequence number, writer state); unchanged = not accepted at all."
fi

kill -9 -- -"$SUB" -"$PUB" 2>/dev/null
teardown_hint "$DOM"
