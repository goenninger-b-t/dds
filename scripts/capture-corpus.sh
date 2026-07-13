#!/usr/bin/env bash
# Regenerate the byte-exact XCDR corpus (FR-CDR-8) from a LIVE RTI Connext writer.
#
# THE ORACLE IS THE WIRE. We capture the SerializedPayloads Connext actually TRANSMITS, off our own receive
# path. We deliberately do NOT use Connext's rti::topic::to_cdr_buffer: that returns a local CDR buffer which
# is neither padded to 4 nor carries the OPTIONS pad bits, so a corpus built from it would have enshrined the
# exact bytes ADR 0061 proved malformed (verified: 1-octet sequence -> to_cdr_buffer 13 octets options=0x0000;
# the same sample ON THE WIRE -> 16 octets options=0x0003).
#
# Needs a local Connext install; NOT run by `make corpus` (which only VERIFIES the committed vectors).
#
#   NDDSHOME=/Applications/rti_connext_dds-7.3.1 ADVERTISE=192.168.2.148 scripts/capture-corpus.sh
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NDDSHOME="${NDDSHOME:-/Applications/rti_connext_dds-7.3.1}"
ARCH="${CONNEXTDDS_ARCH:-arm64Darwin20clang12.0}"
ADVERTISE="${ADVERTISE:-192.168.2.148}"
DOMAIN="${DOMAIN:-0}"
LENS="${LENS:-0 1 2 3 4 5 7 8 15 16 63 64 255 256 257 1023 1024}"

export NDDSHOME
export DYLD_LIBRARY_PATH="$NDDSHOME/lib/$ARCH:${DYLD_LIBRARY_PATH:-}"
export CL_SOURCE_REGISTRY="$REPO//:"

cd "$REPO"
mkdir -p corpus/xcdr2

# Our capture subscriber writes one .bin per distinct (id, seq-len) it sees from Connext.
sbcl --non-interactive \
     --eval '(ql:quickload :dds-bench :silent t)' \
     --eval "(dds.bench:corpus-capture :domain $DOMAIN :advertise-address \"$ADVERTISE\" :seconds 200)" \
     > /tmp/corpus-capture.log 2>&1 &
CAP=$!
sleep 12

for L in $LENS; do
  echo "  connext pinger len=$L"
  # perf_pinger writes PerfPing samples of the requested payload length; it will not get an echo (our
  # capture subscriber does not echo), so bound it and ignore its non-zero exit.
  ( "$REPO/interop/perftest/connext/perf_pinger" "$DOMAIN" 3 "$L" 0 >/dev/null 2>&1 || true ) &
  sleep 4
  kill -TERM %2 2>/dev/null || true
done

sleep 3
kill -TERM $CAP 2>/dev/null || true
wait $CAP 2>/dev/null || true

grep -E "^\[corpus\] captured" /tmp/corpus-capture.log || true
echo "corpus: $(ls -1 corpus/xcdr2/*.bin 2>/dev/null | wc -l | tr -d ' ') vector(s) in corpus/xcdr2/"
