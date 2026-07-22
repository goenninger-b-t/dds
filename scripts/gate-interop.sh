#!/usr/bin/env bash
# gate-interop — live cross-vendor interop (operating contract §6, FR-IO; owner directive 2026-06-17:
# every feature needs an interop test vs BOTH RTI Connext 7.3.1 AND Fast DDS; test the WIRE surface).
#
# WHAT THIS REPLACES. `make interop` was a STUB. In full, it was:
#
#     interop: wire
#     	@echo "interop: 'wire' validates our output vs the tshark RTPS dissector."
#     	@echo "interop: bidirectional Connext interop pending a Connext install (M2, FR-IO)."
#
# It ran `wire` and then ECHOED that Connext interop was "pending a Connext install" — while Connext
# 7.3.1 was installed and passing live legs by hand. The gate asserted NOTHING about interop and could
# not fail. It had been that way since M0 ("the rest are M1+ stubs") and was never revisited through M7.
#
# THE RULE THIS GATE ENFORCES: a gate that cannot run MUST NOT report success. If a vendor is absent we
# FAIL and say which one, rather than printing a green line. Opt out DELIBERATELY and VISIBLY with
# INTEROP_ALLOW_MISSING=connext|fastdds|both.
#
# ⚠️ Fast DDS is LENIENT — it accepts payloads Connext rejects (it could not catch ADR 0061). A green
# Fast DDS leg NEVER substitutes for the Connext leg. Both are required.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

DOMAIN="${DOMAIN:-0}"
SECONDS_RUN="${SECONDS_RUN:-15}"
ALLOW="${INTEROP_ALLOW_MISSING:-}"
fails=0

note() { printf '  %-8s %s\n' "$1" "$2"; }

# macOS has NO `timeout` (it is GNU coreutils). Portable shim: run the command, kill it after N seconds.
# Without this every bounded child died with "command not found" and the gate failed for the wrong reason.
#
# ⚠️ EVERY PEER RUNS IN ITS OWN PROCESS GROUP, AND WE KILL THE GROUP. Killing only the direct child leaks
# the real binary whenever the child is a wrapper (a subshell, or with-fastdds.sh -> bash -> shapes_pub):
# the grandchild is reparented to init and KEEPS PUBLISHING ON THE DOMAIN FOREVER. That is not theoretical
# — this gate leaked a `shapes_pub RED` that then fed 358 phantom samples into a later leg's subscriber and
# made an outbound test look like it was receiving its own traffic. A leaked publisher poisons every
# subsequent run on the machine. macOS has no setsid; perl's setpgrp does the same job.
tmout() {                       # tmout <seconds> <cmd...>
  local secs="$1"; shift
  perl -e 'setpgrp(0,0); exec @ARGV' "$@" & local p=$!
  ( sleep "$secs"; kill -9 -- -"$p" 2>/dev/null ) & local w=$!
  wait "$p" 2>/dev/null; local rc=$?
  kill -9 "$w" 2>/dev/null
  kill -9 -- -"$p" 2>/dev/null
  return "$rc"
}

# start_peer <logfile> <cmd...> -> prints the PGID. stop_peer <pgid> tears the WHOLE group down.
start_peer() {
  local log="$1"; shift
  perl -e 'setpgrp(0,0); exec @ARGV' "$@" >"$log" 2>&1 &
  echo $!
}
stop_peer() {
  local g="${1:-}"; [[ -n "$g" ]] || return 0
  kill -TERM -- -"$g" 2>/dev/null; sleep 1; kill -9 -- -"$g" 2>/dev/null; wait "$g" 2>/dev/null; return 0
}

# wait_peer <pgid> <max-seconds> — let the peer EXIT ON ITS OWN, then return.
#
# WHY THIS EXISTS, and it is not optional. A peer started by start_peer runs in a command substitution, so it
# is NOT a child of this shell and `wait` on it returns IMMEDIATELY — meaning stop_peer used to SIGKILL every
# peer the instant its publisher finished. A C++ peer writing to a FILE has fully-buffered stdout, so a peer
# killed before it flushes leaves an EMPTY LOG and its leg scores ZERO no matter how many samples it actually
# received. That is a false RED, and it is invisible: the log looks like the peer never ran. The Shapes legs
# only escaped it by receiving enough lines (>4 KB) to force intermediate flushes; the large-data legs, at ~15
# lines, never did. Every foreign peer here takes a <seconds> argument and exits normally on its own — so wait
# for that, and keep stop_peer only as the backstop for a peer that hangs.
wait_peer() {
  local g="${1:-}" max="${2:-60}" i=0
  [[ -n "$g" ]] || return 0
  while kill -0 "$g" 2>/dev/null && [[ "$i" -lt "$max" ]]; do sleep 1; i=$((i+1)); done
  return 0
}

# A leg is only green if it moved a MEANINGFUL number of samples. ">0" is nearly vacuous: one sample can
# arrive from a stale peer, a retained sample, or a single lucky datagram, and it cannot demonstrate a
# steady stream. MIN_SAMPLES is the floor every leg is judged against.
MIN_SAMPLES="${MIN_SAMPLES:-5}"

# ---- Vendor presence. Absent + not explicitly excused == FAIL. ----
NDDSHOME="${NDDSHOME:-/Applications/rti_connext_dds-7.3.1}"
have_connext=0
[[ -d "$NDDSHOME" && -x interop/connext/shapes-sub/shapes_sub ]] && have_connext=1

have_fastdds=0
[[ -x scripts/with-fastdds.sh && -x interop/fastdds/shapes/shapes_pub ]] && have_fastdds=1

if [[ "$have_connext" -eq 0 ]]; then
  if [[ "$ALLOW" == "connext" || "$ALLOW" == "both" ]]; then
    note "SKIP" "Connext — EXCUSED by INTEROP_ALLOW_MISSING. NOT validated."
  else
    echo "gate-interop: FAIL — RTI Connext not usable (NDDSHOME=$NDDSHOME, interop/connext/shapes-sub/shapes_sub)." >&2
    echo "              Connext is the STRICT oracle; Fast DDS cannot substitute for it (ADR 0061)." >&2
    echo "              Build it, or set INTEROP_ALLOW_MISSING=connext to skip DELIBERATELY." >&2
    fails=1
  fi
fi
if [[ "$have_fastdds" -eq 0 ]]; then
  if [[ "$ALLOW" == "fastdds" || "$ALLOW" == "both" ]]; then
    note "SKIP" "Fast DDS — EXCUSED by INTEROP_ALLOW_MISSING. NOT validated."
  else
    echo "gate-interop: FAIL — Fast DDS not usable (scripts/with-fastdds.sh, interop/fastdds/shapes/shapes_pub)." >&2
    echo "              Build it, or set INTEROP_ALLOW_MISSING=fastdds to skip DELIBERATELY." >&2
    fails=1
  fi
fi
[[ "$fails" -ne 0 ]] && exit 1

# Both vendors' shapes_pub run FOREVER (neither takes a duration: Connext is
# `shapes_pub <domain> <color> <shapesize>`, Fast DDS is `shapes_pub <color> <count>`), so EVERY child is
# hard-bounded by `timeout`. A gate that HANGS is no better than one that lies.
# Success predicate is our subscriber's per-sample line: "[sub] Square <color> x=.. y=..".

# ---- Leg 1: Connext -> us. The STRICT oracle (Fast DDS cannot substitute — ADR 0061). ----
if [[ "$have_connext" -eq 1 ]]; then
  export NDDSHOME
  export DYLD_LIBRARY_PATH="$NDDSHOME/lib/arm64Darwin20clang12.0:$PWD/interop/connext/shapes-pub:${DYLD_LIBRARY_PATH:-}"
  ADV="${ADVERTISE:-$(ipconfig getifaddr en0 2>/dev/null || echo 127.0.0.1)}"
  log="$(mktemp)"
  ( cd interop/connext/shapes-pub && tmout $((SECONDS_RUN + 8)) ./shapes_pub "$DOMAIN" BLUE >/dev/null 2>&1 ) &
  cxpid=$!
  tmout $((SECONDS_RUN + 25)) ./scripts/with-sbcl.sh \
    --eval "(asdf:load-system :dds-shapes)" \
    --eval "(uiop:symbol-call :dds.shapes :run-subscriber :domain $DOMAIN :advertise-address \"$ADV\" :type :canonical :seconds $SECONDS_RUN)" \
    --eval '(uiop:quit 0)' > "$log" 2>&1
  kill -9 $cxpid 2>/dev/null; wait $cxpid 2>/dev/null
  n="$(grep -c '^\[sub\] Square' "$log" || true)"
  if [[ "$n" -ge "$MIN_SAMPLES" ]]; then note "ok" "Connext -> us: $n sample(s) received"; else
    note "FAIL" "Connext -> us: only $n sample(s), need >= $MIN_SAMPLES (log: $log)"; fails=1; fi
fi

# ---- Leg 2: Fast DDS -> us. LENIENT peer — a green run here proves strictly less. ----
if [[ "$have_fastdds" -eq 1 ]]; then
  log="$(mktemp)"
  # Fast DDS is loopback-whitelisted -> it never sees LAN multicast SPDP; announce unicast to its
  # builtin metatraffic port (127.0.0.1:7410). Its publisher sends the CANONICAL ShapeType.
  ( tmout $((SECONDS_RUN + 8)) ./scripts/with-fastdds.sh bash -c \
       "cd interop/fastdds/shapes && ./shapes_pub RED" >/dev/null 2>&1 ) &
  fdpid=$!
  tmout $((SECONDS_RUN + 25)) ./scripts/with-sbcl.sh \
    --eval "(asdf:load-system :dds-shapes)" \
    --eval "(uiop:symbol-call :dds.shapes :run-subscriber :domain $DOMAIN :advertise-address \"127.0.0.1\" :type :canonical :peers \"127.0.0.1:7410\" :seconds $SECONDS_RUN)" \
    --eval '(uiop:quit 0)' > "$log" 2>&1
  kill -9 $fdpid 2>/dev/null; wait $fdpid 2>/dev/null
  n="$(grep -c '^\[sub\] Square' "$log" || true)"
  if [[ "$n" -ge "$MIN_SAMPLES" ]]; then note "ok" "Fast DDS -> us: $n sample(s) (LENIENT peer — proves less than Connext)"; else
    note "FAIL" "Fast DDS -> us: only $n sample(s), need >= $MIN_SAMPLES (log: $log)"; fails=1; fi
fi

# ---- Leg 3: us -> Connext. THE DIRECTION THAT HID ADR 0057. ----
# For six slices every live leg exercised our READER, and our DataWriter matched NO foreign DataReader at
# all — a false type-gate REJECT that inbound testing structurally could not see. This leg is the guard.
# REP=xcdr1 is REQUIRED, not a tuning choice: a stock foreign shapes DataReader advertises XCDR1 ONLY, and
# DATA_REPRESENTATION is an RxO policy, so our XCDR2-default writer SILENTLY does not match (matched=0, no
# error). Connext's profile pins the LAN interface, so we must advertise the LAN address, not loopback.
if [[ "$have_connext" -eq 1 ]]; then
  export NDDSHOME
  export DYLD_LIBRARY_PATH="$NDDSHOME/lib/arm64Darwin20clang12.0:$PWD/interop/connext/shapes-sub:${DYLD_LIBRARY_PATH:-}"
  ADV="${ADVERTISE:-$(ipconfig getifaddr en0 2>/dev/null || echo 127.0.0.1)}"
  log="$(mktemp)"
  # shapes_sub takes <domain> <seconds> and EXITS NORMALLY — it must, or its C++ stdout buffer never
  # flushes and the log reads empty even though it received everything.
  g="$(start_peer "$log" bash -c "cd interop/connext/shapes-sub && exec ./shapes_sub $DOMAIN $((SECONDS_RUN + 8))")"
  sleep 4
  tmout $((SECONDS_RUN + 25)) ./scripts/with-sbcl.sh \
    --eval "(asdf:load-system :dds-shapes)" \
    --eval "(uiop:symbol-call :dds.shapes :run-publisher :domain $DOMAIN :type :canonical :data-representation :xcdr1 :advertise-address \"$ADV\" :color \"BLUE\" :count $((SECONDS_RUN * 20)) :rate 20)" \
    --eval '(uiop:quit 0)' >/dev/null 2>&1
  wait_peer "$g" $((SECONDS_RUN + 30)); stop_peer "$g"
  n="$(grep -c 'color=BLUE' "$log" || true)"
  if [[ "$n" -ge "$MIN_SAMPLES" ]]; then note "ok" "us -> Connext: $n BLUE sample(s) accepted by the STRICT oracle"; else
    note "FAIL" "us -> Connext: only $n sample(s), need >= $MIN_SAMPLES (log: $log)"; fails=1; fi
fi

# ---- Leg 4: us -> Fast DDS. ----
# Fast DDS is loopback-whitelisted in its profile, so it never sees LAN multicast SPDP: we must announce
# unicast to its builtin metatraffic port. Same REP=xcdr1 RxO requirement as leg 3.
if [[ "$have_fastdds" -eq 1 ]]; then
  log="$(mktemp)"
  g="$(start_peer "$log" ./scripts/with-fastdds.sh bash -c "cd interop/fastdds/shapes && exec ./shapes_sub $((SECONDS_RUN + 8))")"
  sleep 5
  tmout $((SECONDS_RUN + 25)) ./scripts/with-sbcl.sh \
    --eval "(asdf:load-system :dds-shapes)" \
    --eval "(uiop:symbol-call :dds.shapes :run-publisher :domain $DOMAIN :type :canonical :data-representation :xcdr1 :advertise-address \"127.0.0.1\" :peers \"127.0.0.1:7410\" :color \"GREEN\" :count $((SECONDS_RUN * 20)) :rate 20)" \
    --eval '(uiop:quit 0)' >/dev/null 2>&1
  wait_peer "$g" $((SECONDS_RUN + 30)); stop_peer "$g"
  n="$(grep -c 'color=GREEN' "$log" || true)"
  if [[ "$n" -ge "$MIN_SAMPLES" ]]; then note "ok" "us -> Fast DDS: $n GREEN sample(s) (LENIENT peer)"; else
    note "FAIL" "us -> Fast DDS: only $n sample(s), need >= $MIN_SAMPLES (log: $log)"; fails=1; fi
fi

# ---- Legs 5 + 6: LARGE DATA (DATA_FRAG) vs Connext, BOTH directions. ----
# The only fragmentation leg against a foreign stack, and the one whose absence let ADR 0079 ship: our
# emitted datagram size is an interop contract (RTPS 2.5 §8.4.14.1 — fragmentSize is fixed per writer and
# bounded by the SMALLEST max message size across the writer's transports), and Shapes samples are far below
# any MTU so no Shapes leg can exercise it. The peer's profile deliberately sets message_size_max=1400.
# FALSIFIED: with the pre-ADR-0079 default (*fragment-size* 63000) an 8000-octet sample rides unfragmented in
# one ~8 KB datagram and Connext receives ZERO — same-host AND cross-machine.
if [[ "$have_connext" -eq 1 ]]; then
  export NDDSHOME
  # The peer binaries link their Connext dylibs via @loader_path, so each peer dir needs the symlinks the
  # shapes dirs already have. They are gitignored (per-clone setup), so create them if absent rather than
  # failing a fresh clone for a reason that has nothing to do with interop.
  for l in libnddsc libnddscore libnddscpp2; do
    [[ -e "interop/connext/large-data/$l.dylib" ]] ||       ln -sf "$NDDSHOME/lib/${CONNEXTDDS_ARCH:-arm64Darwin20clang12.0}/$l.dylib" "interop/connext/large-data/$l.dylib" 2>/dev/null
  done
  export DYLD_LIBRARY_PATH="$NDDSHOME/lib/${CONNEXTDDS_ARCH:-arm64Darwin20clang12.0}:${DYLD_LIBRARY_PATH:-}"
  ADV="${ADVERTISE:-$(ipconfig getifaddr en0 2>/dev/null || echo 127.0.0.1)}"

  # Leg 5: us -> Connext (the direction ADR 0079 broke).
  log="$(mktemp)"
  g="$(start_peer "$log" bash -c "cd interop/connext/large-data && exec ./large_sub $DOMAIN $((SECONDS_RUN + 10))")"
  sleep 5
  tmout $((SECONDS_RUN + 25)) ./scripts/with-sbcl.sh \
    --eval "(asdf:load-system :dds-shapes)" \
    --eval "(uiop:symbol-call :dds.shapes :run-large-publisher :domain $DOMAIN :size 8000 :count $((SECONDS_RUN + 5)) :rate 2 :advertise-address \"$ADV\")" \
    --eval '(uiop:quit 0)' >/dev/null 2>&1
  wait_peer "$g" $((SECONDS_RUN + 30)); stop_peer "$g"
  n="$(grep -c 'payload-len=8000 pattern=OK' "$log" || true)"
  if [[ "$n" -ge "$MIN_SAMPLES" ]]; then note "ok" "us -> Connext LARGE: $n fragmented sample(s), pattern OK"; else
    note "FAIL" "us -> Connext LARGE: only $n verified sample(s), need >= $MIN_SAMPLES (log: $log)"; fails=1; fi

  # Leg 6: Connext -> us. Our reader reassembles from the WIRE's own fragmentSize/sampleSize, so this leg is
  # independent of our *fragment-size* — it gates DATA_FRAG REASSEMBLY, which nothing else does.
  log="$(mktemp)"
  g="$(start_peer "$log" ./scripts/with-sbcl.sh \
        --eval "(asdf:load-system :dds-shapes)" \
        --eval "(uiop:symbol-call :dds.shapes :run-large-subscriber :domain $DOMAIN :seconds $((SECONDS_RUN + 10)) :advertise-address \"$ADV\")" \
        --eval "(uiop:quit 0)")"
  sleep 8
  tmout $((SECONDS_RUN + 20)) bash -c "cd interop/connext/large-data && exec ./large_pub $DOMAIN 8000 $((SECONDS_RUN + 5))" >/dev/null 2>&1
  wait_peer "$g" $((SECONDS_RUN + 30)); stop_peer "$g"
  n="$(grep -c 'payload-length=8000 pattern=OK' "$log" || true)"
  if [[ "$n" -ge "$MIN_SAMPLES" ]]; then note "ok" "Connext -> us LARGE: $n reassembled sample(s), pattern OK"; else
    note "FAIL" "Connext -> us LARGE: only $n verified sample(s), need >= $MIN_SAMPLES (log: $log)"; fails=1; fi
fi

if [[ "$fails" -ne 0 ]]; then
  echo "gate-interop: FAIL — see above." >&2
  exit 1
fi
echo "gate-interop: PASS — live cross-vendor interop validated (Connext = the strict oracle)."
# NO SILENT CAPS: state what this gate does NOT cover, every run. A gate that quietly tests half the
# surface reads as "interop is covered" when it is not — which is how the DCPS writer went 6 slices
# without EVER matching a foreign reader (ADR 0057; every prior leg had exercised our READER).
echo "gate-interop: COVERAGE — BOTH DIRECTIONS, both vendors: vendor->us and us->vendor (the latter is"
echo "              the direction that hid ADR 0057, and it is gated here with REP=xcdr1 because a stock"
echo "              foreign reader advertises XCDR1 only and DATA_REPRESENTATION is RxO)."
echo "gate-interop: NOT COVERED — Shapes + large-data only, and large-data only vs CONNEXT (there is no"
echo "              Fast DDS LargeData peer, so FRAGMENTATION IS UNTESTED against the second vendor)."
echo "              Per-feature legs (keyed/nokey, TypeLookup, keyed FlatData, liveliness, deadline,"
echo "              durability, security) have drivers under scripts/ and interop/ but are NOT gated yet."
echo "              Say so rather than let a green line read as 'interop is covered'."
