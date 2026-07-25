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

# A LEAKED PEER FROM AN EARLIER RUN POISONS THIS ONE, SILENTLY AND UPWARDS. A stray publisher on the
# same domain and topic inflates sample counts (an aborted run left a shapes_pub alive and the Shapes
# legs read 741/719 instead of ~250) and starves the legs it collides with — three unrelated legs went
# red in the same run. Counts only ever go UP, so the result looks HEALTHIER, which is precisely why
# this must be checked rather than eyeballed. Abort instead of reporting a number nobody can trust.
STRAYS="$(pgrep -f 'interop/(connext|appendable|fastdds).*/(shapes|nokey|mutable|large|appendable|perf)_(pub|sub)' 2>/dev/null || true)"
if [[ -n "$STRAYS" ]]; then
  echo "gate-interop: ABORT — peer process(es) from an earlier run are still alive:" >&2
  ps -o pid,etime,command -p $STRAYS >&2 || true
  echo "gate-interop: they will cross-talk on the same domains and corrupt every count below." >&2
  echo "gate-interop: kill them and re-run (they are this harness's own binaries, not the owner's)." >&2
  exit 1
fi

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
    # NOTE THE TRAILING SPACE. The subscriber's BANNER is "[sub] Square/ShapeType[canonical] domain=0 ...",
  # so the obvious pattern '^\[sub\] Square' MATCHES IT and a leg that received NOTHING scores 1. With the
  # old ">0 samples" test that read GREEN — a totally failing leg reported as passing interop. A per-sample
  # line is "[sub] Square BLUE x=.. y=.. size=..", hence 'Square ' with the space.
  n="$(grep -c '^\[sub\] Square [A-Za-z]' "$log" || true)"
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
    # NOTE THE TRAILING SPACE. The subscriber's BANNER is "[sub] Square/ShapeType[canonical] domain=0 ...",
  # so the obvious pattern '^\[sub\] Square' MATCHES IT and a leg that received NOTHING scores 1. With the
  # old ">0 samples" test that read GREEN — a totally failing leg reported as passing interop. A per-sample
  # line is "[sub] Square BLUE x=.. y=.. size=..", hence 'Square ' with the space.
  n="$(grep -c '^\[sub\] Square [A-Za-z]' "$log" || true)"
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

# ---- Leg 20: DDS-SECURITY cross-vendor, GOV=secure (all-ENCRYPT). The P6 exit gate. ----
# GOV=secure, not GOV=none, and the difference is the whole point: `none` exercises authentication and
# access control with protection NONE, so it proves the §8.7 PKI-DH handshake and the permissions
# documents but NOT ONE BYTE of crypto. `secure` is all-ENCRYPT — the crypto-token exchange over PVMS,
# protected SEDP, and AES-GCM on the data — and the script's own summary reports `ever-keyed=T` only
# when the key exchange actually happened, which is what distinguishes "encrypted" from "matched".
# The runner drives BOTH directions itself: ours->Connext observed by rtiddsspy, and Connext->ours
# with a real secured Connext publisher (hello_secure_pub) whose AEAD data our subscriber decodes.
#
# PREREQUISITE, and it fails LOUDLY rather than skipping: RTI's security plugin resolves
# libssl.3/libcrypto.3 via @loader_path and ships no OpenSSL, so they must be symlinked into
# $NDDSHOME/resource/app/lib/$CONNEXTDDS_ARCH/ (see the runner's header). Without it the plugin cannot
# load and the leg would otherwise look like a protocol failure.
if [[ "$have_connext" -eq 1 && -x interop/security-connext/hello_secure_pub ]]; then
  if [[ ! -e "$NDDSHOME/resource/app/lib/arm64Darwin20clang12.0/libssl.3.dylib" ]]; then
    note "FAIL" "DDS-Security: RTI's OpenSSL symlinks are absent — see interop/security-connext/run-connext-interop.sh"
    fails=1
  else
    log="$(mktemp)"
    tmout $((SECONDS_RUN * 2 + 120)) bash interop/security-connext/run-connext-interop.sh secure "$SECONDS_RUN" \
      > "$log" 2>&1
    passes="$(grep -c 'RESULT: PASS' "$log" || true)"
    keyed="$(grep -c 'ever-keyed=T' "$log" || true)"
    if [[ "$passes" -ge 2 && "$keyed" -ge 1 ]]; then
      note "ok" "DDS-Security GOV=secure: both directions PASS, crypto keys exchanged (ever-keyed=T)"
    else
      note "FAIL" "DDS-Security GOV=secure: $passes/2 direction(s) PASS, keyed=$keyed (log: $log)"; fails=1
    fi
  fi
fi

# ---- Leg 19: TypeLookup CLIENT — our getTypes query against a live Fast DDS server. ----
# The one protocol in this stack with NO Connext oracle at all: RTI does not implement the TypeLookup
# service (ADR 0010), so every byte of it was self-pinned regression vectors plus a tshark decode
# until Fast DDS provided a real server. This leg keeps that peer confirmation running instead of
# leaving it as a one-off manual result recorded in a README.
#
# It asserts the ROUND TRIP, not merely a reply: the probe takes the EK_MINIMAL hash from the peer's
# SEDP PID_TYPE_INFORMATION, issues getTypes, parses the returned TypeObject and RE-HASHES it, and
# passes only if the hash it computes equals the hash it asked for. A reply that parsed but hashed
# differently would be a silent corruption of exactly the identity the type gate matches on.
if [[ "$have_fastdds" -eq 1 && -x interop/fastdds/shapes/shapes_pub ]]; then
  TLDOM=$DOMAIN   # Fast DDS's profile pins the builtin port for this domain; its peers live here
  log="$(mktemp)"
  g="$(start_peer "$log" ./scripts/with-fastdds.sh bash -c "cd interop/fastdds/shapes && exec ./shapes_pub GREEN 0")"
  sleep 6
  tmout $((SECONDS_RUN + 25)) ./scripts/with-sbcl.sh \
    --eval "(asdf:load-system :dds-shapes)" \
    --eval "(uiop:symbol-call :dds.shapes :run-typelookup-probe :domain $TLDOM :seconds $SECONDS_RUN :advertise-address \"127.0.0.1\" :peers \"127.0.0.1:7410\")" \
    --eval '(uiop:quit 0)' > "$log.ours" 2>&1
  stop_peer "$g"
  if grep -q 'tl-probe\] PASS' "$log.ours"; then
    note "ok" "TypeLookup getTypes vs Fast DDS: $(grep -oE 'TypeObject [0-9]+ octets' "$log.ours" | head -1) re-hashes to the queried hash"
  else
    note "FAIL" "TypeLookup getTypes vs Fast DDS: $(grep -oE '\[tl-probe\] FAIL.*' "$log.ours" | head -1) (log: $log.ours)"; fails=1; fi
fi

# ---- Legs 17/18: KEYED FLATDATA, both directions vs Connext (FR-PF-4, ADR 0015/0017; R6). ----
# The crux is not that samples arrive: it is that a keyed FlatData instance's IDENTITY agrees across
# vendors. Our keyhash for a FlatData sample is computed by reading the fields back out of the
# SerializedPayload (key-hash-<name>-fd) rather than from a struct, so it is a genuinely different
# code path from the one every other keyed leg exercises, and RTPS 2.5 §9.6.4.8 is what both sides
# must agree on. NOTE R6: FlatData is not cleared to ship pending patent counsel — gating it here
# tests it, it does not ship it.
if [[ "$have_connext" -eq 1 && -x interop/keyed-flatdata/connext/keyed_flat_sub && -x interop/keyed-flatdata/connext/keyed_flat_pub ]]; then
  export NDDSHOME
  export DYLD_LIBRARY_PATH="$NDDSHOME/lib/arm64Darwin20clang12.0:$PWD/interop/keyed-flatdata/connext:${DYLD_LIBRARY_PATH:-}"
  KFDOM=$((DOMAIN + 9)); KFPEER="127.0.0.1:$((7400 + 250 * KFDOM + 10))"
  # Leg 17: us -> Connext, keyed FlatData.
  log="$(mktemp)"
  g="$(start_peer "$log" bash -c "cd interop/keyed-flatdata/connext && exec ./keyed_flat_sub $KFDOM $((SECONDS_RUN + 8))")"
  sleep 4
  tmout $((SECONDS_RUN + 25)) ./scripts/with-sbcl.sh \
    --eval "(asdf:load-system :dds-shapes)" \
    --eval "(uiop:symbol-call :dds.shapes :run-keyed-flat-publisher :domain $KFDOM :advertise-address \"127.0.0.1\" :peers \"$KFPEER\" :count $((SECONDS_RUN * 5)) :rate 5 :keys 3 :data-representation :xcdr1)" \
    --eval '(uiop:quit 0)' >/dev/null 2>&1
  wait_peer "$g" $((SECONDS_RUN + 30)); stop_peer "$g"
  n="$(grep -c '\[connext-kflat-sub\] #' "$log" || true)"
  if [[ "$n" -ge "$MIN_SAMPLES" ]]; then note "ok" "us -> Connext KEYED FLATDATA: $n sample(s), instances keyed by §9.6.4.8 keyhash"; else
    note "FAIL" "us -> Connext KEYED FLATDATA: only $n sample(s), need >= $MIN_SAMPLES (log: $log)"; fails=1; fi
  # Leg 18: Connext -> us, keyed FlatData.
  log="$(mktemp)"
  g="$(start_peer "$log" bash -c "cd interop/keyed-flatdata/connext && exec ./keyed_flat_pub $KFDOM 0")"
  sleep 3
  tmout $((SECONDS_RUN + 25)) ./scripts/with-sbcl.sh \
    --eval "(asdf:load-system :dds-shapes)" \
    --eval "(uiop:symbol-call :dds.shapes :run-keyed-flat-subscriber :domain $KFDOM :advertise-address \"127.0.0.1\" :peers \"$KFPEER\" :seconds $SECONDS_RUN)" \
    --eval '(uiop:quit 0)' > "$log.ours" 2>&1
  stop_peer "$g"
  n="$(grep -c '\[kflat-sub\] #' "$log.ours" || true)"
  if [[ "$n" -ge "$MIN_SAMPLES" ]]; then note "ok" "Connext -> us KEYED FLATDATA: $n sample(s), read in place from the payload"; else
    note "FAIL" "Connext -> us KEYED FLATDATA: only $n sample(s), need >= $MIN_SAMPLES (log: $log.ours)"; fails=1; fi
fi

# ---- Legs 15/16: the two TypeObject-shape probes (enum TK_ENUM, string8 LARGE form). ----
# Both existed as READMEs describing a manual two-terminal run, and neither had ever been gated. They
# cover the two TypeObject encodings the logging type depends on and that ADR 0009 flags as the
# defect class: our (:enum ...) member announces TK_INT32 where a foreign IDL declares TK_ENUM, and a
# (:string 1024) member announces TI_STRING8_LARGE (0x71) + an LBound UInt32 — the LARGE form, which
# no live peer had ever confirmed. Both peers pin themselves to 127.0.0.1 with an empty
# <multicast_receive_addresses/>, so each needs a unicast SPDP peer, and each gets its OWN DOMAIN.
if [[ "$have_connext" -eq 1 && -x interop/enum-typeobject/enum_pub && -x interop/string-large/stringlarge_pub ]]; then
  export NDDSHOME
  # Leg 15: TK_ENUM writer -> our TK_INT32 reader.
  ENUMDOM=$((DOMAIN + 7)); ENUMPEER="127.0.0.1:$((7400 + 250 * ENUMDOM + 10))"
  export DYLD_LIBRARY_PATH="$NDDSHOME/lib/arm64Darwin20clang12.0:$PWD/interop/enum-typeobject:${DYLD_LIBRARY_PATH:-}"
  log="$(mktemp)"
  g="$(start_peer "$log" bash -c "cd interop/enum-typeobject && exec ./enum_pub $ENUMDOM 0")"
  sleep 4
  PROBE_DOMAIN=$ENUMDOM PROBE_SECONDS=$SECONDS_RUN PROBE_PEERS="$ENUMPEER" \
    tmout $((SECONDS_RUN + 25)) ./scripts/with-sbcl.sh --load interop/enum-typeobject/enum_sub.lisp \
    > "$log.ours" 2>&1
  stop_peer "$g"
  if grep -q 'VERDICT: TOLERATED' "$log.ours"; then
    note "ok" "Connext TK_ENUM -> us: $(grep -c 'enum-probe\] sample #' "$log.ours") sample(s), values decoded (we announce TK_INT32 — ADR 0009 gap TOLERATED, not fixed)"
  else
    note "FAIL" "Connext TK_ENUM -> us: no data (log: $log.ours)"; fails=1; fi
  # Leg 16: string<1024> writer -> our TI_STRING8_LARGE reader.
  SLDOM=$((DOMAIN + 8)); SLPEER="127.0.0.1:$((7400 + 250 * SLDOM + 10))"
  export DYLD_LIBRARY_PATH="$NDDSHOME/lib/arm64Darwin20clang12.0:$PWD/interop/string-large:${DYLD_LIBRARY_PATH:-}"
  log="$(mktemp)"
  g="$(start_peer "$log" bash -c "cd interop/string-large && exec ./stringlarge_pub $SLDOM 0")"
  sleep 4
  PROBE_DOMAIN=$SLDOM PROBE_SECONDS=$SECONDS_RUN PROBE_PEERS="$SLPEER" \
    tmout $((SECONDS_RUN + 25)) ./scripts/with-sbcl.sh --load interop/string-large/stringlarge_sub.lisp \
    > "$log.ours" 2>&1
  stop_peer "$g"
  if grep -q 'VERDICT: INTEROPERATES' "$log.ours"; then
    note "ok" "Connext string<1024> -> us: $(grep -c 'strlarge-probe\] sample #' "$log.ours") sample(s), TI_STRING8_LARGE decoded"
  else
    note "FAIL" "Connext string<1024> -> us: no data (log: $log.ours)"; fails=1; fi
fi

# ---- Legs 13/14: APPENDABLE extensibility, both directions vs Connext (XTypes rules 29/30). ----
# With these, ALL THREE extensibility kinds are exercised live against the strict oracle rather than
# only against our own decoder: FINAL by the Shapes legs, MUTABLE by legs 8/9, APPENDABLE here.
# APPENDABLE is the kind whose framing DIFFERS BY ENCODING — a DHEADER under XCDR2 (rule 30), AsFinal
# with none under XCDR1 (rule 29) — and Table 60 gives it its own encapsulation id, D_CDR2_LE 0x0009.
# Both peers were built and committed and nothing had ever run them.
# REP=xcdr1 for the outbound leg, for the reason legs 3 and 11 give: a stock Connext reader advertises
# XCDR1 only and DATA_REPRESENTATION is an RxO policy. Under XCDR1 rule (29) this exercises the
# AsFinal path; the XCDR2 DHEADER framing is covered by the inbound leg and by make corpus.
if [[ "$have_connext" -eq 1 && -x interop/appendable/appendable_sub && -x interop/appendable/appendable_pub ]]; then
  export NDDSHOME
  export DYLD_LIBRARY_PATH="$NDDSHOME/lib/arm64Darwin20clang12.0:$PWD/interop/appendable:${DYLD_LIBRARY_PATH:-}"
  ADV="${ADVERTISE:-$(ipconfig getifaddr en0 2>/dev/null || echo 127.0.0.1)}"
  # A DEDICATED DOMAIN, and this is not optional. The appendable peers publish "Square"/"ShapeType" —
  # the SAME topic and type name as the Shapes legs, deliberately, because type-consistency matches on
  # the name and a different one would muddy the extensibility result (interop/appendable/AppendableShape.idl
  # says so). On a shared domain that makes them indistinguishable from the Shapes traffic: the first
  # attempt inflated the Shapes legs to 741/719 samples and knocked three unrelated legs over.
  APDOMAIN=$((DOMAIN + 3))
  # LOOPBACK + a unicast peer, not the LAN address. interop/appendable/USER_QOS_PROFILES.xml pins these
  # peers with EMPTY <initial_peers> and NO multicast_receive_addresses, so they announce to nobody and
  # hear no multicast: the ONLY way to meet them is to announce unicast at their metatraffic port and
  # advertise a locator they can answer. The README says as much (ADVERTISE=127.0.0.1 PEERS=...); passing
  # the LAN address instead is a silent non-discovery, not an error.
  APPEER="127.0.0.1:$((7400 + 250 * APDOMAIN + 10))"
  # Leg 13: us -> Connext, APPENDABLE.
  log="$(mktemp)"
  g="$(start_peer "$log" bash -c "cd interop/appendable && exec ./appendable_sub $APDOMAIN $((SECONDS_RUN + 8))")"
  sleep 4
  tmout $((SECONDS_RUN + 25)) ./scripts/with-sbcl.sh \
    --eval "(asdf:load-system :dds-shapes)" \
    --eval "(uiop:symbol-call :dds.shapes :run-publisher :domain $APDOMAIN :type :appendable :data-representation :xcdr1 :advertise-address \"127.0.0.1\" :peers \"$APPEER\" :color \"BLUE\" :count $((SECONDS_RUN * 20)) :rate 20)" \
    --eval '(uiop:quit 0)' >/dev/null 2>&1
  wait_peer "$g" $((SECONDS_RUN + 30)); stop_peer "$g"
  n="$(grep -c '\[connext-sub\] #' "$log" || true)"
  if [[ "$n" -ge "$MIN_SAMPLES" ]]; then note "ok" "us -> Connext APPENDABLE: $n sample(s) accepted by the STRICT oracle"; else
    note "FAIL" "us -> Connext APPENDABLE: only $n sample(s), need >= $MIN_SAMPLES (log: $log)"; fails=1; fi
  # Leg 14: Connext -> us, APPENDABLE.
  log="$(mktemp)"
  g="$(start_peer "$log" bash -c "cd interop/appendable && exec ./appendable_pub $APDOMAIN GREEN")"
  sleep 3
  tmout $((SECONDS_RUN + 25)) ./scripts/with-sbcl.sh \
    --eval "(asdf:load-system :dds-shapes)" \
    --eval "(uiop:symbol-call :dds.shapes :run-subscriber :domain $APDOMAIN :type :appendable :advertise-address \"127.0.0.1\" :peers \"$APPEER\" :seconds $SECONDS_RUN)" \
    --eval '(uiop:quit 0)' > "$log.ours" 2>&1
  stop_peer "$g"
  n="$(grep -c '\[sub\] Square(appendable)' "$log.ours" || true)"
  if [[ "$n" -ge "$MIN_SAMPLES" ]]; then note "ok" "Connext -> us APPENDABLE: $n sample(s) (DHEADER framing decoded)"; else
    note "FAIL" "Connext -> us APPENDABLE: only $n sample(s), need >= $MIN_SAMPLES (log: $log.ours)"; fails=1; fi
elif [[ "$have_connext" -eq 1 ]]; then
  note "FAIL" "Connext APPENDABLE peers not built — run: cd interop/appendable && make"
  fails=1
fi

# ---- Legs 8/9: MUTABLE extensibility, both directions vs Connext (ADR 0086). ----
# The corpus proves our ENCODER reproduces Connext's octets for a @mutable sample. It cannot prove that
# Connext's own DataReader ACCEPTS what we write — type gate, encapsulation id, per-member framing and
# all — and those are different claims. This leg is the second one.
#
# It has already earned its place. The first run scored matched=0 while Connext's log showed it had
# matched US: a ONE-SIDED match, our type gate refusing a conformant peer. Cause: our TypeObject
# announced the member name "t-ns" (from the Lisp slot) where the IDL declares "t_ns", and assignability
# matches members by NameHash — so an identical type was judged inconsistent, silently, with no error
# anywhere. That is the ADR 0057 shape exactly, and only an outbound live leg can see it.
#
# REP=xcdr1 is REQUIRED and is not a tuning choice: Connext sends and expects @mutable as PL_CDR
# (encoding version 1) — the committed vector proves it — and DATA_REPRESENTATION is an RxO policy, so
# an XCDR2-default writer silently fails to match.
if [[ "$have_connext" -eq 1 && -x interop/connext/mutable/mutable_sub ]]; then
  export NDDSHOME
  export DYLD_LIBRARY_PATH="$NDDSHOME/lib/arm64Darwin20clang12.0:$PWD/interop/connext/mutable:${DYLD_LIBRARY_PATH:-}"
  ADV="${ADVERTISE:-$(ipconfig getifaddr en0 2>/dev/null || echo 127.0.0.1)}"
  # Leg 8: us -> Connext, MUTABLE.
  log="$(mktemp)"
  g="$(start_peer "$log" bash -c "cd interop/connext/mutable && exec ./mutable_sub $DOMAIN $((SECONDS_RUN + 8))")"
  sleep 5
  tmout $((SECONDS_RUN + 25)) ./scripts/with-sbcl.sh \
    --eval "(asdf:load-system :dds-bench)" \
    --eval "(uiop:symbol-call :dds.bench :run-mutable-publisher :domain $DOMAIN :advertise-address \"$ADV\" :count $((SECONDS_RUN * 20)) :rate 20 :data-representation :xcdr1)" \
    --eval '(uiop:quit 0)' >/dev/null 2>&1
  wait_peer "$g" $((SECONDS_RUN + 30)); stop_peer "$g"
  # Assert the VALUES, not a sample count: a decode that silently defaulted a member would otherwise pass.
  n="$(grep -c 'a=1 b=2 label=hello t_ns=3 vals=3 7 8 9' "$log" || true)"
  if [[ "$n" -ge "$MIN_SAMPLES" ]]; then note "ok" "us -> Connext MUTABLE: $n sample(s), every member correct (STRICT oracle)"; else
    note "FAIL" "us -> Connext MUTABLE: only $n fully-correct sample(s), need >= $MIN_SAMPLES (log: $log)"; fails=1; fi
  # Leg 9: Connext -> us, MUTABLE. Their PL_CDR framing through our decoder.
  log="$(mktemp)"
  g="$(start_peer "$log" bash -c "cd interop/connext/mutable && exec ./mutable_pub $DOMAIN")"
  sleep 3
  tmout $((SECONDS_RUN + 25)) ./scripts/with-sbcl.sh \
    --eval "(asdf:load-system :dds-bench)" \
    --eval "(uiop:symbol-call :dds.bench :run-mutable-subscriber :domain $DOMAIN :advertise-address \"$ADV\" :seconds $SECONDS_RUN)" \
    --eval '(uiop:quit 0)' > "$log.ours" 2>&1
  stop_peer "$g"
  n="$(grep -c 'a=1 b=2 label=hello t_ns=3 vals=3 7 8 9' "$log.ours" || true)"
  if [[ "$n" -ge "$MIN_SAMPLES" ]]; then note "ok" "Connext -> us MUTABLE: $n sample(s), every member correct"; else
    note "FAIL" "Connext -> us MUTABLE: only $n fully-correct sample(s), need >= $MIN_SAMPLES (log: $log.ours)"; fails=1; fi
elif [[ "$have_connext" -eq 1 ]]; then
  note "FAIL" "Connext MUTABLE peer not built — run: cd interop/connext/mutable && make"
  fails=1
fi

# ---- Legs 11/12: NO_KEY endpoints, both directions vs Connext (RTPS 2.5 §9.3.1.2). ----
# A type's keyed-ness selects the RTPS entity KIND on the wire: 0x03/0x04 for the no-key writer/reader
# against 0x02/0x07 for the keyed pair. That is a discovery-level property, so getting it wrong does not
# corrupt a payload — it makes the endpoints simply not match, which is the failure mode this whole gate
# exists to catch and the one no unit test can. Both peers have been built and sitting unused in
# interop/connext/nokey/; gating them costs one run and closes a "driver exists but nothing runs it" gap.
if [[ "$have_connext" -eq 1 && -x interop/connext/nokey/nokey_sub && -x interop/connext/nokey/nokey_pub ]]; then
  export NDDSHOME
  export DYLD_LIBRARY_PATH="$NDDSHOME/lib/arm64Darwin20clang12.0:$PWD/interop/connext/nokey:${DYLD_LIBRARY_PATH:-}"
  # LOOPBACK + an explicit unicast SPDP peer, exactly as the archived proof runs did
  # (interop/connext/nokey/captures/). Multicast alone does NOT bring these two together here: the
  # macOS application firewall silently drops LAN-sourced UDP for an unapproved peer binary, and these
  # peers get relinked. 7410 = PB(7400) + DG*domain + d1(10), so this pins the leg to domain 0.
  # A RANGE of participant indices, not just index 0. The unicast metatraffic port is
  # PB + DG*domain + d1 + PG*participantIndex (RTPS 2.5 §9.6.1.1), and the index a peer gets depends on
  # what else is already bound on this domain — which, in a gate that has just run eight other legs, is
  # not reliably 0. Pinning 7410 alone made the OUTBOUND leg announce into a port nobody was listening
  # on, while the inbound leg happened to work; covering indices 0-3 removes that ordering dependence.
  NKBASE=$((7400 + 250 * DOMAIN + 10))
  NKPEER="127.0.0.1:$NKBASE,127.0.0.1:$((NKBASE + 2)),127.0.0.1:$((NKBASE + 4)),127.0.0.1:$((NKBASE + 6))"
  # Leg 11: us -> Connext, NO_KEY. REP=xcdr1 is REQUIRED, not tuning — see below.
  #
  # THIS LEG LOOKED LIKE A NO_KEY DEFECT AND WAS NOT ONE. It reported matched=0, and NO_KEY was a red
  # herring: the remote reader was discovered perfectly (topic, type, and entity kind 0x04 all correct)
  # and endpoint-match-p rejected it on (:DATA-REPRESENTATION) alone. A stock Connext DataReader
  # generated from a plain IDL advertises XCDR1 ONLY; DATA_REPRESENTATION is an RxO policy; our
  # XCDR2-default writer therefore silently does not match — matched=0, no error, no INCONSISTENT_TOPIC.
  # Exactly the trap the Shapes leg documents, which run-nokey-publisher had no parameter to avoid.
  log="$(mktemp)"
  g="$(start_peer "$log" bash -c "cd interop/connext/nokey && exec ./nokey_sub $DOMAIN $((SECONDS_RUN + 8))")"
  sleep 4
  tmout $((SECONDS_RUN + 25)) ./scripts/with-sbcl.sh \
    --eval "(asdf:load-system :dds-shapes)" \
    --eval "(uiop:symbol-call :dds.shapes :run-nokey-publisher :domain $DOMAIN :advertise-address \"127.0.0.1\" :peers \"$NKPEER\" :count $((SECONDS_RUN * 5)) :rate 5 :data-representation :xcdr1)" \
    --eval '(uiop:quit 0)' >/dev/null 2>&1
  wait_peer "$g" $((SECONDS_RUN + 30)); stop_peer "$g"
  n="$(grep -c '\[connext-nokey-sub\] #' "$log" || true)"
  if [[ "$n" -ge "$MIN_SAMPLES" ]]; then note "ok" "us -> Connext NO_KEY: $n sample(s) (writer kind 0x03 matched)"; else
    note "FAIL" "us -> Connext NO_KEY: only $n sample(s), need >= $MIN_SAMPLES (log: $log)"; fails=1; fi
  # Leg 12: Connext -> us, NO_KEY.
  log="$(mktemp)"
  g="$(start_peer "$log" bash -c "cd interop/connext/nokey && exec ./nokey_pub $DOMAIN 0")"
  sleep 3
  tmout $((SECONDS_RUN + 25)) ./scripts/with-sbcl.sh \
    --eval "(asdf:load-system :dds-shapes)" \
    --eval "(uiop:symbol-call :dds.shapes :run-nokey-subscriber :domain $DOMAIN :advertise-address \"127.0.0.1\" :peers \"$NKPEER\" :seconds $SECONDS_RUN)" \
    --eval '(uiop:quit 0)' > "$log.ours" 2>&1
  stop_peer "$g"
  n="$(grep -c '\[nokey-sub\] sample #' "$log.ours" || true)"
  if [[ "$n" -ge "$MIN_SAMPLES" ]]; then note "ok" "Connext -> us NO_KEY: $n sample(s) (reader kind 0x04 matched)"; else
    note "FAIL" "Connext -> us NO_KEY: only $n sample(s), need >= $MIN_SAMPLES (log: $log.ours)"; fails=1; fi
fi

# ---- Leg 10: Fast DDS -> us, MUTABLE. The SECOND vendor's parameter framing. ----
# Not redundant with the Connext MUTABLE legs, because the two vendors DISAGREE about the XCDR1
# parameter framing and both readings are defensible: Connext pads a parameter's declared length to a
# multiple of 4 and sets FLAG_MUST_UNDERSTAND on the list terminator (0x7F02); Fast DDS declares the
# exact ssize and writes a bare 0x3F02. Our ENCODER can only be byte-exact against one of them, and it
# matches Connext (the strict oracle); this leg pins the half that must hold for either, which is that
# we DECODE the other vendor's choice. Fast DDS is loopback-whitelisted, so it needs a unicast SPDP peer.
if [[ "$have_fastdds" -eq 1 && -x interop/fastdds/mutable/mutable_pub ]]; then
  log="$(mktemp)"
  g="$(start_peer "$log" ./scripts/with-fastdds.sh bash -c "cd interop/fastdds/mutable && exec ./mutable_pub 0")"
  sleep 4
  tmout $((SECONDS_RUN + 25)) ./scripts/with-sbcl.sh \
    --eval "(asdf:load-system :dds-bench)" \
    --eval "(uiop:symbol-call :dds.bench :run-mutable-subscriber :domain $DOMAIN :advertise-address \"127.0.0.1\" :peers \"127.0.0.1:7410\" :seconds $SECONDS_RUN)" \
    --eval '(uiop:quit 0)' > "$log.ours" 2>&1
  stop_peer "$g"
  n="$(grep -c 'a=1 b=2 label=hello t_ns=3 vals=3 7 8 9' "$log.ours" || true)"
  if [[ "$n" -ge "$MIN_SAMPLES" ]]; then note "ok" "Fast DDS -> us MUTABLE: $n sample(s), every member correct (2nd vendor's framing)"; else
    note "FAIL" "Fast DDS -> us MUTABLE: only $n fully-correct sample(s), need >= $MIN_SAMPLES (log: $log.ours)"; fails=1; fi
elif [[ "$have_fastdds" -eq 1 ]]; then
  note "FAIL" "Fast DDS MUTABLE peer not built — run: ./scripts/with-fastdds.sh bash -c 'cd interop/fastdds/mutable && make gen && make mutable_pub'"
  fails=1
fi

# ---- Leg 7: us -> Fast DDS, LARGE DATA. Fragmentation against the SECOND vendor. ----
# Fast DDS is the LENIENT peer, so this proves strictly less than the Connext large leg — but until this
# existed, fragmentation had exactly ONE vendor behind it, and "our emitted datagram size interoperates" is
# a claim about both. Fast DDS's profile whitelists 127.0.0.1 only and never sees LAN multicast SPDP, so we
# must announce unicast to its builtin metatraffic port. The peer verifies the payload octet-by-octet.
if [[ "$have_fastdds" -eq 1 && -x interop/fastdds/largedata/large_sub ]]; then
  log="$(mktemp)"
  g="$(start_peer "$log" ./scripts/with-fastdds.sh bash -c "cd interop/fastdds/largedata && exec ./large_sub $((SECONDS_RUN + 10))")"
  sleep 6
  tmout $((SECONDS_RUN + 25)) ./scripts/with-sbcl.sh \
    --eval "(asdf:load-system :dds-shapes)" \
    --eval "(uiop:symbol-call :dds.shapes :run-large-publisher :domain $DOMAIN :size 8000 :count $((SECONDS_RUN + 5)) :rate 2 :advertise-address \"127.0.0.1\" :peers \"127.0.0.1:7410\")" \
    --eval '(uiop:quit 0)' >/dev/null 2>&1
  wait_peer "$g" $((SECONDS_RUN + 30)); stop_peer "$g"
  n="$(grep -c 'payload-len=8000 pattern=OK' "$log" || true)"
  if [[ "$n" -ge "$MIN_SAMPLES" ]]; then note "ok" "us -> Fast DDS LARGE: $n fragmented sample(s), pattern OK (LENIENT peer)"; else
    note "FAIL" "us -> Fast DDS LARGE: only $n verified sample(s), need >= $MIN_SAMPLES (log: $log)"; fails=1; fi
elif [[ "$have_fastdds" -eq 1 ]]; then
  note "FAIL" "Fast DDS LARGE peer not built — run: ./scripts/with-fastdds.sh bash -c 'cd interop/fastdds/largedata && make'"
  fails=1
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
echo "gate-interop: NOT COVERED — Shapes + large-data + all three EXTENSIBILITY kinds + NO_KEY. Large-data runs against BOTH vendors"
echo "              (Connext both directions; Fast DDS outbound — there is no Fast DDS LargeData publisher,"
echo "              so DATA_FRAG REASSEMBLY is gated against Connext only). MUTABLE runs against BOTH vendors, for a"
echo "              reason worth stating: BOTH vendors send @mutable as PL_CDR (XCDR1), so these legs gate"
echo "              the parameter-list framing only — the PL_CDR2 (XCDR2) framing has NO live peer behind"
echo "              it from either vendor, so its length-code choice stays externally unpinned."
echo "              NO_KEY is gated BOTH directions vs Connext. Per-feature legs still NOT gated:"
echo "              liveliness, deadline, durability — drivers exist"
echo "              under scripts/ and interop/, but nothing runs them. (enum TK_ENUM and string8-LARGE"
echo "              are legs 15/16; keyed FlatData 17/18; TypeLookup CLIENT 19 — the TypeLookup"
echo "              SERVER side is still ungated: a stock Fast DDS client needs a non-stock patch"
echo "              to query us (FR-IO-2 S4 leg B), so only the client direction is gateable.)"
echo "              DDS-Security is leg 20 at GOV=secure; the sign/datasign governance profiles are"
echo "              runnable by hand (run-connext-interop.sh) but not gated."
echo "              Say so rather than let a green line read as 'interop is covered'."
