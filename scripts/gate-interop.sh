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
tmout() {                       # tmout <seconds> <cmd...>
  local secs="$1"; shift
  "$@" & local p=$!
  ( sleep "$secs"; kill -9 "$p" 2>/dev/null ) & local w=$!
  wait "$p" 2>/dev/null; local rc=$?
  kill -9 "$w" 2>/dev/null
  return "$rc"
}

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
  if [[ "$n" -gt 0 ]]; then note "ok" "Connext -> us: $n sample(s) received"; else
    note "FAIL" "Connext -> us: NO samples (log: $log)"; fails=1; fi
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
  if [[ "$n" -gt 0 ]]; then note "ok" "Fast DDS -> us: $n sample(s) (LENIENT peer — proves less than Connext)"; else
    note "FAIL" "Fast DDS -> us: NO samples (log: $log)"; fails=1; fi
fi

if [[ "$fails" -ne 0 ]]; then
  echo "gate-interop: FAIL — see above." >&2
  exit 1
fi
echo "gate-interop: PASS — live cross-vendor interop validated (Connext = the strict oracle)."
# NO SILENT CAPS: state what this gate does NOT cover, every run. A gate that quietly tests half the
# surface reads as "interop is covered" when it is not — which is how the DCPS writer went 6 slices
# without EVER matching a foreign reader (ADR 0057; every prior leg had exercised our READER).
echo "gate-interop: COVERAGE GAP — INBOUND only (vendor -> us). The OUTBOUND leg (us -> vendor) is NOT"
echo "              gated here. It is the direction that hid ADR 0057, and it needs REP=xcdr1 (a stock"
echo "              foreign shapes reader advertises XCDR1 only, and DATA_REPRESENTATION is RxO, so our"
echo "              XCDR2 writer silently does not match). Run it by hand; gating it is a follow-on."
