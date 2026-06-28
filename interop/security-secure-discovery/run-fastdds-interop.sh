#!/usr/bin/env bash
# T12 — LIVE Fast DDS-Security cross-vendor secure-discovery interop (M7/P6 Slice 4).
#
# Stands up a real eProsima Fast DDS-Security participant and one of OURS on the same domain over UDP
# loopback, sharing the reused Identity-CA / Permissions-CA / Governance (interop/security-secure-discovery),
# and drives the full DDS-Security 1.1 path: SPDP bootstrap -> §8.7 mutual PKI-DH auth handshake over the
# ParticipantStatelessMessage endpoint -> crypto-token exchange over reliable PVMS -> secure SEDP match ->
# protected user data, BOTH directions (ours->FastDDS and FastDDS->ours). tshark captures each direction on
# lo0 and the RTPS-security dissector validates our emitted SEC_PREFIX/SEC_POSTFIX/SRTPS_* submessages.
#
# Connext stays STATIC this slice (RTI Security Plugins absent -> Slice-5 P6 exit gate); see README.md.
#
# Usage: bash interop/security-secure-discovery/run-fastdds-interop.sh [GOV] [SECS]
#   GOV  = none (auth+access-control only, isolates the handshake) | secure (ENCRYPT discovery+rtps). Default none.
#   SECS = seconds per direction. Default 25.
# Prereq: a SECURITY=ON Fast DDS build (docs/provenance.md; spike §4). Not run by CI (external toolchain).
set -uo pipefail

GOV="${1:-none}"
SECS="${2:-25}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CAP_DIR="${SCRIPT_DIR}/captures"
WORK_DIR="${CAP_DIR}/work"
mkdir -p "${CAP_DIR}" "${WORK_DIR}"

TSHARK=/Applications/Wireshark.app/Contents/MacOS/tshark
FASTDDS_BUILD="/Users/frgo/gbt Dropbox/gbt/projects/fastdds/src/fastdds/build"
FASTDDS_BIN="${FASTDDS_BUILD}/examples/cpp/security/security"
FASTDDS_INSTALL="/Users/frgo/gbt Dropbox/gbt/projects/fastdds/install"

# ---- our reused PKI (Identity CA + Permissions CA + EC identities; Slice-2/3 trust anchors) ----
AUTH_PKI="${REPO_ROOT}/interop/security-auth/pki"
AC_PKI="${REPO_ROOT}/interop/security-access-control/pki"
export SSD_IDCA="${AUTH_PKI}/ca/ca-cert.pem"
export SSD_PERMCA="${AC_PKI}/perm-ca-cert.pem"
export SSD_CERT="${AUTH_PKI}/participant_ec/identity_cert.pem"     # Fast DDS peer = TestParticipantEC
export SSD_KEY="${AUTH_PKI}/participant_ec/identity_key.pem"
export SSD_GOV="${SCRIPT_DIR}/fastdds/certs/governance-${GOV}.smime"
export SSD_PERM="${SCRIPT_DIR}/fastdds/certs/permissions-hello.smime"
export FASTDDS_DEFAULT_PROFILES_FILE="${SCRIPT_DIR}/fastdds/secure_profile.xml"
export DYLD_LIBRARY_PATH="${FASTDDS_BUILD}/src/cpp:${FASTDDS_INSTALL}/lib:/opt/homebrew/opt/openssl@3/lib:${DYLD_LIBRARY_PATH:-}"

# our Lisp side uses the OTHER EC identity (ECB) + the PEM governance/permissions our dds.dare consumes
OUR_CA="${AUTH_PKI}/ca/ca-cert.pem"
OUR_CERT="${AUTH_PKI}/participant_ec_b/identity_cert.pem"
OUR_KEY="${AUTH_PKI}/participant_ec_b/identity_key.pem"
OUR_GOV="${SCRIPT_DIR}/pki/governance-${GOV}.p7s"
OUR_PERM="${SCRIPT_DIR}/pki/permissions-hello.p7s"
SBCL="${REPO_ROOT}/scripts/with-sbcl.sh"

for f in "${FASTDDS_BIN}" "${SSD_GOV}" "${SSD_PERM}" "${OUR_GOV}" "${OUR_PERM}" "${SSD_CERT}"; do
  [[ -e "${f}" ]] || { echo "MISSING: ${f}"; exit 2; }
done
echo "=== T12 cross-vendor secure discovery: GOV=${GOV} SECS=${SECS} ==="
echo "Fast DDS-Security peer: ${FASTDDS_BIN}"
"${TSHARK}" -v >/dev/null 2>&1 || echo "[warn] tshark not found at ${TSHARK}"

PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do kill "${p}" >/dev/null 2>&1 || true; done; pkill -f "examples/cpp/security/security" >/dev/null 2>&1 || true; }
trap cleanup EXIT

# our-side Lisp peer launcher: $1=role(pub|sub) $2=logfile; sets global OUR_PID (bash 3.2: no neg index)
OUR_PID=""
our_peer() {
  local role="$1" log="$2"
  "${SBCL}" --non-interactive \
    --eval '(asdf:load-system :dds-tests)' \
    --eval "(uiop:symbol-call :dds.tests :run-secure-interop-peer
              :role \"${role}\" :domain 0 :seconds ${SECS} :port 7420 :peers \"127.0.0.1:7410\"
              :ca \"${OUR_CA}\" :cert \"${OUR_CERT}\" :key \"${OUR_KEY}\"
              :perm-ca \"${SSD_PERMCA}\" :governance \"${OUR_GOV}\" :permissions \"${OUR_PERM}\"
              :topic \"HelloWorldTopic\" :type \"HelloWorld\" :samples 8 :interval 0.5)" \
    --eval '(uiop:quit 0)' >"${log}" 2>&1 &
  OUR_PID=$!
  PIDS+=("${OUR_PID}")
}

# one direction: $1=label $2=fastdds-role $3=our-role
run_dir() {
  local label="$1" frole="$2" orole="$3"
  local pcap="${CAP_DIR}/ssd-${GOV}-${label}.pcapng"
  local flog="${CAP_DIR}/ssd-${GOV}-${label}-fastdds.log"
  local olog="${CAP_DIR}/ssd-${GOV}-${label}-ours.log"
  echo ""
  echo "--- direction: ${label}  (Fast DDS=${frole}, ours=${orole}) ---"
  pkill -9 -f "examples/cpp/security/security" >/dev/null 2>&1 || true; sleep 1   # clear any leaked peer
  rm -f "${pcap}"
  "${TSHARK}" -i lo0 -f "udp portrange 7400-7600" -w "${pcap}" >/dev/null 2>&1 &
  local tpid=$!; PIDS+=("${tpid}"); sleep 1.5
  # Fast DDS first so it binds the standard domain-0 unicast metatraffic port (7410). -s 0 = run
  # unlimited (our SBCL peer needs ~40 s to load before its participant is up); publisher pushes at 500 ms.
  local fargs=(-s 0); [[ "${frole}" == "publisher" ]] && fargs=(-s 0 -i 500)
  ( cd "${FASTDDS_BUILD}/examples/cpp/security" && exec "${FASTDDS_BIN}" "${frole}" "${fargs[@]}" ) >"${flog}" 2>&1 &
  local fpid=$!; PIDS+=("${fpid}"); sleep 2.5
  our_peer "${orole}" "${olog}"; local opid="${OUR_PID}"
  wait "${opid}" 2>/dev/null || true
  sleep 1; kill "${fpid}" >/dev/null 2>&1 || true; pkill -9 -f "examples/cpp/security/security" >/dev/null 2>&1 || true
  kill "${tpid}" >/dev/null 2>&1 || true; sleep 1
  echo "  [ours]    $(grep -aE 'SUMMARY|RESULT' "${olog}" | tail -2 | tr '\n' ' ')"
  echo "  [fastdds] $(grep -aiE 'matched|RECEIVED|SENT|SAMPLE|authoriz|error' "${flog}" | tail -4 | tr '\n' ' | ')"
  echo "  [pcap]    ${pcap}"
}

run_dir "ours2fast" subscriber pub
run_dir "fast2ours" publisher  sub

echo ""
echo "=== tshark RTPS-security dissector validation (our emitted secure submessages) ==="
for pcap in "${CAP_DIR}/ssd-${GOV}-ours2fast.pcapng" "${CAP_DIR}/ssd-${GOV}-fast2ours.pcapng"; do
  [[ -f "${pcap}" ]] || continue
  echo "--- ${pcap##*/} ---"
  "${TSHARK}" -r "${pcap}" -Y 'rtps' -T fields -e frame.number -e rtps.sm.id 2>/dev/null \
    | grep -iE '0x3[0-4]' | head -5 || true
  echo "  submessage-kind histogram:"
  "${TSHARK}" -r "${pcap}" -Y 'rtps' -T fields -e rtps.sm.id 2>/dev/null \
    | tr ',' '\n' | sort | uniq -c | sort -rn | head -20 || true
  echo "  malformed/expert (should be empty for our frames):"
  "${TSHARK}" -r "${pcap}" -Y 'rtps && _ws.expert.severity >= 0x600000' -T fields -e frame.number 2>/dev/null | head || true
done
echo ""
echo "=== done (GOV=${GOV}). Captures in ${CAP_DIR}/ ==="
