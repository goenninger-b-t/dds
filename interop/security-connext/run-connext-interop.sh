#!/usr/bin/env bash
# M7/P6 Slice 5b — LIVE RTI Connext-Security cross-vendor secure interop (the Connext half of the P6 exit gate).
#
# Stands up a real RTI Connext-Security participant (rtiddsspy, security plugin via BuiltinQosLib::Generic.Security)
# and one of OURS on domain 0 over UDP loopback, sharing the reused Identity-CA / Permissions-CA / Governance /
# S/MIME permissions (interop/security-{auth,access-control,secure-discovery}), and drives the DDS-Security 1.1
# path: SPDP -> §8.7 mutual PKI-DH auth -> crypto-token exchange over PVMS -> secure SEDP match -> protected data.
# rtiddsspy is the Connext OBSERVER for the ours->Connext direction (discovery + auth + our->Connext data decode);
# the Connext->ours direction launches a real Connext secured PUBLISHER (hello_secure_pub, an external rtiddsgen
# peer built here via `make`) of OUR HelloWorld type, so ours=subscriber decodes Connext's GOV=secure AEAD data.
#
# Setup (once): the RTI security plugin resolves libssl.3/libcrypto.3 via @loader_path + ships no OpenSSL here, so
#   ln -sf /opt/homebrew/opt/openssl@3/lib/lib{ssl,crypto}.3.dylib \
#          /Applications/rti_connext_dds-7.3.1/resource/app/lib/arm64Darwin20clang12.0/
#
# Usage: bash interop/security-connext/run-connext-interop.sh [GOV] [SECS]
#   GOV  = none (auth+access-control only, protection NONE) | secure (all-ENCRYPT). Default none.
#   SECS = seconds ours runs per direction. Default 25.
set -uo pipefail

GOV="${1:-none}"
SECS="${2:-25}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CAP_DIR="${SCRIPT_DIR}/captures"
mkdir -p "${CAP_DIR}"

export NDDSHOME=/Applications/rti_connext_dds-7.3.1
CONNEXTDDS_ARCH=arm64Darwin20clang12.0
export DYLD_LIBRARY_PATH="${NDDSHOME}/lib/${CONNEXTDDS_ARCH}:${NDDSHOME}/resource/app/lib/${CONNEXTDDS_ARCH}:/opt/homebrew/opt/openssl@3/lib:${DYLD_LIBRARY_PATH:-}"
RTIDDSSPY="${NDDSHOME}/bin/rtiddsspy"
HELLO_PUB="${SCRIPT_DIR}/hello_secure_pub"   # the reverse-direction Connext secured publisher (built by `make` here)
TSHARK=/Applications/Wireshark.app/Contents/MacOS/tshark

# our reused PKI (ours = EC-B identity; Connext = EC identity via USER_QOS_PROFILES.xml)
AUTH_PKI="${REPO_ROOT}/interop/security-auth/pki"
AC_PKI="${REPO_ROOT}/interop/security-access-control/pki"
OUR_CA="${AUTH_PKI}/ca/ca-cert.pem"
OUR_CERT="${AUTH_PKI}/participant_ec_b/identity_cert.pem"
OUR_KEY="${AUTH_PKI}/participant_ec_b/identity_key.pem"
OUR_PERMCA="${AC_PKI}/perm-ca-cert.pem"
OUR_GOV="${REPO_ROOT}/interop/security-secure-discovery/pki/governance-${GOV}.p7s"
OUR_PERM="${REPO_ROOT}/interop/security-secure-discovery/fastdds/certs/permissions-hello.smime"
SBCL="${REPO_ROOT}/scripts/with-sbcl.sh"

for f in "${RTIDDSSPY}" "${SCRIPT_DIR}/USER_QOS_PROFILES.xml" "${OUR_GOV}" "${OUR_PERM}" "${OUR_CERT}"; do
  [[ -e "${f}" ]] || { echo "MISSING: ${f}"; exit 2; }
done
echo "=== Slice 5b LIVE Connext-Security interop: GOV=${GOV} SECS=${SECS} ==="

PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do kill "${p}" >/dev/null 2>&1 || true; done; pkill -f 'rtiddsspy' >/dev/null 2>&1 || true; pkill -f 'hello_secure_pub' >/dev/null 2>&1 || true; }
trap cleanup EXIT

# one direction: $1=label $2=our-role. ours=pub -> Connext=rtiddsspy observer (ours2connext); ours=sub ->
# Connext=hello_secure_pub secured publisher (connext2ours, the Phase-5 reverse direction).
run_dir() {
  local label="$1" orole="$2"
  local pcap="${CAP_DIR}/connext-${GOV}-${label}.pcapng"
  local clog="${CAP_DIR}/connext-${GOV}-${label}-connext.log"
  local olog="${CAP_DIR}/connext-${GOV}-${label}-ours.log"
  local cpeer; [[ "${orole}" == "sub" ]] && cpeer="hello_secure_pub" || cpeer="rtiddsspy"
  echo ""
  echo "--- direction: ${label}  (Connext=${cpeer}, ours=${orole}) ---"
  pkill -9 -f 'rtiddsspy' >/dev/null 2>&1 || true; pkill -9 -f 'hello_secure_pub' >/dev/null 2>&1 || true
  rm -f "${pcap}"
  "${TSHARK}" -i lo0 -f "udp portrange 7400-7600" -w "${pcap}" >/dev/null 2>&1 &
  local tpid=$!; PIDS+=("${tpid}")
  # Connext first so it binds the domain-0 index-0 metatraffic port (7410) before ours (index 5, port 7420).
  if [[ "${orole}" == "sub" ]]; then
    # reverse direction: a real Connext PUBLISHER of our HelloWorld type (rtiddsspy only subscribes) publishes
    # GOV=secure AEAD-protected user DATA forever (2 Hz) for ours to decode; CONNEXT_VERBOSE surfaces its
    # auth/keying/match/decode decisions (the Connext-side oracle). Killed when ours finishes its SECS window.
    ( cd "${SCRIPT_DIR}" && CONNEXT_VERBOSE="${PUBVERB:-1}" exec "${HELLO_PUB}" 0 "OursConnextInterop::${GOV}" 0 ) >"${clog}" 2>&1 &
  else
    ( cd "${SCRIPT_DIR}" && exec "${RTIDDSSPY}" -domainId 0 -qosProfile "OursConnextInterop::${GOV}" \
          -timeout $((SECS + 70)) -mode "${SPYMODE:-USER}" -verbosity "${SPYVERB:-2}" ) >"${clog}" 2>&1 &
  fi
  local cpid=$!; PIDS+=("${cpid}")
  # ours (SBCL loads ~40 s before its participant is up; rtiddsspy is already bound)
  "${SBCL}" --non-interactive \
    --eval '(asdf:load-system :dds-tests)' \
    --eval "(uiop:symbol-call :dds.tests :run-secure-interop-peer
              :role \"${orole}\" :domain 0 :seconds ${SECS} :port 7420 :peers \"127.0.0.1:7410\"
              :ca \"${OUR_CA}\" :cert \"${OUR_CERT}\" :key \"${OUR_KEY}\"
              :perm-ca \"${OUR_PERMCA}\" :governance \"${OUR_GOV}\" :permissions \"${OUR_PERM}\"
              :topic \"HelloWorldTopic\" :type \"HelloWorld\" :samples 8 :interval 0.5)" \
    --eval '(uiop:quit 0)' >"${olog}" 2>&1
  sleep 1; kill "${cpid}" "${tpid}" >/dev/null 2>&1 || true
  pkill -9 -f 'rtiddsspy' >/dev/null 2>&1 || true; pkill -9 -f 'hello_secure_pub' >/dev/null 2>&1 || true; sleep 1
  echo "  [ours]    $(grep -aE 'SUMMARY|RESULT' "${olog}" | tail -2 | tr '\n' ' ')"
  echo "  [ours-sub] $(grep -aiE '\[sub\]|decoded|index=|matched=1|keyed=t' "${olog}" | grep -aviE 'compil|fasl|ftype|proclaim|wrote|cache|load-system' | tail -4 | tr '\n' ' | ')"
  echo "  [ours-auth] $(grep -aiE 'reject|handshake|authenticat|permission-|hash_c|propagate|keyed=t|shared.?secret' "${olog}" | grep -aviE 'compil|fasl|ftype|proclaim|proclamation|wrote|cache|load-system' | tail -3 | tr '\n' ' | ')"
  echo "  [connext] $(grep -aiE 'new |discover|reader|writer|HelloWorld|participant|received|denied|reject|error|sent index|match|crypto|decode' "${clog}" | grep -aviE 'listening|built with|press CTRL' | tail -8 | tr '\n' ' | ')"
  echo "  [pcap]    ${pcap}"
}

run_dir "ours2connext" pub
[[ "${GOV}" == "keep" ]] || run_dir "connext2ours" sub

echo ""
echo "=== done (GOV=${GOV}). Captures in ${CAP_DIR}/ ==="
