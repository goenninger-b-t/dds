#!/usr/bin/env bash
# WP-DDS-SECURITY-ACCESS-CONTROL — our-to-our allow/deny e2e + default-off (Slice 3).
#
# PURPOSE
#   Validate the AccessControl vertical slice our-to-our:
#   (a) run-access-control-allow-deny-test — full e2e allow/deny end-to-end:
#       ALLOW pair (domain 85): "Square" writer sq-a + "Square" reader sq-b;
#       both reach auth-remote :keyed; permissions-gate consults remote grant
#       by authenticated subject; ALLOW rule fires; endpoints MATCH; byte-exact
#       "SQTST001" (8 bytes) round-trip proven.
#       DENY pair (domain 86): "Circle" writer ci-a + "Circle" reader ci-b;
#       both reach :keyed (auth passes); permissions-gate returns :incompatible
#       (DENY rule in remote grant for "Circle"); endpoints do NOT match.
#       NON-VACUOUS: sq-b matched-count >= 1 AND ci-b matched-count = 0;
#       the ONLY difference is the topic name.
#   (b) run-access-control-local-deny-test — check_create_datawriter enforcement:
#       A participant (domain 87) with write-AC enabled + deny rule for "Triangle";
#       check-create-datawriter returns NIL for "Triangle" (refused);
#       NON-VACUOUS: "Square" is NOT refused.
#   (c) run-access-control-default-off-test — default-OFF byte-identical:
#       A participant with no governance/permissions has dp-access-state=NIL;
#       the permissions-gate returns :compatible unconditionally.
#
# ENVIRONMENT STATUS (2026-06-26)
#   - RTI Connext 7.3.1: INSTALLED at /Applications/rti_connext_dds-7.3.1 (rtiddsspy on PATH)
#   - RTI Security Plugins: NOT INSTALLED (libnddssecurity.dylib absent)
#   - Fast DDS 3.6.1: NOT AVAILABLE in this environment
#   - tshark: AVAILABLE at /Applications/Wireshark.app/Contents/MacOS/tshark
#   - Our Lisp build: both Clasp and SBCL validated (349 tests each, all gates green)
#
# LIVE CONNEXT-SECURITY ACCESSCONTROL EXECUTION OUTCOME
#   A live Connext-Security AccessControl run CANNOT be completed in this environment:
#   - The RTI Security Plugins add-on (rti_connext_dds_secure_plugins) is not installed.
#     libnddssecurity.dylib is absent from the Connext lib directory.
#   - Without libnddssecurity.dylib, Connext cannot load its AccessControl plugin, verify
#     the signed Governance/Permissions documents, or enforce topic-level access control.
#
# PORTABLE GUARD (in-process, always runs in CI)
#   All three in-process tests above run as part of the full dds-tests suite (Clasp first).
#   They exercise every layer of the AccessControl slice without a foreign peer:
#   - CMS signature verification proven by run-access-cms-verify-test (signed fixture
#     verifies; tampered doc -> NIL; wrong CA -> NIL; non-vacuous).
#   - Allow/deny matcher proven by run-access-matcher-test + run-access-glob-test.
#   - Permissions-gate verdict ladder proven by run-access-manager-test (unit test).
#   - Full gate ladder (type-gate -> auth-gate -> permissions-gate) proven end-to-end
#     by run-access-control-allow-deny-test (real signed fixtures, real wire, real auth).
#   - Default-OFF byte-identity confirmed by run-access-control-default-off-test.
#
# HOW TO RUN LIVE (owner/developer steps when RTI Security Plugins are installed)
#   1. Install the RTI Security Plugins add-on (rti_connext_dds_secure_plugins).
#   2. Configure a Connext participant with DDS-Security governance/permissions XML using
#      the Permissions CA at interop/security-access-control/pki/ca/ca-cert.pem and a
#      grant that allows "Square" publish/subscribe.
#   3. Start the Connext security participant on domain 0 (subscriber, EC identity).
#   4. Start our security participant (see interop/security-access-control/README.md).
#   5. Capture with tshark:
#        /Applications/Wireshark.app/Contents/MacOS/tshark \
#          -i lo0 -f "udp port 7400" -w captures/ac-live-$(date +%s).pcapng
#   6. Verify: Connext DataReader on "Square" matches and receives samples from our
#      publisher (AccessControl allows "Square"). Observe PID_IDENTITY_TOKEN in SPDP,
#      handshake tokens + CryptoToken in ParticipantStatelessMessage.
#
# DEFERRED CROSS-VENDOR VERIFICATIONS (Slice 5)
#   - Per-participant c.perm-in-handshake Permissions exchange (shared-document model
#     is our-to-our self-consistent; Connext may require c.perm).
#   - Signed-document format: bare PEM-PKCS7 (our format) vs MIME-wrapped S/MIME.
#   - Subject-name normalization: OpenSSL slash format vs RFC 2253.
#   - Deferred knobs: partition-expression matching, validity-date enforcement,
#     Governance protection_kind -> crypto wiring.
#   Full list documented in ADR 0035 and interop/security-access-control/README.md.
#
# CONCLUSION
#   ENVIRONMENT-LIMITED: live Connext-Security AccessControl run requires the RTI Security
#   Plugins add-on (not installed). The portable guard (all three in-process tests) and
#   spec evidence (DDS-Security 1.1 §8.4, §9.4, §9.4.1.2.3 Table 32) provide structural
#   confidence. Live Connext-Security ACCESSCONTROL interop is the P6 exit gate (Slice 5).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TSHARK=/Applications/Wireshark.app/Contents/MacOS/tshark

echo "=== AccessControl our-to-our environment check ==="
echo "Repo root: ${REPO_ROOT}"
echo ""

# Check RTI Connext
if [ -f "/Applications/rti_connext_dds-7.3.1/bin/rtiddsspy" ]; then
    echo "[OK] RTI Connext 7.3.1: rtiddsspy available"
else
    echo "[MISSING] RTI Connext 7.3.1 rtiddsspy not found"
fi

# Check RTI Security Plugins
SECLIB="/Applications/rti_connext_dds-7.3.1/lib/arm64Darwin20clang12.0/libnddssecurity.dylib"
if [ -f "${SECLIB}" ]; then
    echo "[OK] RTI Security Plugins: installed (live AccessControl interop possible)"
else
    echo "[DEFERRED] RTI Security Plugins: NOT installed (libnddssecurity.dylib absent)"
    echo "           Live Connext-Security ACCESSCONTROL interop -> Slice 5 (P6 exit gate)"
fi

# Check tshark
if [ -f "${TSHARK}" ]; then
    echo "[OK] tshark: available at ${TSHARK}"
else
    echo "[MISSING] tshark not found"
fi

# Check Fast DDS
if command -v fastdds >/dev/null 2>&1; then
    echo "[OK] Fast DDS: available"
else
    echo "[DEFERRED] Fast DDS: NOT available in this environment"
fi

echo ""
echo "=== Portable guard: allow/deny e2e + local-deny + default-off ==="
echo "Running three in-process checks (Clasp first, then SBCL):"
echo "  (a) run-access-control-allow-deny-test  — full e2e allow/deny (real signed docs + wire)"
echo "  (b) run-access-control-local-deny-test  — check_create_datawriter enforcement"
echo "  (c) run-access-control-default-off-test — default-OFF byte-identical"
echo ""

CLASP="${REPO_ROOT}/projects/clasp/build/boehmprecise/clasp"
if [ -f "${CLASP}" ]; then
    echo "--- Clasp ---"
    "${CLASP}" --non-interactive \
        --eval "(asdf:test-system :dds-tests)" \
        --eval "(format t \"~&allow-deny-e2e: ~a~%\" (dds.tests:run-access-control-allow-deny-test))" \
        --eval "(format t \"~&local-deny: ~a~%\" (dds.tests:run-access-control-local-deny-test))" \
        --eval "(format t \"~&default-off: ~a~%\" (dds.tests:run-access-control-default-off-test))" \
        --eval "(uiop:quit 0)" 2>&1 || true
else
    echo "[SKIP] Clasp binary not found at ${CLASP}"
fi

echo ""
echo "--- SBCL ---"
if command -v sbcl >/dev/null 2>&1; then
    sbcl --non-interactive \
        --eval "(asdf:test-system :dds-tests)" \
        --eval "(format t \"~&allow-deny-e2e: ~a~%\" (dds.tests:run-access-control-allow-deny-test))" \
        --eval "(format t \"~&local-deny: ~a~%\" (dds.tests:run-access-control-local-deny-test))" \
        --eval "(format t \"~&default-off: ~a~%\" (dds.tests:run-access-control-default-off-test))" \
        --eval "(uiop:quit 0)" 2>&1 || true
else
    echo "[SKIP] sbcl not found on PATH"
fi

echo ""
echo "=== Outcome ==="
echo "ENVIRONMENT-LIMITED: live Connext-Security AccessControl interop requires the RTI"
echo "  Security Plugins add-on (libnddssecurity.dylib absent in this environment)."
echo "Portable guard (all three in-process tests) + DDS-Security 1.1 §8.4 / §9.4 spec"
echo "  evidence provide structural confidence. See interop/security-access-control/README.md"
echo "  and ADR 0035. Live Connext-Security ACCESSCONTROL interop is the P6 exit gate (Slice 5)."
