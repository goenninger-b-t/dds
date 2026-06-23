#!/usr/bin/env bash
# Attempt to capture a Connext-Security payload-protected DATA on loopback.
# The RTI Shapes Demo (rtishapesdemo) has DDS Security built in and uses the
# ecdsa01 example certs from the Connext installation. The governance is set to
# data_protection_kind=ENCRYPT / metadata_protection_kind=NONE so only the
# serialized payload is wrapped in a SecuredPayload (the thinnest target).
#
# This script requires:
#   - NDDSHOME pointing to Connext 7.3.1
#   - tshark installed (at /Applications/Wireshark.app/Contents/MacOS/tshark)
#   - The signed_governance-payload-only.p7s and signed_permissions-spike.p7s
#     already present in this directory (run after openssl smime -sign steps).
#
# NOTE: The RTI Shapes Demo is a GUI macOS .app; it cannot be run headlessly
# from a terminal without a display server. This script documents the manual
# steps needed and the expected QoS properties to set in the GUI.
#
# The alternative is to build the hello_security C example linked against the
# libnddssecurity plugin (which is NOT in the base Connext install; it is a
# separate secure-plugins download). This script records the BLOCKED state.
set -e

SPIKE_DIR="$(cd "$(dirname "$0")" && pwd)"
CERT_BASE="$NDDSHOME/resource/template/rti_workspace/examples/dds_security/cert/ecdsa01"
TSHARK="/Applications/Wireshark.app/Contents/MacOS/tshark"

echo "=== DDS-Security Spike: Connext-Security payload-protection capture ==="
echo ""
echo "NDDSHOME:  $NDDSHOME"
echo "SPIKE_DIR: $SPIKE_DIR"
echo ""

# Step 1: Verify signed governance + permissions exist
for f in signed_governance-payload-only.p7s signed_permissions-spike.p7s; do
    if [ ! -f "$SPIKE_DIR/$f" ]; then
        echo "MISSING: $SPIKE_DIR/$f — run the openssl smime -sign step first."
        exit 1
    fi
done
echo "[OK] Signed governance + permissions present."

# Step 2: Check for libnddssecurity (the separate security plugin library)
SECLIB="$NDDSHOME/lib/arm64Darwin20clang12.0/libnddssecurity.dylib"
if [ -f "$SECLIB" ]; then
    echo "[OK] libnddssecurity.dylib found — CLI build is possible."
else
    echo "[WARN] libnddssecurity.dylib NOT present (requires the RTI Security Plugins add-on)."
    echo "       The RTI Shapes Demo .app bundles it statically but cannot run headlessly."
    echo "       => CLI-based capture BLOCKED without the security plugin package."
fi

# Step 3: Check tshark
if [ ! -f "$TSHARK" ]; then
    echo "[WARN] tshark not found at $TSHARK."
else
    echo "[OK] tshark found."
fi

echo ""
echo "=== Manual capture instructions (GUI path) ==="
echo ""
echo "1. Start tshark to capture loopback:"
echo "   sudo $TSHARK -i lo0 -w $SPIKE_DIR/captures/security-payload.pcapng"
echo ""
echo "2. Open RTI Shapes Demo, go to Participant QoS and set these properties:"
echo "   dds.sec.auth.identity_ca = file:$CERT_BASE/ca/ecdsa01RootCaCert.pem"
echo "   dds.sec.auth.identity_certificate = file:$CERT_BASE/identities/ecdsa01Peer01Cert.pem"
echo "   dds.sec.auth.private_key = file:$CERT_BASE/identities/ecdsa01Peer01Key.pem"
echo "   dds.sec.access.permissions_ca = file:$CERT_BASE/ca/ecdsa01RootCaCert.pem"
echo "   dds.sec.access.governance = file:$SPIKE_DIR/signed_governance-payload-only.p7s"
echo "   dds.sec.access.permissions = file:$SPIKE_DIR/signed_permissions-spike.p7s"
echo ""
echo "   OR: load $SPIKE_DIR/USER_QOS_PROFILES.xml as the DomainParticipant QoS"
echo "   with SPIKE_DIR=$SPIKE_DIR set in the environment."
echo ""
echo "3. Publish Square on topic 'Square', write a few samples."
echo ""
echo "4. Stop tshark. Decode the capture:"
echo "   python3 $SPIKE_DIR/decode-secured-payload.py \\"
echo "           $SPIKE_DIR/captures/security-payload.pcapng"
echo ""
echo "=== Outcome ==="
echo "Status: BLOCKED — libnddssecurity.dylib not installed; GUI app needs display."
echo "Fallback: spec-clause-only (§9.5.3.3) + binary evidence from the Shapes Demo."
