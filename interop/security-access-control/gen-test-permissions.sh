#!/usr/bin/env bash
# Reproducible test fixture generator for WP-DDS-SECURITY-ACCESS-CONTROL T0.
#
# Generates under interop/security-access-control/pki/:
#   perm-ca-cert.pem / perm-ca-key.pem  -- throwaway Permissions CA (EC P-256)
#   governance.xml                        -- Governance doc (plaintext)
#   governance.p7s                        -- governance.xml signed by Permissions CA
#   permissions.xml                       -- Permissions doc (plaintext)
#   permissions.p7s                       -- permissions.xml signed by Permissions CA
#
# Signs using openssl smime -sign -outform PEM (embedded/opaque, DDS-Security 1.1 §9.4.1.1).
# Verifies round-trip with openssl cms -verify.
#
# Prerequisites: openssl >= 3.x on PATH.
# Usage: bash interop/security-access-control/gen-test-permissions.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKI_DIR="${SCRIPT_DIR}/pki"
mkdir -p "${PKI_DIR}"

# ── 1. Permissions CA (EC P-256, self-signed, CA:TRUE) ──────────────────────
# Throwaway test key — committed intentionally; NOT a production credential.
if [[ ! -f "${PKI_DIR}/perm-ca-cert.pem" ]]; then
  openssl ecparam -name prime256v1 -genkey -noout \
      -out "${PKI_DIR}/perm-ca-key.pem" 2>/dev/null
  openssl req -new -x509 -key "${PKI_DIR}/perm-ca-key.pem" \
      -subj "/CN=TestPermissionsCA/O=DDS-Test/C=DE" \
      -days 3650 \
      -extensions v3_ca \
      -out "${PKI_DIR}/perm-ca-cert.pem" 2>/dev/null
  echo "Generated Permissions CA: ${PKI_DIR}/perm-ca-cert.pem"
else
  echo "Permissions CA already exists, skipping."
fi

# ── 2. governance.xml ────────────────────────────────────────────────────────
# DDS-Security 1.1 §9.4.1.2.3 + Annex B (dds_governance.xsd).
# Domain 0: no unauthenticated participants; join access control enabled.
# topic_rule wildcard "*": read AC + write AC both enabled; no RTPS/metadata
# protection (NONE) for this our-to-our spike (crypto protection is Slice 2 carry).
cat > "${PKI_DIR}/governance.xml" <<'XML'
<?xml version="1.0" encoding="UTF-8"?>
<dds xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
     xsi:noNamespaceSchemaLocation="https://www.omg.org/spec/DDS-Security/20190401/dds_governance.xsd">
  <policies>
    <domain_access_rules>
      <domain_rule>
        <domains>
          <id>0</id>
        </domains>
        <allow_unauthenticated_participants>false</allow_unauthenticated_participants>
        <enable_join_access_control>true</enable_join_access_control>
        <discovery_protection_kind>NONE</discovery_protection_kind>
        <liveliness_protection_kind>NONE</liveliness_protection_kind>
        <rtps_protection_kind>NONE</rtps_protection_kind>
        <topic_access_rules>
          <topic_rule>
            <topic_expression>*</topic_expression>
            <enable_discovery_protection>false</enable_discovery_protection>
            <enable_liveliness_protection>false</enable_liveliness_protection>
            <enable_read_access_control>true</enable_read_access_control>
            <enable_write_access_control>true</enable_write_access_control>
            <metadata_protection_kind>NONE</metadata_protection_kind>
            <data_protection_kind>NONE</data_protection_kind>
          </topic_rule>
        </topic_access_rules>
      </domain_rule>
    </domain_access_rules>
  </policies>
</dds>
XML
echo "Generated ${PKI_DIR}/governance.xml"

# ── 3. permissions.xml ───────────────────────────────────────────────────────
# DDS-Security 1.1 §9.4.1.3.2 + Annex B (dds_permissions.xsd).
# subject_name: slash-separated OpenSSL one-line DN (X509_NAME_oneline format)
# matching interop/security-auth/pki participant_ec/rsa identity certs.
# allow publish+subscribe on topic "Square" (fnmatch); deny "Circle"; default DENY.
# Four participants: TestParticipantEC, TestParticipantECB, TestParticipantRSA, TestParticipantRSAB.
cat > "${PKI_DIR}/permissions.xml" <<'XML'
<?xml version="1.0" encoding="UTF-8"?>
<dds xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
     xsi:noNamespaceSchemaLocation="https://www.omg.org/spec/DDS-Security/20190401/dds_permissions.xsd">
  <permissions>
    <grant name="TestParticipantEC">
      <subject_name>/CN=TestParticipantEC/O=DDS-Test/C=DE</subject_name>
      <validity>
        <not_before>2026-01-01T00:00:00</not_before>
        <not_after>2036-01-01T00:00:00</not_after>
      </validity>
      <allow_rule>
        <domains><id>0</id></domains>
        <publish><topics><topic>Square</topic></topics></publish>
        <subscribe><topics><topic>Square</topic></topics></subscribe>
      </allow_rule>
      <deny_rule>
        <domains><id>0</id></domains>
        <publish><topics><topic>Circle</topic></topics></publish>
        <subscribe><topics><topic>Circle</topic></topics></subscribe>
      </deny_rule>
      <default>DENY</default>
    </grant>
    <grant name="TestParticipantECB">
      <subject_name>/CN=TestParticipantECB/O=DDS-Test/C=DE</subject_name>
      <validity>
        <not_before>2026-01-01T00:00:00</not_before>
        <not_after>2036-01-01T00:00:00</not_after>
      </validity>
      <allow_rule>
        <domains><id>0</id></domains>
        <publish><topics><topic>Square</topic></topics></publish>
        <subscribe><topics><topic>Square</topic></topics></subscribe>
      </allow_rule>
      <deny_rule>
        <domains><id>0</id></domains>
        <publish><topics><topic>Circle</topic></topics></publish>
        <subscribe><topics><topic>Circle</topic></topics></subscribe>
      </deny_rule>
      <default>DENY</default>
    </grant>
    <grant name="TestParticipantRSA">
      <subject_name>/CN=TestParticipantRSA/O=DDS-Test/C=DE</subject_name>
      <validity>
        <not_before>2026-01-01T00:00:00</not_before>
        <not_after>2036-01-01T00:00:00</not_after>
      </validity>
      <allow_rule>
        <domains><id>0</id></domains>
        <publish><topics><topic>Square</topic></topics></publish>
        <subscribe><topics><topic>Square</topic></topics></subscribe>
      </allow_rule>
      <deny_rule>
        <domains><id>0</id></domains>
        <publish><topics><topic>Circle</topic></topics></publish>
        <subscribe><topics><topic>Circle</topic></topics></subscribe>
      </deny_rule>
      <default>DENY</default>
    </grant>
    <grant name="TestParticipantRSAB">
      <subject_name>/CN=TestParticipantRSAB/O=DDS-Test/C=DE</subject_name>
      <validity>
        <not_before>2026-01-01T00:00:00</not_before>
        <not_after>2036-01-01T00:00:00</not_after>
      </validity>
      <allow_rule>
        <domains><id>0</id></domains>
        <publish><topics><topic>Square</topic></topics></publish>
        <subscribe><topics><topic>Square</topic></topics></subscribe>
      </allow_rule>
      <deny_rule>
        <domains><id>0</id></domains>
        <publish><topics><topic>Circle</topic></topics></publish>
        <subscribe><topics><topic>Circle</topic></topics></subscribe>
      </deny_rule>
      <default>DENY</default>
    </grant>
  </permissions>
</dds>
XML
echo "Generated ${PKI_DIR}/permissions.xml"

# ── 4. Sign both documents ───────────────────────────────────────────────────
# DDS-Security 1.1 §9.4.1.1: CMS SignedData, S/MIME PEM wrapper, embedded content
# (-nodetach = opaque signing, content embedded in CMS structure).
# sha256 = required digest (§9.4.1.1).
sign_doc() {
  local infile="$1" outfile="$2"
  # DDS-Security 1.1 §9.4.1.1: signed PKCS7/CMS, PEM wrapper.
  # smime -sign -outform PEM produces the spec-required BEGIN PKCS7 headers.
  openssl smime -sign \
    -signer "${PKI_DIR}/perm-ca-cert.pem" \
    -inkey  "${PKI_DIR}/perm-ca-key.pem" \
    -in  "${infile}" \
    -out "${outfile}" \
    -outform PEM \
    -nodetach \
    -md sha256 2>/dev/null
  echo "Signed  ${outfile}"
}

sign_doc "${PKI_DIR}/governance.xml"   "${PKI_DIR}/governance.p7s"
sign_doc "${PKI_DIR}/permissions.xml"  "${PKI_DIR}/permissions.p7s"

# ── 5. Verify round-trip ─────────────────────────────────────────────────────
# openssl cms -verify with -CAfile = the Permissions CA (no system trust store).
# Exit non-zero on failure (set -e above).
verify_doc() {
  local infile="$1" label="$2"
  local verified
  verified=$(openssl cms -verify \
    -in "${infile}" \
    -inform PEM \
    -CAfile "${PKI_DIR}/perm-ca-cert.pem" \
    -no-CAfile \
    -no-CApath \
    -no-CAstore 2>/dev/null)
  local nchars=${#verified}
  echo "Verified ${label}: ${nchars} chars of recovered content"
}

verify_doc "${PKI_DIR}/governance.p7s"  "governance.p7s"
verify_doc "${PKI_DIR}/permissions.p7s" "permissions.p7s"

echo "All fixtures generated and self-verified in ${PKI_DIR}/"
