#!/usr/bin/env bash
# Reproducible test fixture generator for WP-DDS-SECURITY-SECURE-DISCOVERY T0 (M7/P6 Slice 4).
#
# REUSES the Slice-3 trust anchors (does NOT regenerate them):
#   Permissions CA: ../security-access-control/pki/perm-ca-{cert,key}.pem  (signs governance + permissions)
#   Identity CA:    ../security-auth/pki/ca/ca-cert.pem                    (issued the participant certs
#                                                                          whose DNs are the grant subjects)
#
# Generates under interop/security-secure-discovery/pki/ (signed CMS/S-MIME PEM, DDS-Security 1.1 §9.4.1.1):
#   governance-secure.xml/.p7s       -- discovery=ENCRYPT, liveliness=SIGN, rtps=ENCRYPT, enable_discovery_protection=true
#   governance-sign.xml/.p7s         -- all-SIGN authenticated-but-visible tier: discovery/liveliness/rtps/metadata=SIGN (AES-GMAC), data=NONE (visible payload), enable_discovery_protection=true
#   governance-origin-auth.xml/.p7s  -- the *_WITH_ORIGIN_AUTHENTICATION protection kinds (receiver-specific MACs)
#   governance-none.xml/.p7s         -- all-NONE baseline (the security-OFF byte-identical guard)
#   permissions.xml/.p7s             -- publish/subscribe grants for the four test subjects, default DENY
#
# Signs with openssl smime -sign -outform PEM -nodetach -md sha256 (embedded/opaque, §9.4.1.1).
# Verifies every artifact round-trip with openssl cms -verify against the reused Permissions CA.
#
# Prerequisites: openssl >= 3.x on PATH; the reused CAs present (run the Slice-2/3 gen scripts first).
# Usage: bash interop/security-secure-discovery/gen-test-fixtures.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKI_DIR="${SCRIPT_DIR}/pki"
PERM_CA_CERT="${SCRIPT_DIR}/../security-access-control/pki/perm-ca-cert.pem"
PERM_CA_KEY="${SCRIPT_DIR}/../security-access-control/pki/perm-ca-key.pem"
ID_CA_CERT="${SCRIPT_DIR}/../security-auth/pki/ca/ca-cert.pem"
mkdir -p "${PKI_DIR}"

# ── 0. Confirm the reused trust anchors exist (fail loudly; we never regenerate them here) ────
for f in "${PERM_CA_CERT}" "${PERM_CA_KEY}" "${ID_CA_CERT}"; do
  if [[ ! -f "${f}" ]]; then
    echo "ERROR: reused CA material missing: ${f}" >&2
    echo "  run interop/security-access-control/gen-test-permissions.sh and interop/security-auth/gen-test-pki.sh first." >&2
    exit 1
  fi
done
echo "Reusing Permissions CA ${PERM_CA_CERT} and Identity CA ${ID_CA_CERT}"

# ── governance writer: $1=outfile, $2=discovery, $3=liveliness, $4=rtps, $5=topic-enable(true|false),
#                       $6=metadata, $7=data ──────────────────────────────────────────────────
# DDS-Security 1.1 §9.4.1.2.3 + Annex B (dds_governance.xsd). Element names + ProtectionKind tokens
# pinned in T0 (Fast DDS GovernanceParser.cpp lines 35-52; spike 2026-06-27).
write_governance() {
  local out="$1" disc="$2" live="$3" rtps="$4" tenable="$5" meta="$6" data="$7"
  cat > "${out}" <<XML
<?xml version="1.0" encoding="UTF-8"?>
<dds xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
     xsi:noNamespaceSchemaLocation="https://www.omg.org/spec/DDS-Security/20190401/dds_governance.xsd">
  <domain_access_rules>
    <domain_rule>
      <domains>
        <id>0</id>
      </domains>
      <allow_unauthenticated_participants>false</allow_unauthenticated_participants>
      <enable_join_access_control>true</enable_join_access_control>
      <discovery_protection_kind>${disc}</discovery_protection_kind>
      <liveliness_protection_kind>${live}</liveliness_protection_kind>
      <rtps_protection_kind>${rtps}</rtps_protection_kind>
      <topic_access_rules>
        <topic_rule>
          <topic_expression>*</topic_expression>
          <enable_discovery_protection>${tenable}</enable_discovery_protection>
          <enable_liveliness_protection>${tenable}</enable_liveliness_protection>
          <enable_read_access_control>true</enable_read_access_control>
          <enable_write_access_control>true</enable_write_access_control>
          <metadata_protection_kind>${meta}</metadata_protection_kind>
          <data_protection_kind>${data}</data_protection_kind>
        </topic_rule>
      </topic_access_rules>
    </domain_rule>
  </domain_access_rules>
</dds>
XML
  echo "Generated ${out}"
}

write_governance "${PKI_DIR}/governance-secure.xml" \
  "ENCRYPT" "SIGN" "ENCRYPT" "true" "ENCRYPT" "ENCRYPT"
write_governance "${PKI_DIR}/governance-sign.xml" \
  "SIGN" "SIGN" "SIGN" "true" "SIGN" "NONE"
write_governance "${PKI_DIR}/governance-origin-auth.xml" \
  "ENCRYPT_WITH_ORIGIN_AUTHENTICATION" "SIGN_WITH_ORIGIN_AUTHENTICATION" "ENCRYPT_WITH_ORIGIN_AUTHENTICATION" \
  "true" "ENCRYPT" "ENCRYPT"
write_governance "${PKI_DIR}/governance-none.xml" \
  "NONE" "NONE" "NONE" "false" "NONE" "NONE"

# ── permissions.xml ──────────────────────────────────────────────────────────
# DDS-Security 1.1 §9.4.1.3.2 + Annex B (dds_permissions.xsd). subject_name = OpenSSL one-line DN
# matching the interop/security-auth/pki participant identity certs (issued by the reused Identity CA).
# allow publish+subscribe on "Square"; deny "Circle"; default DENY. Four subjects.
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

# ── Sign every document with the reused Permissions CA (§9.4.1.1: CMS SignedData, S/MIME PEM,
#    embedded content via -nodetach, sha256 digest) ──────────────────────────────────────────
sign_doc() {
  local infile="$1" outfile="$2"
  openssl smime -sign \
    -signer "${PERM_CA_CERT}" \
    -inkey  "${PERM_CA_KEY}" \
    -in  "${infile}" \
    -out "${outfile}" \
    -outform PEM \
    -nodetach \
    -md sha256 2>/dev/null
  echo "Signed  ${outfile}"
}

for base in governance-secure governance-sign governance-origin-auth governance-none permissions; do
  sign_doc "${PKI_DIR}/${base}.xml" "${PKI_DIR}/${base}.p7s"
done

# ── Verify every artifact round-trip against the reused Permissions CA (no system trust store) ─
verify_doc() {
  local infile="$1" label="$2" verified nchars
  verified=$(openssl cms -verify \
    -in "${infile}" \
    -inform PEM \
    -CAfile "${PERM_CA_CERT}" \
    -no-CAfile -no-CApath -no-CAstore 2>/dev/null)
  nchars=${#verified}
  echo "Verified ${label}: ${nchars} chars of recovered content"
}

for base in governance-secure governance-sign governance-origin-auth governance-none permissions; do
  verify_doc "${PKI_DIR}/${base}.p7s" "${base}.p7s"
done

echo "All secure-discovery fixtures generated and self-verified in ${PKI_DIR}/"
