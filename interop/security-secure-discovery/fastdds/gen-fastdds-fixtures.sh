#!/usr/bin/env bash
# T12 cross-vendor fixtures for the LIVE Fast DDS-Security peer (M7/P6 Slice 4).
#
# The eProsima Fast DDS AccessControl plugin parses governance/permissions with
# SMIME_read_PKCS7 (src/cpp/security/accesscontrol/Permissions.cpp:354), so it needs the
# MIME S/MIME container, NOT the PEM PKCS7 container our own dds.dare:cms-verify consumes.
# This emits, signed by the SAME reused Permissions CA as gen-test-fixtures.sh:
#   fastdds/certs/governance-none.smime    -- MIME of the existing pki/governance-none.xml   (auth-only baseline)
#   fastdds/certs/governance-secure.smime  -- MIME of the existing pki/governance-secure.xml (ENCRYPT discovery+rtps)
#   fastdds/certs/governance-sign.smime    -- MIME of the existing pki/governance-sign.xml   (all-SIGN authenticated-but-visible)
#   fastdds/certs/governance-datasign.smime -- MIME of pki/governance-datasign.xml         (all-SIGN incl. payload GMAC §9.5.3.3.4.3)
#   fastdds/certs/permissions-hello.smime  -- MIME, wildcard topic '*' for EC+ECB (covers the example HelloWorldTopic)
#   pki/permissions-hello.{xml,p7s}        -- the SAME wildcard permissions in PEM PKCS7 for OUR side
# Content is identical to the committed .xml; only the signature container differs.
# Run after gen-test-fixtures.sh. Usage: bash interop/security-secure-discovery/fastdds/gen-fastdds-fixtures.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SSD_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
PKI_DIR="${SSD_DIR}/pki"
CERTS_DIR="${SCRIPT_DIR}/certs"
PERM_CA_CERT="${SSD_DIR}/../security-access-control/pki/perm-ca-cert.pem"
PERM_CA_KEY="${SSD_DIR}/../security-access-control/pki/perm-ca-key.pem"
mkdir -p "${CERTS_DIR}"

for f in "${PERM_CA_CERT}" "${PERM_CA_KEY}" "${PKI_DIR}/governance-none.xml" "${PKI_DIR}/governance-secure.xml" "${PKI_DIR}/governance-sign.xml" "${PKI_DIR}/governance-datasign.xml"; do
  [[ -f "${f}" ]] || { echo "ERROR: missing ${f} (run gen-test-fixtures.sh first)" >&2; exit 1; }
done

# MIME S/MIME signer for Fast DDS: multipart/signed with an inner "Content-Type: text/plain" part.
# Fast DDS verifies with PKCS7_verify(..., PKCS7_TEXT | PKCS7_NOVERIFY | PKCS7_NOINTERN)
# (Permissions.cpp:408), and PKCS7_TEXT REQUIRES that text/plain wrapper — so we must NOT use
# -nodetach (which produces the opaque application/x-pkcs7-mime form PKCS7_TEXT rejects). This
# matches the eProsima example certs/governance.smime byte-for-byte in container shape.
sign_mime() {
  openssl smime -sign -signer "${PERM_CA_CERT}" -inkey "${PERM_CA_KEY}" \
    -in "$1" -out "$2" -md sha256 -text 2>/dev/null
  echo "Signed (MIME) $2"
}
# PEM PKCS7 signer (our-side consumer dds.dare:cms-verify).
sign_pem() {
  openssl smime -sign -signer "${PERM_CA_CERT}" -inkey "${PERM_CA_KEY}" \
    -in "$1" -out "$2" -outform PEM -nodetach -md sha256 2>/dev/null
  echo "Signed (PEM)  $2"
}

sign_mime "${PKI_DIR}/governance-none.xml"      "${CERTS_DIR}/governance-none.smime"
sign_mime "${PKI_DIR}/governance-secure.xml"    "${CERTS_DIR}/governance-secure.smime"
sign_mime "${PKI_DIR}/governance-sign.xml"      "${CERTS_DIR}/governance-sign.smime"
sign_mime "${PKI_DIR}/governance-datasign.xml" "${CERTS_DIR}/governance-datasign.smime"

# Wildcard interop permissions: allow publish+subscribe on ANY topic (covers the prebuilt example's
# HelloWorldTopic) for the two EC subjects, default DENY. Same two identity-CA-issued subjects as
# gen-test-fixtures.sh; only the topic expression widens to '*'.
cat > "${PKI_DIR}/permissions-hello.xml" <<'XML'
<?xml version="1.0" encoding="UTF-8"?>
<dds xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
     xsi:noNamespaceSchemaLocation="https://www.omg.org/spec/DDS-Security/20190401/dds_permissions.xsd">
  <permissions>
    <grant name="TestParticipantEC">
      <subject_name>C=DE,O=DDS-Test,CN=TestParticipantEC</subject_name>
      <validity>
        <not_before>2026-01-01T00:00:00</not_before>
        <not_after>2036-01-01T00:00:00</not_after>
      </validity>
      <allow_rule>
        <domains><id>0</id></domains>
        <publish><topics><topic>*</topic></topics></publish>
        <subscribe><topics><topic>*</topic></topics></subscribe>
      </allow_rule>
      <default>DENY</default>
    </grant>
    <grant name="TestParticipantECB">
      <subject_name>C=DE,O=DDS-Test,CN=TestParticipantECB</subject_name>
      <validity>
        <not_before>2026-01-01T00:00:00</not_before>
        <not_after>2036-01-01T00:00:00</not_after>
      </validity>
      <allow_rule>
        <domains><id>0</id></domains>
        <publish><topics><topic>*</topic></topics></publish>
        <subscribe><topics><topic>*</topic></topics></subscribe>
      </allow_rule>
      <default>DENY</default>
    </grant>
  </permissions>
</dds>
XML
echo "Generated ${PKI_DIR}/permissions-hello.xml"

sign_pem  "${PKI_DIR}/permissions-hello.xml" "${PKI_DIR}/permissions-hello.p7s"
sign_mime "${PKI_DIR}/permissions-hello.xml" "${CERTS_DIR}/permissions-hello.smime"

# Self-verify each artifact against the reused Permissions CA (independent of the signer above).
for f in "${CERTS_DIR}/governance-none.smime" "${CERTS_DIR}/governance-secure.smime" "${CERTS_DIR}/governance-sign.smime" "${CERTS_DIR}/governance-datasign.smime" "${CERTS_DIR}/permissions-hello.smime"; do
  if openssl smime -verify -in "${f}" -CAfile "${PERM_CA_CERT}" >/dev/null 2>&1; then
    echo "Verified (MIME) ${f}"
  else
    echo "ERROR: MIME verify FAILED for ${f}" >&2; exit 1
  fi
done
openssl cms -verify -in "${PKI_DIR}/permissions-hello.p7s" -inform PEM \
  -CAfile "${PERM_CA_CERT}" -no-CAfile -no-CApath -no-CAstore >/dev/null 2>&1 \
  && echo "Verified (PEM)  ${PKI_DIR}/permissions-hello.p7s"

echo "Fast DDS cross-vendor fixtures ready in ${CERTS_DIR}/ and ${PKI_DIR}/permissions-hello.*"
