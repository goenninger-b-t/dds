#!/usr/bin/env bash
# Generate throwaway test PKI for DDS-Security 1.1 §9.3 Auth plugin unit tests.
# Produces: Identity CA + EC-P256 participant cert + RSA-2048 participant cert + wrong-CA cert.
# Deterministic: fixed CN / serial / dates; safe to re-run (overwrites pki/).
# Requires: openssl >= 3.x  (tested with OpenSSL 3.6.2).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKI_DIR="$SCRIPT_DIR/pki"
OPENSSL="${OPENSSL_BIN:-openssl}"

echo "[gen-test-pki] Cleaning $PKI_DIR..."
rm -rf "$PKI_DIR"
mkdir -p "$PKI_DIR/ca"
mkdir -p "$PKI_DIR/participant_ec"
mkdir -p "$PKI_DIR/participant_ec_b"
mkdir -p "$PKI_DIR/participant_rsa"
mkdir -p "$PKI_DIR/participant_rsa_b"
mkdir -p "$PKI_DIR/wrong_ca"

# --- Identity CA (EC P-256, self-signed) ---
echo "[gen-test-pki] Generating Identity CA (EC P-256)..."
"$OPENSSL" ecparam -name prime256v1 -genkey -noout \
  -out "$PKI_DIR/ca/ca-key.pem"
"$OPENSSL" req -new -x509 -days 3650 -sha256 \
  -key "$PKI_DIR/ca/ca-key.pem" \
  -out "$PKI_DIR/ca/ca-cert.pem" \
  -subj "/CN=TestIdentityCA/O=DDS-Test/C=DE" \
  -set_serial 1

# --- EC P-256 participant cert, signed by test CA ---
echo "[gen-test-pki] Generating EC-P256 participant cert..."
"$OPENSSL" ecparam -name prime256v1 -genkey -noout \
  -out "$PKI_DIR/participant_ec/identity_key.pem"
"$OPENSSL" req -new -sha256 \
  -key "$PKI_DIR/participant_ec/identity_key.pem" \
  -out "$PKI_DIR/participant_ec/identity_csr.pem" \
  -subj "/CN=TestParticipantEC/O=DDS-Test/C=DE"
"$OPENSSL" x509 -req -days 3650 -sha256 \
  -in "$PKI_DIR/participant_ec/identity_csr.pem" \
  -CA "$PKI_DIR/ca/ca-cert.pem" \
  -CAkey "$PKI_DIR/ca/ca-key.pem" \
  -out "$PKI_DIR/participant_ec/identity_cert.pem" \
  -set_serial 2
rm "$PKI_DIR/participant_ec/identity_csr.pem"

# --- EC P-256 participant B cert, signed by test CA ---
echo "[gen-test-pki] Generating EC-P256 participant B cert..."
"$OPENSSL" ecparam -name prime256v1 -genkey -noout \
  -out "$PKI_DIR/participant_ec_b/identity_key.pem"
"$OPENSSL" req -new -sha256 \
  -key "$PKI_DIR/participant_ec_b/identity_key.pem" \
  -out "$PKI_DIR/participant_ec_b/identity_csr.pem" \
  -subj "/CN=TestParticipantECB/O=DDS-Test/C=DE"
"$OPENSSL" x509 -req -days 3650 -sha256 \
  -in "$PKI_DIR/participant_ec_b/identity_csr.pem" \
  -CA "$PKI_DIR/ca/ca-cert.pem" \
  -CAkey "$PKI_DIR/ca/ca-key.pem" \
  -out "$PKI_DIR/participant_ec_b/identity_cert.pem" \
  -set_serial 4
rm "$PKI_DIR/participant_ec_b/identity_csr.pem"

# --- RSA-2048 participant cert, signed by test CA ---
echo "[gen-test-pki] Generating RSA-2048 participant cert..."
"$OPENSSL" genrsa -out "$PKI_DIR/participant_rsa/identity_key.pem" 2048
"$OPENSSL" req -new -sha256 \
  -key "$PKI_DIR/participant_rsa/identity_key.pem" \
  -out "$PKI_DIR/participant_rsa/identity_csr.pem" \
  -subj "/CN=TestParticipantRSA/O=DDS-Test/C=DE"
"$OPENSSL" x509 -req -days 3650 -sha256 \
  -in "$PKI_DIR/participant_rsa/identity_csr.pem" \
  -CA "$PKI_DIR/ca/ca-cert.pem" \
  -CAkey "$PKI_DIR/ca/ca-key.pem" \
  -out "$PKI_DIR/participant_rsa/identity_cert.pem" \
  -set_serial 3
rm "$PKI_DIR/participant_rsa/identity_csr.pem"

# --- RSA-2048 participant B cert, signed by test CA ---
echo "[gen-test-pki] Generating RSA-2048 participant B cert..."
"$OPENSSL" genrsa -out "$PKI_DIR/participant_rsa_b/identity_key.pem" 2048
"$OPENSSL" req -new -sha256 \
  -key "$PKI_DIR/participant_rsa_b/identity_key.pem" \
  -out "$PKI_DIR/participant_rsa_b/identity_csr.pem" \
  -subj "/CN=TestParticipantRSAB/O=DDS-Test/C=DE"
"$OPENSSL" x509 -req -days 3650 -sha256 \
  -in "$PKI_DIR/participant_rsa_b/identity_csr.pem" \
  -CA "$PKI_DIR/ca/ca-cert.pem" \
  -CAkey "$PKI_DIR/ca/ca-key.pem" \
  -out "$PKI_DIR/participant_rsa_b/identity_cert.pem" \
  -set_serial 5
rm "$PKI_DIR/participant_rsa_b/identity_csr.pem"

# --- Untrusted wrong-CA + cert signed by it (for negative/reject tests) ---
echo "[gen-test-pki] Generating wrong-CA and wrong-signed cert..."
"$OPENSSL" ecparam -name prime256v1 -genkey -noout \
  -out "$PKI_DIR/wrong_ca/wrong-ca-key.pem"
"$OPENSSL" req -new -x509 -days 3650 -sha256 \
  -key "$PKI_DIR/wrong_ca/wrong-ca-key.pem" \
  -out "$PKI_DIR/wrong_ca/wrong-ca-cert.pem" \
  -subj "/CN=WrongCANotTrusted/O=DDS-Test/C=DE" \
  -set_serial 10
"$OPENSSL" ecparam -name prime256v1 -genkey -noout \
  -out "$PKI_DIR/wrong_ca/wrong-identity-key.pem"
"$OPENSSL" req -new -sha256 \
  -key "$PKI_DIR/wrong_ca/wrong-identity-key.pem" \
  -out "$PKI_DIR/wrong_ca/wrong-identity-csr.pem" \
  -subj "/CN=WrongParticipant/O=DDS-Test/C=DE"
"$OPENSSL" x509 -req -days 3650 -sha256 \
  -in "$PKI_DIR/wrong_ca/wrong-identity-csr.pem" \
  -CA "$PKI_DIR/wrong_ca/wrong-ca-cert.pem" \
  -CAkey "$PKI_DIR/wrong_ca/wrong-ca-key.pem" \
  -out "$PKI_DIR/wrong_ca/wrong-identity-cert.pem" \
  -set_serial 11
rm "$PKI_DIR/wrong_ca/wrong-identity-csr.pem"

# --- Quick self-test: verify the valid certs against the test CA ---
"$OPENSSL" verify -CAfile "$PKI_DIR/ca/ca-cert.pem" \
  "$PKI_DIR/participant_ec/identity_cert.pem"
"$OPENSSL" verify -CAfile "$PKI_DIR/ca/ca-cert.pem" \
  "$PKI_DIR/participant_ec_b/identity_cert.pem"
"$OPENSSL" verify -CAfile "$PKI_DIR/ca/ca-cert.pem" \
  "$PKI_DIR/participant_rsa/identity_cert.pem"
"$OPENSSL" verify -CAfile "$PKI_DIR/ca/ca-cert.pem" \
  "$PKI_DIR/participant_rsa_b/identity_cert.pem"
# Expected: wrong-identity should NOT verify against the trusted CA
if "$OPENSSL" verify -CAfile "$PKI_DIR/ca/ca-cert.pem" \
  "$PKI_DIR/wrong_ca/wrong-identity-cert.pem" 2>/dev/null; then
  echo "ERROR: wrong-identity-cert unexpectedly verified against trusted CA!" >&2
  exit 1
fi
echo "[gen-test-pki] Negative verify check passed (wrong-CA cert correctly rejected)."

echo "[gen-test-pki] Done. PKI written to $PKI_DIR/"
ls -lR "$PKI_DIR/"
