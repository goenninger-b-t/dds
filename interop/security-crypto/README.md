# DDS-Security Crypto plugin interop (M7/P6, Slice 1)

**Status: Slice 1 LANDED (2026-06-22) — cross-vendor Connext-Security interop DEFERRED**

ADR 0031 documents this Slice-1 result in full.  This file summarises the interop
status honestly so it can be referenced from the ADR and the verification matrix.

---

## What "interop" means for Slice 1 and what it does not

### Level 1 — Structural conformance (ACHIEVED)

The `SecuredPayload` byte layout produced by `dds.security:serialize-secured-payload`
and `encode-serialized-payload` conforms to OMG DDS-Security 1.1 §9.5.3.3.  This is
proven by:

- `run-security-secured-payload-corpus-test`: byte-exact 48-octet `SecuredPayload`
  corpus against the §9.5.3.3 layout (every field offset and width cited from the spec
  clause + the T0 spike, none from memory).
- RTI Shapes Demo **binary string evidence** (T0 spike, §2/§3/§7):
  - `CryptoTransformKind` enum byte at VM `0x18ab418` = `0x04` → `{0,0,0,4}` (Table 69)
  - "RAND_bytes sessionId" / "RAND_bytes (session IV suffix)" → field names match
  - "Cryptography_hmac3steps sessionKey" / "SessionKey" / "sha256" → KDF matches spec
  - `RTI_Security_Cryptography_decode_serialized_data` / `_encodeSerializedDataWithParams`
    → function names confirm the same §9.5.3.3.4.4/4.5 code path

### Level 2 — Cryptographic byte-exactness of the primitives (ACHIEVED, by KAT)

- `dds.dare:aes-256-gcm-seal` / `aes-256-gcm-open` (OpenSSL EVP, ADR 0025):
  KAT-verified byte-exact vs **NIST SP 800-38D Test Case 16**.
- `dds.dare:hmac-sha256` (OpenSSL `EVP_Q_mac`, T1):
  KAT-verified byte-exact vs **RFC 4231 §4.3 HMAC-SHA-256 Test Case 2**
  (authentic published vector — NOT self-generated).

For identical `(master_sender_key, master_salt, session_id, plaintext, iv_suffix)`,
our `(ciphertext, tag)` is byte-identical to any conformant AES-256-GCM + HMAC-SHA256
implementation, including Connext's.  This is equality-by-published-KAT established
without a live Connext-Security peer.

### Level 3 — Our-to-our wire proof (ACHIEVED)

`run-security-encrypted-pubsub-test` (3-node loopback, `run-our2our.sh`):

| Node | `crypto-transform` | Receives |
|---|---|---|
| PUB | `shared-km` (encode) | (publishes "SQUARE" plaintext) |
| SUB | `shared-km` (decode) | byte-exact plaintext |
| PLAIN | NIL (no crypto) | first 4 bytes = `#(0 0 0 4)` (SecuredPayload ciphertext on wire) |

Both SBCL and Clasp pass identically, Clasp first.

### Level 4 — Live cross-vendor Connext-Security byte-compare (DEFERRED)

The RTI Connext Security Plugins (`libnddssecurity.dylib`,
`rti_connext_dds_secure_plugins` add-on) are **not installed** in this environment —
they are a separately licensed product.

Confirmed in T0 spike §1:
- `ls $NDDSHOME/lib/arm64Darwin20clang12.0/libnddssecurity*` → empty
- `nm $NDDSHOME/lib/arm64Darwin20clang12.0/libnddsc.dylib | grep PRESSecurityChannel`
  → symbols are `U` (undefined, loaded at runtime from the absent plugin)

**Do NOT state "cross-vendor interop verified" based on the T1–T3 evidence.**

This live byte-compare is Slice 5 of the M7 roadmap.  It requires:

1. Installing the RTI Security Plugins add-on.
2. Running the signed Governance + Permissions XMLs (already prepared in
   `interop/security-crypto/spike/`).
3. Capturing a live encrypted DATA submessage with tshark.
4. Decoding the `SecuredPayload` with `interop/security-crypto/spike/decode-secured-payload.py`
   and verifying: (a) structural layout matches our serializer; (b) using our
   `decode-serialized-payload` with the matching test key-material successfully opens
   the Connext-produced ciphertext.

Until this is done, the P6 exit gate is NOT met.

---

## Files in this directory

| File | Purpose |
|---|---|
| `run-our2our.sh` | Our-to-our wire proof (arm A: in-process; arm B: tshark ciphertext capture) |
| `spike/governance-payload-only.xml` | Governance: `data_protection_kind=ENCRYPT`, `metadata_protection_kind=NONE` |
| `spike/signed_governance-payload-only.p7s` | Signed with RTI's bundled `ecdsa01RootCaKey.pem` |
| `spike/permissions-spike.xml` | Peer01, publish+subscribe on Square, domain 0, validity 2013–2037 |
| `spike/signed_permissions-spike.p7s` | Signed |
| `spike/USER_QOS_PROFILES.xml` | `dds.sec.*` property names for a security-enabled participant |
| `spike/decode-secured-payload.py` | Parse `SecuredPayload` field-by-field from a pcap/pcapng |
| `spike/run-spike.sh` | Documents the manual GUI steps + the blocked CLI path |
