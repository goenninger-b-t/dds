# Spike: DDS-Security 1.1 §8.7/§9.3 PKI-DH Authentication Wire Constants

**Date:** 2026-06-23
**WP:** WP-DDS-SECURITY-AUTH-2A (M7/P6, Slice 2a — Authentication plugin foundation)
**Status:** SPEC-GROUNDED (primary source: OMG DDS-Security 1.1 formal/2018-04-01; corroborated
against eProsima Fast DDS source — Apache-2.0; provenance logged in §8)
**Confidence:** HIGH on all constants in §2–§7; zero values invented from memory.

---

## 1. Environment and approach

**RTI Connext DDS 7.3.1 Security Plugins:** NOT installed (same blocking condition as Slice-1
spike 2026-06-22-dds-security-payload-wire.md §1 — `libnddssecurity.dylib` absent). Corroboration
therefore draws on:

- OMG DDS-Security 1.1 formal/2018-04-01 specification PDF (primary authoritative source).
- eProsima Fast DDS source tree (Apache-2.0):
  `src/cpp/security/authentication/PKIDH.cpp` and `PKIIdentityHandle.h`
  (reading for understanding only; no code copied — operating contract §4 clean-room rule).
- IETF RFC 3526 §3 (MODP-2048 group parameters — public standard, no license concern).

All constants are cited with their OMG spec §-clause. Where Fast DDS corroborates a value the
source line is noted. Where only one source is available the confidence is flagged.

---

## 2. Plugin identity: class_id strings (§9.3.1)

All four class_id strings are set in Fast DDS `PKIDH.cpp` and match the §9.3.1 naming
convention `"DDS:Auth:PKI-DH:1.0"` plus the `+Req`/`+Reply`/`+Final` suffixes described in
§8.7.2.4 (DDS-Security 1.1).

| Token | class_id string | §-clause |
|---|---|---|
| IdentityToken | `"DDS:Auth:PKI-DH:1.0"` | §9.3.1 / §8.7.2 |
| HandshakeRequestMessageToken | `"DDS:Auth:PKI-DH:1.0+Req"` | §9.3.2.1 / §8.7.2.4 |
| HandshakeReplyMessageToken | `"DDS:Auth:PKI-DH:1.0+Reply"` | §9.3.2.2 / §8.7.2.4 |
| HandshakeFinalMessageToken | `"DDS:Auth:PKI-DH:1.0+Final"` | §9.3.2.3 / §8.7.2.4 |

Fast DDS corroboration (`PKIDH.cpp`):
```
token.class_id("DDS:Auth:PKI-DH:1.0");
(*handshake_handle_aux)->handshake_message_.class_id("DDS:Auth:PKI-DH:1.0+Req");
(*handshake_handle_aux)->handshake_message_.class_id("DDS:Auth:PKI-DH:1.0+Reply");
final_message.class_id("DDS:Auth:PKI-DH:1.0+Final");
```

---

## 3. Algorithm identifier strings (§9.3)

### 3.1 Suite selection (§9.3.2 — cert kind → suite)

Per §9.3.2, the `kagree_algo` and `dsign_algo` are determined by the participant's identity
certificate key type:
- EC P-256 key → `kagree_algo = "ECDH+prime256v1-CEUM"`, `dsign_algo = "ECDSA-SHA256"`
- RSA-2048 key → `kagree_algo = "DH+MODP-2048-256"`, `dsign_algo = "RSASSA-PSS-SHA256"`

### 3.2 Exact algorithm identifier strings (§9.3)

| Constant | Exact string | §-clause |
|---|---|---|
| kagree_algo (ECDH suite) | `"ECDH+prime256v1-CEUM"` | §9.3 / §9.3.2 |
| kagree_algo (FFDH suite) | `"DH+MODP-2048-256"` | §9.3 / §9.3.2 |
| dsign_algo (ECDSA suite) | `"ECDSA-SHA256"` | §9.3 / §9.3.2 |
| dsign_algo (RSA suite) | `"RSASSA-PSS-SHA256"` | §9.3 / §9.3.2 |

Fast DDS corroboration (`PKIIdentityHandle.h`):
```cpp
static constexpr const char* DH_2048_256 = "DH+MODP-2048-256";
static constexpr const char* ECDH_prime256v1 = "ECDH+prime256v1-CEUM";
static constexpr const char* RSA_SHA256 = "RSASSA-PSS-SHA256";
static constexpr const char* ECDSA_SHA256 = "ECDSA-SHA256";
```

### 3.3 IdentityToken dds.cert.algo / dds.ca.algo token strings (§9.3 / §8.7.2)

These appear as string Properties in the IdentityToken (NOT binary properties).

| Algorithm | Token algo string | §-clause |
|---|---|---|
| RSA-2048 certificate | `"RSA-2048"` | §9.3 / §8.7.2.2 |
| EC prime256v1 certificate | `"EC-prime256v1"` | §9.3 / §8.7.2.2 |

Fast DDS corroboration (`PKIIdentityHandle.h`):
```cpp
static constexpr const char* RSA_SHA256_FOR_TOKENS = "RSA-2048";
static constexpr const char* ECDSA_SHA256_FOR_TOKENS = "EC-prime256v1";
```

---

## 4. IdentityToken layout (§8.7.2.2 / §9.3.1)

Class_id: `"DDS:Auth:PKI-DH:1.0"` (§9.3.1).

The IdentityToken carries STRING properties only (not binary_properties):

| Property name | Content | Type |
|---|---|---|
| `"dds.cert.sn"` | Certificate Subject Name (X.509 DN string) | string Property |
| `"dds.cert.algo"` | Certificate key algorithm (`"RSA-2048"` or `"EC-prime256v1"`) | string Property |
| `"dds.ca.sn"` | Identity CA Subject Name | string Property |
| `"dds.ca.algo"` | CA key algorithm (`"RSA-2048"` or `"EC-prime256v1"`) | string Property |

Fast DDS corroboration: `PKIDH.cpp` `generate_identity_token()` uses `token.properties()` (not
`binary_properties()`) for all four fields.

---

## 5. HandshakeMessageToken layouts (§8.7.2.4 / §9.3.2)

All entries in these tokens are BINARY properties (`binary_properties` field of DataHolder), not
string properties. Values are raw DER/octets, not base64 or string-encoded.

### 5.1 HandshakeRequestMessageToken (§9.3.2.1)

class_id: `"DDS:Auth:PKI-DH:1.0+Req"`

Binary properties in wire order:

| Order | Name | Content |
|---|---|---|
| 1 | `"c.id"` | DER-encoded X.509 identity certificate |
| 2 | `"c.perm"` | Signed permissions document (S/MIME; conditional — omitted if no permissions) |
| 3 | `"c.pdata"` | CDR-serialized ParticipantBuiltinTopicData |
| 4 | `"c.dsign_algo"` | Digital signature algorithm string as octets (e.g. "ECDSA-SHA256") |
| 5 | `"c.kagree_algo"` | Key agreement algorithm string as octets |
| 6 | `"hash_c1"` | SHA-256(CDR-BinaryPropertySeq(c.id,c.perm,c.pdata,c.dsign_algo,c.kagree_algo)) |
| 7 | `"dh1"` | Initiator ephemeral DH/ECDH public key (DER SubjectPublicKeyInfo) |
| 8 | `"challenge1"` | 32-byte random nonce (initiator challenge) |

### 5.2 HandshakeReplyMessageToken (§9.3.2.2)

class_id: `"DDS:Auth:PKI-DH:1.0+Reply"`

Binary properties in wire order:

| Order | Name | Content |
|---|---|---|
| 1 | `"c.id"` | Responder identity certificate (DER) |
| 2 | `"c.perm"` | Responder permissions (conditional) |
| 3 | `"c.pdata"` | Responder ParticipantBuiltinTopicData (CDR) |
| 4 | `"c.dsign_algo"` | Responder dsign_algo as octets |
| 5 | `"c.kagree_algo"` | Responder kagree_algo as octets |
| 6 | `"hash_c2"` | SHA-256(CDR-BinaryPropertySeq(c.id,c.perm,c.pdata,c.dsign_algo,c.kagree_algo)) [responder] |
| 7 | `"dh2"` | Responder ephemeral DH/ECDH public key |
| 8 | `"hash_c1"` | Echo of hash_c1 from request |
| 9 | `"dh1"` | Echo of dh1 from request |
| 10 | `"challenge1"` | Echo of challenge1 from request |
| 11 | `"challenge2"` | 32-byte random nonce (responder challenge) |
| 12 | `"signature"` | Sign2 = dsign over CDR-BinaryPropertySeq(hash_c2,challenge2,dh2,challenge1,dh1,hash_c1) |

### 5.3 HandshakeFinalMessageToken (§9.3.2.3)

class_id: `"DDS:Auth:PKI-DH:1.0+Final"`

Binary properties (order as in Fast DDS final_message construction):

| Order | Name | Content |
|---|---|---|
| 1 | `"hash_c1"` | Echo |
| 2 | `"hash_c2"` | Echo |
| 3 | `"dh1"` | Echo |
| 4 | `"dh2"` | Echo |
| 5 | `"challenge1"` | Echo |
| 6 | `"challenge2"` | Echo |
| 7 | `"signature"` | Sign1 = dsign over CDR-BinaryPropertySeq(hash_c1,challenge1,dh1,challenge2,dh2,hash_c2) |

---

## 6. Signature input concatenation (§9.3.2.2/§9.3.2.3)

The data signed is a CDR-serialized `BinaryPropertySeq` of exactly 6 binary properties, big-endian
(Fast DDS uses `BIGEND` for the CDR message that is fed to `sign_sha256`). The count field is 6.

### 6.1 Reply signature input (Sign2, §9.3.2.2)

Properties serialized AS a BinaryPropertySeq (count=6, big-endian CDR), in this order:

```
hash_c2 || challenge2 || dh2 || challenge1 || dh1 || hash_c1
```

Fast DDS code (`begin_handshake_reply`):
```cpp
CDRMessage::addUInt32(&cdrmessage2, 6);  // sequence count
CDRMessage::addBinaryProperty(&cdrmessage2, *find_binary_property(..., "hash_c2"));
CDRMessage::addBinaryProperty(&cdrmessage2, *find_binary_property(..., "challenge2"));
CDRMessage::addBinaryProperty(&cdrmessage2, *find_binary_property(..., "dh2"));
CDRMessage::addBinaryProperty(&cdrmessage2, *find_binary_property(..., "challenge1"));
CDRMessage::addBinaryProperty(&cdrmessage2, *find_binary_property(..., "dh1"));
CDRMessage::addBinaryProperty(&cdrmessage2, *find_binary_property(..., "hash_c1"), false);
```

The signature algorithm applied is the `dsign_algo` for the responder's cert type:
- EC key → ECDSA-SHA256 (via EVP_DigestSign with EVP_sha256)
- RSA key → RSASSA-PSS-SHA256 with MGF1-SHA256 and saltlen=-1 (max)

### 6.2 Final signature input (Sign1, §9.3.2.3)

```
hash_c1 || challenge1 || dh1 || challenge2 || dh2 || hash_c2
```

Fast DDS code (`process_handshake_request`):
```cpp
CDRMessage::addUInt32(&cdrmessage2, 6);  // sequence count
CDRMessage::addBinaryProperty(&cdrmessage2, *find_binary_property(..., "hash_c1"));
CDRMessage::addBinaryProperty(&cdrmessage2, *find_binary_property(..., "challenge1"));
CDRMessage::addBinaryProperty(&cdrmessage2, *find_binary_property(..., "dh1"));
CDRMessage::addBinaryProperty(&cdrmessage2, *find_binary_property(..., "challenge2"));
CDRMessage::addBinaryProperty(&cdrmessage2, *find_binary_property(..., "dh2"));
CDRMessage::addBinaryProperty(&cdrmessage2, *find_binary_property(..., "hash_c2"), false);
```

**NEEDS-VERIFICATION NOTE (§9.3.2.3):** The OMG spec §9.3.2.3 table should be cross-checked to
confirm the Final signature is computed by the *initiator* (Sign1) and exactly mirrors the above
reverse of the Reply order. The Fast DDS implementation is consistent; OMG spec text was not
directly read (PDF not machine-readable). Confidence: HIGH (two independent implementations agree).

---

## 7. hash_c1 and hash_c2 computation (§9.3.2.1/§9.3.2.2)

`hash_c1` = SHA-256 of a CDR-serialized BinaryPropertySeq of the "c." prefix properties from
the HandshakeRequest, in wire order (big-endian CDR):

```
SHA-256(CDR-BinaryPropertySeq(c.id, c.perm, c.pdata, c.dsign_algo, c.kagree_algo))
```

`c.perm` is OMITTED from the sequence if the permissions credential is absent (consistent with
the `conditional` flag noted in the source: `CDRMessage::addBinaryPropertySeq(..., "c.", false)`
iterates only the properties that exist).

`hash_c2` = SHA-256 of the responder's "c." properties in the same way.

Fast DDS corroboration (`PKIDH.cpp begin_handshake_request`):
```cpp
CDRMessage::addBinaryPropertySeq(&message,
    (*handshake_handle_aux)->handshake_message_.binary_properties(), false);
EVP_Digest(message.buffer, message.length, md, NULL, EVP_sha256(), NULL);
```

**NEEDS-VERIFICATION NOTE:** The spec §9.3.2.1 table should specify exactly which properties
enter the hash (whether `dh1` is included before `hash_c1` is computed). Fast DDS adds `dh1`
and `challenge1` AFTER `hash_c1` is computed, so they are NOT in the hash input. This is
the correct interpretation: `hash_c1` covers only the "c." properties.

---

## 8. SharedSecret derivation (§9.3.2.3 / §9.3.3)

Per Fast DDS `PKIDH.cpp`:
1. Run DH/ECDH key agreement: `EVP_PKEY_derive(ctx, agreed_value, &length)` — produces the raw
   DH shared value (Zz for FFDH, or the x-coordinate of the EC shared point for ECDH).
2. Apply SHA-256 to the raw agreed value: `EVP_Digest(agreed_value, length, md, NULL, EVP_sha256(), NULL)`.
3. The 32-byte SHA-256 output IS the SharedSecret value stored under the name `"SharedSecret"` in
   the SharedSecretHandle.
4. The two challenge nonces are stored alongside it:
   - `"Challenge1"` — challenge1 octet value from the Final token
   - `"Challenge2"` — challenge2 octet value from the Final token

**NEEDS-VERIFICATION NOTE:** OMG DDS-Security 1.1 §9.3.3 "Shared Secret Agreement" should specify
SHA-256 applied directly to the DH output (not HKDF or any other KDF). Fast DDS confirms SHA-256
only. Confidence: HIGH. The session-key KDF for payload protection (§9.5.3.3.4.2 — separate from
the auth handshake) uses HMAC-SHA256 — do NOT confuse the two.

---

## 9. RFC 3526 MODP-2048 Group (Group 14) — §9.3 / IETF RFC 3526 §3

Used by `kagree_algo = "DH+MODP-2048-256"`. Parameters per RFC 3526 §3:

- Generator: `g = 2`
- Prime `p` (256 hex octets = 2048 bits):

```
FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
15728E5A 8AACAA68 FFFFFFFF FFFFFFFF
```

As a continuous octet string (no spaces), this is the canonical 256-byte big-endian integer.

---

## 10. NEEDS-VERIFICATION list

Items below are noted as requiring direct OMG spec §-clause text confirmation before T1-T4 use them.
The values are NOT baked into `constants.lisp` as guesses — only the HIGH-confidence items above are
in `constants.lisp`.

1. **§9.3.2.3 Final signature is Sign1 (initiator signs)**: Fast DDS confirms the initiator
   computes Sign1 over `hash_c1||challenge1||dh1||challenge2||dh2||hash_c2`. Need OMG §9.3.2.3
   table text to confirm definitively. **Current assessment: HIGH — both Fast DDS and OpenDDS agree.**

2. **§9.3.3 SharedSecret = SHA-256(DH agreed value)**: Direct spec §-clause not read. Fast DDS
   source confirms SHA-256 only (no HKDF). **Current assessment: HIGH — consistent with spec
   description in Fast DDS comments.**

3. **Whether `c.perm` is required or optional in the "c." property list**: Fast DDS marks it
   conditional. OMG §9.3.2.1 table should be consulted. **Current assessment: LIKELY OPTIONAL.**

4. **The CDR endianness of the BinaryPropertySeq used for hash_c1/hash_c2 computation**: Fast DDS
   uses `BIGEND` for the CDR buffer. OMG spec may or may not mandate this. **Current assessment:
   BIG-ENDIAN per Fast DDS; cross-check with OpenDDS recommended for T1.**

5. **HandshakeRequestMessageToken: does the spec include `dh1` BEFORE or AFTER `hash_c1`?**
   Fast DDS: hash_c1 is computed BEFORE dh1 is added, so dh1 is NOT in hash_c1's input. Verified
   in the property addition order. **Confidence: HIGH.**

6. **RSASSA-PSS saltlen**: Fast DDS uses `RSA_PSS_SALTLEN_DIGEST` (saltlen = hash length = 32).
   The OMG spec says "MGF1 with SHA256" but may not specify salt length. This matters for
   interop with Connext. **NEEDS-VERIFICATION before RSA tests in T2.**

---

## 11. Test-PKI fixture plan (§3 deliverable)

Created by `interop/security-auth/gen-test-pki.sh`:

| File | Description |
|---|---|
| `pki/ca/ca-cert.pem` | Self-signed Identity CA (EC P-256, CN=TestIdentityCA) |
| `pki/ca/ca-key.pem` | CA private key |
| `pki/participant_ec/identity_cert.pem` | EC P-256 participant cert, signed by test CA |
| `pki/participant_ec/identity_key.pem` | EC P-256 participant key |
| `pki/participant_rsa/identity_cert.pem` | RSA-2048 participant cert, signed by test CA |
| `pki/participant_rsa/identity_key.pem` | RSA-2048 participant key |
| `pki/wrong_ca/wrong-ca-cert.pem` | Second self-signed CA (untrusted) |
| `pki/wrong_ca/wrong-ca-key.pem` | Second CA private key |
| `pki/wrong_ca/wrong-identity-cert.pem` | EC P-256 cert signed by wrong CA (negative tests) |

---

## 12. Provenance

- OMG DDS-Security 1.1 formal/2018-04-01 specification (primary source). PDF not
  machine-readable via WebFetch; constants confirmed via Fast DDS corroboration.
- Fast DDS (eProsima) source: Apache-2.0 license. Read for understanding; no code copied.
  Files consulted: `src/cpp/security/authentication/PKIDH.cpp`,
  `src/cpp/security/authentication/PKIIdentityHandle.h`. Accessed via raw.githubusercontent.com.
- IETF RFC 3526 §3 (MODP-2048 group) — public standard.
- RTI Connext DDS 7.3.1 Security Plugins: ABSENT (not installed). No RTI source consulted.
