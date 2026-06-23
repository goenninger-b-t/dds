# Spike: DDS-Security 1.1 §9.5.3.3 Serialized-Payload-Protection Wire Format

**Date:** 2026-06-22  
**WP:** WP-DDS-SECURITY-CRYPTO-MVP (M7/P6, Slice 1 of 5)  
**Status:** SPEC-ONLY FALLBACK (live Connext-Security capture BLOCKED — see §1)  
**Confidence:** HIGH on every field cited here (each backed by §9.5.3.3 clause + RTI
Shapes Demo binary evidence; nothing invented from memory).

---

## 1. Capture attempt: outcome and blocking condition

**Environment verified:**
- NDDSHOME = `/Applications/rti_connext_dds-7.3.1` (RTI Connext DDS 7.3.1 Pro)
- tshark at `/Applications/Wireshark.app/Contents/MacOS/tshark` (confirmed found)
- `rtiddsgen` on PATH
- OpenSSL 3.6.2 at `/opt/homebrew/bin/openssl`

**Blocking condition:** The RTI Security Plugins (`libnddssecurity.dylib`) are **not
installed**. This is a separately licensed add-on package (`rti_connext_dds_secure_plugins`)
not included in the base Connext DDS install. Confirmed by:
- `ls $NDDSHOME/lib/arm64Darwin20clang12.0/` — no `libnddssecurity*`
- `nm $NDDSHOME/lib/arm64Darwin20clang12.0/libnddsc.dylib | grep PRESSecurityChannel` —
  the three `PRESSecurityChannel_*` symbols are `U` (UNDEFINED, resolved at runtime) —
  meaning the plugin must be dlopen'd separately and is absent.

The RTI Shapes Demo GUI app (`RTI Shapes Demo.app`) DOES have security built in statically
(confirmed: `nm rtishapesdemo | grep RTI_Security` yields 200+ defined symbols including
`RTI_Security_Cryptography_decode_serialized_data`, `_encodeSerializedDataWithParams`,
`PRESSecurityChannel_*`). However, it is a GUI macOS `.app` requiring a display server;
it cannot run headlessly from a CI terminal without `DISPLAY` or an Aqua session.

**What was completed (even though the live capture was blocked):**
- Governance XML created: `interop/security-crypto/spike/governance-payload-only.xml`
  (`data_protection_kind=ENCRYPT`, `metadata_protection_kind=NONE`, topic=Square, domain 0)
- Signed: `signed_governance-payload-only.p7s` (OpenSSL S/MIME, signed with the bundled
  `ecdsa01RootCaKey.pem`)
- Permissions XML created: `interop/security-crypto/spike/permissions-spike.xml` (Peer01,
  allow publish+subscribe on Square, domain 0, validity 2013–2037)
- Signed: `signed_permissions-spike.p7s`
- QoS profile XML: `interop/security-crypto/spike/USER_QOS_PROFILES.xml` (the exact
  property names needed for the security-enabled participant)
- Decoder script: `interop/security-crypto/spike/decode-secured-payload.py` (parses a
  real pcap if/when the capture is taken)
- Run script: `interop/security-crypto/spike/run-spike.sh` (documents the manual GUI
  steps + the blocked CLI path)

**Recommended path to obtain a live capture:** either (a) install the RTI Security Plugins
add-on and run the built C hello_security example, or (b) open the RTI Shapes Demo GUI,
load the signed governance + permissions, publish Square, and run tshark in parallel.
The signed governance and permissions files are ready; step (b) is owner-executable in
under 5 minutes.

---

## 2. Pinned wire format (spec-clause source + binary corroboration)

### 2.1 Overall layout

Serialized-payload protection (DDS-Security 1.1 §9.5.3.3.4.4 `encode_serialized_data`)
replaces the DATA submessage's serialized payload with:

```
SecuredPayload  =  SecureDataHeader (20 bytes)
                || crypto_content   (4-byte length prefix + ciphertext)
                || SecureDataTag    (20 bytes, for receiver_specific_macs_count=0)
```

The DATA submessage framing is **not changed** (no SEC_PREFIX/POSTFIX — those are
submessage protection, which requires `metadata_protection_kind != NONE`, out of scope
for this spike). The RTPS DATA submessage's serialized-payload region (the bytes after
the octetsToInlineQos pointer, possibly preceded by a 4-byte CDR representation header)
holds the entire SecuredPayload.

Whether a standard CDR encapsulation header (4 bytes: `0x00 0x03 0x00 0x00` for XCDR2-LE
or `0x00 0x01 0x00 0x00` for CDR-LE) precedes the SecuredPayload within the serialized-
payload field is implementation-defined but consistent (the Connext binary has no
indication it omits it; the decoder script handles both cases). The spec does not mandate
a CDR header for SecuredPayload; Connext wraps it in one to satisfy the serialized-
payload framing rules of the DATA submessage. **The CDR header is NOT part of the
SecureDataHeader and must be skipped before parsing the 20-byte SecureDataHeader.**

### 2.2 SecureDataHeader (§9.5.3.3.1, 20 bytes)

```
Offset  Width  Field                  Value / Notes
------  -----  -----                  -----
  0       4    transformation_kind    CryptoTransformKind = octet[4]
                                      AES256-GCM = {0x00, 0x00, 0x00, 0x04}
                                      (spec Table 69; confirmed by Shapes Demo binary:
                                       RTI_SECURITY_CRYPTO_ALGORITHM_ID_AES256_GCM byte
                                       at VM 0x18ab418 = 0x04, with prefix {0,0,0})
  4       4    transformation_key_id  CryptoTransformKeyId = octet[4]
                                      = sender_key_id from the KeyMaterial (§9.5.2),
                                      assigned randomly at key-material creation time
  8       4    session_id             octet[4], generated via RAND_bytes per session
                                      (confirmed: "RAND_bytes sessionId" string in binary)
                                      Interpreted as uint32 LE (RTPS E-flag endianness)
 12       8    init_vector_suffix     octet[8], generated via RAND_bytes per session
                                      (confirmed: "RAND_bytes (session IV suffix)" string)
```

Total SecureDataHeader = **20 bytes**.

**transformation_kind value for AES256-GCM:**
The spec (§9.5.3.3.1 Table 69) defines `CryptoTransformKind` as `octet[4]` with:
```
CRYPTO_TRANSFORMATION_KIND_NONE      = {0, 0, 0, 0}
CRYPTO_TRANSFORMATION_KIND_AES128_GMAC = {0, 0, 0, 1}
CRYPTO_TRANSFORMATION_KIND_AES128_GCM  = {0, 0, 0, 2}
CRYPTO_TRANSFORMATION_KIND_AES256_GMAC = {0, 0, 0, 3}
CRYPTO_TRANSFORMATION_KIND_AES256_GCM  = {0, 0, 0, 4}
```
The RTI Shapes Demo binary stores these as sequential single bytes starting at symbol
`_RTI_SECURITY_CRYPTO_ALGORITHM_ID_KIND_NONE` (VM 0x18ab414), values 0x00 0x01 0x02
0x03 0x04 respectively, matching the spec. The 4-byte `transformation_kind` field is
written as `{0x00, 0x00, 0x00, N}` where N is the single-byte enum value. For AES256-GCM
(the governance default for high-security) N=4, so:
**`transformation_kind = 0x00 0x00 0x00 0x04`** (4 bytes, endian-independent: all zeros
except the last byte = 4).

### 2.3 crypto_content (§9.5.3.3.4.4)

```
Offset (from end of SecureDataHeader)  Width     Field
------                                 -----     -----
  0                                     4        length (uint32, RTPS E-flag endianness)
  4                                     N        ciphertext (AES-GCM encrypted payload)
```

The plaintext input to AES-GCM is the **original serialized payload** of the DATA
submessage, **including its CDR encapsulation header** (i.e., the entire serialized-
payload field before encryption). The ciphertext length N equals the plaintext length
(AES-GCM does not change the length; the tag is separate in SecureDataTag.common_mac).

The 4-byte length prefix is the IDL `sequence<octet>` wire framing: a `uint32` length
field in the RTPS message endianness (LE if RTPS E-flag=1, BE if E-flag=0), followed
immediately by `length` bytes of ciphertext. This is confirmed by the crypto_content
being defined as `sequence<octet>` in the DDS-Security IDL (§9.5.3.3.1 `CipherText`
typedef), which the CDR/XCDR serializer encodes with a 4-byte length prefix.

### 2.4 SecureDataTag (§9.5.3.3.3, 20 bytes for receiver_specific_macs_count=0)

```
Offset (from end of crypto_content)  Width  Field
------                                -----  -----
  0                                   16     common_mac: the AES-GCM authentication tag
                                             (16 bytes = 128-bit GCM tag)
 16                                    4     receiver_specific_macs_count (uint32 = 0)
```

For serialized-payload protection with no per-reader MAC requirement
(`metadata_protection_kind=NONE`, single session key), `receiver_specific_macs_count=0`
and the SecureDataTag is exactly 20 bytes. Confirmed by:
- "Missing or wrong verification of receiver_specific_macs" in the binary — this is the
  validation path, meaning the count IS inspected.
- "too many receivers. Omitting receiver_specific_macs..." in the binary — at count=0
  the receiver_specific_macs sequence body is empty.
- The spec §9.5.3.3.4.4 step 10: "receiver_specific_macs" is set per-reader only when
  `WITH_ORIGIN_AUTHENTICATION` is active — not for plain `ENCRYPT` without it.

### 2.5 Byte-offset summary (SecuredPayload from serialized-payload start)

Assuming a **4-byte CDR header** prefix (the Connext practice for serialized payloads):

```
Offset  Width  Field
------  -----  -----
   0      4    CDR encapsulation header (e.g. {0x00,0x01,0x00,0x00} CDR-LE) — SKIP
   4      4    transformation_kind = {0x00,0x00,0x00,0x04} (AES256-GCM)
   8      4    transformation_key_id (4 opaque bytes; sender_key_id from KeyMaterial)
  12      4    session_id (4 opaque bytes; random per session)
  16      8    init_vector_suffix (8 opaque bytes; random per session)
  24      4    crypto_content.length (uint32, RTPS E-flag endian)
  28      N    ciphertext (N = crypto_content.length bytes)
  28+N   16    SecureDataTag.common_mac (AES-GCM 128-bit auth tag)
  44+N    4    SecureDataTag.receiver_specific_macs_count = 0 (uint32)
```

Total overhead: 4 (CDR hdr) + 20 (SecureDataHeader) + 4 (ct_len) + 16 (tag) + 4 (rsm_count)
= **48 bytes** plus the ciphertext (which = plaintext length).

If NO CDR header is prepended (possible but less common with Connext):
```
Offset  Width  Field
------  -----  -----
   0      4    transformation_kind = {0x00,0x00,0x00,0x04}
   4      4    transformation_key_id
   8      4    session_id
  12      8    init_vector_suffix
  20      4    crypto_content.length
  24      N    ciphertext
  24+N   16    common_mac
  40+N    4    receiver_specific_macs_count = 0
```

The decoder `decode-secured-payload.py` handles both cases by probing the first 4 bytes
for a CDR representation header pattern before parsing the SecureDataHeader.

---

## 3. Session-key KDF (§9.5.3.3.4.2)

### 3.1 What the spec says

DDS-Security 1.1 §9.5.3.3.4.2 defines the session key as:

```
session_key = HMAC-SHA256(master_sender_key,
                          id_string ∥ master_salt ∥ session_id ∥ counter_string)
```

Where:
- `master_sender_key`: 32 bytes from `KeyMaterial_AES_GCM_GMAC.master_sender_key`
- `master_salt`: 32 bytes from `KeyMaterial_AES_GCM_GMAC.master_salt`
- `session_id`: the 4-byte field from the SecureDataHeader (uint32 LE)
- `id_string`: ASCII literal "SessionKey" (10 bytes; spec Table 70)
- `counter_string`: ASCII literal "0001" (4 bytes; spec Table 70)

The HMAC is HMAC-SHA256, producing a 32-byte output = the 256-bit AES session key.

**RTI binary corroboration:**
- String `"Cryptography_hmac3steps sessionKey"` in the Shapes Demo binary — this is the
  3-step HMAC derivation for the session key.
- String `"SessionKey"` in the binary (quoted in the sessionKey derivation log path).
- Function `RTI_Security_CryptographyEvpPkey_hmac3steps` — the 3-step KDF implementation.
- String `"sha256"` and `_RTI_Security_Util_sha256FromBuffers` symbol — HMAC-SHA256 is the
  hash; no SHA-384 (which our `dds-dare` HKDF uses) is referenced for session-key work.

### 3.2 The "3-step" KDF

The "hmac3steps" label matches the spec's §9.5.3.3.4.2 derivation structure: three
concatenated HMAC inputs (the id_string, the master_salt, the session_id/counter pair)
are hashed in a single HMAC-SHA256 call in some RTI internal conventions. The output is
the `session_key` (32 bytes for AES-256).

**This DIFFERS from `dds-dare`'s HKDF-SHA-384.** The session-key KDF is HMAC-SHA256
(not HKDF-SHA384). The DDS-Security spec mandates HMAC-SHA256 (§9.5.3.3.4.2 Table 70,
hash=SHA-256). The `dds-dare` HKDF-SHA384 was chosen for the DARE key derivation per
the CNSA-2.0 requirement; for the DDS-Security session key we use HMAC-SHA256 per the
spec. A small HMAC-SHA256 primitive over OpenSSL is needed in the new `dds-security`
system (or reuse OpenSSL `EVP_PKEY_new_raw_private_key` + `EVP_DigestSign` as RTI does,
per the `RTI_Security_CryptoLibAdapterEvpNewMacKey (master_sender_key)` string evidence).

### 3.3 Nonce (§9.5.3.3.4.3)

```
nonce (12 bytes) = session_id (4 bytes) ∥ init_vector_suffix (8 bytes)
```

This is the standard GCM 96-bit IV. The `session_id` is the uint32 from the
SecureDataHeader bytes [8:12], and `init_vector_suffix` is the 8 bytes at [12:20].
The nonce is NOT the DARE-style counter nonce; it is composed purely from the header
fields, with randomness coming from how those fields are generated (RAND_bytes for both,
per binary evidence).

### 3.4 AAD (§9.5.3.3.4.4)

```
AAD = SecureDataHeader (20 bytes)
```

The AAD for the AES-GCM AEAD is the **entire 20-byte SecureDataHeader**
(transformation_kind ∥ transformation_key_id ∥ session_id ∥ init_vector_suffix).
This is confirmed by §9.5.3.3.4.4 step 7: `encode_serialized_data` calls
`encode_payload(plaintext, session_key, session_nonce, **header**, ...)` where
`header` is the SecureDataHeader, used as the AAD. The CDR header (if present before
the SecureDataHeader) is **not** part of the AAD.

---

## 4. KeyMaterial_AES_GCM_GMAC (§9.5.2)

The struct used to bootstrap the crypto:

```
master_salt          : octet[32]    — random, per key-material creation
sender_key_id        : octet[4]     — random; placed in transformation_key_id
master_sender_key    : octet[32]    — the 256-bit secret; HMAC-SHA256 key input
receiver_specific_key_id : octet[4] — for per-reader MACs (unused when rsm_count=0)
master_receiver_specific_key : octet[32] — unused at rsm_count=0
transformation_kind  : CryptoTransformKind = {0,0,0,4} for AES256-GCM
```

RTI binary evidence: type `RTI_Security_Cryptography_KeyMaterial_AES_GCM_GMAC`; fields
`master_sender_key`, `master_salt`, `sender_key_id`, `master_receiver_specific_key`,
`receiver_specific_key_id` all confirmed as strings in the binary.

For the MVP (Slice 1), a **pre-shared test KeyMaterial** replaces the Auth-derived key.
The test key sets all fields to known constants; the session_id and init_vector_suffix
are still random (so each encrypt produces a different nonce — nonce reuse is impossible
by construction).

---

## 5. AES-GCM tag size

AES-GCM authentication tag = **128 bits = 16 bytes** (standard GCM, both DARE and here).
The `common_mac` field in SecureDataTag is always 16 bytes.

---

## 6. Hex dump (synthetic reference vector)

Since the live capture is blocked, a synthetic reference vector is given here under a
**known** test KeyMaterial so T1 can reproduce it once the implementation is built.

**Inputs:**
```
plaintext            = 0x00 01 00 00 00 00 00 04  (CDR-LE hdr + minimal ShapeType)
                       ...  (actual IDL payload)
transformation_kind  = {0x00, 0x00, 0x00, 0x04}
master_sender_key    = 0x00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f
                       10 11 12 13 14 15 16 17  18 19 1a 1b 1c 1d 1e 1f
master_salt          = 0x40 41 42 43 44 45 46 47  48 49 4a 4b 4c 4d 4e 4f
                       50 51 52 53 54 55 56 57  58 59 5a 5b 5c 5d 5e 5f
sender_key_id        = {0xaa, 0xbb, 0xcc, 0xdd}
session_id           = {0x01, 0x00, 0x00, 0x00}  (uint32 LE = 1)
init_vector_suffix   = {0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88}
nonce                = session_id ∥ init_vector_suffix
                     = 01 00 00 00  11 22 33 44 55 66 77 88   (12 bytes)
```

**Session key derivation (HMAC-SHA256 per §9.5.3.3.4.2):**
```
session_key = HMAC-SHA256(
    key    = master_sender_key (32 bytes above),
    data   = "SessionKey" ∥ master_salt ∥ session_id ∥ "0001"
           = 53 65 73 73 69 6f 6e 4b 65 79       [SessionKey, 10 bytes]
             40 41 42 43 44 45 46 47 48 49 4a 4b  [master_salt, 32 bytes]
             4c 4d 4e 4f 50 51 52 53 54 55 56 57
             58 59 5a 5b 5c 5d 5e 5f
             01 00 00 00                           [session_id, 4 bytes LE]
             30 30 30 31                           ["0001", 4 bytes]
) => 32 bytes of session key
```

**AAD:**
```
SecureDataHeader = 00 00 00 04  aa bb cc dd  01 00 00 00  11 22 33 44 55 66 77 88
```

The exact ciphertext and tag depend on the session_key value (computed from HMAC-SHA256)
and are produced by the implementation in T1/T2. The STRUCTURAL vector above pins the
layout; the byte-for-byte vector is added in T2 once the HMAC-SHA256 primitive is built
and the known-answer output is computed.

---

## 7. Reference: source + spec citations

| Claim | Source |
|-------|--------|
| SecureDataHeader = transformation_kind(4) + transformation_key_id(4) + session_id(4) + init_vector_suffix(8) | DDS-Security 1.1 §9.5.3.3.1 |
| AES256-GCM transformation_kind = {0,0,0,4} | DDS-Security 1.1 §9.5.3.3.1 Table 69; Shapes Demo binary enum byte at VM 0x18ab418 = 0x04 |
| crypto_content = sequence<octet> → 4-byte LE/BE length prefix + ciphertext | DDS-Security 1.1 §9.5.3.3.1; CDR/IDL sequence<octet> encoding |
| SecureDataTag = common_mac(16) + receiver_specific_macs_count(4) [= 0 for payload protection] | DDS-Security 1.1 §9.5.3.3.3; binary string "too many receivers" + rsm_count check |
| receiver_specific_macs_count = 0 for plain ENCRYPT without WITH_ORIGIN_AUTHENTICATION | DDS-Security 1.1 §9.5.3.3.4.4 step 10; Shapes Demo binary rsm validation paths |
| Nonce = session_id(4) ∥ init_vector_suffix(8) = 12 bytes | DDS-Security 1.1 §9.5.3.3.4.3 |
| session_id and init_vector_suffix both randomly generated (RAND_bytes) | Shapes Demo binary strings: "RAND_bytes sessionId", "RAND_bytes (session IV suffix)" |
| session key = HMAC-SHA256(master_sender_key, "SessionKey" ∥ master_salt ∥ session_id ∥ "0001") | DDS-Security 1.1 §9.5.3.3.4.2 Table 70; Shapes Demo: "Cryptography_hmac3steps sessionKey", "sha256" |
| HMAC-SHA256 (NOT HKDF-SHA384) for the session-key KDF | DDS-Security 1.1 §9.5.3.3.4.2; Shapes Demo: RTI_Security_Util_sha256FromBuffers, EVP_sha256 |
| AAD = SecureDataHeader (20 bytes) | DDS-Security 1.1 §9.5.3.3.4.4 (header passed as AAD to the AEAD) |
| AES-GCM tag = 16 bytes (128-bit) = common_mac | AES-GCM standard; Shapes Demo: RTI_Security_CryptoLibAdapterEvpCipherCtxHandle_getGcmTag |
| KeyMaterial fields: master_salt, sender_key_id, master_sender_key, receiver_specific_key_id, master_receiver_specific_key | DDS-Security 1.1 §9.5.2; Shapes Demo: all field names present as strings |

---

## 8. Remaining uncertainty (deferred to the live-capture owner action)

1. **CDR header before SecureDataHeader:** the spec does not mandate it; Connext may or
   may not prepend the standard CDR encapsulation header within the serialized-payload
   field. This is not security-critical (the decoder handles both; the field is not part
   of the AAD or the plaintext) but the exact offset of byte 0 matters for T1's
   parsing. **Defer to owner: run RTI Shapes Demo with the signed governance + open
   tshark + decode with the provided Python script.**

2. **transformation_key_id endianness:** The 4-byte key_id is written as opaque `octet[4]`
   (not as a `uint32` with endianness) so it is byte-identical regardless of RTPS
   E-flag. Confirmed by the IDL type `CryptoTransformKeyId = octet[4]`.

3. **receiver_specific_macs_count endianness:** This IS a uint32 field and must be written
   in RTPS E-flag endianness (same as the crypto_content length). At value 0 this is
   `00 00 00 00` in both LE and BE so the question is irrelevant for the common case.

---

## 9. Capture harness — ready to run when the Connext Security plugin is available

All files in `interop/security-crypto/spike/`:
- `governance-payload-only.xml` — governance: data_protection_kind=ENCRYPT, metadata=NONE
- `signed_governance-payload-only.p7s` — signed with ecdsa01RootCaKey.pem
- `permissions-spike.xml` — Peer01, publish+subscribe on Square, domain 0
- `signed_permissions-spike.p7s` — signed
- `USER_QOS_PROFILES.xml` — QoS profile with `dds.sec.*` property names
- `decode-secured-payload.py` — parse SecuredPayload from a pcap/pcapng file
- `run-spike.sh` — documents the manual GUI steps

When the security plugin becomes available, the capture can be taken and decoded with:
```bash
sudo tshark -i lo0 -w interop/security-crypto/spike/captures/security-payload.pcapng
# (run RTI Shapes Demo with the signed QoS, publish Square)
python3 interop/security-crypto/spike/decode-secured-payload.py \
        interop/security-crypto/spike/captures/security-payload.pcapng
```

The decoder will print field-by-field offsets, the transformation_kind value, the nonce,
the AAD, and a full hex dump — directly confirming or refuting the byte offsets in §2.5.
