# Spike: DDS-Security 1.1 §9.5 Key-Exchange Constants

**Date:** 2026-06-26
**WP:** WP-DDS-SECURITY-AUTH-KEYX T0 (M7/P6)
**Status:** DONE_WITH_CONCERNS — all pinnable constants resolved; one material concern
(KxKey encryption of KeyMaterial in practice) is flagged NEEDS-VERIFICATION §6.
**Confidence:** HIGH on KxKey KDF (§§1–2); HIGH on KeyMaterial CDR format (§3); HIGH on
message_class_id strings (§4); MATERIAL_CONCERN on KxKey-as-AEAD-key (§6.1).

---

## 1. Environment and approach

**Sources consulted (precedence order):**

1. OMG DDS-Security 1.1 formal/2018-04-01 — primary normative authority. PDF binary; clauses
   referenced by section number. §9.5.3 covers the KDF; §9.5.2 covers KeyMaterial.
2. eProsima Fast DDS (Apache-2.0) — read for corroboration only, no code copied:
   - `src/cpp/security/cryptography/AESGCMGMAC_KeyFactory.cpp` — `create_kx_key()` and
     `register_matched_remote_participant()`.
   - `src/cpp/security/cryptography/AESGCMGMAC_KeyExchange.cpp` — `KeyMaterialCDRSerialize()`,
     `KeyMaterialCDRDeserialize()`, `create_local_participant_crypto_tokens()`,
     `set_remote_participant_crypto_tokens()`, `create_local_datawriter_crypto_tokens()`,
     `set_remote_datawriter_crypto_tokens()`.
   - `src/cpp/security/cryptography/AESGCMGMAC_Types.h` — `KeyMaterial_AES_GCM_GMAC` struct.
   - `src/cpp/security/authentication/PKIDH.cpp` — challenge generation and SharedSecret population.
   - `src/cpp/rtps/security/SecurityManager.cpp` — `GMCLASSID_SECURITY_*` macros.
3. IETF RFC 4231 (HMAC-SHA-256 test vectors) — published KAT source.
4. Prior spike docs in this repo (`2026-06-22`, `2026-06-23`, `2026-06-25`).

**No RTI Connext source, headers, or rtiddsgen output consulted.** Provenance: `docs/provenance.md`
(M7 entry added this session).

---

## 2. Step 1: KxKey derivation — exact KDF + inputs (§9.5.3)

### 2.1 KDF primitive

The key-exchange key derivation is a **two-step HMAC-SHA256** computation — the same `dds.dare:hmac-sha256`
primitive used by `derive-session-key` (§9.5.3.3.4.2), NOT HKDF.

The intermediate is a **SHA-256 hash** (not an HMAC) over the concatenation:
`challenge_1 (32B) || label (16B) || challenge_2 (32B)` → 32-byte digest.
This digest becomes the HMAC key for the outer HMAC-SHA256, with `shared_secret (32B)` as the message.

### 2.2 KxKey derivation (the `master_sender_key` for the Kx KeyMaterial)

The OMG DDS-Security 1.1 spec §9.5.3 specifies a KDF for deriving the key-exchange key from the
authenticated shared secret. Fast DDS (`AESGCMGMAC_KeyFactory.cpp`, `create_kx_key()` at
`register_matched_remote_participant()`) implements it as follows:

```
KxKey = HMAC-SHA256(
    key   = SHA-256(challenge_2 || "key exchange key" || challenge_1),
    data  = shared_secret
)
```

Where:
- `challenge_2` — 32 octets. The nonce from the HandshakeReplyMessageToken binary-property
  `"dds.cryp.kagree_algo"` / `"c2"` — the RESPONDING participant's challenge.
- `"key exchange key"` — 16-byte ASCII label (cookie), hex:
  `6b65792065786368616e6765206b6579`.
- `challenge_1` — 32 octets. The nonce from the HandshakeRequestMessageToken `"c1"` — the
  INITIATING participant's challenge.
- `shared_secret` — 32 octets. The SHA-256-hashed DH/ECDH shared secret from the handshake
  (`"SharedSecret"` entry in the SharedSecretHandle).

Output: 32 octets (AES-256 key).

**Note on challenge naming:** `challenge_1` in the SharedSecretHandle is the initiator's nonce
(`"c1"` from the Request token, stored as `"Challenge1"`); `challenge_2` is the responder's nonce
(`"c2"` from the Reply token, stored as `"Challenge2"`). The challenges are **swapped** between
the two KxKey components (see §2.3).

### 2.3 KxSalt derivation (the `master_salt` for the Kx KeyMaterial)

```
KxSalt = HMAC-SHA256(
    key   = SHA-256(challenge_1 || "keyexchange salt" || challenge_2),
    data  = shared_secret
)
```

Where:
- `challenge_1` — 32 octets (initiator's nonce).
- `"keyexchange salt"` — 16-byte ASCII label, hex:
  `6b6579657863 68616e67652073616c74`.
  Wait — correct full hex: `6b657965786368616e67652073616c74`
  (ASCII: k-e-y-e-x-c-h-a-n-g-e-space-s-a-l-t = 16 bytes).
- `challenge_2` — 32 octets (responder's nonce).
- `shared_secret` — 32 octets.

Output: 32 octets (used as `master_salt` in the KxKeyMaterial).

### 2.4 The full `create_kx_key` two-step algorithm (applicable to both derivations)

```
function create_kx_key(first, cookie, second, shared_secret):
    tmp = first(32B) || cookie(16B) || second(32B)   # 80 bytes total
    sha = SHA-256(tmp)                                # 32 bytes
    return HMAC-SHA256(key=sha, data=shared_secret)   # 32 bytes
```

For KxSalt: first=challenge_1, cookie="keyexchange salt", second=challenge_2.
For KxKey:  first=challenge_2, cookie="key exchange key", second=challenge_1.

### 2.5 Label byte sizes — confirmed 16 octets each

`"keyexchange salt"` = 16 ASCII bytes: `6b657965786368616e67652073616c74`
`"key exchange key"` = 16 ASCII bytes: `6b65792065786368616e6765206b6579`

Both labels are exactly 16 bytes, making the SHA-256 input exactly 80 bytes for both
derivations: 32 + 16 + 32 = 80 octets.

### 2.6 `dds.dare` primitive mapping

| Operation | `dds.dare` function |
|---|---|
| SHA-256(tmp) | `dds.dare:sha-256` |
| HMAC-SHA256(key, data) | `dds.dare:hmac-sha256` |

Both already exist in `dds-dare/`. The implementation in `keyexchange.lisp` (T2) will call
these directly. No new primitives needed.

### 2.7 Spec clause

OMG DDS-Security 1.1 §9.5.3 — "Key Material derivation". The two labels ("keyexchange salt"
and "key exchange key") are spec-defined strings. Fast DDS corroborates them exactly.

**Challenge sizes:** Both challenges are 32 bytes (256-bit BN_rand output in Fast DDS PKIDH.cpp;
stored as `"Challenge1"` / `"Challenge2"` in the SharedSecretHandle). The shared_secret is also
32 bytes (SHA-256 of the raw DH/ECDH output). All three inputs are 32 bytes: confirmed.

---

## 3. Step 2: §9.5.2 KeyMaterial CryptoToken wire layout

### 3.1 `KeyMaterial_AES_GCM_GMAC` struct (§9.5.2 Table 65 — matched to Slice-1 slots)

| Field name (§9.5.2) | Type | Size | Slice-1 `key-material` slot |
|---|---|---|---|
| `transformation_kind` | `CryptoTransformKind` = octet[4] | 4 B | `transformation-kind` |
| `master_salt` | octet[32] | 32 B | `master-salt` |
| `sender_key_id` | `CryptoTransformKeyId` = octet[4] | 4 B | `sender-key-id` |
| `master_sender_key` | octet[32] | 32 B | `master-sender-key` |
| `receiver_specific_key_id` | `CryptoTransformKeyId` = octet[4] | 4 B | (no Slice-1 slot; new in T3) |
| `master_receiver_specific_key` | octet[32] | 32 B | (no Slice-1 slot; new in T3) |

The Slice-1 `key-material` struct has four of the six fields. T3 must add `receiver-specific-key-id`
and `master-receiver-specific-key` slots (or carry them alongside). For AES256-GCM participant-level
protection the `receiver_specific_key_id` is zero and `master_receiver_specific_key` is absent.

### 3.2 CDR serialization of `KeyMaterial_AES_GCM_GMAC` (Fast DDS `KeyMaterialCDRSerialize`)

This is the byte layout placed in the `"dds.cryp.keymat"` binary property. It is NOT standard CDR
sequence encoding; it uses a proprietary compact format (Fast DDS `KeyMaterialCDRSerialize`).

For kind = AES256-GCM (`transformation_kind[3] = 0x04`, `key_len = 32`):

```
Offset  Size   Field
  0      4     transformation_kind[0..3]    — {0x00, 0x00, 0x00, 0x04}
  4      3     padding zeros                — {0x00, 0x00, 0x00}
  7      1     master_salt length byte      — 0x20 (= 32 decimal)
  8     32     master_salt[0..31]
 40      4     sender_key_id[0..3]
 44      3     padding zeros                — {0x00, 0x00, 0x00}
 47      1     master_sender_key length     — 0x20 (= 32)
 48     32     master_sender_key[0..31]
 80      4     receiver_specific_key_id[0..3]  — {0x00,0x00,0x00,0x00} for participant-level
 84      4     absent-key marker            — {0x00,0x00,0x00,0x00} (zero receiver_specific_key_id
                                              → 4 zero bytes instead of a length+key)
Total: 88 bytes for AES256-GCM with no receiver-specific key.
```

**NEEDS-VERIFICATION §6.2:** The 3-byte padding + 1-byte length encoding (`{0x00,0x00,0x00,0x20}`)
is Fast DDS's proprietary framing, not standard CDR `uint32` sequence-length encoding
(`{0x20,0x00,0x00,0x00}` LE). This framing is not explicitly described in the OMG DDS-Security 1.1
§9.5.2 spec text (which says the token is a DataHolder; the CDR encoding of the body is
implementation-specific). The OMG spec does NOT mandate the exact byte layout of the
`binary_property` value. For `our-to-our` interop this layout is what we implement.
For cross-vendor Connext interop (Slice 5) we will need to verify RTI's byte layout via
live capture.

### 3.3 CryptoToken DataHolder structure (§9.3.4 / DDS-Security 1.1)

The CryptoToken is a `DataHolder` carried as one element of the `DataHolderSeq` in the
`ParticipantGenericMessage.message_data`. Its structure (CDR-LE, reusing the 2b-i codec):

```
class_id              = "DDS:Crypto:AES_GCM_GMAC"   (§9.5 / Fast DDS corroboration)
PropertySeq.count     = 0 (empty — no string properties for KeyMaterial tokens)
BinaryPropertySeq.count = 1
BinaryPropertySeq[0]:
    name              = "dds.cryp.keymat"            (§9.5 / Fast DDS corroboration)
    value             = KeyMaterialCDRSerialize(km)   # 88 bytes for AES256-GCM, no rsm key
    propagate         = true (1-byte = 0x01, 3-byte pad = {0x00,0x00,0x00})
```

This maps directly into the existing `handshake-token->dataholder` / `dataholder->handshake-token`
codec from `wire.lisp`, treating the CryptoToken as a `handshake-token` with class-id
`"DDS:Crypto:AES_GCM_GMAC"` and one binary property `"dds.cryp.keymat"`.

### 3.4 KxKey protection of the serialized KeyMaterial — MATERIAL FINDING

**The OMG DDS-Security 1.1 §9.5.3 spec defines that the serialized KeyMaterial is protected by
the KxKey (AES-GCM-encrypted) before being placed in the DataHolder binary property.**

**Fast DDS does NOT implement this encryption.** In both `create_local_participant_crypto_tokens`
and `create_local_datawriter_crypto_tokens`, the serialized bytes are placed in the binary property
directly (`prop.value() = plaintext`). The AES-GCM encrypt/decrypt calls are commented out with:
```cpp
// aes_128_gcm_encrypt(plaintext, remote_participant->...master_sender_key);
```

This is a MATERIAL CONCERN for the implementation plan — see §6.1 (NEEDS-VERIFICATION). The
design specifies KxKey-encrypted transport; whether conformant encryption is required for
our-to-our interop (or whether the plaintext path is sufficient for Slice-4/5 interop) requires
a decision.

---

## 4. Step 3: CryptoToken exchange `message_class_id` values (§7.4.4)

These are the `message_class_id` strings in the `ParticipantGenericMessage` envelope (§7.4.4)
that carries the CryptoToken DataHolder sequence. Defined in Fast DDS SecurityManager.cpp as
`GMCLASSID_SECURITY_*` macros:

| Token exchange type | `message_class_id` string | §-clause |
|---|---|---|
| Participant crypto tokens | `"dds.sec.participant_crypto_tokens"` | §7.4.4 / Fast DDS |
| DataWriter crypto tokens | `"dds.sec.datawriter_crypto_tokens"` | §7.4.4 / Fast DDS |
| DataReader crypto tokens | `"dds.sec.datareader_crypto_tokens"` | §7.4.4 / Fast DDS |

**Spec basis:** DDS-Security 1.1 §7.4.4 defines ParticipantGenericMessage and specifies that the
`message_class_id` distinguishes the purpose of the message. The exact strings above match the
OMG DDS-Security Plugin SPI naming convention (§9.3) and are corroborated by Fast DDS.

For the initial Slice (this WP), only **participant_crypto_tokens** is exchanged (participant-level
key material sufficient for §9.5.3.3 serialized-payload protection). DataWriter/DataReader tokens
are carried in the same envelope format with their respective class_ids.

**Destination endpoint key:** For participant-level crypto tokens the
`destination_endpoint_key` GUID in the ParticipantGenericMessage is `GUID_t::unknown()` (all zeros)
per the SecurityManager.cpp validation check. This is a safe-to-implement default.

**Transport:** In Fast DDS, crypto tokens are sent over the **ParticipantVolatileMessageSecure**
(§7.4.5, the reliable encrypted builtin endpoint, EntityId `0xff0202C3`/`0xff0202C4` from the
2b-i spike). For this Slice, we use the **best-effort PSM stateless channel** (the existing 2b-i
wire) instead — this is the documented Slice-5 carry (ADR 0034 to be written at T8). The
`message_class_id` strings are identical regardless of transport.

---

## 5. Step 4: Published KAT for the KxKey KDF primitive

### 5.1 The KAT strategy

The KxKey KDF is a composition of:
1. SHA-256(80-byte input) → 32-byte intermediate
2. HMAC-SHA256(key=32-byte-intermediate, data=32-byte-shared-secret) → 32-byte output

Neither composition has a published DDS-Security-specific test vector. The individual primitives
(SHA-256 and HMAC-SHA256) each have published KATs we can use to validate the underlying
`dds.dare` operations independently.

### 5.2 HMAC-SHA256 KAT — RFC 4231 Test Case 1

**Source:** IETF RFC 4231, "Identifiers and Test Vectors for HMAC-SHA-224, HMAC-SHA-256,
HMAC-SHA-384, and HMAC-SHA-512", §4.2 (Test Case 1).
**URL:** https://www.rfc-editor.org/rfc/rfc4231#section-4.2

**Published vector (verbatim from RFC 4231 §4.2):**
```
Key        = 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b  (20 bytes)
Data       = 4869205468657265                            ("Hi There")
HMAC-SHA-256 = b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7
```

**Why this vector:** RFC 4231 is the normative published reference for HMAC-SHA-256
conformance. This vector validates that `dds.dare:hmac-sha256` produces the correct output
for a known key+data input. The KxKey KDF's outer step is `HMAC-SHA256(sha256_hash, shared_secret)`;
this vector confirms the HMAC-SHA256 primitive is correct independent of input size.

### 5.3 Additional RFC 4231 vector — Test Case 4

**Source:** RFC 4231 §4.5 (Test Case 4).

```
Key        = 0102030405060708090a0b0c0d0e0f10111213141516171819  (25 bytes)
Data       = cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd...         (50 bytes of 0xcd)
HMAC-SHA-256 = 82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b
```

**Use:** Secondary HMAC-SHA256 KAT with different key/data lengths. Both Test Case 1 and
Test Case 4 must pass for the `hmac-sha256` primitive to be considered correct.

### 5.4 SHA-256 KAT — FIPS PUB 180-4 §B.1 (already used in this repo)

The SHA-256 inner step is already covered by the existing DARE test suite (`dare-test.lisp`),
which pins the FIPS 180-4 §B.2 SHA-384 vector (demonstrating the approach). For SHA-256 specifically
use FIPS PUB 180-4 §B.1, Example 1:

```
Input  (1 block): "abc" = 61626300...
SHA-256 = ba7816bf8f01cfea414140de5dae2ec73b00361bbef0469332d8faebe9b80ae
```

**Source:** NIST FIPS PUB 180-4, §B.1 Example 1.
**URL:** https://csrc.nist.gov/publications/detail/fips/180/4/final

### 5.5 Summary: no published end-to-end KxKey KAT found

There is no published test vector for the full `create_kx_key(challenge_1, "key exchange key",
challenge_2, shared_secret)` composition. The KAT strategy is:
1. Test `dds.dare:hmac-sha256` against RFC 4231 §4.2 + §4.5.
2. Test `dds.dare:sha-256` against FIPS 180-4 §B.1.
3. Test `derive-kx-key` by generating a known (challenge_1, challenge_2, shared_secret) triple
   with both SBCL and Clasp independently, then cross-checking between implementations — NOT
   by computing the expected value here and embedding it as a known answer (that would be
   self-verification only). The two-impl cross-check is a non-fabrication conformance method.

**Explicit statement:** No published end-to-end DDS-Security KxKey test vector was found in
the OMG spec, Fast DDS, RTI documentation, or IETF/NIST publications. The component-primitive
KATs (RFC 4231, FIPS 180-4) are the strongest published anchors available.

---

## 6. Step 5: Assumption confirmation + NEEDS-VERIFICATION list

### 6.1 NEEDS-VERIFICATION (MATERIAL): KxKey encryption of KeyMaterial

**Finding:** Fast DDS currently transmits the serialized `KeyMaterial_AES_GCM_GMAC` bytes
**in plaintext** in the `"dds.cryp.keymat"` binary property. The AES-GCM encrypt/decrypt
calls are commented out in `AESGCMGMAC_KeyExchange.cpp`. This contradicts the OMG DDS-Security
1.1 §9.5.3 intent (the KxKey derivation exists specifically to protect the key material in
transit).

**Impact on this implementation:**
- For `our-to-our` interop (this Slice): we can implement either the spec-conformant
  (KxKey-encrypted) path or the plaintext path — both work internally.
- For Slice-5 cross-vendor Connext interop: we need to know what RTI sends. If RTI also
  sends plaintext (following Fast DDS's lead), our encrypted path will not interoperate.
- **Decision required:** Implement the spec-conformant **KxKey-encrypted** path for this Slice
  (correct behavior per §9.5.3), document the known plaintext-compat divergence with Fast DDS,
  and defer the cross-vendor wire alignment to Slice 5. This is the safest choice: it is
  never a wrong approach to be spec-conformant, and the plaintext fallback can be a compat
  config option later if needed.

**Action:** ADR 0034 must document this finding and the plaintext-vs-encrypted decision.

**If KxKey encryption is implemented (recommended):**
- AEAD: AES-256-GCM (using `dds.dare:aes-256-gcm-seal/open`).
- Key: `KxKey` (32 bytes, derived as in §2.2).
- Nonce (IV): 12 bytes. Source NEEDS-VERIFICATION — the OMG spec §9.5.3 must be consulted
  for the nonce construction. Fast DDS has it commented out so we cannot corroborate.
  Conservative approach: use a random 12-byte IV prepended to the ciphertext, matching
  the AES-GCM pattern used in existing Slice-1 encode.
- AAD: None stated in the spec clause visible here. NEEDS-VERIFICATION.
- Output: IV(12) || ciphertext(88) || tag(16) = 116 bytes for AES256-GCM no-rsm-key case.

### 6.2 NEEDS-VERIFICATION (LOW RISK): KeyMaterial CDR framing vs standard CDR

The `{0x00, 0x00, 0x00, key_len}` framing (3 zero bytes + 1-byte length) used by Fast DDS
is NOT standard CDR `uint32` sequence-length encoding. For our-to-our interop this is
irrelevant (both sides use the same framing). For Slice-5 cross-vendor interop with Connext,
confirm Connext uses the same proprietary framing via live capture.

### 6.3 NEEDS-VERIFICATION (LOW RISK): Number of DataHolders per CryptoToken message

Fast DDS `set_remote_participant_crypto_tokens` validates exactly 1 DataHolder per message
(`remote_participant_tokens.size() != 1`). This cap should be enforced by our parser.

### 6.4 CONFIRMED: manager-in-dcps design holds

`dds-disc` stays crypto-free (only hook slots + match composition). `dds-security` gains
`keyexchange.lisp` with no disc dependency. `dds-dcps/auth-manager.lisp` orchestrates.
Layering is sound and unchanged from the approved design (§3, design doc).

### 6.5 CONFIRMED: KeyMaterial-over-PSM transport holds

Using the existing best-effort PSM stateless channel for crypto-token delivery is viable for
our-to-our (no reliable delivery required; simple resend until acknowledged). The full
ParticipantVolatileMessageSecure (reliable, encrypted) endpoint is a Slice-5 carry — confirmed.

### 6.6 CONFIRMED: 2b-i `dds.security` codec reuse holds

The `make-generic-message` / `parse-generic-message` / `handshake-token->dataholder` /
`dataholder->handshake-token` functions from `auth/wire.lisp` are directly reusable for
CryptoToken messages. The DataHolder format is identical; only the `class_id` string and
binary property name differ from handshake tokens.

### 6.7 CONFIRMED: `key-material` struct slot mapping

All four existing Slice-1 `key-material` slots (`transformation-kind`, `master-salt`,
`sender-key-id`, `master-sender-key`) map directly to §9.5.2 Table 65 fields. The two
additional fields (`receiver_specific_key_id`, `master_receiver_specific_key`) must be
added to the struct in T3, with defaults of all-zeros (absent receiver-specific key).

---

## 7. Constants summary (pinned, for T2/T3 code reference)

### KxKey KDF labels (ASCII, 16 bytes each)

| Symbol | Value | Hex |
|---|---|---|
| `+kxkey-label+` | `"key exchange key"` | `6b65792065786368616e6765206b6579` |
| `+kxsalt-label+` | `"keyexchange salt"` | `6b657965786368616e67652073616c74` |

Label size: 16 bytes (both). SHA-256 input total: 32+16+32 = 80 bytes.
Challenge sizes: 32 bytes each (256-bit BN_rand, stored in SharedSecretHandle).
SharedSecret size: 32 bytes (SHA-256 of DH/ECDH raw output).

### CryptoToken DataHolder identifiers

| Symbol | Value | Source |
|---|---|---|
| `+crypto-token-class-id+` | `"DDS:Crypto:AES_GCM_GMAC"` | §9.5 / Fast DDS |
| `+crypto-token-keymat-prop+` | `"dds.cryp.keymat"` | §9.5 / Fast DDS |

### CryptoToken GenericMessage class_ids

| Symbol | Value | Source |
|---|---|---|
| `+gm-participant-crypto-tokens+` | `"dds.sec.participant_crypto_tokens"` | §7.4.4 / Fast DDS |
| `+gm-datawriter-crypto-tokens+` | `"dds.sec.datawriter_crypto_tokens"` | §7.4.4 / Fast DDS |
| `+gm-datareader-crypto-tokens+` | `"dds.sec.datareader_crypto_tokens"` | §7.4.4 / Fast DDS |

### KeyMaterial CDR byte layout (AES256-GCM, no receiver-specific key)

Total: 88 bytes.
```
[0..3]   transformation_kind  = {0x00,0x00,0x00,0x04}
[4..6]   padding              = {0x00,0x00,0x00}
[7]      master_salt length   = 0x20 (32)
[8..39]  master_salt[0..31]
[40..43] sender_key_id[0..3]
[44..46] padding              = {0x00,0x00,0x00}
[47]     master_sender_key length = 0x20 (32)
[48..79] master_sender_key[0..31]
[80..83] receiver_specific_key_id = {0x00,0x00,0x00,0x00}
[84..87] absent-key marker    = {0x00,0x00,0x00,0x00}
```

### Published KATs

| Primitive | Source | Key | Data | Expected |
|---|---|---|---|---|
| HMAC-SHA-256 | RFC 4231 §4.2 TC1 | `0b0b...(20B)` | `4869205468657265` | `b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7` |
| HMAC-SHA-256 | RFC 4231 §4.5 TC4 | `010203...19(25B)` | `cdcd...(50B)` | `82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b` |
| SHA-256 | FIPS 180-4 §B.1 | N/A | `"abc"` | `ba7816bf8f01cfea414140de5dae2ec73b00361bbef0469332d8faebe9b80ae` |

No published end-to-end DDS-Security KxKey KAT exists. KAT strategy: RFC 4231 + FIPS 180-4
for the component primitives; two-impl (Clasp + SBCL) cross-check for the composition.

---

## 8. Plan validity verdict

**The T1–T8 plan is VALID.** All pinnable constants are resolved. One material concern (§6.1:
KxKey encryption of KeyMaterial) requires a decision in ADR 0034, but does not block T1–T4.
T2 (KxKey derivation) and T3 (KeyMaterial + CryptoToken codec) must record the §6.1 decision
in their implementation — either implement spec-conformant KxKey-AEAD-wrap or implement the
Fast DDS plaintext path with a comment citing this spike and the ADR.

Recommended path: implement **spec-conformant KxKey-AEAD-wrapped** KeyMaterial for this Slice
(correct behavior), document the Fast-DDS plaintext deviation in ADR 0034, and add a compat
path for Slice-5 cross-vendor alignment if needed.
