# Security — DDS-Security Cryptographic plugin (serialized-payload protection)

This page covers the `dds-security` system: the DDS-Security 1.1 **Cryptographic plugin**,
Slice 1 (serialized-payload protection, §9.5.3.3).  Slice 1 (landed 2026-06-22, ADR 0031)
provides the on-the-wire **SecuredPayload** (de)serializer, the **session-key KDF**, the
**`key-material`** bundle, and the **`encode-serialized-payload`** / **`decode-serialized-payload`**
round-trip wired into the `disc-node` send and receive paths.  It reuses the CNSA-2.0 crypto
primitives from the [`dds-dare`](durability.md) system (OpenSSL >= 3.5) — no hand-rolled
crypto.  Every wire constant is cited from the §9.5.3.3 spec clause and the T0 spike
(`docs/superpowers/spikes/2026-06-22-dds-security-payload-wire.md`), never from memory.

DDS-Security is **gated (P6)** and additive: nothing here is on the measured CDR hot path,
and the plaintext path is **byte-identical** to before until a `crypto-transform` is
explicitly set on a `disc-node` (the default is `nil`).

---

## 1. The SecuredPayload wire format (DDS-Security 1.1 §9.5.3.3)

Serialized-payload protection (§9.5.3.3.4.4 `encode_serialized_data`) replaces the DATA
submessage's serialized payload with:

```
SecuredPayload = SecureDataHeader (20 bytes)
              || crypto_content   (4-byte uint32 length prefix + ciphertext)
              || SecureDataTag    (20 bytes, for receiver_specific_macs_count = 0)
```

### 1.1 SecureDataHeader (§9.5.3.3.1, 20 bytes)

| Offset | Width | Field | Notes |
|---|---|---|---|
| 0 | 4 | `transformation_kind` | `octet[4]`; AES256-GCM = `{0x00,0x00,0x00,0x04}` (Table 69) |
| 4 | 4 | `transformation_key_id` | `octet[4]`; the sender's key id (opaque) |
| 8 | 4 | `session_id` | `octet[4]`; random per session |
| 12 | 8 | `init_vector_suffix` | `octet[8]`; random per session |

The 20-byte SecureDataHeader is exactly the **AAD** of the AES-GCM AEAD (§9.5.3.3.4.4).
The 12-byte GCM **nonce** is `session_id (4) || init_vector_suffix (8)` (§9.5.3.3.4.3).

### 1.2 crypto_content (§9.5.3.3.4.4) and SecureDataTag (§9.5.3.3.3)

`crypto_content` is a `sequence<octet>`: a `uint32` length prefix (RTPS E-flag endianness;
this stack emits little-endian, the common case) followed by the ciphertext (its length
equals the plaintext length — AES-GCM does not expand).  `SecureDataTag` for
serialized-payload protection without origin-authentication is `common_mac (16)` (the
128-bit GCM tag) `|| receiver_specific_macs_count (4 = 0)`.

### 1.3 CDR encapsulation header — the decision

The serializer emits the **spec-minimal bare SecuredPayload** (no 4-byte CDR encapsulation
header before the SecureDataHeader).  The spec does not mandate one, and whether Connext
prepends one inside the DATA serialized-payload field is implementation-defined and
currently **unconfirmed** — the live Connext-Security capture was blocked (the RTI Security
Plugins add-on is not installed; spike §1).  A live Connext byte-compare to settle it is
the **deferred follow-on** (Slice 5).  The header, if ever present, is never part of the
AAD or the plaintext.

---

## 2. The API (`dds.security`)

### 2.1 Wire layer

| Symbol | Contract |
|---|---|
| `+transformation-kind-aes256-gcm+` | The `octet[4]` `{0,0,0,4}` constant (§9.5.3.3.1 Table 69) |
| `serialize-secured-payload (kind key-id session-id iv-suffix ciphertext tag)` | Build the bare SecuredPayload octet vector |
| `parse-secured-payload (octets)` | `(values kind key-id session-id iv-suffix ciphertext tag)`; bounds-checked, fail-closed |
| `derive-session-key (master-key master-salt session-id)` | The 32-byte AES-256 session key (§9.5.3.3.4.2) |

`parse-secured-payload` **bounds-checks every field read before allocating**: a too-short
input, or a declared `crypto_content.length` that overflows the buffer, signals
`secured-payload-malformed` — never an out-of-bounds read or a partial parse
(NFR-SEC-POSTURE), and the consistency check gates the result allocation so a hostile
`0xffffffff` length cannot exhaust the heap.  This holds even at `(safety 0)`.

### 2.2 KeyMaterial

`key-material` is a `defstruct*` (§9.5.2 `CryptoTransformKeyMaterial_DH`):

| Slot | Type | Role |
|---|---|---|
| `transformation-kind` | `(simple-array (unsigned-byte 8) (*))` | `octet[4]` algorithm selector |
| `master-salt` | `(simple-array (unsigned-byte 8) (*))` | 32 bytes mixed into the session-key KDF |
| `sender-key-id` | `(simple-array (unsigned-byte 8) (*))` | 4 bytes placed in SecureDataHeader `transformation_key_id` |
| `master-sender-key` | `(simple-array (unsigned-byte 8) (*))` | 32-byte HMAC key for the KDF |
| `iv-counter` | `(unsigned-byte 64)` | monotonic counter for structural nonce uniqueness |
| `iv-counter-lock` | opaque | guards `iv-counter` against concurrent encoders |

**`make-test-key-material`** returns a fresh `key-material` with fixed, published,
non-secret constants.  It is the **MVP scaffold for offline testing only** — NOT for
production use.  The Slice-2 Auth handshake replaces it with per-writer KEM-derived keys.

Single-instance constraint: at most **one** `key-material` instance from
`make-test-key-material` may encode at a time.  Two instances sharing the same master
key start `iv-counter` at 0 and will produce colliding AES-GCM nonces (catastrophic).
Slice-2 Auth resolves this by giving each writer a unique derived key.

### 2.3 Encode / decode

| Symbol | Contract |
|---|---|
| `encode-serialized-payload (km plaintext)` | AES256-GCM-seal PLAINTEXT under KM; return a `SecuredPayload` octet vector |
| `decode-serialized-payload (km secured-octets)` | Parse + AES256-GCM-open; return plaintext or `NIL` (fail-closed on any error) |

`decode-serialized-payload` is **fail-closed**: it returns NIL — never plaintext, never
partial, never an unhandled condition — on any parse error, malformed blob, or GCM
authentication failure (wrong key, tampered ciphertext/tag/AAD).  This holds at
`(safety 0)`.

---

## 3. The `disc-node` `crypto-transform` slot

The `disc-node` struct has a `crypto-transform` slot:

```
(crypto-transform nil :type t)
; DDS-Security §9.5.3.3 Slice-1: key-material; NIL = security OFF, byte-identical (ADR 0031)
```

- **NIL (default):** security is OFF.  The send and receive paths are **byte-identical**
  to before — the `when` check is the only overhead.
- **A `key-material` instance:** security is ON for this node.  Outgoing samples are
  AES256-GCM-sealed before `writer-write`; incoming `SecuredPayload` blobs are decrypted
  on arrival (fail-closed drop on NIL).

### 3.1 Setting `crypto-transform` at node construction

```lisp
;; Create a shared key-material (one instance; shared by all nodes that should talk to each other)
(let* ((shared-km (dds.security:make-test-key-material))

       ;; Publisher: encodes every sample before wire emission
       (pub-node (dds.disc:make-disc-node
                  :guid-prefix pub-prefix :domain 83
                  :host "127.0.0.1" :port 0 :multicast nil
                  :crypto-transform shared-km))

       ;; Subscriber: decodes on receive -> plaintext delivered
       (sub-node (dds.disc:make-disc-node
                  :guid-prefix sub-prefix :domain 83
                  :host "127.0.0.1" :port 0 :multicast nil
                  :crypto-transform shared-km))

       ;; Plain node: no crypto-transform -> receives the raw SecuredPayload ciphertext
       (plain-node (dds.disc:make-disc-node
                    :guid-prefix plain-prefix :domain 83
                    :host "127.0.0.1" :port 0 :multicast nil)))
  ...)
```

All three nodes discover each other normally via SPDP/SEDP — security does not change
the discovery wire format in Slice 1 (`metadata_protection_kind=NONE`).  The DATA
submessage's serialized payload region carries the `SecuredPayload` blob instead of the
plaintext CDR payload.  A node without `crypto-transform` receives the raw ciphertext
bytes (beginning with `#(0 0 0 4)` = AES256-GCM `transformation_kind`).

### 3.2 What the wire looks like

For a plaintext payload `#(S Q U A R E SP 0x01)`:

- `pub-node` calls `encode-serialized-payload` → a 60-byte `SecuredPayload` blob
  (`SecureDataHeader(20) || uint32_LE_length(4) || AES256-GCM-ciphertext(8) || common_mac(16) ||
  rsm_count(4)`).
- The DATA submessage's serialized-payload region carries those 60 bytes.
- `sub-node` receives the blob, calls `decode-serialized-payload` → gets back the 8-byte
  plaintext.
- `plain-node` receives the blob, has no `crypto-transform` → delivers the 60-byte
  ciphertext blob directly to the application.

---

## 4. The session-key KDF (DDS-Security 1.1 §9.5.3.3.4.2)

```
session_key = HMAC-SHA256(master_sender_key,
                          "SessionKey" || master_salt || session_id || "0001")
```

This is **HMAC-SHA256** (§9.5.3.3.4.2 Table 70) — *not* the HKDF-SHA384 used by
`dds-dare` for the DARE key derivation.  The primitive is `dds.dare:hmac-sha256` (a
one-shot OpenSSL `EVP_Q_mac` over the existing handle-based libcrypto resolution; the
foreign key buffer is zeroized before free).

```lisp
(dds.security:derive-session-key master-sender-key master-salt session-id)   ; => 32-octet key
```

---

## 5. Conformance and the honest interop picture

`run-security-secured-payload-corpus-test` checks:

- (a) A **byte-exact** 48-octet `SecuredPayload` corpus;
- (b) Parse round-trips all six fields;
- (c) Fail-closed on truncated (lengths 0, 1, 19, 20, 24, 43) and over-declared inputs;
- (d) `hmac-sha256` against the **RFC 4231 §4.3 HMAC-SHA-256 Test Case 2** published
  vector (genuine independent conformance, never a self-generated vector);
- (e) The `derive-session-key` composition against an independently-assembled HMAC input.

`run-security-payload-fuzz-test` exercises 2081 adversarial inputs through
`decode-serialized-payload` — confirming no OOB read, crash, or partial parse under
`(safety 0)`.

`run-security-encrypted-pubsub-test` proves the disc-node integration end-to-end
(plaintext delivered to the subscribing node, SecuredPayload ciphertext on the wire to
the plain node).

**Cross-vendor interop is an honest three-level picture** — see
`interop/security-crypto/README.md` and ADR 0031 §cross-vendor-deferral.  The
summary: structural + KAT conformance is proven; a live Connext-Security byte-compare
is **deferred** (Slice 5, the P6 exit gate).

---

## 6. Roadmap (Slice 1 of 5 — M7/P6)

| Slice | Description | Status |
|---|---|---|
| **1 (this page)** | Crypto plugin: AES256-GCM `SecuredPayload` + session-key KDF + `disc-node` integration | **LANDED** |
| 2 | Authentication plugin (§8.7): PKIX-DH handshake, certificate exchange, per-writer derived session keys | pending |
| 3 | AccessControl plugin (§8.8): governance/permissions XML, topic-level policy enforcement | pending |
| 4 | Secure discovery (§7.4.4): SPDP/SEDP participant/endpoint authentication | pending |
| 5 | Connext-Security live interop: live cross-vendor byte-compare (the P6 exit gate) | pending |

Slice 2 (Auth) replaces `make-test-key-material` with Auth-handshake-derived per-writer
keys, resolves the single-instance nonce constraint, and eliminates the
decode-failure-on-reliable-reader caveat (matched readers share keys by construction).
See ADR 0031 §9.
