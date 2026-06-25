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

## 6. Authentication plugin — Slice 2a (DDS-Security 1.1 §8.7, §9.3)

Slice 2a (landed 2026-06-24, WP-DDS-SECURITY-AUTH-2A, ADR 0032) delivers the
DDS-Security 1.1 **`DDS:Auth:PKI-DH`** builtin Authentication plugin — the foundation that
ultimately replaces the Slice-1 pre-shared test key with keys derived from a proper
mutual-authentication handshake.

**Scope of Slice 2a:** PKI identity load + the complete §8.7.2.4 three-message PKI-DH
handshake (Request → Reply → Final) → a `SharedSecret`, our-to-our, both §9.3 suites.  No
live discovery, no key derivation into `key-material` — those are Slices 2b and 2c.

### 6.1 The §8.7.2.4 three-message handshake

Two participants mutually authenticate via X.509 certificates and a Diffie-Hellman ephemeral
key exchange:

1. **Request** (requester → replier):  requester's cert (`c.id`), its ephemeral DH public key
   (`dh1`, SubjectPublicKeyInfo DER), a 32-byte nonce (`challenge1`), and a SHA-256 hash of
   the requester's `c.*` properties (`hash_c1`).
2. **Reply** (replier → requester):  replier's cert and ephemeral key (`dh2`), `challenge2`,
   `hash_c2`, echoes of `hash_c1` / `dh1` / `challenge1`, and a **digital signature**
   (`Sign2`) over a CDR big-endian `BinaryPropertySeq` of
   `hash_c2 ∥ challenge2 ∥ dh2 ∥ challenge1 ∥ dh1 ∥ hash_c1` (§9.3.2.2).
   The requester verifies the replier's cert chain + `Sign2`.
3. **Final** (requester → replier):  echoes of all fields + a **digital signature** (`Sign1`)
   over `hash_c1 ∥ challenge1 ∥ dh1 ∥ challenge2 ∥ dh2 ∥ hash_c2` (§9.3.2.3).
   The replier verifies `Sign1`.
4. Both sides independently compute **`SharedSecret = SHA-256(ECDH-or-FFDH-agreed-value)`**
   (§9.3.3).

Both participants reach `:authenticated` with byte-equal `SharedSecret`.

### 6.2 The two §9.3 suites

| Suite | `kagree_algo` | `dsign_algo` | Cert kind |
|---|---|---|---|
| `+suite-ecdh+` | `"ECDH+prime256v1-CEUM"` | `"ECDSA-SHA256"` | EC P-256 |
| `+suite-ffdh+` | `"DH+MODP-2048-256"` | `"RSASSA-PSS-SHA256"` | RSA-2048 |

Suite selection is via `select-auth-suite (local-cert-kind remote-cert-kind)` (§9.3.2):
both EC → `+suite-ecdh+`; both RSA → `+suite-ffdh+`; mismatched → NIL → reject.
`select-auth-suite` is implemented and tested; wiring it into the discovery entry points is a
Slice 2b item.

### 6.3 The API (`dds.security`, Slice 2a)

```lisp
;;; PKI identity

(validate-local-identity ca-pem cert-pem key-pem guid)
  ;; -> (values identity-handle nil) | (values nil reason-string)
  ;; Load + chain-verify the local participant identity from PEM octet vectors.
  ;; GUID: 16-octet array used for the §8.7.2.4 role ordering.

(validate-remote-identity local remote-identity-token)
  ;; -> (values :ok :requester nil) | (values :ok :replier nil) | (values :rejected role reason)
  ;; Parse the remote IdentityToken; decide local role (§8.7.2.4 GUID lexicographic ordering).

(identity-token handle)      ; -> IdentityToken CDR LE octet vector (§8.7.2.2 / §9.3.1)
(free-identity-handle handle)

;;; Suites and selection

+suite-ecdh+        ; ECDH+prime256v1-CEUM / ECDSA-SHA256 / SHA-256 (DDS-Security 1.1 §9.3)
+suite-ffdh+        ; DH+MODP-2048-256 / RSASSA-PSS-SHA256 / SHA-256 (§9.3 / RFC 3526 §3)
(select-auth-suite local-cert-kind remote-cert-kind)
  ;; -> auth-suite | nil
  ;; :ec  + :ec  -> +suite-ecdh+
  ;; :rsa + :rsa -> +suite-ffdh+
  ;; mixed       -> NIL (§9.3.2; handshake must reject)

;;; Handshake state machine

(begin-handshake-request local remote suite)
  ;; -> (values request-token-octets handshake-handle)
  ;; Initiate the handshake as the requester (local GUID < remote GUID per §8.7.2.4).

(begin-handshake-reply local remote request-token-octets suite)
  ;; -> (values reply-token-octets handshake-handle) | (values nil nil)
  ;; Process the Request token as the replier; verify peer cert chain + hash_c1.

(process-handshake handle incoming-token-octets)
  ;; -> (values next-token-or-nil status)
  ;; status: :continue | :authenticated | :rejected
  ;; Requester (:awaiting-reply): processes Reply -> produces Final; state -> :authenticated.
  ;; Replier (:awaiting-final): processes Final; state -> :authenticated. No further token.

;;; SharedSecret access

(handshake-shared-secret handle)            ; -> shared-secret-handle | nil
(shared-secret-bytes shared-secret-handle)  ; -> (simple-array (unsigned-byte 8) (32))
(free-shared-secret-handle handle)          ; -> t  (zeroizes + frees the foreign buffer)
(free-handshake-handle handle)              ; -> t
```

### 6.4 A worked our-to-our example (EC suite)

```lisp
(let* ((ca-pem   (uiop:read-file-string "interop/security-auth/pki/ca/ca-cert.pem"))
       (cert-a   (uiop:read-file-string "interop/security-auth/pki/participant_ec/identity_cert.pem"))
       (key-a    (uiop:read-file-string "interop/security-auth/pki/participant_ec/identity_key.pem"))
       (cert-b   (uiop:read-file-string "interop/security-auth/pki/participant_ec_b/identity_cert.pem"))
       (key-b    (uiop:read-file-string "interop/security-auth/pki/participant_ec_b/identity_key.pem"))
       (to-pem   (lambda (s)
                   (map '(simple-array (unsigned-byte 8) (*)) #'char-code s)))
       (guid-a   (make-array 16 :element-type '(unsigned-byte 8)
                                :initial-contents '(1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16)))
       (guid-b   (make-array 16 :element-type '(unsigned-byte 8)
                                :initial-contents '(200 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16))))

  ;; 1. Load and validate local identities
  (multiple-value-bind (id-a err-a)
      (dds.security:validate-local-identity (funcall to-pem ca-pem)
                                             (funcall to-pem cert-a)
                                             (funcall to-pem key-a) guid-a)
    (assert (not (null id-a)) () (format nil "id-a failed: ~a" err-a))
    (multiple-value-bind (id-b err-b)
        (dds.security:validate-local-identity (funcall to-pem ca-pem)
                                               (funcall to-pem cert-b)
                                               (funcall to-pem key-b) guid-b)
      (assert (not (null id-b)) () (format nil "id-b failed: ~a" err-b))

      ;; 2. Validate remote identity — determine roles (GUID ordering)
      ;; guid-a (1,2,...) < guid-b (200,2,...), so A is :requester, B is :replier.

      ;; 3. Requester sends HandshakeRequestMessageToken
      (multiple-value-bind (req-tok req-hdl)
          (dds.security:begin-handshake-request id-a id-b dds.security:+suite-ecdh+)

        ;; 4. Replier processes Request, sends HandshakeReplyMessageToken
        (multiple-value-bind (rep-tok rep-hdl)
            (dds.security:begin-handshake-reply id-b id-a req-tok dds.security:+suite-ecdh+)
          (assert (not (null rep-tok)) () "reply nil")

          ;; 5. Requester processes Reply, sends HandshakeFinalMessageToken
          (multiple-value-bind (final-tok req-status)
              (dds.security:process-handshake req-hdl rep-tok)
            (assert (eq req-status :continue) () (format nil "req status ~a" req-status))

            ;; 6. Replier processes Final, both sides now :authenticated
            (multiple-value-bind (nil-tok rep-status)
                (dds.security:process-handshake rep-hdl final-tok)
              (assert (eq rep-status :authenticated) () "rep not :authenticated")
              (assert (null nil-tok) () "rep returned unexpected token")
              (assert (eq (dds.security:handshake-handle-state req-hdl) :authenticated))

              ;; 7. Both SharedSecrets are byte-equal
              (let ((ss-req (dds.security:handshake-shared-secret req-hdl))
                    (ss-rep (dds.security:handshake-shared-secret rep-hdl)))
                (assert (equalp (dds.security:shared-secret-bytes ss-req)
                                (dds.security:shared-secret-bytes ss-rep))
                        () "SharedSecrets not byte-equal")
                (format t "~&SharedSecret (32 bytes): ~{~2,'0x~}~%"
                        (coerce (dds.security:shared-secret-bytes ss-req) 'list)))

              ;; 8. Clean up all foreign resources
              (dds.security:free-handshake-handle req-hdl)
              (dds.security:free-handshake-handle rep-hdl)))
          (dds.security:free-identity-handle id-a)
          (dds.security:free-identity-handle id-b))))))
```

Replace `+suite-ecdh+` with `+suite-ffdh+` and the RSA participant fixtures for the FFDH
suite.  The API is identical; only the suite parameter changes.

### 6.5 Published KATs

| KAT | Source | Test |
|---|---|---|
| SHA-256(`""`) | NIST FIPS 180-4 | `run-auth-sha256-kat` |
| ECDH P-256 shared secret | RFC 5903 §8.1 (Group 19 / P-256) | `run-auth-ecdsa-kat` |
| ECDSA-P256/SHA-256 deterministic (`"sample"`) | RFC 6979 §A.2.5 | `run-auth-ecdsa-kat` |
| RSA-PSS-SHA256-saltlen32 (empty msg, valid sig) | Wycheproof rsa_pss_2048_sha256_mgf1_32 tcId 1 | `run-auth-rsa-pss-kat` |
| RSA-PSS-SHA256 invalid-sig rejection | Wycheproof rsa_pss_2048_sha256_mgf1_32 tcId 62 | `run-auth-rsa-pss-kat` |
| FFDH MODP-2048 commutativity | self-consistency round-trip (no published oracle available) | `run-auth-ffdh-kat` |

The FFDH KAT is a self-consistency commutativity proof — no published MODP-2048 shared-secret
test vector was located (NIST CAVP KAS-FFC does not cover OpenSSL `EVP_PKEY`-level MODP-2048).
This is documented honestly; cross-vendor FFDH byte-equality is a Slice 5 verification item.

### 6.6 The honest interop posture

Three levels, as in Slice 1:

1. **Our-to-our mutual authentication + byte-equal SharedSecret** (achieved): both ECDH and
   FFDH suites complete the full three-message handshake; both sides reach `:authenticated`
   with identical SharedSecret values.  Tested by `run-auth-handshake-ecdh-test` and
   `run-auth-handshake-rsa-test`.

2. **Cryptographic primitive conformance** (achieved, by published KAT): ECDH P-256, ECDSA-SHA256,
   RSA-PSS-SHA256 (saltlen=32), and SHA-256 each produce byte-identical output to any conformant
   implementation, proven by RFC 5903, RFC 6979, Wycheproof, and NIST FIPS 180-4 vectors.

3. **Live cross-vendor PKI-DH authentication interop** (DEFERRED to Slice 5 — NOT achieved):
   the RTI Connext Security Plugins are not installed.  Several internal details are
   self-consistent (our-to-our) but unverified against a live Connext peer:
   - The internal-token-vs-CDR-DataHolder wire mapping (Slice 2b item).
   - CDR-BE BinaryPropertySeq alignment for hash_c1/hash_c2/signature inputs.
   - FFDH dh1/dh2 SPKI-DER encoding vs Connext.
   - RSA-PSS saltlen=32 vs Connext's convention.

   **Do NOT interpret this section as "cross-vendor authentication interop verified."**

---

## 6bis. Authentication plugin — Slice 2b-i: wire transport (DDS-Security 1.1 §7.4.4, §9.3.4)

Slice 2b-i (landed 2026-06-25, WP-DDS-SECURITY-AUTH-2BI, ADR 0033) puts the Slice 2a
in-process handshake tokens on the real wire, completing the PSM transport layer.

### 6bis.1 SPDP IdentityToken (§8.7.2.2 / §9.3.1 / RTPS 2.5 §9.4.1.3)

`spdp-data` gains an `identity-token-octets` slot (type `(or (simple-array (unsigned-byte 8) (*)) null)`,
default NIL).  When set:

- `serialize-spdp-data` emits `PID_IDENTITY_TOKEN` (PID 0x1001, DDS-Security 1.1
  §9.4.1.3) carrying the CDR-LE `DataHolder` bytes of the participant's `IdentityToken`.
- The `builtin-endpoint-set` is ORed with bits 22 (`+be-participant-stateless-writer+`)
  and 23 (`+be-participant-stateless-reader+`) per DDS-Security 1.1 §7.4.6.1 Table 29.
- `parse-spdp-data` reads and stores the `identity-token-octets` when PID 0x1001 is
  present; silently skips it when absent (conformant receivers must skip unknown optional
  PIDs per RTPS 2.5 §9.6.2.2.2).

**Default-OFF:** when `identity-token-octets` is NIL the serialized SPDP is byte-identical
to the pre-security wire — no extra PID, no extra bits.

**Don't-break-plain:** plain Connext or Fast DDS receivers skip PID 0x1001 silently
(optional bit set per §9.4.1.3) and ignore PSM bits 22/23 (RTPS 2.5 §8.5.3.1).
See `interop/security-auth-discovery/README.md` for the full environment-limited outcome.

### 6bis.2 The §9.3.4 DataHolder + §7.4.4 ParticipantGenericMessage codec (`dds.security`)

Handshake tokens travel as CDR-LE `DataHolder` blobs inside a
`ParticipantGenericMessage` (`ParticipantStatelessMessage`) envelope.

| Symbol | Contract |
|---|---|
| `handshake-token->dataholder (token)` | Serialize a `handshake-token` struct (Slice 2a) to CDR-LE `DataHolder` octets (§9.3.4): class_id string + `PropertySeq(count=0)` + `BinaryPropertySeq` |
| `dataholder->handshake-token (octets)` | Parse CDR-LE `DataHolder` octets back to a `handshake-token`; bounds-checked, fail-closed (NIL on any malformed/truncated/over-declared input) |
| `make-generic-message (&key ...)` | Serialize a `ParticipantGenericMessage` envelope as CDR-LE: 2×`MessageIdentity`(24) + 3×`GUID_t`(16) + `message_class_id`(CDR-LE string) + `DataHolderSeq`(u32-LE count + `DataHolder*`) |
| `parse-generic-message (octets)` | Parse a CDR-LE envelope; returns 9 values (source-guid sn related-guid related-sn dest-participant-guid dest-endpoint-guid source-endpoint-guid message-class-id dataholder-list) or all NIL on malformed |
| `+auth-message-class-id+` | `"dds.sec.auth"` (the `message_class_id` for all handshake tokens; DDS-Security 1.1 §7.4.4 / §9.3) |

**Endianness split:** the PSM wire (`DataHolder` + `ParticipantGenericMessage`) is
CDR-LE.  The Slice 2a hash/signature inputs (`BinaryPropertySeq` for `hash_c1`,
`hash_c2`, `Sign1`, `Sign2`) remain CDR-BE per §9.3.2 — the BE bytes are carried
verbatim as raw octets inside the LE DataHolder value field.  The two serializations
are distinct and never mixed.

### 6bis.3 PSM endpoints (`dds.disc` / `dds.rtps.discovery`)

| Symbol | Value | Source |
|---|---|---|
| `+entityid-participant-stateless-writer+` | `0x000201C3` | DDS-Security 1.1 §9.5.1.3 Table 40 |
| `+entityid-participant-stateless-reader+` | `0x000201C4` | DDS-Security 1.1 §9.5.1.3 Table 40 |
| `+be-participant-stateless-writer+` | bit 22 | DDS-Security 1.1 §7.4.6.1 Table 29 |
| `+be-participant-stateless-reader+` | bit 23 | DDS-Security 1.1 §7.4.6.1 Table 29 |

`disc-node` gains:
- `%send-stateless-message (node dest-prefix envelope-octets)` — wraps the CDR-LE
  envelope in a DATA submessage and sends unicast to the PSM reader EntityId port.
- `on-stateless-message` slot — a closure called by the receiver thread with
  `(node src-prefix token)` when a PSM DATA arrives.

### 6bis.4 A worked end-to-end example (our-to-our, EC suite)

```lisp
;; Node-A and Node-B both carry an IdentityToken in their SPDP.
(let* ((node-a (dds.disc:make-disc-node
                :guid-prefix prefix-a :host "127.0.0.1" :port 0
                :identity-token-octets (dds.security:identity-token id-a)
                :on-stateless-message
                (lambda (node src-prefix token)
                  (declare (ignore src-prefix))
                  ;; A's callback: receives Reply -> process-handshake -> send Final
                  (%on-a-reply node token state))))
       (node-b (dds.disc:make-disc-node
                :guid-prefix prefix-b :host "127.0.0.1" :port 0
                :identity-token-octets (dds.security:identity-token id-b)
                :on-stateless-message
                (lambda (node src-prefix token)
                  (declare (ignore src-prefix))
                  ;; B's callback: receives Request -> begin-handshake-reply -> send Reply;
                  ;;                receives Final  -> process-handshake -> :authenticated
                  (%on-b-request-or-final node token state)))))
  ;; 1. SPDP discovery (real UDP loopback).
  (dds.disc:start-node node-a)
  (dds.disc:start-node node-b)
  ;; 2. Initiate handshake from A (requester, GUID-A < GUID-B per §8.7.2.4).
  (multiple-value-bind (req-octets req-hdl)
      (dds.security:begin-handshake-request id-a id-b dds.security:+suite-ecdh+)
    (let ((req-tok (dds.security::%parse-token req-octets)))
      ;; 3. Serialize to DataHolder, wrap in PSM envelope, send.
      (dds.disc:%send-stateless-message
        node-a prefix-b
        (dds.security:make-generic-message
          :source-guid src-ep-a :sequence-number 1
          :related-guid zero-guid :related-sn 0
          :dest-participant-guid dest-part-b
          :dest-endpoint-guid dst-ep-b :source-endpoint-guid src-ep-a
          :message-class-id dds.security:+auth-message-class-id+
          :dataholders (list (dds.security:handshake-token->dataholder req-tok)))))
    ;; 4-6 happen via callbacks; poll for completion.
    (loop until (both-authenticated-p state) do (sleep 0.02))
    ;; 7. Both SharedSecrets are byte-equal.
    (assert (equalp (wire-hs-state-a-ss state) (wire-hs-state-b-ss state)))))
```

See `run-auth-handshake-over-wire-test` in
`src/dds-tests/security-auth-test.lisp` for the full working test.

### 6bis.5 The honest interop posture for Slice 2b-i

**Level 1 — Our-to-our handshake over the real UDP wire (ACHIEVED)**
Both nodes reach `:authenticated` with byte-equal `SharedSecret`.  Proven by
`run-auth-handshake-over-wire-test` (Clasp 329 + SBCL 329, Clasp first).

**Level 2 — Don't-break-plain (ENVIRONMENT-LIMITED)**
The in-process portable guard (`run-auth-spdp-identity-token-test` arm b) proves the
DEFAULT-OFF path is byte-identical.  RTPS 2.5 §9.6.2.2.2 requires conformant peers to
silently skip unknown optional PIDs; RTPS 2.5 §8.5.3.1 requires ignoring unknown
endpoint bits.  A live plain-peer session is environment-limited (see
`interop/security-auth-discovery/README.md`).

**Level 3 — Live Connext-Security authentication interop (DEFERRED to Slice 5)**
The RTI Security Plugins are not installed.  The DataHolder byte-match vs Connext,
CDR-BE alignment of hash inputs, FFDH SPKI-DER encoding, and RSA-PSS saltlen are
self-consistent (our-to-our) but unverified against a live Connext peer.

**Do NOT interpret this section as "cross-vendor authentication interop verified."**

---

## 7. Roadmap (M7/P6)

| Slice | Description | Status |
|---|---|---|
| **1** | Crypto plugin: AES256-GCM `SecuredPayload` + session-key KDF + `disc-node` integration (ADR 0031) | **LANDED** |
| **2a** | Authentication plugin: PKI identity + §8.7.2.4 PKI-DH handshake → SharedSecret, both §9.3 suites, our-to-our (ADR 0032) | **LANDED** |
| **2b-i** | Wire transport: SPDP IdentityToken + PSM endpoints + DataHolder/envelope codec + our-to-our handshake over UDP (ADR 0033) | **LANDED** |
| 2b-ii | Discovery integration: on-participant-discovered hook + auth manager + per-participant auth-state + endpoint-match auth-gate + `select-auth-suite` wiring | pending |
| 2c | Crypto key-exchange: derive `key-material` from SharedSecret → replace `make-test-key-material` | pending |
| 3 | AccessControl plugin (§8.8): governance/permissions XML, topic-level policy enforcement | pending |
| 4 | Secure discovery (§7.4.4): SPDP/SEDP participant/endpoint authentication | pending |
| 5 | Connext-Security live interop: live cross-vendor PKI-DH auth interop (the P6 exit gate) | pending |
