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
  `(node src-prefix envelope-octets)` when a PSM DATA arrives.  **As of Slice 2b-ii
  (Decision 1) the hook receives the RAW `ParticipantGenericMessage` envelope octets**
  (only the payload buffer-extent is bounds-checked in `dds-disc`); `dds-disc` stays
  crypto/format-agnostic and the consumer (the auth manager) does `parse-generic-message`
  and dispatches by `message_class_id` — because both the handshake (`dds.sec.auth`) and the
  crypto-token (`dds.sec.participant_crypto_tokens`) messages share this one endpoint with
  different `DataHolder`s, so a pre-parse to a `handshake-token` in `dds-disc` would silently
  drop crypto-token messages.

### 6bis.4 A worked end-to-end example (our-to-our, EC suite)

As of Slice 2b-ii the hook delivers the **raw envelope octets** (Decision 1); the `%on-*`
helpers below first `parse-generic-message` the envelope, take the first `DataHolder`, and
`dataholder->handshake-token` it before driving the handshake (`%psm-envelope->token-octets`
in the test does exactly this).  Most callers should instead just configure an identity on
the participant (§6ter) and let the auth manager drive all of this.

```lisp
;; Node-A and Node-B both carry an IdentityToken in their SPDP.
(let* ((node-a (dds.disc:make-disc-node
                :guid-prefix prefix-a :host "127.0.0.1" :port 0
                :identity-token-octets (dds.security:identity-token id-a)
                :on-stateless-message
                (lambda (node src-prefix envelope)
                  (declare (ignore src-prefix))
                  ;; A's callback: receives Reply -> process-handshake -> send Final
                  (%on-a-reply node envelope state))))
       (node-b (dds.disc:make-disc-node
                :guid-prefix prefix-b :host "127.0.0.1" :port 0
                :identity-token-octets (dds.security:identity-token id-b)
                :on-stateless-message
                (lambda (node src-prefix envelope)
                  (declare (ignore src-prefix))
                  ;; B's callback: receives Request -> begin-handshake-reply -> send Reply;
                  ;;                receives Final  -> process-handshake -> :authenticated
                  (%on-b-request-or-final node envelope state)))))
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

## 6ter. Authentication MANAGER — Slice 2b-ii + 2c (discovery integration + key exchange)

Slice 2b-ii + 2c (landed 2026-06-26, WP-DDS-SECURITY-AUTH-KEYX, ADR 0034 at the capstone)
adds the orchestrator that finally *uses* the handshake automatically: a security-enabled
participant authenticates every discovered security-enabled peer over the PSM wire, exchanges
per-writer key material, and **gates endpoint matching strictly on authentication**.

### 6ter.1 Where it lives

The **auth manager** is `src/dds-dcps/auth-manager.lisp`, mirroring the FR-TYPE-4 type-gate
(`type-gate.lisp`).  It sits in the DCPS layer because it needs BOTH `dds-security` (handshake +
key exchange) AND `dds-disc` (hooks, send, matching); `dds-disc` stays crypto-free.  Per-participant
state hangs off the `domain-participant` (`dp-auth-state`, analogous to `dp-type-gate-state`);
per-remote state (`auth-remote`, keyed by 12-octet GUID prefix) lives in the disc-node's
manager-owned `disc-node-auth-state` table.

### 6ter.2 Turning it on

```lisp
(let ((id (dds.security:validate-local-identity ca-pem cert-pem key-pem guid)))
  ;; a security-enabled participant: advertises its IdentityToken in SPDP + installs the manager
  (dds.dcps:create-participant :domain 0 :identity id))
```

`create-participant :identity <identity-handle>` sets the node's `identity-token-octets` (so SPDP
advertises `PID_IDENTITY_TOKEN` + the PSM bits) and calls `%install-auth-manager`, which installs
three disc-node hooks: `on-participant-discovered` (the requester trigger / replier pre-stash),
`on-stateless-message` (the raw-envelope handshake + key-material dispatcher), and `auth-gate`
(the strict §7.3 endpoint-match verdict).  With **no** `:identity`, `dp-auth-state` stays NIL and
the participant is the byte-identical plain path.

### 6ter.3 The `auth-remote` state machine (§8.7 / §9.5)

| State | Meaning |
|---|---|
| `:none` | discovered + validated; role/suite recorded; no handshake yet |
| `:handshaking` | an in-flight §8.7.2.4 handshake (handle non-NIL) |
| `:authenticated` | handshake complete (SharedSecret); KxKey derived + our CryptoTokens sent; remote KeyMaterial NOT yet installed |
| `:keyed` | authenticated AND the remote writer KeyMaterial installed → endpoint matching resumed |
| `:rejected` | terminal refusal (malformed/untrusted remote, unsupported/mismatched algo, bad handshake) |

The **role** (`:requester` / `:replier`) is decided from the **real RTPS participant GUID prefixes**
(§8.7.2.4 lexicographic order) — deterministic and complementary on both peers — not from
`validate-remote-identity`'s T1 cert-sn-hash stand-in (which is used only for the `:ok`/`:rejected`
verdict).

### 6ter.4 The three design decisions

1. **One stateless endpoint, two message kinds (Decision 1).** The handshake and the crypto-token
   messages arrive on the SAME PSM endpoint with DIFFERENT `DataHolder`s.  `%on-stateless-message`
   now delivers the RAW envelope octets; the manager does `parse-generic-message`, reads
   `message_class_id`, and dispatches: `dds.sec.auth` → handshake; `dds.sec.participant_crypto_tokens`
   → install the remote KeyMaterial.  (Before, `dds-disc` pre-parsed a `handshake-token`, which
   silently dropped crypto-token messages.)
2. **Suite selection encapsulates the unsupported-algo NIL (Decision 2).**
   `select-suite-for-identities (local-identity remote-id-token-octets)` derives both cert kinds via
   the internal `%cert-algo->kind` and returns NIL — meaning *reject this remote* — when EITHER algo
   is unsupported or the suites mismatch, else the selected `auth-suite`.  This keeps the NIL handling
   where `%cert-algo->kind` lives, so the manager never passes NIL to `select-auth-suite` (whose ftype
   is `(member :ec :rsa)`).
3. **Local identity wiring (Decision 3).** The manager holds the local `identity-handle` (with the
   private key) — the disc-node holds only the IdentityToken octets.  `create-participant :identity`
   plumbs it; `%install-auth-manager (p identity-handle)` stores it in `dp-auth-state`.

### 6ter.5 The strict auth-gate (§7.3)

Consulted as the SECOND sequential gate after the type-gate returns `:compatible` (in
`%match-remote-endpoint`), outside the node lock.  Strict authenticated-only matching
(`allow_unauthenticated = FALSE`, the conformant default):

- local **not** security-enabled (`dp-auth-state` NIL) → `:compatible` (security off, unchanged);
- remote `:keyed` → `:compatible`;
- remote `:handshaking` / `:authenticated` (in flight) → `:pending` (park; resumed on `:keyed`);
- remote has NO `auth-remote` (a plain peer, no IdentityToken) OR `:rejected` / `:none` →
  `:incompatible` (strict refuse).

### 6ter.6 Key exchange (§9.5.2 / §9.5.3)

On reaching `:authenticated`, each side derives the §9.5.3 **KxKey** from the SharedSecret +
challenges (`derive-kx-key`, T2 — KxKey held in a `dds.pal` foreign buffer), generates its §9.5.2
per-writer **KeyMaterial** (`generate-writer-key-material`, T3), and sends it **KxKey-encrypted**
over PSM (`make-crypto-token-message`, T3).  The peer decrypts + installs it
(`parse-crypto-token-message`, fail-closed: a bad KxKey or any tamper → no install).  When both
authenticated AND the remote KeyMaterial is installed → `:keyed` → `resume-parked-matches`.  PSM is
best-effort with no resend this slice (the reliable `ParticipantVolatileMessageSecure` endpoint is a
Slice-5 carry); a crypto-token that arrives before the local KxKey exists is buffered and drained on
authentication.

### 6ter.7 The honest interop posture for Slice 2b-ii + 2c

**Level 1 — Our-to-our discovery → authenticate → key exchange → strict-gated match → encrypted DATA (ACHIEVED)**
Two security-enabled participants authenticate on SPDP discovery, exchange conformant
KxKey-encrypted §9.5.2 key material, and both reach `auth-remote` `:keyed` with the other's writer
KeyMaterial installed.  A security-enabled participant strictly refuses an unauthenticated peer
(`run-auth-secured-refuses-plain-test`, non-vacuous via plain↔plain control).  Encrypted pub/sub
round-trip with the exchanged keys proven by `run-auth-encrypted-pubsub-keyx-test` (ciphertext on
wire: plaintext absent + header `#(0 0 0 4)` per §9.5.3.3.1; plaintext delivered to subscriber).
337 tests Clasp + SBCL (Clasp first; non-vacuous — NOT `:keyed` before the exchange completes).

**Level 2 — Don't-break-plain (ACHIEVED)** A participant with no `:identity` is byte-identical to
the pre-security plain path; `run-auth-plain-byte-identical-test` confirms 8-byte `"PLAINDAT"` is
delivered exactly.  A security-enabled participant strictly refuses an unauthenticated peer.

**Level 3 — Live Connext-Security interop (DEFERRED to Slice 5)** The RTI Security Plugins are not
installed.  The §9.5.2 KeyMaterial framing, the KxKey-AEAD wrap, and the reliable Volatile endpoint
are self-consistent (our-to-our) but unverified against a live Connext peer (see ADR 0034).

---

## 6quarter. Key-exchange API reference and worked example

### 6quarter.1 The §9.5.3 KxKey/KxSalt API (`dds.security`)

| Symbol | Contract |
|---|---|
| `derive-kx-key (shared-secret challenge1 challenge2)` | Derive the §9.5.3 KxKey; returns a `kx-key-handle` (foreign buffer). challenge1 = initiator nonce, challenge2 = responder nonce. |
| `derive-kx-salt (shared-secret challenge1 challenge2)` | Derive the §9.5.3 KxSalt; same signature. Challenge inputs are SWAPPED between KxKey and KxSalt by spec design. |
| `kx-key-bytes (handle)` | Return the 32-byte foreign-backed buffer; do not retain past `free-kx-key`. |
| `free-kx-key (handle)` | Zeroize and free the foreign buffer. Idempotent; NIL is a no-op. Every handle from `derive-kx-key`/`derive-kx-salt` must be freed here. |
| `+kxkey-label+` | ASCII `"key exchange key"` (16 bytes, §9.5.3, hex `6b65792065786368616e6765206b6579`). |
| `+kxsalt-label+` | ASCII `"keyexchange salt"` (16 bytes, §9.5.3, hex `6b657965786368616e67652073616c74`). |

KDF construction (§9.5.3; two-step HMAC-SHA256, no HKDF; pinned from the T0 spike §2.4 /
Fast DDS corroboration):

```
KxKey = HMAC-SHA256(key = SHA-256(challenge_2 || "+kxkey-label+" || challenge_1),
                    data = shared_secret)
KxSalt = HMAC-SHA256(key = SHA-256(challenge_1 || "+kxsalt-label+" || challenge_2),
                     data = shared_secret)
```

All inputs are 32-byte vectors.  Both functions signal `secured-payload-malformed` on
wrong-length inputs (fail-closed, NFR-SEC-POSTURE).

### 6quarter.2 The §9.5.2 KeyMaterial + CryptoToken API (`dds.security`)

| Symbol | Contract |
|---|---|
| `generate-writer-key-material (writer-guid)` | Generate a fresh §9.5.2 AES256-GCM `key-material` for the 16-octet `writer-guid` (random master-salt + master-sender-key via `dds.dare:random-bytes`; sender-key-id derived from GUID bytes 0–3). |
| `serialize-crypto-token (km kx-key)` | Serialize `km` as a KxKey-AEAD-wrapped CDR-LE `DataHolder` blob: nonce(12) ∥ AES256-GCM-seal(88-byte KeyMaterial CDR, key=kx-key) ∥ tag(16) = 116 bytes. Fail-closed on AEAD error. |
| `parse-crypto-token (octets kx-key)` | Parse + authenticate a KxKey-wrapped `DataHolder` blob → `key-material` or `NIL` (fail-closed on wrong key, tamper, malformed input). |
| `make-crypto-token-message (km kx-key src-guid dest-guid)` | Build a §7.4.4 `ParticipantGenericMessage` carrying one `CryptoToken` DataHolder (class_id `"dds.sec.participant_crypto_tokens"`). |
| `parse-crypto-token-message (octets kx-key)` | Parse a `ParticipantGenericMessage` + unwrap the single CryptoToken → `key-material` or `NIL`. Enforces exactly-1-DataHolder cap (spike §6.3). |
| `+participant-crypto-tokens-class-id+` | `"dds.sec.participant_crypto_tokens"` (§7.4.4; spike §7). |
| `+crypto-token-class-id+` | `"DDS:Crypto:AES_GCM_GMAC"` (§9.5; spike §7). |
| `+crypto-keymat-prop-name+` | `"dds.cryp.keymat"` (§9.5; spike §7). |

### 6quarter.3 The `crypto-keys` per-writer resolver (`dds.security`)

`crypto-keys` is a `defstruct*` (§9.5.3.3.4 encode/decode direction, T6):

| Symbol | Contract |
|---|---|
| `make-crypto-keys :encode-key-fn F :decode-key-fn G` | Construct a per-writer key resolver. Both functions are required (error default). |
| `crypto-keys-encode-key-fn (ck)` | The encode closure: `(local-writer-guid) -> (or key-material null)` — resolves the local writer's KeyMaterial for outgoing samples. |
| `crypto-keys-decode-key-fn (ck)` | The decode closure: `(remote-writer-guid) -> (or key-material null)` — resolves the remote writer's KeyMaterial for incoming samples. |

Both closures return `NIL` when no key is installed; callers are fail-closed (sample
dropped, no plaintext on the secured path).  The resolver is installed on
`disc-node-crypto-transform` BEFORE `resume-parked-matches` fires.

### 6quarter.4 The `select-suite-for-identities` encapsulation (`dds.security`)

```lisp
(select-suite-for-identities local-identity remote-id-token-octets)
  ;; -> auth-suite | nil
  ;; Derive both cert kinds from the dds.cert.algo property of the local identity and
  ;; the remote IdentityToken octets via %cert-algo->kind, then call select-auth-suite.
  ;; Returns NIL — meaning REJECT the remote — when either algo is unsupported or the
  ;; cert kinds yield no common suite.
```

This keeps the `nil`-handling co-located with `%cert-algo->kind`, so the manager never
passes `nil` to `select-auth-suite` (whose ftype constrains both arguments to
`(member :ec :rsa)` per §9.3.2).

### 6quarter.5 New `disc-node` security extension slots (`dds.disc`)

| Exported accessor | Slot type | Contract |
|---|---|---|
| `disc-node-on-participant-discovered` | `(or null function)` | Called `(node prefix spdp)` outside the node lock on the first SPDP arrival from a security-capable (IdentityToken-carrying) remote (DDS-Security 1.1 §7.3.4). NIL = ignored. |
| `disc-node-auth-gate` | `(or null function)` | Called `(node remote local)` as the second sequential gate after the type-gate in `%match-remote-endpoint`; returns `:compatible` / `:incompatible` / `:pending` (§7.3). NIL = security off → `:compatible`. |
| `disc-node-auth-state` | `hash-table` (EQUALP) | Manager-owned per-participant auth state table; keyed by 12-octet GUID prefix → opaque `auth-remote` record (DDS-Security 1.1 §7.3). |

### 6quarter.6 `%install-auth-manager` (`dds.dcps`)

```lisp
(%install-auth-manager p identity-handle)
  ;; -> domain-participant
  ;; Create P's DDS-Security §8.7 auth-manager state (holding IDENTITY-HANDLE — the local
  ;; identity with the private key) and install its three hooks on P's disc-node:
  ;; ON-PARTICIPANT-DISCOVERED, ON-STATELESS-MESSAGE, and AUTH-GATE.
  ;; Called by create-participant :identity; not normally called directly.
```

### 6quarter.7 A worked end-to-end example — authenticated encrypted pub/sub

```lisp
(let* ((ca-oct   (map '(simple-array (unsigned-byte 8) (*)) #'char-code
                      (uiop:read-file-string
                       "interop/security-auth/pki/ca/ca-cert.pem")))
       (cert-a-oct (map '(simple-array (unsigned-byte 8) (*)) #'char-code
                        (uiop:read-file-string
                         "interop/security-auth/pki/participant_ec/identity_cert.pem")))
       (key-a-oct  (map '(simple-array (unsigned-byte 8) (*)) #'char-code
                        (uiop:read-file-string
                         "interop/security-auth/pki/participant_ec/identity_key.pem")))
       (cert-b-oct (map '(simple-array (unsigned-byte 8) (*)) #'char-code
                        (uiop:read-file-string
                         "interop/security-auth/pki/participant_ec_b/identity_cert.pem")))
       (key-b-oct  (map '(simple-array (unsigned-byte 8) (*)) #'char-code
                        (uiop:read-file-string
                         "interop/security-auth/pki/participant_ec_b/identity_key.pem"))))

  ;; 1. Load and validate local identities
  (multiple-value-bind (id-a err-a)
      (dds.security:validate-local-identity ca-oct cert-a-oct key-a-oct
        (make-array 16 :element-type '(unsigned-byte 8)
                       :initial-contents '(1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16)))
    (assert id-a () (format nil "id-a: ~a" err-a))
    (multiple-value-bind (id-b err-b)
        (dds.security:validate-local-identity ca-oct cert-b-oct key-b-oct
          (make-array 16 :element-type '(unsigned-byte 8)
                         :initial-contents '(200 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16)))
      (assert id-b () (format nil "id-b: ~a" err-b))

      ;; 2. Create security-enabled participants.
      ;;    create-participant :identity sets the SPDP IdentityToken + installs the auth manager.
      (let ((p-a (dds.dcps:create-participant :domain 99 :identity id-a))
            (p-b (dds.dcps:create-participant :domain 99 :identity id-b)))

        ;; 3. Wire peers, announce topics + types.
        ;;    The auth manager fires automatically on SPDP discovery:
        ;;      on-participant-discovered -> handshake -> SharedSecret -> KxKey ->
        ;;      generate-writer-key-material -> serialize-crypto-token -> PSM send ->
        ;;      parse-crypto-token-message on the peer -> install remote-km -> :keyed ->
        ;;      resume-parked-matches -> endpoint match.
        (dds.disc:add-peer (dp-node p-a) "127.0.0.1")
        (dds.disc:add-peer (dp-node p-b) "127.0.0.1")

        ;; 4. Wait for both to reach :keyed.
        ;;    The auth gate parks any endpoint match until :keyed; resume fires automatically.
        (let ((keyed nil))
          (dotimes (i 300)
            (let ((ms-a (dp-auth-state p-a)))
              (when (and ms-a
                         (some (lambda (ar)
                                 (eq (dds.dcps::auth-remote-state ar) :keyed))
                               (alexandria:hash-table-values
                                (dds.disc:disc-node-auth-state (dp-node p-a)))))
                (setf keyed t)
                (return)))
            (sleep 0.02))
          (assert keyed () "participants did not reach :keyed within 6s"))

        ;; 5. Publish known plaintext from A; B receives it decrypted.
        ;;    The crypto-transform slot is now a crypto-keys resolver (not make-test-key-material).
        ;;    A's publish-sample: encode-key-fn(A-writer-guid) -> km -> encode-serialized-payload.
        ;;    B's %deliver-user-sample: decode-key-fn(A-writer-guid) -> km -> decode-serialized-payload.
        (let ((plaintext #(#x4b #x45 #x59 #x58 #x44 #x41 #x54 #x41))) ; "KEYXDATA"
          (dds.disc:publish-sample (dp-node p-a) plaintext)
          ;; ... poll for receipt on p-b, then assert received = plaintext ...
          )

        ;; 6. Cleanup.
        (dds.dcps:delete-participant p-a)
        (dds.dcps:delete-participant p-b)))))
```

See `run-auth-encrypted-pubsub-keyx-test` in `src/dds-tests/security-auth-test.lisp` for
the full working test, including the ciphertext-on-wire assertions (plaintext absent,
header bytes `#(0 0 0 4)` = AES256-GCM `transformation_kind` per §9.5.3.3.1 Table 69).

### 6quarter.8 The honest interop posture (complete picture, ADR 0034)

| Item | Status |
|---|---|
| Our-to-our: auth → key exchange → strict gate → encrypted DATA | **ACHIEVED** (337 tests Clasp + SBCL) |
| Don't-break-plain (byte-identical plain path) | **ACHIEVED** (`run-auth-plain-byte-identical-test`) |
| Strict refusal of unauthenticated peers | **ACHIEVED** (`run-auth-secured-refuses-plain-test`) |
| KxKey-AEAD wrap nonce/AAD vs Connext | **NEEDS-VERIFICATION** (Slice 5) |
| §9.5.2 KeyMaterial CDR framing vs Connext | **NEEDS-VERIFICATION** (Slice 5) |
| KeyMaterial master-key/salt in foreign buffers | **HARDENING-GAP** (control-plane; follow-on) |
| Reliable `ParticipantVolatileMessageSecure` endpoint | **DEFERRED** (Slice 5) |
| RTPS/submessage protection | **DEFERRED** (later slice) |
| Live Connext-Security interop | **DEFERRED** (Slice 5 = the P6 exit gate) |

See ADR 0034 (`docs/adr/0034-dds-security-auth-keyx.md`) for the full analysis.

---

## 7. Roadmap (M7/P6)

| Slice | Description | Status |
|---|---|---|
| **1** | Crypto plugin: AES256-GCM `SecuredPayload` + session-key KDF + `disc-node` integration (ADR 0031) | **LANDED** |
| **2a** | Authentication plugin: PKI identity + §8.7.2.4 PKI-DH handshake → SharedSecret, both §9.3 suites, our-to-our (ADR 0032) | **LANDED** |
| **2b-i** | Wire transport: SPDP IdentityToken + PSM endpoints + DataHolder/envelope codec + our-to-our handshake over UDP (ADR 0033) | **LANDED** |
| **2b-ii** | Discovery integration: on-participant-discovered hook + auth manager (`%install-auth-manager`) + per-participant `dp-auth-state` + strict endpoint-match auth-gate + `select-suite-for-identities` (ADR 0034 at capstone) | **LANDED** |
| **2c** | Crypto key-exchange: §9.5.3 KxKey + §9.5.2 per-writer KeyMaterial exchanged over PSM, installed per remote (ADR 0034 at capstone) | **LANDED** |
| 3 | AccessControl plugin (§8.8): governance/permissions XML, topic-level policy enforcement | pending |
| 4 | Secure discovery (§7.4.4): SPDP/SEDP participant/endpoint authentication | pending |
| 5 | Connext-Security live interop: live cross-vendor PKI-DH auth interop (the P6 exit gate) | pending |
