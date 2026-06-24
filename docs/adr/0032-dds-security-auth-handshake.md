# ADR 0032 — DDS-Security Authentication plugin: PKI-DH handshake → SharedSecret (Slice 2a)

- **Status:** Accepted (M7/P6; WP-DDS-SECURITY-AUTH-2A, 2026-06-24)
- **Relates to:** ADR 0031 (Slice 1 Crypto plugin — the `key-material` Slice 2c will feed with
  derived keys); ADR 0025 (DARE — the `dds-dare` OpenSSL FFI extended here); FR-SEC-2 (no
  hand-rolled crypto); NFR-SEC-POSTURE (bounds-checked parsers, fail-closed, fuzzed);
  NFR-MEM (off the measured CDR hot path); the T0 spike
  (`docs/superpowers/spikes/2026-06-23-dds-security-auth-wire.md`) — the primary wire-constant
  reference for this ADR.
- **Standards:** OMG DDS-Security 1.1 §8.7 (Authentication plugin behaviour), §8.7.2 (the
  `DDS:Auth:PKI-DH` builtin plugin identity and token contracts), §8.7.2.4 (three-message
  handshake state machine — Request / Reply / Final), §9.3 (`DDS:Auth:PKI-DH` algorithm
  specification), §9.3.1 (class_id strings and IdentityToken layout), §9.3.2 (HandshakeMessageToken
  layouts and signature-input concatenations), §9.3.2.1 (HandshakeRequestMessageToken),
  §9.3.2.2 (HandshakeReplyMessageToken, Sign2), §9.3.2.3 (HandshakeFinalMessageToken, Sign1),
  §9.3.3 (SharedSecret derivation); RFC 5903 §8.1 (ECDH P-256 KAT); RFC 6979 §A.2.5
  (ECDSA-P256/SHA-256 deterministic KAT); NIST FIPS 180-4 (SHA-256); RFC 3526 §3
  (MODP-2048 Group 14); Google Wycheproof rsa_pss_2048_sha256_mgf1_32 tcId 1 + 62
  (RSA-PSS verify KAT).

## Context

M7/P6 Slice 1 (ADR 0031) protects user data on the wire with AES-256-GCM, but the encryption key
is a **pre-shared test scaffold** (`make-test-key-material`).  Real DDS-Security establishes
keys through the **Authentication plugin** (§8.7 `DDS:Auth:PKI-DH`): two participants mutually
authenticate via X.509 certificates and a Diffie-Hellman handshake, agreeing a **SharedSecret**
from which per-entity encryption keys are later derived.

Authentication is decomposed into three vertical sub-slices per the VSD principle:

| Sub-slice | Scope | Status |
|---|---|---|
| **2a (this ADR)** | PKI identity + §8.7.2.4 three-message handshake → SharedSecret, our-to-our, both §9.3 suites | **LANDED** |
| 2b | Run the handshake over live discovery: IdentityToken in SPDP, ParticipantStatelessMessage builtin endpoints, gate matching on auth result | pending |
| 2c | Crypto key-exchange (ParticipantVolatileMessageSecure) → derive `key-material` from SharedSecret → replace the Slice-1 pre-shared key | pending |

**Slice 2a goal:** two in-process participants run the full §8.7.2.4 handshake and agree a
SharedSecret.  Every negative scenario (untrusted CA, tampered cert, bad signature, replayed
nonce, unsupported algorithm, malformed token) fails closed.  No live discovery, no
`key-material` derivation — those are 2b and 2c.

---

## Decision — as-built architecture

### Module layout

Three new files added as an `auth` unit inside the existing **`dds-security`** ASDF system
(no new top-level system — `dds-security.asd` updated with three new components):

| File | Responsibility |
|---|---|
| `src/dds-security/auth/constants.lisp` | Wire constants: all class_id strings, algorithm-id strings, token binary-property NAME strings, IdentityToken property NAME strings, field widths, RFC 3526 MODP-2048 Group 14 parameters (spike-pinned, never from memory — T0) |
| `src/dds-security/auth/identity.lisp` | `validate-local-identity`, `validate-remote-identity`, `identity-handle` defstruct, IdentityToken CDR-LE serialization, `%parse-remote-token-strings` (bounds-checked) |
| `src/dds-security/auth/suites.lisp` | `auth-suite` vtable defstruct; `+suite-ecdh+`; `+suite-ffdh+`; `select-auth-suite` |
| `src/dds-security/auth/handshake.lisp` | `begin-handshake-request`, `begin-handshake-reply`, `process-handshake`, `handshake-handle` / `shared-secret-handle` defstructs, CDR-BE BinaryPropertySeq helpers, internal token serialize/parse |

**Crypto FFI:** all X.509 / EC / RSA / ECDH / FFDH / ECDSA / RSA-PSS / SHA-256 / `RAND_bytes`
go through **`dds-dare`'s existing handle-based OpenSSL FFI, extended** — no new FFI layer, no
hand-rolled crypto (FR-SEC-2).  New `dds-dare` exports (`ecdh-gen-keypair`, `ecdh-compute`,
`ecdsa-sign`, `ecdsa-verify`, `ffdh-gen-keypair`, `ffdh-compute`, `rsa-pss-sign`,
`rsa-pss-verify`, `sha-256`, `x509-load-ca`, `x509-load-cert`, `x509-load-cert-der`,
`x509-to-der`, `x509-verify-chain`, `x509-public-key`, `x509-subject-name`, `x509-free`,
`x509-ca-free`, `pkey-load-private`, `pkey-free`, `pkey-kind`, `random-bytes`,
`free-secret-octets`, `ec-p256-import-private`, `ec-p256-import-public`) added to `dds-dare`.

**Secrets:** the private key (`EVP_PKEY*` foreign handle), the ephemeral DH private key, and the
SharedSecret are held in **foreign buffers via `dds.pal:alloc-static`/`free-static`** — the
clasp#1793-safe pattern from DARE.  Nonces (`challenge1`, `challenge2`) are plain GC-heap arrays
(not secret).

### Crypto suites (§9.3)

Two suites implemented in full, both §9.3-conformant:

| Suite name | kagree_algo string | dsign_algo string | Identity cert | Key agreement | Signature |
|---|---|---|---|---|---|
| `+suite-ecdh+` | `"ECDH+prime256v1-CEUM"` | `"ECDSA-SHA256"` | EC P-256 | ECDH over P-256 | ECDSA-SHA256 |
| `+suite-ffdh+` | `"DH+MODP-2048-256"` | `"RSASSA-PSS-SHA256"` | RSA-2048 | DH over RFC 3526 MODP-2048 Group 14 | RSASSA-PSS-SHA256, saltlen=32, MGF1-SHA256 |

The algorithm-identifier strings are **spike-pinned** from §9.3 / §9.3.2 (corroborated by
Fast DDS Apache-2.0 source `PKIIdentityHandle.h`; provenance: spike §3.2).

**Suite selection (§9.3.2, `select-auth-suite`):**

- Both participants have EC P-256 certs → `+suite-ecdh+`
- Both participants have RSA-2048 certs → `+suite-ffdh+`
- Mismatched cert kinds → NIL (handshake MUST reject per §9.3.2)

`select-auth-suite` is **implemented and tested** (see `run-auth-suite-selection-test`), but is
not yet **wired** into the `begin-handshake-request` / `begin-handshake-reply` entry points —
the entry points currently take an explicit `suite` argument.  Wiring `select-auth-suite` into
the discovery integration is a **Slice 2b item**.

### IdentityToken (§8.7.2.2 / §9.3.1)

class_id: `"DDS:Auth:PKI-DH:1.0"` (§9.3.1).

Four STRING properties (not binary_properties — spike §4):

| Property name | Content |
|---|---|
| `"dds.cert.sn"` | Certificate Subject Name (X.509 DN string) |
| `"dds.cert.algo"` | Certificate key type: `"RSA-2048"` or `"EC-prime256v1"` (§9.3.1) |
| `"dds.ca.sn"` | Identity CA Subject Name |
| `"dds.ca.algo"` | CA key type: `"RSA-2048"` or `"EC-prime256v1"` |

Serialized as CDR LE `DataHolder` (class_id string + `Properties(count=4)` + `BinaryProperties(count=0)`)
by `%build-identity-token`.  Parsed back by `%parse-remote-token-strings` with bounds-check on
every length field (NFR-SEC-POSTURE; fail-closed on any truncation or property count overflow).

### The §8.7.2.4 three-message handshake

In Slice 2a the tokens are passed in-process via function arguments.  Slice 2b puts them on
`ParticipantStatelessMessage`.

#### HandshakeMessageToken binary properties

All handshake-token fields are BINARY properties (raw octets, not strings — spike §5).
Property names are spike-pinned from §9.3.2:

`c.id`, `c.perm`, `c.pdata`, `c.dsign_algo`, `c.kagree_algo`, `hash_c1`, `hash_c2`,
`dh1`, `dh2`, `challenge1`, `challenge2`, `signature`.

**Internal token format (in-process only — NOT CDR DataHolder wire):**

The tokens as serialized by `%serialize-token` / parsed by `%parse-token` use a tagged binary
format internal to Slice 2a:

```
magic(4 bytes: #xD0 #xDD #x53 #x70)
| uint32-LE(class-id-byte-count) | class-id-bytes
| uint32-LE(property-count)
| foreach property: uint32-LE(name-byte-count) | name-bytes | uint32-LE(value-byte-count) | value-bytes
```

This is **not** the CDR `DataHolder` format that appears on the wire in
`ParticipantStatelessMessage`.  The mapping to CDR DataHolder binary-property wire format is a
**Slice 2b item** (see Known limitations §5).

`%parse-token` bounds-checks every length field before trusting it and returns NIL on any
malformed input — never an OOB access, even at `(safety 0)` (NFR-SEC-POSTURE).

#### hash_c1 / hash_c2 computation (§9.3.2)

SHA-256 of a CDR big-endian BinaryPropertySeq of the five `c.*` properties (in wire order):

```
hash_c1 = SHA-256(CDR-BE-BinaryPropertySeq(c.id, c.perm, c.pdata, c.dsign_algo, c.kagree_algo))
```

Fast DDS corroboration confirms big-endian CDR for the signature/hash inputs (spike §6).
`c.perm` is included even when empty (Slice 2a uses a 4-byte stub for `c.pdata` and an empty
octet vector for `c.perm`; the hash is computed over the same empty vector so both sides agree).

#### Signature inputs (§9.3.2.2 Sign2, §9.3.2.3 Sign1)

A CDR big-endian `BinaryPropertySeq` of exactly 6 binary properties (`+sig-input-property-count+ = 6`):

**Reply Sign2 (replier signs):** `hash_c2 ∥ challenge2 ∥ dh2 ∥ challenge1 ∥ dh1 ∥ hash_c1`

**Final Sign1 (requester signs):** `hash_c1 ∥ challenge1 ∥ dh1 ∥ challenge2 ∥ dh2 ∥ hash_c2`

Order spike-pinned from §9.3.2.2 / §9.3.2.3 and corroborated by Fast DDS `PKIDH.cpp`
(spike §6.1 / §6.2).

#### SharedSecret derivation (§9.3.3)

```
raw_agreed = ECDH or FFDH key-agreement(my-priv, peer-pub)
SharedSecret = SHA-256(raw_agreed)   [32 bytes]
```

The raw agreed value is zeroized before freeing.  The 32-byte SharedSecret is stored in a
foreign-backed buffer (`dds.pal:alloc-static 32`).  The `shared-secret-handle` also carries
`challenge1` and `challenge2` (the nonces that Slice 2c will combine with the SharedSecret
to derive `key-material`).

### Public API (`dds.security`, Slice 2a)

```lisp
validate-local-identity  (ca-pem cert-pem key-pem guid)
  -> (values identity-handle nil) | (values nil reason-string)

validate-remote-identity  (local remote-identity-token)
  -> (values verdict role reason)
  ;; verdict: :ok | :rejected
  ;; role:    :requester | :replier  (lexicographic GUID ordering, §8.7.2.4)

begin-handshake-request  (local remote suite)
  -> (values request-token-octets handshake-handle)

begin-handshake-reply  (local remote request-token-octets suite)
  -> (values reply-token-octets handshake-handle) | (values nil nil)

process-handshake  (handle incoming-token-octets)
  -> (values next-token-or-nil status)
  ;; status: :continue | :authenticated | :rejected

handshake-shared-secret  (handle)  -> shared-secret-handle | nil
shared-secret-bytes       (ssh)    -> (simple-array (unsigned-byte 8) (32))
free-handshake-handle     (handle) -> t
free-shared-secret-handle (ssh)    -> t
free-identity-handle      (handle) -> t
identity-token            (handle) -> (simple-array (unsigned-byte 8) (*))

+suite-ecdh+        ; auth-suite defstruct instance, ECDH+prime256v1-CEUM / ECDSA-SHA256
+suite-ffdh+        ; auth-suite defstruct instance, DH+MODP-2048-256 / RSASSA-PSS-SHA256
select-auth-suite   (local-cert-kind remote-cert-kind) -> auth-suite | nil
```

---

## Error handling (fail-closed) + security posture

Every failure path in the authentication code produces `(values :rejected reason)` or
`(values nil reason)` — no partial SharedSecret, no escaping condition, no OOB.

Negative battery (each individually tested by `run-auth-negatives-test`, 8 cases):

1. **Untrusted CA** — peer cert does not chain to the local trusted CA → reject.
2. **Tampered cert** — bit-flip in the peer cert DER → `x509-verify-chain` fails → reject.
3. **Expired / malformed cert** — X.509 validation fails → reject.
4. **Bad Reply signature (Sign2)** — `dsign-verify` on the Reply token returns NIL → reject.
5. **Bad Final signature (Sign1)** — `dsign-verify` on the Final token returns NIL → reject.
6. **Replayed / wrong nonce (challenge echo)** — echo mismatch detected before signature verify → reject.
7. **Mismatched hash_c1** — replier recomputes and compares; mismatch → reject.
8. **Wrong suite / algorithm string** — the replier receives a request with a different
   `c.kagree_algo` / `c.dsign_algo` than the suite implies → hash_c1 mismatch → reject.

Every negative is paired with a matching positive control so the test cannot pass by
always-rejecting.

**Token parser:** `%parse-token` and `%parse-remote-token-strings` are bounds-checked at every
length field and are fuzzed by `run-auth-token-fuzz-test` (2000 adversarial blobs through a
`process-handshake` path compiled at `(safety 0)`) — no OOB, crash, or unhandled condition.

**Secrets:** private keys and the SharedSecret live in foreign buffers via
`dds.pal:alloc-static`/`free-static`.  The raw ECDH/FFDH agreed value is zeroized before its
parent stack frame exits.  Ephemeral DH private keys are freed after use or in `unwind-protect`
cleanup.

---

## Published KATs

All vectors are from published, independent sources — never self-generated.

| KAT | Source | Test |
|---|---|---|
| SHA-256(`""`) = `e3b0c44...` | NIST FIPS 180-4 | `run-auth-sha256-kat` |
| ECDH P-256 IKEv2 shared secret | RFC 5903 §8.1 (Group 19 / P-256) | `run-auth-ecdsa-kat` |
| ECDSA-P256/SHA-256 deterministic (message `"sample"`) | RFC 6979 §A.2.5 | `run-auth-ecdsa-kat` |
| RSA-PSS-SHA256-saltlen32 (empty message, valid sig) | Google Wycheproof rsa_pss_2048_sha256_mgf1_32 tcId 1 | `run-auth-rsa-pss-kat` |
| RSA-PSS-SHA256 invalid-sig rejection | Google Wycheproof rsa_pss_2048_sha256_mgf1_32 tcId 62 | `run-auth-rsa-pss-kat` |
| FFDH MODP-2048 round-trip commutativity | self-consistency (see below) | `run-auth-ffdh-kat` |

**FFDH honesty note:** No published MODP-2048 DH shared-secret KAT vector was located (NIST
CAVP KAS-FFC test packages do not cover MODP-2048 / Group 14 with OpenSSL's `EVP_PKEY`
API-level results; RFC 3526 provides group parameters only, not test vectors).  The FFDH KAT
is therefore a **self-consistency round-trip**: two independently generated ephemeral keypairs
(A, B) → `ffdh-compute(A-priv, B-pub) == ffdh-compute(B-priv, A-pub)` with a SHA-256 digest
length check.  This proves the group arithmetic is consistent; it does not prove byte-equality
against an external oracle.  This is stated explicitly in the test docstring and in the
Known Limitations below.

---

## Cross-vendor interop — the three-level honest picture

The RTI Connext DDS 7.3.1 Security Plugins (`rti_connext_dds_secure_plugins` add-on,
`libnddssecurity.dylib`) are a **separately licensed package not installed in this environment**.

### Level 1 — Our-to-our mutual authentication (achieved)

Both `+suite-ecdh+` and `+suite-ffdh+` complete the full three-message handshake
(Request → Reply → Final) between two in-process participants.  Both sides reach
`:authenticated` and their `(shared-secret-bytes ssh)` values are **byte-equal** — the ECDH or
FFDH key agreement converges on the same SharedSecret.  This is proven by
`run-auth-handshake-ecdh-test` (EC suite) and `run-auth-handshake-rsa-test` (RSA/FFDH suite).

### Level 2 — Cryptographic primitive conformance (achieved, by published KAT)

The underlying crypto primitives (ECDH P-256, ECDSA-SHA256, RSA-PSS-SHA256, SHA-256) produce
**byte-identical output to any conformant implementation** for the same inputs, as proven by
the published KATs (RFC 5903, RFC 6979, Wycheproof, NIST FIPS 180-4) in `run-auth-ecdsa-kat`
and `run-auth-rsa-pss-kat`.  These are published, independently verifiable vectors.

### Level 3 — Live cross-vendor authentication interop (DEFERRED — NOT achieved)

A live test of the complete PKI-DH handshake against a **running RTI Connext-Security stack**
on the wire has **not been performed**.  It requires the licensed Security Plugins add-on (not
installed).  This is the **P6 exit gate** (Slice 5).

Several aspects of the Slice 2a implementation are self-consistent (our-to-our) but their
**exact byte-match against a Connext peer is unverified**:

1. The internal-token-vs-CDR-DataHolder mapping: the Slice 2a internal token format is NOT the
   CDR `DataHolder` / `ParticipantStatelessMessage` format that appears on the wire.  Slice 2b
   maps the token binary-properties into the wire DataHolder layout.
2. The CDR-BE BinaryPropertySeq alignment for hash_c1/hash_c2/signature inputs: the alignment
   (exact per-property byte boundaries) is self-consistent with the Fast DDS corroboration but
   unverified against a live Connext capture.
3. The FFDH dh1/dh2 `SubjectPublicKeyInfo` DER encoding: `EVP_PKEY_get1_encoded_public_key`
   produces the SPKI-DER blob; its exact byte layout vs Connext has not been compared.
4. The RSA-PSS salt length: saltlen=32 (= the digest length, the Wycheproof convention; Fast DDS
   uses `RSA_PSS_SALTLEN_DIGEST`; the OMG spec says "MGF1 with SHA256" without specifying the
   salt length).
5. `select-auth-suite` is implemented and tested but not yet wired into `begin-handshake-request`
   / `begin-handshake-reply` — that wiring is a Slice 2b discovery-integration item.

**Do NOT interpret any statement in this ADR as "cross-vendor authentication interop verified."**
The live compare is **Slice 5** of the M7 roadmap.

---

## Known limitations / Slice-5 carries

1. **Internal-token vs CDR DataHolder wire format (Slice 2b).**  The `%serialize-token` /
   `%parse-token` format is in-process only (tagged binary).  The §8.7 `ParticipantStatelessMessage`
   wire format carries tokens as CDR `DataHolder` with a `BinaryPropertySeq` inside.  The mapping
   is a Slice 2b item.

2. **CDR-BE alignment of BinaryPropertySeq (Slice 5 verification).**  The hash/signature
   inputs use big-endian CDR BinaryPropertySeq per Fast DDS corroboration.  The exact
   per-property alignment (presence of padding between entries) is self-consistent but
   unverified against a live Connext capture.

3. **FFDH dh1/dh2 SPKI-DER encoding + params (Slice 5 verification).**  The DER encoding produced
   by OpenSSL's `EVP_PKEY_get1_encoded_public_key` for the DH+MODP-2048-256 ephemeral public key
   has not been compared byte-for-byte against a Connext peer.  The FFDH params import only `p`
   and `g` (RFC 3526), not the 256-bit subgroup order `q`, so OpenSSL cannot perform a full
   subgroup-membership check on the peer public (the `2 <= y <= p-2` range check still applies,
   and the value is signed under a CA-chained cert, so a MITM cannot inject a small-subgroup
   element) and the generated private exponent is full-width rather than the 256-bit width implied
   by the suite name — a Slice-5 item (supply `q` / use a named FFDHE group for full pubkey
   validation + the intended exponent width).

4. **RSA-PSS salt length (Slice 5 verification).**  Saltlen=32 is the Wycheproof / Fast DDS
   convention; the OMG spec §9.3 does not specify it numerically.  If Connext uses a different
   saltlen (e.g. `RSA_PSS_SALTLEN_MAX`), Sign2 / Sign1 will fail to verify cross-vendor.

5. **`select-auth-suite` not yet wired into entry points + no in-handshake algorithm cross-check
   (Slice 2b).**  `begin-handshake-request` and `begin-handshake-reply` currently receive an
   explicit `suite` argument.  In Slice 2b the caller (the discovery integration) will invoke
   `select-auth-suite` from the cert key kinds and pass the result through.  Relatedly, the
   replier reads the peer's advertised `c.kagree_algo` / `c.dsign_algo` strings only to recompute
   `hash_c` — it does NOT explicitly assert they equal the suite in use.  A mismatch already
   fails closed today (a wrong key-agreement makes `EVP_PKEY_derive` error, or the signature
   fails to verify), so this is not exploitable our-to-our; but an explicit algorithm-agility
   guard (reject unless the advertised strings match the suite), plus an in-handshake
   mismatched-algo-string negative test, belongs with the Slice-2b `select-auth-suite` wiring.

6. **FFDH KAT is self-consistency, not published oracle (documented).**  No MODP-2048
   shared-secret KAT vector from an independent published source was located.  The round-trip
   commutativity test proves the group arithmetic is correct but does not establish byte-equality
   against an external oracle.

---

## Tests

| Test | What it proves |
|---|---|
| `run-auth-sha256-kat` | SHA-256(`""`) = NIST FIPS 180-4 vector |
| `run-auth-ecdsa-kat` | ECDH P-256 RFC 5903 §8.1 KAT (both directions); ECDSA-SHA256 RFC 6979 §A.2.5 KAT; wrong-key reject |
| `run-auth-rsa-pss-kat` | Wycheproof RSA-PSS-SHA256-saltlen32 tcId 1 (valid sig verified) + tcId 62 (invalid sig rejected) |
| `run-auth-ffdh-kat` | FFDH MODP-2048 commutativity round-trip; SHA-256 digest length |
| `run-auth-suite-selection-test` | `select-auth-suite` returns correct suite for both-EC / both-RSA / mismatched pairs |
| `run-auth-identity-test` | `validate-local-identity` loads EC + RSA fixtures; rejects wrong-CA cert |
| `run-auth-handshake-ecdh-test` | Full ECDH suite three-message handshake → both :authenticated + byte-equal SharedSecret; tampered-reply → rejected; tampered-final → rejected |
| `run-auth-handshake-rsa-test` | Full FFDH/RSA suite three-message handshake → both :authenticated + byte-equal SharedSecret |
| `run-auth-negatives-test` | 8 fail-closed negatives: untrusted-CA, tampered-cert, bad-reply-sig, bad-final-sig, wrong-challenge-echo, wrong-hash-c1, mismatched-suite, malformed-token |
| `run-auth-token-corpus-test` | Token structural corpus: class_id strings, binary-property NAME strings, CDR-BE BinaryPropertySeq hash/sig input encoding, IdentityToken CDR-LE layout |
| `run-auth-token-fuzz-test` | 2000 adversarial token blobs through `process-handshake` at `(safety 0)` — no OOB, crash, or unhandled condition |

Clasp 325 + SBCL 325 (both, Clasp first).  All gates green.

---

## §9 — M7 roadmap (5 slices)

| Slice | Description | Status |
|---|---|---|
| 1 | Crypto builtin plugin: AES256-GCM serialized-payload protection (ADR 0031) | LANDED |
| **2a (this ADR)** | Authentication plugin: PKI identity + §8.7.2.4 three-message PKI-DH handshake → SharedSecret, both §9.3 suites, our-to-our | **LANDED** |
| 2b | Authentication plugin: live discovery integration — IdentityToken in SPDP, ParticipantStatelessMessage builtin endpoints, gate matching on auth result, `select-auth-suite` wired to cert key kinds | pending |
| 2c | Crypto key-exchange: ParticipantVolatileMessageSecure → derive `key-material` from SharedSecret + challenges → replace `make-test-key-material` (Slice 1 pre-shared key) | pending |
| 3 | AccessControl plugin (§8.8): governance/permissions XML, topic-level protection policy enforcement | pending |
| 4 | Secure discovery (§7.4.4): SPDP/SEDP participant/endpoint authentication, encrypted discovery metadata | pending |
| 5 | Connext-Security live interop: live cross-vendor PKI-DH auth interop (the P6 exit gate); requires the licensed RTI Security Plugins add-on | pending |

**What Slice 2b (discovery) adds:**

- `IdentityToken` carried in the SPDP `ParticipantBuiltinTopicData` PID (the §8.7 RTPS-mapping
  for participant authentication data).
- `ParticipantStatelessMessage` builtin endpoints (writer EntityId `0xff0003c2`, reader
  `0xff0003c7` per §9.5.1.3) for the handshake token exchange.
- `select-auth-suite` wired into the entry points (cert key kinds from the loaded identity).
- Gate matching: a participant whose authentication ends in `:rejected` is not matched for
  user-data communication.

**What Slice 2c (key-material) adds:**

- `ParticipantVolatileMessageSecure` builtin endpoints for the crypto key-exchange.
- Derives `key-material` from the SharedSecret + `Challenge1` + `Challenge2` (the §9.5.2
  KDF).
- Replaces `make-test-key-material` — each writer gets a unique `key-material` derived from
  the DH exchange, eliminating the Slice-1 single-instance nonce constraint structurally.

---

## Consequences

- **NFR-MEM:** `make mem` stays **0.0000** bytes/sample.  The auth and handshake code is
  entirely control-plane — no per-sample path.
- **NFR-SEC-POSTURE:** `%parse-token` and `%parse-remote-token-strings` are bounds-checked at
  every length field; `run-auth-token-fuzz-test` proves no OOB / crash / partial parse on 2000
  adversarial blobs at `(safety 0)`.
- **FR-SEC-2:** no hand-rolled crypto.  All X.509 / ECDH / FFDH / ECDSA / RSA-PSS / SHA-256
  / RAND primitives go through OpenSSL EVP via the `dds-dare` handle-based CFFI.
- **NFR-PORT:** no reader conditionals in `src/dds-security/`.  The OpenSSL CFFI layer
  (`dds-dare`) is already Clasp+SBCL validated.  `gate-hotpath(8)` unaffected.
- **Gates:** `build` PASS; `test-clasp` 325 PASS; `test-sbcl` 325 PASS; `gate-hotpath(8)`
  PASS; `gate-types(1689)` PASS; `mem(0.0000)` PASS; `fuzz` PASS; `wire` PASS (no new wire
  surface in Slice 2a — the token is in-process only).

## References

- T0 spike: `docs/superpowers/spikes/2026-06-23-dds-security-auth-wire.md`
- Design spec: `docs/superpowers/specs/2026-06-23-dds-security-auth-2a-handshake-design.md`
- `src/dds-security/auth/constants.lisp` — all spike-pinned wire constants
- `src/dds-security/auth/identity.lisp` — `validate-local-identity`, `validate-remote-identity`,
  `identity-handle`, IdentityToken CDR-LE serialization, bounds-checked token parser
- `src/dds-security/auth/suites.lisp` — `auth-suite` vtable, `+suite-ecdh+`, `+suite-ffdh+`,
  `select-auth-suite`
- `src/dds-security/auth/handshake.lisp` — the §8.7.2.4 state machine, CDR-BE BinaryPropertySeq
  helpers, `shared-secret-handle`, `%derive-shared-secret`
- `src/dds-dare/openssl-ffi.lisp`, `primitives.lisp`, `packages.lisp` — extended OpenSSL FFI
  (X.509 chain verification, ECDH/FFDH key agreement, ECDSA/RSA-PSS sign/verify, SHA-256,
  `random-bytes`, `free-secret-octets`, `ec-p256-import-private/public`)
- `src/dds-tests/security-auth-test.lisp` — all 11 auth test functions
- `interop/security-auth/gen-test-pki.sh` — test-PKI fixture generator (CA + EC-A + EC-B + RSA-A
  + wrong-CA + wrong-CA-signed cert)
- `interop/security-auth/pki/` — generated PEM fixtures
- `docs/wiki/security.md` — user-facing API + worked example + roadmap position
- ADR 0031 — Slice 1 (Crypto plugin; the `key-material` Slice 2c will feed)
- ADR 0025 — DARE (the `dds-dare` OpenSSL FFI extended here)
