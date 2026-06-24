# WP-DDS-SECURITY-AUTH-2A — design (Slice 2a: PKI identity + the PKI-DH handshake → SharedSecret)

- **Status:** Approved (design), 2026-06-23. M7/P6. First sub-slice of Slice 2 (Authentication) of the
  5-slice M7 DDS-Security roadmap (ADR 0031 §9).
- **Relates to:** ADR 0031 (Slice 1 Crypto plugin — the `disc-node crypto-transform` slot + `key-material`
  this Auth work will eventually feed in Slice 2c); the `dds-dare` OpenSSL FFI (extended here); the
  `dds.pal` foreign-buffer arena (secrets).
- **Constraints:** OMG DDS-Security 1.1 §8.7 (Authentication plugin) + §9.3 (`DDS:Auth:PKI-DH`); the
  operating contract (no hand-rolled crypto FR-SEC-2; no wire constants from memory; bounds-check parsers
  even at `(safety 0)` NFR-SEC-POSTURE; `defun*`/`defstruct*` + full ftype; no reader conditionals outside
  `dds-pal/`; Clasp AND SBCL both, Clasp first; no AI/assistant attribution in any repo file).

---

## 1. Problem + goal

M7/P6 Slice 1 (Crypto plugin, ADR 0031) protects user data on the wire with AES-256-GCM, but the key is a
**pre-shared test scaffold** (`make-test-key-material`). Real DDS-Security establishes keys through the
**Authentication plugin** (§8.7 `DDS:Auth:PKI-DH`): two participants mutually authenticate with X.509
certificates and a Diffie-Hellman handshake, agreeing a **SharedSecret** from which per-entity keys are
later derived.

Authentication is large — it spans PKI/identity, the handshake protocol, discovery integration, and the
crypto key-exchange. Per VSD it is split into three vertical sub-slices (owner-confirmed 2026-06-23):

- **2a (this spec)** — PKI identity + the PKI-DH handshake → **SharedSecret**, our-to-our, in isolation.
- **2b** — run the handshake over live discovery (IdentityToken in SPDP, the ParticipantStatelessMessage
  builtin endpoints, gate matching on auth).
- **2c** — crypto key-exchange (ParticipantVolatileMessageSecure) → derive `key-material` from the
  SharedSecret → replace the Slice-1 pre-shared key (end-to-end encrypted pub/sub with no pre-shared key).

**2a goal:** two in-process participants run the full §8.7.2.4 handshake and agree a SharedSecret; every
negative (untrusted CA, tampered cert, bad signature, replayed nonce, unsupported algorithm, malformed
token) **fails closed**. No live discovery, no key-material derivation — those are 2b/2c.

## 2. Scope boundary

**In scope (2a):**
- PKI identity: load + validate the local identity (Identity CA + participant cert + private key);
  validate a remote identity (chain-verify a peer cert to the trusted CA); the IdentityToken.
- The §8.7.2.4 three-message handshake state machine (Request / Reply / Final) → a validated SharedSecret.
- **Both** §9.3 suites: `ECDH+prime256v1-CEUM` (EC certs, ECDSA-SHA256) and `DH+MODP-2048-256`
  (RSA-2048 certs, RSASSA-PSS-SHA256-MGF1), with the §9.3.2 algorithm selection.
- Fail-closed negatives; bounds-checked + fuzzed token parsing; published KATs.
- A generated test-PKI fixture (one Identity CA signing one EC + one RSA participant cert).

**Out of scope (deferred):**
- Live discovery / the ParticipantStatelessMessage builtin endpoints / IdentityToken-in-SPDP → **2b**.
- Deriving `key-material` from the SharedSecret + ParticipantVolatileMessageSecure crypto key-exchange +
  replacing the pre-shared key → **2c**.
- AccessControl (governance/permissions documents) → Slice 3 (the handshake's permissions field is empty
  in 2a).
- Live RTI Connext-Security authentication interop → **Slice 5** (the licensed Security plugins are not
  installed here; same plugins-not-installed reason as Slice 1's deferred live byte-compare).
- Real identity provisioning / KMS / cert enrolment (2a uses a generated test fixture).

## 3. Crypto suite (classic / interoperable — the PQ tension)

DDS-Security 1.1 `DDS:Auth:PKI-DH` is **classic** crypto. Post-quantum / CNSA-2.0 authentication (ML-DSA
signatures, ML-KEM key-establishment) is **not in the standard** — using it on the handshake (which **is**
wire-visible, unlike DARE's zero-wire at-rest encryption) would break interoperability with RTI Connext
(the Slice-5 goal). 2a therefore implements the **standard classic suites** and stays interoperable; any
PQ-auth is a possible separate overlay later, not part of Slice 2 (owner-confirmed 2026-06-23).

Both §9.3 suites are implemented (owner chose full §9.3 conformance):

| Suite | Key agreement | Identity cert | Signature | Hash |
|---|---|---|---|---|
| ECDH | `ECDH+prime256v1-CEUM` (P-256) | EC P-256 | ECDSA-SHA256 | SHA-256 |
| FFDH | `DH+MODP-2048-256` | RSA-2048 | RSASSA-PSS-SHA256-MGF1 | SHA-256 |

The exact algorithm-identifier **strings**, the RFC 3526 MODP-2048 group parameters, and the §9.3.2
selection rule are **spike-pinned** (T0) from §9.3, never from memory.

## 4. Architecture

A new isolated `auth` unit inside the existing `dds-security` ASDF system (no new system), three focused
files, all **control-plane** (off the measured CDR hot path — `mem` stays 0.0000):

- `src/dds-security/auth/identity.lisp` — PKI: `validate-local-identity` (load CA + cert + key, verify own
  chain), `validate-remote-identity` (chain-verify a peer cert to the trusted CA), the IdentityToken.
- `src/dds-security/auth/handshake.lisp` — the §8.7.2.4 three-message state machine; the
  HandshakeMessageTokens (property + binary-property lists); nonce challenges; the signature over the
  spec's concatenation; → the SharedSecret.
- `src/dds-security/auth/suites.lisp` — the two §9.3 suites behind one internal `auth-suite` vtable
  (`defstruct` of closures), selected per §9.3.2 from the certs' key types.

**Crypto FFI:** all X.509 / EC / RSA / ECDH / FFDH / ECDSA / RSA-PSS / SHA-256 / `RAND_bytes` go through
**`dds-dare`'s existing handle-based OpenSSL FFI, extended** — no new FFI layer, no hand-rolled crypto
(FR-SEC-2). New `dds-dare` exports are added for the X.509 + key-agreement + signature primitives 2a needs.

**Secrets:** private keys, the ephemeral DH private key, and the SharedSecret are held in **foreign buffers
via `dds.pal:alloc-static`/`free-static`** (the clasp#1793-safe pattern established by DARE — secrets never
on a GC heap; `static-vectors` free/make never called directly).

## 5. The handshake protocol (§8.7.2.4)

In 2a the tokens are passed in-process by a test driver; 2b puts them on ParticipantStatelessMessage. Exact
token field-names, the BinaryProperty layout, the algorithm strings, the signature-input concatenation
order, the SharedSecret derivation, and the IdentityToken computation are **spike-pinned (T0)** from
§8.7/§9.3 + offline RTI evidence — never invented.

1. `validate-local-identity` (each side): load CA + own cert + private key; verify own cert chains to the
   CA; compute the IdentityToken.
2. `validate-remote-identity`: compare IdentityTokens; the lexicographically-lower adjusted GUID is the
   **requester**, the other the **replier** (the §8.7.2.4 ordering rule).
3. **Request** (requester→replier) — `HandshakeRequestMessageToken`: requester's cert, its ephemeral DH/ECDH
   public key `dh1`, a 256-bit nonce `challenge1`, the SPDP-data hash. (Permissions field empty — Slice 3.)
4. **Reply** (replier→requester) — `HandshakeReplyMessageToken`: replier's cert, `dh2`, `challenge2`, and a
   **signature** by the replier over the spec's concatenation of the hashes / challenges / DH public keys.
   The requester verifies the replier's cert chains to the CA **and** the signature.
5. **Final** (requester→replier) — `HandshakeFinalMessageToken`: a **signature** by the requester over the
   symmetric concatenation. The replier verifies it.
6. Both compute **SharedSecret** = the ECDH/FFDH agreement of `(dh1, dh2)` → SHA-256 (the spec's exact
   derivation). Mutual authentication holds: each verified the other chains to the trusted CA **and** proved
   private-key possession (the challenge signature), **and** both agree the secret.

**Components (handles — control-plane structs, no CLOS dispatch, no per-sample alloc):**
- `identity-handle` — cert + private key + IdentityToken + the trusted-CA store.
- `handshake-handle` — per-peer state: role, nonces, ephemeral DH keypair, peer cert, phase.
- `auth-suite` — the §9.3 vtable `{kagree-gen, kagree-compute, dsign-sign, dsign-verify, hash}`.
- `shared-secret-handle` — the agreed secret + the challenges (the inputs 2c will turn into `key-material`).

**Public entry points (2a):**
- `(validate-local-identity ca-path cert-path key-path guid) -> identity-handle | (values nil reason)`
- `(validate-remote-identity local remote-identity-token) -> (values verdict role reason)` where `verdict`
  ∈ `{:ok, :rejected}` and `role` ∈ `{:requester, :replier}` (the §8.7.2.4 ordering). It decides whether to
  proceed and the local role from the IdentityTokens; the **peer certificate** arrives later inside the
  Request/Reply token and is chain-verified inside `process-handshake`.
- `(begin-handshake-request local remote) -> request-token`
- `(process-handshake handle incoming-token) -> (values next-token-or-nil status)` where `status` ∈
  `{:continue, :authenticated, :rejected}`; `process-handshake` chain-verifies the peer cert in the token,
  verifies the challenge signature, and on `:authenticated` exposes the `shared-secret-handle`.

## 6. Error handling (fail-closed) + security posture

Every failure → `(values :rejected reason)` (or `(values nil reason)` for identity load) — never a partial
or forged SharedSecret, never an escaping exception. The negative battery (each MUST fail closed):

- **Untrusted CA** — peer cert does not chain to our trusted CA → reject.
- **Tampered / expired / malformed cert** — X.509 validation fails → reject.
- **Bad signature** on Reply/Final — `dsign-verify` fails → reject (no private-key possession proof).
- **Replayed / wrong nonce** — the signature covers the challenges, so a stale/wrong challenge → verify
  fails → reject; nonces are fresh per-handshake from `RAND_bytes`.
- **Unsupported / mismatched algorithm** — §9.3.2 selection fails → reject.
- **Malformed token** — bounds-checked parse (NFR-SEC-POSTURE, even at `(safety 0)`) → reject, never OOB.

**Posture:** the token parser is bounds-checked + fuzzed (mirrors Slice 1's decode). Crypto primitives via
OpenSSL (vetted, constant-time). Secrets in foreign buffers via `dds.pal:alloc-static`/`free-static`.
Nonces + ephemeral keys from the OpenSSL CSPRNG. No hand-rolled crypto.

## 7. Testing / Definition of Done

- **Our-to-our mutual auth** succeeds for **both** suites (ECDH-P256+EC, FFDH-2048+RSA) → byte-equal
  SharedSecret on both ends.
- The **full negative battery** fails closed (untrusted-CA, tampered-cert, bad-sig, replayed-nonce,
  unsupported-algo, malformed-token), with non-vacuous assertions.
- **Token byte-conformance** to the spike-pinned §8.7/§9.3 layout (a corpus test).
- **Token-parser fuzz** at `(safety 0)` — no OOB / crash / signal escape.
- **Published KATs** where they exist (ECDH P-256, ECDSA / RSA-PSS verify, the SHA-256 SharedSecret
  derivation) — independent published vectors, never self-generated (the Slice-1 discipline).
- **Gates green both impls, Clasp first:** `build`, `test-clasp`, `test-sbcl`, `gate-hotpath(8)`,
  `gate-types`, `mem 0.0000` (control-plane), `fuzz`, `wire`.
- **Live Connext-Security auth interop DEFERRED to Slice 5** (plugins not installed); for 2a the cross-DDS
  surface is the **offline token-format conformance** (spike-pinned vs §8.7/§9.3 + RTI evidence). The
  per-feature cross-DDS-interop directive is satisfied at 2b/2c when the handshake reaches the wire — stated
  honestly, no overclaim.

## 8. Global constraints (inherited)

- **No hand-rolled crypto** — all X.509/ECDH/FFDH/ECDSA/RSA-PSS/SHA/RAND via `dds-dare`/OpenSSL (FR-SEC-2).
- **OMG DDS-Security 1.1 conformance** — §8.7 + §9.3; both suites; the token wire format never deviates.
- **No wire constants from memory** — token strings, algorithm ids, MODP group, signature concatenation,
  SharedSecret derivation, IdentityToken computation all **spike-pinned (T0)** with clause citations.
- **Bounds-check the token parser even at `(safety 0)`** — fail-closed, fuzzed (NFR-SEC-POSTURE).
- **Secrets in foreign buffers** via `dds.pal:alloc-static`/`free-static` (clasp#1793-safe); never the GC heap.
- `defun*`/`defstruct*` + full ftype on every function; **no reader conditionals outside `dds-pal/`**;
  **Clasp AND SBCL both, Clasp first**; **no AI/assistant attribution** (cite "the operating contract").
- Control-plane only — `mem` stays 0.0000; `gate-hotpath` unaffected.

## 9. Task decomposition (spike-first, subagent-driven)

- **T0 — spike.** Pin the §8.7/§9.3 constants (token property/binary-property names, algorithm-id strings,
  the RFC 3526 MODP-2048 group, the signature concatenation order, the SharedSecret derivation, the
  IdentityToken computation) from the spec + offline RTI evidence (Connext cert tooling / binary strings);
  generate the test-PKI fixture (CA + EC + RSA via `openssl`) under `interop/security-auth/`. Re-plan
  checkpoint (as in Slice 1, if the live RTI evidence is unavailable, fall back to spec-only + document).
- **T1 — identity.** `identity.lisp` + the `dds-dare` X.509 FFI extensions: `validate-local-identity`,
  `validate-remote-identity` (chain-verify), the IdentityToken. Tests: load the fixture, validate, reject
  a wrong-CA cert.
- **T2 — handshake (ECDH-P256 suite).** `suites.lisp` (EC suite first) + `handshake.lisp` state machine →
  SharedSecret, our-to-our. Tests: our-to-our auth → byte-equal secret; bad-sig + replayed-nonce reject.
- **T3 — second suite.** Add `DH+MODP-2048-256` + RSA-2048 + RSASSA-PSS + the §9.3.2 selection/negotiation.
  Tests: RSA-suite auth; unsupported/mismatched-algo reject.
- **T4 — negatives + conformance.** The full fail-closed battery + the token-format corpus + the parser
  fuzz + the published KATs.
- **T5 — capstone.** ADR 0032 + docs lockstep (`docs/wiki/security.md` Auth section, `README.md`,
  `docs/verification.csv` `P6-SEC-AUTH-HANDSHAKE` row) + final whole-branch review → squash-merge presented
  for owner approval (HOLD PUSH).

## 10. Risks

- **Spike evidence (low-moderate):** the live RTI Connext-Security cert/handshake tooling may be
  unavailable (the plugins are not installed). Mitigation: spec-only pinning + document, exactly as Slice 1
  handled the absent Security plugins; the token format is fully specified in §8.7/§9.3.
- **Two suites (moderate):** full §9.3 doubles the crypto surface (EC + RSA, ECDH + FFDH) and adds the
  §9.3.2 selection. Mitigation: sequence ECDH-P256 first (T2), add FFDH-2048 second (T3) behind the same
  `auth-suite` vtable.
- **OpenSSL FFI breadth (moderate):** X.509 chain verification + EVP key-agreement + EVP sign/verify is a
  larger OpenSSL surface than DARE's AEAD/HMAC. Mitigation: handle-based bindings (the DARE pattern), each
  primitive KAT-checked.

## 11. References

- OMG DDS-Security 1.1 §8.7 (Authentication plugin behaviour, the handshake), §9.3 (`DDS:Auth:PKI-DH`
  algorithms + tokens), §9.3.2 (algorithm selection).
- ADR 0031 (Slice 1; the M7 5-slice roadmap; the `key-material` 2c will feed).
- `src/dds-dare/openssl-ffi.lisp`, `primitives.lisp` — the OpenSSL FFI to extend.
- `src/dds-pal/` — `alloc-static`/`free-static` (foreign-buffer secrets).
- RFC 3526 (MODP-2048 group); RFC 8422 / SEC1 (ECDH P-256); FIPS 186-4 (ECDSA); RFC 8017 (RSASSA-PSS).
