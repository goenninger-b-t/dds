# WP-DDS-SECURITY-CRYPTO-MVP — design

- **Status:** Approved (design), 2026-06-22. **M7 / P6 — DDS-Security Slice 1 of 5** (the gated security milestone).
- **Relates to:** REQUIREMENTS FR-SEC-1 (the five SEC plugins), FR-SEC-2 (vetted crypto only — no hand-rolled),
  FR-RTPS-1 (the security submessages gated to P6), IMPLEMENTATION-PLAN §M7 (P6 exit = Connext-Security
  interop). Builds on `dds-dare` (the already-built AES-GCM/HKDF over OpenSSL, ADR 0025), `dds-rtps` (the
  message/submessage layer), `dds-disc` (the dataplane).
- **Standards:** **OMG DDS-Security 1.1** (formal, 2018) §8.5 (the builtin Crypto plugin interfaces:
  CryptoKeyFactory / CryptoKeyExchange / CryptoTransform), **§9.5.3.3** (the AES-GCM-GMAC builtin Crypto
  plugin: SecureDataHeader / crypto_content / SecureDataTag, session-key derivation, the nonce), **§9.5.2**
  (the KeyMaterial). OMG DDSI-RTPS 2.5 §7.3 (security). All exact wire constants are **pinned from the T0
  spike (a live Connext-Security capture) + the cited spec clause — never from memory.**

---

## 0. Milestone context (the slicing — this is Slice 1 of 5)

DDS-Security 1.1 is the full 5-plugin suite; per the non-negotiable VSD rule it ships as a sequence of
end-to-end slices (each its own spec→plan→build). The agreed roadmap: **Slice 1 (this WP) = Cryptographic
plugin payload protection** · Slice 2 = Authentication (PKI-DH handshake, replaces the test key) · Slice 3 =
Access Control (governance/permissions) · Slice 4 = secure discovery + key exchange · Slice 5 = Connext-
Security interop (the P6 exit gate). Logging + Data Tagging plugins are descoped unless requested.

## 1. Goal

Protect user-data on the wire end-to-end (our-pub → our-sub), byte-exact AES-GCM, with the **conformant**
DDS-Security AES-GCM-GMAC **serialized-payload protection** wire format (a `SecuredPayload` replacing the
serialized payload), reusing `dds-dare`'s AES-GCM (no hand-rolled crypto). A **pre-shared test KeyMaterial**
stands in for the Auth-handshake-derived key (Slice 2 replaces it — an explicit MVP scaffold, NOT a
conformance deviation). The shipped wire format must match what a Connext-Security participant emits for
payload protection (validated offline against a real capture).

## 2. Approaches considered

- **A — Serialized-payload protection, spike-first, reuse `dds-dare` (chosen).** The thinnest conformant
  level: encrypt the serialized payload into a `SecuredPayload`; the DATA submessage framing is untouched
  (no SEC_PREFIX/POSTFIX — those are submessage protection, a later slice). Reuses the built AES-GCM.
- **B — Submessage protection (SEC_PREFIX/POSTFIX) first.** Protects the whole DATA submessage — more of
  the spec's wire surface but more invasive to the RTPS engine for the same "encrypted data" outcome.
  Deferred to a later slice.
- **C — A quick non-conformant demo (XOR / skip the format).** Rejected — violates FR-SEC-2 (vetted crypto
  only) and the OMG-conformance directive.

## 3. Design (Approach A)

### 3.1 New `dds-security` ASDF system

A new `dds-security/` system (package `dds.security`, layer L8, gated). Depends on `dds-dare` (AES-GCM,
HKDF/HMAC), `dds-core`, `dds-pal` — no `dds-rtps` dep (the cursor is from `dds-core`). Files: `crypto.lisp`
(the transform + the session-key KDF + SecuredPayload (de)serialization), `key-material.lisp` (the
KeyMaterial struct + the test-key factory), `packages.lisp`.

### 3.2 The `SecuredPayload` wire format (DDS-Security 1.1 §9.5.3.3)

Serialized-payload protection replaces the serialized payload with a `SecuredPayload` =
`SecureDataHeader` ∥ `crypto_content` ∥ `SecureDataTag`:
- **SecureDataHeader** = `transformation_kind`(4) ∥ `transformation_key_id`(4) ∥ `session_id`(4) ∥
  `init_vector_suffix`(8). The `transformation_kind` identifies AES256-GCM (the exact 4-byte value pinned
  from the spec §9.5.3.3.1 + the spike).
- **crypto_content** = the AES-GCM ciphertext (its framing — a length prefix or not — pinned from the spike
  + §9.5.3.3.4.4; the plaintext is the original serialized payload including its CDR encapsulation header).
- **SecureDataTag** = `common_mac`(16) = the AES-GCM authentication tag; `receiver_specific_macs` = a count
  (0 for payload protection, where there are no per-reader MACs) + entries.

The **nonce** (12 B) = `session_id`(4) ∥ `init_vector_suffix`(8) (§9.5.3.3.4.3). The **AAD** for the AEAD
is the SecureDataHeader (the exact AAD scope pinned from §9.5.3.3.4.4 + the spike). The **session key** is
derived from the KeyMaterial's `master_sender_key` via the spec's KDF (§9.5.3.3.4.2 — HMAC-based, the exact
PRF/hash pinned from the spike; reuse `dds-dare`'s HKDF/HMAC where the hash matches, else add the small
HMAC-SHA256 primitive over OpenSSL).

`encode-serialized-payload (transform plaintext) → secured-payload-octets` and
`decode-serialized-payload (transform secured-payload-octets) → plaintext` are the two operations. Both
reuse `dds.dare:aes-256-gcm-seal`/`aes-256-gcm-open`. `decode` is **bounds-checked at every field read**
(a malformed/short SecuredPayload returns a fail-closed error, never an OOB read; even at `(safety 0)`,
NFR-SEC-POSTURE) and fuzzed.

### 3.3 `KeyMaterial` + the test key

A `KeyMaterial` struct (§9.5.2): `transformation_kind`, `master_salt`, `sender_key_id`, `master_sender_key`
(32 B), `receiver_specific_key_id`, `master_receiver_specific_key`. A **test-key factory** builds a fixed
pre-shared KeyMaterial (a known 32-B master key + a fixed key_id + AES256-GCM kind) for the MVP. The Auth
handshake (Slice 2) produces the real KeyMaterial via the shared secret; this scaffold is then removed.

### 3.4 `dds-disc` integration

A disc-node **crypto-transform slot** (set when security is enabled with a KeyMaterial; default NIL =
security off). When set:
- **Writer:** `publish-sample` encodes the serialized payload via `encode-serialized-payload` before
  `writer-write`, so the DATA carries the SecuredPayload.
- **Reader:** the payload-delivery path (`%on-user-data` / before `%deliver-user-sample`) decodes via
  `decode-serialized-payload` before the plaintext reaches DCPS.
Default OFF → **byte-identical to today** (no security = the plaintext path unchanged; `make mem` 0.0000 on
the plaintext default path).

### 3.5 Data flow

DCPS serializes a sample → `publish-sample` → encode (derive the session key, AES-GCM seal with the
nonce + AAD → SecuredPayload) → `writer-write` → DATA carries the SecuredPayload. Reader: DATA arrives →
the SecuredPayload → decode (parse SecureDataHeader, derive the session key, AES-GCM open → plaintext) →
DCPS deserializes the plaintext.

## 4. Testing — Definition of Done (spike-first)

1. **T0 spike (the wire oracle):** stand up a Connext-Security participant (certificates, governance,
   permissions; payload/data protection ENCRYPT) → capture its payload-protected user-data on the wire →
   decode the `SecuredPayload` **offline** → pin the exact byte layout (SecureDataHeader fields, the
   AES256-GCM `transformation_kind` value, `crypto_content` framing, `SecureDataTag`, the session-key KDF,
   the nonce, the AAD scope). RE-PLAN checkpoint. If Connext-Security cannot be stood up, fall back to
   spec-clause-only conformance and escalate (do not invent constants).
2. **Byte-exact conformance corpus (gates the format):** `encode-serialized-payload` of a known plaintext
   under a known KeyMaterial produces the exact `SecuredPayload` bytes the spec §9.5.3.3 + the spike pin
   (a reference vector; both CDR endiannesses where the format carries endianness).
3. **Our-to-our round-trip:** `decode(encode(p)) = p`; a tamper (flip a ciphertext/tag byte) → `decode`
   fails closed (AES-GCM auth failure); the wire carries the SecuredPayload, never plaintext.
4. **Bounds/fuzz:** `decode-serialized-payload` over adversarial/short/oversized SecuredPayloads → a clean
   fail-closed error, no OOB/crash/mis-decode, prod + `(safety 0)` (NFR-SEC-POSTURE).
5. **`dds-disc` our-to-our live:** our-pub → our-sub with security enabled → the subscriber receives the
   correct plaintext; a tshark capture shows the DATA payload is the SecuredPayload (ciphertext, not the
   ShapeType plaintext).
6. **The interop DoD (owner-chosen):** our `encode-serialized-payload` output **byte-compares equal** to
   the Connext-Security payload-protection `SecuredPayload` from the T0 capture (same key/plaintext where
   reproducible, else field-by-field structural equality + the AES-GCM verifying against Connext's tag).
7. **All quality gates green both impls (Clasp first):** `make test`, `gate-hotpath`, `gate-types`, `mem`
   (the plaintext default path 0.0000; the security send-path cost measured + reported), `fuzz` (the new
   decode arm), `wire`.

## 5. Decomposition (subagent-driven, spike-first)

- **T0 — Connext-Security capture + offline decode spike.** Stand up Connext Security (certs/governance/
  permissions, payload protection) → capture → decode the SecuredPayload offline → pin the wire format +
  constants + KDF. Re-plan checkpoint (controller confirms before T1).
- **T1 — SecuredPayload wire format + session-key KDF.** The (de)serialization of SecureDataHeader/
  crypto_content/SecureDataTag + the session-key derivation (reuse `dds-dare` HKDF/HMAC or add HMAC-SHA256),
  byte-exact vs the spike + the spec; the conformance corpus vector.
- **T2 — `encode/decode-serialized-payload` + KeyMaterial + test key.** The two transform ops over
  `dds-dare` AES-GCM + the KeyMaterial struct + the test-key factory; the round-trip + tamper + bounds/fuzz
  tests.
- **T3 — `dds-disc` integration.** The node crypto-transform slot + the `publish-sample` encode hook + the
  reader decode hook (default OFF byte-identical); the our-to-our encrypted pub/sub live test + the tshark
  ciphertext-on-the-wire check.
- **T4 — capstone.** The offline Connext-Security byte-compare DoD + ADR 0031 (the Crypto plugin as-built +
  the Slice-1/5 roadmap) + docs lockstep (README P6 row, wiki, verification.csv) + final whole-branch review
  → squash-merge presented for owner approval (HOLD PUSH).

## 6. Risks

- **Connext-Security config is heavy (moderate-high):** certs, signed governance + permissions, the
  payload-protection-only profile. The T0 spike de-risks it; the fallback is spec-clause-only conformance +
  escalation. The owner accepted this cost for the stronger wire oracle.
- **Session-key KDF hash (low):** the spec's PRF may differ from `dds-dare`'s HKDF-SHA384; if so, add a
  small HMAC-SHA256 over OpenSSL (reuse the existing FFI), no hand-rolled crypto.
- **Per-sample AES-GCM on the send path (measured):** a real cost on the SECURITY path (not the plaintext
  hot path, which stays 0.0000 with security off); measured + reported, not assumed.
- **Test-key scaffold (bounded):** clearly marked; removed when Slice 2's Auth handshake lands.

## 7. Non-negotiables (inherited)

- **No hand-rolled crypto** — reuse `dds-dare`'s AES-GCM / OpenSSL (FR-SEC-2).
- **OMG DDS-Security 1.1 conformance** — the wire format never deviates; a vendor interop behavior would go
  ON TOP of conformant behavior, never replace it.
- **No wire constants from memory** — the transformation_kind, the KDF, the nonce, the SecuredPayload byte
  layout are pinned from the spec clause + the T0 Connext capture, cited in comments.
- **Bounds-check the decode path even at `(safety 0)`** — a malformed SecuredPayload must never OOB; fuzzed.
- `defun*`/`defstruct*` + full ftype on every new function; no reader conditionals outside `dds-pal/`; Clasp
  + SBCL both validate, Clasp first; the plaintext default path byte-identical (`make mem` 0.0000); no AI /
  assistant attribution in any repo file.

## 8. References

- OMG DDS-Security 1.1 §8.5 (Crypto plugin interfaces), §9.5.2 (KeyMaterial), §9.5.3.3 (AES-GCM-GMAC builtin
  Crypto plugin — SecuredPayload, session key, nonce).
- REQUIREMENTS FR-SEC-1/FR-SEC-2, FR-RTPS-1 (security submessages gated P6); IMPLEMENTATION-PLAN §M7.
- ADR 0025 — DARE (the reusable AES-GCM/HKDF over OpenSSL).
- `src/dds-dare/primitives.lisp` — `aes-256-gcm-seal`/`aes-256-gcm-open` (reuse).
- `src/dds-rtps/reliable.lisp` — `writer-write` (the payload boundary).
- `src/dds-disc/dataplane.lisp` — `publish-sample`, `%on-user-data` (the encode/decode hooks).
