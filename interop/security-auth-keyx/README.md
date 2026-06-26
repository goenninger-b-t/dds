# DDS-Security Auth key-exchange interop — our-to-our e2e + don't-break-plain (M7/P6 Slice 2b-ii + 2c)

**Status: ENVIRONMENT-LIMITED (2026-06-26) — live Connext-Security key-exchange interop DEFERRED to Slice 5**

This directory contains the interop harness for WP-DDS-SECURITY-AUTH-KEYX (Slice 2b-ii + 2c):
the full secure-participant end-to-end vertical slice — SPDP discovery, on-discovery PKI-DH
handshake, KxKey derivation, KxKey-encrypted §9.5.2 KeyMaterial exchange, and AES256-GCM
encrypted pub/sub with the **exchanged** per-writer keys (no pre-shared key).

ADR 0034 documents the full design and the honest interop posture.

---

## What this harness runs

### `run-our-to-our.sh`

Runs two in-process sub-checks against the test suite:

1. **`run-auth-encrypted-pubsub-keyx-test`** — the complete our-to-our headline:
   - Two security-enabled participants (`create-participant :identity`) on the same domain.
   - SPDP discovery → on-discovery PKI-DH handshake → SharedSecret → KxKey → KxKey-encrypted
     KeyMaterial exchange over PSM → both reach `auth-remote` `:keyed` → endpoint matching
     resumed → A publishes known plaintext → B receives and decrypts it.
   - Ciphertext-on-wire proof: the plaintext bytes (`"KEYXDATA"`) are ABSENT from the wire
     bytes; the first 4 bytes of the secured payload are `#(0 0 0 4)` (AES256-GCM
     `transformation_kind`, DDS-Security 1.1 §9.5.3.3.1 Table 69, not the plaintext).
   - No `make-test-key-material` anywhere: the live path uses the KxKey-derived per-writer key.

2. **`run-auth-plain-byte-identical-test`** — don't-break-plain:
   - Two plain participants (no `:identity`) on the same domain.
   - Known plaintext `"PLAINDAT"` (8 bytes) is published and received byte-identical.
   - Confirms the security build does not regress the plain (unauthenticated) data path.

3. **`run-auth-secured-refuses-plain-test`** — strict-refuse (§7.3 conformant default):
   - Security-enabled participant SEC and plain participant PLAIN, same topic/type/QoS.
   - Asserts SEC's `disc-node-matched-count` = 0 (the auth-gate refuses PLAIN).
   - Non-vacuous: plain↔plain control participants C and D on the same topic match each other
     (proving the refusal is the auth-gate, not a topic/type/QoS mismatch).

---

## Environment status

| Tool | Status |
|---|---|
| RTI Connext 7.3.1 (`rtiddsspy`) | INSTALLED |
| RTI Security Plugins (`libnddssecurity.dylib`) | **NOT INSTALLED** |
| Fast DDS 3.6.1 | **NOT AVAILABLE** in this environment |
| tshark | AVAILABLE |
| Our Lisp build (Clasp + SBCL) | VALID — 337 tests each (Clasp first), all gates green |

---

## Deferred live check — Slice 5 (the P6 exit gate)

A live PKI-DH handshake + KxKey derivation + KeyMaterial exchange + encrypted DATA exchange
against a running RTI Connext-Security stack has **NOT been performed** and is the
**Slice 5 P6 exit gate**.  It requires:

- The licensed RTI Security Plugins add-on (`rti_connext_dds_secure_plugins`).
  `libnddssecurity.dylib` is absent from
  `/Applications/rti_connext_dds-7.3.1/lib/arm64Darwin20clang12.0/`.

The aspects that are our-to-our self-consistent but unverified against a live Connext peer
(as documented in ADR 0034):

- **KxKey-AEAD wrap nonce/AAD** — Fast DDS sends KeyMaterial in plaintext (AEAD calls
  commented out in `AESGCMGMAC_KeyExchange.cpp`); our implementation is spec-conformant per
  §9.5.3 intent (KxKey-encrypted, never in the clear); nonce = fresh random 12 bytes per
  wrap; AAD = empty (conservative; our-to-our self-consistent).  The exact Connext convention
  for nonce source and AAD is unknown until Slice 5.

- **§9.5.2 KeyMaterial CDR framing** — uses the Fast DDS `{3-zeros, 1-byte-length}` format
  for the sequence fields (not standard CDR `uint32`).  Our-to-our self-consistent; verify
  against Connext at Slice 5.

- **Full reliable `ParticipantVolatileMessageSecure` endpoint (§8.8.4)** — KeyMaterial is
  carried over the best-effort PSM stateless transport; resend on loss is a Slice-5 carry.

- **DataHolder byte-layout and PSM serializedPayload encapsulation header** — self-consistent
  from ADR 0033; cross-vendor verification is Slice 5.

**Do NOT interpret this README as "cross-vendor key-exchange interop verified."**

---

## Portable guard (in CI; always green)

The in-process test suite provides the portable structural guards for the three checks above.
Model on the existing cross-DDS tests: all 337 tests run under the security build; the
default (no-identity) path is byte-identical, confirmed by `run-auth-plain-byte-identical-test`
and by the existing 300+ durability/shapes/keyed/FlatData cross-DDS tests passing under
the security build with `identity-token-octets = NIL`.

---

## RTPS/DDS-Security spec evidence

**DDS-Security 1.1 §7.3 (Authentication posture):** `allow_unauthenticated_participants = FALSE`
is the conformant default.  A security-enabled participant MUST refuse endpoint matching
for unauthenticated peers.  `run-auth-secured-refuses-plain-test` proves this.

**DDS-Security 1.1 §9.5.3 (KxKey KDF):** KxKey = HMAC-SHA256(key = SHA-256(challenge_2 ∥
"key exchange key" ∥ challenge_1), data = shared_secret).  Both primitives are verified by
RFC 4231 TC1 + TC4 published vectors.

**DDS-Security 1.1 §9.5.2 (KeyMaterial):** one `CryptoTransformKeyMaterial_DH` per local
writer per session.  The `writer-km-table` invariant (one instance shared across all
authenticated remotes for the same writer GUID) is proven by the `kpub-single-writer-km`
`(eq ...)` assertion in `run-auth-encrypted-pubsub-keyx-test`.

---

## How to run the live check (when RTI Security Plugins are available)

1. Install the RTI Security Plugins add-on (the `rti_connext_dds_secure_plugins` package).
2. Configure a Connext participant with a valid DDS-Security PKI governance/permissions XML
   using the same CA as our test PKI (`interop/security-auth/pki/ca/ca-cert.pem`).
3. Start the Connext security participant on domain 0 (subscriber with an EC identity).
4. Start our security participant:
   ```bash
   scripts/with-clasp.sh --eval '
     (asdf:load-system :dds)
     (let* ((ca   (uiop:read-file-string "interop/security-auth/pki/ca/ca-cert.pem"))
            (cert (uiop:read-file-string "interop/security-auth/pki/participant_ec/identity_cert.pem"))
            (key  (uiop:read-file-string "interop/security-auth/pki/participant_ec/identity_key.pem"))
            (to-oct (lambda (s) (map (quote (simple-array (unsigned-byte 8) (*)))
                                     (function char-code) s)))
            (guid (make-array 16 :element-type (quote (unsigned-byte 8))
                                 :initial-contents (quote (1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16))))
            (id   (dds.security:validate-local-identity
                     (funcall to-oct ca) (funcall to-oct cert) (funcall to-oct key) guid))
            (p    (dds.dcps:create-participant :domain 0 :identity id)))
       (loop (sleep 1)))
   '
   ```
5. Observe with tshark:
   ```bash
   /Applications/Wireshark.app/Contents/MacOS/tshark \
     -i lo0 -f "udp port 7400" -w captures/keyx-live-$(date +%s).pcapng
   ```
6. Verify with the RTPS dissector:
   - Both participants exchange `ParticipantStatelessMessage` DATA submessages carrying the
     PKI-DH handshake tokens (ADR 0033 PSM endpoints `0x000201C3` / `0x000201C4`).
   - After handshake, `ParticipantStatelessMessage` DATA submessages carry the CryptoToken
     (`dds.sec.participant_crypto_tokens` `message_class_id`).
   - Subsequent user-DATA submessages carry AES256-GCM `SecuredPayload` (first 4 bytes of
     serialized payload = `{0x00, 0x00, 0x00, 0x04}` per §9.5.3.3.1 Table 69).

---

## References

- ADR 0034: `docs/adr/0034-dds-security-auth-keyx.md` (full design + carries)
- ADR 0033: `docs/adr/0033-dds-security-auth-wire.md` (PSM wire transport)
- `interop/security-auth-discovery/README.md` — Slice 2b-i don't-break-plain (model for this file)
- `src/dds-tests/security-auth-test.lisp` — all auth-keyx tests
- `docs/wiki/security.md` §6ter / §6quarter — auth manager + key-exchange API reference
