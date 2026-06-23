# ADR 0031 — DDS-Security Cryptographic plugin: serialized-payload protection (Slice 1)

- **Status:** Accepted (M7/P6; WP-DDS-SECURITY-CRYPTO-MVP, 2026-06-22)
- **Relates to:** ADR 0025 (DARE — the `dds-dare` OpenSSL FFI this Slice reuses);
  ADR 0026 (PERSISTENT store — the DARE key-epoch this work sits beside);
  FR-SEC-2 (vetted native crypto, no hand-rolling); NFR-SEC-POSTURE (bounds-checked,
  fail-closed); NFR-MEM (off the measured CDR hot path); the T0 spike
  (`docs/superpowers/spikes/2026-06-22-dds-security-payload-wire.md`) — the primary
  wire-format reference for this ADR (the §9.5.3.3 clauses and the RTI binary-string
  evidence cited throughout are there).
- **Standards:** OMG DDS-Security 1.1 §9.5.2 (KeyMaterial), §9.5.3.3 (Crypto plugin
  serialized-payload protection), §9.5.3.3.1 (SecureDataHeader, SecureDataTag IDL/layout),
  §9.5.3.3.3 (SecureDataTag), §9.5.3.3.4.2 (session-key KDF), §9.5.3.3.4.3 (nonce),
  §9.5.3.3.4.4 (`encode_serialized_data`), §9.5.3.3.4.5 (`decode_serialized_data`);
  NIST SP 800-38D (AES-GCM); RFC 4231 (HMAC-SHA-256 KAT vectors).

## Context

P6 (DDS-Security) is a gated milestone.  The first work-package is a minimal vertical
slice of the **Cryptographic builtin plugin (§7.4 / §9.5)**: serialized-payload
protection (§9.5.3.3) using AES256-GCM.  This is the most tractable slice because
it has no Auth or AccessControl dependency — a pre-shared `key-material` is sufficient
for Slice 1 — and it provides an immediately demonstrable, wire-observable security
property: a node with `crypto-transform` set emits **ciphertext on the wire**, not the
plaintext serialized payload.

Slice 1 is decomposed into five tasks.  T0 is the spike (wire format + blocking
conditions); T1–T3 are implementation; T4 (this ADR) is the as-built record, the
honest interop writeup, and the gate sweep.

---

## Decision — as-built architecture

### Module layout

A standalone **`dds-security`** ASDF system (depends on `dds-lang`, `dds-pal`,
`dds-core`, `dds-dare`, `cffi`; NO `dds-rtps` and NO `dds-disc` dep in the library itself),
wired into `dds.asd` and `dds-tests.asd`.

| File | Responsibility |
|---|---|
| `src/dds-security/packages.lisp` | Package `dds.security` |
| `src/dds-security/crypto.lisp` | `serialize-secured-payload`, `parse-secured-payload`, `derive-session-key`, all wire constants |
| `src/dds-security/key-material.lisp` | `key-material` defstruct (§9.5.2 fields + nonce state), `make-test-key-material` |
| `src/dds-security/transform.lisp` | `encode-serialized-payload`, `decode-serialized-payload`, `%km-next-iv-suffix`, `%assemble-header-aad` |

The AEAD primitive (`dds.dare:aes-256-gcm-seal`/`aes-256-gcm-open`) and the KDF
primitive (`dds.dare:hmac-sha256`) are **reused from `dds-dare`** — no new crypto
primitive is hand-rolled (FR-SEC-2).

### T1 — Wire format + session-key KDF (`crypto.lisp`)

#### SecuredPayload layout (§9.5.3.3; spike §2.5)

Every constant below is pinned from the §9.5.3.3 clause and corroborated by the spike
(spike §7 reference table); none from memory.

```
SecuredPayload =  SecureDataHeader (20 bytes)
               || crypto_content.length (uint32 LE)
               || ciphertext (N bytes)
               || common_mac (16 bytes)
               || receiver_specific_macs_count (uint32 LE = 0)
```

**SecureDataHeader** (§9.5.3.3.1, 20 bytes):

| Offset | Width | Field | Value / Notes |
|---|---|---|---|
| 0 | 4 | `transformation_kind` | `octet[4]` = `{0x00,0x00,0x00,0x04}` for AES256-GCM (Table 69; spike §2.2) |
| 4 | 4 | `transformation_key_id` | `octet[4]` = `sender_key_id` from the KeyMaterial (opaque; spike §8 item 2) |
| 8 | 4 | `session_id` | `octet[4]`; random per session (spike §2.2; binary "RAND_bytes sessionId") |
| 12 | 8 | `init_vector_suffix` | `octet[8]`; random per session (spike §2.2; binary "RAND_bytes (session IV suffix)") |

`crypto_content` is an IDL `sequence<octet>` (§9.5.3.3.1): a `uint32` length prefix
(RTPS E-flag endianness; this stack emits LE, the common case) followed by `N` bytes
of ciphertext.  N equals the plaintext length — AES-GCM does not expand the payload.

`SecureDataTag` (§9.5.3.3.3): `common_mac (16)` (the 128-bit GCM authentication tag)
`|| receiver_specific_macs_count (uint32 LE = 0)` for serialized-payload protection
without origin-authentication (§9.5.3.3.4.4 step 10; spike §2.4).  Total = 20 bytes.

The **20-byte SecureDataHeader is exactly the GCM AAD** (§9.5.3.3.4.4; spike §3.4).
The **12-byte GCM nonce** is `session_id (4) || init_vector_suffix (8)` (§9.5.3.3.4.3;
spike §3.3).

**CDR encapsulation header — the decision.**  The serializer emits the **spec-minimal
bare SecuredPayload** (no 4-byte CDR encapsulation header before the SecureDataHeader).
The spec §9.5.3.3.4.4 does not mandate one.  Whether Connext prepends one inside the
DATA serialized-payload field is implementation-defined and currently **unconfirmed**
(the live Connext-Security capture was blocked; see §cross-vendor-deferral below).
The header — if ever present — is never part of the AAD or the plaintext (spike §2.1).

#### Session-key KDF (§9.5.3.3.4.2; spike §3.1)

```
session_key = HMAC-SHA256(master_sender_key,
                          "SessionKey" || master_salt || session_id || "0001")
```

This is **HMAC-SHA256** (Table 70), **not** the HKDF-SHA384 used by `dds-dare` for the
DARE key derivation.  The string literals `"SessionKey"` (10 bytes) and `"0001"` (4 bytes)
are spec Table 70 pinned; confirmed by the spike binary strings (spike §3.1/§3.2).
The primitive is `dds.dare:hmac-sha256` — a one-shot `EVP_Q_mac(name='HMAC',
subalg='SHA256')` call over the existing `*libcrypto*` handle; the foreign key buffer
is zeroized before free.

#### Bounds-checking (NFR-SEC-POSTURE)

`parse-secured-payload` bounds-checks **every field read before allocating**:

- A total length below the minimum (header + length-prefix + tag = 44 bytes) signals
  `secured-payload-malformed` before any field parse.
- The declared `crypto_content.length` is cross-checked against the actual remaining
  bytes: a hostile `0xffffffff` would overflow and is rejected before the ciphertext
  array is allocated.
- A non-zero `receiver_specific_macs_count` signals `secured-payload-malformed` (Slice 1
  does not implement per-reader MACs).

These checks are explicit manual checks, not assertions — they hold even at `(safety 0)`.

### T2 — KeyMaterial + encode/decode (`key-material.lisp`, `transform.lisp`)

#### `key-material` defstruct (§9.5.2)

Fields: `transformation-kind` (octet[4]), `master-salt` (octet[32]), `sender-key-id`
(octet[4]), `master-sender-key` (octet[32]), plus nonce-uniqueness state:
`iv-counter` (unsigned-byte 64) and `iv-counter-lock`.

#### Nonce-uniqueness — the structural argument

AES-GCM nonce reuse under the same session key is catastrophic (NIST SP 800-38D §8.3:
a single repeated nonce-key pair exposes the authentication key and enables plaintext
recovery).  In Slice 1 the session key is fixed per `key-material` instance (session_id
is all-zeros, so the KDF always yields the same 32-byte key for a given master key).
Nonce uniqueness therefore falls entirely on the `iv_suffix`:

- `key-material-iv-counter` is a `(unsigned-byte 64)` counter, initial value 0.
- `%km-next-iv-suffix` claims the next value **under `key-material-iv-counter-lock`**,
  increments the counter, and encodes the value as a big-endian uint64 into the 8-byte
  field.
- Two concurrent `encode-serialized-payload` callers on the **same `km`** each observe
  a different counter value — uniqueness is **structural**, not timing-dependent.
- At 10^7 messages/s, the counter wraps at ~58 000 years of continuous operation:
  no operational key lives long enough.

**Single-instance constraint.**  This structural guarantee holds only within **one**
`key-material` instance.  Two instances sharing the same `master_sender_key` +
`master_salt` both start `iv-counter` at 0 and will produce colliding nonces under the
same session key (catastrophic).  The `make-test-key-material` docstring documents this
constraint explicitly.  **The Slice-2 Auth handshake resolves it** by deriving a unique
per-writer key via the DH exchange — each writer gets its own `key-material` with a
unique master key, so the collision precondition is eliminated structurally.

#### `make-test-key-material` — the MVP scaffold

Returns a fresh `key-material` with fixed pre-shared constants (consecutive bytes
`0x00..0x1F` for `master_sender_key`; `0x40..0x5F` for `master_salt`; `0xDEADBEEF`
for `sender_key_id`).  Intended for offline unit/round-trip tests only.  NOT for
production use.  Replaced by the Slice-2 Auth-handshake-derived key.

#### `encode-serialized-payload` / `decode-serialized-payload`

`encode-serialized-payload (km plaintext)`:
1. Claims a unique `iv_suffix` from the monotonic counter.
2. Derives the session key via `derive-session-key`.
3. Assembles the 20-byte SecureDataHeader as the GCM AAD (`%assemble-header-aad`).
4. Calls `dds.dare:aes-256-gcm-seal` with nonce = session_id(4) || iv_suffix(8).
5. Serializes via `serialize-secured-payload`.

`decode-serialized-payload (km secured-octets)`:
1. `parse-secured-payload` — any `secured-payload-malformed` is caught → NIL.
2. Reconstructs the 20-byte AAD from the **wire-parsed** header fields (§9.5.3.3.4.5).
3. Derives the session key from the **wire-parsed** `session_id`.
4. Calls `dds.dare:aes-256-gcm-open` — returns NIL on auth failure.
5. Any condition (parse error, constraint, etc.) → NIL (fail-closed).

### T3 — `disc-node` integration (`disc.lisp`, `dataplane.lisp`)

**`disc-node-crypto-transform`** slot (added to `defstruct* disc-node`):

```lisp
(crypto-transform nil :type t)
; DDS-Security 1.1 §9.5.3.3 Slice-1: key-material for AES256-GCM serialized-payload
; protection; NIL = security OFF, byte-identical hot path (ADR 0031)
```

Default NIL means the hot path is **byte-identical** to before: no security overhead,
no CLOS dispatch, no allocation.

**`make-disc-node :crypto-transform`** keyword threads the value into the slot.

**Send hook** (`publish-sample`, `dataplane.lisp` line ~991):

```lisp
(when (disc-node-crypto-transform node)
  (setf payload (dds.security:encode-serialized-payload
                 (disc-node-crypto-transform node) payload)))
```

Runs before `writer-write`; if `encode-serialized-payload` returns the SecuredPayload
blob, `writer-write` puts it into the HistoryCache and the reliable engine sends it.

**Receive hook** (`%deliver-user-sample`, `dataplane.lisp`, at the top of the function body):

```lisp
(when (disc-node-crypto-transform node)
  (let ((plain (dds.security:decode-serialized-payload
                (disc-node-crypto-transform node) vec)))
    (unless plain (return-from %deliver-user-sample t))
    (setf vec plain)))
```

Placed at the top of the common delivery sink, which is called by both `%on-user-data`
(direct DATA path) and `%on-user-data-frag` (DATA_FRAG reassembly path).  This ensures
encrypted samples larger than `*fragment-size*` that fragment on send are correctly
decrypted after reassembly.  On NIL (authentication failure or malformed blob) the
function returns early — the sample is **dropped** (fail-closed, best-effort).  The
reliable reader does not record the SN as received, so the writer may retransmit; see
Known Limitations item 1.  The ZC arms in `%on-user-data` are NOT affected (the
`(zc-loan-marker-p zc)` and resolved-ZC `t` arms call `%deliver-user-marker` /
`%deliver-user-sample` directly; crypto+ZC is loud-guarded at `make-disc-node`).

**`run-security-encrypted-pubsub-test`** (`src/dds-tests/security-test.lisp`):
a 3-node loopback (domain 83, topic `SSquare`): PUB (encode), SUB (decode → plaintext),
PLAIN (no crypto-transform → receives the raw SecuredPayload ciphertext).  Asserts:
(a) SUB receives the exact plaintext; (b) PLAIN receives bytes that are NOT the
plaintext; (c) PLAIN's first 4 bytes are `#(0 0 0 4)` (AES256-GCM `transformation_kind`,
§9.5.3.3.1 Table 69) — the wire carries the SecuredPayload, not the plaintext.

---

## Cross-vendor interop — the three-level result

The RTI Connext Security Plugins (`libnddssecurity.dylib`, `rti_connext_dds_secure_plugins`
add-on) are a **separately licensed package not installed in this environment**.  The
honest result has three distinct levels:

### Level 1 — Structural conformance (achieved)

Our `SecuredPayload` byte layout conforms to OMG DDS-Security 1.1 §9.5.3.3 — proven
byte-exact by the T1 corpus test (`run-security-secured-payload-corpus-test`) against the
spec layout, and corroborated by the RTI Shapes Demo binary STRING evidence in the T0
spike (algorithm/plugin name strings, the `CryptoTransformKind` enum byte at VM
`0x18ab418 = 0x04`, "RAND_bytes sessionId", "RAND_bytes (session IV suffix)",
"Cryptography_hmac3steps sessionKey" — spike §2/§3/§7).  This is **structural
corroboration from a shipped Connext binary**, not a live wire capture.

### Level 2 — Cryptographic byte-exactness of the primitives (achieved, by KAT)

Our AES-256-GCM (`dds-dare`, OpenSSL EVP) is KAT-verified byte-exact against **NIST SP
800-38D Test Case 16** (`run-dare-aes-gcm-kat-test`, ADR 0025).  Our `hmac-sha256` is
KAT-verified against **RFC 4231 §4.3 HMAC-SHA-256 Test Case 2**
(`run-security-secured-payload-corpus-test` step d).  These are published, independent
conformance vectors — never self-generated.

Corollary: for identical `(key, nonce, AAD, plaintext)` our `(ciphertext, tag)` is
**byte-identical to any conformant AES-256-GCM implementation**, including Connext's.
This is equality-by-published-KAT, established **without a live Connext-Security peer**.

### Level 3 — Live cross-vendor byte-compare (DEFERRED — NOT achieved)

The end-to-end byte-compare of a full `SecuredPayload` emitted by a **running RTI
Connext-Security instance** for the same key/plaintext, or decryption of a
Connext-encrypted blob using our `decode-serialized-payload`, has **not been performed**.
It requires the licensed Connext Security Plugin add-on (not installed).

**Do NOT interpret any statement in this ADR as "cross-vendor interop verified" or
"byte-for-byte vs Connext."**

This live compare is **Slice 5** of the M7 roadmap (the P6 exit gate).  See §10 below.
The `interop/security-crypto/README.md` records this honestly.

---

## Known limitations (Slice 1)

1. **Fail-closed decode-failure drop on the reliable reader path does not record the SN.**
   If `decode-serialized-payload` returns NIL on a RELIABLE subscription, `%deliver-user-sample`
   returns early without recording the SN in the reader proxy's received set.  The
   reliable writer (whose HEARTBEAT still includes that SN) will detect the SN as not
   acknowledged and retransmit.  This is NOT reachable in the Slice-1 single-pre-shared-key
   scope (every matched node shares the one key, so legitimate traffic always decrypts).
   It mirrors the existing zero-copy invalid-ref best-effort drop in `%on-user-data`'s
   `((null zc))` arm (`src/dds-disc/dataplane.lisp` line ~1441).  **Slice-2 Auth** (matched
   readers share keys by construction from the DH exchange) removes the precondition
   entirely.

2. **Minor: an `encode-serialized-payload` on a `writer-write` `:timeout` consumes an
   `iv-counter` slot.**  The encode runs before `writer-write` checks the bounded cache;
   if the cache is full and `max_blocking_time` elapses, the encoded payload is discarded
   but the `iv-counter` has already been incremented.  This is a harmless monotonic nonce
   gap (AES-GCM nonces need only be unique within a key's life, not consecutive) and
   occurs only on the finite-bounded-cache path.  It is not a security concern.

3. **`make-test-key-material` single-instance constraint.**  At most one `key-material`
   instance from `make-test-key-material` may encode at a time (two would start
   `iv-counter` at 0 and collide on the same nonce under the same session key — AES-GCM
   catastrophic failure).  The `run-security-encrypted-pubsub-test` uses ONE shared
   instance on both the publishing and subscribing nodes; this is the intended pattern.
   Resolved by Slice-2 per-writer derived keys.

4. **Crypto + zero-copy is unsupported in Slice 1 (loud-guarded).**  A `§9.5.3.3`
   `SecuredPayload` is a heap copy of the ciphertext and cannot be applied in-place to
   an existing zero-copy loan buffer.  `make-disc-node` signals an `error` if both
   `:crypto-transform` and `:zerocopy-enabled` are active simultaneously
   (`src/dds-disc/disc.lisp`, after `%zc-make-pool`).  Resolving the in-place
   encryption of a ZC loan without an extra copy is a Slice-3 follow-on.

5. **DATA_FRAG path IS covered (resolved in this WP).**  The decode runs at the common
   delivery sink `%deliver-user-sample` (`src/dds-disc/dataplane.lisp`), covering both
   the direct DATA path and the DATA_FRAG reassembly path (`%on-user-data-frag` → 
   `%deliver-user-sample`).  An encrypted sample larger than `*fragment-size*` (1024 bytes)
   is encoded, fragmented into multiple DATA_FRAGs on send, reassembled, and then
   decrypted at the sink — byte-exact to the original plaintext.  Regression-tested by
   `run-security-encrypted-fragmented-test` (domain 84, 2000-byte plaintext).

6. **P6-hardening follow-on (deferred): redundant per-sample session-key derivation.**
   `derive-session-key` runs an HMAC-SHA256 on every `encode-serialized-payload` /
   `decode-serialized-payload` call.  Because `session_id` is fixed per `key-material`
   instance in Slice 1, the result is byte-identical on every call — the session key
   could be derived once at key-material construction and cached.  This is a
   correctness-neutral optimization deferred to P6 hardening (Slice 2 changes the
   session-id per-handshake, at which point caching requires a per-session-id cache
   entry, not a single cached value).  Also deferred: migration of the encode/decode
   buffers onto the static arena (`*static-arena-bytes*`) when the crypto path is on
   the measured hot path.

---

## §9 — M7 roadmap (5 slices)

| Slice | Description | Status |
|---|---|---|
| **1 (this ADR)** | Crypto builtin plugin: AES256-GCM serialized-payload protection | **LANDED** |
| 2 | Authentication plugin (§8.7): PKIX-DH handshake, certificate exchange, derived per-writer session keys — replaces `make-test-key-material` + resolves the single-instance constraint | pending |
| 3 | AccessControl plugin (§8.8): governance/permissions XML, topic-level protection policy enforcement | pending |
| 4 | Secure discovery (§7.4.4): SPDP/SEDP participant/endpoint authentication, encrypted discovery metadata | pending |
| 5 | Connext-Security live interop: live cross-vendor byte-compare of the full `SecuredPayload`; requires the RTI Security Plugins add-on (the P6 exit gate) | pending |

**What Slice 2 (Auth) changes:**

- Replaces the fixed `make-test-key-material` with an Auth-handshake-derived
  per-writer session key.  Each writer gets a unique key derived from the DH exchange,
  so the single-instance nonce constraint is resolved structurally (each writer's
  `key-material` has a unique `master_sender_key` + `master_salt` → the same nonce on
  two writers maps to different ciphertexts under different keys → no collision).
- Matched readers share keys via the handshake, so a decode failure on legitimate
  reliable traffic becomes impossible (removing the Slice-1 reliable-reader caveat).
- The `disc-node crypto-transform` slot accepts the Auth-derived `key-material` exactly
  as it accepts the test key today; no API change in Slices 2–4.

---

## Consequences

- **NFR-MEM:** `make mem` stays **0.0000** bytes/sample — the security encode/decode
  path is control-plane (off the measured CDR hot path); `disc-node-crypto-transform`
  defaults to NIL and the check is a single `when` — the `publish-sample` / `%on-user-data`
  hot paths are unaffected when security is OFF.
- **Gates:** `make test` (SBCL 314 + Clasp 314, both, Clasp first — +1 for `run-security-encrypted-fragmented-test`); `gate-hotpath(8)`;
  `gate-types(1612)`; `mem(0.0000)`; `fuzz`; `wire` — all green on both impls.
- The `dds.security` package is exported from the `dds-security` ASDF system;
  `dds.dare:hmac-sha256` is the only new export from `dds-dare`.
- No reader conditionals outside `dds-pal/` (CI lint).

## NFR impact

- **NFR-SEC-POSTURE:** `parse-secured-payload` is bounds-checked at every field before
  allocation; `decode-serialized-payload` is fail-closed (NIL on any error, including
  OOB); the corpus test + the 2081-input fuzz (`run-security-payload-fuzz-test`) both
  confirm no OOB/crash/partial-parse on adversarial inputs.
- **NFR-PORT:** no reader conditionals in `dds-security/`; the HMAC-SHA256 and
  AES-GCM primitives are impl-agnostic (`dds-dare` OpenSSL CFFI, already Clasp+SBCL
  validated by ADR 0025).
- **FR-SEC-2:** no hand-rolled crypto; all primitives are OpenSSL EVP.

## References

- T0 spike: `docs/superpowers/spikes/2026-06-22-dds-security-payload-wire.md`
- `src/dds-security/crypto.lisp` — wire constants + `serialize-secured-payload` /
  `parse-secured-payload` / `derive-session-key`
- `src/dds-security/key-material.lisp` — `key-material` defstruct + `make-test-key-material`
- `src/dds-security/transform.lisp` — `encode-serialized-payload` / `decode-serialized-payload`
  + the nonce-uniqueness argument block
- `src/dds-disc/disc.lisp` — `disc-node-crypto-transform` slot + `make-disc-node :crypto-transform` + crypto+ZC guard
- `src/dds-disc/dataplane.lisp` — `publish-sample` encode hook (line ~991) + `%deliver-user-sample`
  decode hook (common sink covering both DATA and DATA_FRAG paths)
- `src/dds-tests/security-test.lisp` — `run-security-secured-payload-corpus-test`,
  `run-security-payload-fuzz-test`, `run-security-encrypted-pubsub-test`,
  `run-security-encrypted-fragmented-test` (DATA_FRAG path; domain 84, 2000-byte plaintext)
- `interop/security-crypto/run-our2our.sh` — the our-to-our wire ciphertext proof
- `interop/security-crypto/README.md` — the honest interop level writeup
- `docs/wiki/security.md` — user-facing API + worked example + roadmap
- ADR 0025 — DARE: the AES-256-GCM and HMAC-SHA256 primitives reused here
