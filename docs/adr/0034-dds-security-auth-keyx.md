# ADR 0034 — DDS-Security Authentication: discovery integration, key exchange, and strict endpoint gating (Slice 2b-ii + 2c)

- **Status:** Accepted (M7/P6; WP-DDS-SECURITY-AUTH-KEYX, 2026-06-26)
- **Relates to:** ADR 0033 (Slice 2b-i — the PSM wire transport whose `on-stateless-message`
  hook this slice finally gives an implementation); ADR 0032 (Slice 2a — the in-process
  PKI-DH handshake and §9.3 suites); ADR 0031 (Slice 1 — the `disc-node` `crypto-transform`
  slot that this slice wires to per-writer exchanged keys instead of the pre-shared
  `make-test-key-material`); ADR 0025 (DARE — the `dds-dare` OpenSSL FFI extended for
  `hmac-sha256` in Slice 2a and `aes-256-gcm-seal/open` used here for KxKey-AEAD-wrap);
  FR-SEC-2 (no hand-rolled crypto); NFR-SEC-POSTURE (bounds-checked parsers, fail-closed,
  fuzzed); NFR-MEM (off the measured CDR hot path).
- **Standards:** OMG DDS-Security 1.1 §7.3 (Participant authentication posture), §7.4.3
  (ParticipantStatelessMessage endpoint), §7.4.4 (ParticipantGenericMessage IDL layout),
  §8.7 (Authentication plugin behaviour), §8.7.2.4 (three-message handshake state machine),
  §9.3 (`DDS:Auth:PKI-DH`), §9.3.2 (algo-vs-suite cross-check), §9.3.4 (DataHolder IDL),
  §9.5.2 (KeyMaterial — `CryptoTransformKeyMaterial_DH`), §9.5.3 (KxKey/KxSalt KDF and
  serialized-payload protection); the T0 spike
  (`docs/superpowers/spikes/2026-06-26-dds-security-keyexchange.md`) — the primary
  wire-constant reference for this ADR.

---

## Context

ADR 0033 (Slice 2b-i) delivered the PSM wire transport: SPDP carries the `IdentityToken`
in `PID_IDENTITY_TOKEN`, handshake tokens travel as CDR-LE `DataHolder` blobs inside
`ParticipantGenericMessage` envelopes, and an `on-stateless-message` hook slot was added
to `disc-node`.  The hook was exercised only by explicit test code — there was no automatic
trigger, no auth manager, no endpoint gate, no key exchange, and no use of the resulting
`SharedSecret`.  The Slice-1 pre-shared `make-test-key-material` was still on the live path.

This ADR documents the **merged Slice 2b-ii + 2c** work package
(WP-DDS-SECURITY-AUTH-KEYX): the complete secure-participant vertical slice, our-to-our.

---

## Goal

Deliver the **secure participant end-to-end, our-to-our**: a participant configured with
an identity automatically authenticates every discovered security-enabled peer over the
PSM wire, exchanges per-writer key material derived from the SharedSecret, **gates endpoint
matching strictly on authentication** (§7.3), and **encrypts/decrypts real user data with
the exchanged keys — dropping the Slice-1 pre-shared test key**.

This is a single vertical slice through every layer: identity → SPDP discovery →
on-discovery handshake trigger → SharedSecret → KxKey → KeyMaterial exchange → installed
per-writer keys → encrypted DATA on the wire → decrypted at the reader.

---

## Approved decisions

Three design decisions were approved before implementation (design spec §2):

### Decision 1 — Full end-to-end vertical slice

Absorb Slice 2c (crypto key-exchange) into this work package and deliver one complete
slice through all layers: auth manager (2b-ii) + KxKey KDF + KeyMaterial generation +
CryptoToken encode/send + install + per-writer exchanged-key resolver replacing
`make-test-key-material` (2c).  A manager that authenticates but does not use the key
is a horizontal layer, not a vertical slice.

### Decision 2 — Strict authenticated-only matching (§7.3 conformant default)

A security-enabled participant refuses all unauthenticated endpoint matches
(`allow_unauthenticated_participants = FALSE`, the DDS-Security 1.1 §7.3 default posture).
The `allow_unauthenticated` governance knob is **YAGNI — deferred** (no use case in scope).
Plain (no-identity) participants are byte-identical to the pre-security wire.

### Decision 3 — Conformant §9.5.2 KeyMaterial, KxKey-encrypted, over the best-effort PSM transport

The KeyMaterial wire format is conformant §9.5.2 `CryptoTransformKeyMaterial_DH`
(88-byte CDR blob; fast-DDS-style framing; see §Honest interop posture).  Transport is
**KxKey-encrypted** per §9.5.3 intent (keys never in the clear on the wire); AAD is empty
(conservative, our-to-our self-consistent; see §Honest interop posture).  The reliable
`ParticipantVolatileMessageSecure` builtin endpoint defined in §8.8.4 is a documented
**Slice-5 carry** — this slice carries CryptoTokens over the existing best-effort PSM
stateless endpoint, with pending-token buffering on the receiver side.  The KeyMaterial
format is conformant so Slice-5 interop is reachable without changing the wire layout.

---

## Architecture

### Layering

The **auth manager** lives in `src/dds-dcps/auth-manager.lisp`, mirroring
`src/dds-dcps/type-gate.lisp` (the established DCPS-layer extension point for `disc-node`
matching policy).  Both `dds-security` (handshake + key-exchange functions) and `dds-disc`
(hooks, send, matching) must be reachable from the manager; placing it in `dds-dcps` keeps
the `dds-disc` ↔ `dds-security` dependency graph acyclic.  `dds-disc` gains only thin
extension point slots; no crypto calls live there.

### Module layout

| File | Responsibility |
|---|---|
| `src/dds-security/auth/keyexchange.lisp` | §9.5.3 KxKey/KxSalt KDF; §9.5.2 KeyMaterial generation + CDR serializer/parser; CryptoToken DataHolder encode/decode; `ParticipantGenericMessage` CryptoToken wrapper |
| `src/dds-security/auth/suites.lisp` | `select-suite-for-identities` (new); `%cert-algo->kind` (T1); algo-vs-suite cross-check guards inserted in `handshake.lisp` (T1) |
| `src/dds-security/key-material.lisp` | `crypto-keys` defstruct + `%wrap-km-as-resolver` (T6); `key-material` extended with `receiver-specific-key-id` + `master-receiver-specific-key` slots (T3) |
| `src/dds-dcps/auth-manager.lisp` | Auth manager orchestrator: per-participant `auth-manager-state`, per-remote `auth-remote` state machine, `%install-auth-manager`, `%participant-auth-gate` |
| `src/dds-dcps/entities.lisp` | `dp-auth-state` slot on `domain-participant`; `create-participant :identity` keyword |
| `src/dds-disc/disc.lisp` | `on-participant-discovered`, `auth-gate`, `auth-state` slots on `disc-node`; `%consult-auth-gate` second gate in `%match-remote-endpoint`; `on-participant-discovered` trigger in `%record-participant`; auth-state cleanup in `%lease-sweep` |
| `src/dds-disc/dataplane.lisp` | `crypto-keys` dispatch in `publish-sample` (encode) and `%deliver-user-sample` (decode); `%local-writer-guid-vec` helper |
| `src/dds-disc/stateless-message.lisp` | `%on-stateless-message` updated to deliver RAW envelope octets (Decision 1) |

### §9.5.3 KxKey derivation

Two-step HMAC-SHA256 construction (T0 spike §2.4; no HKDF):

```
KxSalt = HMAC-SHA256(
    key  = SHA-256(challenge_1(32B) || "keyexchange salt"(16B) || challenge_2(32B)),
    data = shared_secret(32B))

KxKey = HMAC-SHA256(
    key  = SHA-256(challenge_2(32B) || "key exchange key"(16B) || challenge_1(32B)),
    data = shared_secret(32B))
```

Labels are pinned from the T0 spike (§9.5.3 / Fast DDS corroboration), never from memory:

| Label | Hex | Constant |
|---|---|---|
| KxKey label | `6b65792065786368616e6765206b6579` | `+kxkey-label+` |
| KxSalt label | `6b657965786368616e67652073616c74` | `+kxsalt-label+` |

Inputs: `challenge_1` = 32-byte initiator nonce; `challenge_2` = 32-byte responder nonce;
`shared_secret` = 32-byte SHA-256(DH/ECDH raw output) from ADR 0032.  **The challenge
assignments are SWAPPED between KxSalt and KxKey** — asymmetric by spec design.

`derive-kx-key` and `derive-kx-salt` each return a `kx-key-handle` whose `bytes` slot is
a `dds.pal:alloc-static`/`free-static` foreign buffer (clasp#1793-safe; never
`static-vectors` directly).  Both must be freed via `free-kx-key`.

### One KeyMaterial per local writer (§9.5 conformance — T6)

§9.5 requires a single `KeyMaterial` per local writer, shared across all authenticated
remotes.  The manager's `auth-manager-state` holds a `writer-km-table` (EQUALP hash-table,
16-octet writer GUID → `key-material`).  `%am-get-or-create-writer-km` is the
get-or-create idiom: if an entry exists for the writer GUID it is returned; otherwise
`generate-writer-key-material` is called once and the result is stored.  All auth-remote
entries for the same local writer receive the identical `key-material` instance.  This is
proven structurally at 2 participants by the `kpub-single-writer-km` `(eq ...)` assertion
in `run-auth-encrypted-pubsub-keyx-test`.

### Per-writer exchanged-key resolver (`crypto-keys` — T6)

`crypto-keys` (`src/dds-security/key-material.lisp`) holds two closures:

- `encode-key-fn (local-writer-guid) -> (or key-material null)` — resolves the local
  writer's `key-material` for outgoing samples (§9.5.3.3.4.4 encode direction).  The
  closure does an O(1) `gethash` into `writer-km-table`.
- `decode-key-fn (remote-writer-guid) -> (or key-material null)` — resolves the remote
  writer's `key-material` from the installed auth-remote for that GUID prefix (§9.5.3.3.4.5
  decode direction).

Both return `nil` when no key is installed; callers treat `nil` as fail-closed (sample
dropped, no plaintext on the secure path).  The resolver is installed on the disc-node's
`crypto-transform` slot the moment the first remote reaches `:keyed`, BEFORE
`resume-parked-matches` fires, so no matched endpoint ever sees an absent resolver.

### Auth-gate (§7.3 strict posture — T4/T5)

`%consult-auth-gate` is the **second sequential gate** after `%consult-type-gate`
in `%match-remote-endpoint`, outside the node lock, on the receiver thread.  Verdict
ladder for `%participant-auth-gate`:

| Condition | Verdict |
|---|---|
| `dp-auth-state` NIL (security off) | `:compatible` — unchanged plain path |
| remote `auth-remote` state `:keyed` | `:compatible` |
| remote state `:handshaking` / `:authenticated` (in flight) | `:pending` → `%park-match`; resumed on `:keyed` |
| no `auth-remote` (plain peer, no IdentityToken) OR state `:rejected` / `:none` | `:incompatible` (strict refuse) |

`allow_unauthenticated = FALSE` is not a configuration knob here — it is the unconditional
conformant default (§7.3 Table 5; the knob is YAGNI-deferred to a later slice).

### Algo-vs-suite cross-check (T1 — closes ADR 0032 §Known-limitations 5)

ADR 0032 §5 noted that `select-auth-suite` was wired but the per-handshake guard
(asserting that the peer's `c.dsign_algo` / `c.kagree_algo` strings in the Request token
match the selected suite) was absent.  T1 inserts the guard at two sites in
`src/dds-security/auth/handshake.lisp`:

- **Replier** (`begin-handshake-reply`): after `peer-dsign-str` / `peer-kagree-str` are
  decoded, before the `hash_c1` equality check.  A mismatch → `return-from
  begin-handshake-reply (values nil nil)` (fail-closed).
- **Requester** (`%process-reply`): same check via `(reject)`, matching the existing
  rejection pattern.  `reject` sets state `:rejected` and returns `(values nil
  :rejected)`.

`%cert-algo->kind` (T1, `suites.lisp`) maps the IdentityToken `dds.cert.algo` string
to a keyword: `"EC-prime256v1"` → `:ec`; `"RSA-2048"` → `:rsa`; anything else → `nil`.
Uses pinned constants `+token-algo-ec+` / `+token-algo-rsa+` from `constants.lisp`.

`select-suite-for-identities` (T5, `suites.lisp`) wraps `%cert-algo->kind` + `select-auth-suite`:
derives both cert kinds from the local `identity-handle` token and the remote IdentityToken
octets; returns `nil` (reject this remote) when EITHER kind is `nil` or the kinds yield no
common suite.  This keeps the `nil`-handling co-located with `%cert-algo->kind` so the
manager never passes `nil` to `select-auth-suite` (whose ftype is `(member :ec :rsa)`).

### Lock discipline

- All `auth-remote` reads/mutations are under the per-participant `auth-manager-state` lock.
- `%am-on-authenticated` does only in-lock work (derive KxKey, generate/stash `local-km`,
  drain pending-ct list) and RETURNS a send-needed flag; the actual PSM send and
  `resume-parked-matches` happen OUTSIDE the lock.
- `resume-parked-matches` is always called outside the manager lock (it takes the node lock
  internally).
- Lock ordering is always manager → node; no cycle.

---

## Data flow (end-to-end)

1. `create-participant :domain D :identity id-handle` → `dp-auth-state` set; SPDP
   carries `PID_IDENTITY_TOKEN` + PSM bits 22/23; `%install-auth-manager` wires three hooks.
2. SPDP discovery: `%record-participant` detects a new security-capable remote (non-nil
   `identity-token-octets`) → fires `on-participant-discovered` OUTSIDE the lock.
3. Auth manager `%am-on-participant-discovered` → `select-suite-for-identities` → role by
   §8.7.2.4 GUID prefix ordering (`%prefix-lex<`; deterministic, complementary on both peers).
4. Requester: `begin-handshake-request` → `%am-send-handshake` → PSM wire.
   Replier: `on-stateless-message` hook → `parse-generic-message` + `dds.sec.auth` dispatch →
   `dataholder->handshake-token` → `begin-handshake-reply` → PSM wire.
5. Three-message PKI-DH handshake (ADR 0032 / ADR 0033 state machine) → both `:authenticated` →
   **SharedSecret** (32 bytes, foreign buffer).
6. Both sides: `derive-kx-key` (challenge assignments per §9.5.3, swapped per label).
7. `%am-get-or-create-writer-km` → `generate-writer-key-material` (once per writer GUID) →
   `serialize-crypto-token` (KxKey-encrypted 88-byte KeyMaterial; random 12-byte nonce;
   empty AAD) → `make-crypto-token-message` → PSM wire (`dds.sec.participant_crypto_tokens`
   class_id).
8. Peer: `on-stateless-message` → `parse-generic-message` + `dds.sec.participant_crypto_tokens`
   dispatch → `parse-crypto-token-message` (decrypt + authenticate; fail-closed on any
   tamper) → install `remote-km` in `auth-remote`.
9. Both authenticated AND `remote-km` non-nil → `:keyed` (under lock) → install
   `crypto-keys` resolver on `crypto-transform` → `resume-parked-matches` (OUTSIDE lock) →
   endpoints match.
10. Publisher `publish-sample`: `encode-key-fn(local-writer-guid)` → `encode-serialized-payload
    (km plaintext)` → AES256-GCM sealed DATA on the wire.
11. Subscriber `%deliver-user-sample`: `decode-key-fn(remote-writer-guid)` →
    `decode-serialized-payload(km secured-bytes)` → plaintext delivered; nil on any GCM
    auth failure (fail-closed drop, no plaintext leak).

---

## KAT note (published primitives; no end-to-end DDS KxKey vector)

The KxKey/KxSalt KDF is composed from two published primitives:

| Primitive | Source | Test |
|---|---|---|
| HMAC-SHA256 — TC1 | RFC 4231 §4.2 | `run-auth-keymaterial-roundtrip` (`derive-kx-key` composition path; key=RFC 4231 TC1 key, data=RFC 4231 TC1 data, expected=RFC 4231 TC1 expected) |
| HMAC-SHA256 — TC4 | RFC 4231 §4.5 | same test |
| AES-256-GCM AEAD-wrap / open | NIST SP 800-38D TC16 (via `dds.dare:aes-256-gcm-seal/open`, ADR 0025) | `run-dare-aes-gcm-kat-test` |

**No published end-to-end DDS-Security KxKey test vector is known to exist** (Fast DDS has
the AEAD calls commented out; RTI Connext vectors are proprietary).  The KAT strategy is:
verify each component primitive against an external published vector, then prove the
composition is self-consistent on both Clasp and SBCL (cross-impl check).  The `kx-key-bytes`
result is used to encrypt a known `key-material` CDR blob; the decrypted result is checked
to be byte-identical to the original.  This is honest, not overclaimed.

---

## Honest interop posture and Slice-5 carries

**Achieved this slice (our-to-our):** two security-enabled participants discover each other
on SPDP, complete the §8.7.2.4 PKI-DH handshake over the PSM wire, derive the KxKey,
exchange KxKey-encrypted §9.5.2 KeyMaterial, both reach `auth-remote` `:keyed`, endpoint
matching is resumed, and encrypted DATA with the exchanged keys flows pub→sub and is
decrypted correctly.  `make-test-key-material` is no longer on the live path.

**Do NOT interpret this ADR as "cross-vendor authentication + key-exchange interop verified."**

The following items are explicitly deferred to Slice 5:

### Carry 1 — KxKey-AEAD wrap details (NEEDS-VERIFICATION vs Connext)

Fast DDS sends KeyMaterial **in plaintext** (`AESGCMGMAC_KeyExchange.cpp` has the AEAD
calls commented out).  This implementation is **spec-conformant per §9.5.3 intent**
(KxKey-encrypted, never in the clear).  The AES-GCM nonce is a fresh random 12 bytes
per wrap; AAD is empty (conservative; context is implicit from the DataHolder
`class_id` and property name).  The wire blob is `nonce(12) || ciphertext(88) || tag(16)`
= 116 bytes inside the DataHolder value field.  The nonce/AAD choices are our-to-our
self-consistent.  **NEEDS-VERIFICATION vs a live Connext-Security peer at Slice 5** —
we do not know Connext's AEAD nonce source or AAD for the KeyMaterial wrap.

### Carry 2 — Full reliable ParticipantVolatileMessageSecure endpoint (§8.8.4)

§8.8.4 defines a reliable builtin endpoint for CryptoToken exchange
(`ParticipantVolatileMessageSecure`).  This implementation carries CryptoTokens over the
**existing best-effort PSM stateless transport** (the same endpoint used for handshake
tokens) with a simple pending-list buffer on the receiver side.  On loopback this is
sufficient (test stable 3×/impl both impls).  The full reliable resend mechanism is the
**Slice-5 carry** that also enables cross-vendor robustness.

### Carry 3 — §9.5.2 KeyMaterial CDR framing (NEEDS-VERIFICATION vs Connext)

The 88-byte KeyMaterial CDR uses **Fast DDS's `{3-zeros, 1-byte-length}` framing**
for the `master_salt` and `master_sender_key` sequence fields (T0 spike §3.2 / Fast DDS
`KeyMaterialCDRSerialize`), not the standard CDR `uint32` sequence-length encoding.  For
our-to-our this is self-consistent.  **Cross-vendor Connext verification is Slice 5.**

### Carry 4 — KeyMaterial master key/salt in GC-heap (HARDENING-GAP) — RESOLVED for the MASTER slots (WP-SECURITY-KEYMATERIAL-HARDEN, 2026-07-02)

**RESOLVED (master slots).**  The `key-material` struct (`src/dds-security/key-material.lisp`)
now holds its three MASTER secret byte slots — `master-salt`, `master-sender-key`,
`master-receiver-specific-key` — in FOREIGN/STATIC (off-GC-heap, non-moved, SAP-addressable)
memory via `dds.dare:octets->secret` (the Lisp-vector companion to the ADR 0025 / ADR 0032
`free-secret-octets` secret discipline).  `make-key-material` hardens these master slots at
construction.  A moving GC can no longer copy the master secrets, freed heap cannot linger with
them, and they are reliably wiped-then-freed on teardown (operating contract NFR-MEM /
CNSA-2.0 data-at-rest).

**Derived session-key caches are EPHEMERAL GC-HEAP (by design, NOT foreign-static).**  The
`cached-session-key`, `cached-recv-session-key` and `cached-recv-master-key` slots hold plain
GC-heap vectors — re-derivable per `session_id` from the master secrets, short-lived,
GC-reclaimed; they are NOT long-lived secrets-at-rest.  Storing a fresh foreign-static copy per
`session_id` (as an intermediate A2 revision did) was UNSAFE: the cache-miss path `setf`s a new
foreign buffer without freeing the prior, so a `session_id`-varying peer — reachable PRE-AUTH,
since `%km-session-key-at` runs before the GCM auth check and a hostile peer sets an arbitrary
`session_id` per datagram — would UNBOUNDEDLY leak un-wiped foreign key buffers (a foreign-static
memory-exhaustion DoS plus a key-hygiene failure).  Free-on-replace is NOT a fix either: the
lock-free hit path hands the slot pointer to a concurrent GCM open, so freeing on replace is a
use-after-free.  The correct representation is therefore plain GC-heap (the pre-A2 form):
ephemeral, re-derivable, GC-safe, no leak.

**Fail-closed zeroized guard.**  `%km-session-key-at`, `%km-receiver-session-key-at` and
`km-receiver-descriptor-list` — the entry points that read the freed MASTER secrets — check
`key-material-zeroized` FIRST and signal `key-material-zeroized-error` on a torn-down KM, so a
zeroized KM is structurally unusable rather than a use-after-free of its freed master buffers
(defense-in-depth beyond the quiescent-teardown contract; a single flag check off the zero-alloc
hit path).  For `km-receiver-descriptor-list` this is a SIGNAL, not a NIL return: a NIL descriptor
reads as origin-auth-disabled, so returning NIL for a zeroized origin-auth KM would be a fail-OPEN
gate bypass.

**Zeroize-on-teardown.**  A single choke `zeroize-key-material` (idempotent, fail-closed via a
`zeroized` marker) WIPES-then-frees the three MASTER slots and DROPS (nils, GC-reclaims — no
wipe/free needed) the ephemeral heap caches.  Every free path funnels through it at a QUIESCED
data path: the crypto-manager's `all-kms` roster (covering even re-key-orphaned KMs, never freed
mid-run → no use-after-free) is walked by `cm-teardown` from `delete-participant` after
`stop-node` joins the receiver thread; the disc-node's PVMS bootstrap KeyMaterials
(KxKey/KxSalt-derived) are wiped in `stop-node`.  The producers (`generate-key-material`,
`%parse-km`, `%pvms-derive-bootstrap-km`) wipe their transient heap secrets after the copy.

**Wire + crypto UNCHANGED** — a storage-representation change only; the byte-exact corpora,
the NIST AES-GCM KAT, and the KDF/roundtrip tests are all unchanged.  `make mem` stays
`0.0000` (the static alloc is at key-material creation; the derived-cache miss is now a GC-heap
alloc off the steady-state hot path; the A1/ZA-1 zero-alloc arms AND the session-key steady-state
HIT path are unaffected — still a slot load).  Proven by `run-security-keymaterial-harden-test`
(master slots foreign-static + zeroize-on-free wipe; derived caches GC-heap; a `session_id`-rotation
no-leak sweep over many distinct session_ids; the fail-closed guard on all three entry points;
idempotency), green on SBCL and Clasp.  On SBCL the off-heap discrimination uses
`sb-ext:heap-allocated-p`; on Clasp/Boehm the GC is non-moving (no foreign/off-heap
sub-representation) so the WIPE is the master-slot hardening evidence — documented in the
`dds.pal:static-vector-p` per-impl docstrings (NFR-PORT).

**MINOR-4 — remote-KM drop-on-unmatch (RESOLVED for the active tables + prompt secret-wipe;
WP-SECURITY-CARRIES-BATCH, 2026-07-03).**  When a REMOTE participant leases out (`%lease-sweep` fires the new
`disc-node-on-participant-lost` hook), `cm-forget-remote-participant` DROPS that peer's KeyMaterials from the
FOUR ACTIVE lookup registries (`remote-participant-crypto`, `remote-entity-crypto`, `key-id-index`,
`remote-key-id-entity`) — so a lost peer's keys are UNRESOLVABLE (fail-closed) and a peer-churning participant's
data-path lookup tables stay BOUNDED — and WIPES each dropped KM's master secrets IN PLACE
(`wipe-key-material-secrets`: fill-0, prompt hygiene, so key material does not linger until teardown).  The KM
handle is deliberately KEPT in `all-kms` so its foreign-static master buffers are freed EXACTLY ONCE at the
QUIESCED participant teardown (`cm-teardown`, after the receiver thread is joined): freeing on lease-out would
USE-AFTER-FREE a concurrent in-flight decode (a lease-expired peer's delayed/replayed datagram resolved before
the drop) — the no-mid-run-free invariant.  So `all-kms` still holds one WIPED (secret-free) tiny handle per
churned peer until teardown — the security concern (lingering key material) is fully resolved; the residual is
the deferred foreign free, the price of UAF-safety.  Proven by `%cm-forget-remote` (in
`run-security-crypto-manager-test`): register → forget → asserts the master secrets are zero, the peer is
unresolvable (bounded), the handle is retained in `all-kms`, an unrelated peer is untouched, and a second forget
is a no-op.

### Carry 5 — Full 3-participant end-to-end test (DEFERRED)

A 3-participant end-to-end test requires a third identity cert fixture and additional
harness plumbing; deferred to Slice 5.  The single-per-writer-KM invariant (one
`key-material` instance per writer GUID, shared across all auth-remote entries) is proven
structurally at 2 participants by the `kpub-single-writer-km` `(eq ...)` assertion:
the encode resolver returns the identical object stored in `writer-km-table`, not a
newly generated copy.  Note: decode resolves the remote KeyMaterial per-participant (by
the 12-octet GUID prefix), not per remote-writer EntityId / sender_key_id — correct under
the current one-DataWriter-per-participant v1 invariant, but a participant with more than
one remote writer would mis-resolve; per-writer decode resolution is a follow-on.

### Carry 6 — RTPS/submessage protection

This stack implements §9.5.3.3 **serialized-payload protection** (from Slice 1,
ADR 0031): the DATA submessage's serialized payload is sealed/opened.
RTPS-level submessage protection (sealing the entire submessage or the RTPS message
body) is outside scope for this slice — a later work package.

### Carry 7 — Live RTI Connext-Security interop (the P6 exit gate — Slice 5)

A live PKI-DH handshake + key-exchange + encrypted DATA exchange against a running
RTI Connext-Security stack has NOT been performed.  It requires the licensed Security
Plugins add-on (`rti_connext_dds_secure_plugins` / `libnddssecurity.dylib`), which is
not installed in this environment.  This is the **P6 exit gate**.

---

## Tests

| Test | What it proves | Added in |
|---|---|---|
| `run-auth-suite-selection-test` (extended) | `%cert-algo->kind` EC/RSA/unknown; round-trip: string → kind → `select-auth-suite` → suite | T1 |
| `run-auth-negatives-test` N9 (N9a/N9b) | algo-vs-suite guard: cross-suite FFDH request to ECDH replier → nil; kagree-only mismatch → nil; guard proven non-vacuous (guard-removed run shows failure) | T1 |
| `run-auth-keymaterial-roundtrip` | KxKey derivation (RFC 4231 TC1+TC4 HMAC primitives); KeyMaterial CDR round-trip; wrong-KxKey → NIL; tampered-ciphertext → NIL; empty → NIL; wrong-class_id → NIL; 2-DataHolder → NIL; `kpub-single-writer-km` `(eq ...)` | T2/T3/T6 |
| `run-auth-cryptotoken-fuzz` | 2000 blobs × 2 parsers (normal + safety-0) = 8000 parse calls, all NIL, 0 crashes | T3 |
| `run-auth-gate-compose-test` | `:incompatible` → 0 matches; `:pending` → park then resume; `:compatible` → match fired | T4 |
| `run-auth-manager-handshake-test` | Two `create-participant :identity` → both reach `auth-remote` `:keyed` with the other's writer `key-material` installed (NON-VACUOUS: not `:keyed` before the exchange) | T5 |
| `run-auth-encrypted-pubsub-keyx-test` | A→B with exchanged keys: `crypto-keys` resolver set; encode-km = table-km `(eq)`; **ciphertext on wire** (plaintext absent + header bytes `#(0 0 0 4)` per §9.5.3.3.1 Table 69); B receives byte-exact plaintext; NO `make-test-key-material` anywhere | T6+T7 |
| `run-auth-secured-refuses-plain-test` | Security-enabled participant refuses plain peer (matched-count = 0); non-vacuous: plain↔plain matches (C↔D control); preconditions asserted first | T7 |
| `run-auth-plain-byte-identical-test` | Plain participants byte-identical with security build on path; 8-byte `"PLAINDAT"` delivered exactly | T7 |

Clasp 337 + SBCL 337.  All gates green at T7 (T8 gate sweep appended in §Consequences).

---

## §M7 roadmap update

| Slice | Description | Status |
|---|---|---|
| 1 | Crypto plugin: AES256-GCM `SecuredPayload` + session-key KDF (ADR 0031) | LANDED |
| 2a | Authentication plugin: PKI identity + §8.7.2.4 PKI-DH handshake → SharedSecret, both §9.3 suites, our-to-our (ADR 0032) | LANDED |
| 2b-i | Wire transport: SPDP IdentityToken + PSM endpoints + DataHolder/envelope codec + our-to-our handshake over UDP (ADR 0033) | LANDED |
| **2b-ii + 2c (this ADR)** | Auth manager: on-discovery trigger + auth-remote state machine + strict endpoint gate + KxKey KDF + per-writer KeyMaterial exchange + exchanged-key resolver | **LANDED** |
| 3 | AccessControl plugin (§8.8): governance/permissions XML, topic-level enforcement | pending |
| 4 | Secure discovery: SPDP/SEDP participant/endpoint authentication | pending |
| 5 | Connext-Security live interop (P6 exit gate; RTI Security Plugins required) | pending |

---

## Consequences

- **NFR-MEM:** `make mem` stays **0.0000** bytes/sample.  The security path is control-plane
  and off the measured CDR hot path.  The `crypto-keys` resolver dispatch in `publish-sample`
  and `%deliver-user-sample` adds one `typep` check on the secured path; the no-crypto path
  (`crypto-transform nil`) is unchanged.
- **NFR-SEC-POSTURE:** `parse-crypto-token` and `parse-crypto-token-message` are
  bounds-checked at every length/count field; `run-auth-cryptotoken-fuzz` proves no OOB,
  crash, or partial parse on 8000 calls (2000 × 2 parsers × 2 safety levels) at
  `(safety 0)`.  Fail-closed on wrong key, tamper, or malformed input.
- **FR-SEC-2:** no hand-rolled crypto.  KxKey KDF = `dds.dare:sha-256` + `dds.dare:hmac-sha256`
  (OpenSSL `EVP_Q_mac`); AES-GCM wrap = `dds.dare:aes-256-gcm-seal/open` (ADR 0025);
  KeyMaterial generation random bytes via `dds.dare:random-bytes`.
- **NFR-PORT:** no reader conditionals in `src/dds-security/` or `src/dds-disc/` or
  `src/dds-dcps/auth-manager.lisp`.  `gate-hotpath(8)` unaffected.
- **Default-OFF:** a participant without `:identity` is byte-identical plain and has no
  auth-gate overhead.
- **Gates (T8 gate sweep):** appended when the gate sweep completes (§Task 8 report);
  expected: `build` PASS; `test-clasp` 337+ PASS; `test-sbcl` 337+ PASS; `gate-hotpath`
  PASS; `gate-types` PASS; `mem(0.0000)` PASS; `fuzz` PASS.

---

## References

- T0 spike: `docs/superpowers/spikes/2026-06-26-dds-security-keyexchange.md`
- Design spec: `docs/superpowers/specs/2026-06-26-dds-security-auth-keyx-design.md`
- `src/dds-security/auth/keyexchange.lisp` — KxKey KDF, KeyMaterial CDR, CryptoToken codec
- `src/dds-security/auth/suites.lisp` — `%cert-algo->kind`, `select-suite-for-identities`
- `src/dds-security/auth/handshake.lisp` — algo-vs-suite cross-check guards (T1)
- `src/dds-security/key-material.lisp` — `crypto-keys` struct + `%wrap-km-as-resolver`
- `src/dds-dcps/auth-manager.lisp` — auth manager orchestrator
- `src/dds-dcps/entities.lisp` — `dp-auth-state`, `create-participant :identity`
- `src/dds-disc/disc.lisp` — `on-participant-discovered`, `auth-gate`, `auth-state` slots;
  `%consult-auth-gate`; `%record-participant` discovery trigger; `%lease-sweep` cleanup
- `src/dds-disc/dataplane.lisp` — `crypto-keys` dispatch (encode/decode)
- `src/dds-disc/stateless-message.lisp` — raw-envelope `%on-stateless-message` (Decision 1)
- `src/dds-tests/security-auth-test.lisp` — all WP-DDS-SECURITY-AUTH-KEYX test functions
- `interop/security-auth-keyx/README.md` — our-to-our e2e harness + environment-limited
  Connext-Security deferral (Slice 5)
- ADR 0033 — Slice 2b-i (the PSM wire transport extended by this slice)
- ADR 0032 — Slice 2a (the in-process handshake)
- ADR 0031 — Slice 1 (the `crypto-transform` slot wired here to the exchanged-key resolver)
- ADR 0025 — DARE (the `dds-dare` OpenSSL FFI)
