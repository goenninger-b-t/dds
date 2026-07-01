# ADR 0036 — DDS-Security Secure Discovery: submessage + whole-RTPS protection, origin-auth, reliable PVMS, governance protection-kinds (Slice 4)

- **Status:** Accepted (M7/P6; WP-DDS-SECURITY-SECURE-DISCOVERY, 2026-06-28)
- **Relates to:** ADR 0035 (Slice 3 — AccessControl; the governance struct extended here and the
  permissions-gate this slice composes with); ADR 0034 (Slice 2b-ii + 2c — the auth manager + KxKey +
  per-writer KeyMaterial exchange, whose interim best-effort PSM crypto-token path this slice replaces
  with reliable PVMS); ADR 0033 (Slice 2b-i — the PSM `DataHolder`/`ParticipantGenericMessage` wire codec
  reused for the crypto-token exchange; **the propagate-byte carry re-opens this ADR — Slice 5**); ADR 0032
  (Slice 2a — the PKI-DH handshake → SharedSecret the PVMS bootstrap key derives from); ADR 0031 (Slice 1 —
  the byte-exact `crypto.lisp`/`transform.lisp` serialized-payload codec the shared `crypto-header.lisp`
  factors out, and the deferred crypto-data-path arena migration picked up at T10); ADR 0025 (DARE — the
  `dds-dare` AES-256-GCM / HMAC-SHA256 OpenSSL FFI; FR-SEC-2 no hand-rolled crypto); NFR-SEC-POSTURE
  (bounds-checked fail-closed parsers, fuzzed); NFR-MEM (the rtps/submessage data path); NFR-PORT (Clasp +
  SBCL both validate, Clasp first; no reader conditionals outside `dds-pal/`).
- **Standards:** OMG DDS-Security 1.1 §7.3.7 (the secure RTPS submessage element model — `SEC_PREFIX`,
  `SEC_BODY`, `SEC_POSTFIX`, `SRTPS_PREFIX`, `SRTPS_POSTFIX`); §7.4.4 (`ParticipantGenericMessage`); §7.4.5 /
  §9.5.1.3 (the secure builtin EntityIds); §7.4.6.1 Table 28/29 (the `BuiltinEndpointSet` security bits
  16–27); §8.5.1.7–.9 (`encode/decode_datawriter_submessage`, `encode/decode_datareader_submessage`);
  §8.5.1.10–.12 (`encode/decode_rtps_message`); §9.4.1.2 (the Governance `ProtectionKind` /
  `BasicProtectionKind` model + `dds_governance.xsd`); §9.5.2 (`KeyMaterial_AES_GCM_GMAC`); §9.5.2.2 /
  §9.5.3 (the CryptoToken exchange + KxKey/KxSalt + session-key/receiver-key derivations §9.5.3.3.4); §9.5.3.1
  (the SharedSecret-derived ParticipantVolatileMessageSecure bootstrap key). The T0 spike
  (`docs/superpowers/spikes/2026-06-27-dds-security-secure-discovery.md`) is the pinned-value reference; every
  constant is dual-corroborated against eProsima Fast DDS (Apache-2.0, read for understanding only) and the
  tshark RTPS-security dissector. **No RTI Connext source, headers, or generated code was ever read.**

---

## Context

ADR 0034 (Slice 2b-ii + 2c) delivered the complete secure-participant vertical slice: a security-enabled
participant authenticates every discovered security-enabled peer (§8.7.2.4 PKI-DH → SharedSecret), derives
the §9.5.3 KxKey, exchanges §9.5.2 per-writer KeyMaterial, gates endpoint matching strictly on
authentication, and encrypts the **serialized payload** of user DATA (§9.5.3.3, the Slice-1 codec) with the
exchanged keys. ADR 0035 (Slice 3) added the AccessControl policy layer.

What was still in the clear: the **discovery traffic itself** (SEDP endpoint announcements, the WLP
liveliness assertions, the SPDP re-announce) and **every RTPS submessage except the user payload region**.
An eavesdropper could read the full domain topology (every topic, type, QoS, partition) and a forger could
inject control-plane submessages (a spoofed `GAP` suppresses samples; a spoofed `ACKNACK` purges a writer's
unacked history) — none of which serialized-payload protection touches.

Secure discovery (DDS-Security 1.1 §7.3.7 + the §8.5 Cryptographic plugin beyond Slice-1) closes this. It is
the widest M7 slice by deliberate owner decision (2026-06-27): submessage protection + whole-RTPS-message
protection + receiver-specific MACs (origin authentication), a reliable `ParticipantVolatileMessageSecure`
endpoint carrying the crypto-token exchange, the Governance protection-kind model, and the wiring of the
secure builtin discovery endpoints. It was built as one branch but as eleven internal vertical increments
(T1–T11 + T-RECONCILE + T-ORIGINAUTH), each independently testable with its own two-stage review gate.

This ADR documents the **WP-DDS-SECURITY-SECURE-DISCOVERY** work package: Slice 4 of the five-slice M7/P6
roadmap. **Per owner decision 2026-06-28, Slice 4 ships now (our-to-our complete; live Fast DDS bidirectional
SPDP discovery + four conformant fixes). Full cross-vendor `auth → keyed → secure-SEDP → protected data`,
the slice-wide propagate-byte fix, the downstream divergences, and live RTI Connext are Slice 5 — the P6
exit gate.**

---

## Goal

Deliver **secure discovery end-to-end, our-to-our**, governed by the Governance protection-kind policy:

- protect the builtin SEDP endpoint discovery (`discovery_protection_kind`), the participant-message /
  liveliness WLP (`liveliness_protection_kind`), and a secure SPDP re-announce;
- protect the whole RTPS datagram of the user data plane between matched secure participants
  (`rtps_protection_kind`) and **enforce it on receive** (drop forged plain user-plane submessages);
- carry the crypto-token exchange that establishes the `:keyed` relationship over a real **reliable**
  `ParticipantVolatileMessageSecure` endpoint, replacing Slice-2c's interim best-effort PSM path;
- support **origin authentication** (the receiver-specific MAC) on every tier;
- keep the plain (security-OFF) wire **byte-identical** to before (the false-REJECT guard); and
- verify it cross-vendor against a **live Fast DDS-Security peer**, fixing wire divergences this slice.

Demonstrated end-to-end (our-to-our): two security-enabled participants under a signed Governance with
`discovery_protection_kind=ENCRYPT` / `rtps_protection_kind=ENCRYPT` authenticate, exchange crypto tokens
over reliable PVMS, reach `:keyed`, announce the protected topic **only** over secure SEDP (never plain SEDP),
match, and exchange user data protected at payload + whole-RTPS tiers (the user DATA submessage rides
inside the SRTPS-encrypted datagram; per-user-endpoint submessage protection is Carry 4 / not wired) —
with the topic name provably absent from the cleartext. A plain peer is refused non-vacuously.

---

## Approved decisions

Three structural decisions were approved before implementation (design spec §4), each with its rejected
alternative.

### Decision 1 — Crypto-plugin organization: additive, not a refactor

Slice-1's byte-exact `src/dds-security/crypto.lisp` / `transform.lisp` (serialized-payload protection) are
left untouched. The new tiers are added under `src/dds-security/crypto/`:

- `crypto-header.lisp` — the shared `CryptoHeader` / `CryptoContent` / `CryptoFooter` codec, including the
  receiver-specific-MAC list. Reused by all tiers; Slice-1's `SecureDataHeader` is the structural subset, and
  Slice-1's `serialize/parse-secured-payload` were rewired to **delegate** to this codec (DRY; the Slice-1
  corpus is the regression guard, now asserted unconditionally).
- `submessage.lisp` — `encode/decode_datawriter_submessage` + the datareader twins, over one shared
  `%encode-secured-region` / `%decode-secured-region` engine.
- `rtps-message.lisp` — `encode/decode_rtps_message`, thin wrappers on that **same** engine (only the bracket
  kinds, the protected unit, and the SIGN body-walk differ).

*Rejected:* folding all tiers into one module — it churns landed conformant code for no gain and risks a
behaviour drift in the shipped Slice-1 codec.

### Decision 2 — Key management: a dedicated `crypto-manager`

`src/dds-dcps/crypto-manager.lisp`, parallel to `auth-manager.lisp`, owns the §8.5 key registries
(`ParticipantCrypto`, `EntityCrypto`) and the crypto-token exchange over PVMS, driven by the auth state
machine at the `:authenticated → :keyed` edge. It mirrors the spec's plugin split (Authentication vs
Cryptographic). *Rejected:* cramming this into `auth-manager` — that file already owns the handshake + the
per-writer key table; conflating the two plugins hurts both.

### Decision 3 — Reliable PVMS: reuse the existing RTPS reliable engine

The `ParticipantVolatileMessageSecure` endpoint is a reliable, volatile (KEEP_ALL, no durability) builtin
endpoint. It reuses the M2 reliable writer/reader state machine (HEARTBEAT/ACKNACK/GAP) configured with the
secure EntityIds and a volatile history. *Rejected:* a bespoke reliability path — we have a tested reliable
engine; re-implementing it for one builtin endpoint is pure risk.

---

## Architecture

### Layering

The split mirrors the Slice-2/Slice-3 plugin split exactly:

- **The crypto tiers** (Header/Content/Footer codec, submessage, whole-RTPS, the §9.5.3.3.4 derivations) live
  in `dds-security` (`crypto/`). They depend only on `dds-dare` + `dds.core.buffer`. The 4-byte submessage
  header is inlined via `dds.core.buffer` (NOT `dds-rtps`) to keep `dds-security` free of an upward
  dependency — `dds-rtps` → `dds-security`, never the reverse.
- **The crypto-manager** lives in `dds-dcps` (`crypto-manager.lisp`), parallel to `auth-manager.lisp`. It needs
  BOTH `dds-security` (the tiers + key generation) AND `dds-disc` (hooks, send, EntityCrypto resolvers);
  `dds-disc` stays crypto-free.
- **`dds-disc`** gains the reliable PVMS endpoint (`volatile-secure.lisp`), the secure-builtin send/receive
  plumbing, and **cross-layer closure slots** the crypto-manager / access-control install onto the disc-node
  (encode = LOCAL EntityCrypto by entity-id, decode = REMOTE EntityCrypto by the wire `transformation_key_id`,
  the governance-gated protected-topic predicate, the rtps-protection encode/decode resolvers). `dds-disc`
  calls the installed closures and never imports `dds-dcps`.

### Module layout

| File | Responsibility | Increment |
|---|---|---|
| `src/dds-rtps/discovery.lisp` | secure builtin EntityIds + `BuiltinEndpointSet` bits 16–27 (co-located with the existing builtin EntityIds, DRY) | T0 |
| `src/dds-security/crypto/constants.lisp` | §7.3.7 submessage kinds; `+kdf-label-session-receiver-key+`; `ProtectionKind`/`BasicProtectionKind` enums + XSD alist | T0 |
| `src/dds-security/crypto/crypto-header.lisp` | shared `CryptoHeader`(20) / `CryptoContent` / `CryptoFooter` codec + receiver-MAC list; the BE `%put/%get-u32-be` helpers | T1, T-RECONCILE |
| `src/dds-security/crypto/submessage.lisp` | `encode/decode-datawriter-submessage` + datareader twins; origin-auth derivations + per-receiver MAC; the shared region engine | T2, T3 |
| `src/dds-security/crypto/rtps-message.lisp` | `encode/decode-rtps-message` (SRTPS sandwich); the SIGN verbatim-body walk | T4 |
| `src/dds-security/crypto.lisp` | `%derive-labeled-session-key` (the no-counter KDF, both labels); Slice-1 codec now delegates | T-RECONCILE |
| `src/dds-security/access-control/{governance,parser}.lisp` | the protection-kind fields + parser + accessors | T5 |
| `src/dds-security/auth/keyexchange.lisp` | `%serialize/%parse-km-cdr` (88-byte + 120-byte origin-auth CDR); per-writer KM migrated to PVMS | T8, T-ORIGINAUTH |
| `src/dds-dcps/crypto-manager.lisp` | `ParticipantCrypto` + `EntityCrypto` registries; `generate-key-material`; the four resolvers; the token exchange + `:keyed` promotion | T6, T8 |
| `src/dds-dcps/access-control.lisp` | governance → disc-node protection-kind slots; mints origin-auth KMs from governance | T9, T10, T11 |
| `src/dds-disc/volatile-secure.lisp` | the reliable PVMS endpoint + `%pvms-derive-bootstrap-km` | T7 |
| `src/dds-disc/disc.lisp`, `dataplane.lisp` | secure-builtin send/receive; SEC_PREFIX disambiguation; `%maybe-wrap-srtps` + the receive-side rtps_protection enforcement | T9, T10, T11 |

### Wire model (every value pinned in T0, dual-corroborated; structure §7.3.7 / §9.5.3.3)

**Shared crypto elements (`crypto-header.lisp`).**

- `CryptoHeader` (20 octets) = `transformation_kind`[4] ‖ `transformation_key_id`[4] ‖ `session_id`[4] ‖
  `init_vector_suffix`[8]. The 12-byte GCM nonce is `session_id` ‖ `init_vector_suffix`.
  `transformation_kind` = `#(0 0 0 4)` for AES-256-GCM (ENCRYPT), `#(0 0 0 3)` for AES-256-GMAC (SIGN);
  `transformation_key_id` selects which KeyMaterial the receiver decodes with (the O(1) index key).
- `CryptoContent` = `uint32` **big-endian** length ‖ ciphertext (ENCRYPT only; absent for SIGN — the plaintext
  travels verbatim, MAC-only).
- `CryptoFooter` = `common_mac`[16] ‖ `receiver_specific_macs`: `uint32` **big-endian** count ‖
  count × { `receiver_specific_key_id`[4], `mac`[16] }. Count = 0 when origin-auth is off (the footer is then
  byte-compatible with Slice 1).

**Submessage protection** (secure SEDP, secure participant-message, secure SPDP, PVMS):
```
SEC_PREFIX (0x31)    submessage header + CryptoHeader(20)
SEC_BODY   (0x30)    submessage header + CryptoContent          ; ENCRYPT only
                     <original submessage VERBATIM, no SEC_BODY> ; SIGN
SEC_POSTFIX(0x32)    submessage header + CryptoFooter
```

**Whole-RTPS-message protection** (`rtps_protection_kind`):
```
RTPS Header (20)     untouched — the plain SPDP bootstrap stays readable
SRTPS_PREFIX (0x33)  submessage header + CryptoHeader(20)
SEC_BODY    (0x30)   submessage header + CryptoContent          ; ENCRYPT (the encrypted submessage stream)
                     <original submessage stream VERBATIM>       ; SIGN (located by walking to SRTPS_POSTFIX)
SRTPS_POSTFIX(0x34)  submessage header + CryptoFooter
```

**Secure builtin EntityIds** (§7.4.5 / §9.5.1.3) and the `BuiltinEndpointSet` bits (§7.4.6.1):

| Endpoint | Writer / Reader | SPDP bits |
|---|---|---|
| secure SEDP publications | `0xff0003c2` / `0xff0003c7` | 16 / 17 |
| secure SEDP subscriptions | `0xff0004c2` / `0xff0004c7` | 18 / 19 |
| secure participant-message (WLP) | `0xff0200c2` / `0xff0200c7` | 20 / 21 |
| ParticipantStatelessMessage (PSM, plain) | `0x000201c3` / `0x000201c4` | 22 / 23 |
| ParticipantVolatileMessageSecure (PVMS) | `0xff0202c3` / `0xff0202c4` | 24 / 25 |
| secure SPDP re-announce | `0xff0101c2` / `0xff0101c7` | 26 / 27 |

**Cross-vendor wire reconciliation (T-RECONCILE, owner-directed, pulled forward from T12).** Two
foundational AES-GCM-GMAC divergences sat under *every* tier (and the shipped Slice-1 payload codec), so they
were fixed before the corpus grew: (1) `%derive-labeled-session-key` **drops** the `"0001"` KDF counter that an
earlier reading appended — Fast DDS `compute_sessionkey` and Cyclone `crypto_calculate_session_key` both hash
exactly `id_string ‖ master_salt ‖ session_id`; (2) the `CryptoFooter` `receiver_specific_macs` count is
**big-endian** on the wire (and a Step-2 audit found the `CryptoContent` length sibling is BE too). Both are
corroborated clean-room against Fast DDS **and** Eclipse Cyclone DDS (they agree); the OMG PDF could not be
located in-repo, so the value rests on dual-vendor corroboration (carried). The private `%put/%get-u32-be`
helpers force BE via a save/set/restore under `unwind-protect`, leaving the frozen `dds.core.buffer` contract
untouched. Every ENCRYPT corpus vector was regenerated with real `equalp` literal assertions.

### Key model

**KeyMaterial (§9.5.2 `KeyMaterial_AES_GCM_GMAC`).** Reuses the KEYX struct: `transformation_kind`[4] ‖
`master_salt`(32) ‖ `sender_key_id`[4] ‖ `master_sender_key`(32) ‖ `receiver_specific_key_id`[4] ‖
`master_receiver_specific_key`(seq). KEYX left the receiver fields empty (88-byte CDR); origin-auth populates
them (`receiver_specific_key_id` ≠ 0 + a 32-byte `master_receiver_specific_key` ⇒ the 120-byte CDR). The
`%serialize/%parse-km-cdr` codec keys the form on the same `has_specific_key` discriminator Fast DDS uses; the
88-byte no-origin-auth form is byte-identical to before.

**Registries (owned by `crypto-manager`).**

- **ParticipantCrypto** — one master KeyMaterial the local participant generates for `rtps_protection`, plus,
  per matched remote, the remote's ParticipantCrypto KeyMaterial. Encode-our-datagrams uses local; decode
  theirs uses remote (resolved by the source GUID-prefix).
- **EntityCrypto** — one KeyMaterial per local secure builtin endpoint (secure SEDP pub/sub W+R, secure
  participant-message, secure SPDP) and per matched-remote endpoint, keyed for O(1) lookup by
  `transformation_key_id`.

**Derivations (§9.5.3.3.4).**

- Session key = `HMAC-SHA256(master_sender_key, "SessionKey" ‖ master_salt ‖ session_id)` (Slice-1
  `derive-session-key`, reused via the shared `%derive-labeled-session-key`).
- Receiver-specific session key (origin-auth) =
  `HMAC-SHA256(master_receiver_specific_key, "SessionReceiverKey" ‖ master_salt ‖ session_id)` — the same
  framing helper, only the label differs (`+kdf-label-session-receiver-key+`).
- The per-receiver MAC is a pure GMAC under that key:
  `AES-256-GCM(recv_session_key, nonce = the common_mac's 12-octet IV, AAD = common_mac, plaintext = empty)`.
  The nonce-equals-the-common_mac-IV point is load-bearing and was corroborated against Fast DDS
  `serialize_SecureDataTag`.

**Origin-auth key direction (§9.5.3.3.4.3, the subtle point).** The receiver-specific MAC uses the
**RECEIVER's** key. Sender A, for each matched remote B, computes a GMAC with B's
`master_receiver_specific_key` (received in B's crypto token) tagged with B's `receiver_specific_key_id`; B
verifies with its OWN local receiver key. So `encode :receivers` = the matched-remote **readers'** receiver
keys, and `decode :my-receiver-key` = the LOCAL reader's key. Both sides derive the receiver session key under
the **sender KM's** `master_salt` + the receiver key + `session_id`. The decoder, when a receiver key is
supplied, MUST find its own footer entry, recompute the GMAC, and **constant-time** compare — an absent entry
or a mismatch fails closed **even though the common_mac is valid** (stricter than Fast DDS, which accepts an
empty footer).

**PVMS bootstrap (§9.5.3.1).** The PVMS endpoint is submessage-protected (ENCRYPT) with a KeyMaterial derived
**directly from the SharedSecret** — no exchange needed (it is the endpoint that *carries* the other tokens):
`master_salt` = `derive-kx-salt`, `master_sender_key` = `derive-kx-key` (the SAME §9.5.3 KDFs the KEYX tier
wraps tokens with — byte-identical to Fast DDS `create_kx_key`), `sender_key_id` = `#(0 0 0 0)`. The
crypto-token DataHolders ride as plaintext *inside* those protected PVMS submessages — the conformant
replacement for Slice-2c's interim app-level KxKey-encryption over best-effort PSM.

**Per-role nonce disjointness (T8 — a correctness crux).** The bootstrap KM is symmetric across the pair and
the non-PVMS codec uses a fixed all-zero `session_id`; a bidirectional exchange under that key from
`iv-counter` 0 would **reuse AES-GCM nonces (catastrophic)**. `%pvms-role-session-id` gives each role a
distinct non-zero `session_id` (winner = lexicographically-greater GUID prefix → `base-1`, loser → `base`;
`base = #x80000000 | fold(winner)`), threaded into the PVMS encode path → distinct keys **and** disjoint nonce
spaces both directions. The non-PVMS tiers keep the fixed `session_id` (the byte-exact corpus is unchanged).
An on-wire guard parses the actual encoded `session_id` (offset 12) so a revert to the fixed value fails
loudly. (Corroborated against Fast DDS `register_matched_remote_participant` `max()` / `-=1`; whether our
`base` matches Fast DDS's exact operand for the no-reuse property cross-vendor is a Slice-5 carry — decode
interop is fine, the value is self-describing on the wire.)

**Crypto-token classes (§9.5.2.2 / §7.4.4).** Reuses the KEYX CryptoToken DataHolder codec with the three
`message_class_id`s `dds.sec.{participant,datawriter,datareader}_crypto_tokens`, all flowing over reliable
PVMS. KEYX's per-writer KeyMaterial was **migrated** from the best-effort PSM path (carried under
`participant_crypto_tokens`) to PVMS under `datawriter_crypto_tokens`; the old PSM token branch + the
per-writer table were removed (PSM is now handshake-only), and the Slice-2c tests moved with it.

### Governance protection-kind model (T5)

The Slice-3 `governance` struct gains domain-rule `discovery_protection_kind` / `liveliness_protection_kind`
/ `rtps_protection_kind` (`ProtectionKind`, 5 values: `:none` / `:sign` / `:encrypt` /
`:sign-with-origin-auth` / `:encrypt-with-origin-auth`) and topic-rule
`enable_discovery_protection` / `enable_liveliness_protection` (bool) + `metadata_protection_kind` /
`data_protection_kind` (`BasicProtectionKind`, 3 values). The parser maps the XSD token via the T0
`+protection-kind-xsd-strings+` reverse-lookup with a `(member kw valid-kinds)` tier guard (the 5-value
domain kinds vs the 3-value per-topic kinds). Accessors resolve the effective kind per domain + per topic.

**Fail-closed (the T5 Critical, caught + fixed in review).** A *missing required* protection-kind element used
to return a hard-coded `:sign`/`:encrypt` default with a *fabricated* "XSD default" docstring citation — but
the XSD declares these elements REQUIRED and Fast DDS REJECTS them absent. The fix:
`%ac-node-protection-kind` returns NIL on absent → `parse-governance` aborts to NIL; every fabricated citation
was purged; the topic-rule initforms are documented as **constructor defaults, NOT spec defaults**.

`protection-kind-base` (`dds.security`) maps a `ProtectionKind` to its base kind (`:sign` | `:encrypt`) + an
origin-auth flag, so the announce/encode paths honour SIGN-vs-ENCRYPT-vs-origin-auth from governance rather
than hard-coding one (the T9 Important fix).

### The `:authenticated → :keyed` state machine

`auth-remote` keeps its Slice-2 shape (`none → handshaking → authenticated → keyed → rejected`). The
`:authenticated → :keyed` edge is now mediated by the crypto-manager (`cm-on-authenticated`): register the
local ParticipantCrypto + builtin EntityCryptos → exchange Participant/DW/DR tokens over reliable PVMS →
install the remote tokens → `%cm-try-promote` to `:keyed` only when the participant + secure-SEDP pub-W +
secure-SEDP sub-R are all installed. Only at `:keyed` does `rtps_protection` engage and secure-SEDP matching
proceed. The Slice-2 gate ladder's existing `:keyed` precondition enforces this; its *meaning* deepened to
"crypto established" — no new gate. (Adding the four PM/SPDP tokens to the local token set does NOT widen the
promotion precondition, so keying never hangs against a liveliness-unprotected peer — reviewer-verified.)

### What is protected, and when

```
plain SPDP            always clear (carries the Identity/Permissions tokens; rtps-protection-exempt pre-keying)
PSM handshake         always clear (the §8.7 auth bootstrap, exempt)
PVMS                  submessage-protected (ENCRYPT) with the SharedSecret-derived bootstrap key
once :keyed →
  user data plane     rtps_protection (SRTPS) when rtps_protection_kind ≠ NONE  (+ receive-side enforcement)
  secure SEDP         discovery_protection_kind, for topics with enable_discovery_protection
  secure participant-msg (WLP)  liveliness_protection_kind  (plain WLP fully suppressed when protected)
  secure SPDP         re-announce over the protected channel (plain SPDP still bootstraps)
```

A protected topic's endpoints are announced **only** over secure SEDP (the `topic-discovery-protected-p`
partition), never plain SEDP — otherwise an outsider reads the topology. The whole secure path sits behind
the same NIL-checks the Slice-2 gate ladder uses: no governance, or every kind = NONE → no secure bits in the
`BuiltinEndpointSet`, the crypto resolvers return NIL, plain SPDP/SEDP exactly as before — **the plain wire
does not change a byte** (the false-REJECT guard).

### SEC_PREFIX dispatch (one submessage id, five consumers)

The single `SEC_PREFIX` id (0x31) now brackets PVMS (T7), secure SEDP (T9), secure participant-message and
secure SPDP (T11). `%on-secure-submessage` disambiguates by the wire `transformation_key_id`: PVMS's bootstrap
KM `sender_key_id` is hard `#x00000000` and `generate-key-material` mints only NON-ZERO ids, so an all-zero
key-id → PVMS, a non-zero id in the index → the secure-builtin handler, neither → PVMS → GCM-drop
(fail-closed; reviewer-confirmed no misroute). `%on-secure-builtin` decodes **once** (MAC-verified) then
routes by the RECOVERED inner `writerId` (with a `(t nil)` drop default), so a tampered/forged bracket is
dropped before any branch.

### Receive-side `rtps_protection` enforcement (T10 — the two review-caught holes)

The wrap alone is not enough: under `rtps_protection_kind = ENCRYPT`, a forged **plain** datagram spoofing a
keyed peer's source GUID-prefix would otherwise be processed. `%rtps-protection-required-from` (keyed source +
governance `rtps_protection` ≠ NONE) drops every **user-plane** submessage on a non-SRTPS datagram from such a
source: user DATA / DATA_FRAG (discriminated by `%user-writer-entityid-p`, kind `0x02`/`0x03`) **and** the user
reliability-control submessages (HEARTBEAT / ACKNACK / GAP / HEARTBEAT_FRAG / NACK_FRAG). Without the latter, a
forged plain GAP suppresses samples, a forged plain ACKNACK purges unacked history, a forged plain HEARTBEAT
corrupts the reader proxy. **Builtin metatraffic is exempt** (intentionally plain this slice — see Carry 2):
builtin DATA is discriminated by `writerId`, and builtin reliability is routed to its handlers in the clauses
**before** the gated user fall-through, so there is no false-REJECT. Legitimate keyed peers always SRTPS-wrap
their user traffic, so a plain user-plane submessage from a keyed peer cannot legitimately occur. NONE
governance / not-keyed source ⇒ enforcement off, byte-identical delivery.

---

## Data flow / the secure-discovery sequence

1. Two security-enabled participants are configured with identities (Slice 2) + signed Governance/Permissions
   (Slice 3) whose Governance sets the protection kinds. Plain SPDP bootstraps; the §8.7 PKI-DH handshake runs
   over plain PSM → SharedSecret; AccessControl gates the participant.
2. At `:authenticated`, each side derives the PVMS bootstrap KM from the SharedSecret + challenges, enables the
   reliable PVMS endpoint, registers its local ParticipantCrypto + builtin EntityCryptos, and sends its
   Participant/DW/DR crypto tokens over reliable PVMS (HEARTBEAT/ACKNACK-repaired).
3. Each side installs the remote tokens; when participant + secure-SEDP pub-W + sub-R are installed →
   `:keyed` → `resume-parked-matches`.
4. At `:keyed`, `announce-endpoints` partitions: protected topics flow **only** over secure SEDP
   (`0xff0003`/`0xff0004`), submessage-protected per `discovery_protection_kind`, to authenticated peers, OFF
   plain SEDP; the SPDP `BuiltinEndpointSet` carries bits 16–19 only when discovery is protected.
5. A protected `DiscoveredWriter/ReaderData` arrives as a `SEC_PREFIX…SEC_POSTFIX` bracket, is decoded by the
   matched-remote EntityCrypto (resolved by `transformation_key_id`, + the receiver MAC under origin-auth),
   and drives endpoint matching — gated on `:keyed`, fail-closed on any decode error.
6. User data then flows SRTPS-wrapped (T10) when `rtps_protection_kind` ≠ NONE; the receiver decodes by the
   source ParticipantCrypto and re-dispatches, enforcing the drop of any forged plain user-plane submessage.
7. WLP liveliness rides secure participant-message (`liveliness_protection_kind`); a secure SPDP re-announce
   rides the discovery tier (T11).

---

## Conformance & dual-vendor verification (the DoD heart)

Every interop-critical decision (the builtin EntityIds, the submessage kinds, the CryptoHeader/Content/Footer
layout incl. the BE counts, the session-key + receiver-specific-key KDF labels and the dropped counter, the
`message_class_id`s, the extended KeyMaterial CDR, the receiver-specific-MAC input, the PVMS bootstrap-key
derivation, and the builtin-endpoint share-vs-own-key question) is dual-corroborated against Fast DDS
(Apache-2.0, provenance-logged) and the tshark RTPS-security dissector. **RTI Connext source was never read.**
A byte-exact corpus covers every new structure (both endiannesses, all protection kinds incl. origin-auth),
gated like P0.

### Live Fast DDS-Security cross-vendor result (T12, 2026-06-28) — honest posture

A **SECURITY=ON** eProsima Fast DDS v3.6.1 peer was built from the present source on this repo's reused
Identity-CA / Permissions-CA / Governance and run live against our stack over UDP loopback, both directions
(`interop/security-secure-discovery/`, `run-fastdds-interop.sh`, our `run-secure-interop-peer`).

**ACHIEVED cross-vendor:** the SECURITY=ON build; Fast DDS full initialisation against our PKI; **bidirectional
SPDP discovery** (our peer `discovered=2` both directions). Four wire/config divergences were found and **fixed
conformantly** (verified our-to-our, both impls green):

1. **PSM SerializedPayload encapsulation header** — our `ParticipantStatelessMessage` omitted the RTPS 2.5
   §10.2 4-octet CDR_LE header (`00 01 00 00`) a conformant peer prepends/strips (Fast DDS
   `SecurityManager.cpp:933-938`). Fixed symmetric (`%psm-encapsulate` + strip-on-receive); our DataHolder
   corpus untouched.
2. **Governance XML root** — the OMG `dds_governance.xsd` + Fast DDS (`GovernanceParser.cpp`) want
   `<domain_access_rules>` as a DIRECT child of `<dds>`; our non-conformant `<policies>` wrapper was a latent
   bug only cross-vendor surfaced. Fixtures made conformant; the parser tolerates both (no false-REJECT).
3. **Subject-name DN serialization** — our oneline `string=` vs Fast DDS RFC2253 (`Permissions.cpp:632`).
   Added the serialization-insensitive `%dn-equal` / `permissions-grant-for` (a latent always-wrong-cross-vendor
   bug); all three subject-match sites route through it — reduces false-REJECT.
4. **S/MIME container + loopback reachability** — Fast DDS needs multipart/signed `text/plain` (`PKCS7_TEXT`,
   `Permissions.cpp:408`); added the MIME fixtures + `create-participant :port` + Fast DDS `initialPeers`
   (the macOS multi-NIC pattern).

**NOT achieved cross-vendor (the honest line): no `auth → keyed → secure-SEDP → protected data`.** The §8.7
handshake is **REJECTED at the remote IdentityToken parse** — root cause = the propagate-byte divergence
(Carry 1). Because the handshake blocks first, **none** of the keyed crypto tiers (PVMS token exchange, secure
SEDP, rtps_protection, secure WLP/SPDP, protected data) were exercised cross-vendor. The downstream candidate
divergences sit *behind* the handshake, unreached. **Do NOT interpret this slice as "cross-vendor secure
discovery verified."** What is verified cross-vendor is the SECURITY=ON build, bidirectional SPDP discovery,
and the four fixes; everything keyed is our-to-our self-consistent + byte-exact-corpus + fuzzed.

**tshark — environment-limited.** tshark in this environment does not dissect the macOS lo0 `NULL/Loopback`
link-layer (IP/UDP empty; tcpdump confirms well-formed RTPS on lo0). The live RTPS-security dissector pass
could not be performed; secure-submessage byte-exactness rests on the in-suite byte-exact corpus
(`run-security-{submessage,crypto-header,rtps-message}-corpus-test`, green). We never reach the SEC_/SRTPS_
stage cross-vendor anyway (the handshake rejects first).

**RTI Connext-Security — static only.** The Security Plugins are not installed (no `libnddssecurity*`).
Connext-Security is verified statically this slice (OMG clause + tshark dissector + byte-exact corpus); live
Connext-Security secure discovery is the **Slice-5 P6 exit gate**.

---

## Honest interop posture and the numbered Slice-5 carries

**Achieved this slice (our-to-our, ACHIEVED):** two security-enabled participants under signed Governance
authenticate, exchange crypto tokens over **reliable** PVMS, reach `:keyed`, announce protected topics **only**
over secure SEDP, match, and exchange user data protected at payload + whole-RTPS tiers (the user DATA
submessage rides inside the SRTPS-encrypted datagram; per-user-endpoint submessage protection is Carry 4 /
not wired), with origin authentication where governance requires it. SIGN, ENCRYPT, and the `*_WITH_ORIGIN_AUTH`
kinds are each proven; the receiver-specific MAC gates beyond the common_mac (non-vacuous tamper tests). The
receive-side enforcement drops forged plain user-plane submessages. Security-OFF is byte-identical.

**Live cross-vendor (PARTIAL):** SECURITY=ON Fast DDS build + bidirectional SPDP discovery + four conformant
fixes (above). **NOT achieved cross-vendor:** auth, keying, secure SEDP, protected data — blocked at the
propagate-byte divergence. **Live RTI Connext: static only.**

The following are explicitly deferred to **Slice 5** (the P6 exit gate WP), consolidating every carry from the
work-package ledger:

1. **The propagate-byte fix (the handshake blocker — slice-wide).** Our Token `Property`/`BinaryProperty`
   codec serialises a 4-octet `propagate` field per property that Fast DDS does NOT put on the wire
   (`CDRMessage.cpp:828-906`; `propagate` is a local include-filter) — misaligning every cross-vendor token, so
   the §8.7 handshake rejects at the remote IdentityToken. The fix spans `auth/wire.lisp` + `identity.lisp` +
   `handshake.lisp` + their parsers + the keyexchange crypto-tokens + the **entire** DDS-Security token
   byte-exact corpus (currently pinned WITH the byte, i.e. never validated against a real peer) + ADR 0033.
   **Review guidance (mandatory):** the fix must **pin the actual OMG clause** for the on-wire Property layout
   (the self-pinned corpus is precisely why our-to-our never caught this) **and DECODE-TOLERATE both forms**
   (accept a property with or without a trailing propagate, do not hard-drop) — else we false-REJECT a
   spec-literal peer that *does* emit it.
2. **The downstream cross-vendor divergences (behind the handshake, unreached).** Each was identified and
   carried but cannot be exercised live until Carry 1 lands: (a) the **session_id base** derivation aligning to
   Fast DDS's exact `max()` operand for the no-reuse property; (b) the SIGN **GMAC AAD byte-span** (ours = the
   full original submessage, vs Fast DDS's exact auth-only span); (c) SIGN inter-submessage **4-octet
   re-alignment** (Fast DDS re-aligns each walked submessage; we write/walk verbatim — a non-issue for the
   4-aligned normal case); (d) **reliable PULL** (HEARTBEAT/ACKNACK) for secure-SEDP (currently push + dedup);
   (e) **metatraffic rtps-wrapping** — T10 wraps only the user data plane; a strict Connext
   `rtps_protection = ENCRYPT` peer REJECTS plain metatraffic from a keyed participant, so discovery may fail
   (the metatraffic IS submessage-protected, not in the clear, but it is not RTPS-wrapped). This is the most
   likely *next* cross-vendor blocker once Carry 1 is fixed.
   (f) **`%on-secure-builtin` inner-writerId cross-check (defense-in-depth).** `%on-secure-builtin` routes
   by the recovered inner writerId after MAC verification but does not assert that the
   `transformation_key_id`-resolved endpoint equals the inner writerId. Benign today (the path requires a
   genuine authenticated+keyed peer's EntityCrypto); a one-line consistency assert (resolved-endpoint ==
   inner writerId) would be defense-in-depth against future routing logic changes.
3. **Zero-alloc into-buffer AEAD on the data path — PARTIALLY RESOLVED (ADR 0038, WP-DDS-SECURITY-ZEROALLOC-AEAD,
   2026-07-01).** The **`data_protection` (serialized-payload) tier + the shared into-buffer foundation are resolved
   in ADR 0038**: an into-buffer AEAD FFI (`aes-256-gcm-{seal,open}-into`) + `dds.pal:static-sap+` (FFI 864 → 0.000
   B/iter) + a session-key cache + an into-buffer codec core (`encode/decode-serialized-payload-into`; the existing
   entries are now thin wrappers) + a refcount-gated encode payload pool (353 → 0.0) + a loaned decode-plaintext pool
   (4042 → 0.0) make the LIVE `data_protection` publish + receive path zero GC-alloc/sample, and `make mem` gained
   security-ON arms (`aead-encode`/`-decode`/`-live-pub`/`-live-rx`, all 0.0000) that finally cover the security path.
   **The submessage (`metadata_protection`) + whole-RTPS (`rtps_protection`, the ~2.2 KB/datagram) tiers are CARRIED
   to Slice 2** — they REUSE the same foundation; they are NOT zero-alloc yet. Wire byte-identical throughout (NIST
   KAT + every byte-exact corpus green UNCHANGED). Original note (still true for the un-migrated tiers): the SRTPS
   send/receive buffer is reused in place but the codec's `→octets` return + the AEAD intermediates leave a ~2.2 KB
   /datagram heap residual (OpenSSL-FFI dominates the ~5 µs/op); do not read a green `make mem` on the CDR path as
   covering the dds-disc rtps path — the security-ON arms cover only the `data_protection` tier.
4. **Per-topic `metadata_protection_kind` applied to user endpoints.** The primitive supports it and the
   governance field is parsed, but selective per-user-endpoint submessage protection is not wired —
   `rtps_protection` already protects user datagrams wholesale, so nothing is left in the clear; this is a thin
   follow-on.
5. **Builtin-endpoint share-vs-own-key vs Connext.** For our-to-our we generate + exchange a per-builtin-endpoint
   EntityCrypto KeyMaterial (the general, conformant path). Whether the secure builtin endpoints carry their own
   key or share the ParticipantCrypto key differs across vendors; verified vs Fast DDS this slice, the Connext
   choice is a Slice-5 item.
6. **KeyMaterial GC-heap hardening (carried from ADR 0034).** Control-plane key material lives on the GC heap
   (the AEAD copies the key into a `with-foreign-pointer` buffer before OpenSSL, byte-identical to shipped KEYX;
   there is no new SAP-to-heap path). Migrating it to foreign/static buffers is the hardening follow-on.
7. **PVMS bootstrap-KM table pruning.** `pvms-bootstrap-kms` is never pruned on peer-loss (safe-direction
   retention); prune via `remhash` on participant-lost / un-auth, like the SEDP matches.
8. **`%dn-normalize` RFC2253 edge cases.** The DN normaliser is naive on escaped/quoted RFC2253 separators and
   multi-valued RDNs; harden for the full cross-vendor DN grammar.
9. **The Slice-1 serialized-payload AAD divergence (the `data_protection` tier).** Slice-1's serialized-payload
   AAD is the 20-byte `SecureDataHeader`, where Fast DDS uses an EMPTY AAD for the payload tier — so the shipped
   Slice-1 data-protection is likely NOT Fast-DDS-interop on the payload tier. This pre-dates this slice and
   warrants its own ADR/decision (own WP or Slice 5); it was not changed here.
10. **Zero-Copy × `rtps_protection` SHMEM cleartext.** With Zero-Copy/SHMEM transfer, only the 16-byte
    reference datagram is RTPS-wrapped; the user payload sits in shared memory in the clear. Reconciling
    SHMEM transfer with `rtps_protection` confidentiality is a backlog item.
11. **Live RTI Connext-Security secure-discovery interop — the P6 exit gate.** Requires the licensed Security
    Plugins (not installed). The Fast DDS-Security peer + harness + run scripts now exist in
    `interop/security-secure-discovery/` for Slice 5.

---

## Tests

| Test | What it proves | Increment |
|---|---|---|
| `run-security-crypto-header-corpus-test` | CryptoHeader/Content/Footer byte-exact + the unconditional Slice-1 48-octet byte-identity regression | T1 |
| `run-security-submessage-corpus-test` | datawriter/datareader submessage byte-exact (ENCRYPT 88B + SIGN 80B; the GMAC tag identical across the SIGN reframe proves the AAD is untouched) | T2 |
| `run-security-submessage-fuzz-test` | 2500 adversarial brackets, prod + `(safety 0)`, fail-closed (hostile `octetsToNext`, oversized counts → T1 cap) | T2 |
| origin-auth corpus + fuzz | 2-receiver ENCRYPT 128B / SIGN 120B byte-exact; wrong-receiver-key → NIL while common_mac valid; hostile counts hit the T1 cap | T3 |
| `run-security-rtps-message-corpus-test` + fuzz | whole-RTPS byte-exact (100B ENCRYPT + 92B SIGN); the SIGN body-walk is bounded + terminating + fail-closed | T4 |
| (T-RECONCILE) regenerated corpus | every ENCRYPT vector re-pinned (no-counter session key + BE `crypto_content` length + BE footer count), real `equalp` literals | T-RECONCILE |
| governance protection-kind parse | the 5-value/3-value tier guard; missing-required-element → parse NIL; wrong-tier token → parse NIL | T5 |
| `run-security-crypto-manager-test` | the registries + four resolvers; a genuine 8-thread × 50 register/resolve race (hash-count = 400); the participant origin-auth resolvers (wrong receiver key fails the receiver-MAC though common_mac valid) | T6, T10 |
| `run-volatile-secure-reliable-test` | PVMS: drop every send of SN1 → B empty → HEARTBEAT/ACKNACK repair → deliver-once + byte-equal over 10 more HBs (non-vacuous) | T7 |
| `run-volatile-secure-fail-closed-test` | wrong bootstrap KM seed, 30 rounds, 0 deliveries | T7 |
| `run-secure-discovery-keyed-test` | crypto-token exchange over PVMS → `:keyed`; the two roles' `session_id`s DIFFER and are non-zero (the nonce-disjointness guard); 3-peer PVMS purge-bound | T8 |
| `run-secure-discovery-origin-auth-test` | full e2e under `ENCRYPT_WITH_ORIGIN_AUTHENTICATION`: `:keyed`, 120-byte receiver KeyMaterial exchanged, B matches A's protected writer with a verified per-receiver MAC, `"Square"` never in cleartext | T-ORIGINAUTH |
| `run-secure-sedp-origin-auth-tamper-test` | the WRONG receiver key (same key_id) → B NEVER matches **even though the common_mac is valid** (non-vacuous) | T-ORIGINAUTH |
| `run-rtps-protection-test` | the SPDP/PSM/PVMS exemption (NIL dest-prefix stays plain); a keyed-dest send is SRTPS on the wire + payload never in cleartext; wrong-ParticipantCrypto drop; origin-auth | T10 |
| `run-rtps-protection-enforce-test` / `-reliability-test` | a forged plain user-DATA / HEARTBEAT/ACKNACK/GAP/HEARTBEAT_FRAG/NACK_FRAG spoofing a keyed peer's prefix is dropped; **non-vacuous** (delivered from a not-keyed source + under NONE governance); plain builtin SPDP/SEDP from the keyed peer still processed (no false-REJECT) | T10 |
| `run-secure-discovery-protected-test` | the full participant e2e: `:keyed` → secure SEDP → match → byte-exact `"Square"` SRTPS-wrapped on the wire; plain peer refused non-vacuously | T9, T10 |
| `run-secure-participant-message-test` / `-tamper-test` | secure WLP (SIGN over `0xff0200`), B detects liveliness; a one-octet-flipped copy fails the MAC and is dropped | T11 |
| `run-secure-spdp-reannounce-test` | an armed node advertises bits 26/27; plain SPDP still bootstraps; a FRESH peer that saw no plain SPDP registers the participant from the protected re-announce alone | T11 |

All green SBCL + Clasp (Clasp first). Gate sweep results in §Consequences.

---

## §M7 roadmap update

| Slice | Description | Status |
|---|---|---|
| 1 | Crypto plugin: AES256-GCM `SecuredPayload` + session-key KDF (ADR 0031) | LANDED |
| 2a | Authentication: PKI identity + §8.7.2.4 PKI-DH → SharedSecret, both §9.3 suites (ADR 0032) | LANDED |
| 2b-i | Wire transport: SPDP IdentityToken + PSM endpoints + DataHolder/envelope codec (ADR 0033) | LANDED |
| 2b-ii + 2c | Auth manager: on-discovery trigger + auth-remote state machine + strict gate + KxKey + per-writer KeyMaterial exchange (ADR 0034) | LANDED |
| 3 | AccessControl plugin (§8.4 / §9.4): CMS-verify Governance + Permissions, topic-level enforcement (ADR 0035) | LANDED |
| **4 (this ADR)** | **Secure discovery (§7.3.7 / §8.5): submessage + whole-RTPS protection, origin-auth, reliable PVMS, governance protection-kinds, secure builtin endpoints — our-to-our complete; live Fast DDS = bidirectional SPDP discovery + 4 fixes** | **LANDED** |
| 5 | Connext-Security live interop + full cross-vendor `auth → keyed → data` (the propagate-byte fix + the downstream divergences + live Connext) — **the P6 exit gate** | pending |

---

## Consequences

- **NFR-MEM:** `make mem` stays **0.0000** bytes/sample — the gated CDR serialize/deserialize hot path is
  untouched. The SRTPS send/receive path reuses its buffer in place but is **not** zero-alloc (Carry 3); it is
  off the measured `make mem` path. Before/after numbers in
  `bench/report/2026-06-28-wp-secure-discovery-t10.md` (and `…-t4.md`): ~5 µs/op, OpenSSL-FFI-dominated;
  T10-send ≈ T4-encode + ~270 B/datagram, T10-recv ≈ T4-decode + ~340 B/datagram.
- **NFR-SEC-POSTURE:** every new decoder bounds-checks length/offset against the buffer extent before each
  read (the `check-room` arithmetic is `(safety 0)`-independent); fail-closed everywhere (malformed /
  truncated / out-of-order / missing / GCM-mismatch / wrong-key → drop, never a signal out of the receive
  thread, never unverified plaintext); resource caps (`+max-receiver-specific-macs+`) reject before
  allocation; every parser has a `(safety 0)` fuzz arm.
- **FR-SEC-2:** no hand-rolled crypto — AES-256-GCM / HMAC-SHA256 / GMAC via `dds-dare` (OpenSSL).
- **NFR-PORT:** no reader conditionals in `src/dds-security/crypto/`, `src/dds-dcps/crypto-manager.lisp`, or
  the secure-discovery `dds-disc` code. Clasp + SBCL both validate, Clasp first.
- **Default-OFF / false-REJECT guard:** no governance, or every kind = NONE → no secure bits, NIL crypto
  resolvers, plain SPDP/SEDP byte-identical to the pre-Slice-4 wire.
- **Gates (T13 final sweep, both impls, Clasp first):** see the WP report
  `.superpowers/sdd/task-T13-report.md`; the slice's own runs were `test-clasp` 377 / `test-sbcl` 377;
  `gate-hotpath(8)` PASS; `gate-types(2016)` PASS; `mem(0.0000)` PASS; `fuzz` PASS. Known pre-existing flakes
  (keyed-flatdata-copy-behavior, volatile-latejoiner, no-double-delivery, durability-latejoiner, the
  secure-discovery-protected UDP capture-window) are machine-load-induced and pass on a clean sequential
  re-run — not a Slice-4 regression.

---

## References

- T0 spike: `docs/superpowers/spikes/2026-06-27-dds-security-secure-discovery.md`
- Design spec: `docs/superpowers/specs/2026-06-27-dds-security-secure-discovery-design.md`
- `src/dds-rtps/discovery.lisp` — secure builtin EntityIds + `BuiltinEndpointSet` bits 16–27 (T0)
- `src/dds-security/crypto/constants.lisp` — submessage kinds + KDF label + ProtectionKind/BasicProtectionKind (T0)
- `src/dds-security/crypto/crypto-header.lisp` — the shared CryptoHeader/Content/Footer codec + BE helpers (T1, T-RECONCILE)
- `src/dds-security/crypto/submessage.lisp` — submessage protection + origin-auth (T2, T3)
- `src/dds-security/crypto/rtps-message.lisp` — whole-RTPS protection (T4)
- `src/dds-security/access-control/{governance,parser}.lisp` — the protection-kind model (T5)
- `src/dds-security/auth/keyexchange.lisp` — the 88/120-byte KeyMaterial CDR + PVMS token migration (T8, T-ORIGINAUTH)
- `src/dds-dcps/crypto-manager.lisp` — the registries + resolvers + token exchange + `:keyed` promotion (T6, T8)
- `src/dds-dcps/access-control.lisp` — governance → disc-node protection-kind slots (T9, T10, T11)
- `src/dds-disc/volatile-secure.lisp` — the reliable PVMS endpoint + bootstrap-key derivation (T7)
- `src/dds-disc/{disc,dataplane}.lisp` — secure-builtin send/receive + SEC_PREFIX dispatch + `%maybe-wrap-srtps` + receive enforcement (T9, T10, T11)
- `src/dds-tests/security-test.lisp` — all WP-DDS-SECURITY-SECURE-DISCOVERY test functions
- `src/dds-tests/secure-interop.lisp` — `run-secure-interop-peer` (the live Fast DDS harness peer, T12)
- `interop/security-secure-discovery/README.md` — the live Fast DDS result + the four fixes + the Connext static / Slice-5 deferral
- `bench/report/2026-06-28-wp-secure-discovery-t10.md`, `…-t4.md` — the data-path bench
- `docs/provenance.md` — every Fast DDS / Cyclone source consulted across the slice (T0–T12, T-RECONCILE, T-ORIGINAUTH)
- ADR 0035 — Slice 3 (AccessControl; the governance struct + permissions-gate)
- ADR 0034 — Slice 2b-ii + 2c (the auth manager + KxKey + key exchange)
- ADR 0033 — Slice 2b-i (the PSM wire codec; re-opened by Carry 1)
- ADR 0032 — Slice 2a (the PKI-DH handshake → SharedSecret)
- ADR 0031 — Slice 1 (the byte-exact serialized-payload codec)
- ADR 0025 — DARE (the `dds-dare` OpenSSL FFI)
