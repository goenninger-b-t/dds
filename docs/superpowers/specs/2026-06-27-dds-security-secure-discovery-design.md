# DDS-Security Secure Discovery — Design (M7 / P6, Slice 4)

> Status: design, awaiting owner review. Operating-contract workflow: brainstorm → spec (this) → plan → subagent-driven implementation → final review → finish-branch.

**WP:** `WP-DDS-SECURITY-SECURE-DISCOVERY` · **Milestone:** M7 / P6 · **Slice:** 4 of the 5-slice DDS-Security roadmap · **ADR:** 0036 (to be written at the capstone).

---

## 1. Goal

Implement OMG DDS-Security 1.1 **secure discovery** end-to-end, our-to-our and cross-vendor against a live Fast DDS-Security peer: protect the builtin discovery traffic (SEDP endpoint discovery, participant-message/liveliness, and a secure SPDP re-announce) and the whole RTPS datagram between matched secure participants, governed by the Governance protection-kind policy, reusing the Slice-1 crypto primitives and the Slice-2 authentication/key-exchange machinery.

This is the widest M7 slice by deliberate owner decision (2026-06-27): it is effectively the entire §8.5 Cryptographic plugin beyond Slice-1's serialized-payload protection (submessage protection + whole-RTPS-message protection + receiver-specific MACs / origin authentication), plus a reliable ParticipantVolatileMessageSecure builtin endpoint, plus the Governance protection-kind model, plus the wiring of the secure builtin discovery endpoints. It lands as one branch but is built as internal vertical increments, each independently testable with its own review gate, so no horizontal layer is built in isolation.

## 2. Scope (owner-confirmed)

IN:
- **Submessage protection** (§8.5.1.7–.9): `encode/decode_datawriter_submessage`, `encode/decode_datareader_submessage` — the `SEC_PREFIX`/`SEC_BODY`/`SEC_POSTFIX` sandwich.
- **RTPS-message protection** (§8.5.1.10–.12): `encode/decode_rtps_message` — the `SRTPS_PREFIX`/`SEC_BODY`/`SRTPS_POSTFIX` whole-datagram sandwich.
- **Origin authentication** (the `_WITH_ORIGIN_AUTHENTICATION` protection kinds): receiver-specific key derivation + the `receiver_specific_macs` list, both encode and decode sides.
- **Reliable ParticipantVolatileMessageSecure (PVMS)** builtin endpoint (bits 24/25): real reliable (HEARTBEAT/ACKNACK) volatile endpoint carrying the crypto-token exchange, replacing KEYX's interim best-effort path.
- **Governance protection-kind model**: parse + expose `discovery_protection_kind`, `liveliness_protection_kind`, `rtps_protection_kind`, the per-topic `enable_discovery_protection`/`enable_liveliness_protection`, and `metadata_protection_kind`/`data_protection_kind`. Full `ProtectionKind` (5 values) for the domain-rule kinds; `BasicProtectionKind` (3 values) for the per-topic kinds.
- **Secure builtin endpoint wiring**: secure SEDP publications/subscriptions (bits 16–19), secure participant-message (bits 20/21), secure SPDP re-announce (bits 26/27).
- **Live Fast DDS-Security cross-vendor** secure-discovery interop (a headless Fast DDS-Security build is available this slice).

OUT (this slice — recorded as carries):
- Per-topic **`metadata_protection_kind`** *applied to user endpoints* (selective user-endpoint submessage protection). The primitive supports it and the governance field is parsed; `rtps_protection` already protects user datagrams wholesale, so nothing is left in the clear. Wiring per-user-endpoint metadata protection is a thin follow-on (owner may elect to include it at plan time).
- **Live RTI Connext-Security** execution (RTI Security Plugins not installed) — Connext is verified statically (spec clauses + tshark RTPS-security dissector + byte-exact corpus); live Connext-Security interop remains the **Slice-5 P6 exit gate**.

## 3. Non-negotiable constraints (from the operating contract)

- OMG DDS-Security 1.1 / DDSI-RTPS 2.5 / XCDR conformance; the only allowed deviation is interop behavior added *on top*, never replacing. False-REJECT is the worst defect class.
- No wire constant from memory — every value pinned in T0 from the cited clause and dual-corroborated (§9 below).
- No hand-rolled crypto — AES-256-GCM / HMAC-SHA256 via `dds-dare` / OpenSSL only (FR-SEC-2).
- Bounds-check every network-facing parser even at `(safety 0)`; fail-closed; resource caps; fuzzed.
- Hot-path purity + static arena + zero-alloc/sample on the data-path crypto (`rtps_protection` and submessage encode/decode run per datagram); before/after bench required.
- `defun*` / `defstruct*` + full `ftype` on every function; no reader conditionals outside `dds-pal/`.
- Clasp **and** SBCL both validate, Clasp first.
- Docs in lockstep (docstrings + `docs/wiki` + README + `verification.csv`); SBOM auto-regenerated; no AI attribution in any repo file (cite "the operating contract").

## 4. Architecture

Three structural choices (each with the rejected alternative):

**4.1 Crypto-plugin organization — additive, not a refactor.** Leave Slice-1's byte-exact `crypto.lisp` / `transform.lisp` (serialized-payload) untouched. Add, under `src/dds-security/crypto/`:
- `crypto-header.lisp` — the shared `CryptoHeader` / `CryptoContent` / `CryptoFooter` codec, including the receiver-specific-MAC list. Reused by all tiers; the Slice-1 SecureDataHeader is a structural subset.
- `submessage.lisp` — `encode/decode_datawriter_submessage`, `encode/decode_datareader_submessage`.
- `rtps-message.lisp` — `encode/decode_rtps_message`.
- `crypto-keys.lisp` (or extend the existing key-material code) — the §9.5.3 derivations: session key (reused from Slice 1), receiver-specific session key (new), and the KeyMaterial accessors.

*Rejected:* folding all tiers into one module — it churns landed conformant code for no gain.

**4.2 Key management — a dedicated `crypto-manager`.** A new `src/dds-dcps/crypto-manager.lisp`, parallel to `auth-manager.lisp`, owns the §8.5 key registries (ParticipantCrypto, EntityCrypto) and the crypto-token exchange over PVMS. It mirrors the spec's plugin split (Authentication vs Cryptographic) and is driven by the auth state machine. *Rejected:* cramming this into `auth-manager` — that file already owns the handshake + the KEYX per-writer table; conflating the two plugins hurts both.

**4.3 Reliable PVMS — reuse the existing RTPS reliable engine.** The ParticipantVolatileMessageSecure endpoint is a reliable, volatile (KEEP_ALL, no durability) builtin endpoint. Reuse the M2 reliable writer/reader state machine (HEARTBEAT/ACKNACK/GAP) configured with the secure EntityIds and a volatile history. *Rejected:* bespoke reliability — we have a tested reliable engine.

## 5. Wire formats

All exact byte values are pinned in T0 from §7.3.7 / §9.5.3.3 and dual-corroborated; the *structure* is fixed here.

**5.1 Shared crypto elements (`crypto-header.lisp`).**
- `CryptoHeader` (20 octets) = `transformation_kind`[4] ‖ `transformation_key_id`[4] ‖ `session_id`[4] ‖ `init_vector_suffix`[8]. GCM nonce (12 B) = `session_id` ‖ `init_vector_suffix`. `transformation_kind` for AES-256-GCM is the `#(0 0 0 4)` Slice 1 uses; `transformation_key_id` selects which KeyMaterial the receiver decodes with.
- `CryptoContent` = `uint32` length ‖ ciphertext (ENCRYPT); absent for SIGN (plaintext travels in the clear, MAC-only).
- `CryptoFooter` = `common_mac`[16] ‖ `receiver_specific_macs`: `uint32` count ‖ count × { `receiver_key_id`[4], `mac`[16] }. Count = 0 when origin-auth off (footer is then byte-compatible with Slice 1).

**5.2 Submessage protection** (secure SEDP, secure participant-message):
```
SEC_PREFIX (0x31)    header + CryptoHeader(20)
SEC_BODY   (0x30)    header + CryptoContent        ; ciphertext (ENCRYPT) | original submessage verbatim (SIGN)
SEC_POSTFIX(0x32)    header + CryptoFooter
```
Decode validates `SEC_PREFIX`→`SEC_POSTFIX` bracketing, looks up the key by `transformation_key_id`, verifies `common_mac` (+ its own receiver-specific MAC if present), then GCM-opens. AAD per the clause (CryptoHeader + relevant submessage headers).

**5.3 RTPS-message protection** (`rtps_protection_kind`):
```
RTPS Header (20)     untouched — SPDP bootstrap stays readable
SRTPS_PREFIX (0x33)  header + CryptoHeader(20)
SEC_BODY    (0x30)   header + CryptoContent         ; encrypted original submessage stream (ENCRYPT) | verbatim (SIGN)
SRTPS_POSTFIX(0x34)  header + CryptoFooter
```
Keyed by the ParticipantCrypto KeyMaterial; applied to every datagram once the pair is `:keyed`. Bootstrap SPDP + PSM handshake datagrams are exempt.

**5.4 Secure builtin endpoint EntityIds** (pinned in T0 from §7.4.5; bits 16–27 already in-repo; PSM `0x000201c3/c4` + PVMS `0xff0202c3/c4` already pinned). Expected, T0-verified + dual-corroborated:
- secure SEDP publications writer/reader `0xff0003c2` / `0xff0003c7`
- secure SEDP subscriptions writer/reader `0xff0004c2` / `0xff0004c7`
- secure participant-message writer/reader `0xff0200c2` / `0xff0200c7`
- secure SPDP writer/reader `0xff0101c2` / `0xff0101c7`

## 6. Key model

**6.1 KeyMaterial (§9.5.2.1.1).** Reuse the KEYX `KeyMaterial_AES_GCM_GMAC` struct: `transformation_kind`[4] ‖ `master_salt`(32) ‖ `sender_key_id`[4] ‖ `master_sender_key`(32) ‖ `receiver_specific_key_id`[4] ‖ `master_receiver_specific_key`(seq). KEYX left the receiver fields empty (88-byte CDR); origin-auth populates them (`receiver_specific_key_id` ≠ 0, 32-byte `master_receiver_specific_key`, ~120-byte CDR).

**6.2 Registries (owned by `crypto-manager`).**
- **ParticipantCrypto** — one master KeyMaterial the local participant generates for `rtps_protection`, plus per matched remote the remote's ParticipantCrypto KeyMaterial. Encode-our-datagrams uses local; decode-theirs uses remote.
- **EntityCrypto** — one KeyMaterial per local secure builtin endpoint (secure SEDP pub/sub W+R, secure participant-message, secure SPDP) and per matched-remote endpoint, keyed for O(1) lookup by `transformation_key_id`.

**6.3 Derivations (§9.5.3.3.4).**
- Session key: `HMAC-SHA256(master_sender_key, "SessionKey" ‖ master_salt ‖ session_id)` — Slice-1 `derive-session-key`, reused verbatim (label bytes pinned in T0).
- Receiver-specific session key (origin-auth): `HMAC-SHA256(master_receiver_specific_key, "SessionReceiverKey" ‖ master_salt ‖ session_id)`. The per-receiver MAC is a GMAC under that key; the sender emits one `{receiver_key_id, mac}` per matched receiver; the receiver verifies its own entry. Labels + MAC input pinned in T0.

**6.4 Crypto-token exchange (§9.5.2.2, §8.5.2).** Reuse KEYX's CryptoToken DataHolder codec. New per-class `message_class_id` (pinned T0):

| Token | `message_class_id` | Feeds |
|---|---|---|
| ParticipantCryptoToken | `dds.sec.participant_crypto_tokens` | ParticipantCrypto (remote) |
| DatawriterCryptoToken | `dds.sec.datawriter_crypto_tokens` | EntityCrypto (remote writer) |
| DatareaderCryptoToken | `dds.sec.datareader_crypto_tokens` | EntityCrypto (remote reader) |

All flow over reliable PVMS. T0 reconciles whether KEYX's per-writer KM (carried under `participant_crypto_tokens`) should migrate to `datawriter_crypto_tokens`; if so, the correction is its own increment and KEYX's tests move with it.

**6.5 PVMS bootstrap (§9.5.3.1).** The PVMS endpoint is submessage-protected with a KeyMaterial **derived directly from the SharedSecret** (no exchange), so it can carry the other tokens. The crypto-token DataHolders ride as plaintext *inside* those protected PVMS submessages — the conformant replacement for KEYX's interim app-level KxKey-encryption over best-effort PSM.

**6.6 Open conformance point.** Whether the secure builtin endpoints carry their own EntityCrypto KeyMaterial or share the ParticipantCrypto key differs across vendors. For our-to-our we generate+exchange per-builtin-endpoint KeyMaterial (the general, conformant path). The live Fast DDS run this slice will surface Fast DDS's actual choice; any residual Connext divergence is a Slice-5 item.

## 7. Governance model + flow

**7.1 Model.** The Slice-3 governance struct gains: domain-rule `discovery_protection_kind` / `liveliness_protection_kind` / `rtps_protection_kind` (`ProtectionKind`, 5 values); topic-rule `enable_discovery_protection` / `enable_liveliness_protection` (bool) + `metadata_protection_kind` / `data_protection_kind` (`BasicProtectionKind`, 3 values). The parser maps the XSD; the matcher resolves the effective kinds per domain + topic.

**7.2 State machine.** `auth-remote` keeps its shape (`none→handshaking→authenticated→keyed→rejected`); the `:authenticated→:keyed` edge is mediated by `crypto-manager`: register local ParticipantCrypto + builtin EntityCrypto → exchange tokens over reliable PVMS → install remote tokens → promote to `:keyed`. Only at `:keyed` does `rtps_protection` engage and secure-SEDP matching proceed. The gate ladder's existing `:keyed` precondition enforces this; no new gate — its meaning deepens to "crypto established."

**7.3 What is protected, and when.**
```
plain SPDP           always clear (carries tokens; rtps-protection-exempt pre-keying)
PSM handshake        always clear (auth bootstrap, exempt)
PVMS                 submessage-protected with the SharedSecret-derived key (bootstrap)
once :keyed →
  every datagram     rtps_protection (SRTPS) if rtps_protection_kind ≠ NONE
  secure SEDP        discovery_protection_kind, for topics with enable_discovery_protection
  secure participant-msg  liveliness_protection_kind
  secure SPDP        re-announce over the protected channel
```
Protected topics' endpoints are announced **only** over secure SEDP (never plain SEDP) — otherwise an outsider reads the topology.

**7.4 Security-OFF byte-identical (false-REJECT guard).** No governance, or every kind = NONE → no secure bits in `BuiltinEndpointSet`, `crypto-transform` NIL, plain SPDP/SEDP exactly as today. The entire secure path sits behind the same NIL-check the gate ladder already uses; the plain wire does not change a byte.

## 8. Error handling & security posture

- Every new decoder bounds-checks length/offset against the buffer extent before each read, even at `(safety 0)`; fail-closed (malformed/truncated/out-of-order/missing → drop, never signal out of the receive thread, never deliver unverified plaintext). Resource caps (max receiver-specific-MAC count, max secure-submessage size) reject before allocation. GCM-open / MAC mismatch → drop, no fallback. Each decoder gets a `(safety 0)` fuzz arm.
- `rtps_protection` + submessage encode/decode are on the data path: `defstruct` + monomorphic, static-arena crypto buffers, zero alloc/sample steady state, before/after bench (the Slice-1 pattern; ADR 0031's deferred arena migration is picked up here). Control-plane parts (governance, key mgmt, token exchange) are not hot-path.
- Key material in `dds.pal` foreign buffers, freed on teardown (clasp#1793-safe alloc/free through `dds.pal`).

## 9. Conformance & dual-vendor verification (the DoD heart)

For every interop-critical decision — builtin EntityIds, submessage kinds, `CryptoHeader`/`Footer` layout, the session-key + receiver-specific-key KDF labels, the `message_class_id`s, the extended KeyMaterial CDR, the receiver-specific-MAC input, the PVMS bootstrap-key derivation, and the builtin-endpoint share-vs-own-key question — T0 produces dual corroboration:
- **Fast DDS** (Apache-2.0, clean-room readable, provenance logged): corroborate each constant/algorithm against its `security/` module; and — new this slice — a **live headless Fast DDS-Security peer** is the cross-vendor wire oracle (real ours↔Fast DDS secure-discovery run; divergences are bugs fixed this slice, not deferred).
- **RTI Connext** (never read RTI source): the OMG clause is the oracle; corroborate via the vendor-neutral Wireshark/tshark RTPS-security dissector, public Connext docs, and any captures. Live Connext-Security execution is the Slice-5 exit gate.
- Where the two diverge, document it, take the spec-conformant path, record the interop risk as a Slice-5 item.

Plus: a byte-exact corpus for every new structure (both endiannesses, all protection kinds incl. origin-auth) gated like P0; tshark must dissect our emitted secure submessages as valid.

## 10. Testing strategy

Per-primitive unit + round-trip; byte-exact corpus; `(safety 0)` fuzz on every parser; our-to-our e2e per increment (two secured participants → `:keyed` → protected SEDP → match → protected data, byte-exact plaintext, ciphertext-on-wire asserted, plain peer refused non-vacuously); security-OFF byte-identical; bench on the rtps/submessage data path; `make mem` zero-alloc. **Live Fast DDS-Security cross-vendor** secure-discovery run (T12). Interop harness with governance/permissions fixtures + run scripts for Fast DDS (live) and Connext (static/Slice-5). Both impls (Clasp first), every gate green.

## 11. Task spine (internal vertical increments — each independently testable, 2-stage reviewed)

| # | Increment |
|---|---|
| T0 | Spike: pin all constants + resolve ambiguities with dual Connext+Fast DDS corroboration; locate/build the headless Fast DDS-Security peer + confirm RTI absence; governance fixtures (protection kinds); provenance; constants load both impls |
| T1 | `crypto-header.lisp` shared codec (Header/Content/Footer + receiver-MAC list) — exercised e2e by T2 |
| T2 | `submessage.lisp`: encode/decode datawriter + datareader submessage (SIGN+ENCRYPT) — byte-exact + fuzz |
| T3 | Origin-auth: receiver-specific key + MAC list (both submessage); populate KeyMaterial receiver fields — byte-exact + fuzz |
| T4 | `rtps-message.lisp`: encode/decode whole-RTPS (SRTPS sandwich), all kinds — hot-path + bench |
| T5 | Governance protection-kind model (parser + struct + accessors) |
| T6 | `crypto-manager`: ParticipantCrypto + EntityCrypto registries + key resolvers (by `transformation_key_id`) |
| T7 | Reliable PVMS endpoint (reuse reliable engine, volatile, SharedSecret-derived bootstrap key, submessage-protected) |
| T8 | Crypto-token exchange over PVMS (Participant/DW/DR token classes) + `:authenticated→:keyed` promotion + reconcile KEYX per-writer KM migration |
| T9 | Secure SEDP wiring (protected DiscoveredWriter/ReaderData; protected topics off plain SEDP; gate match) — e2e |
| T10 | `rtps_protection` engagement (wrap datagrams once keyed; bootstrap exemptions) — e2e + bench + mem |
| T11 | Secure participant-message (liveliness) + secure SPDP re-announce — e2e |
| T12 | Live Fast DDS-Security cross-vendor secure-discovery interop (ours↔Fast DDS: SPDP + auth + crypto-token exchange + secure SEDP + protected data); fix wire divergences; document. Connext static (tshark + corpus) |
| T13 | Capstone: ADR 0036, wiki/README/verification.csv, interop harness docs (Fast DDS live + Connext static/Slice-5), provenance, SBOM; final dual-impl gate sweep |

## 12. Known limitations / Slice-5 carries

- Live RTI Connext-Security secure-discovery interop (plugins not installed) — the P6 exit gate.
- Per-topic `metadata_protection_kind` applied to user endpoints (deferred; `rtps_protection` covers user traffic wholesale).
- The builtin-endpoint share-vs-own-key choice vs Connext (verified vs Fast DDS this slice; Connext at Slice 5).
- Any residual Fast-DDS-vs-spec divergence taken the spec-conformant way, with the interop note for Connext.
- KeyMaterial GC-heap hardening (carried from ADR 0034) — control-plane key material on the GC heap.

## 13. ADR

ADR 0036 (`docs/adr/0036-dds-security-secure-discovery.md`) is written at the capstone (T13), recording the three structural choices, the wire/key/governance models, the dual-vendor verification result, and the numbered Slice-5 carries.
