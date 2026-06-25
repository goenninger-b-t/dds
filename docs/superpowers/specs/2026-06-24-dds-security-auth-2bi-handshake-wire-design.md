# WP-DDS-SECURITY-AUTH-2BI — design (Slice 2b-i: the §8.7 handshake over the real ParticipantStatelessMessage wire)

- **Status:** Approved (design), 2026-06-24. M7/P6. First sub-slice of Slice 2b (discovery integration)
  of Slice 2 (Authentication) of the M7 5-slice roadmap (ADR 0031 §9, ADR 0032).
- **Relates to:** ADR 0032 (Slice 2a — the §8.7.2.4 PKI-DH handshake → SharedSecret, our-to-our in
  isolation; the internal-token-vs-CDR-DataHolder-wire carry this slice now implements). The dds-disc
  discovery/builtin-endpoint layer; the dds-rtps message/discovery layer.
- **Constraints:** OMG DDS-Security 1.1 §7.4 (the ParticipantStatelessMessage builtin endpoints +
  the ParticipantGenericMessage envelope) + §9.3.4 (HandshakeMessageToken as a DataHolder); DDSI-RTPS
  2.5 §8.5 (SPDP); the operating contract (no wire constants from memory — spike-pinned + §-cited; bounds-check
  parsers even at `(safety 0)`, fail-closed; `defun*`/`defstruct*` + full ftype; no reader conditionals
  outside `dds-pal/`; Clasp AND SBCL both, Clasp first; no AI/assistant attribution; clean-room).

---

## 1. Problem + goal

Slice 2a delivers the §8.7.2.4 PKI-DH handshake → SharedSecret, but **our-to-our in isolation** — the
handshake tokens are passed in-process by a test harness; nothing is on the wire. To authenticate real
remote participants, the handshake must ride the **ParticipantStatelessMessage** builtin endpoints during
discovery.

Slice 2b (discovery integration) is decomposed (owner-confirmed 2026-06-24) into:
- **2b-i (this spec)** — the **wire transport**: put the handshake onto the real ParticipantStatelessMessage
  wire (SPDP IdentityToken + the PSM builtin endpoints + the §9.3.4 DataHolder token wire format), our-to-our.
- **2b-ii** — the **discovery integration + gating**: the on-participant-discovered hook + the auth manager +
  per-participant auth-state + the endpoint-matching auth-gate (composed with the TypeLookup type-gate) +
  wiring `select-auth-suite` + the algo-vs-suite cross-check.

**2b-i goal:** the §8.7 handshake completes over the **real ParticipantStatelessMessage wire** between two
of our participants — `begin-handshake-request` → serialize to the §9.3.4 wire form → send via the PSM
builtin writer → the peer's PSM reader receives → parse → `process-handshake` → … → both reach
`:authenticated` over the wire with a byte-equal SharedSecret. It STOPS there: the handshake is driven by a
test harness, NOT auto-triggered on discovery, and endpoint matching is NOT gated yet (those are 2b-ii).

## 2. Scope boundary

**In scope (2b-i):**
- `PID_IDENTITY_TOKEN` (and the §7.4.6.1 security builtin-endpoint-set bits) added to the SPDP participant
  announcement, so a peer sees we carry an identity + advertise the PSM endpoints.
- The **ParticipantStatelessMessage** builtin endpoints (writer 0x000201C3 / reader 0x000201C4, best-effort):
  send + receive + the receive-dispatch routing + a `disc-node` hook.
- The §7.4.x **ParticipantGenericMessage** envelope codec + the §9.3.4 **HandshakeMessageToken-as-DataHolder**
  codec (CDR-LE) — the bridge from 2a's internal token to the wire.
- The our-to-our handshake-over-the-real-PSM-wire test (harness-driven) + a don't-break-plain-discovery
  live check vs plain Connext + Fast DDS.

**Out of scope (deferred):**
- The on-participant-discovered hook + the auth manager + per-participant auth-state + the match auth-gate +
  `select-auth-suite` wiring + the algo-vs-suite cross-check → **2b-ii**.
- ParticipantVolatileMessageSecure (the crypto-key-exchange endpoint) + deriving `key-material` → **2c**.
- AccessControl (governance/permissions in PID_PROPERTY_LIST) → **Slice 3**.
- Live RTI Connext-**Security** handshake interop (needs the licensed Security plugins, not installed) →
  **Slice 5** (the P6 exit gate). 2b-i's cross-DDS check is only that our security-enabled SPDP does not
  break PLAIN (non-security) Connext/Fast DDS discovery.

## 3. The wire formats (spike-pinned, §-cited)

The exact byte layouts — the PSM EntityIds, the §7.4.6.1 endpoint-set bits, `PID_IDENTITY_TOKEN`, the
ParticipantGenericMessage envelope struct, and the §9.3.4 DataHolder layout — are **pinned by the T0 spike**
from OMG DDS-Security 1.1 §7.4/§9.3 + DDSI-RTPS 2.5 §8.5, corroborated against eProsima Fast DDS
(read-for-understanding) + a plain-Connext SPDP capture for the envelope shape. Never invented.

- **SPDP IdentityToken:** `PID_IDENTITY_TOKEN` (T0-pinned PID, ~0x1001) carries the IdentityToken (the
  §8.7.2.2 Token = class_id + a PropertySeq) in the SPDP ParameterList; the §7.4.6.1 builtin-endpoint-set
  bits advertise the PSM (and later PVMS) endpoints.
- **ParticipantStatelessMessage** (§7.4.3 builtin endpoints; §7.4.4 the ParticipantGenericMessage): the PSM
  writer (0x000201C3) / reader (0x000201C4), best-effort (no HEARTBEAT/ACKNACK). The DATA payload is a CDR-LE
  ParticipantGenericMessage: `message_identity {source_guid, sequence_number}`, `related_message_identity`,
  `destination_participant_guid`, `destination_endpoint_guid`, `source_endpoint_guid`, `message_class_id`
  (the §9.3 auth class), `message_data` = a sequence of DataHolder.
- **HandshakeMessageToken as a DataHolder** (§9.3.4): CDR-LE `class_id` string (e.g.
  `"DDS:Auth:PKI-DH:1.0+Req"`) + a `BinaryPropertySeq` of the token's binary properties.

**Endianness subtlety (must keep distinct):** the 2a **signature** (Sign2/Sign1) is computed over a CDR-**BE**
BinaryPropertySeq (the spike-pinned signed data, unchanged from 2a). The **transport DataHolder** here is
CDR-**LE**. No conflict: the signature is one *property* in the LE DataHolder; it was *computed* over a BE
serialization of the *other* fields in 2a. `wire.lisp` keeps signature-computation (BE, 2a) strictly separate
from transport-serialization (LE, this slice). The spike pins which serialization each uses.

## 4. Architecture / components

- `src/dds-rtps/discovery.lisp` (modify) — add an `identity-token-octets` slot to `spdp-data`; emit
  `PID_IDENTITY_TOKEN` in `serialize-spdp-data` + the security endpoint-set bits in
  `+builtin-endpoint-set-default+` when present; parse it in `%fill-spdp-param`. (SPDP is a fixed struct, not
  a property list — slots + explicit serialize/parse cases.)
- `src/dds-security/auth/wire.lisp` (new) — the §9.3.4 DataHolder codec: `(handshake-token->dataholder-octets
  token) -> octets` and `(dataholder-octets->handshake-token octets) -> token | nil` (bounds-checked,
  fail-closed). This is the DDS-Security wire form, so it lives with the auth unit. Exported from `dds.security`.
- `src/dds-disc/stateless-message.lisp` (new) — the PSM builtin endpoints: `%send-stateless-message` (build the
  §7.4.x envelope, wrap the DataHolder, best-effort DATA on the PSM writer), `%on-stateless-message` (parse the
  envelope + the DataHolder, fail-closed, hand the reconstructed token + the source GUID to the hook); the
  `disc-node` `on-stateless-message` slot; the `%handle-datagram` dispatch branch for the PSM writer EntityId.
  Mirrors `src/dds-disc/participant-message.lisp` (the WLP builtin).
- `make-disc-node` — gains `:identity-token-octets` (plumb the local IdentityToken into SPDP). Default NIL =
  no security PIDs/bits = byte-identical SPDP (a non-security node is unchanged).

**Default-OFF byte-identical:** a node built without `:identity-token-octets` emits today's SPDP exactly
(no `PID_IDENTITY_TOKEN`, no security endpoint bits, no PSM endpoints) and the dataplane is unchanged — so
Slices 1–2a and all existing interop are unaffected. The PSM transport is control-plane discovery (off the
measured CDR hot path) — `make mem` stays 0.0000.

## 5. Data flow

A test harness in 2b-i drives the handshake (2b-ii auto-triggers it on discovery):
1. Node A: `validate-local-identity` → `begin-handshake-request(A, B)` → internal Request token.
2. `wire.lisp`: token → §9.3.4 DataHolder octets (CDR-LE).
3. `stateless-message.lisp`: wrap in the §7.4.x envelope (dest = B's participant GUID; class = auth) →
   `%send-stateless-message` on A's PSM writer → the wire → B's PSM reader.
4. B's `%on-stateless-message`: parse envelope → DataHolder → reconstruct the token → `process-handshake`
   produces the Reply → steps 2–4 back to A → Final → both reach `:authenticated`, byte-equal SharedSecret.

## 6. Error handling (fail-closed) + posture

- The PSM envelope + DataHolder parsers are **bounds-checked even at `(safety 0)`** — a malformed / short /
  garbage / over-declared PSM message is dropped (`nil`), never an OOB read or a crash (NFR-SEC-POSTURE);
  fuzzed.
- PSM is best-effort — a lost handshake message just means the handshake does not complete (2b-ii re-drives
  on re-announce; 2b-i's test drives it directly). The receiver thread must never crash on a bad PSM message.
- No new secrets on this path (the SharedSecret stays in the 2a foreign buffer); no hand-rolled crypto (the
  wire codec is pure serialization; the crypto is all 2a/dds-dare).

## 7. Testing / Definition of Done

- **Our-to-our handshake over the real PSM wire:** two disc-nodes, each with an identity, complete the
  §8.7 handshake via their PSM builtin endpoints (harness-driven) → both `:authenticated` + byte-equal
  SharedSecret. The tokens genuinely traverse `%send-stateless-message` → the UDP wire → `%on-stateless-message`.
- **Wire codec corpus + round-trip:** the envelope + DataHolder serialize/parse round-trips; a corpus asserts
  the bytes match the spike-pinned §9.3.4/§7.4.x layout (a self-consistency vector of OUR serializer — the
  byte-exact-vs-Connext match is still Slice 5).
- **Don't-break-plain-discovery (the cross-DDS DoD):** a node built WITH `:identity-token-octets` (so SPDP
  carries `PID_IDENTITY_TOKEN` + the security endpoint bits) is discovered by **plain (non-security) Connext
  7.3.1 + Fast DDS 3.6.1**, which cleanly ignore the unknown PID + extra bits, and plain discovery + pub/sub
  (Shapes) still works both directions. Run live; capture/document.
- **PSM-parser fuzz** at `(safety 0)` — malformed envelope/DataHolder blobs → `nil`, no OOB/crash.
- **Default-OFF byte-identical:** a node without an identity token emits byte-identical SPDP + an unchanged
  dataplane; `make mem` 0.0000; the existing Slice-1/2a + plain-interop tests are unaffected.
- **Gates green both impls, Clasp first:** build, test-clasp, test-sbcl, gate-hotpath, gate-types, mem (0.0000),
  fuzz, wire (tshark validates the PSM DATA submessage shape on the wire).
- Live Connext-**Security** handshake interop **DEFERRED to Slice 5**.

## 8. Global constraints (inherited)

- No wire constants from memory — the PSM EntityIds, endpoint-set bits, `PID_IDENTITY_TOKEN`, the
  ParticipantGenericMessage envelope, the §9.3.4 DataHolder all **spike-pinned (T0)** with §-citations.
- OMG DDS-Security 1.1 §7.4/§9.3 + DDSI-RTPS 2.5 conformance — the wire format never deviates.
- Bounds-check the PSM/DataHolder parsers even at `(safety 0)`, fail-closed, fuzzed (NFR-SEC-POSTURE).
- Default-OFF (no identity token) = byte-identical SPDP + unchanged dataplane; `make mem` 0.0000.
- No hand-rolled crypto (the wire codec is serialization; crypto is 2a/dds-dare).
- `defun*`/`defstruct*` + full ftype; **no reader conditionals outside `dds-pal/`**; **Clasp AND SBCL both,
  Clasp first**; **no AI/assistant attribution** (cite the operating contract / the spec clause); clean-room.

## 9. Task decomposition (spike-first, subagent-driven)

- **T0 — spike.** Pin the PSM EntityIds (0x000201C3/C4) + the §7.4.6.1 builtin-endpoint-set bits +
  `PID_IDENTITY_TOKEN` + the §7.4.x ParticipantGenericMessage envelope + the §9.3.4 DataHolder layout from
  §7.4/§9.3 + Fast DDS + a plain-Connext SPDP capture (for the SPDP/envelope shape). Re-plan checkpoint.
- **T1 — SPDP IdentityToken.** The `spdp-data` slot + `serialize-spdp-data`/`%fill-spdp-param` cases +
  the endpoint-set bits + `make-disc-node :identity-token-octets`. Test: round-trip the SPDP with/without the
  token; default-OFF byte-identical.
- **T2 — the wire codec.** `wire.lisp` (token ↔ §9.3.4 DataHolder, CDR-LE, fail-closed) + the §7.4.x envelope
  codec + a byte-corpus vs the spike + a parser fuzz.
- **T3 — PSM endpoints + handshake-over-wire.** `stateless-message.lisp` (the PSM builtin writer/reader +
  the `%handle-datagram` dispatch + the hook) + the our-to-our handshake-over-the-real-PSM-wire test.
- **T4 — capstone.** The don't-break-plain Connext + Fast DDS live check + ADR 0033 + docs lockstep
  (wiki/security.md §6 update, README P6 row, verification.csv) + the full gate sweep + the final whole-branch
  review → squash-merge presented for owner approval (HOLD PUSH).

## 10. Risks

- **Spike evidence (low-moderate):** the security parts of SPDP/PSM are only emitted by a Connext with the
  Security plugins (not installed), so the security wire constants are pinned spec + Fast DDS only; a plain-Connext
  capture grounds the SPDP/envelope shell. Same honest handling as Slice 1/2a.
- **SPDP regression (moderate):** adding `PID_IDENTITY_TOKEN` + endpoint bits to SPDP must NOT break plain
  interop — the don't-break-plain check (T4) is the guard; default-OFF keeps non-security nodes byte-identical.
- **Receiver-thread robustness (moderate):** a malformed PSM message must never crash the receiver thread —
  bounds-checked fail-closed parse + fuzz (T2/T3).

## 11. References

- OMG DDS-Security 1.1 §7.4 (builtin secure endpoints; ParticipantStatelessMessage; ParticipantGenericMessage),
  §7.4.6.1 (the BuiltinEndpointSet security bits), §9.3.4 (HandshakeMessageToken as a DataHolder), §8.7.2.2
  (the IdentityToken).
- DDSI-RTPS 2.5 §8.5 (SPDP), §9.6 (the ParameterList / PID encoding).
- ADR 0032 (Slice 2a — the handshake + the internal-token-vs-wire carry this slice implements).
- `src/dds-rtps/discovery.lisp` (spdp-data + serialize/parse); `src/dds-disc/participant-message.lisp` (the
  builtin-endpoint pattern to mirror); `src/dds-disc/disc.lisp` (`%handle-datagram` dispatch, `make-disc-node`);
  `src/dds-security/auth/handshake.lisp` (the internal token the wire codec bridges).
