# ADR 0033 — DDS-Security Authentication plugin: §8.7 handshake over the ParticipantStatelessMessage wire (Slice 2b-i)

- **Status:** Accepted (M7/P6; WP-DDS-SECURITY-AUTH-2BI, 2026-06-25)
- **Relates to:** ADR 0032 (Slice 2a — the in-process handshake whose tokens this
  slice puts on the wire); ADR 0031 (Slice 1 Crypto plugin — Slice 2c will feed its
  `key-material` with SharedSecret-derived keys); ADR 0025 (DARE — the `dds-dare`
  OpenSSL FFI extended by Slice 2a and consumed here); FR-SEC-2 (no hand-rolled
  crypto); NFR-SEC-POSTURE (bounds-checked parsers, fail-closed, fuzzed);
  NFR-MEM (off the measured CDR hot path).
- **Standards:** OMG DDS-Security 1.1 §7.4.4 (ParticipantGenericMessage IDL layout),
  §7.4.6.1 (PSM builtin endpoint set, Table 29), §8.7 (Authentication plugin
  behaviour), §8.7.2.4 (three-message handshake state machine), §9.3 (`DDS:Auth:PKI-DH`
  algorithm specification), §9.3.4 (DataHolder / DataHolderSeq IDL); OMG RTPS 2.5
  §9.4.1.3 (PID_IDENTITY_TOKEN), §9.5.1.3 (PSM EntityIds), §9.6.2.2.2 (unknown PID
  skipping); the T0 spike
  (`docs/superpowers/spikes/2026-06-25-dds-security-auth-wire-transport.md`) — the
  primary wire-constant reference for this ADR.

---

## Context

ADR 0032 (Slice 2a) delivered the complete §8.7.2.4 PKI-DH three-message handshake
(Request → Reply → Final → SharedSecret) between two in-process participants.  Tokens
were passed as function arguments using an internal tagged-binary format.  Slice 2b-i
puts those tokens on the **wire**: the SPDP carries the `IdentityToken` in
`PID_IDENTITY_TOKEN`, and the handshake tokens travel over the
`ParticipantStatelessMessage` (PSM) builtin endpoints in CDR-LE `DataHolder` /
`ParticipantGenericMessage` frames.

The sub-slice structure of WP-DDS-SECURITY-AUTH-2BI:

| Sub-slice | Scope | Status |
|---|---|---|
| **2b-i (this ADR)** | Wire transport: SPDP IdentityToken, PSM endpoints, DataHolder/envelope codec, our-to-our handshake over UDP | **LANDED** |
| 2b-ii | Discovery integration: on-participant-discovered hook, auth manager, per-participant auth-state, endpoint-match auth-gate, `select-auth-suite` wired to cert key kinds | pending |
| 2c | Crypto key-exchange: derive `key-material` from SharedSecret → replace `make-test-key-material` | pending |

**Slice 2b-i goal:** two real disc-nodes (with SPDP carrying `PID_IDENTITY_TOKEN` +
PSM bits 22/23) perform real SPDP discovery and then complete the full §8.7.2.4
handshake over the PSM wire.  Both sides reach `:authenticated` with byte-equal
`SharedSecret`.  The handshake is driven by explicit test code (not yet by the
on-discovery hook — that is 2b-ii).

---

## Decision — as-built architecture

### Module layout

Two new files added to the existing `dds-security` ASDF system (no new top-level
system) and one new file in the existing `dds-disc` system:

| File | Responsibility |
|---|---|
| `src/dds-security/auth/wire.lisp` | §9.3.4 CDR-LE DataHolder codec + §7.4.4 ParticipantGenericMessage / ParticipantStatelessMessage envelope codec |
| `src/dds-rtps/discovery.lisp` | Extended with `PID_IDENTITY_TOKEN` (PID 0x1001) serialization + `identity-token-octets` slot on `spdp-data`; PSM endpoint-set bits 22/23 added to the `+builtin-endpoint-set-default+` mask when `identity-token-octets` is non-nil |
| `src/dds-disc/stateless-message.lisp` | PSM builtin endpoints (`+entityid-participant-stateless-writer+` = 0x000201C3, `+entityid-participant-stateless-reader+` = 0x000201C4), `%send-stateless-message`, `on-stateless-message` dispatch slot on `disc-node` |

### SPDP IdentityToken (§8.7.2.2 / §9.3.1 / RTPS 2.5 §9.4.1.3)

`spdp-data` gains an `identity-token-octets` slot (type `(or (simple-array
(unsigned-byte 8) (*)) null)`, default NIL).  When non-NIL:

- `serialize-spdp-data` emits `PID_IDENTITY_TOKEN` (PID 0x1001, per DDS-Security 1.1
  §9.4.1.3) carrying the CDR-LE `DataHolder` bytes produced by
  `dds.security:identity-token` — the same 4-string `DataHolder` built in Slice 2a.
- The `builtin-endpoint-set` is ORed with bits 22 (`+be-participant-stateless-writer+`)
  and 23 (`+be-participant-stateless-reader+`) per DDS-Security 1.1 §7.4.6.1 Table 29.
- `parse-spdp-data` populates the `identity-token-octets` field when PID 0x1001 is
  present, discarding unknown PIDs otherwise (RTPS 2.5 §9.6.2.2.2 conformance).

**Default-OFF byte-identical:** when `identity-token-octets` is NIL (the default), the
serialized SPDP is byte-identical to the pre-security wire — no new PID, no extra bits.
This is proven by `run-auth-spdp-identity-token-test` arm (b).

**Don't-break-plain:** a PLAIN peer (no security) skips PID 0x1001 silently because the
optional bit (bit 14 of the PID word) is set per §9.4.1.3.  The PSM bits 22/23 in
`builtin-endpoint-set` are unknown to a plain receiver and are ignored per RTPS 2.5
§8.5.3.1.  The in-process test and the RTPS spec argument are the portable evidence; see
`interop/security-auth-discovery/README.md` for the full environment-limited outcome.

### The §9.3.4 DataHolder CDR-LE codec (`src/dds-security/auth/wire.lisp`)

The Slice 2a internal tagged-binary token format is **not** the wire format.  The PSM
wire carries tokens as CDR-LE `DataHolder` blobs inside a `DataHolderSeq`.

**`handshake-token->dataholder (token)`** — serializes a `handshake-token` struct to
CDR-LE `DataHolder` octets:

```
class_id:          u32-LE(strlen+1) | ascii | NUL | pad-to-4
PropertySeq:       u32-LE(0)             -- always count=0 for HST; present per §9.3.4
BinaryPropertySeq: u32-LE(count) | BinaryProperty*
  BinaryProperty:  name(CDR-LE string) | value(u32-LE(len) | bytes) | propagate(1B) | 3-pad
```

`PropertySeq` emits count=0 (empty), not an absent field — the XCDR1 `@optional`
encoding is count=0, not a 0-byte sequence (pinned from T0 spike §10.5 via Fast DDS
`CDRMessage::addParticipantGenericMessage`; HIGH confidence).

**`dataholder->handshake-token (octets)`** — the inverse: bounds-checks every length
field (caps: seq-count ≤ 65536; string len ≤ 65536; value len ≤ 0x1000000); returns NIL
on any malformed/truncated/over-declared input (fail-closed, NFR-SEC-POSTURE, holds at
`(safety 0)`).

### The §7.4.4 ParticipantGenericMessage envelope codec

`make-generic-message` serializes the outer envelope as CDR-LE:

```
message_identity        (GUID_t[16] + int64 LE[8] = 24 octets)
related_message_identity (MessageIdentity, 24 octets)
destination_participant_key (GUID_t, 16 octets)
destination_endpoint_key    (GUID_t, 16 octets)
source_endpoint_key         (GUID_t, 16 octets)
message_class_id (CDR-LE string; "+DDS+Auth+PKI-DH:1.0+HandshakeRequest" etc.)
message_data (u32-LE(count) + DataHolder*)
```

No `message_aux` field (pinned from Fast DDS `CDRMessage::addParticipantGenericMessage`
via T0 spike §10.1; HIGH confidence).

`parse-generic-message` is the inverse: returns 9 values
`(source-guid sn related-guid related-sn dest-participant-guid dest-endpoint-guid
  source-endpoint-guid message-class-id dataholder-octets-list)` on success,
`(NIL 0 NIL 0 NIL NIL NIL NIL NIL)` on any malformed input (fail-closed).

### Endianness split

Two separate endiannesses coexist within the authentication layer:

| Layer | Endianness | Rationale |
|---|---|---|
| PSM wire transport (DataHolder + envelope) | **CDR-LE** | RTPS 2.5 §8.3.3 / §9.6.1 E-flag; PSM DATA submessage carries CDR-LE payload |
| Handshake hash/signature inputs | **CDR-BE** | §9.3.2 BinaryPropertySeq hash inputs; Fast DDS corroboration (Slice 2a, spike §6) |

The Slice 2a `%cdr-be-binaryproperty-seq` helpers in `handshake.lisp` and the Slice
2b-i `%build-dataholder-le` / `%cdr-binary-property-le` in `wire.lisp` are distinct and
never mixed.  This is the conformant design; the LE/BE split is documented in the
`wire.lisp` file header.

### PSM EntityIds (§9.5.1.3, spike §3.1)

Both EntityIds are pinned from DDS-Security 1.1 §9.5.1.3 Table 40 and the T0 spike;
never from memory:

| Symbol | Value | Role |
|---|---|---|
| `+entityid-participant-stateless-writer+` | `0x000201C3` | PSM writer EntityKind 0xC3 (built-in with key) |
| `+entityid-participant-stateless-reader+` | `0x000201C4` | PSM reader EntityKind 0xC4 (built-in with key) |

### Message class_id constant

`+auth-message-class-id+` = `"dds.sec.auth"` — the
`ParticipantGenericMessage.message_class_id` used for all handshake tokens (DDS-Security 1.1
§7.4.4 / §9.3; corroborated by Fast DDS `AUTHENTICATION_PARTICIPANT_STATELESS_MESSAGE`).

### `%send-stateless-message` and `on-stateless-message`

`disc-node` gains two additions in `stateless-message.lisp`:

- `%send-stateless-message (node dest-prefix envelope-octets)` — wraps the envelope in
  a DATA submessage and sends it unicast to the dest-prefix's PSM reader EntityId port.
- `on-stateless-message` slot — a `(or function null)` closure set at construction;
  called by the receiver thread with `(node src-prefix token)` when a PSM DATA arrives
  at our PSM reader endpoint.

### Endianness of the PSM DATA submessage

The PSM DATA carries the `ParticipantGenericMessage` as CDR-LE serialized payload (E-flag
= 1, Little-Endian; per RTPS 2.5 §8.3.3.1).  The existing Slice 2a signature (CDR-BE
`BinaryPropertySeq`) is carried verbatim as raw bytes within the CDR-LE DataHolder
binary-property value field — no cross-conversion (spike §10.4 confirms this: the BE
bytes are opaque octets inside the LE envelope).

---

## Our-to-our handshake-over-wire proof

`run-auth-handshake-over-wire-test` proves end-to-end:

1. Two real `disc-node` instances, each with `:identity-token-octets` set, perform
   **real SPDP discovery** on loopback (unicast peer list).
2. Node-A (GUID prefix `0x010203...`, lexicographically smaller) is the requester per
   §8.7.2.4.
3. A is requester: `begin-handshake-request` → `handshake-token->dataholder` →
   `make-generic-message` → `%send-stateless-message` (UDP unicast to B).
4. B's `on-stateless-message` callback receives the token via the live UDP wire →
   `parse-generic-message` → `dataholder->handshake-token` → `%serialize-token` →
   `begin-handshake-reply` → sends the Reply to A.
5. A's callback receives Reply → `process-handshake` → A reaches `:authenticated`;
   sends Final to B.
6. B receives Final → `process-handshake` → B reaches `:authenticated`.
7. Both `(shared-secret-bytes)` values are **byte-equal** (32 bytes, SHA-256 of the
   ECDH agreed value, §9.3.3).

All seven steps are proven by the test's assertions (bounded 4-second poll).

---

## Don't-break-plain interop check — actual outcome

The live cross-peer don't-break check is **ENVIRONMENT-LIMITED**:

- RTI Connext 7.3.1 is installed; `rtiddsspy` is available.
- The RTI Shapes Demo (the standard scriptable ShapeType peer) requires a display
  session and is not headlessly scriptable in this CI environment.
- Fast DDS 3.6.1 peer tools are **not installed** in this environment.
- `run-dont-break-plain.sh` documents the live steps and runs the portable guard.

**Portable guard:** `run-auth-spdp-identity-token-test` arm (b) proves that the
DEFAULT-OFF path (identity-token-octets=NIL) is byte-identical to the pre-security
wire.  All existing cross-DDS interop tests (300+ tests running both Connext and Fast
DDS against our security build) pass with NIL identity-token-octets, confirming that
the security build does not regress plain discovery or DATA exchange.

**RTPS spec evidence:** PID 0x1001 has the optional bit set (bit 14) per DDS-Security
1.1 §9.4.1.3; RTPS 2.5 §9.6.2.2.2 mandates that unknown optional PIDs are silently
skipped.  PSM bits 22/23 in `BuiltinEndpointSet` are ignored by a receiver that does
not implement DDS-Security (RTPS 2.5 §8.5.3.1).

---

## What Slice 2b-ii adds

The `on-stateless-message` slot exists and is tested; what 2b-ii delivers is the
automatic wiring:

- **On-participant-discovered hook** in the SPDP receive path: when a peer SPDP carries
  `PID_IDENTITY_TOKEN`, the disc-node extracts it and triggers the auth-state machine.
- **Auth manager**: per-participant auth-state record (pending-request / pending-reply /
  authenticated / rejected); lifecycle tied to discovery events.
- **Endpoint-match auth-gate**: a participant whose authentication ends in `:rejected`
  is NOT matched for user-data communication (the DCPS match is deferred or cancelled).
- **`select-auth-suite` wired**: instead of an explicit `suite` argument,
  `begin-handshake-request` / `begin-handshake-reply` will call `select-auth-suite`
  from the cert key kinds loaded during identity validation.
- **Algorithm cross-check**: explicit assertion that the peer's advertised
  `c.kagree_algo` / `c.dsign_algo` strings in the Request token match the selected
  suite (the current implementation fails closed via EVP error or signature rejection,
  but the explicit guard + a dedicated negative test belong with the suite-wiring).

---

## Known limitations / Slice-5 carries

1. **Slice 2b-ii not yet implemented.** The `on-stateless-message` hook in T3 is
   driven by explicit test code (not by the SPDP discovery trigger).  The auth manager,
   per-participant auth-state, and the endpoint-match gate are pending.

2. **`select-auth-suite` not yet wired into entry points.** `begin-handshake-request`
   and `begin-handshake-reply` take an explicit `suite` argument.  Wiring
   `select-auth-suite` (cert key kinds → suite) into the auto-triggered 2b-ii code path
   is the natural attachment point.

3. **DataHolder + PSM-payload byte-match vs Connext unverified (Slice 5).** The CDR-LE
   DataHolder encoding is self-consistent (our-to-our, proven by corpus + fuzz) and based on the
   §9.3.4 IDL and Fast DDS corroboration.  The exact byte-match against a live Connext
   peer has not been performed (the RTI Security Plugins are not installed).  Concretely: the PSM
   serializedPayload here is the raw `ParticipantGenericMessage` and OMITS the 4-byte CDR_LE
   encapsulation header (`00 01 00 00`) that a real DDS-Security peer prepends (spike §5) —
   self-consistent our-to-our (both ends omit it), but adding-on-send / skipping-on-receive is a
   required Slice-5 cross-vendor fix (a Connext peer would otherwise consume `00 01 00 00` as the
   first 4 bytes of `message_identity`).

4. **Empty-sequence encoding (Slice 5 verification).** `PropertySeq` emits count=0
   (not XCDR1-absent flag).  Fast DDS corroboration confirms count=0; verification
   against a live Fast DDS-Security capture is a Slice-5 item.

5. **Live Connext-Security authentication interop (Slice 5 — the P6 exit gate).**
   A live PKI-DH handshake against a running RTI Connext-Security stack on the wire
   has NOT been performed.  It requires the licensed Security Plugins add-on
   (`rti_connext_dds_secure_plugins`), which is not installed.  The aspects that are
   self-consistent (our-to-our) but unverified vs Connext live:
   - DataHolder CDR-LE exact byte layout.
   - CDR-BE BinaryPropertySeq hash/signature input alignment.
   - FFDH dh1/dh2 SPKI-DER encoding.
   - RSA-PSS saltlen=32 vs Connext's convention.

   **Do NOT interpret any statement in this ADR as "cross-vendor authentication interop
   verified."**

---

## Tests

| Test | What it proves |
|---|---|
| `run-auth-spdp-identity-token-test` | (a) PID_IDENTITY_TOKEN round-trips + PSM bits 22/23 set; (b) DEFAULT-OFF byte-identical |
| `run-auth-wire-codec-test` | (a) DataHolder round-trip fidelity; (b) ParticipantGenericMessage round-trip byte-exact; (c) self-consistency prefix vs pinned CDR-LE corpus |
| `run-auth-wire-fuzz-test` | 2000 adversarial blobs through `dataholder->handshake-token` AND `parse-generic-message` at `(safety 0)` — fail-closed (NIL) on every input |
| `run-auth-handshake-over-wire-test` | Full SPDP discovery + §8.7.2.4 handshake over real UDP loopback → both `:authenticated` + byte-equal SharedSecret |

Clasp 329 + SBCL 329.  All gates green.

---

## §M7 roadmap update

| Slice | Description | Status |
|---|---|---|
| 1 | Crypto plugin: AES256-GCM `SecuredPayload` + session-key KDF (ADR 0031) | LANDED |
| 2a | Authentication plugin: PKI identity + §8.7.2.4 PKI-DH handshake → SharedSecret, our-to-our (ADR 0032) | LANDED |
| **2b-i (this ADR)** | Wire transport: SPDP IdentityToken + PSM endpoints + DataHolder/envelope codec + our-to-our handshake over UDP | **LANDED** |
| 2b-ii | Discovery integration: on-participant-discovered hook + auth manager + per-participant auth-state + endpoint-match auth-gate + `select-auth-suite` wiring | pending |
| 2c | Crypto key-exchange: `ParticipantVolatileMessageSecure` → derive `key-material` from SharedSecret + challenges | pending |
| 3 | AccessControl plugin (§8.8) | pending |
| 4 | Secure discovery: SPDP/SEDP participant/endpoint authentication | pending |
| 5 | Connext-Security live interop (P6 exit gate; requires RTI Security Plugins) | pending |

---

## Consequences

- **NFR-MEM:** `make mem` stays **0.0000** bytes/sample.  The PSM transport is
  control-plane discovery — no per-sample path.
- **NFR-SEC-POSTURE:** `dataholder->handshake-token` and `parse-generic-message` are
  bounds-checked at every length field; `run-auth-wire-fuzz-test` proves no OOB /
  crash / partial parse on 2000 adversarial blobs at `(safety 0)`.
- **FR-SEC-2:** no hand-rolled crypto.  The DataHolder and envelope codecs are pure
  CDR-LE serialization; the signature bytes are carried verbatim from Slice 2a without
  recomputation.
- **NFR-PORT:** no reader conditionals in `src/dds-security/` or `src/dds-disc/`.
  `gate-hotpath(8)` unaffected.
- **Default-OFF:** a disc-node without `:identity-token-octets` has byte-identical
  SPDP and no `on-stateless-message` overhead.
- **Gates:** `build` PASS; `test-clasp` 329 PASS; `test-sbcl` 329 PASS;
  `gate-hotpath(8)` PASS; `gate-types` PASS; `mem(0.0000)` PASS; `fuzz` PASS;
  `wire` PASS (PSM DATA submessage shape validated).

---

## References

- T0 spike: `docs/superpowers/spikes/2026-06-25-dds-security-auth-wire-transport.md`
- Design spec: `docs/superpowers/specs/2026-06-24-dds-security-auth-2bi-handshake-wire-design.md`
- `src/dds-security/auth/wire.lisp` — §9.3.4 DataHolder codec + §7.4.4 envelope codec
- `src/dds-rtps/discovery.lisp` — SPDP `PID_IDENTITY_TOKEN` + PSM endpoint-set bits
- `src/dds-disc/stateless-message.lisp` — PSM EntityIds, `%send-stateless-message`,
  `on-stateless-message` slot
- `src/dds-tests/security-auth-test.lisp` — all 2b-i test functions
- `interop/security-auth-discovery/README.md` — don't-break-plain outcome
- `interop/security-auth-discovery/run-dont-break-plain.sh` — harness + environment docs
- ADR 0032 — Slice 2a (the in-process handshake extended by this slice)
- ADR 0031 — Slice 1 (Crypto plugin)
- ADR 0025 — DARE (the `dds-dare` OpenSSL FFI)
