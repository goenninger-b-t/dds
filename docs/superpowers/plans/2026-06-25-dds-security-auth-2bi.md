# WP-DDS-SECURITY-AUTH-2BI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The DDS-Security §8.7 PKI-DH handshake completes over the real ParticipantStatelessMessage builtin-endpoint wire between two of our participants (harness-driven), our-to-our.

**Architecture:** SPDP carries `PID_IDENTITY_TOKEN` + the §7.4.6.1 security builtin-endpoint bits; a new PSM builtin writer/reader (best-effort, EntityId 0x000201C3/C4) transports a §7.4.x ParticipantGenericMessage envelope whose `message_data` is a §9.3.4 HandshakeMessageToken DataHolder (CDR-LE); a new `wire.lisp` bridges the 2a internal token to/from that DataHolder. Default-OFF (no identity token) = byte-identical SPDP + unchanged dataplane.

**Tech Stack:** Common Lisp (SBCL + Clasp, Clasp first), the `dds-rtps` discovery/ParameterList layer, the `dds-disc` builtin-endpoint + receive-dispatch layer, the `dds-security` 2a auth unit, `dds.core.buffer` CDR cursors, `defun*`/`defstruct*`.

## Global Constraints

- **No wire constants from memory** — the PSM EntityIds, the §7.4.6.1 builtin-endpoint-set bits, `PID_IDENTITY_TOKEN`, the §7.4.x ParticipantGenericMessage envelope layout, and the §9.3.4 DataHolder layout are **pinned by T0 (the spike)** from OMG DDS-Security 1.1 §7.4/§9.3 + DDSI-RTPS 2.5 §8.5/§9.6 + Fast DDS (read-for-understanding) + a plain-Connext SPDP capture, each cited in a comment. Tasks T1-T3 consume the T0-pinned constants from `src/dds-security/auth/constants.lisp` (the existing auth constants file) and/or `src/dds-rtps/discovery.lisp`.
- **OMG DDS-Security 1.1 §7.4/§9.3 + DDSI-RTPS 2.5 conformance** — the wire format never deviates.
- **Bounds-check the PSM envelope + DataHolder parsers even at `(safety 0)`** — a malformed/short/garbage message fails closed (returns NIL, dropped), never an OOB read or a receiver-thread crash; fuzzed (NFR-SEC-POSTURE).
- **Default-OFF byte-identical** — a `disc-node` built WITHOUT `:identity-token-octets` emits today's SPDP exactly (no `PID_IDENTITY_TOKEN`, no security endpoint bits, no PSM endpoints) and the dataplane is unchanged; `make mem` stays 0.0000. The PSM transport is control-plane discovery, off the measured CDR hot path.
- **No hand-rolled crypto** — the wire codec is pure serialization; all crypto is the 2a auth unit / `dds-dare`.
- **Endianness:** the 2a signature (Sign2/Sign1) is over CDR-**BE** (unchanged); the transport DataHolder + envelope here are CDR-**LE**. Keep them strictly separate.
- `defun*`/`defstruct*` + **full ftype** on every function; **no reader conditionals outside `dds-pal/`**; **Clasp AND SBCL both, Clasp first**; **no AI/assistant attribution** (cite "the operating contract" / the spec clause / the RFC); one-line comments only.
- Tests register in `src/dds-tests/packages.lisp` (export) + `src/dds-tests/echo-test.lisp` (`run-all-tests` alist), the way the existing `run-auth-*` tests do.

---

## File map

- `src/dds-rtps/discovery.lisp` (modify) — `spdp-data` `identity-token-octets` slot (~line 156); emit `PID_IDENTITY_TOKEN` in `serialize-spdp-data` (~181) + the security bits in `+builtin-endpoint-set-default+` (~58) when present; parse in `%fill-spdp-param` (~231). The PSM EntityId constants live here next to the SPDP/SEDP ones (~16-33).
- `src/dds-security/auth/wire.lisp` (new) — the §9.3.4 DataHolder codec (token ↔ CDR-LE DataHolder) + the §7.4.x ParticipantGenericMessage envelope codec; bounds-checked, fail-closed. Exported from `dds.security`.
- `src/dds-disc/stateless-message.lisp` (new) — the PSM builtin endpoints (`%send-stateless-message` / `%on-stateless-message`), the `on-stateless-message` `disc-node` hook, the `%handle-datagram` dispatch branch. Mirrors `src/dds-disc/participant-message.lisp`.
- `src/dds-disc/disc.lisp` (modify) — `on-stateless-message` slot on `disc-node` (~67) + `:identity-token-octets` keyword on `make-disc-node` (~241) + populate `%node-spdp-data` (~321) + the PSM dispatch branch in `%handle-datagram` (~970).
- `dds-security.asd` / `dds-disc.asd` (modify) — add the new components.
- `src/dds-tests/security-auth-test.lisp` (modify) + `packages.lisp` + `echo-test.lisp` — the new tests.
- `interop/security-auth/` (T0 capture) + `interop/security-auth-discovery/` (T4 don't-break-plain harness).
- `docs/adr/0033-dds-security-auth-wire.md` (new, T4); `README.md`, `docs/wiki/security.md`, `docs/verification.csv` (T4).

---

### Task 0 (SPIKE): Pin the §7.4/§9.3 wire constants + a plain-Connext SPDP capture

Investigation/scaffold, not TDD. Re-plan checkpoint at the end.

**Files:** Create `docs/superpowers/spikes/2026-06-25-dds-security-auth-wire-transport.md`; capture under `interop/security-auth/` (a plain-Connext + plain-Fast-DDS SPDP capture); append the pinned constants to `src/dds-security/auth/constants.lisp` and/or note where they go in `discovery.lisp`.

**Interfaces produced:** the pinned values T1-T3 consume — `+entityid-stateless-writer+` (0x000201C3) / `+entityid-stateless-reader+` (0x000201C4); the §7.4.6.1 builtin-endpoint-set bit positions for the secure builtins; `+pid-identity-token+`; the IdentityToken Token CDR layout (class_id + PropertySeq); the ParticipantGenericMessage envelope field order + types; the §9.3.4 HandshakeMessageToken DataHolder layout (class_id + BinaryPropertySeq) + the `message_class_id` string for auth.

- [ ] **Step 1:** Read OMG DDS-Security 1.1 §7.4.3 (the builtin secure-discovery + stateless endpoints), §7.4.4 (the ParticipantGenericMessage / ParticipantStatelessMessage structure), §7.4.6.1 (the BuiltinEndpointSet security bits), §9.3.4 (the HandshakeMessageToken serialized as a DataHolder), §8.7.2.2 (the IdentityToken). Record each pinned value WITH its §-clause in the spike doc. Use WebSearch/WebFetch for the OMG spec + corroborate against eProsima Fast DDS (`BuiltinProtocols`/`PDPSecurity`/`SecurityManager` + the `ParticipantStatelessMessage` types) — record provenance; mark anything you cannot ground as NEEDS-VERIFICATION rather than guessing.
- [ ] **Step 2:** Capture a PLAIN (non-security) Connext 7.3.1 + Fast DDS 3.6.1 SPDP announcement with tshark (the existing interop harnesses show how) to ground the SPDP ParameterList + the participant-data shape the IdentityToken PID slots into. (The security PIDs/bits themselves are NOT emitted by a plain peer — those are spec + Fast-DDS-pinned; the capture grounds the SPDP shell + confirms our additions will be appended cleanly.)
- [ ] **Step 3:** Append the pinned constants to `src/dds-security/auth/constants.lisp` (or, for the RTPS-level ones — the EntityIds + endpoint-set bits + PID — to `src/dds-rtps/discovery.lisp` next to the existing SPDP/SEDP constants), each a `defconstant`/`defparameter` with a one-line §-citation docstring. Confirm both impls still load (Clasp first). No logic.
- [ ] **Step 4: Re-plan checkpoint.** Summarize pinned-vs-NEEDS-VERIFICATION; flag any §7.4/§9.3 detail that changes T1-T3 (the plan assumes: SPDP is a ParameterList we append two PIDs to; PSM is best-effort DATA with no HEARTBEAT; the envelope is a CDR-LE struct; the DataHolder is class_id + BinaryPropertySeq). Commit the spike + capture + constants. Present the checkpoint before T1.

---

### Task 1: SPDP IdentityToken (slot + serialize/parse + endpoint-set bits + make-disc-node plumbing)

**Files:** Modify `src/dds-rtps/discovery.lisp` (the `spdp-data` slot + serialize + parse + the endpoint-set bits), `src/dds-disc/disc.lisp` (`make-disc-node` `:identity-token-octets` + `%node-spdp-data`); Test `src/dds-tests/security-auth-test.lisp` (`run-auth-spdp-identity-token-test`).

**Interfaces:**
- Consumes: T0 `+pid-identity-token+`, the security endpoint-set bits, the IdentityToken Token layout; `dds.security:identity-token` (the local IdentityToken octets from a `identity-handle`); the existing `spdp-data` struct + `serialize-spdp-data`/`parse-spdp-data`/`%fill-spdp-param`.
- Produces: `spdp-data` gains an `identity-token-octets` slot (default NIL); `make-disc-node` gains `:identity-token-octets` (default NIL); `%node-spdp-data` populates it; a peer's `parse-spdp-data` exposes it via the slot.

- [ ] **Step 1: Write the failing test** `run-auth-spdp-identity-token-test`: (a) build an `spdp-data` WITH `identity-token-octets` set to a fixture IdentityToken (from `validate-local-identity` on the EC fixture), `serialize-spdp-data` then `parse-spdp-data` → the parsed `identity-token-octets` byte-equals the input AND the parsed `builtin-endpoint-set` has the T0-pinned security bits set; (b) **default-OFF byte-identical:** an `spdp-data` with `identity-token-octets`=NIL serializes to bytes IDENTICAL to today (no `PID_IDENTITY_TOKEN`, no security bits) — assert against a pre-change golden (or assert the PID is absent + the endpoint-set has no security bits).
- [ ] **Step 2: Run — expect FAIL** (slot/PID unknown). Clasp first: `./scripts/with-clasp.sh --eval '(ql:quickload :dds-tests :silent t)' --eval '(dds.tests:run-auth-spdp-identity-token-test)'`.
- [ ] **Step 3: Implement** — add the `identity-token-octets` slot to `spdp-data`; in `serialize-spdp-data` emit `write-parameter +pid-identity-token+ <octets>` + OR the security bits into the emitted `builtin-endpoint-set` ONLY when `identity-token-octets` is non-nil; in `%fill-spdp-param` add the `+pid-identity-token+` branch (bounds-checked read). In `disc.lisp`: `make-disc-node :identity-token-octets` → a node slot → `%node-spdp-data` sets `spdp-data-identity-token-octets`. `defun*` + full ftype; one-line §-cited comments.
- [ ] **Step 4: Run — expect PASS** both impls (Clasp first, then SBCL via `make test-sbcl` or the per-test sbcl invocation). Register the test.
- [ ] **Step 5: Commit** `feat(security): WP-DDS-SECURITY-AUTH-2BI T1 — SPDP PID_IDENTITY_TOKEN + security endpoint-set bits (default-OFF byte-identical) (M7/P6 Slice 2b-i)`.

---

### Task 2: The wire codec — §9.3.4 DataHolder + §7.4.x ParticipantGenericMessage envelope

**Files:** Create `src/dds-security/auth/wire.lisp`; Modify `dds-security.asd`, `src/dds-security/packages.lisp`; Test `src/dds-tests/security-auth-test.lisp` (`run-auth-wire-codec-test`, `run-auth-wire-fuzz-test`).

**Interfaces:**
- Consumes: T0 the DataHolder + envelope layouts + the auth `message_class_id`; the 2a internal handshake-token (the binary-property set produced by `begin-handshake-request`/`-reply`/`process-handshake` in `src/dds-security/auth/handshake.lisp` — read how the token's properties are structured); `dds.core.buffer` CDR-LE cursors.
- Produces, exported from `dds.security`: `(handshake-token->dataholder octets-or-token) -> dataholder-octets` (CDR-LE), `(dataholder->handshake-token octets) -> token | nil` (fail-closed), `(make-generic-message …) -> envelope-octets` (the §7.4.x ParticipantGenericMessage CDR-LE), `(parse-generic-message octets) -> (values message-identity related-identity dest-guid src-guid message-class-id dataholder-octets-list) | nil` (fail-closed, bounds-checked).

- [ ] **Step 1: Write the failing test** `run-auth-wire-codec-test`: take a real Request token from `begin-handshake-request` (EC fixture), `handshake-token->dataholder` then `dataholder->handshake-token` → the reconstructed token drives `process-handshake` on the peer to the SAME next state as the in-process 2a path (round-trip fidelity); wrap it in `make-generic-message` then `parse-generic-message` → the message-class-id + the dest/src GUIDs + the DataHolder round-trip byte-identically. Plus a byte-corpus `%check` that the DataHolder's leading bytes match the T0-pinned class_id+CDR-LE layout.
- [ ] **Step 2: Run — expect FAIL** (codec undefined). Clasp first.
- [ ] **Step 3: Implement `wire.lisp`** — the DataHolder codec (CDR-LE: encapsulation/class_id string + BinaryPropertySeq from the token's binary properties; the inverse parse bounds-checks every length before reading) + the ParticipantGenericMessage envelope codec (the T0-pinned field order). The token's binary properties map 1:1 to the DataHolder's `binary_properties` (same names/values — the SIGNATURE property carries the 2a BE-computed bytes verbatim; do NOT recompute it here). `defun*` + full ftype; add to `dds-security.asd` after `handshake`; export from `dds.security`.
- [ ] **Step 4: Write `run-auth-wire-fuzz-test`** — N≈2000 malformed/short/oversized/random blobs through `dataholder->handshake-token` AND `parse-generic-message`, both prod + `(safety 0)`; assert each → NIL, no OOB/crash/signal escape (mirror `run-auth-token-fuzz-test`). Run all both impls (Clasp first). Register both tests.
- [ ] **Step 5: Commit** `feat(security): WP-DDS-SECURITY-AUTH-2BI T2 — §9.3.4 DataHolder + §7.4.x ParticipantGenericMessage wire codec (CDR-LE, bounds-checked, fuzzed) (M7/P6 Slice 2b-i)`.

---

### Task 3: ParticipantStatelessMessage builtin endpoints + handshake-over-the-wire

**Files:** Create `src/dds-disc/stateless-message.lisp`; Modify `src/dds-disc/disc.lisp` (`on-stateless-message` slot + the `%handle-datagram` dispatch branch), `dds-disc.asd`, `src/dds-disc/packages.lisp`; Test `src/dds-tests/security-auth-test.lisp` (`run-auth-handshake-over-wire-test`).

**Interfaces:**
- Consumes: T0 the PSM EntityIds; T2's `wire.lisp` codecs; the existing builtin-endpoint send pattern (`%send-paramlist`/`%send-msg-buf` in `disc.lisp`) + the WLP pattern in `src/dds-disc/participant-message.lisp`; the `%handle-datagram` DATA-by-writerId dispatch cond (`disc.lisp` ~917-972); 2a `begin-handshake-request`/`-reply`/`process-handshake`.
- Produces: `%send-stateless-message (node dest-prefix envelope-octets)` (best-effort DATA on the PSM writer EntityId, no HEARTBEAT); `%on-stateless-message (node src-prefix buf poff plen)` (parse via T2, fail-closed, call the hook); a `disc-node` `on-stateless-message` slot (`(or null function)`, default NIL) + a `make-disc-node :on-stateless-message` keyword; the `%handle-datagram` branch routing the PSM writer EntityId to `%on-stateless-message`.

- [ ] **Step 1: Write the failing test** `run-auth-handshake-over-wire-test`: two real disc-nodes on a loopback domain (mirror an existing 2-node disc test), each built with `:identity-token-octets` + an `:on-stateless-message` callback that feeds the received token into its handshake state + sends the next token back via `%send-stateless-message`. Drive: node A `begin-handshake-request` → A's PSM writer → B's PSM reader (`%on-stateless-message`) → B replies → … → BOTH nodes reach `:authenticated` with a byte-equal SharedSecret, with the tokens genuinely crossing the UDP wire (assert via the callback wiring, not an in-process shortcut).
- [ ] **Step 2: Run — expect FAIL** (`%send-stateless-message`/dispatch undefined). Clasp first.
- [ ] **Step 3: Implement `stateless-message.lisp`** (mirror `participant-message.lisp`): `%send-stateless-message` (write a DATA submessage with writerId = the PSM writer EntityId, readerId = the PSM reader EntityId, the envelope as the SerializedPayload, best-effort — no HEARTBEAT) to the dest participant's metatraffic locator; `%on-stateless-message` (parse the envelope+DataHolder via T2, fail-closed on NIL, else call `(disc-node-on-stateless-message node)` with the reconstructed token + src GUID). In `disc.lisp`: add the `on-stateless-message` slot + keyword; add the `%handle-datagram` cond branch `((= wtr +entityid-stateless-writer+) (%on-stateless-message node src-prefix buf poff plen))` before the user-data fallthrough. Add to `dds-disc.asd`; export from `dds.disc`. `defun*` + full ftype.
- [ ] **Step 4: Run — expect PASS** both impls (Clasp first). Register the test.
- [ ] **Step 5: Commit** `feat(disc): WP-DDS-SECURITY-AUTH-2BI T3 — ParticipantStatelessMessage builtin endpoints + handshake over the real PSM wire (M7/P6 Slice 2b-i)`.

---

### Task 4: Capstone — don't-break-plain interop + ADR 0033 + docs + gate sweep + final review

**Files:** Create `interop/security-auth-discovery/` (the don't-break-plain harness); Create `docs/adr/0033-dds-security-auth-wire.md`; Modify `README.md`, `docs/wiki/security.md`, `docs/verification.csv`.

- [ ] **Step 1: The don't-break-plain-discovery LIVE check.** A harness `interop/security-auth-discovery/run-dont-break-plain.sh`: start an OUR participant built WITH `:identity-token-octets` (so SPDP carries `PID_IDENTITY_TOKEN` + the security endpoint bits) publishing/subscribing ShapeType; run a PLAIN (non-security) Connext 7.3.1 peer and a PLAIN Fast DDS 3.6.1 peer; assert (a) the peer discovers our participant (the unknown PID + extra endpoint bits are ignored), (b) plain Shapes pub/sub works both directions, (c) the peer does NOT error on our SPDP. Capture tshark + document the outcome honestly. (Run live; if a peer is unavailable, document the limitation — the in-process default-OFF byte-identical test from T1 is the portable guard.)
- [ ] **Step 2: ADR 0033** (as-built): the §8.7 handshake over the ParticipantStatelessMessage wire; the SPDP IdentityToken + endpoint bits; the §9.3.4 DataHolder + §7.4.x envelope codec; the BE-signature/LE-transport split; default-OFF byte-identical; the our-to-our + don't-break-plain posture with live Connext-Security handshake interop DEFERRED to Slice 5; how 2b-ii (the on-discovery trigger + auth manager + match-gating + select-auth-suite wiring) follows. Model on ADR 0032.
- [ ] **Step 3: Docs lockstep** — `docs/wiki/security.md` §6 update (the PSM wire transport + the SPDP IdentityToken + the new `dds.security`/`dds.disc` API + the roadmap); `README.md` P6 row → "Slice 1 + 2a + 2b-i (handshake on the wire) landed; 2b-ii/2c/3-5 pending"; `docs/verification.csv` append a clean 6-column `P6-SEC-AUTH-WIRE` row (evidence = handshake-over-PSM-wire our-to-our + the codec corpus/fuzz + the don't-break-plain Connext+Fast DDS check; live Connext-Security DEFERRED). Verify it parses (Python `csv`, 6 cols).
- [ ] **Step 4: Full gate sweep** Clasp first: `make build && make test-clasp && make test-sbcl && make gate-hotpath && make gate-types && make mem && make fuzz && make wire`. Expected all green; `mem 0.0000`; `wire` validates the PSM DATA submessage shape. Report each.
- [ ] **Step 5: Commit** `docs(security): WP-DDS-SECURITY-AUTH-2BI T4 — don't-break-plain interop + ADR 0033 + docs + gate sweep (M7/P6 Slice 2b-i)`.
- [ ] **Step 6 (controller, not this task):** the final whole-branch review over `main..HEAD` (most capable model) → one fix wave → squash-merge presented for owner approval (HOLD PUSH).

---

## Self-review

**Spec coverage:** §2 SPDP IdentityToken → T1; §2/§3 PSM endpoints → T3; §3 DataHolder + envelope codec → T2; §3 endianness split → T2 (signature carried verbatim); §5 data flow → T3 test; §6 fail-closed/bounds/fuzz → T2 (codec) + T3 (receiver); §7 DoD (handshake-over-wire, codec corpus, don't-break-plain, fuzz, default-OFF, gates) → T1/T2/T3/T4; §9 tasks → T0-T4. The spike-pinned wire constants (§3/§8) are pinned in T0 and consumed thereafter — the correct spike-first handling, not a gap. No gap.

**Placeholder scan:** the only deferred values are the T0 spike constants (EntityIds, endpoint-set bits, PID, envelope/DataHolder layout) — explicitly assigned to T0 with §-citations, the conformant no-constants-from-memory handling, not vague TODOs. The negatives (fuzz/fail-closed) are concrete. No hand-waving.

**Type consistency:** `spdp-data identity-token-octets` (T1) consumed by T3's nodes; `handshake-token->dataholder`/`dataholder->handshake-token` + `make-generic-message`/`parse-generic-message` (T2) consumed by T3's `%send`/`%on-stateless-message`; `%send-stateless-message`/`%on-stateless-message` + the `on-stateless-message` slot (T3) consistent; the PSM EntityIds (T0) used in T3's send + dispatch. Consistent.
