# WP-DDS-SECURITY-AUTH-KEYX — design (M7/P6 Slice 2b-ii + 2c, merged)

**Status:** DESIGN — approved 2026-06-26, pending spec review.
**Milestone:** M7 / P6 — DDS-Security 1.1. Completes Slice 2 (Authentication) and absorbs Slice 2c (crypto key exchange).
**Prior:** Slice 1 = crypto-payload (ADR 0031); Slice 2a = handshake → SharedSecret (ADR 0032); Slice 2b-i = handshake over the PSM wire (ADR 0033).
**ADR (to be written at the capstone):** 0034.

---

## 1. Goal (the vertical slice)

Deliver the **secure participant end-to-end, our-to-our**: a participant configured with an identity automatically authenticates every discovered security-enabled peer over the ParticipantStatelessMessage (PSM) wire, exchanges per-writer key material, **gates endpoint matching on authentication**, and **encrypts/decrypts real user data with the exchanged keys — dropping the Slice-1 pre-shared test key** (`make-test-key-material`).

This is a single vertical slice through every layer: identity → handshake → SharedSecret → KxKey → key-material exchange → installed per-writer keys → encrypted DATA on the wire → decrypted at the reader. Authenticating without using the resulting key would be a horizontal layer; this slice is end-to-end.

**Non-goals (deferred):** AccessControl/permissions (Slice 3); secure discovery — secured SPDP/SEDP (Slice 4); live Connext-Security interop (Slice 5 = the P6 exit gate); the full reliable ParticipantVolatileMessageSecure builtin endpoint (Slice 5 — see §9); RTPS/submessage protection beyond §9.5.3.3 serialized-payload protection (later).

---

## 2. Approved decisions

1. **Slice boundary:** full end-to-end vertical slice (auth manager + gating + key-material exchange + encrypted data, pre-shared key dropped). Absorbs Slice 2c.
2. **Enforcement posture:** **strict authenticated-only** matching for a security-enabled participant (DDS-Security default `allow_unauthenticated_participants = FALSE`). The `allow_unauthenticated` governance knob is **YAGNI — deferred**. Plain (no-identity) participants are byte-identical to today.
3. **Key-exchange transport:** conformant **§9.5.2 KeyMaterial**, **KxKey-encrypted** (keys never in clear on the wire), carried over the **existing 2b-i PSM stateless transport** with a simple resend, after authentication. The full reliable **ParticipantVolatileMessageSecure** endpoint is a documented **Slice-5 cross-vendor carry** (same rhythm as 2b-i's deferred encapsulation header). The KeyMaterial **format** stays conformant so Slice-5 interop is reachable.

---

## 3. Architecture

The auth/key **manager lives in the DCPS layer** — `src/dds-dcps/auth-manager.lisp` — mirroring `src/dds-dcps/type-gate.lisp`. It installs hooks onto the disc-node and holds per-participant security state at the `domain-participant` level (`dp-auth-state`, analogous to `dp-type-gate-state`, `src/dds-dcps/entities.lisp:36`).

Layering rationale: `dds-disc` already depends on `dds-security` (2b-i's `%on-stateless-message` calls `dds.security:parse-generic-message`), so the manager — which needs both `dds-security` (handshake + keyexchange) and `dds-disc` (hooks, send, matching) — must sit **above both**, in `dds-dcps`. `dds-disc` stays crypto-free and gains only thin extension points. `dds-security` gains no dependency on `dds-disc` (acyclic preserved).

---

## 4. Components

### New

**`src/dds-dcps/auth-manager.lisp`** — the orchestrator.
- Per-remote security state, keyed by 12-octet GUID prefix (`equalp`, the established per-remote registry pattern, `disc.lisp:113`): `handshake-handle` (in-flight), `authenticated-p`, `kx-key` (foreign), installed remote `KeyMaterial` (per remote writer GUID), state enum (`:none|:handshaking|:authenticated|:keyed|:rejected`).
- Installs three hooks onto the disc-node: `on-participant-discovered` (trigger), `on-stateless-message` (drive handshake + receive key material — the 2b-i hook slot, finally given an implementation here), and the `auth-gate` (consulted at endpoint-match).
- Drives: validate remote identity → `select-auth-suite` → role by GUID order → handshake state machine → SharedSecret → KxKey → generate + send KeyMaterial → install remote KeyMaterial → mark `:keyed` → `dds.disc:resume-parked-matches`.

**`src/dds-security/auth/keyexchange.lisp`** — pure `dds-security` (no disc dep).
- §9.5.3 **KxKey/KxSalt derivation** from the SharedSecret + challenges (KDF labels pinned by the spike).
- §9.5.2 **KeyMaterial generation** — random master key / master salt / key-id per writer (`dds.dare` RAND; secrets in `dds.pal` foreign buffers).
- **CryptoToken serialize/parse** — a §7.4.4 ParticipantGenericMessage carrying the KxKey-encrypted KeyMaterial (class_ids pinned by the spike); reuses the 2b-i `dds.security` envelope codec. Fail-closed, bounds-checked.

### Modified

- **`src/dds-disc/disc.lisp`** — add the `on-participant-discovered` hook slot (fired from `%record-participant:666` when a *new, security-capable* remote — non-nil `identity-token-octets` in `spdp-data` — is first recorded); add the `disc-node-auth-gate` slot; compose it at `%match-remote-endpoint:892` as the **second gate after the type-gate** (identical `:compatible/:incompatible/:pending` ladder + `%park-match`/`resume-parked-matches`); clear per-remote auth-state on lease-out (`%lease-sweep:743`). Crypto-free.
- **`src/dds-security/auth/handshake.lisp`** — close the **algo-vs-suite cross-check** gap (replier 390–393, requester 516–517: assert the peer's advertised `dsign`/`kagree` strings equal the selected suite's, else fail-closed); **wire `select-auth-suite`** (derive local cert-kind from the local identity, remote cert-kind from the remote IdentityToken `dds.cert.algo` property: `"EC-prime256v1"`→`:ec`, `"RSA-2048"`→`:rsa`), making the explicit `suite` argument internal/derived.
- **Slice-1 crypto path** (`src/dds-security/transform.lisp` + `key-material.lisp`, and the disc-node `crypto-transform` resolution) — resolve the **exchanged per-writer** KeyMaterial (keyed by writer GUID) instead of `make-test-key-material`. `make-test-key-material` is retired from the live path (may remain for unit tests only).

---

## 5. Data flow (end-to-end)

1. Participant A (identity configured) → `validate-local-identity` → IdentityToken + PSM bits in SPDP (2b-i).
2. A discovers B (`%record-participant`) → **`on-participant-discovered`** fires → manager `validate-remote-identity` (B's IdentityToken from `spdp-data`) → role by §8.7.2.4 GUID order.
3. Requester: `select-auth-suite` (A-kind, B-kind) → `begin-handshake-request` → send over PSM.
4. 3-message handshake (2a state machine over 2b-i wire) → both `:authenticated` → **SharedSecret**.
5. Both derive **KxKey** from the SharedSecret (§9.5.3).
6. Each generates §9.5.2 **KeyMaterial** for its writers → KxKey-encrypts → sends **CryptoTokens** over PSM (resend until installed) → peer installs the remote writer's KeyMaterial.
7. Manager marks the remote `:keyed` → **`resume-parked-matches`** → endpoints match.
8. A's writer publishes → crypto-transform encrypts with A's exchanged per-writer KeyMaterial → B's reader decrypts with the installed remote KeyMaterial. **No pre-shared key anywhere.**

---

## 6. Auth-gate (strict, conformant)

At `%match-remote-endpoint`, after the type-gate returns `:compatible`, consult `auth-gate(node, remote, local)` (extract the remote prefix via `%remote-guid-prefix`, `type-gate.lisp:85`):

- local **not** security-enabled (no identity) → `:compatible` (plain path, unchanged, byte-identical).
- remote `:keyed` (authenticated + keys installed) → `:compatible`.
- handshake/key-exchange in flight → `:pending` (`%park-match`; resumed on completion).
- remote has no IdentityToken (plain peer) **or** handshake/key-exchange rejected → `:incompatible` (strict refuse).

Consulted outside the node lock, on the receiver thread, exactly like the type-gate. Verdicts cached per remote; resume on `:keyed` transition.

---

## 7. Error handling / fail-closed

- Every handshake/keyexchange/CryptoToken parser is **bounds-checked before each read/alloc and fail-closed** (the 2b-i pattern; the receiver thread never crashes or signals). Caps on lengths/counts.
- A failed/rejected handshake, or a KeyMaterial decrypt failure (bad KxKey / tamper), installs **no keys** → the remote stays unmatched (`:pending`→`:incompatible`). **No plaintext fallback** for a security-enabled participant.
- KxKey, master keys/salts, SharedSecret held in `dds.pal:alloc-static/free-static` foreign buffers (clasp#1793-safe; never `static-vectors` directly — see the operating contract / `[[clasp-threading-gap]]`).
- **No hand-rolled crypto** (FR-SEC-2): all primitives via `dds-dare`/OpenSSL.

---

## 8. Constraints (global, copied verbatim into the plan)

- OMG DDS-Security 1.1 conformance is non-negotiable; the only allowed deviation is interop behavior added on top, never replacing. False-REJECT is the worst class.
- Never hardcode wire constants from memory — pin every §9.5 constant (KeyMaterial layout, KxKey KDF labels, CryptoToken GenericMessage `message_class_id` values) from the spec clause + Fast-DDS corroboration (Apache, read-for-understanding, provenance recorded; **no RTI source** — clean-room). Cite the clause.
- KATs are **published vectors only**, fetched from the authoritative source, never self-generated/recalled.
- `defun*`/`defstruct*` on every function/struct; full `ftype` on every function.
- No reader conditionals outside `dds-pal/`.
- Both impls validate, **Clasp first**, identically.
- Docs in lockstep (docstrings + `docs/wiki/security.md` + README + `docs/verification.csv`) on every API change; SBOM auto-regenerated.
- Hot-path purity + static-arena: the default (no-identity) path allocates zero per-sample and is byte-identical; `mem 0.0000` on the default workload.

---

## 9. Honest interop posture (our-to-our this slice)

Achieved: full our-pub→our-sub — two security-enabled participants authenticate on discovery, exchange conformant KxKey-encrypted §9.5.2 key material, match **only** once authenticated, and exchange **encrypted** user data with **no pre-shared key**.

**Slice-5 cross-vendor carries** (documented in ADR 0034):
- The full **reliable ParticipantVolatileMessageSecure** builtin endpoint (this slice carries the conformant KeyMaterial over the best-effort PSM transport instead).
- RTPS-/submessage-level protection (this stack does §9.5.3.3 serialized-payload protection from Slice 1).
- 2b-i's existing carries (PSM serializedPayload encapsulation header, etc.).
- Live RTI Connext-Security end-to-end (RTI Security Plugins / `libnddssecurity` not installed here).

don't-break-plain: plain participants byte-identical; a security-enabled participant **strictly refuses** unauthenticated peers (conformant default).

---

## 10. Testing / DoD (spike-first, both impls Clasp-first)

- **T0 spike:** pin the §9.5 key-exchange constants (KeyMaterial format, KxKey KDF labels, CryptoToken `message_class_id` values) from the spec + Fast-DDS corroboration (clean-room); fetch a **published** KxKey/KDF KAT (e.g. the relevant HKDF/HMAC vector our OpenSSL reproduces — never self-generated). Confirm assumptions or re-plan.
- **Unit:** KxKey-derivation KAT (published); KeyMaterial generation + CryptoToken round-trip; algo-vs-suite cross-check negatives (both roles); `select-auth-suite` wiring (EC/RSA/ mismatch→reject).
- **Integration (headline, our-to-our):** two security-enabled disc-nodes discover → authenticate → exchange keys → **match only once authenticated** → **encrypted pub/sub round-trip with no pre-shared key** (assert ciphertext on the wire + plaintext at the reader); a security-enabled participant **refuses a plain peer** (non-vacuous strict-gating); plain-to-plain **byte-identical** (don't-break-plain).
- **Fuzz:** the keyexchange/CryptoToken parser (safety 0), 2b-i style.
- **Gates:** build / test-clasp / test-sbcl / gate-hotpath / gate-types / mem 0.0000 (default path) / fuzz / wire — green both impls.
- **Cross-DDS (directive):** the live secured cross-vendor run is Slice 5 (plugins not installed); the our-to-our end-to-end + the plain don't-break check stand here; a harness is provided for the owner's full env.

---

## 11. References

- OMG DDS-Security 1.1: §8.7 (authentication), §8.8.4 (ParticipantVolatileMessageSecure), §9.3 (auth plugin), §9.5.2 (KeyMaterial), §9.5.3 (key derivation + data protection), §7.4.4 (ParticipantGenericMessage).
- Recon (this repo): `src/dds-security/auth/{handshake,suites,identity,wire}.lisp`; `src/dds-disc/{disc,stateless-message,dataplane}.lisp`; `src/dds-dcps/type-gate.lisp`; `src/dds-dcps/entities.lisp`.
- Prior: ADR 0031 (crypto-payload), ADR 0032 (handshake), ADR 0033 (handshake wire).
