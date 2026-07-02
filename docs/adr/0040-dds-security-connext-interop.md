# ADR 0040 — Live RTI Connext-Security cross-vendor interop: the §8.7 auth → keyed → secure-SEDP → protected-data reconciliation campaign (Slice 5b, Connext half of the P6 exit gate)

- **Status:** Accepted (M7/P6; WP-DDS-SECURITY-CONNEXT-INTEROP, 2026-07-02)
- **Relates to:** ADR 0037 (Slice 5 — live Fast DDS-Security, the Fast-DDS half of the same P6 exit gate; ADR 0040 closes the Connext half); ADR 0036 (Slice 4 — secure discovery our-to-our; the metatraffic SRTPS and INFO_SRC carries confirmed here vs a keyed Connext peer); ADR 0035 (Slice 3 — AccessControl; the Permissions document plumbed into `c.perm` and validated by Connext); ADR 0034 (Slice 2b-ii + 2c — auth manager + KxKey; the auth state machine driven cross-vendor here); ADR 0033 (Slice 2b-i — the PSM `DataHolder`/`ParticipantGenericMessage` wire codec; the class_id version-tolerance and lean-Reply carries resolved here); ADR 0032 (Slice 2a — §8.7.2.4 PKI-DH handshake; the challenge-binding sub-protocol adds to the §8.7.2.3-level above it); ADR 0031 (Slice 1 — the serialized-payload crypto codec; the empty-AAD + SecureDataTag 4-align addenda shipped in ADR 0037 are exercised and confirmed vs a live Connext peer here); ADR 0025 (DARE — the `dds-dare` OpenSSL FFI: AES-256-GCM / HMAC-SHA256 / GMAC / ECDH / CMS); NFR-SEC-POSTURE (bounds-checked fail-closed parsers, fuzz-gated; a **false REJECT is the worst defect class**); NFR-PORT (Clasp + SBCL both validate, Clasp first; no reader conditionals outside `dds-pal/`); the operating contract §4 (clean-room — OpenDDS read for understanding, **RTI Connext source, headers, and generated code never read**).
- **Standards:** OMG DDS-Security 1.1 §7.2.x (`Property_t` / `BinaryProperty_t` / `DataHolder` / `ParticipantGenericMessage`); §7.4.3.3 (monotonic `message_identity.sequence_number` on the PSM ParticipantStatelessMessage writer); §7.4.3.4 (AuthRequestMessageToken mechanism overview); §8.4.2.9 (`check_remote_datawriter` / `check_remote_datareader` — endpoint matching is an access-control, not a keying, decision); §8.5.1.10–.12 (`encode/decode_rtps_message` — whole-RTPS protection mandatory for every datagram between keyed participants, SPDP/PSM/PVMS exempt); §8.7.2.3 (the AuthRequestMessageToken challenge-binding sub-protocol, **OPTIONAL** per the spec); §8.7.2.4 (PKI-DH requester/replier role election + handshake flow); §9.3.2 (handshake token content — algo names, NUL-tolerance, optional property advertisement); §9.3.2.1 (`IdentityToken` optional properties; `c.id` PEM encoding); §9.3.2.2 / §9.3.2.3 (`HandshakeReplyMessageToken` optional echo fields); §9.3.1 (handshake-token `class_id` format — plugin family + version + role); §9.4.1.2.3 (`rtps_protection_kind` ProtectionKind — when NONE, no whole-RTPS KeyMaterial is exchanged); §9.5.3.3.5 (`encode_rtps_message` — prepend a source-declaring `INFO_SRC` inside the protected payload); RTPS 2.5 §9.4.5.9 / §8.3.7.9 (InfoSource submessage: `SubmessageHeader[INFO_SRC=0x0c, E, octetsToNextHeader=20]` ‖ unused(4) ‖ ProtocolVersion(2) ‖ VendorId(2) ‖ GuidPrefix(12) = 24 octets).

---

## Context

ADR 0037 delivered the **Fast-DDS half** of the P6 exit gate: live `SPDP → §8.7 PKI-DH auth → SharedSecret → permissions → PVMS crypto-token exchange → :keyed → reliable secure-SEDP endpoint match → protected user DATA both directions` against a SECURITY=ON eProsima Fast DDS v3.6.1 peer. Its final residual carry #4 — *"live RTI Connext-Security secure discovery: the remaining half of the P6 exit gate"* — was explicitly deferred because the licensed RTI Security Plugins (`libnddssecurity*`) were absent.

On 2026-07-02 the owner enabled the RTI Security Plugins under a valid license. Slice 5b opens immediately.

**The P6 exit gate requires the SAME behavioral proof vs RTI Connext 7.3.1:** protected user DATA flows both directions (`ours↔live Connext`, GOV=secure, all-ENCRYPT). The Slice-5 / ADR-0037 fixes are the baseline; each may or may not hold vs Connext. The oracle is the LIVE outcome — Connext's verbosity-5 log + our per-iteration `[role] discovered/matched/keyed/sent/decoded` line. tshark cannot dissect macOS `lo0` NULL/Loopback link layer (confirmed again); the **live cross-vendor decode in both directions is itself the wire proof**. RTI Connext is a black-box interop peer; **RTI source, headers, and generated code were never read**.

**Harness setup (Phase 0, reversible):** RTI Connext 7.3.1 ships `libnddssecurity.dylib` resolving `libssl.3`/`libcrypto.3` via `@loader_path` (bypassing `DYLD_LIBRARY_PATH`). No bundled OpenSSL. Fixed with reproducible symlinks from the RTI plugin directory to `/opt/homebrew/opt/openssl@3/lib/lib{ssl,crypto}.3.dylib` (OpenSSL 3.6.2, ABI-compatible with the 3.5.1-built plugin). The `interop/security-connext/` harness reuses the Slice-5 PKI (Identity-CA / Permissions-CA / Governance); `USER_QOS_PROFILES.xml` configures the `OursConnextInterop::secure` profile (domain 0 / UDPv4 loopback / our cert+key+gov-doc paths). The run script (`run-connext-interop.sh`) launches either `rtiddsspy` (Phases 1–4: observer only) or the clean-room `hello_secure_pub` Connext publisher (Phase 5+: the reverse-direction peer, built from `HelloWorld.idl` + `hello_secure_pub.cxx` under `interop/security-connext/`, generated by `rtiddsgen -language C++11`, git-ignored tooling artifacts). The harness, IDL, and publisher source are committed; captures are git-ignored.

---

## Campaign shape

A **live-peer-driven reconciliation campaign in two arcs**, holding the **our-to-our-green invariant** (both impls, byte-exact corpora unchanged, fuzz, gate-hotpath, gate-types) after every step:

**Arc 1 — mutual authentication + GOV=none endpoint match (Phases 2–3):** drive from `SPDP discovered=1` through the §8.7 PKI-DH handshake to `:authenticated` (both roles), then through crypto-token exchange (or its absence at GOV=none) to user-endpoint match and live sample decode. Five wire divergences in the handshake; one governance/keying policy divergence for the match gate.

**Arc 2 — GOV=secure protected data BOTH directions (Phases 4–6):** advance from `:keyed` to live protected user DATA. The forward direction (ours=pub → Connext=sub) needed two emit-conformant divergence fixes (SRTPS metatraffic wrap + INFO_SRC). The reverse direction (a FULL Connext participant publisher → ours=sub) was blocked at the §8.7 handshake by the **§8.7.2.3 AuthRequestMessageToken challenge-binding sub-protocol** — a missing DDS-Security feature, not a tolerance gap. Implementing it conformantly and cleanly (caabeec + a553d0a) closed the handshake; no post-auth reconciliation was needed.

**Correction posture:** every Arc 1 fix relaxes an over-strict false-REJECT (our check blocked a conformant form); every Arc 2 fix emits the stronger OMG-conformant form (our emission was insufficient). Neither arc required dropping a trust gate or weakening a corpus.

---

## The divergences (Arc 1: mutual authentication)

All five are `tolerate not weaken`: our code was more strict than the OMG clause; each relaxation accepts a conformant form our prior code rejected while leaving every trust gate (cert-chain-verify + Sign1/Sign2) intact.

| # | What | §clause | SHA | Why conformant + fail-closed |
|---|---|---|---|---|
| 1 | **Empty `IdentityToken`** — Connext advertises `class_id` only; zero `Properties` / `BinaryProperties`. Our `validate-remote-identity` required all four `dds.cert.*` / `dds.ca.*` properties. | §9.3.2.1 — the four properties are OPTIONAL advertisement hints; the class_id is the mandatory plugin id; identity + algo are carried in the §8.7.2.4 handshake. A conformant reference peer omitting them proves they are not mandatory. | `57a78cb` | `%parse-remote-token-strings` returns a fifth `WELL-FORMED-P`; identity validation rejects only on malformed CDR; `select-suite-for-identities` falls back to the local cert kind when the remote omits its algo. **The sole trust gate — cert-chain + Sign — is unchanged.** |
| 2 | **Handshake-token `class_id` plugin version `1.2` vs `1.0`** — Connext's tokens carry `DDS:Auth:PKI-DH:1.2+{Req,Reply,Final}`; our 5 exact `string=` match sites used the 1.0 constants. | §9.3.1 / §9.3.2.1 / §8.7.2.4 — the interop contract is the plugin FAMILY (`DDS:Auth:PKI-DH`) and message ROLE (`+Req` / `+Reply` / `+Final`); the version between them is the plugin revision. | `92e6bb3` | One shared `%class-id-role-match-p` (family PREFIX + role SUFFIX, both derived from the pinned 1.0 constants — no version literal hardcoded) replaces the 5 exact-match sites. NIL for a different plugin family or unrecognized role; the `class_id` is never a trust boundary. |
| 3 | **Lean `HandshakeReplyMessageToken`** — Connext's Reply carries `c.id` / `c.perm` / `c.pdata` / `c.dsign_algo` / `c.kagree_algo` / `dh2` / `challenge1` / `challenge2` / `signature` but **omits** `hash_c2`, `hash_c1`, `dh1`. Our code required all of them. | §9.3.2.2 / §9.3.2.3 — `hash_c2`, `hash_c1`, `dh1` are REDUNDANT for the requester (it generated `dh1` / `hash_c1` and recomputes `hash_c2` from the Reply's `c.*` properties). | `dd2e654` | Require from the Reply only `c.id` / `dh2` / `challenge2` / `signature`; run the echo checks only when the echo is PRESENT; recompute `hash_c2` from the Reply's credential properties and feed it into Sign2. **Sign2 is still verified** over the BinaryPropertySeq(`hash_c2_recomputed`, `challenge2`, `dh2`, our `challenge1` / `dh1` / `hash_c1`) — a replayed or substituted Reply signed over different ephemerals fails that verify. |
| 4 | **Trailing NUL on `c.dsign_algo` / `c.kagree_algo` octets** — Connext null-terminates its binary-property algo strings (`"ECDSA-SHA256\0"`); our `string=` comparison failed. | §9.3.2 — the algorithm NAME is the interop contract; a trailing NUL is a C-string serialization artifact. | `9b0f1b3` | One shared `%algo-name-match-p` (`string-right-trim` a trailing NUL before comparing) at the two algo cross-check sites (requester + replier). A genuinely different algo (or an interior NUL) still mismatches; the VERBATIM NUL-included octets remain the `hash_c` / Sign input, so the crypto binding is unchanged. |
| 5 | **Our `c.id` certificate PEM must be NUL-terminated** — Connext (verbosity 5): `"identity certificate binary property contains a malformed certificate. In particular, the certificate is not properly null terminated."` Ours emitted the raw PEM; Fast DDS does not require a NUL (corroborated ADR 0037). | §9.3.2.1 — `c.id` carries the X.509 certificate; a trailing C-string NUL is a well-known terminator. OpenSSL `PEM_read_bio_CMS` ignores a trailing byte after `-----END CERTIFICATE-----`. | `ff05122` | One shared `%c-id-pem-octets` appends a single trailing NUL; used at BOTH self-credential sites (request `c.id`+`hash_c1`; reply `c.id`+`hash_c2`). The SAME octets are the `c.id` property AND the `hash_c` input, so both ends recompute the identical hash; Fast DDS / ours still load it (a form both vendors accept). The byte-exact `+ec-identity-token-vector+` corpus carries no `c.id` and is unchanged. |

## The divergence (Arc 1: user-endpoint match)

| # | What | §clause | SHA | Why conformant + fail-closed |
|---|---|---|---|---|
| 6 | **GOV=none match blocked on `:keyed`; Connext sends no ParticipantCrypto token** — at `rtps_protection=NONE` Connext has no participant-level KeyMaterial to share; our match gates required `:keyed` unconditionally. Both sides confirmed (Connext verbosity-5: PVMS HEARTBEAT always `firstSN=1,lastSN=0` — empty writer). | §8.4.2.9 (`check_remote_datawriter/reader`) — endpoint matching is an **access-control** decision (authentication + permissions), not a keying decision. §9.4.1.2.3 / §8.5 — `rtps_protection_kind=NONE` means no whole-RTPS KeyMaterial; no crypto token is exchanged. Requiring `:keyed` when governance mandates no protection is an over-strict false-REJECT providing zero security benefit. | `f7b04ac` | New `dds.security:governance-any-protection-p` (T iff any protection kind ≠ NONE); stored as `disc-node-crypto-keying-required-p` (**default T — fail-closed**: auth-only or no-AccessControl participants keep the strict `:keyed` gate, byte-identical). Both gates (`%participant-auth-gate` in auth-manager, `%participant-permissions-gate` in access-control) match an `:authenticated` remote when `crypto-keying-required-p` is NIL. The two TRUST gates (§8.7 cert-chain+Sign = `:authenticated`, §8.4 permissions on the §8.7.2.5-validated subject) remain **fully enforced**; only the KEYING gate — which secures nothing when every protection kind is NONE — is dropped, and only when governance says so. The `run-secure-discovery-protected-test` (GOV=ENCRYPT) still requires `:keyed` (verified non-vacuously). |

## The divergences (Arc 2: GOV=secure — emit-conformant)

Both are strengthening (our emission was weaker than the OMG spec required; each fix makes ours more conformant).

| # | What | §clause | SHA | Why conformant + fail-closed |
|---|---|---|---|---|
| 7 | **Secure-SEDP / PM / SPDP metatraffic sent unwrapped** — `%maybe-wrap-srtps` engaged only when a destination GUID prefix was threaded (user-data send path only); ALL metatraffic datagrams were submessage-protected (SEC_PREFIX) but NOT whole-RTPS-protected. A strict `rtps_protection=ENCRYPT` Connext printed "unencoded rtps message" 239× and discarded them. Root cause also included a **buffer overflow**: the secure-metatraffic send buffer had only 64 bytes slack over `20+len(secured)`; the SRTPS ENCRYPT wrap needs ≥79 more → `%maybe-wrap-srtps` returned NIL → `%send-raw-buf` dropped the datagram fail-closed. | §8.5.1.10–.12 / §9.4.1.2.3 — `rtps_protection_kind` protects EVERY datagram between matched+keyed participants; the only exemptions are plain SPDP bootstrap, PSM handshake, and the PVMS crypto-bootstrap endpoint. | `583dd4a` | Thread the destination-participant GUID prefix through `%send-secure-bracket` / `%send-secure-endpoint` → `%send-msg-buf` so `%maybe-wrap-srtps` engages on secure-SEDP/PM/SPDP to a `:keyed` peer. PVMS stays unwrapped (the crypto-bootstrap exemption). Buffer slack 64→160 (`+secure-metatraffic-buffer-slack+`). The SIGN-tier `governance-sign` `rtps_protection` set ENCRYPT→SIGN (coherent SIGN posture), and its test updated to accept the topic inside a SIGN SRTPS_PREFIX bracket (never plain — not a weakening). No corpus regenerated (codec untouched). |
| 8 | **SRTPS protected payload lacks a §9.5.3.3.5 source-declaring `INFO_SRC`** — Connext's `decode_rtps_message` printed "wrong INFO_SRC" 328× after fix #7 (the SRTPS MAC / decrypt succeeded; the plaintext content check failed). The `INFO_SRC` Connext requires lives INSIDE the encrypted `SEC_BODY`. Fast DDS tolerated its absence (ADR 0037, 88 decoded without it), confirming this is a Connext-specific enforcement of a clause the spec REQUIRES. | §9.5.3.3.5 — `encode_rtps_message` MUST prepend a source-declaring `INFO_SRC` binding the protected submessages to their origin participant (a cut-and-paste defense: a spliced SEC_BODY under a forged outer RTPS Header fails the check because the encrypted INFO_SRC's GuidPrefix won't match). RTPS 2.5 §9.4.5.9 / §8.3.7.9 — InfoSource layout: `SubmessageHeader[0x0c, E, 20]` ‖ unused(4) ‖ ProtocolVersion(2) ‖ VendorId(2) ‖ GuidPrefix(12) = 24 octets total. | `616c091` | `dds.rtps.message:put-info-src-into` — a zero-alloc raw-offset writer of the 24-octet INFO_SRC. `%maybe-wrap-srtps` prepends the INFO_SRC (this node's GUID prefix) to the submessage stream BEFORE protection via an in-place right-shift of `[20,LEN)` by 24 (reverse copy, overlap-safe). The CLEAR wire is unchanged (`SRTPS_PREFIX ‖ SEC_BODY ‖ SRTPS_POSTFIX`). Receive: `dispatch-message` no-ops an unhandled submessage id, so a leading INFO_SRC in the decoded stream is transparently skipped. Zero-alloc preserved (`run-rtps-protection-zeroalloc-test`: SRTPS wrap 0.00 B/datagram, RX unwrap 0.00; the in-place shift + raw write cons nothing). No corpus regenerated. |

## The §8.7.2.3 AuthRequestMessageToken sub-protocol (the Phase-6 feature)

This is NOT a tolerance divergence but a **missing DDS-Security feature**. A full Connext participant (unlike `rtiddsspy`) enforces the §8.7.2.3-OPTIONAL challenge-binding mechanism: on SPDP discovery it mints a `future_challenge` nonce and sends it in an `AuthRequestMessageToken`; it then requires the requester's `challenge1` to bind to it byte-for-byte. Ours implemented none of this; `rtiddsspy` and Fast DDS (v3.6.1) do not enforce the binding, which is why ours↔Fast-DDS worked without it.

**The binding equation** (all byte-for-byte `equalp`, no hashing — verbatim from the OMG clauses and OpenDDS `AuthenticationBuiltInImpl.cpp` `challenges_match` at 1232–1246; RTI source never read):
- `AuthRequestMessageToken`: `message_class_id` = `dds.sec.auth_request`; DataHolder `class_id` = `DDS:Auth:PKI-DH:1.0+AuthReq` (Connext emits 1.2 — matched version-tolerant via `%class-id-role-match-p`); one binary property `future_challenge` = a 256-bit nonce minted ONCE per remote at discovery (CSPRNG `RAND_bytes 32`, stable across retransmits; stored on the `auth-remote`).
- **Requester:** `HandshakeRequest.challenge1` == its own `future_challenge` (verbatim; NOT the peer's nonce — the disproven "echo peer nonce" interpretation is confirmed wrong).
- **Replier:** verify `Request.challenge1` == the requester's advertised `future_challenge` (iff received; reject fail-closed on mismatch); then `HandshakeReply.challenge2` == its own `future_challenge`.
- **Requester processing the Reply:** verify `Reply.challenge2` == the replier's advertised `future_challenge` (iff received) AND `Reply.challenge1` == the sent `challenge1` (echo).
- **Absence-tolerant:** a NIL expected nonce (peer sent no `auth_request`) SKIPS the check. §8.7.2.3-OPTIONAL: a spec-literal peer that omits the sub-protocol (Fast DDS v3.6.1) must never be false-rejected. A WRONG stored nonce would FAIL the byte-exact check, so the gate never false-accepts.

**Why the binding is defense-in-depth, not the primary replay defense:** PKI-DH replay resistance is already anchored in Sign2/Sign1 over the locally-generated fresh ephemeral challenges. The binding ties the handshake nonces to the auth_request nonces minted before the handshake — a second independent freshness proof. It raises the bar from "compromise the ephemeral ECDH key to forge the Sign" to "simultaneously compromise the ephemeral key AND predict/alter the per-remote nonce minted at discovery." Neither step is achievable without breaking the ECDH or the cert-chain.

**§7.4.3.3 monotonic `message_identity.sequence_number`:** the PSM writer was hardcoding `sequence_number=0` (a §7.4.3.3 violation); a strict Connext stateless reader deduped our retransmits. Fixed to a monotonic per-participant counter (`source_guid` = participant GUID prefix; first value 1), shared across the `auth_request` and all three handshake tokens.

| Commit | What |
|---|---|
| `caabeec` | §8.7.2.3 challenge-binding in the PKI-DH handshake API: `begin-handshake-request` accepts a `challenge1-nonce` keyword, `begin-handshake-reply` accepts `expected-challenge1` + `challenge2-nonce`, `process-handshake` accepts `expected-challenge2`; byte-exact `equalp` verify, fail-closed, absence-tolerant. New `run-auth-challenge-binding-test`. Corpora / KATs unchanged. |
| `a553d0a` | Auth manager mints a `future_challenge` per remote on discovery; sends the `AuthRequestMessageToken` (`dds.sec.auth_request`) via the PSM writer; binds `challenge1` / `challenge2` to the nonce; verifies the peer's nonce on both roles; drives the monotonic §7.4.3.3 `message_identity.sequence_number`. |

---

## The green cross-vendor run — the DoD

**Live, both directions, vs RTI Connext 7.3.1** + `libnddssecurity` under the **GOV=secure** governance (`discovery_protection` / `rtps_protection` / `metadata_protection` / `data_protection` = ENCRYPT), sharing the reused Identity-CA / Permissions-CA / Governance, `bash interop/security-connext/run-connext-interop.sh secure 20` (repeatable):

- **forward (ours=publisher → Connext=`rtiddsspy` subscriber):** `keyed=T`, user endpoint `matched=1`, `sent=8`, `RESULT: PASS`. `rtiddsspy` logs 8× `New data … topic="HelloWorldTopic" type="HelloWorld"` — Connext decodes 8/8 of our GOV=secure all-ENCRYPT-protected HelloWorld user samples. The full AEAD path exercised: PVMS ParticipantCryptoToken keying → secure-SEDP endpoint match under `metadata_protection` → SRTPS whole-RTPS wrap (with §9.5.3.3.5 INFO_SRC) → `data_protection` ENCRYPT (AES-256-GCM).

- **reverse (Connext=`hello_secure_pub` publisher → ours=subscriber):** `keyed=T`, `matched=1`, `samples>0` (≈38–39 per 20-second run), `decoded>0`, `RESULT: PASS`. Decoded content: `"Hello world from Connext"`. No post-authentication reconciliation was needed — session_id / AAD / KeyMaterial / secure-SEDP / SRTPS all decoded cleanly once the §8.7 handshake completed; the spec-faithful `future_challenge` property name is exactly what Connext reads.

The residual `DecryptFinal` errors in both directions are benign participant-metatraffic (`EntityId 0x000001C1`) — not the user-data topic (confirmed: identical errors appear in the GOV=secure baseline before and after).

**This closes both halves of the P6 exit gate: ADR 0037 (Fast-DDS half) + ADR 0040 (Connext half).**

---

## Security posture

The final adversarial review (M7/P6 Slice 5b) refuted **5 bypass attempts**:

| Bypass attempt | Outcome |
|---|---|
| **Challenge suppression** — attacker does not send an `auth_request`, so the peer stores no nonce, skipping the binding check; the HandshakeRequest uses a chosen `challenge1` | Dies at **Sign1** — the attacker cannot sign over the chosen `challenge1` under the cert key it does not hold; cert-chain-verify ensures the cert is ours before Sign1 is evaluated |
| **Forged `auth_request`** — attacker injects a fake `dds.sec.auth_request` with a different nonce, overwriting the stored `future_challenge` before the legitimate one arrives | The stored nonce is written ONCE at first-recv (auth-remote is per-remote); a subsequent receipt is ignored (idempotent). Even if overwritten, the attacker still cannot forge Sign1 over the resulting `challenge1`. |
| **Handshake replay** — attacker replays a captured (GUID, handshake, signatures) tuple | Dies at **Sign2** — the replier's `challenge2` is freshly minted per run; a replayed Reply signed over a different session's `challenge2` fails the verify. |
| **Nonce overwrite via multiple sequential `auth_request`s** — send N `auth_request` messages to flip the stored nonce just before the requester sends its Request | The first-recv idempotency guard prevents overwrite. Even overwritten: the attacker cannot cause a `challenge1` == (its overwritten nonce) because the requester reads its OWN `future_challenge` from `auth-remote`, which the attacker does not control (it's local state). |
| **Unbound path** — some combination of absence-tolerance + fallback paths bypasses the check | Absence-tolerance fires only when the stored nonce is NIL (peer truly sent no `auth_request`). A WRONG stored nonce fails the byte-exact `equalp`. No code path accepts a non-NIL expected nonce with a non-matching `challenge1`. |

**Conclusion:** all 5 bypass attempts die at the cert-chain-verify or the possession-proof Sign. The challenge-binding is **defense-in-depth** on top of the PKI-DH Sign, not the primary trust anchor. No trust gate (CA chain-verify, Sign1/Sign2, §8.4 permissions, AEAD tag) was dropped, weakened, or corpora-regenerated by this campaign. Every Arc-1 reconciliation relaxes an over-strict false-REJECT; every Arc-2 reconciliation strengthens our emission.

**Clean-room IP:** OMG DDS-Security 1.1 + DDSI-RTPS 2.5 are the design authority. OpenDDS `AuthenticationBuiltInImpl.cpp` / `Spdp.cpp` / `DdsSecurityCore.idl` (Apache-2.0 / read for understanding; provenance-logged in `docs/provenance.md`) corroborated the binding equation and the property name. Fast DDS `PKIDH.cpp` / `SecurityManager.cpp` (Apache-2.0) confirmed Fast DDS does NOT implement the sub-protocol (and thus confirms absence-tolerance is necessary for ours↔Fast-DDS regression). **RTI Connext source, headers, and generated code were never read.**

---

## Honest posture

- **Achieved (GOV=secure, both directions, live):** protected user DATA flows ours↔live RTI Connext 7.3.1 (GOV=secure, all-ENCRYPT) — full `SPDP → §8.7 PKI-DH auth+AuthRequestMessageToken → SharedSecret → permissions → PVMS ParticipantCryptoToken exchange → :keyed → reliable secure-SEDP endpoint match → SRTPS+INFO_SRC+metadata_protection+data_protection`. Both directions live. This is the **Connext half of the P6 exit gate**.
- **GOV=none reverse direction (not live-verified, not overclaimed):** Phase 3 proved ours→Connext at GOV=none (`matched=1`, 8 samples decoded by Connext). The reverse (Connext→ours at GOV=none) was not live-verified: the Phase-2/3 harness used `rtiddsspy` (subscriber-only), which never publishes, so ours had no Connext writer to match. GOV=none is unit-tested (`run-auth-negatives-test`, `run-access-manager-test`, `governance-protection-kind`) and the GOV=none forward direction IS live-verified. The DoD is **GOV=secure both directions** with the full Connext publisher; GOV=none reverse is a coverage note, not a gap in the DoD.
- **ours↔Fast-DDS not regressed:** `run-fastdds-interop.sh secure 15` — GOV=secure protected user DATA still flows both directions (ours2fast `matched=1 sent=8`; fast2ours `matched=1 decoded≈29`). GOV=none `matched=0` is **pre-existing** (Fast DDS silently discards our `dds.sec.auth_request`, confirmed against `SecurityManager.cpp:1676–1679`) — byte-identical to the pre-WP baseline at `6bddd5b`, not a regression.
- **Byte-exact corpora / KATs unchanged:** the sub-protocol is a protocol-flow addition; no emitted codec primitive changed. All four byte-exact security corpora (submessage / crypto-header / rtps-message / auth-token) + NIST/DARE KATs are green UNCHANGED on both impls.

---

## Residual carries

1. **GOV=none reverse live coverage.** The DoD is GOV=secure both-directions with the full `hello_secure_pub` publisher. GOV=none reverse (Connext=pub → ours=sub) is not live-covered: `rtiddsspy` subscribes only. Unit-tested + GOV=none forward live-verified. A GOV=none reverse live run with `hello_secure_pub` in `--governance governance-none.smime` mode would complete the picture but is not a DoD gate.
2. **Best-effort `auth_request` pre-authentication DoS.** A forged `dds.sec.auth_request` from an unauthenticated peer can false-REJECT a legitimate peer (by poisoning the stored `future_challenge` before the legitimate nonce arrives — requires racing the first-recv guard). This is an **availability** concern (a DoS like garbage SPDP), never a false-ACCEPT (the cert-chain + Sign trust gates are untouched). Future hardening: timestamp-gate the nonce-overwrite window, or verify the sender's GUID prefix is reachable. Deferred — out of scope for the P6 exit gate.
3. **ours↔Fast-DDS GOV=none `matched=0` pre-existing gap.** Fast DDS silently discards our `dds.sec.auth_request` (unknown `message_class_id`); the GOV=none handshake reaches `:keyed` (confirmed) but the endpoint match stays `matched=0`. This is a Fast DDS gap (not a regression introduced here) and is pre-existing since the Slice-5/ADR-0037 baseline at `6bddd5b`. Tracked as-is.
4. **Residual benign metatraffic `DecryptFinal` errors.** ~117 "unencoded rtps message" rejects at Connext (plain builtin HEARTBEAT/HEARTBEATs from the plain SEDP writer under all-protected governance) + the `DecryptFinal` errors on the participant-metatraffic EntityId `0x000001C1`. Neither blocks user-data matching. The plain-SEDP residual is the Phase-4 carry; full §8.5.1.10 coverage would require wrapping the residual plain builtin reliability too (future hardening).
5. **ADR-0037 residual carries still open vs Connext.** The 0xC2→0xC7 pairing DRY; the secure-builtin-ACKNACK unit count; the SIGN-tier alignment (the ENCRYPT governance did not exercise the SIGN GMAC AAD span). The ADR-0036 hardening carries (zero-alloc into-buffer AEAD on the full `dds-disc` rtps path; per-topic `metadata_protection` applied to user endpoints; `pvms-bootstrap-kms` pruning on peer-loss; `%dn-normalize` RFC2253 edge cases; KeyMaterial GC-heap → foreign/static) remain open.

---

## §M7 roadmap update

| Slice | Description | Status |
|---|---|---|
| 1 | Crypto plugin: AES256-GCM `SecuredPayload` (ADR 0031) | LANDED |
| 2a | Authentication: §8.7.2.4 PKI-DH → SharedSecret (ADR 0032) | LANDED |
| 2b-i | PSM IdentityToken + `DataHolder`/envelope codec (ADR 0033) | LANDED |
| 2b-ii + 2c | Auth manager + KxKey + crypto-token exchange (ADR 0034) | LANDED |
| 3 | AccessControl (§8.4 / §9.4) (ADR 0035) | LANDED |
| 4 | Secure discovery our-to-our (§7.3.7 / §8.5) (ADR 0036) | LANDED |
| 5 | Live Fast DDS-Security cross-vendor — the Fast-DDS half of the P6 exit gate (ADR 0037) | LANDED |
| **5b (this ADR)** | **Live RTI Connext 7.3.1 cross-vendor — the Connext half of the P6 exit gate. The §8.7.2.3 AuthRequestMessageToken sub-protocol + §7.4.3.3 monotonic PSM seq unblock the full-participant handshake; protected user DATA flows BOTH ways ours↔live Connext (GOV=secure, all-ENCRYPT). P6 exit gate COMPLETE — both halves.** | **LANDED (2026-07-02)** |

---

## Consequences

- **P6 exit gate COMPLETE.** ADR 0037 (Fast-DDS half) + ADR 0040 (Connext half) jointly close the P6 milestone gate. No remaining P6 live-interop requirement is open.
- **NFR-SEC-POSTURE:** every reconciled parser stays bounds-checked + fail-closed. No false-REJECT: a spec-literal peer is accepted wherever the form is self-describing (absent IdentityToken props, version-tolerant class_id, optional echo fields, NUL-terminated algo strings). No false-ACCEPT: the cert-chain-verify + Sign trust gates are untouched throughout; a wrong stored nonce fails byte-exact `equalp`. The `governance-any-protection-p` gate defaults T (fail-closed), so any protection kind ≠ NONE still requires `:keyed`.
- **FR-SEC-2:** no hand-rolled crypto — the sub-protocol uses `RAND_bytes 32` (CSPRNG nonce) and `equalp` (constant-time byte compare on fixed-length vectors); the AEAD/PKI-DH are unchanged (OpenSSL via `dds-dare`).
- **NFR-PORT:** no reader conditionals outside `dds-pal/`; Clasp + SBCL both validate, Clasp first. Known NFR-PORT Clasp full-suite live-socket/threading flake (`[SDP-SEC-PREFIX-ON-WIRE]` / `[SDP-BYTE-EXACT]`) wanders and is SBCL-clean — re-run, do not chase.
- **Clean-room / IP:** OMG DDS-Security 1.1 + OpenDDS (Apache-2.0) + Fast DDS (Apache-2.0) read for understanding; provenance-logged (`docs/provenance.md`). RTI Connext source / headers / generated code never read.
- **Gates (final sweep, both impls, Clasp first):** `make test-clasp` 395 PASS; `make test-sbcl` 395 PASS (one first-run Clasp-pattern VOLATILE-LATEJOINER-ZERO flake on first attempt, gone on retry — the documented NFR-PORT timing flake, not a security regression); `make gate-hotpath` PASS (8 hot-path files clean); `make gate-types` PASS (2146 `defun`s ftype-declared); `make fuzz` PASS. `make bench` N/A — no hot-path change (the sub-protocol is control-plane auth flow, not the CDR / AEAD sample path); the `make mem` arms are unchanged (zero-alloc AEAD established by ADR 0038/0039; the sub-protocol adds no per-sample alloc). The live Connext interop is the DoD gate; it is not a CI-automatable gate (external licensed toolchain).

---

## References

- Phase reports (git-ignored): `.superpowers/sdd/5b-phase{2,3,4,5}-report.md` — the authoritative per-phase campaign record
- `interop/security-connext/` — the harness: `USER_QOS_PROFILES.xml`, `run-connext-interop.sh`, `HelloWorld.idl`, `hello_secure_pub.cxx`, `.gitignore`; captures git-ignored
- `src/dds-security/auth/{constants,identity,handshake,keyexchange}.lisp` — the IdentityToken optional-props + class_id version-tolerance + lean-Reply + NUL-term + `%c-id-pem-octets` reconciliations; `begin-handshake-request/reply/process-handshake` challenge-nonce API
- `src/dds-security/auth/packages.lisp` — `dds.security:governance-any-protection-p` export
- `src/dds-security/access-control/plugin.lisp` — `governance-any-protection-p` implementation
- `src/dds-dcps/auth-manager.lisp` — per-remote `future_challenge` lifecycle; `auth_request` send/receive; monotonic §7.4.3.3 `message_identity.sequence_number`; `disc-node-crypto-keying-required-p` gate
- `src/dds-disc/{disc,dataplane}.lisp` — SRTPS metatraffic wrap (dest-prefix threading + buffer slack); `put-info-src-into` + in-place right-shift in `%maybe-wrap-srtps`
- `src/dds-tests/security-test.lisp` — `run-auth-challenge-binding-test` (the binding unit test); secure-discovery / PVMS / SEDP / access-manager regressions
- ADR 0037 — Slice 5 (Fast-DDS half; the other P6 exit-gate half; residual carries also carried here)
- ADR 0036 — Slice 4 (secure discovery our-to-our; metatraffic-wrap and INFO_SRC carries confirmed here)
- ADR 0031 — Slice 1 (the empty-AAD + SecureDataTag addenda confirmed vs live Connext with no new divergence)
- `docs/provenance.md` — all OMG + OpenDDS + Fast DDS sources consulted across this campaign
