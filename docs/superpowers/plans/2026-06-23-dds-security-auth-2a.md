# WP-DDS-SECURITY-AUTH-2A Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Two in-process DDS participants mutually authenticate via the DDS-Security 1.1 §8.7 PKI-DH handshake (both §9.3 suites) and agree a byte-equal SharedSecret; every negative fails closed.

**Architecture:** A new isolated `auth` unit inside the existing `dds-security` ASDF system — `identity.lisp` (PKI load/validate + IdentityToken), `suites.lisp` (the two §9.3 algorithm suites behind one `auth-suite` closure-vtable), `handshake.lisp` (the §8.7.2.4 three-message state machine → SharedSecret). All crypto goes through the existing `dds-dare` handle-based OpenSSL FFI, extended with the X.509 / key-agreement / signature primitives 2a needs. Secrets live in `dds.pal` foreign buffers. Control-plane only — no hot-path impact.

**Tech Stack:** Common Lisp (SBCL + Clasp, Clasp first), `dds-dare` over OpenSSL 3.6.2 (handle-based CFFI), `dds.pal` foreign-buffer arena, the `dds-security` `dds.security` package, `defun*`/`defstruct*`.

## Global Constraints

- **No hand-rolled crypto** — all X.509 / EC / RSA / ECDH / FFDH / ECDSA / RSASSA-PSS / SHA-256 / `RAND_bytes` via the `dds-dare` OpenSSL FFI (extend it); never reimplement a primitive (FR-SEC-2).
- **OMG DDS-Security 1.1 conformance** — §8.7 (handshake) + §9.3 (`DDS:Auth:PKI-DH` algorithms/tokens) + §9.3.2 (selection); both suites; the token wire format never deviates.
- **No wire constants from memory** — token property/binary-property name strings, the algorithm-identifier strings, the RFC 3526 MODP-2048 group, the signature-input concatenation order, the SharedSecret derivation, and the IdentityToken computation are **pinned by T0** (the spike) with §-clause citations, never invented. Tasks T1-T4 consume the T0-pinned constants from `src/dds-security/auth/constants.lisp`.
- **OpenSSL FFI is discovered against the installed header** — exact EVP/X509 function signatures (e.g. `X509_verify_cert`, `EVP_PKEY_derive`, `EVP_DigestSign`/`EVP_DigestVerify`) are confirmed against the OpenSSL 3.6.2 headers the `dds-dare` build already uses (see `src/dds-dare/openssl-ffi.lisp`), not from memory; each is KAT-checked.
- **Bounds-check the token parser even at `(safety 0)`** — a malformed/short token fails closed, never an OOB read; fuzzed (NFR-SEC-POSTURE).
- **Secrets in foreign buffers** via `dds.pal:alloc-static`/`free-static` (the clasp#1793-safe pattern); never the GC heap; never call `static-vectors` free/make directly.
- `defun*`/`defstruct*` + **full ftype** on every function; **no reader conditionals outside `dds-pal/`**; **Clasp AND SBCL both, Clasp first**; **no AI/assistant attribution** in any repo file (cite "the operating contract" / the spec clause).
- Control-plane only — `make mem` stays **0.0000**; `gate-hotpath` unaffected.
- Tests register in `src/dds-tests/packages.lisp` (export) + `src/dds-tests/echo-test.lisp` (`run-all-tests` alist), the way the existing `run-security-*` tests do.

---

## File structure

- `src/dds-security/auth/constants.lisp` (new) — the T0-pinned §8.7/§9.3 wire constants (token name strings, algorithm-id strings, MODP-2048 group, IdentityToken + signature-input layout), each with a §-citation docstring.
- `src/dds-security/auth/identity.lisp` (new) — `identity-handle`, `validate-local-identity`, `validate-remote-identity`, the IdentityToken.
- `src/dds-security/auth/suites.lisp` (new) — `auth-suite` vtable + the two §9.3 suites + `select-auth-suite` (§9.3.2).
- `src/dds-security/auth/handshake.lisp` (new) — `handshake-handle`, `begin-handshake-request`, `process-handshake`, the token (de)serialization, `shared-secret-handle`.
- `src/dds-dare/openssl-ffi.lisp` + `primitives.lisp` (modify) — new X.509 / ECDH / FFDH / ECDSA / RSA-PSS primitives, exported from `dds.dare`.
- `src/dds-security/packages.lisp` (modify) — export the new `dds.security` auth symbols.
- `dds-security.asd` (modify) — add the four `auth/` components (serial, after the Slice-1 files).
- `src/dds-tests/security-auth-test.lisp` (new) — the 2a tests; `src/dds-tests/packages.lisp` + `echo-test.lisp` (modify) — register them.
- `interop/security-auth/` (new) — the test-PKI fixture + the `openssl` generator script (T0).
- `docs/adr/0032-dds-security-auth-handshake.md` (new, T5); `docs/wiki/security.md`, `README.md`, `docs/verification.csv` (modify, T5).

---

### Task 0 (SPIKE): Pin §8.7/§9.3 wire constants + generate the test-PKI fixture

This is an investigation/scaffold task, not TDD. Re-plan checkpoint at the end.

**Files:**
- Create: `docs/superpowers/spikes/2026-06-23-dds-security-auth-wire.md`
- Create: `interop/security-auth/gen-test-pki.sh`, and the generated `interop/security-auth/pki/` (CA + EC cert + RSA cert + keys)
- Create: `src/dds-security/auth/constants.lisp`

**Interfaces:**
- Produces: `constants.lisp` exporting (internal to `dds.security`) the pinned values T1-T4 consume — at minimum: `+auth-plugin-class-id+`, `+kagree-algo-ecdh+`/`+kagree-algo-ffdh+` strings, `+dsign-algo-ecdsa+`/`+dsign-algo-rsa+` strings, the HandshakeMessageToken property/binary-property **name** strings (`+prop-c-id+`, `+prop-c-dh1+`, `+prop-challenge1+`, …), the `+modp-2048-p+`/`+modp-2048-g+` group, the IdentityToken computation rule, and the signature-input concatenation order; plus the test-PKI file paths.

- [ ] **Step 1:** Read OMG DDS-Security 1.1 §8.7.2 (Identity/handshake behaviour, the message-token layouts, the request/reply/final ordering and signature inputs) and §9.3 (`DDS:Auth:PKI-DH` — the algorithm strings, the `kagree`/`dsign` properties, MODP-2048, the SharedSecret derivation, the IdentityToken). Record each pinned value in the spike doc **with its exact §-clause**.
- [ ] **Step 2:** Gather offline RTI evidence if available (Connext cert-config / `openssl`-inspectable artifacts, binary strings in the installed Connext libs) to corroborate the algorithm strings + token names — exactly as Slice 1's T0 used RTI Shapes-Demo strings. If the licensed Security plugins are absent (expected — same as Slice 1), record that and pin **spec-only**, documented honestly.
- [ ] **Step 3:** Write `interop/security-auth/gen-test-pki.sh` using `openssl`: a self-signed **Identity CA**; one **EC P-256** participant cert (`identity_ec.pem` + key) and one **RSA-2048** participant cert (`identity_rsa.pem` + key), each signed by the CA; plus a deliberately **wrong-CA** cert (signed by a second untrusted CA) for the negative tests. Run it; commit the generated `pki/`.
- [ ] **Step 4:** Write `src/dds-security/auth/constants.lisp` — every pinned constant as a `defconstant`/`defparameter` with a one-line `§`-citation docstring. No logic. Add it to `dds-security.asd` (first auth component) and confirm it loads on Clasp then SBCL.
- [ ] **Step 5: Re-plan checkpoint.** Summarize what was pinned vs spec-only-vs-RTI-corroborated; flag any §8.7/§9.3 detail that changes T1-T4 (e.g. if the SharedSecret derivation or signature input differs from this plan's assumption). Commit the spike + fixture + `constants.lisp`. Present the checkpoint to the controller before T1.

---

### Task 1: Identity — PKI load/validate + IdentityToken (+ the dds-dare X.509 FFI)

**Files:**
- Modify: `src/dds-dare/openssl-ffi.lisp`, `src/dds-dare/primitives.lisp`, `src/dds-dare/packages.lisp` (X.509 primitives)
- Create: `src/dds-security/auth/identity.lisp`
- Modify: `dds-security.asd`, `src/dds-security/packages.lisp`
- Test: `src/dds-tests/security-auth-test.lisp` (`run-auth-identity-test`)

**Interfaces:**
- Consumes: T0 `constants.lisp`; `dds.pal:alloc-static`/`free-static`; the `dds-dare` OpenSSL handle pattern (`src/dds-dare/openssl-ffi.lisp`).
- Produces, exported from `dds.dare`: `(x509-load-cert pem-octets) -> cert-handle|nil`, `(x509-load-ca pem-octets) -> ca-store|nil`, `(x509-verify-chain ca-store cert-handle) -> (member t nil)`, `(x509-public-key cert-handle) -> pkey-handle`, `(pkey-load-private pem-octets) -> pkey-handle|nil`, `(pkey-kind pkey-handle) -> (member :ec :rsa)`, `(x509-free …)`/`(pkey-free …)`. Exported from `dds.security`: `(defstruct* identity-handle …)`, `(validate-local-identity ca-pem cert-pem key-pem guid) -> identity-handle | (values nil reason)`, `(identity-token identity-handle) -> octet-vector`, `(validate-remote-identity local remote-identity-token) -> (values verdict role reason)`.

- [ ] **Step 1: Write the failing test** `run-auth-identity-test` in `src/dds-tests/security-auth-test.lisp`: load the T0 fixture CA + EC cert + key via `validate-local-identity`; assert it returns an `identity-handle` (not `(values nil …)`); assert `(identity-token h)` is a non-empty octet vector matching the T0-pinned computation for a known fixture cert (byte-exact regression vector); load the **wrong-CA** cert and assert `validate-local-identity` returns `(values nil <reason>)` (chain-verify fails closed). Use one-line `%check`-style assertions like the existing security tests.
- [ ] **Step 2: Run — expect FAIL** (`validate-local-identity` undefined). Clasp first: `./scripts/with-clasp.sh --eval '(ql:quickload :dds-tests :silent t)' --eval '(dds.tests:run-auth-identity-test)'`.
- [ ] **Step 3: Implement the dds-dare X.509 FFI** in `openssl-ffi.lisp`/`primitives.lisp`: handle-based bindings (`foreign-symbol-pointer :library *libcrypto*`, the DARE pattern) for `d2i`/`PEM_read_bio` cert load, `X509_STORE` + `X509_STORE_CTX` + `X509_verify_cert` chain verify, `X509_get_pubkey`, `PEM_read_bio_PrivateKey`, `EVP_PKEY_id`→`:ec`/`:rsa`. Confirm each signature against the installed OpenSSL 3.6.2 header. Export from `dds.dare`. Free handles via the existing DARE finalize pattern.
- [ ] **Step 4: Implement `identity.lisp`** — `validate-local-identity` (load CA store + cert + key, `x509-verify-chain` own cert, hold the private key in a `dds.pal:alloc-static` foreign buffer), `identity-token` (the T0-pinned cert-fingerprint+GUID computation), `validate-remote-identity` (compare IdentityTokens, decide `:requester`/`:replier` by the §8.7.2.4 GUID ordering, return `:rejected` on a malformed/unknown token). `defun*` + full ftype; add the files to `dds-security.asd`; export from `dds.security`.
- [ ] **Step 5: Run — expect PASS** both impls (Clasp first, then `sbcl --non-interactive …`). Register `run-auth-identity-test` in `packages.lisp` + `echo-test.lisp`.
- [ ] **Step 6: Commit** `feat(security): WP-DDS-SECURITY-AUTH-2A T1 — PKI identity (load/validate/IdentityToken) + dds-dare X.509 FFI (M7/P6 Slice 2a)`.

---

### Task 2: Handshake state machine + the ECDH-P256 suite → SharedSecret

**Files:**
- Modify: `src/dds-dare/openssl-ffi.lisp`, `primitives.lisp`, `packages.lisp` (ECDH + ECDSA + SHA primitives)
- Create: `src/dds-security/auth/suites.lisp`, `src/dds-security/auth/handshake.lisp`
- Modify: `dds-security.asd`, `src/dds-security/packages.lisp`
- Test: `src/dds-tests/security-auth-test.lisp` (`run-auth-handshake-ecdh-test`)

**Interfaces:**
- Consumes: T1 `identity-handle`/`validate-remote-identity`; T0 constants.
- Produces, exported from `dds.dare`: `(ecdh-gen-keypair) -> (values pub-octets priv-handle)`, `(ecdh-compute priv-handle peer-pub-octets) -> shared-octets`, `(ecdsa-sign priv-handle data) -> sig-octets`, `(ecdsa-verify pub-handle data sig) -> (member t nil)`. Exported from `dds.security`: `(defstruct* auth-suite …)` (closure vtable `kagree-gen`/`kagree-compute`/`dsign-sign`/`dsign-verify`/`hash`), `+suite-ecdh+`, `(defstruct* handshake-handle …)`, `(defstruct* shared-secret-handle …)`, `(begin-handshake-request local remote) -> request-token`, `(process-handshake handle incoming-token) -> (values next-token-or-nil status)` (`status` ∈ `{:continue,:authenticated,:rejected}`), `(handshake-shared-secret handle) -> shared-secret-handle`, `(shared-secret-bytes h) -> octet-vector`.

- [ ] **Step 1: Write the failing test** `run-auth-handshake-ecdh-test`: build two `identity-handle`s from the EC fixture (distinct GUIDs) sharing the CA; `validate-remote-identity` each way to fix roles; drive `begin-handshake-request` (requester) → `process-handshake`(replier, request)→reply → `process-handshake`(requester, reply)→final → `process-handshake`(replier, final)→`:authenticated`; assert both ends reach `:authenticated` and `(shared-secret-bytes …)` are **byte-equal** across the two sides and 32 bytes. Add two negatives: (a) flip a byte in the reply signature → requester's `process-handshake` returns `:rejected`; (b) reuse a stale `challenge1` in the final → replier returns `:rejected`.
- [ ] **Step 2: Run — expect FAIL** (handshake undefined). Clasp first.
- [ ] **Step 3: Implement the dds-dare ECDH/ECDSA FFI** (`EVP_PKEY` P-256 keygen, `EVP_PKEY_derive` ECDH, `EVP_DigestSign`/`EVP_DigestVerify` with SHA-256 for ECDSA). Confirm against the OpenSSL header; KAT each (an SEC1/NIST P-256 ECDH vector; an ECDSA verify vector). Secrets (the ECDH private handle, the shared bytes) via `dds.pal:alloc-static`. Export from `dds.dare`.
- [ ] **Step 4: Implement `suites.lisp`** — `auth-suite` vtable + `+suite-ecdh+` wiring the ECDH/ECDSA/SHA-256 primitives. **Implement `handshake.lisp`** — the token (de)serialization (property/binary-property lists per the T0-pinned layout, **bounds-checked parse**, fail-closed), the Request/Reply/Final builders, the signature over the T0-pinned concatenation, the verify steps (peer cert chain-verify via T1 + signature verify), the SharedSecret derivation, and the `process-handshake` state machine. Nonces + ephemeral keys from `RAND_bytes`. `defun*` + full ftype; add to `dds-security.asd`; export from `dds.security`.
- [ ] **Step 5: Run — expect PASS** both impls (Clasp first). Register the test.
- [ ] **Step 6: Commit** `feat(security): WP-DDS-SECURITY-AUTH-2A T2 — §8.7.2.4 handshake state machine + ECDH-P256 suite -> byte-equal SharedSecret; bad-sig/replay fail closed (M7/P6 Slice 2a)`.

---

### Task 3: The second §9.3 suite — FFDH-2048 + RSA + §9.3.2 selection

**Files:**
- Modify: `src/dds-dare/openssl-ffi.lisp`, `primitives.lisp`, `packages.lisp` (FFDH + RSA-PSS)
- Modify: `src/dds-security/auth/suites.lisp` (add `+suite-ffdh+` + `select-auth-suite`)
- Test: `src/dds-tests/security-auth-test.lisp` (`run-auth-handshake-rsa-test`)

**Interfaces:**
- Consumes: T2 `auth-suite`/handshake; T0 `+modp-2048-p+`/`+modp-2048-g+`.
- Produces, exported from `dds.dare`: `(ffdh-gen-keypair p g) -> (values pub-octets priv-handle)`, `(ffdh-compute priv-handle peer-pub-octets) -> shared-octets`, `(rsa-pss-sign priv-handle data) -> sig-octets`, `(rsa-pss-verify pub-handle data sig) -> (member t nil)`. Exported from `dds.security`: `+suite-ffdh+`, `(select-auth-suite local-cert-kind remote-cert-kind) -> auth-suite | nil` (§9.3.2).

- [ ] **Step 1: Write the failing test** `run-auth-handshake-rsa-test`: two `identity-handle`s from the **RSA** fixture; the full handshake → byte-equal 32-byte SharedSecret via `+suite-ffdh+`; assert `select-auth-suite` returns `+suite-ffdh+` for `(:rsa :rsa)` and `+suite-ecdh+` for `(:ec :ec)`; a mismatched/unsupported pair (e.g. `(:ec :rsa)` if the T0 §9.3.2 rule forbids it) returns `nil` → the handshake rejects.
- [ ] **Step 2: Run — expect FAIL** (`+suite-ffdh+`/`select-auth-suite` undefined). Clasp first.
- [ ] **Step 3: Implement the dds-dare FFDH/RSA-PSS FFI** (`EVP_PKEY` DH from the MODP-2048 params, `EVP_PKEY_derive`; `EVP_DigestSign`/`Verify` with RSA-PSS + SHA-256 + MGF1). KAT each (an RSASSA-PSS verify vector; an FFDH MODP-2048 agreement vector if available, else a self-consistency round-trip + a published DH test vector). Secrets via `dds.pal:alloc-static`.
- [ ] **Step 4: Implement** `+suite-ffdh+` in `suites.lisp` + `select-auth-suite` per the T0-pinned §9.3.2 rule. The `handshake.lisp` state machine is suite-agnostic (it already drives the vtable) — confirm no changes beyond selecting the suite from the cert kinds.
- [ ] **Step 5: Run — expect PASS** both impls (Clasp first). Register the test.
- [ ] **Step 6: Commit** `feat(security): WP-DDS-SECURITY-AUTH-2A T3 — FFDH-2048 + RSA-PSS suite + §9.3.2 selection (M7/P6 Slice 2a)`.

---

### Task 4: The fail-closed negative battery + token-format corpus + parser fuzz + KAT roll-up

**Files:**
- Test: `src/dds-tests/security-auth-test.lisp` (`run-auth-negatives-test`, `run-auth-token-corpus-test`, `run-auth-token-fuzz-test`)
- Modify: `src/dds-security/auth/handshake.lisp` / `identity.lisp` only if a negative exposes a real gap

**Interfaces:**
- Consumes: T1-T3 entry points + the T0 wrong-CA fixture.

- [ ] **Step 1: Write `run-auth-negatives-test`** — assert each fails closed (`:rejected`/`(values nil …)`, never a SharedSecret, never a throw): untrusted-CA peer cert; expired/tampered cert (mutate a fixture cert byte); bad signature (Reply and Final, both suites); replayed/wrong nonce; unsupported algorithm (`select-auth-suite` → nil); a truncated and an over-long token. Non-vacuous: also assert the matching positive still authenticates.
- [ ] **Step 2: Write `run-auth-token-corpus-test`** — serialize a known Request/Reply/Final (fixed fixture inputs + fixed nonces injected) and assert the bytes match the T0-pinned §8.7/§9.3 layout (a committed byte-exact regression vector); round-trip parse → identical structure.
- [ ] **Step 3: Write `run-auth-token-fuzz-test`** — N≈2000 malformed/short/random token blobs through `process-handshake` (in both prod and a `(safety 0)` compiled path); assert each returns `:rejected`/`nil` with no OOB/crash/signal escape (mirror `run-security-payload-fuzz-test`).
- [ ] **Step 4: Run all three** Clasp first then SBCL; fix any real fail-closed gap they expose in `handshake.lisp`/`identity.lisp` (re-run after a fix).
- [ ] **Step 5: Commit** `test(security): WP-DDS-SECURITY-AUTH-2A T4 — fail-closed negatives + token corpus + parser fuzz (M7/P6 Slice 2a)`.

---

### Task 5: Capstone — ADR 0032 + docs lockstep + full gate sweep + final review

**Files:**
- Create: `docs/adr/0032-dds-security-auth-handshake.md`
- Modify: `docs/wiki/security.md`, `README.md`, `docs/verification.csv`

- [ ] **Step 1: ADR 0032** (as-built): the §8.7 PKI-DH handshake → SharedSecret; both §9.3 suites + §9.3.2 selection; the `dds-dare` OpenSSL FFI extension (no hand-rolled crypto); foreign-buffer secrets; the spike-pinned constants; the our-to-our + offline-conformance posture with **live Connext-Security auth DEFERRED to Slice 5** (honest, no overclaim); how 2b (discovery) and 2c (key-material → drop the pre-shared key) follow. Model structure on ADR 0031.
- [ ] **Step 2: Docs lockstep** — `docs/wiki/security.md` Authentication section (the `dds.security` auth API + the handshake + the roadmap position); `README.md` P6 row updated to "Slice 1 + Slice 2a (auth handshake) landed; 2b/2c/3-5 pending"; `docs/verification.csv` append a clean 6-column `P6-SEC-AUTH-HANDSHAKE` row (evidence = our-to-our both suites + negatives + token-conformance + KATs; live cross-vendor deferred). Verify the CSV parses (6 cols).
- [ ] **Step 3: Full gate sweep** Clasp first: `make build && make test-clasp && make test-sbcl && make gate-hotpath && make gate-types && make mem && make fuzz && make wire`. Expected: both green, `mem 0.0000`, all gates PASS. Report each with its number.
- [ ] **Step 4: Commit** `docs(security): WP-DDS-SECURITY-AUTH-2A T5 — ADR 0032 + docs lockstep + gate sweep (M7/P6 Slice 2a)`.
- [ ] **Step 5 (controller, not this task):** final whole-branch review over `main..HEAD` (most capable model) → one fix wave → squash-merge presented for owner approval (HOLD PUSH).

---

## Self-review

**Spec coverage:** §2 scope → all tasks; §3 suite (both) → T2 (ECDH) + T3 (FFDH) + §9.3.2 selection (T3); §4 architecture (identity/handshake/suites over extended dds-dare FFI) → T1/T2/T3; §5 protocol → T2 state machine; §6 error handling/fail-closed + foreign-buffer secrets → T1-T4 (secrets in T1/T2/T3, negatives in T4); §7 DoD (both-suite auth, negatives, token corpus, fuzz, KATs, gates, live-deferred) → T2/T3/T4/T5; §9 task list → T0-T5. The spike-pinned constants (§3/§5/§8) are pinned in T0 and consumed thereafter — the correct spike-first handling per the operating contract, explicitly flagged, not a plan gap (the Slice-1 precedent). No gap.

**Placeholder scan:** the only "to-be-pinned" values are the T0 spike constants + the OpenSSL-header-discovered FFI signatures — both are explicitly assigned to T0 / header-discovery with §-citations and KATs, the conformant handling of the no-constants-from-memory rule, not vague TODOs. No "add error handling"/"handle edge cases" hand-waving (the negatives are enumerated in T4).

**Type consistency:** `identity-handle` (T1) consumed by T2/T3; `auth-suite` + `+suite-ecdh+` (T2) extended by `+suite-ffdh+` + `select-auth-suite` (T3); `handshake-handle`/`shared-secret-handle` + `process-handshake`/`begin-handshake-request` (T2) used by T3/T4; the `dds.dare` `x509-*`/`ecdh-*`/`ffdh-*`/`ecdsa-*`/`rsa-pss-*` names are consistent across T1-T3. `shared-secret-bytes` (T2) used in T2/T3 tests. Consistent.
