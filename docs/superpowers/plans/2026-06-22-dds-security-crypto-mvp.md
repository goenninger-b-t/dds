# WP-DDS-SECURITY-CRYPTO-MVP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Protect user-data end-to-end (our-pub → our-sub), byte-exact AES-GCM, with the conformant DDS-Security 1.1 SecuredPayload wire format (serialized-payload protection), reusing `dds-dare`'s AES-GCM — M7/P6 Slice 1 of 5.

**Architecture:** A new `dds-security` ASDF system implements `encode/decode-serialized-payload` over the SecuredPayload format (SecureDataHeader + AES-GCM ciphertext + SecureDataTag, §9.5.3.3) using `dds.dare:aes-256-gcm-seal/open`, with a pre-shared test KeyMaterial. A disc-node crypto-transform slot (default OFF = plaintext path byte-identical) hooks encode at `publish-sample` and decode at the reader payload path. **Spike-first:** a live Connext-Security capture, decoded offline, pins every wire constant before T1.

**Tech Stack:** Common Lisp (SBCL + Clasp), new `dds-security` (`dds.security`) over `dds-dare` (AES-GCM/HKDF, OpenSSL), `dds-rtps` (cursor/octet layer), `dds-disc` (dataplane); RTI Connext Security 7.3.1 (certs/governance/permissions) + tshark for the T0 spike + the byte-compare DoD.

## Global Constraints

- **No hand-rolled crypto** — reuse `dds.dare:aes-256-gcm-seal`/`aes-256-gcm-open` (returns `(values ct tag)` / `plaintext|NIL`) and `dds.dare:hkdf-sha384`; if the spec's session-key PRF differs (AES256-GCM commonly uses SHA-256), add a small HMAC-SHA256/HKDF-SHA256 over the existing `dds-dare` OpenSSL FFI — never hand-roll (FR-SEC-2).
- **OMG DDS-Security 1.1 conformance** — the SecuredPayload wire format never deviates; a vendor interop behavior goes ON TOP of conformant behavior, never replaces it.
- **No wire constants from memory** — `transformation_kind` (the AES256-GCM value), the session-key KDF, the nonce composition, the SecureDataHeader/crypto_content/SecureDataTag byte layout + endianness are pinned from the **T0 spike (the live Connext capture) + the cited §9.5.3.3 clause**, cited in comments. The plan's T1-T2 use placeholder names for these constants; T0 fills the exact values (re-plan checkpoint).
- **Bounds-check the decode path even at `(safety 0)`** — a malformed/short SecuredPayload returns a fail-closed error, never an OOB read; fuzzed (NFR-SEC-POSTURE).
- **Default OFF byte-identical** — security disabled = today's plaintext path unchanged; `make mem` stays 0.0000 on the plaintext default path (the per-sample AES-GCM cost is on the security send path only, measured + reported).
- `defun*`/`defstruct*` + full ftype on every new function; **no reader conditionals outside `dds-pal/`**; **Clasp AND SBCL both, Clasp first**; no AI/assistant attribution.

## File map

- `dds-security.asd` (new) — the system (`:depends-on ("dds-lang" "dds-pal" "dds-core" "dds-dare" "dds-rtps" "cffi")`, pathname `src/dds-security`, serial, components packages+crypto+key-material). Model on `dds-dare.asd`.
- `src/dds-security/packages.lisp` (new) — the `dds.security` package + exports.
- `src/dds-security/key-material.lisp` (new) — the `key-material` struct + `make-test-key-material`.
- `src/dds-security/crypto.lisp` (new) — the SecuredPayload (de)serialization + the session-key KDF + `encode/decode-serialized-payload`.
- `src/dds-disc/dataplane.lisp` + `src/dds-disc/disc.lisp` — the disc-node crypto-transform slot + the encode hook (`publish-sample`) + the decode hook (`%on-user-data`).
- `src/dds-tests/security-test.lisp` (new) + `echo-test.lisp` + `packages.lisp` — the corpus/round-trip/fuzz/live tests.
- `dds.asd` / `dds-tests.asd` — add `dds-security` to the umbrella + the test deps.
- `interop/security-crypto/` (new, T0+T4) — the Connext-Security capture + offline decode + byte-compare.
- `docs/adr/0031-dds-security-crypto.md` (new); `README.md`, `docs/wiki/`, `docs/verification.csv` (T4).

---

### Task 0: Spike — Connext-Security payload-protection capture + offline decode

**Files:** Create `interop/security-crypto/spike/` (the Connext-Security config + run script + a Python decoder) + `docs/superpowers/spikes/2026-06-22-dds-security-payload-wire.md`. NO `src/` change (build-clean spike).

**Goal:** Pin the EXACT serialized-payload-protection wire format Connext-Security emits, so T1 builds to the wire (not memory).

- [ ] **Step 1: Stand up Connext Security with payload protection.** Build a minimal Connext-Security config: a CA + a participant certificate, a signed governance doc (`domain_rule` with `data_protection_kind = ENCRYPT` and `metadata_protection_kind = NONE` so ONLY the serialized payload is protected — the thinnest), a signed permissions doc granting publish/subscribe on `Square`. Run a Connext-Security `shapes_pub` (reuse `interop/connext/` apps + the security QoS) writing a keyed `Square`. (RTI's `openssl`-based example certs/governance under `$NDDSHOME/resource/.../secure` are a starting template.)

- [ ] **Step 2: Capture + decode the SecuredPayload offline.** tshark-capture the user-data DATA on lo0. The serialized payload is replaced by a SecuredPayload. Write a Python decoder (`interop/security-crypto/spike/decode-secured-payload.py`) that walks the DATA submessage's serialized-payload region and parses: `transformation_kind`(4), `transformation_key_id`(4), `session_id`(4), `init_vector_suffix`(8), the `crypto_content` (and its framing — length-prefixed?), the `SecureDataTag` (`common_mac`(16) + `receiver_specific_macs`). Report the byte offsets, the endianness, the AES256-GCM `transformation_kind` value, and confirm `receiver_specific_macs` count = 0 for payload protection.

- [ ] **Step 3: Pin the session-key KDF + nonce + AAD.** From §9.5.3.3.4 + the capture: the nonce = `session_id ∥ init_vector_suffix` (12 B); the session key = KDF(master_sender_key, session_id, …) — pin the PRF/hash (SHA-256 vs other) and the KDF inputs; the AAD scope (the SecureDataHeader bytes, and whether anything else). Where the key isn't known (Connext's master key is internal), pin the STRUCTURE + verify our own seal reproduces a self-consistent SecuredPayload of the same shape; the byte-for-byte key-equal compare is done in T4 only where a shared known key is reproducible.

- [ ] **Step 4: Write the finding + RE-PLAN CHECKPOINT.** `docs/superpowers/spikes/2026-06-22-dds-security-payload-wire.md`: the exact byte layout, the `transformation_kind` value, the KDF, the nonce, the AAD, with offsets + a hex dump. Controller confirms before T1 (the constants flow into T1/T2). If Connext-Security cannot be stood up, document the spec-clause-only fallback + escalate (do NOT invent constants).

- [ ] **Step 5: Commit** (spike doc + harness; NO src):
```bash
git add interop/security-crypto/spike docs/superpowers/spikes/2026-06-22-dds-security-payload-wire.md
git commit -m "spike(security): WP-DDS-SECURITY-CRYPTO-MVP — Connext-Security serialized-payload-protection wire format pinned (DDS-Security 1.1 §9.5.3.3) (M7/P6)"
```

---

### Task 1: `dds-security` system + SecuredPayload format + session-key KDF

**Files:**
- Create: `dds-security.asd`, `src/dds-security/packages.lisp`, `src/dds-security/crypto.lisp`
- Modify: `dds.asd` (umbrella), `dds-tests.asd` (test dep)
- Test: `src/dds-tests/security-test.lisp` (`run-security-secured-payload-corpus-test`), registered + exported

**Interfaces:**
- Consumes: `dds.dare:aes-256-gcm-seal`/`aes-256-gcm-open`/`hkdf-sha384`; the spike's pinned constants.
- Produces: `serialize-secured-payload (kind key-id session-id iv-suffix ciphertext tag) → octets` + `parse-secured-payload (octets) → (values kind key-id session-id iv-suffix ciphertext tag)` (bounds-checked); `derive-session-key (master-key session-id …) → 32-octet key` (the spike's KDF); the constant `+transformation-kind-aes256-gcm+` (pinned from the spike).

- [ ] **Step 1: The system + package.** `dds-security.asd` modeled on `dds-dare.asd` (deps + components packages/key-material/crypto). `src/dds-security/packages.lisp`: `(defpackage #:net.goenninger.dds.security (:nicknames #:dds.security) (:use #:cl #:net.goenninger.dds.lang) (:export …))`. Add `dds-security` to `dds.asd`'s `:depends-on` and `dds-tests.asd`.

- [ ] **Step 2: Write the failing corpus test.** In `src/dds-tests/security-test.lisp`: a known `transformation_kind`/`key_id`/`session_id`/`iv_suffix`/`ciphertext`/`tag` → `serialize-secured-payload` produces the EXACT bytes the spike pinned (paste the spike's reference hex), and `parse-secured-payload` round-trips them. Use `%check`.

- [ ] **Step 3: Run it — expect FAIL** (functions undefined), Clasp first (commands as in the durability tests).

- [ ] **Step 4: Implement `serialize-secured-payload`/`parse-secured-payload`** in `crypto.lisp` per the spike's exact layout (SecureDataHeader fixed fields, `crypto_content` framing, `SecureDataTag` common_mac + empty receiver_specific_macs), using the `dds.core.buffer` cursor (put/get-u32 etc.) at the pinned endianness. `parse-secured-payload` bounds-checks every field read against the octet length (fail-closed on short input).

- [ ] **Step 5: Implement `derive-session-key`** per the spike's KDF (reuse `dds.dare:hkdf-sha384` if it matches; else add `hmac-sha256`/`hkdf-sha256` in `crypto.lisp` over the `dds-dare` OpenSSL FFI — a small primitive, no hand-rolling). Add `+transformation-kind-aes256-gcm+` (the pinned value, cited).

- [ ] **Step 6: Run the corpus test — expect PASS** both impls; register/export; commit `feat(security): WP-DDS-SECURITY-CRYPTO-MVP — dds-security system + SecuredPayload (de)serialization + session-key KDF, byte-exact vs Connext capture (DDS-Security 1.1 §9.5.3.3) (M7/P6, ADR 0031)`. Gates: `make build` (the new system loads both impls) + `make gate-types`.

---

### Task 2: `encode/decode-serialized-payload` + KeyMaterial + test key

**Files:**
- Create: `src/dds-security/key-material.lisp`
- Modify: `src/dds-security/crypto.lisp` (the two transform ops)
- Test: `src/dds-tests/security-test.lisp` (`run-security-payload-roundtrip-test`, `run-security-payload-fuzz-test`)

**Interfaces:**
- Consumes: T1's `serialize/parse-secured-payload`, `derive-session-key`, `+transformation-kind-aes256-gcm+`; `dds.dare:aes-256-gcm-seal/open`.
- Produces: `key-material` struct (transformation-kind, master-salt, sender-key-id, master-sender-key) + `make-test-key-material () → key-material`; `encode-serialized-payload (km plaintext) → secured-octets`; `decode-serialized-payload (km secured-octets) → plaintext|NIL`.

- [ ] **Step 1: KeyMaterial + test key.** `key-material.lisp`: `(defstruct* key-material …)` (§9.5.2 fields) + `make-test-key-material` returning a fixed pre-shared KeyMaterial (a known 32-B master key, fixed key_id, AES256-GCM kind). Docstring: this is the MVP scaffold the Slice-2 Auth handshake replaces.

- [ ] **Step 2: Write the failing round-trip + tamper test.** `run-security-payload-roundtrip-test`: `(decode-serialized-payload km (encode-serialized-payload km PT)) = PT`; flip one ciphertext byte and one tag byte → `decode` returns NIL (fail-closed, AES-GCM auth fail); a non-secured/short blob → `decode` returns NIL (not a crash). And `run-security-payload-fuzz-test`: N random/short/oversized SecuredPayloads → `decode` returns NIL or the correct PT, never OOB/crash, prod + `(safety 0)`.

- [ ] **Step 3: Run — expect FAIL.**

- [ ] **Step 4: Implement.** `encode-serialized-payload`: pick a `session_id`/`init_vector_suffix` (a per-write counter ensuring nonce uniqueness — the nonce is `session_id ∥ iv_suffix`), `derive-session-key`, build the SecureDataHeader, `aes-256-gcm-seal (session-key nonce header-as-aad plaintext) → (ct, tag)`, `serialize-secured-payload kind key-id session-id iv-suffix ct tag`. `decode-serialized-payload`: `parse-secured-payload`, `derive-session-key`, `aes-256-gcm-open (session-key nonce header-as-aad ct tag)` → plaintext|NIL.

- [ ] **Step 5: Run — expect PASS** both impls; register/export; commit `feat(security): WP-DDS-SECURITY-CRYPTO-MVP — encode/decode-serialized-payload over dds-dare AES-GCM + KeyMaterial + test-key; round-trip + tamper-fails-closed + bounds/fuzz (M7/P6, ADR 0031)`. Gates: build + gate-types + the fuzz arm.

---

### Task 3: `dds-disc` integration — encrypted pub/sub our-to-our

**Files:**
- Modify: `src/dds-disc/disc.lisp` (a `crypto-transform` disc-node slot) + `src/dds-disc/dataplane.lisp` (`publish-sample` encode hook ~964; the reader decode hook in `%on-user-data` ~1357)
- Modify: `dds-disc.asd` (depend on `dds-security`)
- Test: `src/dds-tests/security-test.lisp` (`run-security-encrypted-pubsub-test`)

**Interfaces:**
- Consumes: T2's `encode/decode-serialized-payload`, `make-test-key-material`; `make-disc-node`, `publish-sample`, `%on-user-data`.
- Produces: a `make-disc-node :crypto-transform <key-material>` option (default NIL = security off); when set, `publish-sample` emits the SecuredPayload and the reader decodes before delivery.

- [ ] **Step 1: Write the failing test.** `run-security-encrypted-pubsub-test` (two-node loopback, domain 83, mirror `run-durability-origin-accessor-test`'s wiring but BOTH nodes built with `:crypto-transform (dds.security:make-test-key-material)`): pub publishes a known payload; sub receives EXACTLY that plaintext (decode worked); and assert `node-sample` on a node WITHOUT the transform would see ciphertext (the wire carried the SecuredPayload, not plaintext) — i.e. a third reader without the key gets undecodable bytes (or no delivery). 

- [ ] **Step 2: Run — expect FAIL** (`:crypto-transform` option undefined).

- [ ] **Step 3: disc-node slot + hooks.** Add a `crypto-transform` slot to the `disc-node` struct (default NIL) + the `make-disc-node :crypto-transform` keyword. In `publish-sample` (~964): when `(disc-node-crypto-transform node)` is set, `(setf payload (dds.security:encode-serialized-payload <km> payload))` before `writer-write`. In `%on-user-data` (~1357): when set, `decode-serialized-payload` the received payload before delivery — if `decode` returns NIL (auth fail / not-secured), DROP best-effort (no delivery, no crash), else deliver the plaintext. Default NIL → both hooks are skipped → byte-identical.

- [ ] **Step 4: Run — expect PASS** both impls.

- [ ] **Step 5: Live tshark check + gate + commit.** A small harness `interop/security-crypto/run-our2our.sh` (or extend the test) capturing the loopback: assert the DATA serialized-payload region is NOT the ShapeType plaintext (it's the SecuredPayload ciphertext). Then `make test-clasp && make test-sbcl && make gate-hotpath && make gate-types && make mem` (the plaintext default path 0.0000; report the security-path per-sample cost) + commit `feat(disc): WP-DDS-SECURITY-CRYPTO-MVP — disc-node crypto-transform slot (default OFF byte-identical) + publish/receive payload encode/decode hooks; our-to-our encrypted pub/sub live (M7/P6, ADR 0031)`.

---

### Task 4: Capstone — offline Connext byte-compare + ADR 0031 + docs + final review

**Files:** `interop/security-crypto/` (the byte-compare); `docs/adr/0031-dds-security-crypto.md` (new); `README.md`, `docs/wiki/` (new security page or section), `docs/verification.csv`.

- [ ] **Step 1: The interop DoD — offline byte-compare.** Using the T0 Connext capture, compare our `encode-serialized-payload` output to Connext's payload-protection `SecuredPayload`: field-by-field structural equality (SecureDataHeader layout, kind, the crypto_content/SecureDataTag framing), and — where a shared known key + plaintext is reproducible — a byte-for-byte AES-GCM compare (our seal == Connext's ciphertext+tag for the same key/nonce/aad/plaintext), OR our `aes-256-gcm-open` verifying against Connext's tag. Document the exact level of equality achieved honestly.

- [ ] **Step 2: ADR 0031** (as-built: the Crypto plugin serialized-payload protection; the SecuredPayload format pinned from the spike; the dds-dare reuse; the test-key scaffold; the byte-compare result; the Slice 1/5 roadmap + what Slice 2 [Auth] changes). Mark the M7 roadmap.

- [ ] **Step 3: Docs lockstep.** `README.md` P6 row (Slice 1 landed); a `docs/wiki/security.md` page (the Crypto plugin + the SecuredPayload + the `dds-security` API + the roadmap); `docs/verification.csv` append a clean 6-column `P6-SEC-CRYPTO-PAYLOAD` row (verify it parses, last row 6 cols).

- [ ] **Step 4: Full gate sweep both impls (Clasp first).**
```
make build && make test-clasp && make test-sbcl && make gate-hotpath && make gate-types && make mem && make fuzz && make wire
```
Expected: both green (deterministic), gate-hotpath PASS, gate-types PASS, mem 0.0000 (plaintext default), fuzz PASS (incl. the new decode arm), wire PASS.

- [ ] **Step 5: Commit the capstone**, then (controller, NOT this task) the final whole-branch review over `main..HEAD` → ONE fix wave → squash-merge presented for owner approval (HOLD PUSH).

---

## Self-review

**Spec coverage:** §3.1 new system → T1. §3.2 SecuredPayload format + KDF → T1. §3.3 KeyMaterial + test key → T2. §3.4 dds-disc integration → T3. §3.5 data flow → T2/T3. §4 DoD: spike (T0), corpus (T1), round-trip/tamper/fuzz (T2), live our-to-our + tshark (T3), offline Connext byte-compare (T4), gates (T4). §5 decomposition → the 5 tasks. §6 risks (Connext config, KDF hash, send-path cost) → T0 spike + T1 KDF step + T3 mem measurement. All covered.

**Placeholder scan:** every code/test step shows the structure + the exact dds-dare reuse + the test shape. The deferred values (the SecuredPayload exact bytes, the transformation_kind, the KDF hash) are **pinned by T0 (the spike) per the operating contract's no-constants-from-memory rule** — they are explicitly named ("the spike pins X") with where they flow (T1 Steps 4-5), not vague "TBD". This is the correct spike-first handling, not a plan gap.

**Type consistency:** `serialize-secured-payload (kind key-id session-id iv-suffix ciphertext tag)` / `parse-secured-payload (octets) → (values …)` (T1) consumed by `encode/decode-serialized-payload` (T2). `key-material` + `make-test-key-material` (T2) consumed by T3's `make-disc-node :crypto-transform`. `aes-256-gcm-seal → (values ct tag)` / `aes-256-gcm-open (… ct tag) → plaintext|NIL` are the real `dds-dare` signatures (verified). The disc-node `crypto-transform` slot + the `publish-sample`/`%on-user-data` hooks are consistent across T3.
