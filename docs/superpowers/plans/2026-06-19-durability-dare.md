# CNSA-2.0 DARE (Phase 3a) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the always-on CNSA-2.0 Data-At-Rest Encryption layer (ADR 0021 cap. 7) as a `durable-store` decorator: seal payloads with a KEM-DEM envelope (ML-KEM-1024 → HKDF-SHA384 → per-store AES-256-GCM data key), proven end-to-end over the in-memory store; disk is the MUST follow-on (3b).

**Architecture:** A new standalone `dds-dare` ASDF system wraps OpenSSL ≥ 3.5 (`libcrypto`) via CFFI — AES-256-GCM, ML-KEM-1024 (FIPS-203), SHA-384, HKDF-SHA384 — behind small `defun*` primitive wrappers, a KEM-DEM `seal-payload`/`open-payload` envelope, and a pluggable key-provider vtable (file-based default). A `make-encrypted-store` decorator in `dds-durability` wraps an inner `durable-store`, sealing on `put` / opening on `get-range`, with metadata AAD-authenticated so the inner store still indexes/replays without decrypting. Fail-closed throughout; secrets in foreign buffers (zeroized).

**Tech Stack:** Common Lisp (SBCL + Clasp; AllegroCL where available), ASDF, **CFFI → OpenSSL ≥ 3.5 libcrypto** (confirmed present: OpenSSL 3.6.2, `ML-KEM-1024` available), the existing `dds-durability` store vtable.

## Global Constraints

(Every task implicitly includes these — from the operating contract, `REQUIREMENTS.md`, the memory, ADR 0021/0023/0024, and the design spec `docs/superpowers/specs/2026-06-19-durability-dare-design.md`.)

- **`defun*` for every function, `defstruct*` for every struct** (`dds.lang`): `(defun* name (lambda-list) (function (arg-types…) result-type) "docstring" body…)` — required-arg count matches the signature; docstring mandatory non-empty. Every `defstruct*` slot `:type`. `make gate-types` enforces full ftype coverage.
- **NO hand-rolled crypto** (FR-SEC-2). OpenSSL provides every primitive; we only WRAP (CFFI) + COMPOSE (the envelope) per NIST guidance. CNSA-2.0 = **AES-256-GCM** (FIPS-197 / SP 800-38D), **ML-KEM-1024** (FIPS-203), **SHA-384** (FIPS-180-4), **HKDF-SHA384** (SP 800-56C / RFC 5869). The OpenSSL algorithm name for the KEM is exactly **`"ML-KEM-1024"`**.
- **NIST KATs are the conformance oracle.** Pin known-answer vectors from AUTHORITATIVE sources — NIST CAVP (AES-GCM, SHA-384), FIPS-203 / NIST ACVP ML-KEM intermediate values, RFC 5869 / SP 800-56C HKDF appendix vectors, or the OpenSSL `test/recipes` data. **NEVER fabricate crypto bytes** — cite the vector's source in the test. A KAT proves the OpenSSL binding yields the correct algorithm.
- **Verify the OpenSSL CFFI against the installed headers** (OpenSSL 3.6.2 man pages: `EVP_PKEY-ML-KEM`, `EVP_PKEY_encapsulate`, `EVP_EncryptInit_ex`/GCM, `EVP_KDF`/`EVP-HKDF`, `EVP_Q_digest`/`EVP_sha384`). Do NOT invent `defcfun` signatures from memory — confirm names/arities against `<openssl/evp.h>` / the man pages on this host.
- **Fail-closed, never silent fallback.** Any auth failure (wrong key, tampered ct/tag/AAD) → hard failure, never plaintext, never partial. OpenSSL < 3.5 / ML-KEM absent → **hard startup error** (`dare-available-p` NIL → signal), NEVER a silent plaintext path (the arena-exhaustion-never-falls-back principle).
- **Secrets in FOREIGN buffers** (CFFI `foreign-alloc` / `static-vectors`), explicitly **zeroized** after use (a GC-moved heap array can't be reliably wiped); keys/DEK/shared-secret NEVER logged.
- **NFR-SEC-POSTURE:** the `open-payload` parse of untrusted sealed bytes is bounds-checked even at `(safety 0)`; fuzzed.
- **NFR-MEM:** DARE is control-plane (the collect loop ~5 ms poll), OFF the measured CDR hot path → `make mem` stays **0.0000**. (Foreign-buffer crypto is fine here; not the static arena.)
- **No reader conditionals** (`#+sbcl`/`#+clasp`) outside `dds-pal/` — CFFI is impl-agnostic; a Clasp FFI gap is a documented `(dds.pal:pal-impl-name)` NFR-PORT skip, never a `#+`.
- **No "Claude"/AI attribution** anywhere; no `Co-Authored-By`. **Docs lockstep** (ADR + wiki + README + verification.csv + provenance) at the capstone. **SBOM** auto-regenerates; add OpenSSL to the pinned table (`scripts/generate-sbom.py`) + record provenance (OpenSSL Apache-2.0 license).
- **DoD per task:** compiles + tests green on SBCL AND Clasp (or a documented NFR-PORT gap); applicable gates green; commit references the WP id + requirement id. Verification uses the `make` targets (a bare `sbcl --eval (ql:quickload :dds-tests)` lacks the source registry).
- **Branch:** `wp-durability-dare` (already created, the design spec committed). Autonomous commits within the branch; **HOLD PUSH** until owner's word; squash-merge presented for approval after the final whole-branch review.

---

## File Structure

```
dds-dare.asd                        NEW  — the crypto/DARE ASDF system (sibling .asd at repo root)
src/dds-dare/packages.lisp          NEW  — defpackage net.goenninger.dds.dare (nick dds.dare)
src/dds-dare/openssl-ffi.lisp       NEW  — CFFI bindings to OpenSSL ≥ 3.5 libcrypto + dare-available-p + load
src/dds-dare/primitives.lisp        NEW  — sha-384, hkdf-sha384, aes-256-gcm-seal/open, ml-kem-* wrappers
src/dds-dare/envelope.lisp          NEW  — seal-payload / open-payload (KEM-DEM); the sealed-blob format
src/dds-dare/key-provider.lisp      NEW  — key-provider vtable + make-file-key-provider
src/dds-durability/store-encrypted.lisp  NEW — make-encrypted-store (durable-store decorator)
src/dds-durability/packages.lisp    MOD  — export make-encrypted-store
dds-durability.asd                  MOD  — :depends-on + add "dds-dare" + the store-encrypted component
dds.asd                             MOD  — add "dds-dare" to the umbrella
dds-tests.asd                       MOD  — :depends-on "dds-dare" + a dare-test component
src/dds-tests/dare-test.lisp        NEW  — KATs + envelope/provider/decorator/fuzz tests
src/dds-tests/packages.lisp + echo-test.lisp  MOD — export + register run-* tests
scripts/generate-sbom.py            MOD (Task 7) — pin OpenSSL; docs/provenance.md MOD (Task 7)
docs/adr/0025-durability-dare.md    NEW (Task 7); docs/wiki/durability.md + README.md + verification.csv MOD (Task 7)
```

Package skeleton (Task 1 creates it; later tasks extend the export list):
```lisp
(defpackage #:net.goenninger.dds.dare
  (:nicknames #:dds.dare)
  (:use #:common-lisp #:net.goenninger.dds.lang)
  (:documentation "DDS.DARE — CNSA-2.0 Data-At-Rest Encryption (AES-256-GCM + ML-KEM-1024 + SHA-384) over OpenSSL ≥ 3.5. ADR 0021 cap. 7.")
  (:export #:dare-available-p #:dare-unavailable
           #:sha-384 #:hkdf-sha384 #:aes-256-gcm-seal #:aes-256-gcm-open
           #:ml-kem-1024-keygen #:ml-kem-1024-encapsulate #:ml-kem-1024-decapsulate
           #:seal-payload #:open-payload #:dare-open-failure
           #:key-provider #:make-file-key-provider #:key-provider-recipient-public-key
           #:key-provider-decapsulate #:key-provider-open #:key-provider-close
           #:*dare-error-hook*))
```

---

## Task 1: `dds-dare` system + OpenSSL CFFI load + `dare-available-p` + SHA-384/HKDF (with KATs)

**Goal:** Stand up the system, bind libcrypto, gate availability, and ship the two simplest primitives (SHA-384, HKDF-SHA384) with NIST/RFC KATs — establishing the CFFI + KAT pattern. No DDS deps yet.

**Files:** Create `dds-dare.asd`, `src/dds-dare/packages.lisp`, `src/dds-dare/openssl-ffi.lisp`, `src/dds-dare/primitives.lisp`, `src/dds-tests/dare-test.lisp`; Modify `dds.asd`, `dds-tests.asd`, `src/dds-tests/packages.lisp`, `src/dds-tests/echo-test.lisp`.

**Interfaces produced:**
- `(dare-available-p)` → `boolean` — T iff libcrypto loaded AND OpenSSL ≥ 3.5 (via `OpenSSL_version_num`) AND `ML-KEM-1024` fetchable. `dare-unavailable` condition for the hard-error path.
- `(sha-384 octets)` → `(simple-array (unsigned-byte 8) (48))` — SHA-384 digest (via `EVP_Q_digest` or `EVP_Digest` + `EVP_sha384()`).
- `(hkdf-sha384 ikm salt info out-len)` → `(simple-array (unsigned-byte 8) (out-len))` — HKDF (extract+expand) with SHA-384 (via the `EVP_KDF` "HKDF" provider). `ikm`/`salt`/`info` octet vectors, `out-len` a positive fixnum.

- [ ] **Step 1: Probe + pin OpenSSL facts.** Confirm on this host: `openssl version` (≥ 3.5 — expect 3.6.2), the libcrypto dylib path (e.g. `/opt/homebrew/opt/openssl@3/lib/libcrypto.dylib`), and the `ML-KEM-1024` algorithm name. Record the exact `EVP_KDF`/`EVP_Q_digest`/version-fn signatures from the installed man pages in a comment block at the top of `openssl-ffi.lisp` (provenance). Do NOT proceed on memory — pin against the headers.
- [ ] **Step 2: Failing KAT test** in `src/dds-tests/dare-test.lisp` (package `dds.tests`, `%check`). Pin AUTHORITATIVE vectors (cite the source in a comment — do NOT fabricate):
```lisp
(defun* run-dare-sha384-hkdf-kat-test ()
    (function () t)
  "SHA-384 (FIPS-180-4 / NIST CAVP) + HKDF-SHA384 (RFC 5869 / SP 800-56C) known-answer vectors."
  ;; SHA-384("abc") = NIST FIPS-180-4 example (cite §): cb00753f45a35e8b b5a03d699ac65007 272c32ab0eded163
  ;;   1a8b605a43ff5bed 8086072ba1e7cc23 58baeca134c825a7  (48 bytes) — pin the exact bytes from the standard.
  ;; HKDF-SHA384: use an RFC-5869-style vector (RFC 5869 gives SHA-256; for SHA-384 pin a NIST SP 800-56C
  ;;   or OpenSSL test/recipes HKDF-SHA384 vector — cite it; never invent).
  (let ((d (dds.dare:sha-384 (dds.dare::%ascii "abc"))))
    (%check :sha384-abc (equalp d <the 48 pinned bytes>) "SHA-384(abc) KAT"))
  (let ((okm (dds.dare:hkdf-sha384 <ikm> <salt> <info> <L>)))
    (%check :hkdf-sha384 (equalp okm <pinned OKM>) "HKDF-SHA384 KAT"))
  t)
```
(The implementer fills `<…>` from the cited standards — the vector bytes are sourced, not invented.)
- [ ] **Step 3: Run, verify FAIL** (`sha-384` undefined): `make test-sbcl 2>&1 | grep -E "dare-sha384|undefined|FAIL"`.
- [ ] **Step 4: `dds-dare.asd`** (sibling .asd):
```lisp
(defsystem "dds-dare"
  :description "DDS.DARE — CNSA-2.0 Data-At-Rest Encryption (AES-256-GCM + ML-KEM-1024 + SHA-384) over OpenSSL >= 3.5."
  :depends-on ("dds-lang" "dds-pal" "dds-core" "cffi")
  :pathname "src/dds-dare"
  :serial t
  :components ((:file "packages") (:file "openssl-ffi") (:file "primitives"))
  :in-order-to ((test-op (test-op "dds-tests"))))
```
- [ ] **Step 5: Implement** `packages.lisp` (the defpackage above), `openssl-ffi.lisp` (`cffi:define-foreign-library` for libcrypto + `use-foreign-library`; `OpenSSL_version_num` binding; `dare-available-p` + `dare-unavailable` condition; the EVP_MD + EVP_KDF bindings needed for SHA-384/HKDF — confirm signatures against the host headers), and `primitives.lisp` (`sha-384`, `hkdf-sha384` — output into foreign buffers, copy to a Lisp `(unsigned-byte 8)` result, free/zeroize the foreign buffer). All `defun*`-typed. A `%ascii` helper for test strings is fine in the dare package (internal).
- [ ] **Step 6: Wire + register** — `dds.asd` + `dds-tests.asd` (`:depends-on "dds-dare"` + `(:file "dare-test")`); export `#:run-dare-sha384-hkdf-kat-test`; add to the `run-all-tests` alist (echo-test.lisp).
- [ ] **Step 7: Run both impls + gate-types.** `make test-sbcl`/`make test-clasp 2>&1 | grep -E "dare-sha384|tests: [0-9]+ passed|FAIL"` (Clasp: if cffi→libcrypto fails to load on Clasp, document an NFR-PORT `(dds.pal:pal-impl-name)`-skip + note it; SBCL must pass). `make gate-types 2>&1 | tail -1` PASS.
- [ ] **Step 8: Commit** `feat(dare): WP-DURABILITY-DARE — dds-dare system + OpenSSL CFFI + dare-available-p + SHA-384/HKDF-SHA384 with NIST KATs (M6/P5, FIPS-180-4/SP800-56C)`.

---

## Task 2: AES-256-GCM AEAD primitive (with NIST KAT)

**Goal:** `aes-256-gcm-seal`/`open` over OpenSSL EVP, byte-exact vs a NIST GCM vector; fail-closed open.

**Files:** Modify `src/dds-dare/primitives.lisp`, `src/dds-dare/openssl-ffi.lisp` (EVP_CIPHER bindings), `src/dds-tests/dare-test.lisp` (+ test); packages/alist.

**Interfaces produced:**
- `(aes-256-gcm-seal key nonce aad plaintext)` → `(values ciphertext tag)` — `key` 32 octets, `nonce` 12 octets, `aad`/`plaintext` octet vectors; `ciphertext` same length as plaintext, `tag` 16 octets. (EVP_EncryptInit_ex(EVP_aes_256_gcm) → set IVLEN 12 → EncryptUpdate(aad) → EncryptUpdate(pt) → EncryptFinal → GET_TAG ctrl.)
- `(aes-256-gcm-open key nonce aad ciphertext tag)` → `(or (simple-array (unsigned-byte 8) (*)) null)` — the plaintext, or **NIL on auth failure** (DecryptFinal returns ≤0 when the tag/AAD don't verify). NEVER returns plaintext on failure.

- [ ] **Step 1: Failing KAT + tamper test** `run-dare-aes-gcm-kat-test` — pin a NIST CAVP AES-256-GCM vector (key/iv/aad/pt → ct/tag; cite the CAVP file/line): assert `aes-256-gcm-seal` produces the exact ct+tag; assert `aes-256-gcm-open` round-trips to pt; assert a 1-bit flip in tag / ct / aad → `open` returns NIL (fail-closed). Source the vector, don't invent.
- [ ] **Step 2: Run, verify FAIL.**
- [ ] **Step 3: Implement** the EVP_CIPHER bindings + the two wrappers (foreign buffers for key/nonce/ct/tag, zeroize the key buffer after use). Confirm the GCM tag-get/set ctrl constants (`EVP_CTRL_GCM_GET_TAG`=0x10, `EVP_CTRL_GCM_SET_TAG`=0x11, `EVP_CTRL_GCM_SET_IVLEN`=0x9) against the installed `<openssl/evp.h>` — pin, don't memorize.
- [ ] **Step 4: Run both impls + gate-types + mem.** `make … gate-types mem` — mem 0.0000.
- [ ] **Step 5: Commit** `feat(dare): WP-DURABILITY-DARE — AES-256-GCM AEAD (seal/open, fail-closed) + NIST CAVP KAT (M6/P5, FIPS-197/SP800-38D)`.

---

## Task 3: ML-KEM-1024 KEM primitive (with FIPS-203 KAT) — the riskiest, isolated

**Goal:** `ml-kem-1024-keygen`/`encapsulate`/`decapsulate` over the OpenSSL 3.5 EVP_PKEY KEM API, with a FIPS-203 known-answer check + the encaps/decaps round-trip (same shared secret).

**Files:** Modify `src/dds-dare/primitives.lisp`, `src/dds-dare/openssl-ffi.lisp` (EVP_PKEY KEM bindings), `dare-test.lisp`; packages/alist.

**Interfaces produced:**
- `(ml-kem-1024-keygen)` → `(values public-key private-key)` — opaque key handles OR serialized octets (decide: serialized octet vectors are simpler to store/test; use the raw public/private encodings via `EVP_PKEY_get_raw_public_key`/`..._private_key` or the `EVP_PKEY` DER export — confirm what OpenSSL 3.6 exposes for ML-KEM and pin it).
- `(ml-kem-1024-encapsulate public-key)` → `(values kem-ciphertext shared-secret)` — `kem-ciphertext` (the ML-KEM-1024 ciphertext octets), `shared-secret` 32 octets. (`EVP_PKEY_CTX_new_from_name(NULL,"ML-KEM-1024",NULL)` → `EVP_PKEY_encapsulate_init` → `EVP_PKEY_encapsulate`.)
- `(ml-kem-1024-decapsulate private-key kem-ciphertext)` → `shared-secret` (32 octets). (`EVP_PKEY_decapsulate_init` → `EVP_PKEY_decapsulate`.)

- [ ] **Step 1: Failing test** `run-dare-ml-kem-kat-test` — (a) round-trip: `keygen` → `encapsulate(pub)` → `decapsulate(priv, ct)` yields the SAME `shared-secret` (the core KEM correctness); (b) a FIPS-203 / NIST ACVP ML-KEM-1024 known-answer vector if a deterministic-seed path is available (ML-KEM keygen/encaps are randomized — for a strict KAT use the NIST ACVP "deterministic" (d,z)/(m) seed vectors via the OpenSSL test entropy hook IF exposed; if the installed OpenSSL doesn't expose a deterministic seed API, document that + rely on the round-trip + a decapsulate-known-(ct,priv)→ss vector from NIST ACVP, which IS deterministic). Cite the vector source; never invent. (c) wrong-key: decapsulate with a different private key → a DIFFERENT shared secret (ML-KEM implicit rejection still yields a deterministic-but-different ss).
- [ ] **Step 2: Run, verify FAIL.**
- [ ] **Step 3: Implement** the EVP_PKEY KEM bindings + wrappers. Confirm the OpenSSL 3.6 ML-KEM raw-key export + encapsulate/decapsulate signatures against the host `EVP_PKEY-ML-KEM` / `EVP_PKEY_encapsulate` man pages — this is the least-familiar API; pin it exactly. Foreign buffers for keys/ss; zeroize private-key + shared-secret buffers.
- [ ] **Step 4: Run both impls + gate-types.** (ML-KEM is the most likely Clasp-FFI risk — if Clasp can't load/run, the documented NFR-PORT skip; SBCL must pass.)
- [ ] **Step 5: Commit** `feat(dare): WP-DURABILITY-DARE — ML-KEM-1024 KEM (keygen/encapsulate/decapsulate) + FIPS-203 round-trip/KAT (M6/P5, FIPS-203)`.

---

## Task 4: KEM-DEM envelope (`seal-payload`/`open-payload`)

**Goal:** Compose the primitives into the per-store envelope: derive the DEK from an ML-KEM shared secret via HKDF-SHA384, seal/open a record's payload with AES-256-GCM, the `version∥nonce∥ct∥tag` blob format, AAD = metadata, fail-closed.

**Files:** Create `src/dds-dare/envelope.lisp`; Modify `dds-dare.asd` (component), `dare-test.lisp`; packages/alist.

**Interfaces produced:**
- `(derive-dek shared-secret)` → 32-octet DEK = `(hkdf-sha384 shared-secret #() (%ascii "dds-dare/dek/v1") 32)`.
- `(seal-payload dek nonce aad plaintext)` → `(simple-array (unsigned-byte 8) (*))` = `version(1)=#x01 ∥ nonce(12) ∥ ciphertext ∥ tag(16)`.
- `(open-payload dek sealed aad)` → `(or (simple-array (unsigned-byte 8) (*)) null)` — parse version+nonce+ct+tag (BOUNDS-CHECKED: reject if `(length sealed) < 1+12+16` or version≠1, return NIL), `aes-256-gcm-open` → plaintext or **NIL** (fail-closed). `dare-open-failure` condition optional; NIL is the in-band fail signal the decorator drops on.
- `(make-record-aad topic writer-guid sn kind)` → octet vector = `topic-utf8 ∥ writer-guid(16) ∥ sn-as-8-LE ∥ kind-byte` — the authenticated metadata binding.

- [ ] **Step 1: Failing test** `run-dare-envelope-test` — seal→open round-trip recovers plaintext; the sealed blob starts with `#x01` + has length `1+12+len(pt)+16`; a tamper in any region (version/nonce/ct/tag) → open NIL; a wrong DEK → open NIL; a changed AAD (different topic/sn) → open NIL (the metadata binding); a truncated/short sealed blob → open NIL, no error (bounds). Use `%check`.
- [ ] **Step 2: Run, verify FAIL.**
- [ ] **Step 3: Implement** `envelope.lisp` (the 4 fns; the nonce is supplied by the caller/decorator — the envelope doesn't own the counter). Bounds-check `open-payload` even at `(safety 0)`.
- [ ] **Step 4: Run both impls + gate-types + mem.** Expected PASS, mem 0.0000.
- [ ] **Step 5: Commit** `feat(dare): WP-DURABILITY-DARE — KEM-DEM envelope (HKDF-SHA384 DEK + AES-256-GCM seal/open, AAD-bound metadata, fail-closed, bounds-checked) (M6/P5)`.

---

## Task 5: Key-provider vtable + file-based provider

**Goal:** The pluggable key-provider (mirrors the durable-store vtable) + the default file provider that generates/loads the ML-KEM-1024 keypair (perms-enforced) and performs decapsulation internally (so the private key stays inside the provider).

**Files:** Create `src/dds-dare/key-provider.lisp`; Modify `dds-dare.asd`, `dare-test.lisp`; packages/alist.

**Interfaces produced:**
- `(key-provider …)` closure-vtable `defstruct*`: slots `recipient-public-key` (→ the ML-KEM public key octets), `decapsulate` (kem-ciphertext → shared-secret, internal to the provider), `open`, `close` — each `(or null function)`; public dispatch `defun*`s `key-provider-recipient-public-key`/`-decapsulate`/`-open`/`-close` (one slot-read + funcall).
- `(make-file-key-provider &key dir)` → `key-provider`. On `open`: if `dir/ml-kem-1024.key` (private) + `.pub` exist, load them (REFUSE if perms looser than 0600/0700 — check via `osicat`/`sb-posix` through `dds.pal` if available, else `uiop` stat; pick the portable path), else `ml-kem-1024-keygen` + write them with 0600/0700; never log the key. `decapsulate` calls `ml-kem-1024-decapsulate` with the loaded private key.

- [ ] **Step 1: Failing test** `run-dare-key-provider-test` — a file provider in a temp dir: first `open` generates the keypair (files exist); a second provider on the same dir `open`s + loads the SAME public key (so `decapsulate` of a `ciphertext` encapsulated to that public key yields the matching shared secret — round-trips through encapsulate/decapsulate); loosening the key file perms (chmod 0644) → the next `open` REFUSES (signals). Use `%check`; clean up the temp dir.
- [ ] **Step 2: Run, verify FAIL.**
- [ ] **Step 3: Implement** `key-provider.lisp`. For perms-check + file IO use the portable path (`uiop:file-exists-p`, `with-open-file` for octets, and a perms check — confirm what's available; a `dds.pal` perms helper if one exists, else `uiop`/`sb-posix` behind a runtime `pal-impl-name` guard, NOT a `#+`). Keypair files are octet encodings from Task 3's keygen.
- [ ] **Step 4: Run both impls + gate-types.** (File IO + perms may have a Clasp gap → documented NFR-PORT skip if so.)
- [ ] **Step 5: Commit** `feat(dare): WP-DURABILITY-DARE — pluggable key-provider vtable + file-based ML-KEM-1024 provider (perms-enforced, KMS hook) (M6/P5, ADR 0021 cap.7)`.

---

## Task 6: `make-encrypted-store` decorator + durability-service wiring + integration

**Goal:** The `durable-store` decorator that seals on `put` / opens on `get-range` over an inner store + a per-store DEK (from the key provider) + a per-store counter nonce; wire a DARE-wrapped store into the durability service; prove a DARE-wrapped service still relays correctly (transparency) and a tampered stored record is dropped.

**Files:** Create `src/dds-durability/store-encrypted.lisp`; Modify `src/dds-durability/packages.lisp`, `dds-durability.asd` (+ dep on `dds-dare` + the component), `src/dds-tests/dare-test.lisp` / `durability-test.lisp`; packages/alist.

**Interfaces produced:**
- `(make-encrypted-store inner-store key-provider)` → `durable-store`. On construction: `key-provider-open`; `ml-kem-1024-encapsulate(recipient-public-key)` → `(kem-ct, ss)`; `DEK = derive-dek(ss)`; hold the DEK (foreign, zeroized on close) + a per-store 96-bit nonce counter + the `kem-ct` (the key-blob, kept for the open path / 3b persistence). Vtable:
  - `put topic guid sn key-hash kind payload` → `nonce = next counter`; `aad = make-record-aad topic guid sn kind`; `sealed = seal-payload dek nonce aad payload`; delegate to `inner` `store-put` with `sealed` as the payload. Returns the inner result.
  - `get-range topic` → `inner` `store-get-range`; for each record, `open-payload dek record.payload (make-record-aad …)`; on NIL (auth fail) **DROP the record** (count + `*dare-error-hook*`), else return a `durable-record` copy with the opened plaintext payload.
  - `topics`/`purge`/`count-fn` → delegate to `inner` unchanged (metadata is cleartext in the inner store).
  - `open`/`close` → key-provider open/close + DEK zeroize on close.
- `*dare-error-hook*` — a bindable `defparameter` (condition/context/count), default a rate-limited WARN.

- [ ] **Step 1: Failing test** `run-dare-encrypted-store-test` — put N records (varying topics/guids/sn/kind) into `(make-encrypted-store (make-memory-store) (make-file-key-provider :dir tmp))`; assert (a) `get-range` round-trips each payload byte-exact; (b) the INNER store's raw payloads are SEALED (start with `#x01`, ≠ the plaintext — confirm via the inner store directly); (c) `topics`/`count` delegate correctly; (d) tamper a stored sealed record in the inner store → `get-range` DROPS it (count drops by 1, the hook fired) — no plaintext leak, no error. `%check`.
- [ ] **Step 2: Run, verify FAIL.**
- [ ] **Step 3: Implement** `store-encrypted.lisp` + export `make-encrypted-store` + `*dare-error-hook*`; add the `dds-dare` dep to `dds-durability.asd`.
- [ ] **Step 4: Integration — DARE-wrapped service transparency** (extend `durability-test.lisp`): a `durability-service` whose spec's store factory is `(lambda () (make-encrypted-store (make-memory-store) (make-file-key-provider :dir tmp)))`; an our-stack publisher writes N TRANSIENT_LOCAL samples then exits; a late-joiner receives all N byte-exact (the service sealed-into-store then opened-on-replay transparently). Assert N delivered. This proves DARE is transparent to the relay/replay path.
- [ ] **Step 5: Run both impls + the full sweep** — `make test-sbcl`/`test-clasp` (≥ prior + new), `make gate-hotpath gate-types mem`; mem 0.0000.
- [ ] **Step 6: Commit** `feat(durability): WP-DURABILITY-DARE — encrypted-store decorator (seal on put / open on get-range, per-store DEK + counter nonce, tamper-drop) + DARE-wrapped service transparency (M6/P5, ADR 0021 cap.7)`.

---

## Task 7: Open-path fuzz + capstone (ADR + docs + cross-DDS transparency + gates + final review)

**Goal:** Fuzz the untrusted open path; the cross-DDS transparency confirmation; ADR 0025; docs lockstep; SBOM/provenance for OpenSSL; full gate sweep; final whole-branch review.

**Files:** `src/dds-tests/pbt-test.lisp` (fuzz arm); `docs/adr/0025-durability-dare.md` (NEW); `docs/wiki/durability.md` + `README.md` + `docs/verification.csv` (MOD); `scripts/generate-sbom.py` + `docs/provenance.md` (MOD); `interop/durability-dare/` (transparency harness, if run live).

- [ ] **Step 1: Fuzz arm** — add an `open-payload` fuzz arm to `run-pbt-tests` (`pbt-test.lisp`): random/short/oversized/tampered sealed blobs + random AAD + a valid DEK → `open-payload` returns NIL or the (correct) plaintext, NEVER an error/OOB/crash, incl. a `(safety 0)` variant. Update the pbt summary line. `make fuzz` green.
- [ ] **Step 2: Cross-DDS transparency** — DARE adds no wire surface; confirm a DARE-wrapped durability service still delivers correctly to a LIVE foreign late-joiner (Connext 7.3.1 and/or Fast DDS 3.6.1) — reuse an `interop/durability-*` harness with the secure-store factory; the foreign reader receives correct samples (proving DARE is wire-transparent). Document in `interop/durability-dare/README.md` (honest: the substance is the KATs; this is a transparency check). If live peers are unavailable this run, the our-stack transparency integration test (Task 6 Step 4) is the proof + document the deferral.
- [ ] **Step 3: ADR 0025** — the as-built DARE architecture: the KEM-DEM envelope, ML-KEM-1024/AES-256-GCM/SHA-384 via OpenSSL ≥ 3.5 (no hand-rolling; the libsodium-not-used reasoning), the key-provider model, fail-closed, the foreign-buffer/zeroize secret handling, the per-session-DEK / 3b-key-epoch boundary, the threat-model scope (at-rest only), and the §10 MUST follow-on roadmap. Reference ADR 0021 cap.7 / 0023 / 0024 + the design spec.
- [ ] **Step 4: SBOM + provenance** — add OpenSSL (≥ 3.5, Apache-2.0) to `scripts/generate-sbom.py`'s pinned table (version 3.6.2 as installed, supplier/download/license); record OpenSSL in `docs/provenance.md` (vetted native crypto per FR-SEC-2). Regenerate SBOM (the hook does it on commit).
- [ ] **Step 5: Docs lockstep** — `docs/wiki/durability.md` (a DARE section + a worked secure-store-factory example + the OpenSSL ≥ 3.5 deployment requirement), README P5 row (the durability service now has an always-on CNSA-2.0 DARE layer over the store; disk = the MUST 3b follow-on), `docs/verification.csv` (a DARE row: the KATs, fail-closed, the MUST follow-ons).
- [ ] **Step 6: Full gate sweep both impls** — `make test-sbcl`/`test-clasp`, `make gate-hotpath gate-types mem fuzz wire` — all green; mem 0.0000; document any Clasp NFR-PORT skip (FFI).
- [ ] **Step 7: Final whole-branch review** (fresh reviewer, most capable model, over `main..wp-durability-dare`): the crypto composition (KEM-DEM correctness; HKDF labels; nonce discipline; AAD binding), no-hand-rolled-crypto, the KATs source-authentic + byte-exact, fail-closed everywhere, secret zeroization/foreign-buffers, OpenSSL<3.5 hard-error (no plaintext fallback), bounds-checked + fuzzed open path, NFR-MEM (mem 0.0000), no reader conditionals, docs/SBOM/provenance lockstep, no AI attribution, and that the §10 MUST roadmap is recorded. Fix findings (re-run the covering gate per fix).
- [ ] **Step 8: Commit** `docs(dare): WP-DURABILITY-DARE — ADR 0025 + wiki/README/verification + OpenSSL SBOM/provenance + open-path fuzz; Phase-3a capstone (M6/P5)`; then present the squash-merge for owner approval (HOLD PUSH).

---

## Self-review (author checklist — completed)

- **Spec coverage:** §4 modules → Tasks 1–6 (openssl-ffi+primitives T1–3, envelope T4, key-provider T5, decorator T6). §5 envelope → T4; key mgmt → T5; per-store DEK+counter nonce → T6. §6 threat model/foreign-buffers/fail-closed → T2/T4/T6 + the constraints. §7 error handling → fail-closed in T2/T4/T6, hard-error in T1. §8 testing → KATs T1–3, envelope T4, provider T5, decorator+transparency T6, fuzz+cross-DDS T7. §9 ordering → Tasks 1–7 (the 5 spec slices refined: primitives split into T1–3 so ML-KEM is isolated for review). §10 MUST follow-on roadmap → recorded in ADR 0025 (T7), not built here.
- **Placeholder scan:** the only `<…>` are the KAT vector bytes, DELIBERATELY left for the implementer to source from cited standards (fabricating crypto bytes would be a defect); every other step has concrete code/contract. No TBD/TODO.
- **Type/name consistency:** `sha-384`/`hkdf-sha384` (T1) → `derive-dek` (T4); `aes-256-gcm-seal/open` (T2) → `seal-payload/open-payload` (T4) → decorator (T6); `ml-kem-1024-keygen/encapsulate/decapsulate` (T3) → key-provider (T5) → decorator (T6); `make-encrypted-store`/`*dare-error-hook*` (T6); `key-provider` vtable (T5). The sealed-blob format `version∥nonce∥ct∥tag` consistent T4↔T6. `dare-available-p`/`dare-unavailable` (T1) gate everything.
- **Crypto-byte honesty:** every KAT step says "source from the cited standard, never invent" — the load-bearing conformance vectors are authoritative, not hallucinated.
