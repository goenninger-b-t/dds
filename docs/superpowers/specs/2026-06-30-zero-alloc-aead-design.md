# Zero-Alloc AEAD — Design (M7/P6 security hardening, Slice 1: serialized-payload / data_protection tier)

> Status: design, owner-approved 2026-06-30. Operating-contract workflow: brainstorm (this) → plan → subagent-driven implementation → final review → finish-branch.

**WP:** `WP-DDS-SECURITY-ZEROALLOC-AEAD` (slice 1) · **Milestone:** M7 / P6 (security hardening, after the P6 Fast-DDS exit gate) · **ADR:** 0038 (written at the capstone) · **Prior art:** ADR 0031 (Slice-1 crypto-payload serialized-payload protection), ADR 0034 (auth key material; `alloc-static` precedent), ADR 0036 (Carry-3: zero-alloc into-buffer AEAD).

---

## 1. Problem

Per ADR-0036 Carry-3, the secured RTPS data path is **not** zero-alloc. With security enabled, the AEAD encode/decode allocate GC-heap memory **per sample** in steady state:

- the OpenSSL FFI `aes-256-gcm-seal`/`-open` `make-array` their ciphertext / tag / plaintext outputs on the GC heap (`src/dds-dare/primitives.lisp`);
- `derive-session-key` (→ `hmac-sha256`) runs **per sample** inside `%seal-with-km`/`%open-with-km`, allocating the session key + label buffers each call, even though the session key is effectively constant per KeyMaterial;
- the codec allocates per-sample intermediates (`make-array` outputs, `subseq`/`copy-seq` of header fields and the `→octets` return).

The `make mem` gate asserts `0.0000` B/sample but runs a **security-OFF** CDR workload only; it does not exercise the security path at all. This breaches NFR-MEM / the static-arena rule (steady state allocates zero bytes/sample) whenever security is on.

The dominant cost is on the whole-RTPS (`rtps_protection`) path (~2.2 KB/datagram). The **foundation** that fixes it — into-buffer AEAD + a session-key cache — is shared by all three AEAD tiers (data_protection payload, metadata_protection submessage, rtps_protection whole-message). This slice proves that foundation on the simplest tier.

## 2. Goal (slice 1)

Make the **data_protection (serialized-payload) AEAD tier** allocate **zero GC-heap bytes/sample** in steady state, proven by a new security-ON `make mem` arm (`bytes-consed`/iter < 1.0 on SBCL; smoke on Clasp). Establish the shared foundation (into-buffer FFI entries + session-key cache + into-buffer codec core) that slice 2 reuses for the submessage and whole-RTPS tiers. The change is allocation/representation only — **the wire output bytes are invariant**: the byte-exact corpus and the NIST KAT stay green.

## 3. Scope

**IN (slice 1):**
1. Additive into-buffer FFI entries in `dds-dare`: `aes-256-gcm-seal-into`, `aes-256-gcm-open-into`.
2. A session-key cache on the KeyMaterial (derive-once for a fixed `session_id`; re-derive on change).
3. An into-buffer serialized-payload codec core (`encode-serialized-payload-into` / `decode-serialized-payload-into`), with the existing allocating entries refactored to thin wrappers over the core.
4. Wiring the live data_protection publish + receive path to the into-buffer core over a reused buffer (the end-to-end of the slice).
5. A security-ON `make mem` arm proving the data_protection round-trip at 0.0000; a NIST-KAT arm for the `-into` FFI.

**OUT (later slices, not this spec):**
- Slice 2: extend the foundation to the submessage (`metadata_protection`) and whole-RTPS (`rtps_protection`, the ~2.2 KB/datagram carry) tiers + the dataplane borrow (`%encode-secured-region` scratch and `%maybe-wrap-user-submessages` → `pool-acquire`; the `→octets`/`subseq` sites → write-into-borrowed-region); an SRTPS mem arm.
- GC-heap key-material → foreign/static + zeroize-on-teardown (the ADR-0034 deferral).
- ZC × `rtps_protection` leaving the SHMEM payload cleartext.

## 4. Constraints (operating contract)

- **Hot-path purity:** no CLOS dispatch and no per-sample object instantiation on the codec path; `defstruct` + monomorphic functions.
- **Static memory:** hot-path buffers from the startup static arena (`dds.pal:alloc-static` / `dds.core.arena` pool); anything addressed by a raw SAP is foreign/static, never a GC-heap array.
- **Byte-identical wire:** this is an allocation change, not a wire change. The byte-exact corpus (`security-test.lisp`: secured-payload + padded-SecuredPayload goldens; and the crypto-header/submessage/rtps goldens that share the core) and the NIST AES-GCM KAT (`dare-test.lisp`) stay green **unchanged**. No corpus regeneration.
- **Bounds-checked + fail-closed receive:** `decode`/`open-into` validate lengths before reading even at `(safety 0)`; `open-into` returns NIL on auth-failure and leaves no readable plaintext in the output buffer; the T10 empty-AAD `find_key` integrity gate is preserved.
- **Both impls (Clasp first):** the into-buffer FFI goes through `dds.pal:static-pointer`; no reader conditionals outside `dds-pal/`.
- **Clean-room / no wire constants from memory:** unchanged from prior crypto work; no RTI source.
- **Docs in lockstep:** docstrings on every new exported symbol; ADR 0038 at the capstone; wiki/README touched if API scope shifts. No AI-assistant attribution; cite "the operating contract §N".

## 5. Architecture

Four units, each independently testable.

### 5.1 Into-buffer FFI (`src/dds-dare/`, additive)

- `aes-256-gcm-seal-into (ct-out tag-out key nonce aad plaintext) → (values t)` — the EVP encrypt writes the ciphertext (length = `|plaintext|`, known a priori; GCM is a stream cipher) into `ct-out` and the 16-byte tag into `tag-out`, **through the caller's static-vector SAPs** (`dds.pal:static-pointer`), with the output vectors GC-pinned for the call. No `make-array`.
- `aes-256-gcm-open-into (pt-out key nonce aad ct tag) → (or t null)` — writes plaintext into `pt-out` and returns T on auth-success; on failure returns NIL and leaves no readable plaintext in `pt-out` (zeroed / not written). Fail-closed.
- The existing allocating `aes-256-gcm-seal`/`aes-256-gcm-open` are **unchanged** (the NIST KAT, auth, key-exchange, and data-at-rest callers are untouched).
- **YAGNI:** no `hmac-sha256-into` — the session-key cache (5.2) removes the per-sample KDF, so the HMAC never runs in steady state.

### 5.2 Session-key cache (`src/dds-security/key-material.lisp` + `transform.lisp`)

The session key is `derive-session-key(master_sender_key, master_salt, session_id)`. `master_sender_key` and `master_salt` are fixed per KeyMaterial; for the data path `session_id` is the constant `+fixed-session-id+`, so the session key is constant per KeyMaterial. Add a cache slot to the KeyMaterial struct holding the last `(session-id . session-key)`. `%seal-with-km`/`%open-with-km` (and their into variants) consult it: reuse on a `session_id` match, else derive once and recache. This removes the per-sample KDF for the steady state and still correctly handles the rare per-role `session_id` (e.g. PVMS winner/loser) by recompute-on-change — never per sample. The cached key is GC-heap for now (consistent with the ADR-0034 key-material deferral; derived once, so it does not move `bytes-consed` in steady state); the later key-material-hardening slice moves all key material to foreign + zeroize.

### 5.3 Codec core + allocating wrappers (`src/dds-security/transform.lisp`)

- `encode-serialized-payload-into (out-buf km plaintext) → length` — the zero-alloc core: cached session key + `aes-256-gcm-seal-into` writing ciphertext/tag directly into `out-buf`'s region at the computed offsets; the CryptoHeader fields (kind/key_id/session_id/iv_suffix) written via the existing cursor serializers (already alloc-free). The 12-byte GCM nonce is the contiguous `session_id(4)‖iv_suffix(8)` sub-region of the CryptoHeader already written into `out-buf` (the 20-byte header is `kind‖key_id‖session_id‖iv_suffix`, so bytes [8,20) are exactly the nonce) — `seal-into` is handed that region's SAP+offset, so no separate nonce buffer is allocated (this eliminates the per-sample `make-array` of the nonce and any per-KM nonce-buffer race). Returns the written length. No `subseq`/`copy-seq`/`make-array`.
- `decode-serialized-payload-into (pt-out km secured) → (or length null)` — parse the CryptoHeader in place; the nonce, ciphertext, and tag are passed to `open-into` as SAP+offset slices of the `secured` input buffer (no `make-array` of any field), with the `find_key` integrity gate (kind+key_id equal the KM) applied before the open; `aes-256-gcm-open-into` writes into `pt-out`. Returns the plaintext length, or NIL fail-closed.
- The existing `encode-serialized-payload` / `decode-serialized-payload` become **thin allocating wrappers** over the core (allocate a temp output, call the core, return the result). Consequence: the byte-exact corpus tests call the wrappers → exercise the core → **byte-identity is proven automatically**, and the wire is invariant by construction.

### 5.4 Data-path wiring + the mem arm

- The live data_protection encode (publish path) and decode (receive path) call the into-buffer core with a **caller-provided reused output buffer** + the cached session key — the end-to-end of the slice. The core is buffer-agnostic (it writes into whatever `out-buf` it is handed); the plan picks the precise reused buffer when wiring the live path (the existing per-send serialization buffer or an arena `pool-acquire` buffer). Security-OFF and non-data_protection paths are byte-identical (the core is only reached when data_protection is engaged).
- `make mem` gains a security-ON arm (`run-mem-test-secure`, wired into the `mem` target): build a test KeyMaterial, then a steady-state loop of `encode-serialized-payload-into` + `decode-serialized-payload-into` over reused input/output buffers, asserting `(/ (- (bytes-consed) before) iters) < 1.0` on SBCL (Clasp smoke). This closes the gap that `make mem` never covered the security path.

## 6. Data flow

Encode (steady state, data_protection on): publish → serialize sample into the (reused) payload buffer → `encode-serialized-payload-into(out-buf, km, payload)`: cache hit returns the session key (no KDF) → `aes-256-gcm-seal-into` writes ct+tag into `out-buf` through SAPs (no FFI make-array) → header written via cursor → return length. Zero GC-heap allocation.

Decode: receive → `decode-serialized-payload-into(pt-out, km, secured)`: parse header in place → `find_key` gate → cache hit session key → `aes-256-gcm-open-into` into `pt-out` → return length or NIL. Zero GC-heap allocation; fail-closed on auth failure / malformed input.

## 7. Error handling / fail-closed

- `aes-256-gcm-open-into` / `decode-serialized-payload-into` return NIL on auth failure or malformed input and never expose partial/plaintext on failure.
- All length/offset checks run before reading wire data, even at `(safety 0)`; `out-buf` capacity is checked ≥ required (header + ciphertext + tag) before writing.
- The empty-AAD `find_key` integrity gate (kind + key_id must equal the KM, from T10) is preserved in the into-buffer decode.
- GC-pinning: the FFI pins the caller's static output vectors for the EVP call (no movement under SBCL/Clasp GC during the foreign write).

## 8. Verification & DoD

- **Headline:** `make mem` security-ON arm reports `0.0000` B/sample for the data_protection encode/decode round-trip (SBCL); Clasp smoke passes.
- **Wire invariant:** every byte-exact security corpus green **unchanged** (no regeneration); the NIST AES-GCM KAT green; a new KAT arm asserts `aes-256-gcm-seal-into`/`-open-into` produce byte-identical output to the allocating entries on NIST TC16.
- **our-to-our green both impls (Clasp first):** `make test-clasp` + `make test-sbcl` + `make corpus` + `make fuzz` + `make gate-hotpath` + `make gate-types` + `make mem`. The fuzz decoder arms still drive the decode path.
- **Hot-path purity:** `gate-hotpath` green (no CLOS/per-sample alloc introduced).
- **Docs:** ADR 0038 (foundation + flips ADR-0036 Carry-3 status for the payload tier); docstrings on the new exported FFI + codec symbols; wiki/README if scope shifts.

## 9. Risks

- **The FFI is the load-bearing change.** Writing EVP output through a caller SAP (vs `make-array`+copy) must reproduce the NIST KAT byte-for-byte and pin the output vector for the call. Mitigation: the new KAT arm asserts `-into == allocating`; both go through one `dds.pal:static-pointer` path (Clasp-first).
- **Session-id assumption.** The cache assumes `session_id` is near-constant on the data path. If a tier varies it per sample (it does not today — PVMS varies per role, not per sample), the cache degrades to per-sample re-derive (correct, just not zero-alloc); flagged for slice 2 where the submessage/PVMS tiers are wired.
- **Publish-path integration.** Wiring the live data path to the reused buffer touches the hot publish/receive path; the byte-exact corpus + the our-to-our e2es guard against a regression, and the change is gated to the data_protection-engaged path (security-OFF byte-identical).

## 10. ADR

ADR 0038 (`docs/adr/0038-zero-alloc-aead.md`) at the capstone: the into-buffer FFI + session-key cache + codec-core foundation, the security-ON mem arm, the byte-invariance proof, and the flip of ADR-0036 Carry-3 for the payload tier (submessage + whole-RTPS carried to slice 2).
