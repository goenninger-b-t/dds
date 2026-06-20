# ADR 0025 — DARE: CNSA-2.0 Data-At-Rest Encryption for the durability service

- **Status:** Accepted (M6/P5; WP-DURABILITY-DARE Phase 3a, 2026-06-19)
- **Relates to:** ADR 0021 (durability service scope — **capability 7 = always-on CNSA-2.0 DARE**);
  ADR 0023 (Phase-1 TRANSIENT service architecture); ADR 0024 (Phase-2 dedup);
  `docs/superpowers/specs/2026-06-19-durability-dare-design.md` (design spec, the architecture
  this ADR records as-built); FR-SEC-2 (vetted native crypto, no hand-rolling); NFR-SEC-POSTURE
  (bounds-checked untrusted parse, fail-closed); NFR-MEM (foreign/static secret buffers).
- **Standards:** NIST FIPS-197 (AES), SP 800-38D (GCM), FIPS-203 (ML-KEM), FIPS-180-4 (SHA-384),
  RFC 5869 / SP 800-56C Rev 2 (HKDF), CNSA 2.0 (ML-KEM-1024 + AES-256 + SHA-384).

## Context

Capability 7 of ADR 0021 is an **always-on, CNSA-2.0 Data-At-Rest Encryption** layer so the
durability service's persisted samples are never written in plaintext. CNSA 2.0 mandates
**AES-256-GCM** (AEAD), **ML-KEM-1024** (FIPS-203, post-quantum key establishment) and
**SHA-384**. Phase 3a builds and proves the encryption envelope + key management as a
`durable-store` **decorator** over the existing in-memory store (the proving ground — "at rest"
is not literal for RAM); the disk-backed store (slice 3b, a MUST follow-on — see §10 below) plugs
underneath the same decorator so disk holds only sealed bytes from its first byte.

The durability service is control-plane (a ~5 ms collect-poll loop) and **off the measured CDR hot
path**, so blocking OpenSSL FFI does not violate the static-arena hot-path rule — `make mem` stays
0.0000 bytes/sample.

## Decision — as-built architecture

### Module layout

A standalone **`dds-dare`** ASDF system (pure crypto, no DDS deps: `dds-pal` + `dds-core` + `cffi`)
plus a thin decorator in `dds-durability`:

| Unit | File | Responsibility |
|---|---|---|
| OpenSSL CFFI bindings | `src/dds-dare/openssl-ffi.lisp` | Handle-based bindings to OpenSSL ≥ 3.5 `libcrypto` (EVP AEAD, EVP_PKEY ML-KEM, EVP_MD/EVP_KDF). `dare-available-p` startup gate. |
| Primitives | `src/dds-dare/primitives.lisp` | `aes-256-gcm-seal/open`, `ml-kem-1024-keygen/encapsulate/decapsulate`, `sha-384`, `hkdf-sha384` + the secret-buffer helpers. Each carries a NIST/IETF KAT. |
| Envelope | `src/dds-dare/envelope.lisp` | `seal-payload`/`open-payload` + `derive-dek` + `make-record-aad` — the KEM-DEM envelope. Fail-closed. |
| Key provider | `src/dds-dare/key-provider.lisp` | A key-provider closure-vtable + default `make-file-key-provider :dir`. The KMS hook. |
| Store decorator | `src/dds-durability/store-encrypted.lisp` | `make-encrypted-store inner-store key-provider` → a `durable-store` sealing on `put`, opening on `get-range`, delegating `topics`/`purge`/`count`/`open`/`close` to `inner`. |

### The KEM-DEM envelope (NIST envelope encryption)

**Per-store keying.** On store open the key-provider yields the ML-KEM-1024 recipient public key
(CNSA 2.0 = ML-KEM-**1024**, FIPS-203 Level 5). The decorator **encapsulates** to it →
`(kem-ciphertext, shared-secret)`, then derives **`DEK = HKDF-SHA384(ikm=shared-secret, salt=∅,
info="dds-dare/dek/v1", L=32)`** (a 256-bit AES key). The `info` label is a pinned KDF domain
separator (changing it ⇒ a new envelope version byte). On open, the provider **decapsulates**
`(kem-ciphertext, private-key) → shared-secret → HKDF-SHA384 → the same DEK`. The DEK is
re-derivable iff you hold the ML-KEM private key (the root of trust); decapsulation runs **inside
the provider**, so the raw private key need never leave it (an HSM/KMS provider keeps it
off-process).

**Per-record sealing.** AES-256-GCM under the DEK, with a **unique 96-bit counter nonce** per
record (a counter, not random — eliminates the GCM birthday-bound reuse risk within a DEK's life)
and **`AAD = UTF-8(topic) ∥ writer-guid(16) ∥ sn(8 LE) ∥ kind(1)`** (authenticated, not encrypted
— the inner store indexes/replays by these and any relabel/move is detected). The sealed-payload
bytes handed to the inner store are **`version(1)=0x01 ∥ nonce(12) ∥ ciphertext ∥ tag(16)`**
(minimum valid length 29). Only the CDR payload is encrypted; the record metadata stays
cleartext-authenticated (metadata confidentiality is a MUST follow-on, §10).

### Crypto library — OpenSSL ≥ 3.5 via handle-based CFFI (no hand-rolling, FR-SEC-2)

All three CNSA-2.0 algorithms come from **one vetted library, OpenSSL ≥ 3.5** (ML-KEM landed in the
3.5 LTS): AES-256-GCM via `EVP_CIPHER`, ML-KEM-1024 via the `EVP_PKEY` KEM API
(`EVP_PKEY_encapsulate`/`decapsulate`), SHA-384 via `EVP_Q_digest`, HKDF via the `EVP_KDF` "HKDF"
provider. We **wrap and compose** (KEM-DEM, the HKDF label, nonce discipline, AAD) per NIST
guidance; we do **not** implement any primitive. Every wrapped signature is pinned against the
installed OpenSSL 3.6.2 headers and cited in-source.

**libsodium not used.** The owner directive "use libsodium if appropriate" resolves to
NOT-appropriate: libsodium lacks ML-KEM and SHA-384; OpenSSL ≥ 3.5 covers all three, so adding
libsodium for the AEAD alone would be redundant FFI/SBOM surface.

**Impl-agnostic, no reader conditionals.** `cffi` is impl-agnostic. The bindings dispatch every
OpenSSL call through `cffi:foreign-symbol-pointer` on an **explicitly-resolved `*libcrypto*`
handle** (`%ossl-sym`), resolved at load time from `$DDS_DARE_LIBCRYPTO` then known homebrew/Linux
paths. This fixes a LibreSSL global-namespace collision that broke Clasp on macOS (Clasp loads
`/usr/lib/libcrypto.*` = LibreSSL at startup; name-based `foreign-funcall` would then bind the
wrong, ML-KEM-less symbol). The handle path is the same library on the same host for SBCL and
Clasp (the operating contract's impl-agnostic-CFFI rule) — no `#+sbcl`/`#+clasp` anywhere.

### Key-provider vtable + the default file provider

The key-provider is a closure-vtable (mirrors the `durable-store` vtable): slots
`recipient-public-key`, `decapsulate`, `open`, `close`. The default `make-file-key-provider :dir`
holds an ML-KEM-1024 keypair in `<dir>/ml-kem-1024.{pub,key}`, generated on first open and loaded
thereafter. Permissions are **enforced (0600 file / 0700 dir, set before the key bytes are written
— a TOCTOU mitigation) and checked at open via `LC_ALL=C ls -la`**; the check **fails CLOSED** — a
group/other-readable key, or perms that cannot be positively verified (ls absent/unparseable),
refuses to load (ADR's review security finding, commit `8d7dea5`). `key-provider-decapsulate`
performs `ml-kem-1024-decapsulate` internally; the raw private key is never returned to the caller
(the KMS hook point). The vtable IS the pluggable KMS hook — an HSM/cloud-KMS backend drops in by
supplying different slot closures.

### Secret handling — all secrets foreign/static (owner "Conform: all secrets")

The brief's original design held only the working buffers foreign and copied derived secrets onto
the GC heap. **After the brief, the owner directed "Conform: all secrets" — so ALL DARE secret
material now lives in foreign-backed `static-vectors`, never a GC-heap array** (commits `27d12b7`,
`200b856`). This is the as-built:

- **Three secrets are foreign/static and zeroized+freed at end-of-life:** the ML-KEM-1024
  **private key** (held inside the file key-provider), the **shared secret** (transient, freed once
  the DEK is derived), and the **DEK** (held for the store lifetime). The DEK is **born in a
  static-vector** (`%make-secret-octets`) — `%hkdf-sha384-into` copies the EVP output directly into
  the secret buffer, so the DEK **never transits the heap**.
- **Helpers (`dds.dare`):** `%make-secret-octets` (allocate a zero-init static-vector),
  `%foreign->secret` (copy a foreign buffer into a static-vector), and the exported
  **`free-secret-octets`** (`(fill v 0)` then `static-vectors:free-static-vector` — idempotent on
  NIL; returns NIL so callers write `(setf slot (free-secret-octets slot))`). The HKDF path is DRY:
  one `%hkdf-sha384-into` EVP body, the `secret` flag selecting a static (DEK) vs heap (the public
  `hkdf-sha384` primitive) copy-out.
- **Rationale (design spec §6):** a GC-moved heap array cannot be reliably wiped — the collector may
  have left stale copies. Pinned foreign storage can. This is the same principle as the static-arena
  hot-path rule, applied to secret key material.
- **Throw-safe frees.** Every shared-secret free and every DEK re-derivation is `unwind-protect`-
  guarded (commit `200b856`), so a throw mid-derivation (e.g. an OpenSSL error inside `derive-dek`)
  still zeroizes+frees the transient secret rather than leaking it.
- **Not secret (stay on the heap):** the public key, KEM ciphertexts, GCM tags, nonces, AAD,
  digests, and the **opened plaintext payloads**. In-RAM plaintext confidentiality is the §10.4
  follow-on (and is not fully achievable in pure Lisp — see there).

### Fail-closed everywhere (binding, NFR-SEC-POSTURE)

- `open-payload` returns **NIL — never plaintext, never partial** — on any failure: a blob shorter
  than 29 bytes, a wrong version byte, or any AES-GCM authentication failure (wrong DEK, tampered
  ciphertext/tag/nonce, or altered AAD). The bounds checks are **explicit manual checks**, so they
  hold even at `(safety 0)` (the operating contract §4).
- The decorator's `get-range` **drops** a record that fails to open (increments a counter, fires the
  bindable `*dare-error-hook*`), and never delivers unauthenticated data.
- A provider that cannot decapsulate ⇒ the store **fails to open**.
- **OpenSSL < 3.5 / ML-KEM absent ⇒ a hard startup error (`dare-unavailable`), never a silent
  plaintext fallback** (the arena-exhaustion principle: no silent downgrade).

### Per-session DEK and the 3a/3b key-epoch boundary

Slice 3a keys **one fresh DEK per store-open** (a new encapsulation each session), counter nonce
from 0 — GCM-safe by construction within a session, and the in-memory store starts empty each run,
so no cross-restart nonce reuse is possible. The `version` byte reserves forward-compat for **3b**
(disk), where persisted records outlive an open: 3b adds a **key-epoch** (an epoch→kem-ciphertext
map, a per-epoch DEK + nonce space) so cross-restart nonce reuse is structurally impossible. NOT
built in 3a.

## Threat model & scope

DARE gives **confidentiality + integrity + authenticity of stored payloads** against an adversary
with read/write access to the store's bytes (3b: disk); tampering is detected (the GCM tag + AAD)
and fails closed. It **does NOT** protect, and these are recorded MUST follow-ons (§10):

- **In-memory plaintext** — the service holds opened payloads in RAM to relay (§10.4; with an honest
  feasibility caveat).
- **Data in transit** — the relay emits standard plaintext DDS samples on the wire; wire
  confidentiality is DDS-Security (the whole P6 milestone, §10.5).
- **Metadata / traffic analysis** — topic/GUID/SN/kind are cleartext-authenticated; metadata
  confidentiality is §10.3.

The cryptographic set is **exactly the CNSA-2.0 suite** (AES-256-GCM, ML-KEM-1024, SHA-384,
HKDF-SHA384) with **no hand-rolled crypto** (FR-SEC-2).

## Conformance

- **NIST/IETF Known-Answer-Tests are the conformance oracle** (the crypto analogue of the byte-exact
  CDR corpus), from **published** sources — never self-generated: AES-256-GCM vs **NIST SP 800-38D**
  Test Case 16; SHA-384 vs **FIPS-180-4**; HKDF-SHA384 vs **RFC 5869 / SP 800-56C**; ML-KEM-1024 vs
  the **C2SP/CCTV ML-KEM-1024** intermediate vectors. These prove the OpenSSL binding yields the
  correct CNSA-2.0 algorithms byte-exact.
- **Envelope:** seal→open round-trip; AAD round-trips; tamper (a flipped byte in
  ciphertext/tag/nonce/AAD) fails closed; a different ML-KEM keypair (different DEK) fails closed.
- **Store decorator:** records seal into the inner store + unseal on `get-range` byte-exact; a
  tampered stored record is dropped + the hook fires; topics/purge/count delegate.
- **Open-path fuzz (NFR-SEC-POSTURE):** `fuzz-dare-open-payload` (`src/dds-tests/pbt-test.lisp`,
  3000 iters) feeds `open-payload` adversarial sealed blobs — short / oversized / pure-random /
  all-zero / tampered / wrong-AAD / strictly-truncated-valid + one genuinely-sealed blob under its
  true AAD — and asserts the result is **NIL or the correct plaintext, never an error/OOB/crash**, a
  `(safety 0)` arm reaching the same verdict. (Skips cleanly when OpenSSL ≥ 3.5 is unavailable; the
  crypto correctness is then carried by the KATs.)
- **Cross-DDS DoD — transparency (light by nature; design spec §8).** DARE adds **zero
  wire-observable surface** (the relay emits standard DDS samples; at-rest only). The in-process
  authoritative proof is `dds.tests:run-dare-service-transparency-test` (a DARE-wrapped service
  delivers byte-correct retained samples to a same-stack late-joiner; passes on **SBCL and Clasp**,
  Clasp first). The **live foreign-peer confirmation** (`interop/durability-dare/`, 2026-06-19, both
  peers): a DARE-wrapped durability service delivered byte-correct samples to LIVE late-joiners —
  **Connext 7.3.1: 352** received (service retained 403), **Fast DDS 3.6.1: 152** received (= the
  152 collected) — and both captures match the plain-store transient wire shape **byte-for-byte**
  (replay EntityId `0x00000102`, `firstAvailableSeqNumber=1` held on every HEARTBEAT, `CDR_LE
  (0x0001)` on all DATA, NACK→retransmit repair). The encrypted store is transparent on the wire.

## Consequences

- **NFR-MEM:** `make mem` stays 0.0000 bytes/sample — DARE is control-plane, off the measured CDR
  hot path. No bench warranted (no hot-path change).
- **Gates:** `make test` (SBCL 283 + Clasp 283, **both deterministic**, 10/10 each), `gate-hotpath`,
  `gate-types`, `mem` (0.0000), `fuzz`, `wire` — all green on both impls.
- **Deployment constraint:** **OpenSSL ≥ 3.5 is a hard runtime requirement** (ML-KEM landed there);
  runtime-checked at startup, hard-error if absent. SBOM-pinned (3.6.2 as installed), recorded in
  `docs/provenance.md`.
- **Clasp determinism via the PAL (clasp#1793 avoided).** DARE secret buffers are allocated and
  released through the impl-agnostic PAL (`dds.pal:alloc-static` / `dds.pal:free-static`), never
  `static-vectors:free-static-vector` directly. On SBCL `free-static` truly frees; on Clasp it
  recycles the buffer into a lock-guarded, zero-on-reuse pool and **never** calls the
  `obj_deallocate_unmanaged_instance` backend that `GC_FREE`s an interior pointer and corrupts the
  Boehm heap (clasp#1793, the documented Clasp gap — the same workaround the engine's hot-path static
  buffers already use). Result: DARE validates **deterministically on both SBCL and Clasp (10/10 runs
  each, zero SIGSEGV)**; and since `free-static-vector` is no longer on the secret path, the cosmetic
  `gc_interface.cc:128` debug `printf` is gone too. Secrets stay zeroized — `free-secret-octets`
  `(fill v 0)` before release, and the pool re-zeros on reuse.

## §10 — MUST follow-on roadmap (owner directive 2026-06-19; NOT optional, sequenced asap)

These were formerly "out of scope"; per owner directive they are MUST, each its own vertical slice
(brainstorm→spec→plan→subagent-driven). Recorded here, **not built in 3a**:

1. **(3b) Disk-backed PERSISTENT store + cross-restart key-epoch/nonce discipline** — a file-backed
   `durable-store` surviving process/system restart, ALWAYS DARE-wrapped (no plaintext-on-disk
   path); the key-epoch envelope extension (epoch→kem-ciphertext, per-epoch nonce space) the §5
   `version` byte reserves; PERSISTENT per-writer lifetime semantics. **The immediate next slice.**
2. **(3b, folded) Phase-2 carry-forwards** — live TRANSIENT-tier coexistence proof (RTI Persistence
   Service at the TRANSIENT tier — the TRANSIENT_LOCAL dual-relay proof was not exercisable, ADR
   0024), dynamic-topic-add after service start, and pruning the collect-loop `seen-data`/`seen-lc`
   sets (the unbounded-growth NFR-MEM item the Phase-2 review flagged). Small.
3. **(3c) Metadata confidentiality** — seal the record metadata (topic/GUID/SN/kind), not just the
   payload; requires an encrypted/independent index so the store can still locate records (the
   current AAD-cleartext model forfeits this). A DARE extension.
4. **In-memory plaintext confidentiality** — minimize plaintext lifetime + `mlock`/zeroize working
   buffers (best-effort). **Honest caveat:** full RAM-plaintext confidentiality is not achievable in
   pure Lisp without OS/hardware support (confidential computing / enclaves / page-locking); this
   MUST is bounded to the achievable near-term piece (the key material is **already**
   foreign-buffered + zeroized in 3a). Confidence the full goal is reachable as-is: **low**.
5. **(M7/P6) DDS-Security — in-transit / wire confidentiality + the five DDS-Security plugins** — the
   entire P6 milestone (the relay currently emits standard plaintext DDS samples on the wire).
   Honestly a whole milestone, not a small slice; sequence it as its own milestone after the
   at-rest + persistence slices land.

## References

- ADR 0021 — Durability service scope + capability 7 (always-on CNSA-2.0 DARE)
- ADR 0023 — TRANSIENT durability service Phase-1 architecture
- ADR 0024 — Phase-2 dedup (PID_ORIGINAL_WRITER_INFO + bounded watermark)
- `docs/superpowers/specs/2026-06-19-durability-dare-design.md` — the DARE design spec
- `src/dds-dare/` — `openssl-ffi.lisp` / `primitives.lisp` / `envelope.lisp` / `key-provider.lisp`
- `src/dds-durability/store-encrypted.lisp` — the encrypted-store decorator
- `src/dds-tests/durability-test.lisp` — `run-dare-*` unit/integration tests (incl.
  `run-dare-service-transparency-test`)
- `src/dds-tests/pbt-test.lisp` — `fuzz-dare-open-payload` (open-path fuzz arm)
- `interop/durability-dare/` — live cross-DDS transparency harness + captures (Connext 352 / Fast DDS 152)
- `docs/wiki/durability.md` §8 — DARE user documentation + the secure-store-factory example
- `docs/provenance.md` — OpenSSL provenance (vetted native crypto, FR-SEC-2)
