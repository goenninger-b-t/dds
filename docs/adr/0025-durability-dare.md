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
- **OpenSSL < 3.5 / ML-KEM absent ⇒ `dare-available-p` returns `(values NIL reason)` (ADR 0064: a
  fail-closed status value, no longer the `dare-unavailable` signal), and the store REFUSES to open —
  never a silent plaintext fallback** (the arena-exhaustion principle: no silent downgrade).

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
   **§10.2 seen-set bound RESOLVED** (WP-DURABILITY-HARDENING-BATCH): the distinct-origin count is
   now capped at `dds.durability:*max-collect-origins*` with fail-closed refuse-new-origins — see the
   ADR 0024 non-goals entry for the full dedup-safety argument (no watermark is ever evicted, so no
   double-delivery). Follow-on: safe capacity-reclaim via durable per-origin high-water re-seed.
3. **(3c) Metadata confidentiality** — seal the record metadata (topic/GUID/SN/kind), not just the
   payload; requires an encrypted/independent index so the store can still locate records (the
   current AAD-cleartext model forfeits this). A DARE extension.

   **§10.3 (3c) RESOLVED — AS-BUILT (WP-DURABILITY-METADATA-CONF-3c).** The v2/epoch encrypted-store
   decorator (`make-encrypted-store` with `:epoch-dir`; both the file AND SQLite backends) now seals
   the record metadata, not just the payload. No cleartext topic name, writer-GUID, sequence number,
   or key-hash touches disk — in log filenames, `topics.map`, frame headers, SQLite `topic`/
   `writer_guid`/`sn`/`key_hash` columns, or the raw file/DB bytes. Mechanism:
   - **k_meta** — a cross-restart-stable HMAC/AES key derived (`dds.dare:derive-meta-key`, HKDF-SHA384
     with a distinct `"dds-dare/meta/v1"` info label) as a SIBLING of the ADR-0045 log-MAC key, from
     the SAME deterministic ML-KEM decapsulation of the persisted `logmac.anchor` ciphertext. A fresh
     process re-derives k_meta identically (FIPS-203 decapsulation is deterministic) and re-locates +
     decrypts the sealed metadata. **Zero new key-management surface** (no new key file, no new anchor).
   - **topic-hash** = `HMAC-SHA-256(k_meta, #x01 ∥ UTF-8(topic))`, hex-encoded, used as the inner
     store's topic identifier (file log basename / `topics.map` key / SQLite `topic` column). This is
     the "encrypted/independent index": `store-get-range(topic)` re-hashes the query topic and still
     locates records by topic equality, while the topic NAME never touches disk.
   - **Sealed metadata frame** — the real `guid(16) ∥ sn(8 LE) ∥ kind(1) ∥ kh-present(1) ∥ [key-hash(16)]
     ∥ payload(N)` is sealed together under the per-epoch DEK (`%seal-meta-frame`), with the AEAD AAD =
     the topic-hash bytes. guid/sn/kind/key-hash are thus GCM-authenticated inside the ciphertext, which
     **subsumes** the prior `%record-aad-v2` cleartext-key-hash AAD binding.
   - **Surrogates** — the inner store receives only deterministic surrogates: the topic-hash, a 16-byte
     guid-surrogate `HMAC(k_meta, #x02 ∥ guid ∥ sn)[0..16)` (unique per (guid,sn) ⇒ preserves the
     idempotent (guid,sn) dedup), `sn'=0`, NIL key-hash, `kind=:data`. It never sees plaintext metadata.
   - **Decrypt-then-sort compaction** — the inner store is opened KEEP_ALL (it cannot order the hashed
     surrogate, and has no real kind/key-hash); `store-get-range` decrypts every blob, recovers the real
     metadata, sorts by the REAL `(writer-guid, sn)`, then applies the effective KEEP_LAST / settled-drop
     policy (supplied to `store-open` — the inner store's factory-config `:history-kind`/`:history-depth`
     is NOT consulted on the encrypted tier, since the inner runs KEEP_ALL; pass the policy to
     `store-open`, as `service-start` does). Per-topic `store-count topic` is the logical
     (post-compaction) count; the total `store-count nil` is the inner PHYSICAL count (includes
     not-yet-physically-reclaimed superseded blobs), so total ≠ Σ per-topic on a KEEP_LAST store — a
     diagnostic-only divergence. (Sliver 3a reclaims those superseded blobs online for the **SQLite**
     backend, so the SQLite total now CONVERGES to the logical Σ; the divergence persists for the file
     tier until 3b and for cross-restart ≤D leftovers until 3c — see the Physical space residual below.)
     The v3 log-MAC chain (ADR 0045) covers the sealed-metadata frame
     unchanged (its per-topic seed is keyed on the topic-hash, still per-topic-distinct).

   **Residuals (accepted, documented):**
   - **Topic-equality linkability** — same topic ⇒ same topic-hash (a deterministic keyed index is
     required to LOCATE records). Value-confidentiality is met; unlinkability is NOT claimed. An
     adversary can tell two records share a topic, and count records per topic, without learning the
     name. (Likewise the GUID-surrogate reveals that two records share a (guid,sn), i.e. are the same
     retained sample — trivially true anyway.)
   - **Physical space (RESOLVED — AS-BUILT, both backends, continuously-open + cross-restart; continuously-
     open: SQLite = WP-DURABILITY-ENCRECLAIM-SQLITE / Sliver 3a, file = WP-DURABILITY-ENCRECLAIM-FILE /
     Sliver 3b; cross-restart: WP-DURABILITY-ENCRECLAIM-SWEEP / Sliver 3c).** Superseded/settled blobs on the
     encrypted tier were compacted LOGICALLY (correct reads) but physically RETAINED until `store-purge` —
     the inner store runs KEEP_ALL (keep-last-by-real-SN ordering is impossible on a hashed surrogate without
     leaking SN), so its own KEEP_LAST eviction never fires. Sliver 3a physically reclaims them for the
     **continuously-open SQLite** backend via three additive pieces (Sliver 3b adds the **file** backend
     below, reusing the same decorator window):
     - an **additive `store-delete` vtable slot** (`store.lisp`) — per-record delete-by-(topic, writer-
       guid, sn), with the EXACT NIL-fallback binding of `store-sync` / `store-set-chain-mac-fn`: a backend
       that omits the slot returns `:unsupported` and the decorator falls back to today's logical-only
       compaction (byte-identical). SQLite + memory implement it (3a); the **file store** implements it as of
       Sliver **3b** (below); a hypothetical slotless backend still gets the `:unsupported` fallback.
     - a **thin SQLite `:delete`** — the same DELETE + `%sqlite-recompute-topic` survivor re-MAC as the
       Sliver-1 online evict, wrapped in ONE `sqlite:with-transaction` so it is INTERNALLY ATOMIC (a crash
       between the DELETE and the re-MAC rolls back ⇒ a clean chained store never false-rejects on reopen).
     - a **decorator online prior-surrogate window** — the surrogate is per-SAMPLE, so the decorator
       remembers each instance's `(topic-hash, real-key-hash) → {(real-guid, real-sn, surrogate)}` and, when
       the window exceeds the effective depth D (`eff-hd` from `store-open`), physically deletes the entries
       **smallest by `%record-guid-sn<`** (writer-guid bytes ascending, THEN sn — the SAME order as the
       logical view's `%keep-last-latest`, via `store-delete inner th surrogate 0`), so the physical set
       equals the logical newest-D `%compact-topic-records` view **EXACTLY for ALL cases** — including a
       single instance fed by MULTIPLE writer GUIDs (a pure-sn drop would keep the wrong survivor when the
       min-sn sample sits on the higher writer-guid — a get-range divergence) and an out-of-order writer
       (the no-data-loss crux). The window append is **dedup'd on the deterministic surrogate**, so an
       idempotent re-put of an already-tracked (guid,sn) — which `store-put` no-ops physically (INSERT OR
       IGNORE) — never double-counts and evicts a LIVE newest-D row (a public-API idempotency-contract
       data-loss defect the naive append had). The window is cleared on `store-close` / `store-open` and
       per-topic on `store-purge` (bounds decorator RAM; prevents a stale window from mis-evicting a later
       same-instance write).
     The inner PHYSICAL count (`store-count nil`) now converges to Σ D per instance instead of N. The
     put+delete PAIR is deliberately NON-atomic (a LOWER bar than Sliver 1/2): a crash between the put and
     the delete leaks the prior blob (physically retained, still logically compacted at get-range) and
     self-heals on the next delete — a space leak, never a false-reject.
     **File backend `:delete` (RESOLVED — AS-BUILT, WP-DURABILITY-ENCRECLAIM-FILE / Sliver 3b).** The append-
     only file log cannot delete-in-place AND the inner file store is opened KEEP_ALL with NIL-key-hash
     surrogates, so the Sliver-2 own-KEEP_LAST threshold counter never fires — the file `:delete` needs its
     OWN mark-superseded + reclaim: (1) an **immediate in-memory remhash** of the surrogate row (so
     `store-count nil` + the index reflect the removal at once); (2) the surrogate key joins a per-topic
     **in-memory `pending-delete` set** whose SIZE is the O(1) reclaim trigger (distinct from the dormant
     KEEP_LAST counter); (3) crossing `*compaction-superseded-threshold*` runs a `%rewrite-topic-log` variant
     that replays the log **EXCLUDING the pending-delete surrogate keys** (in addition to the existing
     `%compact-topic-records` settled pass), then clears the set — reusing the **SAME Sliver-2 atomic
     tmp+fsync+rename** rewrite (re-emitting a fresh v3 chain) and **PRESERVING the append-fd
     close-before-rewrite / reopen-after guard** (a stale fd appending to the renamed-away log = data loss).
     NO new crash-atomicity machinery — the atomicity is inherited. The continuously-open encrypted file tier's
     on-disk log is thus bounded to **≤ (D + threshold)** per instance instead of growing to N. The bare
     (non-encrypted) file store's Sliver-2 KEEP_LAST path is unchanged (the slot exists but only the decorator
     drives it; a KEEP_ALL encrypted file tier deletes nothing, on-disk == N).
     **Crash lower-bar (parity with 3a):** the `pending-delete` set is IN-MEMORY (empty on reopen). A crash
     DURING the reclaim rewrite leaves the original log intact (rename is the commit point; the orphan `.tmp`
     is discarded on open), the chain verifies, the newest D survive. A crash BETWEEN the in-mem remhash and
     the batched rewrite reappears the surrogate on reopen (the remhash was in-memory only) — but get-range
     still logically compacts it (correct reads) and the chain verifies: a **self-healing SPACE leak**, never
     a false-reject or loss. A same-session fault self-heals on the next put (the `pending-delete` set stays
     armed — the rewrite faulted before the clear — so the next `store-delete` retries).
     **Cross-restart case (RESOLVED — AS-BUILT, WP-DURABILITY-ENCRECLAIM-SWEEP / Sliver 3c, both backends).**
     `instance-windows` is IN-RAM and clrhash'd on `store-open` (bounds decorator RAM + prevents a stale
     window from mis-evicting), so after a RESTART the fresh window does not know a prior session's ≤D newest
     survivors per instance: post-restart online eviction (which tracks only THIS-session puts) never evicts
     them and they leak until the next restart — across K restarts a hammered instance accumulates ~K·D
     physical rows. Sliver 3c adds a **decorator compaction-on-open SWEEP** at the END of the `:open` lambda
     (after the DEK reload + the `instance-windows` clrhash), for `:keep-last` only and only once `k_meta` is
     resident: for each inner topic-hash (`store-topics inner`), **decrypt its surrogate rows** (REUSING the
     get-range decrypt — `open-payload-v2` over the epoch-DEK map + `%open-meta-frame`, with the AEAD AAD
     recovered from the on-disk topic-hash hex via the new `%meta-unhex`, since the plaintext topic name is
     off-disk), **group the `:data` records by their REAL key-hash**, and — via the SAME
     `%trim-window-to-depth` the online evict now shares — **`store-delete` the leftovers beyond newest-D AND
     SEED `instance-windows` with the surviving newest-D** (same `(real-guid, real-sn, surrogate)` entry shape,
     same `%win-entry<` order). The **window-seed is the crux**: without it the fresh window stays empty and
     the next same-instance put cannot evict the prior survivors (they leak); WITH it the next higher-SN put
     pushes the seeded window to D+1 and evicts the oldest survivor, so **cross-restart physical converges to D
     exactly like the continuously-open case** (SQLite = ~D; file = ≤ D+threshold on disk, = D in the in-mem
     index). The sweep is off the hot path (once per open, control-plane — it decrypts the whole store once,
     the same cost the first get-range would incur), reuses `store-delete` (a `:unsupported` backend skips the
     reclaim but is still seeded — the guard remains), re-MACs the survivors (SQLite atomic DELETE + re-MAC /
     file atomic reclaim rewrite) so the chain verifies clean after the sweep, and is **idempotent** (an
     already-≤D store finds nothing beyond-D → no deletes, no churn). No vtable/wire change. Proven RED→GREEN
     by the test-only `*durability-debug-disable-open-sweep*` switch: sweep-disabled reproduces the pre-3c
     accumulation (SQLite/file in-mem physical (2 4 6 8) across K=4 restart cycles), sweep-enabled bounds it
     ((2 2 2 2); file on-disk ≤ D+threshold). Multi-writer-per-instance grouping is locked cross-restart by a
     dedicated case (one instance fed by two writer GUIDs A\<B: the sweep keeps the (guid,sn)-newest-D `B·3,
     B·6`, NOT the pure-SN `A·5,B·6`). The encrypted-tier physical-reclaim story is now CLOSED for both
     backends, continuously-open AND cross-restart. A space, not a correctness, tradeoff throughout.
     **Benign residual (FILE, topics.map-dependent, NOT introduced by 3c):** the file sweep's cross-restart AAD
     recovery reads the topic-hash id from `store-topics` (the file store's `id-map`, rebuilt from `topics.map`
     on reopen). On a clean write→close→reopen (what 3c targets — every test) it always persists. If `topics.map`
     were LOST, `store-topics` falls back to the double-hex `tid` (`store-file.lisp` `id->topic` miss), so
     `%meta-unhex(tid)` yields the WRONG AAD, the GCM tag fails, and the sweep SILENTLY does not reclaim that
     topic — a bounded space non-reclaim, **no data loss, no false-reject, no crash** (the unhex is bounds-safe;
     `store-get-range` still serves that topic correctly via the caller's real topic name). This is an orthogonal
     `topics.map`-durability failure mode, not introduced by 3c. **SQLite is immune** (the topic is persisted in
     the DB `topic` column, not a side map).
     **Steady-state window residual — RESOLVED (WP-DURABILITY-SETTLED-RECLAIM, put-time settle-hook).**
     As originally shipped, a settled/quiescent instance's window entry persisted in `instance-windows`
     until `store-purge` or `store-close`, so a workload of endlessly-distinct settling instances grew the
     decorator RAM with the settled-instance count. The decorator now sees the REAL `kind`/`key-hash` (the
     inner store sees only `:data` surrogates and cannot detect a settle), so its `:put` folds every keyed
     put into a per-instance `settle-tally` and, on the SETTLE transition — the **shared** pass-1-equal
     predicate (`%settle-tally-fold` in `store.lisp`, the SAME detector the file store's settle trigger uses,
     ADR 0029 §10.1) — `remhash`es the instance's `instance-windows` entry (and its tally), mirroring
     `%purge-topic-windows`' per-key removal. Clearing the window on settle is exactly the `:purge` FIX-3
     discipline, so a later re-registration seeds a fresh window and is never mis-evicted. `instance-windows`
     now stays bounded to the live + in-flight instance count under settling churn — proven by
     `run-durability-encrypted-physical-reclaim-test` case (10) (RED→GREEN via
     `*durability-debug-disable-settle-trigger*`, observed through `*durability-debug-window-count-hook*`).
     RAM-only (the inner physical settled-instance rows are the separate file/SQLite on-disk concern).
   - **`store-topics` cross-restart** — the decorator names topics from an in-session reverse map
     (topic-hash → real name); after a restart the plaintext names are off-disk, so `store-topics`
     enumerates only topics touched this session. Records are still fully located/served by topic-hash
     (the durability service matches on discovery, never on a name enumeration).
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
