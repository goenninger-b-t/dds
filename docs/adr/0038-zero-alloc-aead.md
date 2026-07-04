# ADR 0038 — Zero-alloc AEAD: the `data_protection` (serialized-payload) tier + the shared into-buffer foundation (M7/P6 Slice-1 hardening)

- **Status:** Accepted (M7/P6; WP-DDS-SECURITY-ZEROALLOC-AEAD, 2026-07-01)
- **Relates to:** ADR 0031 (Slice 1 — the serialized-payload `data_protection` codec whose allocating
  `encode/decode-serialized-payload` entries this WP refactors into **thin wrappers over a new into-buffer
  core**; the empty-AAD + SecureDataTag-4-align + SEC_BODY-4-align addenda are preserved byte-identically);
  ADR 0025 (DARE — the `dds-dare` AES-256-GCM OpenSSL FFI this WP extends with additive **into-buffer** entries);
  ADR 0034 (the auth key-material GC-heap deferral — the session-key cache keeps the derived key on the GC heap,
  carried forward here); ADR 0036 (Slice 4 — **Carry 3** [zero-alloc into-buffer AEAD on the data path] is
  PARTIALLY resolved here for the `data_protection` tier + the shared foundation; **Carry 10** [ZC × `rtps_protection`
  SHMEM cleartext] carried); ADR 0037 (Slice 5 — the Fast-DDS interop capstone; the two shipped Slice-1 crypto-wire
  addenda whose wire this WP leaves byte-identical); ADR 0014 / ADR 0018 (the zerocopy-pool refcount+generation
  precedent mirrored by the cache-change send-refcount, and the FlatData-ZC loan-registry SHAPE reused — non-SAP —
  by the decode loan); the operating contract §4 (hot-path purity; static-arena, RESOURCE_LIMITS-not-GC on
  exhaustion; bounds-check even at `(safety 0)`; clean-room, no wire constant from memory); NFR-MEM (steady state
  allocates **zero** bytes/sample); NFR-SEC-POSTURE (bounds-checked, fail-closed, fuzzed); NFR-PORT (Clasp + SBCL
  both validate, Clasp first; no reader conditionals outside `dds-pal/`); FR-SEC-2 (no hand-rolled crypto).
- **Standards:** OMG DDS-Security 1.1 §9.5.2 (`KeyMaterial_AES_GCM_GMAC`); §9.5.3.3 (Cryptographic-plugin
  serialized-payload protection); §9.5.3.3.1 (SecureDataHeader / CryptoHeader layout); §9.5.3.3.3 (SecureDataTag);
  §9.5.3.3.4.2 (the session-key KDF — HMAC-SHA256, no counter, reconciled T-RECONCILE/ADR 0036); §9.5.3.3.4.3 (the
  12-byte GCM nonce = `session_id ‖ init_vector_suffix`); §9.5.3.3.4.4 / §9.5.3.3.4.5 (`encode/decode_serialized_data`,
  empty AAD per the ADR-0031 addendum). NIST SP 800-38D (AES-GCM); NIST SP 800-38D Test Case 16 + the existing
  byte-exact SecuredPayload corpus are the wire oracles. **No RTI Connext source, headers, or generated code was
  ever read** (clean-room; the into-buffer FFI reproduces the NIST KAT byte-for-byte, corroborated only against
  the published vector).

---

## Context

Per ADR-0036 **Carry 3**, the secured RTPS data path is **not** zero-alloc: with security enabled the AEAD
encode/decode allocate GC-heap memory **per sample** in steady state, and the `make mem` gate — which asserts
`0.0000` B/sample — ran a **security-OFF** CDR workload only, so it never exercised the security path at all.
This breaches NFR-MEM (steady state allocates zero bytes/sample) whenever security is on. Three distinct
per-sample allocation sources existed:

1. the OpenSSL AEAD FFI (`aes-256-gcm-seal`/`-open`) `make-array`s its ciphertext/tag/plaintext outputs on the
   GC heap, and — discovered mid-WP — the EVP call machinery itself conses ~770–860 B/iter even after the output
   `make-array`s are removed (boxed SAPs + repeated `foreign-symbol-pointer` lookups);
2. `derive-session-key` (HMAC-SHA256) runs **per sample** even though the session key is effectively constant per
   KeyMaterial for the data path (fixed `session_id`);
3. the codec allocates per-sample intermediates (the `→octets` return, `subseq`/`copy-seq` of fields, the nonce
   `make-array`), and the **live** dataplane retains the payload/plaintext **by reference** (the writer HistoryCache
   for retransmit/KEEP_LAST/batch/async; the reader `disc-node-samples` store, which is never purged), so a naive
   reused buffer aliases live entries.

The dominant absolute cost is on the whole-RTPS (`rtps_protection`, ~2.2 KB/datagram) tier, but the **foundation**
that fixes all of it — an into-buffer AEAD FFI + a session-key cache + an into-buffer codec core — is shared by all
three AEAD tiers. This WP proves that foundation on the simplest tier (`data_protection`) end-to-end on the live
path, and leaves the submessage / whole-RTPS tiers to **reuse** it in Slice 2.

This ADR documents the **WP-DDS-SECURITY-ZEROALLOC-AEAD** work package as built, from the controller's
commit-by-commit ledger (`5af89ad` base … `0382df9` T5d) on `wp-dds-security-zeroalloc-aead`.

---

## Scope — read this before the numbers (no overclaim)

**This slice delivers the `data_protection` (serialized-payload) AEAD tier + the shared foundation only.** The
submessage (`metadata_protection`) and whole-RTPS (`rtps_protection`, the ~2.2 KB/datagram) tiers are **NOT** made
zero-alloc here — they REUSE the same into-buffer FFI + session-key cache + into-buffer-core foundation in **Slice
2**. So ADR-0036 **Carry 3 is PARTIALLY resolved**: the foundation + the `data_protection` tier are resolved by
this ADR; the submessage + whole-RTPS application is carried forward. **Do NOT read this as "all AEAD tiers are
zero-alloc."**

---

## Decision — as-built architecture

Ten increments, each its own commit + (where non-trivial) a two-stage review, holding the our-to-our-green +
wire-byte-identical invariant on both impls (Clasp first) after every step. Every `before → after` figure below is
from the ledger (SBCL `dds.pal:bytes-consed`; Clasp `bytes-consed` is 0 → the measured arms self-skip/smoke while
the structural asserts run on both — NFR-PORT).

### 1. Into-buffer AEAD FFI + EVP-pointer caching + `dds.pal:static-sap+` (the load-bearing foundation)

- **Into-buffer entries** (`src/dds-dare/primitives.lisp`, T1): additive `aes-256-gcm-seal-into` /
  `aes-256-gcm-open-into` write the ciphertext/tag (seal) and plaintext (open) **through the caller's static-vector
  SAPs** at caller offsets — no `make-array` output. NIST SP 800-38D TC16 byte-identical to the allocating entries
  (cross-asserted); fail-closed on auth-failure with a plaintext wipe; O(1) output-extent bounds asserts that hold
  at `(safety 0)`. The existing allocating `aes-256-gcm-seal`/`-open` are **untouched** (the KAT / auth / key-exchange
  / data-at-rest callers are unaffected).
- **The mid-WP blocker (recorded honestly):** T1 removed the output `make-array`s but the EVP call machinery still
  consed — `aes-256-gcm-seal-into` = 863.94 B/iter, `-open-into` ≈ 848→768 B/iter (SBCL, reused buffers). A spike
  attributed ~91 % to repeated `foreign-symbol-pointer` lookups (~10/call) and the rest to boxed-SAP outputs +
  `with-foreign-pointer` scratch. Two bisectable fixes, folded into the slice:
  - **EVP-fn-pointer caching** (T1b-i): the `%ossl-sym` macro resolves each EVP symbol **once per FASL load** via
    `(load-time-value (cffi:foreign-symbol-pointer …) t)`, and `*%aes-256-gcm-cipher*` caches the `EVP_aes_256_gcm()`
    handle via a load-time `eval-when`. seal-into 863.94 → **79.95**, open-into ≈848 → **63.90** B/iter (~91 %).
  - **Zero-box SAPs + `dds.pal:static-sap+`** (T1b-ii): a new inline PAL primitive computes the raw foreign SAP at
    `VEC[OFFSET]` **without boxing the pointer** (SBCL `sb-sys:sap+`/`vector-sap`; Clasp `cffi:inc-pointer` over
    `static-vector-pointer`), plus a cached null pointer, a `with-foreign-object` output-length cell, in-place GCM
    (the EVP `in == out` aliasing the OUTPUT region; the caller's plaintext is read-only, so the sample survives),
    and AAD pinned via `with-pointer-to-vector-data`. seal-into **79.95 → 0.000**, open-into **63.90 → 0.000** B/iter.
- **`static-sap+` is an ADDITIVE `dds.pal` contract change** — a new export (`#:static-sap+`, in the `pal-contract.lisp`
  memory group, alongside `alloc-static`/`static-pointer`/`static-length`). Contract: the argument MUST be an
  `alloc-static`-backed (foreign, non-moving) vector — a GC-movable heap vector's SAP would be unsafe; the boxing
  entry point `static-pointer` remains for control-plane use. `safety 0` is contained to the inline body; the
  seal/open callers keep the extent asserts.

Net: the FFI is now **zero-cons** (FFI 864 → **0.000 B/iter**), so the codec above it can reach 0.0000.

### 2. Session-key cache (`src/dds-security/key-material.lisp` + `transform.lisp`, T2)

`derive-session-key(master_sender_key, master_salt, session_id)` is constant per KeyMaterial for the fixed data-path
`session_id`. `%km-session-key-at` caches the last `(session-id . session-key)` on the KeyMaterial: **derive-once**,
byte-compared in place on the hit path (lock-free, zero-alloc). Publication is **barrier-safe** via `dds.pal:fence`
(SBCL `sb-thread:barrier` / Clasp `mp:fence`) — the two-slot publish/consume uses the `session_id` as the ready-flag
(miss = key-store → `:release` → id-store; hit = id-match → `:acquire` → key-load: correct StoreStore/LoadLoad,
fixing an arm64 weak-memory torn read caught in review). This removes the per-sample HMAC-SHA256 KDF from
`%seal/%open-with-km`. The cached key stays on the GC heap (derived once → it does not move `bytes-consed` in steady
state), consistent with the ADR-0034 key-material deferral (see Residual (b)).

### 3. Into-buffer codec core + thin allocating wrappers (`src/dds-security/transform.lisp`, T3)

- `encode-serialized-payload-into (out-buf km plaintext) → length` and
  `decode-serialized-payload-into (pt-out km secured) → (or length null)` — the zero-alloc cores. The CryptoHeader /
  `crypto_content` length / §9.5.3.3.3 4-align pad / rsm_count are written through the buffer with **raw offset
  writes** (no cursor struct is consed — a `dds.core.buffer:cursor` is not inlined, so binding one heap-conses
  ~48 B/call). The 12-byte GCM nonce is the **in-place `OUT-BUF[8..20]` sub-slice** (`session_id ‖ iv_suffix`), handed
  to `seal-into` as SAP+offset — no separate nonce buffer. decode parses the header in place, applies the empty-AAD
  `find_key` integrity gate (kind + key_id equal the KM), and passes nonce/ciphertext/tag as SAP+offset slices of the
  input to `open-into`; fail-closed NIL on auth-failure / malformed input. Codec-own alloc = **0.66 B/iter** (the
  residual is the shared FFI SAP-boxing, since eliminated in §1).
- The existing `encode-serialized-payload` / `decode-serialized-payload` are now **thin allocating wrappers** over
  the cores. Consequence: the byte-exact corpus calls the wrappers → exercises the cores → **byte-identity is proven
  automatically**; additionally an **oracle-pin** test pins `encode-into` byte-for-byte to the INDEPENDENT
  `serialize-secured-payload` oracle (not the wrapper), so the core cannot silently drift.

### 4. Security-ON `make mem` arm (T4)

`run-mem-test-secure` drives `encode/decode-serialized-payload-into` over REUSED static buffers (100k iters),
asserting `bytes-consed/iter < 1.0` on SBCL (Clasp smoke; SKIP-graceful if AES-GCM is absent), and is wired into
`make mem`. **Result: `aead-encode` 0.0000 + `aead-decode` 0.0000 B/sample (SBCL) — the headline codec DoD, proven.**
This closes the gap that `make mem` never covered the security path.

### 5. Encode payload pool with cache-change send-refcount (`src/dds-rtps/{history,reliable}.lisp`, `src/dds-core/arena.lisp`, T5a-pre + T5a)

- **Release-safety first** (T5a-pre): send build-thunks close over the cache-change payload **by reference** and emit
  LATER (async/flow sender; retransmit on another thread); a pooled buffer released at eviction and re-acquired before
  a captured thunk copies it would put wrong bytes on the wire (multi-reader: A's ACK-purge vs B's NACK-retransmit).
  A lock-guarded **send-refcount** was added to `cache-change` (mirroring the zerocopy-pool refcount+generation),
  acquired at each capture site and released after copy-into-datagram; because `dds.pal:cas`/`atomic-incf` are M0
  stubs (see Residual (e)), the existing non-recursive writer lock is the sanctioned per-cache lock. Behaviorally
  neutral; both eviction paths take the SAME lock so a concurrent evict observes refcount > 0.
- **The pool** (T5a): a per-writer-HistoryCache buffer pool on the disc-node arena (torn down at `stop-node`);
  `publish-sample` encodes via `encode-serialized-payload-into` into a `pool-acquire`d buffer; release is
  refcount-gated at the single eviction choke `%hc-remove-change` AND at last-ref-drop (exactly-once; no
  double-release / leak / resurrection). **Lazy provisioning** on the live handshake path (`writer-ensure-payload-pool`
  / `%ensure-secured-payload-pool`): crypto is installed AFTER `enable-publisher` (the DDS-Security order), so the pool
  is carved on the first secured publish — the live secure-discovery publisher is zero-alloc, not just the
  pre-set-key case. Exhaustion → the existing `%writer-add-bounded` `:timeout` / RETCODE_TIMEOUT (RESOURCE_LIMITS),
  buffer returned, **never a GC fallback**. **Encode 353.5 → 0.0 B/sample; the live keys-after-enable path
  (`aead-encode-live` arm) 0.0000.**

### 6. Loaned decode plaintext (`src/dds-disc/{disc,dataplane,packages}.lisp`, T5b + T5d)

- `disc-node-samples` is **never purged** (node-lifetime retention), so there is no natural release point keyed to
  "the app took the sample" — the decode buffer MUST use a **loan**. The receiver decodes via
  `decode-serialized-payload-into` into a per-node **decode-pool** buffer (carved once from a static arena;
  `*secured-pool-capacity* + *secured-pool-headroom*` × `*secured-payload-max-bytes*`) and stores a
  `secured-loan-handle` — not a plaintext vector — in the store, its lifetime tied to a **loan registry** (not the
  store). **Secured reads ADOPT an app-facing read-contract** (see below): `node-take-loaned` returns `(values VEC
  COUNT)`; the app reads the plaintext IN PLACE via `secured-loan-bytes` over `[0, len)`; `node-return-loan` releases
  the buffer, recycles the handle, and remhashes the dangling store entry (no use-after-free, no wrong-bytes).
  `stop-node` returns all loans before teardown. **Decode 4042.88 → 0.0000 B/sample.**
- **Review fix (T5b Critical):** `%secured-loan-release` store-eviction is IDENTITY-GUARDED (the `(guid,sn)` slot is
  cleared only when THIS handle still occupies it), so a reliable-link **duplicate** of an undrained secured sample
  frees only its own buffer and never evicts the accepted original (no silent sample loss, no pinned slot); proven
  FAILING-FIRST by `run-secured-decode-loan-dup-test`.
- **The loan wrapper itself, pooled** (T5d): the `secured-loan-handle` is drawn from a per-node **freelist**
  (recycled fully-dissociated on return), the outstanding-loan **registry** is a fixed vector with O(1) swap-remove
  via the handle's `reg-index` (no per-loan cons), and `node-take-loaned` fills a **reused** result vec (no per-take
  list cons). This eliminates the ~72–87 B/sample loan-wrapper residual that T5c had surfaced, so the **full secured
  RECEIVE loop** — not just the payload codec — adds 0.0000 B/sample over the non-secured baseline.

### App-facing contract change — the secured-read loan API

A **loan-capable** secured reader (opt-in `set-secured-loan-capable`; **default OFF = the allocating-decode
bare-vector path, byte-identical**) MUST read through the loan API and RETURN every loan:
`set-secured-loan-capable` → `node-take-loaned` `(values VEC COUNT)` → `secured-loan-bytes` (read `[0, len)` in
place, zero copy) → `node-return-loan (node VEC COUNT)`. Callers must test `secured-loan-handle-p` first (an
arena-carve-fail bare-vector fallback carries no loan). Use-after-return of a recycled handle is a documented
caller-contract violation (memory-safe within the arena, undefined otherwise). Documented in the API docstrings +
`docs/wiki/security.md` §3.3.

---

## The proof (the DoD)

- **`make mem` security-ON arms (SBCL), all 0.0000:** `aead-encode` 0.0000, `aead-decode` 0.0000,
  `aead-encode-live` 0.0000, `aead-live-pub` data_protection delta ~0.0000 (plain ≈191.9 vs secured ≈191.9 on one
  warmed node so the common ~190 B/sample framing cancels; asserted `|Δ| < 2.0` to absorb the ~0.33 B/sample SBCL
  `get-bytes-consed` 64 KB GC-boundary accounting quantum), `aead-live-rx` **0.0000 EXACT** (the deterministic
  `%secured-wrapper-cycle-bps` over all six wrapper ops). The end-to-end separate-node live receive delta is
  1.62 B/sample @256 / 1.18 @4096 — GC-quantum noise (the EXACT 0 is the deterministic wrapper-cycle); `%source-guid`
  16 B cancels in the over-baseline delta (shared path).
- **Exhaustion = backpressure, never GC (both sides):** encode pool full → `publish-sample` `:timeout` /
  RETCODE_TIMEOUT, admitted count capped, exhausted publishes cons ~0 B; decode pool full →
  `disc-node-decode-pool-rejects++` (SAMPLE_REJECTED), sample-count capped, sample left un-acked → writer
  backpressure. No heap fallback either side.
- **Wire byte-identical throughout:** the NIST AES-GCM KAT and **every** byte-exact SecuredPayload / crypto-header
  corpus stay green **UNCHANGED** (no regeneration); the `data_protection` end-to-end tests
  (`run-security-encrypted-pubsub-test` — now adopting the loan read contract — and `-encrypted-fragmented-test`)
  are byte-exact. The diff is the FFI/codec/pool/loan machinery + tests + docs — no wire change.
- **Honest scope:** the `aead-live-pub`/`-rx` deltas are the cost of enabling `data_protection` OVER the non-secured
  baseline for the **encode + decode PAYLOAD path** — NOT a whole-datagram-zero claim. A full loop still conses the
  pre-existing NON-security per-sample allocs (`make-cache-change`, RTPS framing) IDENTICALLY with security on/off,
  so they cancel in the delta.

---

## Consequences

- **NFR-MEM:** `make mem` now **covers the security path** and reports 0.0000 for the `data_protection` AEAD tier
  (encode + decode, live pub + rx). Previously the gate ran a security-OFF CDR workload only. This resolves ADR-0036
  Carry 3 for the `data_protection` tier + the shared foundation (submessage / whole-RTPS carried to Slice 2).
- **NFR-SEC-POSTURE:** `open-into` / `decode-serialized-payload-into` are bounds-checked (O(1) extent checks that
  hold at `(safety 0)`) and fail-closed (NIL, no readable plaintext left on failure; the empty-AAD `find_key` gate
  preserved); the existing fuzz arms still drive the decode path; pool exhaustion is a graceful RESOURCE_LIMITS, not
  a crash.
- **FR-SEC-2:** no hand-rolled crypto — AES-256-GCM via `dds-dare` (OpenSSL EVP); the into-buffer entries are the
  same EVP calls writing through caller SAPs, NIST-KAT byte-identical.
- **NFR-PORT:** `static-sap+` is the one new PAL primitive, with per-impl bodies inside `dds-pal/` only; no reader
  conditionals elsewhere. Clasp + SBCL both validate (Clasp first); the measured-alloc arms self-skip on Clasp
  (`bytes-consed` is 0) while the structural exhaustion / lifecycle asserts run on both.
- **Hot-path purity:** the codec cores + pool/loan use `defstruct` + monomorphic functions (the `secured-loan-handle`
  mirrors the shipped `zc-loan-marker`); no per-sample CLOS dispatch. `gate-hotpath` green.
- **Default-OFF / byte-identical:** a reader that does not `set-secured-loan-capable`, and every non-secured reader,
  keep the allocating-decode bare-vector path; security-OFF is byte-identical.
- **Gates (final sweep, both impls, Clasp first):** see §Gate sweep below.

---

## Residual carries (recorded, NOT fixed here)

**(a) Submessage + whole-RTPS tiers reuse the foundation — Slice 2. RESOLVED (ADR 0039, 2026-07-02).** The
`metadata_protection` (submessage) and `rtps_protection` (whole-RTPS, the ~2.2 KB/datagram) tiers are now zero-alloc
on the common ENCRYPT/SIGN path (send + receive), reusing this foundation (the into-buffer FFI — extended with an
AAD-region arm for the SIGN sub-range — + the session-key cache + the into-buffer-core + thin-wrapper pattern + the
arena buffer-pool pattern), via `%encode/%decode-secured-region-into` + five per-node static scratch pools. With the
`data_protection` tier here, **all three AEAD tiers are zero-alloc** → this completes ADR-0036 Carry 3 (flipped to
fully resolved). Origin authentication (receiver-specific MACs) stays the deferred allocating fallback (ADR 0039
Residual (a)). **Still open (carried into ADR 0039 Residual (d)):** when a future `rtps_protection` rekeying
(session_id rotation) lands, it must confirm the decode receiver stays single-threaded OR harden
`%km-session-key-at`'s two-slot publish against a concurrent-different-session_id tear (the current fence protocol is
tear-safe only while session_id is effectively constant per km and decode is single-threaded).

**(b) KeyMaterial GC-heap → foreign + zeroize (ADR-0034 deferral).** The session-key cache and the KeyMaterial key
bytes live on the GC heap. Derived once, so they do not move steady-state `bytes-consed`; migrating all key material
to foreign/static buffers with zeroize-on-teardown is the hardening follow-on (ADR 0034 / ADR-0036 Carry 6).

**(c) Zero-Copy × `rtps_protection` SHMEM cleartext (ADR-0036 Carry 10).** With ZC/SHMEM transfer only the 16-byte
reference datagram is RTPS-wrapped; the payload sits in shared memory in the clear. Reconciling SHMEM with
`rtps_protection` confidentiality is a backlog item (and crypto+ZC is loud-guarded per ADR 0031).

**(d) Saved-image foreign-pointer staleness (T1b-i). — RESOLVED (WP-ADR-SMALL-CARRIES C3, 2026-07-03).** The
`load-time-value` / `eval-when`-cached EVP function pointers + the `EVP_aes_256_gcm()` handle were correct for
load-from-source (tests + `make`) but went **stale across a dumped image** (`save-lisp-and-die`): on restart the
shared library is re-mapped at a new address, so the first AEAD/X.509 call would dereference a dangling pointer.
**Closed by C3:** `%ossl-sym` now resolves each symbol through a shared, re-resolvable **box** (a 1-slot vector
interned in `*ossl-sym-boxes*`; per-call cost is one `svref`, still zero cons) instead of a frozen per-call-site
`load-time-value` pointer, and an image-restart hook `%dare-reresolve-foreign-pointers` re-opens `*libcrypto*` +
re-resolves every box + `*%aes-256-gcm-cipher*` in place on startup (`*%null-ptr*` is address 0, reload-stable, so
it is left as-is). The hook is registered through a new **portable PAL seam** `dds.pal:register-image-restart-hook`
(SBCL `sb-ext:*init-hooks*`, Clasp `core:*initialize-hooks*`; the only place the reader conditional lives is
`dds-pal/`). `run-dare-image-restart-reresolve-test` simulates the post-restart staleness (nulls a sample of boxes
+ the cipher) and proves the hook repopulates them and that a seal/open through the re-resolved pointers is
byte-identical to the pre-restart output (fail-closed on tamper). Wire + KAT/corpora unchanged.

**(e) M0 atomics stubs. — RESOLVED (WP-PAL-ATOMICS, ADR 0041).** `dds.pal:cas` / `atomic-incf` are now
implemented on both impls over a PAL `atomic-cell` (SBCL `sb-ext:`, Clasp `mp:`; concurrency-proven). The
revisit was made an *informed* decision: the cache-change send-refcount **stays writer-lock-guarded** —
every refcount access site already holds the writer lock for other reasons (the unsent-read / cache-lookup
on acquire, the pool-release on the ref drop), so lock-free would yield **zero** contention win while
introducing a releasable-check-vs-acquire TOCTOU (the refcount is one field of a `{refcount, evicted,
pooled-buffer, pool-freelist, unsent-base}` invariant mutated as a unit). The atomics land as a tested API
for a future genuinely-lock-free consumer. See ADR 0041 for the full assessment.

**(f) `open-into` CTX_new-NULL OOM path (T1b-ii, Minor). — RESOLVED (WP-RESIDUAL-FIXES-BATCH-A, 2026-07-04).**
Fixed by the preferred zero-cost shape: the ciphertext staging into `pt-out` now happens **after** the
`EVP_CIPHER_CTX_new()` NULL check (`src/dds-dare/primitives.lisp` `aes-256-gcm-open-into`), so on the OOM early
path `pt-out` is never written at all — a failed context allocation leaves no staged bytes (docstring updated).
No dedicated test: forcing `EVP_CIPHER_CTX_new` to return NULL is not cheaply drivable (allocator-level OOM
injection into OpenSSL); a code-shape fix verified by inspection + the existing round-trip/KAT suite.

**(g) `node-return-loan` count-discipline edge (T5d, Minor). — RESOLVED (WP-RESIDUAL-FIXES-BATCH-A, 2026-07-04).**
The COUNT is now **mandatory for a vector of loans**: `node-return-loan` signals an error on a vector passed
without its populated count instead of walking the whole capacity vec, so the stale-tail premature double-release
is impossible by construction (`src/dds-disc/dataplane.lisp`; docstring + wiki updated). The single-handle and
list shapes are unchanged; all callers already passed the count.

**(h) PRE-EXISTING secured store growth (NOT introduced by this WP). — RESOLVED (WP-SECURED-STORE-GROWTH).**
`%secured-loan-release` cleaned only `disc-node-samples`, not the parallel per-`(guid,sn)` tables (`sample-writers`
/ `-writer-guids` / `-origins` / `-key-hashes`); and the arena-carve-fail bare-vector store grew on a never-purged
secured stream (memory-exhaustion, attacker-drivable by a keyed peer streaming samples never loaned back). **Closed
by WP-SECURED-STORE-GROWTH:** a single purge choke — `%purge-secured-sample (node guid sn)` — drops `(guid,sn)`
from ALL five parallel tables at one place (zero-alloc macrolet; the secured receive zero-alloc arms stay 0.0000),
called under the identity guard from `%secured-loan-release` so every released/evicted secured sample's metadata is
purged (no table retained). The arena-carve-fail allocating fallback is now **bounded**: the undrained bare-vector
store is capped at the pool working-set budget (`*secured-pool-capacity* + *secured-pool-headroom*`) and **fails
closed** (RESOURCE_LIMITS / `decode-pool-rejects`, un-acked → writer backpressure) at the cap, mirroring pool
exhaustion — never a GC-silent unbounded store; and the carve-fail handler now catches `storage-condition` too so a
real off-heap OOM degrades gracefully as documented. Leak-proof regression: `run-secured-store-growth-test` (streams
many secured samples with/without draining, asserts the tables are purged on release and the carve-fail store stays
bounded; written RED on the pre-fix code).

**(i) DCPS take-loaned-for-secured follow-on.** The secured loan lives at the `disc-node` level; the DCPS
`read/take` path is byte-identical and NOT opted-in (`%drain-one-sample` errors loudly on a `secured-loan-handle` to
guard a future DCPS-loan mis-wire). Extending the loan to the DCPS API is a follow-on.

---

## §M7 roadmap update

| Slice | Description | Status |
|---|---|---|
| 1 | Crypto plugin: AES256-GCM `SecuredPayload` `data_protection` (ADR 0031) | LANDED |
| 2a–2c | Authentication + key exchange (ADR 0032 / 0033 / 0034) | LANDED |
| 3 | AccessControl (ADR 0035) | LANDED |
| 4 | Secure discovery our-to-our (ADR 0036) | LANDED |
| 5 | Live Fast DDS-Security cross-vendor (ADR 0037) — the Fast-DDS half of the P6 exit gate | LANDED |
| 5b | Live RTI Connext-Security secure discovery — the remaining half of the P6 exit gate (RTI plugins gated) | pending |
| **1-HARDENING (this ADR)** | **Zero-alloc AEAD: the `data_protection` tier + the shared into-buffer foundation (ADR 0038)** | **LANDED** |
| 2-ZEROALLOC | Extend the foundation to the `metadata_protection` (submessage) + `rtps_protection` (whole-RTPS) tiers (ADR 0039) | LANDED |

---

## Gate sweep (final, both impls, Clasp first)

- `make build` (Clasp + SBCL): PASS.
- `make test-clasp` / `make test-sbcl`: **389 / 389**.
- `make corpus`: PASS (M1 byte-exact XCDR placeholder — unchanged; the security byte-exact corpora run under `make test`).
- `make fuzz` (both impls): PASS.
- `make gate-hotpath`: PASS (8).
- `make gate-types`: PASS (2100).
- `make mem`: **0.0000 all arms** (incl. `aead-encode`/`aead-decode`/`aead-encode-live`/`aead-live-pub` delta ~0 /
  `aead-live-rx` deterministic 0.0000).
- `make bench`: **N/A** — this WP has a before/after `make mem` number (the appropriate measurement for an allocation
  change); the latency/throughput bench is unchanged (the wire and the CDR hot path are byte-identical). The
  per-component `before → after` B/sample figures are in this ADR and the WP bench notes.

---

## References

- Design spec: `docs/superpowers/specs/2026-06-30-zero-alloc-aead-design.md`
- `src/dds-pal/{pal-contract,pal-sbcl,pal-clasp}.lisp` — the additive `static-sap+` PAL primitive
- `src/dds-dare/primitives.lisp` — `aes-256-gcm-seal-into` / `aes-256-gcm-open-into`; `src/dds-dare/openssl-ffi.lisp` — the `%ossl-sym` EVP-pointer caching
- `src/dds-security/key-material.lisp` — the session-key cache slot + `%km-session-key-at`
- `src/dds-security/transform.lisp` — `encode/decode-serialized-payload-into` cores + the thin allocating wrappers
- `src/dds-rtps/{history,reliable}.lisp` + `src/dds-core/arena.lisp` — the cache-change send-refcount + the encode payload pool + lazy provisioning
- `src/dds-disc/{disc,dataplane,packages}.lisp` — the decode pool + `secured-loan-handle` + handle freelist + fixed-vector registry + `set-secured-loan-capable` / `node-take-loaned` / `node-return-loan` / `node-return-all-loans`
- `src/dds-dcps/entities.lisp` — the `%drain-one-sample` secured-handle type-guard
- `src/dds-tests/gen-test.lisp` — `run-mem-test-secure` (the `aead-*` arms); `src/dds-tests/security-test.lisp` — `run-secured-decode-loan-alloc-test` / `-dup-test`, `run-secured-encode-pool-balance-test`, `run-secured-live-zeroalloc-test`
- `docs/wiki/security.md` §3.3 — the zero-alloc secured-receive loan contract
- ADR 0031 (Slice 1 codec + the crypto-wire addenda), ADR 0025 (DARE FFI), ADR 0034 (key-material deferral), ADR 0036 (Carry 3 / Carry 10), ADR 0037 (Slice 5 Fast-DDS interop), ADR 0014 / 0018 (the refcount + loan-registry precedents)
