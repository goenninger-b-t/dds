# Design — CNSA-2.0 Data-At-Rest Encryption (DARE) for the durability service (M6/P5→M7/P6, Phase 3a)

- **Date:** 2026-06-19
- **Status:** Design approved (brainstorm); spec under owner review before the implementation plan.
- **Scope:** the always-on CNSA-2.0 DARE crypto layer (ADR 0021 capability 7), built as a `durable-store`
  decorator over the existing **in-memory** store — the encryption envelope + key management proven
  end-to-end before the disk-backed store (the immediate MUST follow-on, slice 3b) plugs underneath it so
  disk holds only sealed bytes.
- **Relates to:** ADR 0021 (durability service scope + capability 7 = always-on CNSA-2.0 DARE); ADR 0023
  (Phase-1 service architecture); ADR 0024 (Phase-2 dedup); the durable-store vtable (`src/dds-durability/
  store.lisp`); FR-SEC-2 (vetted native crypto, no hand-rolling); NFR-SEC-POSTURE; NFR-MEM (foreign buffers).
- **Standards:** NIST FIPS-197 (AES), SP 800-38D (GCM), FIPS-203 (ML-KEM), FIPS-180-4 (SHA-384),
  SP 800-56C / RFC 5869 (HKDF), CNSA 2.0 (ML-KEM-1024 + AES-256 + SHA-384).

## 1. Goal

Capability 7 of ADR 0021: an always-on, CNSA-2.0 Data-At-Rest Encryption layer so the durability service's
persisted samples are never written in plaintext. CNSA 2.0 mandates **AES-256-GCM** (AEAD), **ML-KEM-1024**
(FIPS-203, key establishment), and **SHA-384**. This slice (3a) builds + proves the encryption envelope + key
management as a `durable-store` decorator over the in-memory backing; the disk-backed store (slice 3b, a MUST
follow-on §10) plugs underneath so the always-on enforcement attaches where "at rest" is real.

## 2. Owner decisions (brainstorm, 2026-06-19)

1. **DARE-first ordering:** build + prove the CNSA-2.0 envelope (store decorator) over the in-memory store
   FIRST; disk is the immediate next slice (3b). "Security-first / integral DARE" — disk holds only sealed
   bytes from its first byte.
2. **Full CNSA-2.0 in this slice:** AES-256-GCM + ML-KEM-1024/FIPS-203 + SHA-384 + key management, all here.
3. **Crypto library:** OpenSSL ≥ 3.5 for all three algorithms (one vetted CFFI surface, one SBOM dep). The
   owner directive "use libsodium if appropriate" resolves to NOT-appropriate here: libsodium lacks ML-KEM and
   SHA-384, OpenSSL ≥ 3.5 covers all three (ML-KEM landed in OpenSSL 3.5 LTS), so adding libsodium just for the
   AEAD is redundant FFI/SBOM surface.
4. **Key management:** a pluggable key-provider vtable (mirrors the durable-store vtable) with a default
   FILE-based provider; the vtable IS the pluggable KMS hook (HSM/cloud-KMS drop in later).

## 3. Engine facts grounding the design (from a code survey)

- The `durable-store` is a closure-vtable (`store.lisp:18-28`): slots `put get-range topics purge open close
  count-fn`; `store-put store topic writer-guid sn key-hash kind payload`; `store-get-range store topic` →
  `durable-record` list (slots `topic writer-guid sn key-hash kind payload`). A decorator wraps an inner store.
- The service-spec selects the store via a 0-arg factory (`spec.lisp`: `:store (lambda () …)`, default
  `make-memory-store`); `make-durability-service` calls it once. A DARE-wrapped store is just a different
  factory: `(lambda () (make-encrypted-store (make-memory-store) (make-file-key-provider …)))`.
- NO crypto is wired (only a hand-rolled MD5 for the control-plane keyhash, `dds-core/md5.lisp` — NOT
  DARE-suitable). `cffi` is already a dependency (`dds-pal.asd`). NO file I/O exists in `src/`.
- The durability service is control-plane (collect loop ~5 ms poll), OFF the measured CDR hot path — so
  blocking OpenSSL FFI + (later) disk I/O do not violate NFR-MEM's static-arena hot-path rule. `make mem`
  stays 0.0000.

## 4. Architecture & module layout

A new standalone **`dds-dare`** ASDF system (pure crypto/DARE, no DDS deps) + a thin decorator in
`dds-durability`:

| Unit | File | Responsibility |
|---|---|---|
| OpenSSL CFFI bindings | `src/dds-dare/openssl-ffi.lisp` | `cffi` bindings to OpenSSL ≥ 3.5 `libcrypto`: EVP AEAD (AES-256-GCM), EVP_PKEY ML-KEM-1024, EVP_MD SHA-384 + HKDF. `dare-available-p` startup check (OpenSSL ≥ 3.5 + ML-KEM present) → hard error if absent. cffi is impl-agnostic → no reader conditionals. |
| Primitives | `src/dds-dare/primitives.lisp` | `defun*` wrappers: `aes-256-gcm-seal/open`, `ml-kem-encapsulate/decapsulate`, `sha-384`, `hkdf-sha384`. Each with a NIST KAT. |
| Envelope | `src/dds-dare/envelope.lisp` | `seal-payload`/`open-payload` — the KEM-DEM envelope (§5). Fail-closed. |
| Key provider | `src/dds-dare/key-provider.lisp` | A key-provider closure-vtable + default `make-file-key-provider :dir` (ML-KEM-1024 keypair, perms-enforced). The KMS hook. |
| Store decorator | `src/dds-durability/store-encrypted.lisp` | `make-encrypted-store inner-store key-provider` → a `durable-store` sealing on `put`, opening on `get-range`, delegating `topics`/`purge`/`count` to `inner` (metadata stays AAD-authenticated cleartext so the inner store indexes/replays without decrypting). |

`dds-dare` deps: `dds-pal` + `dds-core` + `cffi`. `dds-durability` gains a dep on `dds-dare`. New external dep
**OpenSSL ≥ 3.5** — justified (CNSA-2.0 mandates vetted crypto, no hand-rolling; the one library covering all
three algorithms), SBOM-pinned, recorded in `docs/provenance.md`; **OpenSSL ≥ 3.5 is a hard deployment
constraint** (ML-KEM landed there), runtime-checked.

## 5. The CNSA-2.0 envelope + key management

**Per-store keying (KEM-DEM, NIST envelope encryption).** On store open the key-provider yields the
ML-KEM-1024 recipient keypair (CNSA 2.0 = ML-KEM-**1024**, FIPS-203 Level 5). Establish the data key:
- **Encapsulate** to the public key → `(kem-ciphertext, shared-secret)`; **`DEK = HKDF-SHA384(shared-secret,
  info="dds-dare/dek/v1")`** (256-bit). The `kem-ciphertext` is stored once in the store's **key-blob**.
- On open, the provider **decapsulates** `(kem-ciphertext, private-key) → shared-secret → HKDF-SHA384 → the
  same DEK`. The DEK is re-derivable iff you hold the ML-KEM private key (the root of trust). Decapsulation is
  performed inside the provider, so the raw private key need never leave it (an HSM/KMS provider keeps it
  off-process).

**Per-record sealing.** AES-256-GCM under the DEK; a **unique 96-bit counter nonce** per record (a counter,
not random — eliminates the GCM birthday-bound reuse risk within a DEK's life); **AAD = topic ∥
writer-guid(16) ∥ sn(8) ∥ kind** (authenticated, not encrypted — the inner store indexes/replays by these and
any relabel/move is detected); sealed-payload bytes = **`version(1) ∥ nonce(12) ∥ ciphertext ∥ tag(16)`**,
handed to the inner store as the record's payload. Only the CDR payload is encrypted; metadata stays
cleartext-authenticated (metadata confidentiality is a MUST follow-on §10).

**Nonce discipline + the 3a/3b boundary.** This slice keys **one fresh DEK per store-open** (a new
encapsulation each session), counter nonce from 0 — GCM-safe by construction within a session, and the
in-memory store starts empty each run, so no cross-restart reuse. The `version` byte reserves forward-compat
for **3b** (disk), where persisted records outlive an open: 3b adds a **key-epoch** (epoch→kem-ciphertext map,
per-epoch DEK + nonce space) so cross-restart nonce reuse is structurally impossible. NOT built in 3a.

**Key-provider vtable** (mirrors `durable-store`): slots `recipient-public-key`, `decapsulate`, `open`,
`close`. Default `make-file-key-provider :dir` — ML-KEM-1024 keypair in a key dir, generated on first use,
**0600/0700 perms enforced + checked at open** (refuse to open on loose perms), never logged.

**Fail-closed (binding).** `open-payload` returns a hard failure on any GCM auth failure (wrong DEK, tampered
ciphertext/tag/AAD) — never plaintext, never partial. The decorator's `get-range` **drops** a record that
fails to open (counts it, fires a bindable hook), never delivers unauthenticated data. A provider that cannot
decapsulate → the store **fails to open**.

## 6. Threat model & security posture

DARE gives confidentiality + integrity + authenticity of **stored payloads** against an adversary with
read/write access to the store's bytes (3b: disk); tampering is detected (GCM tag + AAD) and fails closed. It
does NOT protect: in-memory plaintext (the service holds payloads in RAM to relay — MUST follow-on §10, with
the feasibility caveat there); data in transit (DDS-Security, MUST follow-on §10); metadata/traffic analysis
(topic/GUID/SN/kind cleartext-authenticated — metadata confidentiality is MUST §10).

Exactly the CNSA-2.0 set (AES-256-GCM, ML-KEM-1024, SHA-384, HKDF-SHA384) — **no hand-rolled crypto**
(FR-SEC-2): OpenSSL provides every primitive; we only wrap + compose (KEM-DEM, HKDF labels, nonce discipline,
AAD) per NIST guidance. Secrets (shared-secret, DEK, private-key buffers) live in **foreign/static buffers**
(explicitly zeroized after use; never logged) — a GC-moved heap array can't be reliably wiped. OpenSSL < 3.5 /
ML-KEM absent → a **hard startup error, never a silent plaintext fallback** (the arena-exhaustion principle).

**Always-on framing.** ADR 0021 cap 7 = always-on/integral. 3a builds + proves the envelope over in-memory
(the proving ground — "at rest" isn't literal for RAM). The always-on enforcement attaches in 3b: the
disk-store factory is hardwired to return a DARE-wrapped store — no plaintext-on-disk code path.

## 7. Error handling

Fail-closed everywhere (§5). OpenSSL FFI errors surfaced, not swallowed. Key-dir perms enforced. DARE-
unavailable → hard error, no silent fallback. A record auth failure → dropped + counted + hook. All new parse
paths (the open path on untrusted sealed bytes) bounds-checked even at `(safety 0)` (NFR-SEC-POSTURE).

## 8. Testing strategy

- **NIST Known-Answer-Tests (the conformance oracle, like the byte-exact CDR corpus):** AES-256-GCM vs NIST
  GCM vectors (byte-exact ct+tag), ML-KEM-1024 vs FIPS-203 KATs (encaps/decaps), SHA-384 vs NIST vectors,
  HKDF-SHA384 vs RFC 5869 / SP 800-56C vectors — pinned regression vectors proving the OpenSSL binding yields
  the correct CNSA-2.0 algorithms.
- **Envelope:** seal→open round-trip; AAD round-trips.
- **Tamper:** flip a byte in ciphertext / tag / nonce / AAD-metadata → fails closed.
- **Wrong key:** a different ML-KEM keypair → different DEK → fails closed.
- **Store decorator:** `durable-record`s seal into the in-memory store + unseal on `get-range` byte-exact; a
  tampered stored record dropped + hook fires; topics/purge/count delegate.
- **Key provider:** file provider generates + reloads the keypair; loose perms → refuse to open.
- **Fuzz (NFR-SEC-POSTURE):** the open path on untrusted/tampered/short/oversized sealed bytes → fail-closed,
  never OOB, `(safety 0)` variant.
- **Gates:** SBCL + Clasp (cffi→libcrypto is impl-agnostic; a documented NFR-PORT skip if Clasp FFI gaps);
  gate-types; no reader conditionals; mem 0.0000 (DARE off the CDR path).
- **Cross-DDS DoD (light, by nature):** DARE adds NO wire-observable surface (the relay emits standard DDS
  samples). The per-feature interop check is a TRANSPARENCY confirmation: a DARE-wrapped durability service
  still delivers correct data to a live foreign late-joiner (Connext/Fast DDS). Correctness substance = the
  NIST KATs.

## 9. Vertical-slice implementation ordering (this slice, 3a)

1. OpenSSL CFFI bindings + `dare-available-p` + primitive wrappers (AES-256-GCM, ML-KEM-1024, SHA-384,
   HKDF-SHA384) + **NIST KATs**.
2. KEM-DEM envelope (`seal-payload`/`open-payload`) + round-trip / tamper / wrong-key tests.
3. Key-provider vtable + file provider + tests.
4. `make-encrypted-store` decorator + the durability-service secure-store wiring + integration test (DARE-
   wrapped service collects→seals→stores→unseals→replays; foreign late-joiner receives correct data
   [transparency]; a tampered record dropped).
5. Open-path fuzz + capstone (ADR, wiki/README/verification, provenance/SBOM, full gate sweep, final review).

Each slice: implement → 2 reviews/task → gates → autonomous branch commits → final whole-branch review →
squash-merge presented for approval, push held.

## 10. MUST follow-on slices (committed — implement asap; owner directive 2026-06-19)

These were the former "out of scope" items; per owner directive they are MUST, sequenced asap (NOT optional,
NOT indefinitely deferred). Each is its own vertical slice (brainstorm→spec→plan→subagent-driven).

1. **(3b) Disk-backed PERSISTENT store + cross-restart key-epoch/nonce discipline** — a file-backed
   `durable-store` surviving process/system restart, ALWAYS DARE-wrapped (no plaintext-on-disk path); the
   key-epoch envelope extension (epoch→kem-ciphertext, per-epoch nonce space) the §5 `version` byte reserves;
   PERSISTENT per-writer lifetime semantics. **MUST — the immediate next slice.** Normal-sized.
2. **(3b, folded) Phase-2 carry-forwards** — live TRANSIENT-tier coexistence proof (RTI Persistence Service
   participates at the TRANSIENT tier), dynamic-topic-add after service start, and pruning the collect-loop
   `seen-data`/`seen-lc` sets (the unbounded-growth NFR-MEM item the Phase-2 final review flagged as a Phase-3
   prerequisite). **MUST — ride slice 3b.** Small.
3. **(3c) Metadata confidentiality** — seal the record metadata (topic/GUID/SN/kind), not just the payload;
   requires an encrypted/independent index so the store still locates records (the current AAD-cleartext model
   forfeits this). **MUST.** Normal-sized, a DARE extension.
4. **In-memory plaintext confidentiality** — minimize plaintext lifetime + `mlock`/zeroize working buffers
   (best-effort; the key material is already foreign-buffered + zeroized in 3a). **MUST, with an honest
   caveat:** full RAM-plaintext confidentiality is not achievable in pure Lisp without OS/hardware support
   (confidential computing / enclaves / page-locking); this MUST is bounded to the achievable near-term piece
   (locked+zeroized key/work buffers, shortest plaintext window) unless the owner adds a hardware/OS target.
   Confidence the full goal is reachable as-is: low.
5. **(M7/P6) DDS-Security — in-transit / wire confidentiality + the five DDS-Security plugins** — the entire
   P6 security milestone (the relay currently emits standard plaintext DDS samples on the wire). **MUST**, but
   honestly a whole milestone, not a small slice; sequence it as its own milestone after the durability
   service's at-rest + persistence slices land.

## 11. Out of scope (genuinely — not durability/DARE)

- The rest of the Connext Professional service suite (Routing/Recording/Cloud-Discovery/Admin-Console/Monitor)
  remains out of scope (ADR 0021) — unchanged by this directive.
