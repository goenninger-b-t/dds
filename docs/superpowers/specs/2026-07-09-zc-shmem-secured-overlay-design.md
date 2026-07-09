# Confidential Zero-Copy/SHMEM for ENCRYPT-tier writers — design

**WP:** WP-SECURITY-ZC-SHMEM-OVERLAY
**ADR:** 0051 (new)
**Date:** 2026-07-09
**Requirement lineage:** ADR-0038 residual (c); ADR-0036 Carry 10; ADR 0031 §4 (crypto+ZC loud-guard); ADR 0042 (FlatData loan-write gate).
**Status:** approved (owner, 2026-07-09) — proceed to implementation plan.

---

## 1. Problem

The zero-copy/SHMEM transport carries a large sample by placing its serialized bytes
in a shared-memory pool slot and sending only a 20-octet *reference* datagram over the
wire. Confidentiality of the in-slot bytes is governed by `%zc-payload-wire-protected-p`
(`src/dds-disc/dataplane.lisp:883`), which **disables the ZC path entirely** for any
writer whose `rtps_protection_kind` or `metadata_protection_kind` ≠ NONE. Those two tiers
encrypt the *datagram* at send time, not the serialized payload — so if such a writer used
ZC, the pool slot would hold the user payload in the clear and a co-resident process
mapping the segment could recover it. The gate is fail-closed and correct; the cost is that
an rtps/metadata-protected writer forfeits ZC/SHMEM and eats the full serialize + SHMEM-ring
double-buffer cost on every large sample.

`data_protection` is deliberately **not** gated: it transforms at serialize time, so its
pool slot already holds an encrypted `SecuredPayload`. A `data_protection=ENCRYPT` writer
therefore already gets confidential zero-copy SHMEM today, and the reader's existing
`%deliver-user-sample` decode handles it.

So the gap is narrow and precise: **a writer whose governance mandates `rtps_protection` or
`metadata_protection` confidentiality (ENCRYPT) cannot use ZC/SHMEM.** This slice closes
that gap by reusing the `data_protection` `SecuredPayload` mechanism as an in-slot overlay.

## 2. Threat model (unchanged from ADR-0036 Carry 10)

- **Co-resident SHMEM reader** (a process on the same host mapping the writer's pool
  segment): must never recover the plaintext user payload. *Closed here* by encrypting the
  in-slot bytes.
- **Co-resident SHMEM writer** (a process that can overwrite slot bytes): must not be able
  to inject a payload the matched reader accepts. *Closed* by the AES-GCM tag — a tampered
  slot fails authentication and is dropped fail-closed.
- **Network eavesdropper**: sees only the rtps/metadata-wrapped 20-octet reference datagram
  (never the SHMEM payload). Unchanged.
- **Discriminator tamper** (an attacker trying to make the reader treat ciphertext as
  plaintext): the "this slot is an overlay" flag lives *inside* the wire-protected reference
  datagram, so it is integrity-protected and cannot be flipped by a SHMEM-resident attacker.

## 3. Scope

**In scope (MVP vertical slice):**
- Writers with `rtps_protection_kind = ENCRYPT` **or** `metadata_protection_kind = ENCRYPT`,
  `data_protection` = NONE/unset, ZC enabled, payload > `*zerocopy-min-payload-bytes*`, with a
  matched co-located ZC-capable reader.
- The classic **copy-on-read** delivery path (`%zc-try-resolve` → `%deliver-user-sample`).

**Out of scope / explicitly deferred:**
- **SIGN-only tiers.** A SIGN tier authenticates but does not hide the payload — the payload
  is visible on the wire, so plaintext-in-SHMEM is not a *new* exposure. The current gate
  blocks SIGN-only ZC conservatively; relaxing it to raw ZC (no overlay needed) is a
  follow-on, out of this slice.
- **The literal-zero-copy `flatdata-view` loan path** (`%zc-defer` / loan-capable readers).
  A reader cannot consume ciphertext in place; decryption requires a reader-private output
  buffer. Overlay slots are forced onto copy-on-read. This is the accepted "zero-copy →
  single-copy" floor — physics, not a defect.
- **Cross-vendor interop.** ZC/SHMEM is a same-host, same-vendor transport between two of our
  own participants; a Connext / Fast DDS peer never receives a ZC reference. The overlay is
  same-vendor by construction and adds no wire surface (see §7).
- **`data_protection` writers** — already covered by the existing ungated path; untouched.
- **Mixed governance where `data_protection` is non-NONE** — the existing serialize-time
  path applies; no overlay.

## 4. Design

### 4.1 Key — reuse the per-writer EntityCrypto key

Every local user writer already has a per-writer EntityCrypto `key-material` minted by
`cm-register-local-entity` (`src/dds-dcps/crypto-manager.lisp:132`), and it is shipped to
every matched reader unconditionally as a `datawriter_crypto_tokens` CryptoToken over the
volatile-secure endpoint (`crypto-manager.lisp:649–656`). For an ENCRYPT-tier writer,
`%cm-entity-protection-kind` (`crypto-manager.lisp:273`) resolves the KM's transformation
kind to `:encrypt` (AES256-GCM) — a usable confidentiality key. A matched reader registers
that KM by the writer's GUID via `cm-register-matched-remote-entity` and resolves it through
the `crypto-keys` decode-fn. **No new key, no new derivation, no new exchange.**

### 4.2 In-slot format — a `data_protection` `SecuredPayload`

The overlay bytes are exactly a `data_protection` ENCRYPT `SecuredPayload` as produced by
`encode-serialized-payload-into` (`src/dds-security/transform.lisp:194`):

```
SecureDataHeader(20) = kind(4) ‖ key_id(4) ‖ session_id(4) ‖ iv_suffix(8)
  ‖ crypto_content.length(4, BE)
  ‖ ciphertext(N)
  ‖ common_mac / tag(16)
  ‖ 4-align pad
  ‖ receiver_specific_macs_count(4, BE = 0)
Total = 44 + N + pad
```

No new format is introduced — this is the identical, already byte-exact-tested `SecuredPayload`.

### 4.3 Write path

In `%zc-change-item` (`dataplane.lisp:1036`), the current gate returns NIL (disables ZC)
when `%zc-payload-wire-protected-p` is true. New behavior: when the writer is
**overlay-eligible** — wire-protected, ENCRYPT-tier, has a resolvable ENCRYPT EntityCrypto
KM, `data_protection` NONE — the writer instead:

1. Seals the serialized payload into a per-writer static scratch buffer via
   `encode-serialized-payload-into <scratch> <writer-EntityCrypto-KM> <plaintext>` (the
   existing zero-alloc AEAD; scratch drawn from a pool mirroring `submsg-scratch-pool`).
2. Hands the resulting `SecuredPayload` bytes to `%zc-loan` as the slot payload — identical
   to how a `data_protection` writer's already-encrypted payload reaches the slot.
3. Emits the reference datagram with the **overlay sentinel** set (§4.4).

The wire reference datagram continues through the normal rtps/metadata send wrap. The slot
now holds ciphertext; no user plaintext lands in SHMEM.

> **Note on the writer-side copy.** Sealing into scratch then `%zc-loan`-copying into the
> slot is one memcpy — the same copy the raw ZC path already performs (`%zc-loan`
> zerocopy-pool.lisp:180). We do **not** seal directly into the SHMEM SAP in this slice: the
> into-buffer AEAD FFI consumes a static-vector-backed buffer, not a bare foreign SAP. A
> future `-into-sap` FFI variant that seals straight into the slot (eliminating this copy) is
> a recorded follow-on, not part of the MVP.

### 4.4 The discriminator — reference-datagram reserved field

`parse-zc-reference` (`src/dds-cdr/cdr.lisp:116`) currently returns `(slot-index,
generation, slot-bytes)` and reads-and-ignores the `reserved` u32 at reference-body offset
16. We repurpose that field as an **overlay sentinel**: 0 = raw (existing behavior), a fixed
non-zero marker = "slot holds a `data_protection` `SecuredPayload` overlay." `encode-zc-reference`
(`cdr.lisp:100`) sets it; `parse-zc-reference` returns it as a fourth value.

Rationale (why the reference datagram, not the slot header): the reference travels *inside*
the rtps/metadata wrap and is therefore integrity-protected — a SHMEM-resident attacker
cannot flip the flag to defeat decryption. A slot-header flag would live in attacker-writable
shared memory. The 32-byte slot header's spare bytes are left untouched.

Wire compatibility: non-overlay samples keep `reserved = 0` → byte-identical. Overlay samples
carry a non-zero reserved value, but such references only ever travel between our own
participants (ZC is same-vendor), and our own `parse-zc-reference` is forward/backward
compatible (0 ⇒ no overlay).

### 4.5 Read path

In `%zc-try-resolve` (`dataplane.lisp:2311`, copy-on-read), after resolving the slot bytes:
- If the parsed reference carries the overlay sentinel, decode the resolved bytes as a
  `data_protection` `SecuredPayload` using the **remote-writer** EntityCrypto KM (resolved by
  the remote-writer GUID through the node's `crypto-keys` decode-fn), producing the plaintext
  for delivery. This decode is applied **regardless of the reader's own `data_protection`
  governance kind** (an rtps/metadata-only reader has `data_protection` = NONE but must still
  decode the overlay).
- Missing KM (reader not yet keyed) or failed GCM authentication ⇒ **fail-closed drop** +
  `%secured-decode-fail` accounting, mirroring the existing secured-decode failure handling.

Loan-capable (literal-zero-copy) readers are forced onto the copy-on-read path for overlay
references (`%zc-defer` declines the marker when the overlay sentinel is set), because the
`flatdata-view` reads fields directly off the (encrypted) slot.

### 4.6 Nonce uniqueness

`encode-serialized-payload-into` advances the writer EntityCrypto KM's monotonic,
lock-guarded `iv-counter` (`transform.lisp:49`). When `data_protection` = NONE, the overlay
encode is the *only* consumer of that KM's counter (the rtps/metadata wire wrap uses the
participant KM, not the EntityCrypto KM). Nonce uniqueness per (key, session_id) is therefore
structural. Sending the same cache-change to both a remote reader (wire wrap, participant KM)
and a local reader (overlay, EntityCrypto KM) advances only the EntityCrypto counter once for
the overlay; the two encodings are independent and both yield the same plaintext on decode.

## 5. Gate / routing summary

| Writer governance | `data_protection` | ZC path today | ZC path after this slice |
|---|---|---|---|
| all NONE | NONE | raw ZC | raw ZC (unchanged) |
| `data_protection`=ENCRYPT | ENCRYPT | ZC, slot = SecuredPayload | unchanged |
| rtps/metadata = ENCRYPT | NONE | **disabled** | **ZC via in-slot overlay (new)** |
| rtps/metadata = SIGN only | NONE | disabled | disabled (deferred follow-on) |
| loan-write (FlatData TX) | any protected | disabled | disabled (unchanged) |

## 6. Components & boundaries

- `src/dds-cdr/cdr.lisp` — `encode-zc-reference` / `parse-zc-reference`: carry the overlay
  sentinel (4th value). Purely additive; `reserved=0` path byte-identical.
- `src/dds-disc/dataplane.lisp` — write-site routing in `%zc-change-item`
  (overlay-eligibility predicate + seal-into-scratch); read-site decode in `%zc-try-resolve`;
  `%zc-defer` decline for overlay references; a new `%zc-overlay-eligible-p` predicate beside
  `%zc-payload-wire-protected-p`.
- `src/dds-disc/disc.lisp` — a per-writer overlay scratch pool/arena/lock mirroring the
  existing `submsg-scratch-pool` triple (`disc.lisp:463`), if the send scratch pools are not
  reusable as-is.
- `src/dds-security/transform.lisp` — reused unchanged (`encode/decode-serialized-payload-into`).
- `src/dds-dcps/crypto-manager.lisp` — reused unchanged (EntityCrypto KM mint + token ship +
  remote registration + `crypto-keys` resolvers).

No interface package outside the A0-owned contracts changes shape; the CDR reference
encode/parse gains one optional/return value (additive). ADR 0051 records the ADR 0031 §4
loud-guard relaxation.

## 7. Interop & wire posture

The feature is **intra-host, same-vendor**: ZC/SHMEM engages only between two hofvarpnir
participants on one host. A cross-vendor peer receives the normal UDP/wire path, never a ZC
reference. Non-overlay samples keep `reserved = 0` (wire byte-identical); overlay references
are exchanged only between our own participants. Therefore:
- The byte-exact XCDR corpus, the security corpora, and the NIST AES-GCM KATs are **unchanged**.
- The existing Connext 7.x + Fast DDS interop tests are **unaffected** (no wire-surface change
  a peer can observe).
- The cross-DDS-interop-per-feature rule is satisfied by *"no observable wire surface added"* —
  there is no cross-vendor wire behavior to validate, exactly as WP-SECURITY-ZC-SHMEM-CLEARTEXT
  recorded "Wire byte-identical."

## 8. Testing

New test `run-zc-shmem-secured-overlay-test`, patterned on `run-zc-shmem-secured-cleartext-test`,
non-vacuous, on **both impls (Clasp first)**:
- **Part A (functional):** an ENCRYPT-tier (metadata_protection=ENCRYPT, data_protection=NONE)
  ZC writer publishes a large sample to a matched co-located reader; assert the reader delivers
  the correct plaintext.
- **Part B (leak-proof, non-vacuous):** inspect the live pool slot and assert the plaintext
  marker is **provably absent** (ciphertext present), with a non-secured control sample whose
  plaintext **is** present in its slot. Written RED against the pre-change (gated-off / would-be
  plaintext) behavior.
- **Fail-closed:** a reader without the writer's EntityCrypto KM, and a tampered slot (flip a
  ciphertext byte), both drop with `%secured-decode-fail` incremented and no delivery.
- Regression: `run-zc-shmem-secured-cleartext-test` and all ZC/SHMEM + security regressions stay
  green; `make gate-hotpath` (no per-sample alloc introduced on the non-secured hot path) and
  `make corpus` unchanged.

## 9. Performance

Expected win: on large ENCRYPT-tier samples, skip the serialize + SHMEM-ring double-buffer;
pay one writer-side memcpy (already present in raw ZC) + one AEAD seal, and one reader-side
decrypt-copy. Bench: publish a stream of large (e.g. 16 KiB) ENCRYPT-tier samples ZC vs the
current gated-off (serialize+ring) path; record datagram/copy counts + p50/p99 latency into
`bench/report/2026-07-09-zc-shmem-secured-overlay.md`. No perf claim lands without before/after
numbers (FR-LANG-7). The non-secured ZC path must be byte-identical + zero-alloc (gate-hotpath).

## 10. ADR 0051 content

- Relax the ADR 0031 §4 crypto+ZC loud-guard for the **ENCRYPT-tier** case: ZC is permitted via
  the in-slot `data_protection` `SecuredPayload` overlay under the per-writer EntityCrypto key.
- Flip ADR-0038 residual (c) and confirm ADR-0036 Carry 10 to **resolved for the ENCRYPT case**.
- **Forward requirement:** any future in-slot write site (e.g. an `-into-sap` direct-seal
  optimization, or a new loan-write variant) MUST apply the same overlay-or-gate discipline at
  its write site, or the SHMEM-cleartext leak reopens. Record in that WP's acceptance criteria
  (mirrors the ADR-0036 Carry 10 forward requirement that ADR 0042 discharged).
- **Deferred follow-ons:** (a) SIGN-only raw-ZC relaxation; (b) `-into-sap` direct-seal to
  eliminate the writer-side scratch memcpy.

## 11. Definition of Done

- Both impls green (Clasp first), new test + all regressions.
- `make gate-hotpath`, `make corpus`, security corpora, NIST KATs unchanged/green.
- ADR 0051 written; ADR-0038(c) + ADR-0036 Carry 10 cross-references updated.
- Docstrings for every added/changed exported symbol; `docs/wiki/` (security + zero-copy pages)
  + `README.md` status; `docs/verification.csv` row.
- Before/after bench in `bench/report/`.
- SBOM current (pre-commit hook).
- Clean-room: no wire constant invented — the `SecuredPayload` layout and AES-GCM parameters are
  reused verbatim from the existing spec-pinned codec; the overlay sentinel is a local transport
  discriminator (our own ZC reference format), not an OMG wire constant.
