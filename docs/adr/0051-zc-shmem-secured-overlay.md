# ADR 0051 — Confidential Zero-Copy/SHMEM for ENCRYPT-tier writers: the in-slot `data_protection` SecuredPayload overlay

- **Status:** Accepted (WP-SECURITY-ZC-SHMEM-OVERLAY, 2026-07-09) — **NOT cleared for ship, pending counsel (R6)** (the whole Zero-Copy/SHMEM feature area carries the patent-review marker; ADR 0014/0015/0017/0042; `*zerocopy-enabled*` defaults NIL).
- **Deciders:** A0 (integrator), A12 (security), A10 (perf/features)
- **Requires:** REQUIREMENTS FR-PF-3 (Zero-Copy/SHMEM), FR-SEC-* (DDS-Security), NFR-SEC-POSTURE (fail-closed, bounds-checked), NFR-MEM (static/zero steady-state allocation on the non-secured hot path), NFR-CLOS (hot-path purity), NFR-PORT (Clasp + SBCL both validate, Clasp first); the operating contract §4 (never hardcode a wire constant; bounds-check network-facing buffers; clean-room), §6 (no perf change without a before/after measurement).
- **Amends / builds on:** ADR 0031 §4 (the crypto+ZC loud-guard, **relaxed here for the ENCRYPT case**), ADR 0036 Carry 10 (the SHMEM-cleartext governance gate, WP-SECURITY-ZC-SHMEM-CLEARTEXT), ADR 0038 (the zero-alloc `encode/decode-serialized-payload-into` core reused verbatim as the overlay codec; residual (c)), ADR 0042 (the loan-write TX gate — the forward-requirement precedent), ADR 0014/0018 (the WP-ZEROCOPY pool + the ZC reference format the overlay sentinel extends).
- **Resolves:** ADR 0038 residual (c) **for the ENCRYPT case**; confirms ADR 0036 Carry 10 resolved for all confidentiality tiers.
- **Standards reused (no new wire constant):** OMG DDS-Security 1.1 §9.5.3.3 (`SecuredPayload` — Cryptographic-plugin serialized-payload protection); §9.5.3.3.1 (SecureDataHeader); §9.5.3.3.3 (SecureDataTag); §9.5.3.3.4.4 (`encode_serialized_data`, AES256-GCM ENCRYPT tier); §9.5.2 (`KeyMaterial_AES_GCM_GMAC` — the per-writer EntityCrypto key). The overlay **sentinel** is a LOCAL transport discriminator in **our own** ZC reference format (`dds.cdr:+zc-encapsulation-id+`, ADR 0014 — ours, NOT an OMG clause). NIST SP 800-38D (AES-GCM) — the KAT is unchanged. **No RTI Connext source/headers/generated code was read** (clean-room).

---

## Context

Zero-Copy over SHMEM (`*zerocopy-enabled*`, FR-PF-3, ADR 0014) publishes a large sample by copying its
serialized bytes **once** into a per-writer SHMEM sample-pool slot and transmitting a small DATA submessage
that carries only a **20-octet reference body** (in place of the payload) — the whole RTPS datagram is a few
dozen octets (measured 64 for a 16 KiB sample: RTPS header + DATA submessage + the 20-octet reference body),
independent of payload size. ADR 0036 Carry 10 (WP-SECURITY-ZC-SHMEM-CLEARTEXT) closed a
confidentiality leak: the datagram-tier transforms — `rtps_protection` (§8.5.1.10-.12, whole-RTPS) and
`metadata_protection` (§8.5.1.7-.9, user-submessage) — encrypt the *datagram* at send time, so under raw
Zero-Copy they would wrap only the reference while the user payload sat in the pool **in the clear**. The
fix (`%zc-payload-wire-protected-p`, `src/dds-disc/dataplane.lisp`) **disables the raw ZC path entirely**
for any writer whose `rtps_protection_kind` or `metadata_protection_kind` ≠ NONE — fail-closed and correct,
but at the cost that such a writer **forfeits ZC/SHMEM** and eats the full serialize + submessage/SRTPS-wrap
+ SHMEM-ring double-buffer cost on every large sample. ADR 0031 §4 backs this with a general crypto+ZC
loud-guard.

`data_protection` (§9.4.1.2.4) was deliberately **not** gated: it transforms at serialize time
(`publish-sample`), so its pool slot already holds an encrypted `SecuredPayload`. A `data_protection=ENCRYPT`
writer therefore already gets confidential zero-copy SHMEM today (the ADR 0038 T5a path), and the reader's
existing `%deliver-user-sample` decode handles it.

So the gap is narrow and precise: **a writer whose governance mandates `rtps_protection` or
`metadata_protection` confidentiality (ENCRYPT), with `data_protection` = NONE, cannot use ZC/SHMEM** — even
though the exact `SecuredPayload` mechanism that makes `data_protection` ZC-safe is already sitting in the
codebase, zero-alloc and byte-exact-tested. This ADR records closing that gap.

## Decision

**Relax the ADR 0031 §4 crypto+ZC loud-guard for the ENCRYPT-tier case.** An **overlay-eligible** writer —
wire-protected (rtps/metadata ENCRYPT), `data_protection` = NONE, with a resolvable ENCRYPT EntityCrypto
`key-material` — MAY use ZC/SHMEM by sealing the serialized payload **into the pool slot as a
`data_protection` `SecuredPayload`** under its own per-writer EntityCrypto key. The slot then holds
ciphertext; a co-resident process mapping the segment recovers only an AES-256-GCM ciphertext+tag. The read
side decodes it **copy-on-read** and delivers the plaintext. Every other governance combination is
unchanged (see the routing table). This is a **transport-routing + in-slot-format** decision, not a
codec or a wire-format change: the overlay bytes are the identical, already byte-exact-tested §9.5.3.3
`SecuredPayload`, and non-overlay ZC references stay byte-identical.

### 1. Key — reuse the per-writer EntityCrypto key (no new key, no new exchange)

Every local user writer already has a per-writer EntityCrypto `key-material` minted by
`cm-register-local-entity` and shipped to every matched reader unconditionally as a
`datawriter_crypto_tokens` CryptoToken over the volatile-secure endpoint. For an ENCRYPT-tier writer this
KM's transformation kind is `:encrypt` (AES256-GCM, {0,0,0,4}) — a usable confidentiality key
(`dds.security:key-material-encrypt-p`, the negation of `%km-gmac-p`, DRY). A matched reader registers that
KM by the writer's GUID and resolves it through the node's `crypto-keys` decode-fn. **No new key material,
no new derivation, no new exchange.**

### 2. In-slot format — a `data_protection` `SecuredPayload` (§9.5.3.3)

The overlay bytes are exactly a `data_protection` ENCRYPT `SecuredPayload` as produced by the zero-alloc
`encode-serialized-payload-into` (ADR 0038, `src/dds-security/transform.lisp`): SecureDataHeader(20) =
kind(4) ‖ key_id(4) ‖ session_id(4) ‖ iv_suffix(8), then crypto_content.length(4, BE) ‖ ciphertext(N) ‖
common_mac/tag(16) ‖ 4-align pad ‖ receiver_specific_macs_count(4, BE = 0); total 44 + N + pad. **No new
format** — the identical, byte-exact-tested codec.

### 3. Write path — seal into scratch, `%zc-loan` into the slot

At `%zc-change-item`, when `%zc-overlay-eligible-p` is T (the new predicate beside
`%zc-payload-wire-protected-p`), the writer seals the serialized payload into a per-writer static scratch
buffer via `encode-serialized-payload-into`, hands the resulting `SecuredPayload` bytes to `%zc-loan` as the
slot payload (identical to how a `data_protection` writer's already-encrypted payload reaches the slot), and
emits the reference datagram with the **overlay sentinel** set. An over-slot payload (SecuredPayload
> slot-bytes) fails **closed** to NIL (the sample takes the normal serialize path), never signals a
buffer-overflow. The reference datagram continues through the normal rtps/metadata send wrap.

> **The writer-side copy.** Sealing into scratch then `%zc-loan`-copying into the slot is one memcpy — the
> same copy the raw ZC path already performs. We do **not** seal directly into the SHMEM SAP in this slice:
> the into-buffer AEAD FFI consumes a static-vector-backed buffer, not a bare foreign SAP. A future
> `-into-sap` FFI variant that seals straight into the slot (eliminating this copy) is a recorded follow-on
> (§Deferred).

### 4. The discriminator — the reference-datagram reserved field (integrity-protected)

`parse-zc-reference` (`src/dds-cdr/cdr.lisp`) previously read-and-ignored the `reserved` u32 at
reference-body offset 16. It is repurposed as an **overlay sentinel** `+zc-ref-overlay-secured+` (value 1):
0 = raw (existing behaviour, byte-identical), 1 = "this slot holds a `data_protection` `SecuredPayload`
overlay." `encode-zc-reference` sets it; `parse-zc-reference` returns it as a fourth value.

**Why the reference datagram, not a slot-header flag:** the reference travels *inside* the rtps/metadata
wrap and is therefore integrity-protected — a SHMEM-resident attacker cannot flip the flag to defeat
decryption and make the reader treat ciphertext as plaintext. A slot-header flag would live in
attacker-writable shared memory. The 32-byte slot header's spare bytes are left untouched. Non-overlay
samples keep `reserved = 0` → **wire byte-identical**; overlay references travel only between our own
same-vendor participants, and `parse-zc-reference` is forward/backward compatible (0 ⇒ no overlay).

### 5. Read path — copy-on-read decode regardless of the reader's own governance

At `%zc-try-resolve` (copy-on-read), after resolving the slot bytes: if the parsed reference carries the
overlay sentinel, decode the resolved bytes as a `data_protection` `SecuredPayload` using the
**remote-writer** EntityCrypto KM (resolved by the writer GUID through the node's `crypto-keys` decode-fn),
producing the plaintext for delivery. This decode is applied **regardless of the reader's own
`data_protection` governance kind** — an rtps/metadata-only reader has `data_protection` = NONE but must
still decode the overlay. **Fail-closed:** a missing KM (reader not yet keyed) or a failed GCM
authentication (tampered slot) **drops** the sample with `%secured-decode-fail` accounting, mirroring the
existing secured-decode failure handling, and delivers nothing. Loan-capable (literal-zero-copy) readers
are forced onto copy-on-read for overlay references (`%zc-defer` declines the marker), because a
`flatdata-view` cannot read fields directly off an encrypted slot.

### 6. Nonce uniqueness

`encode-serialized-payload-into` advances the writer EntityCrypto KM's monotonic, lock-guarded `iv-counter`
via `%km-next-iv-suffix-into`. Nonce uniqueness per (key, session_id) holds because **every consumer of the
writer's EntityCrypto key resolves the SAME `key-material` object, and that object has a SINGLE monotonic,
lock-guarded `iv-counter`** — so each encode (the overlay seal AND, for `metadata_protection=ENCRYPT`, the
submessage wrap) draws a distinct counter value ⇒ a distinct IV ⇒ no (key, nonce) reuse. This is the
correct rationale precisely because a `metadata_protection=ENCRYPT`-tier writer's EntityCrypto counter has
**two** consumers, not one: the `metadata_protection` submessage wrap of the reference DATA resolves its key
via `cm-encode-entity-km cm user-writer-id` (`crypto-manager.lisp:834`, DDS-Security 1.1 §8.5), and the
overlay resolves via `%zc-overlay-km` → `crypto-keys` `encode-key-fn` → `cm-encode-entity-km cm
user-writer-id` (`crypto-manager.lisp:418`); `cm-register-local-entity` mints exactly ONE KeyMaterial per
entity-id (idempotent get-or-create), so both resolve the **identical** KM object and both draw from its one
shared counter. Only `rtps_protection` uses the separate *participant* KM — a different object with its own
counter.

> **Warning (tie to the Forward Requirement above).** Do NOT assume the overlay is the sole consumer of the
> EntityCrypto counter, and do NOT assume the participant KM is the only other consumer of the writer's key.
> Nonce safety rests on all consumers **sharing one KM object** with its single `iv-counter`. A future
> optimization that introduced a **second copy** of the EntityCrypto KM (rather than sharing the one object)
> would give each copy its own counter and **silently reintroduce catastrophic AES-GCM (key, nonce) reuse**.
> Any such change MUST preserve the single-shared-KM invariant.

## Gate / routing summary

| Writer governance | `data_protection` | ZC path before | ZC path after this ADR |
|---|---|---|---|
| all NONE | NONE | raw ZC | raw ZC (unchanged) |
| `data_protection`=ENCRYPT | ENCRYPT | ZC, slot = SecuredPayload | unchanged |
| rtps/metadata = ENCRYPT | NONE | **disabled** (gated off) | **ZC via in-slot overlay (new)** |
| rtps/metadata = SIGN only | NONE | disabled | disabled (**deferred follow-on** — SIGN is not confidential) |
| loan-write (FlatData TX) | any protected | disabled | disabled (unchanged, ADR 0042) |

## Forward requirement (a gate obligation on every future WP)

**Any future in-slot write site MUST apply the same overlay-or-gate discipline at its write site, or the
SHMEM-cleartext leak reopens for secured writers.** Concretely: a new `-into-sap` direct-seal optimization,
a new loan-write variant, or any other code path that places serialized user bytes into a pool slot for a
wire-protected writer MUST either (a) seal them as a `data_protection` `SecuredPayload` overlay under the
per-writer EntityCrypto key and set the overlay sentinel (as here), or (b) route the writer to the gated-off
serialize path (`%zc-payload-wire-protected-p`, ADR 0036 Carry 10). Record this in that WP's acceptance
criteria. This mirrors the ADR 0036 Carry 10 forward requirement that ADR 0042 discharged for the
loan-write TX site.

## Deferred follow-ons (recorded, NOT built here)

1. **SIGN-only raw-ZC relaxation. — CLOSED 2026-07-11 (ADR 0058), but NOT as written here.** The reasoning
   below is **wrong** and is superseded: it argues only about *confidentiality* and silently drops
   *integrity*. With raw ZC the RTPS signature covers only the 20-octet reference datagram, so the slot
   payload would be **unauthenticated** — a co-resident process could tamper with it undetected, dropping the
   one guarantee the SIGN tier exists to provide. ADR 0058 instead extends the **overlay** to SIGN: the
   payload stays visible in the slot (as SIGN intends) and carries a GMAC `common_mac` the reader verifies
   fail-closed. *(Original text, kept for provenance: "A SIGN tier authenticates but does not hide the
   payload — the payload is visible on the wire, so plaintext-in-SHMEM is not a new exposure. The current
   gate blocks SIGN-only ZC conservatively; relaxing it to raw ZC (no overlay needed) is a follow-on.")*
2. **`-into-sap` direct-seal. — CLOSED 2026-07-11 (ADR 0058): DECLINED on measurement.** The scratch→slot
   memcpy this would remove is only **2.6–4.5 %** of the overlay's send cost (the AEAD pass dominates it by
   ~25×; `bench/report/2026-07-11-zc-overlay-into-sap.md`). A ~3 % gain on an opt-in edge path does not
   justify forking the one sealing primitive every `data_protection` tier depends on onto a second,
   SAP-writing code path, nor sealing into shared memory. Re-open if the AEAD ever stops dominating (see
   ADR 0058 §3).
3. **Multi-writer / per-endpoint overlay keying.** The overlay keys on the single per-writer EntityCrypto KM
   (N = 1 writer today). A multi-writer / per-endpoint overlay-keying generalization is a follow-on if the
   per-endpoint protection-kind model (ADR 0046) ever needs distinct overlay keys per user endpoint.

## Consequences

- **ADR 0038 residual (c) → RESOLVED for the ENCRYPT case.** The Zero-Copy × `rtps_protection`/`metadata_protection`
  SHMEM-cleartext residual is closed for confidentiality (ENCRYPT) tiers: such a writer now gets ZC with the
  payload confidential in the slot. SIGN-only stays gated (deferred follow-on 1).
- **ADR 0036 Carry 10 confirmed resolved for all confidentiality tiers.** The leak stays closed: a
  wire-protected writer either seals the overlay (ENCRYPT) or is gated off (SIGN, loan-write). No cleartext
  user payload lands in SHMEM in any path.
- **NFR-SEC-POSTURE:** fail-closed on missing KM and on GCM auth failure (tampered slot); the overlay codec
  is the bounds-checked, fail-closed `decode-serialized-payload-into`; the sentinel is integrity-protected
  inside the wire wrap.
- **NFR-MEM / hot-path purity:** the non-secured raw ZC path is **untouched** — byte-identical and zero-alloc
  (`make gate-hotpath` green). The overlay adds one AEAD seal (zero-cons, ADR 0038) + the pre-existing
  writer-side memcpy on the ENCRYPT path only.
- **NFR-PORT:** no new reader conditional outside `dds-pal/`; both impls validate (Clasp first). Part B/C/D
  of the test skip cleanly where the SHMEM pool is not carved (Clasp/macOS by-name-attach gap, ADR 0013).
- **Interop / wire posture:** ZC/SHMEM is intra-host, same-vendor; a cross-vendor peer never receives a ZC
  reference. Non-overlay references stay `reserved = 0` (byte-identical). The byte-exact XCDR corpus, the
  security corpora, the NIST AES-GCM KATs, and the Connext 7.x + Fast DDS interop tests are **unchanged** —
  there is no observable cross-vendor wire surface added (the cross-DDS-interop-per-feature obligation is
  satisfied by "no wire surface added," exactly as WP-SECURITY-ZC-SHMEM-CLEARTEXT recorded "wire
  byte-identical").
- **Clean-room:** no wire constant invented — the `SecuredPayload` layout and AES-GCM parameters are reused
  verbatim from the existing spec-pinned codec; the overlay sentinel is a local transport discriminator in
  our own ZC reference format, not an OMG wire constant.

## Test

`dds.disc:run-zc-shmem-secured-overlay-test` (registered as `"zc-shmem-secured-overlay"`), both impls
(Clasp first), non-vacuous:

- **Part A (deterministic, portable):** an ENCRYPT EntityCrypto KM makes `%zc-overlay-eligible-p` T; no KM →
  fail-closed NIL; a GMAC (SIGN) payload key → NIL (deferred); an over-slot SecuredPayload fails closed to
  NIL (never a buffer-overflow).
- **Part B (SHMEM-gated live segment):** the non-secured control's plaintext IS present in the pool segment
  (non-vacuity); the ENCRYPT overlay slot holds ciphertext — the plaintext marker is provably ABSENT — and
  `disc-node-zc-sends` advances (the overlay DID take ZC).
- **Part C (full loopback read side):** a governance-NONE reader attaches the writer's pool, resolves the
  overlay reference through the real receive path (`%msg-datagram` → `%rtps-feed-datagram`), and recovers
  the plaintext byte-exact via the copy-on-read decode.
- **Part D (fail-closed):** a reader with no EntityCrypto key drops the sample (no delivery, no crash); a
  one-octet ciphertext tamper in the sealed slot fails the AES-GCM tag → `%secured-decode-fail` advances,
  nothing delivered.

**On the overlay-sentinel integrity (threat-model item §4 — an attacker cannot flip the decode decision).**
Parts C/D drive the reference DATA through `%rtps-feed-datagram` **without** the production
metadata/rtps SRTPS wrap, so the sentinel's integrity is established **structurally by the code**, not by an
end-to-end wrap→unwrap test: `%zc-try-resolve` reads the overlay flag **only** from the received DATA
submessage via `parse-zc-reference`, **never** from the attacker-writable slot header — and in production
that submessage rides inside the integrity-protected metadata/rtps wrap (the same wrap the writer's
governance mandates). A SHMEM-resident attacker therefore has no writable copy of the flag to flip. The
structural argument is airtight; adding a full wrap→unwrap arm would exercise the SRTPS codec (already
covered by the security corpora), not the routing decision this ADR introduces.

## References

- Design spec: `docs/superpowers/specs/2026-07-09-zc-shmem-secured-overlay-design.md`
- `src/dds-cdr/cdr.lisp` — `+zc-ref-overlay-secured+`, `encode-zc-reference` / `parse-zc-reference` (the 4th value)
- `src/dds-disc/dataplane.lisp` — `%zc-overlay-eligible-p`, the `%zc-change-item` overlay write arm, the `%zc-try-resolve` overlay decode, the `%zc-defer` decline
- `src/dds-security/transform.lisp` — `key-material-encrypt-p`; the reused `encode/decode-serialized-payload-into`
- `src/dds-disc/secure-sedp.lisp` — `run-zc-shmem-secured-overlay-test`
- `docs/wiki/security.md` §3.8, `docs/wiki/transports.md` (Zero-Copy security gate) — the use-case + worked example
- `bench/report/2026-07-09-zc-shmem-secured-overlay.md` — the copy/datagram profile
- ADR 0031 (§4 loud-guard), ADR 0036 (Carry 10), ADR 0038 (residual (c) + the zero-alloc codec), ADR 0042 (the forward-requirement precedent), ADR 0014/0018 (WP-ZEROCOPY pool + reference format)
