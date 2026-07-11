# ADR 0058 — The ZC/SHMEM overlay serves the SIGN tier too (not raw ZC); the `-into-sap` direct seal is declined on measurement

Status: Accepted
Date: 2026-07-11
Work package: post-WP tracked-residual close-out (owner-directed item 6)
Relates to: ADR 0051 (the in-slot `data_protection` SecuredPayload overlay — this closes **both** of its deferred follow-ons 1 and 2, and **corrects the rationale** of follow-on 1); ADR 0036 Carry 10 (the ZC × wire-protection SHMEM-cleartext gate); ADR 0042 (the loan-write acquire/commit slot protocol); ADR 0038/0039 (the zero-alloc AEAD foundation this reuses verbatim)

## 1. Context

ADR 0051 gave a **wire-protected ENCRYPT-tier writer** its Zero-Copy back: instead of being gated off
(ADR 0036 Carry 10 — a raw ZC payload would sit in SHMEM in the clear while only the 20-octet reference
datagram gets RTPS-wrapped), such a writer seals its payload as a `data_protection` SecuredPayload
**into the pool slot** under its per-writer EntityCrypto key. It left two follow-ons:

1. **SIGN-only raw-ZC relaxation.** *"A SIGN tier authenticates but does not hide the payload — the
   payload is visible on the wire, so plaintext-in-SHMEM is not a new exposure. The current gate blocks
   SIGN-only ZC conservatively; relaxing it to raw ZC (no overlay needed) is a follow-on."*
2. **`-into-sap` direct-seal.** An into-SAP AEAD variant sealing straight into the slot, removing the
   one writer-side scratch→slot memcpy. *"A strict optimization."*

## 2. Decision 1 — SIGN gets the overlay, **not** raw ZC. ADR 0051's stated rationale was wrong.

**A SIGN-only wire-protected writer is now overlay-eligible** (`%zc-overlay-eligible-p` no longer demands
`key-material-encrypt-p`; it asks only whether an EntityCrypto KM resolves). Its payload is sealed as a
**GMAC** `SecuredPayload` into the slot: the payload stays **visible** — exactly as the SIGN tier leaves it
visible on the wire — and carries a `common_mac` the reader verifies **fail-closed**.

ADR 0051's follow-on-1 reasoning is **rejected**. It argued only about **confidentiality** ("plaintext in
SHMEM is not a new exposure") and silently dropped **integrity**:

> With raw ZC, the RTPS signature covers only the **20-octet reference datagram**. The payload lives in
> the SHMEM slot, **outside everything the SIGN tier signs**. A co-resident process could tamper with the
> slot bytes and the reader would accept the sample — the signature still verifies, because it never
> covered the payload. Raw ZC would therefore **silently drop the one guarantee the SIGN tier exists to
> provide.**

The SIGN tier promises authenticity, not secrecy. Relaxing it to raw ZC honours the *secrecy* it never
promised and discards the *authenticity* it did. The overlay costs one AEAD pass and keeps both properties
aligned with the configured governance:

| governance (data_protection = NONE) | slot content | confidential? | authenticated? |
|---|---|---|---|
| rtps/metadata = **ENCRYPT** | ciphertext (GCM) | yes | yes (GCM tag) |
| rtps/metadata = **SIGN** | visible payload + `common_mac` (GMAC) | no — as SIGN intends | **yes** |
| rtps/metadata = SIGN, *raw ZC* (the rejected option) | visible payload, bare | no | **NO — regression** |

**This is a gate relaxation, not new crypto.** `encode-serialized-payload-into` already implements both
sub-tiers (§9.5.3.3.4.3 GMAC / §9.5.3.3.4.4 GCM), and the reader's decode is gated on the overlay
*sentinel*, not on the tier — so the SIGN path reuses the ADR 0038/0039 zero-alloc foundation verbatim.

**The single-shared-KM nonce invariant (ADR 0051 Forward Requirement) still holds** and is load-bearing
here too: GMAC is AES-GCM with an empty plaintext, so it consumes the *same* `iv-counter` and would be
just as catastrophically broken by (key, nonce) reuse. The overlay and the submessage wrap continue to
share **one** KM object with its single monotonic counter. A future change that introduces a *second copy*
of the EntityCrypto KM reintroduces nonce reuse — for SIGN exactly as for ENCRYPT.

**Exactness fix carried with it.** The send-side capacity gate hardcoded the ENCRYPT framing
(`44 + len + 3`). It is now the exact per-tier sealed length,
`dds.security:secured-payload-length` (ENCRYPT `44 + N + pad4(N)`; SIGN `40 + align4(N)`) — one definition
shared with the encoder, so the slot-capacity check can neither under-count (overflow) nor over-count
(needlessly refuse ZC for a payload that would have fit).

## 3. Decision 2 — the `-into-sap` direct seal is **declined**, on measurement

Full numbers: `bench/report/2026-07-11-zc-overlay-into-sap.md`.

| payload | seal µs/op | memcpy µs/op | memcpy share |
|---|---|---|---|
| 4 KiB | 6.689 | 0.178 | 2.6 % |
| 16 KiB | 22.864 | 1.080 | 4.5 % |
| 64 KiB | 94.251 | 3.373 | 3.5 % |

The AEAD pass dominates the copy by ~25×. The memcpy the optimization would remove is **2.6–4.5 %** of the
overlay's send cost — and that is a *ceiling*, since a direct seal still pays the whole AEAD pass. Buying
~3 % on an opt-in edge path (ENCRYPT/SIGN × Zero-Copy × SHMEM) is not worth (a) forking or rewriting
`encode-serialized-payload-into` — the one primitive every `data_protection` tier depends on — onto a
second, SAP-writing code path, since duplicated §9.5.3.3 framing arithmetic is exactly where crypto bugs
hide; nor (b) sealing **into shared memory**, where the slot transiently holds partially-written AEAD state
(the ADR-0042 acquire/commit protocol does keep that invisible to a lock-free reader — the generation is
published only after the write — but it is new exposure for a 3 % return).

**Re-open condition, recorded so this is not a permanent no:** the ratio is what makes it a bad trade, not
the idea. If the AEAD ever stops dominating (hardware crypto offload, a DMA path, a much cheaper tier),
re-run the bench; if the memcpy share exceeds ~20 %, reconsider.

## 4. Consequences

- **ADR 0051 deferred follow-ons 1 and 2 are both CLOSED** (1 implemented — with a corrected rationale;
  2 declined with evidence). Follow-on 3 (multi-writer / per-endpoint overlay keying) was already closed
  by WP-DCPS-API-COMPLETION S6.T3.
- **No wire-format change, no hot-path change for any non-overlay writer.** A writer that was ineligible
  and gated off now takes the overlay instead — strictly more capable, never less protected.
- **The ZC gate keeps its fail-closed shape.** No KM / no scratch / carve-fail / over-slot → NIL → the
  sample falls through to the normal serialize + `%send-raw-buf` path. No cleartext user payload lands in
  SHMEM in any path, and no *unauthenticated* payload lands there either.

## 5. Verification

- `zc-overlay-sign-tier` (RED before, GREEN after): a SIGN-tier writer's overlay KM is GMAC (not ENCRYPT)
  and **is** overlay-eligible; the sealed SecuredPayload round-trips through the real §9.5.3.3 codec; a
  **tampered** sealed slot is **rejected fail-closed** — the integrity the raw-ZC alternative would have
  silently lost; and `secured-payload-length` predicts the seal exactly, for both tiers.
- 560/560 tests green on **both** Clasp and SBCL; `gate-hotpath` + `gate-types` green.
