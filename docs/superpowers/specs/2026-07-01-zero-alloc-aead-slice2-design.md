# Zero-Alloc AEAD — Slice 2 Design (submessage + whole-RTPS tiers)

> Status: design, owner-approved 2026-07-01. Operating-contract workflow: brainstorm (this) → plan → subagent-driven implementation → final review → finish-branch.

**WP:** `WP-DDS-SECURITY-ZEROALLOC-AEAD` (Slice 2 / ZA-2) · **Milestone:** M7 / P6 (security hardening) · **ADR:** 0039 (at the capstone) · **Prior art:** ADR 0038 (ZA-1: the data_protection tier + the shared foundation), ADR 0031/0034/0036 (Carry-3).

---

## 1. Problem

ZA-1 made the **data_protection (serialized-payload)** AEAD tier zero-alloc and built the shared foundation (into-buffer FFI `aes-256-gcm-{seal,open}-into`, `dds.pal:static-sap+`, the session-key cache `%km-session-key-at`, the encode payload pool, the decode loan). But the **other two AEAD tiers still allocate per sample**: both the **submessage (metadata_protection)** and **whole-RTPS (rtps_protection)** tiers run through the *allocating* shared core `%encode/%decode-secured-region` (`src/dds-security/crypto/submessage.lisp`), which still calls the allocating `aes-256-gcm-seal`/`-open` (not the `-into` FFI) and allocates its scratch + `→octets` return + parse `make-array`s; the dataplane wraps (`%maybe-wrap-srtps`, `%maybe-wrap-user-submessages` in `dataplane.lisp`) `subseq` their inputs and use a per-call `alloc-static (+ len 8192)` scratch. This is the **~2.2 KB/datagram ADR-0036 Carry-3 remainder**. `encode/decode-rtps-message` (`rtps-message.lisp`) are pure delegations to the core, so fixing the core fixes the whole-RTPS tier too.

**Geometry (drives the design):** the secured bracket is larger than the plaintext — **ENCRYPT +56 B / SIGN +48 B**; the ENCRYPT ciphertext lands **32 B forward** of the plaintext (PREFIX 4 + CryptoHeader 20 + SEC_BODY hdr 4 + ct_len 4), the SIGN verbatim region **24 B forward** (PREFIX 4 + CryptoHeader 20). This is the in-place crux.

## 2. Goal (ZA-2)

Make the submessage (metadata_protection) and whole-RTPS (rtps_protection) AEAD tiers allocate **zero GC-heap bytes/sample** on the live secured path (send **and** receive), proven by a `make mem` arm (delta over the non-secured baseline == 0). Wire **byte-identical**: the T1 crypto-header/footer, T2 submessage (ENCRYPT 88 / SIGN 80), T3 origin-auth-prefix, and T4 whole-RTPS (ENCRYPT 100 / SIGN 92) byte-exact goldens — and the ZA-1 payload goldens — stay green **unchanged** (an allocation/representation change, never a wire change). This closes ADR-0036 Carry-3 (flip to fully resolved for the common path).

## 3. Scope

**IN (ZA-2):**
1. A **GMAC-into** dds.dare primitive for the SIGN branch (pt-len=0, AAD = the verbatim region by SAP, tag-only output).
2. The core **`%encode-secured-region-into` / `%decode-secured-region-into`** (reusing seal-into/open-into + `%km-session-key-at` + `%km-next-iv-suffix-into` + `%put-u32-be-at`; SIGN decode returns (offset,len) bounds); the existing entries refactored to thin allocating wrappers over the core. `encode/decode-rtps-message` unchanged (delegations) → the whole-RTPS tier fixed by the core.
3. **Dataplane borrow:** a new **per-node datagram-sized send-scratch pool**; `%maybe-wrap-srtps` + `%maybe-wrap-user-submessages` wrap into it then `replace` into the reused `tx-msg` in place; drop the `subseq` inputs + the per-call `alloc-static +8192`. RX opens into a reused buffer / in place; `%on-user-secure-submessage` re-dispatch uses a **reused per-node RX buffer**.
4. A **security-ON `make mem` arm** covering metadata_protection + rtps_protection send + receive at 0 B/sample over baseline; exhaustion → RESOURCE_LIMITS backpressure never GC.

**OUT (deferred carries):**
- **Origin-auth (receiver-specific MACs) zero-alloc** — off the common empty-receivers path (the corpora + e2e use no origin-auth). Zero-alloc-ing it needs a receiver-session-key cache (parallel to `%km-session-key-at`) + footer-region MAC writes + the GMAC-into per receiver. The common ENCRYPT/SIGN path is zero-alloc; origin-auth stays allocating (correct, byte-identical), documented in ADR 0039 (like the ADR-0034 key-material deferral).
- The other ZA-1 residuals not specific to these tiers (key-material foreign-hardening, ZC×rtps SHMEM, saved-image re-resolve, PAL atomics stubs, secured samples-store growth) — tracked in ADR 0038, not ZA-2.

## 4. Constraints (operating contract)

- **Byte-identical wire:** an allocation change only. T1/T2/T3/T4 + the ZA-1 payload byte-exact goldens stay green **unchanged**; NEVER regenerate/weaken a corpus. Keep the allocating `%encode/%decode-secured-region` as thin wrappers over the `-into` core so the corpora exercise the core (the ZA-1 wrapper trick).
- **our-to-our green BOTH impls (Clasp first):** test-clasp + test-sbcl + corpus + fuzz + gate-hotpath + gate-types + mem after each task.
- **Hot-path purity / static-arena:** no CLOS/per-sample alloc; the send-scratch pool + RX buffers are foreign/static (`dds.pal:alloc-static` / `make-buffer-pool`); anything addressed by a raw SAP is foreign/static; exhaustion → RESOURCE_LIMITS backpressure, never a GC-heap fallback.
- **Fail-closed + bounds-checked receive even at (safety 0):** decode validates lengths/offsets before reading; a decode failure → drop, no plaintext; the SIGN (offset,len) bounds are validated against the input extent.
- `defun*`/`defstruct*` + full `ftype`; one-line comments; **no reader conditionals outside `dds-pal/`** (the GMAC-into rides the existing dds.dare FFI; any impl-specifics live in dds-pal); no AI-assistant attribution (cite "the operating contract §N"); SBOM auto; docs lockstep (ADR 0039 + flip ADR-0036 Carry-3 + wiki/verification/README at the capstone).

## 5. Architecture

Reuses the ZA-1 foundation on `main` (into-buffer FFI, `static-sap+`, session-key cache, `%km-next-iv-suffix-into`, `%put-u32-be-at`, the pool pattern). One new FFI primitive; the rest is applying the ZA-1 codec-into + dataplane-borrow patterns to two more tiers.

### 5.1 GMAC-into (`src/dds-dare/`)
Extend the into-buffer seal so the SIGN branch can compute a pure GMAC tag with **no plaintext output**: `aes-256-gcm-seal-into` with pt-len=0 authenticates the AAD (the verbatim submessage/RTPS region, passed by SAP — it may point into the out-buffer, since `seal-into` already stages AAD via `with-pointer-to-vector-data`) and writes only the 16-byte tag through the caller SAP. NIST-KAT-pinned; byte-identical to the existing GMAC. (Confirm `aes-256-gcm-open-into` verifies with region-AAD for the SIGN decode.)

### 5.2 Core into-buffer codec (`src/dds-security/crypto/submessage.lisp`)
- `%encode-secured-region-into (out-buf out-off km kind plain plain-off plain-len receivers) → length` — build the SEC/SRTPS_PREFIX ‖ CryptoHeader ‖ (SEC_BODY[ct] | verbatim) ‖ SEC/SRTPS_POSTFIX[tag(+rsm)] bracket into `out-buf` at `out-off`, byte-identical to `%encode-secured-region`. Raw-offset header writes (the SecureDataHeader layout == `serialize-crypto-header`), `%km-next-iv-suffix-into` stamps the iv into the header, `%km-session-key-at` (cached) + `aes-256-gcm-seal-into` seals ct+tag (ENCRYPT) or GMAC-into (SIGN) with the nonce = the in-place header sub-slice; `%put-u32-be-at` for ct_len + rsm_count; the `ct-pad` + footer 4-align preserved. No `make-array`/`subseq`/`alloc-static`.
- `%decode-secured-region-into (pt-out pt-off km secured secured-off secured-len sign-walk-p) → (or length null)` — parse the header/footer by offset (no `make-array`); ENCRYPT → `aes-256-gcm-open-into` into `pt-out`; **SIGN → verify (GMAC) + return the (offset,len) bounds** of the verbatim region within `secured` (no copy). Fail-closed (bounds validated; NIL on failure).
- The existing `%encode/%decode-secured-region` + `encode/decode-{datawriter,datareader,rtps}-{sub,}message` become thin allocating wrappers over the `-into` core (temp buffer → core → subseq), so the T2/T4 corpora + the origin-auth path exercise the core unchanged.

### 5.3 Dataplane borrow (`src/dds-disc/dataplane.lisp` + `disc.lisp` + `secure-sedp.lisp`)
- A **per-node datagram-sized send-scratch pool** (`make-buffer-pool`, element-bytes = max datagram + bracket overhead, capacity = a small fixed count + headroom; distinct from the ZA-1 per-writer payload pool — these brackets are datagram-sized on the node send/receiver threads). Guarded like the other node pools.
- `%maybe-wrap-srtps`: `%encode-secured-region-into` the `[20,len)` region (input by offset, no subseq) into a pooled scratch, then `replace` into `tx-msg` in place (the in-place replace already exists); release the scratch.
- `%maybe-wrap-user-submessages`: wrap each user submessage via the `-into` core into a pooled scratch (drop the `+8192` per-call alloc + the per-submessage `subseq`), rebuild into `tx-msg` in place.
- **RX:** the SRTPS unwrap in `%handle-datagram` opens the stream into a reused buffer / in place (drop the `subseq`); `%on-user-secure-submessage`'s re-dispatch synthetic datagram uses a **reused per-node RX buffer** (safe — the inner data_protection DATA registers its own distinct ZA-1 decode loan; the reused buffer's lifetime spans only the recursive `%handle-datagram`).

### 5.4 Live mem arm (`src/dds-tests/gen-test.lisp` / `security-test.lisp`)
Extend the ZA-1 T5c/T5d `bytes-consed` harness: assert 0 B/sample over the non-secured baseline for **metadata_protection (submessage)** send+receive and **rtps_protection (SRTPS)** send+receive; and an exhaustion test (send-scratch pool empty → RESOURCE_LIMITS backpressure, never GC).

## 6. Data flow

Encode (steady state): serialize the datagram into the reused `tx-msg`; for a secured tier, `%*-secured-region-into` writes the bracket into a pooled send-scratch (cached session key, seal-into/GMAC-into, no alloc), then `replace` into `tx-msg` in place; release the scratch. Decode: open the ENCRYPT ciphertext into a reused buffer (or the SIGN region validated in place → (offset,len)); the re-dispatch reuses a per-node RX buffer. Zero GC-heap allocation on both.

## 7. Error handling / fail-closed

Decode/`-into` validates every offset/length against the input extent before reading (even at (safety 0)); a GMAC/GCM failure or malformed bracket → NIL → drop (no plaintext, no re-dispatch). The SIGN (offset,len) bounds are validated within `secured`. Send-scratch / RX-buffer pool exhaustion → RESOURCE_LIMITS backpressure (drop + counter), never a GC-heap fallback. Origin-auth (allocating, deferred) path unchanged + fail-closed as today.

## 8. Verification & DoD

- **Headline:** `make mem` reports 0 B/sample over baseline for metadata_protection + rtps_protection, send AND receive.
- **Wire invariant:** T1/T2/T3/T4 + the ZA-1 payload byte-exact goldens green **unchanged** (no regen); the allocating wrappers route through the `-into` core.
- **our-to-our green both impls (Clasp first):** all gates; the secure-discovery e2es (which exercise submessage + SRTPS protection) pass.
- **Fail-closed:** the fuzz decoder arms (submessage + rtps) still pass; exhaustion → backpressure not GC.
- **Docs:** ADR 0039; ADR-0036 Carry-3 → fully resolved (common path); README/verification.csv/wiki in lockstep; origin-auth deferral documented.

## 9. Risks

- **In-place wrap when the bracket is +56/+48 B larger than the plaintext** (multi-bracket for the submessage tier). Mitigation: wrap into a pooled scratch then `replace` into `tx-msg` (uniform for both tiers), rather than a forward memmove.
- **SIGN byte-exactness:** the verbatim placement + the `ct-pad` + footer 4-align must stay bit-identical to the T2/T4 SIGN goldens (80/92). Mitigation: the corpora exercise the core via the wrappers; a byte diff vs `%encode-secured-region` catches any divergence.
- **Decode re-dispatch buffer lifetime across recursion** (the reused RX buffer must not alias a live inner loan). Mitigation: the inner DATA owns a distinct ZA-1 decode-pool buffer; the reused buffer is returned when `%handle-datagram` returns.
- **Origin-auth deferred:** the receiver-specific-MAC path stays allocating (documented). If a target deployment leans on origin-auth, a follow-up adds the receiver-session-key cache.

## 10. ADR

ADR 0039 (`docs/adr/0039-zero-alloc-aead-slice2.md`) at the capstone: the GMAC-into + the `-into` core for the submessage/whole-RTPS tiers + the per-node send-scratch pool + the RX-buffer reuse; the measurements; the flip of ADR-0036 Carry-3 to fully resolved (common path); the origin-auth deferral + any residual carries.

## Decomposition (SDD tasks, dependency order)

- **T1** — dds.dare GMAC-into (SIGN: pt-len=0, region-AAD by SAP, tag-only) + confirm open-into region-AAD for SIGN verify. *(small/low, KAT-pinned.)*
- **T2** — the core `%encode/%decode-secured-region-into` + refactor the existing entries to thin wrappers. *(medium/medium — SIGN placement + 4-align byte-exact vs T2/T4.)*
- **T3** — SRTPS dataplane borrow (`%maybe-wrap-srtps` + RX) over a per-node send-scratch pool / reused buffer. *(medium/medium.)*
- **T4** — submessage dataplane borrow + decode re-dispatch (`%maybe-wrap-user-submessages` + `%on-user-secure-submessage`). *(larger/high — multi-bracket in-place, buffer lifetime across recursion.)*
- **T5** — live `make mem` arm (metadata_protection + rtps_protection send+receive 0 over baseline) + exhaustion-backpressure test. *(medium/medium.)*
- **T6** — capstone: ADR 0039 + flip ADR-0036 Carry-3 + README/verification/wiki + final dual-impl gate sweep. *(small/low.)*
