# Zero-Alloc AEAD Slice 2 (submessage + whole-RTPS tiers) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Make the submessage (metadata_protection) and whole-RTPS (rtps_protection) AES-256-GCM tiers allocate zero GC-heap bytes/sample on the live secured path (send + receive), reusing the ZA-1 foundation, with the wire byte-identical.

**Architecture:** The two tiers share the allocating core `%encode/%decode-secured-region` (submessage.lisp); `encode/decode-rtps-message` are pure delegations. Add an into-buffer core (`%encode/%decode-secured-region-into`) built on the ZA-1 primitives (`aes-256-gcm-{seal,open}-into`, a new SIGN GMAC-into, `%km-session-key-at`, `%km-next-iv-suffix-into`, `%put-u32-be-at`, `dds.pal:static-sap+`); refactor the existing entries to thin allocating wrappers (so the T2/T4 corpora exercise the core → byte-identity for free). Wire the dataplane wraps to a new per-node datagram-sized send-scratch pool + reused RX buffers.

**Tech Stack:** Common Lisp (SBCL + Clasp), the ZA-1 into-buffer FFI + PAL SAP + arena buffer-pool, `dds.core.buffer`, `defun*`/`defstruct*`.

**Branch:** `wp-dds-security-zeroalloc-aead-s2` (from `main` = 914f210); squash-merge to `main` at the end.

## Global Constraints

- **Byte-identical wire:** an allocation change, NOT a wire change. The T1 crypto-header/footer, T2 submessage (ENCRYPT **88** / SIGN **80**), T3 origin-auth-prefix, T4 whole-RTPS (ENCRYPT **100** / SIGN **92**), and the ZA-1 payload byte-exact goldens stay green **UNCHANGED** — NEVER regenerate/weaken. Keep the allocating `%encode/%decode-secured-region` as thin wrappers over the `-into` core so the corpora exercise the core (the ZA-1 trick); if a corpus byte changes, the core diverged — fix the core.
- **our-to-our green BOTH impls (Clasp first) after every task:** `make test-clasp` + `make test-sbcl` + `make corpus` + `make fuzz` + `make gate-hotpath` + `make gate-types` + `make mem`. Clasp may abort only at the known NFR-PORT live-socket flake `[SDP-SEC-PREFIX-ON-WIRE]`/`[SDP-BYTE-EXACT]`/`[VOLATILE-LATEJOINER-ZERO]` (re-run / isolation-verify).
- **Hot-path purity / static-arena:** no CLOS/per-sample alloc on the codec/dataplane path; the send-scratch pool + RX buffers are foreign/static (`make-buffer-pool` / `alloc-static`); anything addressed by a raw SAP is foreign/static; exhaustion → RESOURCE_LIMITS backpressure, never a GC-heap fallback.
- **Fail-closed + bounds-checked receive even at (safety 0):** decode validates offsets/lengths before reading; the SIGN (offset,len) bounds validated against the input extent; failure → NIL → drop, no plaintext.
- **ORIGIN-AUTH (receiver-specific MACs) zero-alloc is DEFERRED** — keep the `receivers` non-empty path ALLOCATING (correct, byte-identical), documented. The common empty-receivers ENCRYPT/SIGN path is the zero-alloc target.
- **The send-scratch pool is a NEW per-node datagram-sized pool, DISTINCT from the ZA-1 per-writer payload pool** (`history-cache-payload-pool`).
- `defun*`/`defstruct*` + full `ftype`; one-line comments; **no reader conditionals outside `dds-pal/`**; no AI-assistant attribution (cite "the operating contract §N"); SBOM auto.
- Geometry: bracket overhead ENCRYPT **+56 B** / SIGN **+48 B**; the ENCRYPT ciphertext lands **32 B forward** of the plaintext (PREFIX 4 + CryptoHeader 20 + SEC_BODY hdr 4 + ct_len 4), the SIGN verbatim region **24 B forward** (PREFIX 4 + CryptoHeader 20). `ct-pad = (−|ciphertext|) mod 4`.

---

## File Structure

- `src/dds-dare/primitives.lisp` — extend `aes-256-gcm-seal-into` for the SIGN GMAC case (pt-len 0, region-AAD, tag-only); confirm `aes-256-gcm-open-into` region-AAD verify. Existing entries unchanged.
- `src/dds-security/crypto/submessage.lisp` — add `%encode-secured-region-into` / `%decode-secured-region-into`; refactor `%encode/%decode-secured-region` + `%encode/%decode-secured-submessage` to thin wrappers. `encode/decode-{datawriter,datareader,rtps}-{sub,}message` unchanged (they call the wrappers).
- `src/dds-security/crypto/rtps-message.lisp` — unchanged (pure delegations to the core).
- `src/dds-disc/disc.lisp` — add the per-node send-scratch pool slot + a reused secure-redispatch RX buffer slot; provision at node init, free at teardown.
- `src/dds-disc/dataplane.lisp` — rewire `%maybe-wrap-srtps` + `%maybe-wrap-user-submessages` (+ `%wrap-one-user-submessage`) to the `-into` core over the pooled scratch; the RX SRTPS unwrap in `%handle-datagram`.
- `src/dds-disc/secure-sedp.lisp` — `%on-user-secure-submessage` re-dispatch over the reused RX buffer.
- `src/dds-tests/security-test.lisp` + `gen-test.lisp` — the into-oracle-pin tests + the live mem arm.

---

## Task 1: GMAC-into (SIGN) FFI

**Files:** Modify `src/dds-dare/primitives.lisp` (`aes-256-gcm-seal-into`), `src/dds-tests/dare-test.lisp` (KAT arm).

**Interfaces:**
- Consumes: the ZA-1 `aes-256-gcm-seal-into (out ct-off tag-off key nonce-vec nonce-off aad pt pt-off pt-len)`.
- Produces: `aes-256-gcm-seal-into` handles `pt-len = 0` (SIGN/GMAC) — authenticates AAD (`aad`, possibly a SAP into `out` itself), writes ONLY the 16-byte tag at `tag-off`, no ciphertext. `aes-256-gcm-open-into` confirmed to verify with a region-AAD (pt-len 0) for SIGN decode.

**Method:** the existing `seal-into` already stages AAD via `with-pointer-to-vector-data` and writes ct+tag through the out SAP; for `pt-len = 0` the EVP EncryptUpdate(PT) step is skipped (as in the allocating path) and only GET_TAG runs → tag at `tag-off`, zero ciphertext bytes written. Verify AAD-from-`out` (the SIGN verbatim region will live in the out-buffer) is safe (the AAD SAP + the out SAP may overlap — GCM reads AAD before/independently of the ct write; confirm the EVP call order tolerates it, else stage AAD first). Same for `open-into` (verify GMAC over region-AAD, pt-len 0).

- [ ] **Step 1: failing KAT arm** — extend `run-dare-aes-gcm-kat-test` with a GMAC(SIGN) case: `seal-into` with pt-len 0 + a non-empty AAD → assert the tag equals the allocating `aes-256-gcm-seal` GMAC (pt="", aad=region) byte-for-byte (NIST-consistent); `open-into` pt-len 0 with the right tag → T, tampered → NIL.
- [ ] **Step 2:** run `make test-sbcl 2>&1 | grep -i gmac-into` → FAIL.
- [ ] **Step 3:** implement the pt-len-0 path in `seal-into`/`open-into`; full ftype; one-line comments; docstring cites §9.5.3.3.4.3.
- [ ] **Step 4:** green; the existing seal-into/open-into KAT arms + all DARE tests still pass.
- [ ] **Step 5: gates + commit** — `make test-clasp test-sbcl gate-types`; `git commit -m "feat(security): WP-DDS-SECURITY-ZEROALLOC-AEAD — T1(ZA-2) GMAC-into (SIGN pt-len-0 region-AAD tag-only), KAT byte-identical (M7/P6 Slice 2)"`.

---

## Task 2: into-buffer core `%encode/%decode-secured-region-into` + wrappers

**Files:** Modify `src/dds-security/crypto/submessage.lisp`; Test `src/dds-tests/security-test.lisp`.

**Interfaces:**
- Consumes: T1 GMAC-into; `%km-session-key-at (km vec off)`, `%km-next-iv-suffix-into (km vec off)`, `%put-u32-be-at`/`%get-u32-be-at` (transform.lisp), `dds.pal:static-sap+`, the layout constants (`+sec-submessage-header-len+`=4, `+secure-data-header-len+`=20, `+crypto-content-length-len+`=4, `+common-mac-len+`=16, `+submessage-sec-body+`, `+receiver-specific-macs-count-len+`).
- Produces:
  - `%encode-secured-region-into (out-buf out-off km mode plain plain-off plain-len receivers prefix-kind postfix-kind &optional session-id) → length` — write the bracket into `out-buf` (static octet-buffer) at `out-off`, byte-identical to `%encode-secured-region`; return the total bracket length. No `make-array`/`subseq`/`alloc-static`. The 12-byte nonce = the in-place CryptoHeader `session_id‖iv_suffix` sub-slice (the header is written first). ENCRYPT: `aes-256-gcm-seal-into` writes ct at the SEC_BODY-content offset + tag at the POSTFIX common_mac offset; write the SEC_BODY header + cnt_length (BE) + ct-pad via raw offset. SIGN: copy the verbatim region into place, GMAC-into the tag (AAD = the in-place verbatim region). `receivers` non-empty → fall back to the allocating `%compute-receiver-macs` path (deferred; may allocate).
  - `%decode-secured-region-into (pt-out pt-off km secured secured-off secured-len sign-walk-p) → (values length mode)|null` — parse header/footer by offset (no make-array); ENCRYPT → `aes-256-gcm-open-into` plaintext into `pt-out`, return (len :encrypt); SIGN → verify GMAC + return `(values (offset,len-of-verbatim-region-within-secured) :sign)` (no copy). Fail-closed (bounds validated; NIL on failure).
- The existing `%encode-secured-region`/`%decode-secured-region` + `%encode/%decode-secured-submessage` become thin allocating wrappers (temp buffer → core → subseq); `encode/decode-{datawriter,datareader,rtps}-{sub,}message` unchanged.

**Method:** mirror ZA-1's `encode/decode-serialized-payload-into` (transform.lisp) exactly, extended for the PREFIX/POSTFIX submessage headers + the SEC_BODY (ENCRYPT) / verbatim (SIGN) middle. Cursor-free raw-offset writes (ZA-1 found the cursor struct conses + `dynamic-extent` doesn't help through the serialize-crypto-* calls → write the 4-byte submessage headers, the 20-byte CryptoHeader, the SEC_BODY, and the footer by offset). The allocating `%encode-secured-region` body (submessage.lisp:282-331) is the byte-layout reference — reproduce its exact sequence.

- [ ] **Step 1: failing oracle-pin test** — `run-security-secured-region-into-test`: for a fixed km + fixed iv-counter, ENCRYPT and SIGN, assert `%encode-secured-region-into` output `equalp` the allocating `%encode-secured-region` (the independent oracle) for BOTH the SEC_PREFIX/SEC_POSTFIX (submessage) and SRTPS_PREFIX/SRTPS_POSTFIX (whole-RTPS) bracket kinds; assert `%decode-secured-region-into` round-trips (ENCRYPT plaintext byte-exact; SIGN bounds point at the verbatim region byte-exact); too-short input → NIL. (Register in the dispatch alist.)
- [ ] **Step 2:** run → FAIL (undefined).
- [ ] **Step 3:** implement the `-into` core + refactor the 4 entries to wrappers; export nothing new outside the package (internal `%`).
- [ ] **Step 4:** green **and** the T2 (`:t2-encrypt-byte-exact` 88 / `:t2-sign-byte-exact` 80), T4 (`:t4-encrypt` 100 / `:t4-sign-byte-exact` 92), T1 crypto-header/footer, T3 origin-auth-prefix, and the ZA-1 payload corpora PASS UNCHANGED (the wrappers route through the core).
- [ ] **Step 5: full gates + commit** — `make test-clasp test-sbcl corpus fuzz gate-hotpath gate-types`; `git commit -m "feat(security): WP-DDS-SECURITY-ZEROALLOC-AEAD — T2(ZA-2) into-buffer %encode/%decode-secured-region-into + allocating wrappers (submessage+whole-RTPS; corpus byte-identical) (M7/P6 Slice 2)"`.

---

## Task 3: SRTPS dataplane borrow

**Files:** Modify `src/dds-disc/disc.lisp` (send-scratch pool slot + RX buffer slot; init/teardown), `src/dds-disc/dataplane.lisp` (`%maybe-wrap-srtps`), `src/dds-disc/disc.lisp` (the RX SRTPS unwrap in `%handle-datagram`, ~1261-1274).

**Interfaces:**
- Consumes: T2 `%encode/%decode-secured-region-into`; `dds.core.arena:make-buffer-pool`/`pool-acquire`/`pool-release`.
- Produces: `disc-node` slot `send-scratch-pool` (a `make-buffer-pool`, element-bytes = max datagram + `+56` overhead, capacity = a small fixed count + headroom; provisioned at node init from the arena, freed at teardown) + a reused `secure-rx-buf` slot. A helper `%with-send-scratch (node) → octet-buffer|nil` (acquire/release, or a lock-guarded borrow).

**Method:** `%maybe-wrap-srtps` (dataplane.lisp:90) currently `(subseq vec 20 len)` (D1) + `encode-rtps-message` (→ allocating core) + in-place `replace`. Rewire: acquire a scratch from the pool; call `%encode-secured-region-into scratch 0 km :encrypt/:sign vec 20 (- len 20) receivers +srtps-prefix+ +srtps-postfix+` (input by offset — NO subseq); `replace vec (scratch-vec) :start1 20 :end2 bracket-len`; release the scratch; return `(+ 20 bracket-len)`. Pool exhaustion (`pool-acquire`→NIL) → return NIL (fail-closed drop, the existing "required-but-failed" contract) — never GC. The RX SRTPS unwrap: open the stream into the reused `secure-rx-buf` (or in place) via `%decode-secured-region-into`, drop the `(subseq vec 20 size)`.

- [ ] **Step 1: failing test** — extend the secure-discovery/SRTPS e2e (or a focused test) to assert an SRTPS-protected datagram round-trips byte-exact with the pooled path, AND a focused bytes-consed check that a steady-state SRTPS send over a reused buf conses 0 (SBCL) for the wrap itself (the plain-region subseq + the core scratch are gone).
- [ ] **Step 2:** run → the bytes-consed check FAILs (still allocating) / the e2e passes on the old path.
- [ ] **Step 3:** add the pool slot + init/teardown; rewire `%maybe-wrap-srtps` + the RX unwrap.
- [ ] **Step 4:** green; the SRTPS e2e (secure-discovery-protected/-sign) round-trips byte-exact; the SRTPS wrap bytes-consed → 0 (SBCL). Security-OFF byte-identical.
- [ ] **Step 5: gates + commit** — `make test-clasp test-sbcl corpus fuzz gate-hotpath gate-types mem`; `git commit -m "feat(security): WP-DDS-SECURITY-ZEROALLOC-AEAD — T3(ZA-2) SRTPS dataplane borrow (per-node send-scratch pool + reused RX buf; %maybe-wrap-srtps via -into, drop the subseq) (M7/P6 Slice 2)"`.

---

## Task 4: submessage dataplane borrow + decode re-dispatch

**Files:** Modify `src/dds-disc/dataplane.lisp` (`%maybe-wrap-user-submessages`, `%wrap-one-user-submessage`), `src/dds-disc/secure-sedp.lisp` (`%on-user-secure-submessage`).

**Interfaces:**
- Consumes: T2 `-into` core; the T3 send-scratch pool + `secure-rx-buf`.
- Produces: `%maybe-wrap-user-submessages` uses the pooled scratch (drop the `(make-octet-buffer (+ len 8192))` D5 + the per-submessage `(subseq vec start sm-end)` D6); `%wrap-one-user-submessage` calls the `-into` core with `vec`+offset+len into the scratch. `%on-user-secure-submessage`'s re-dispatch synthetic datagram uses the reused `secure-rx-buf` (drop the per-call `make-octet-buffer`).

**Method:** `%maybe-wrap-user-submessages` (dataplane.lisp:153) walks [20,len) and rebuilds into an `out` buffer. Rewire: `out` = a pooled scratch (from the T3 pool, sized ≥ len + N×56 headroom — or reuse the same pool if sized for the max datagram+brackets); for each user submessage, instead of `(subseq vec start sm-end)` + `%wrap-one-user-submessage` (→ allocating), call the `-into` core writing the bracket directly into `out` at the running offset (input `vec`+start+sublen, no subseq); INFO_* pass-through via `put-octets` (no alloc); then `replace vec out`; release the scratch. Keep every fail-closed branch (malformed/overrun/won't-fit → NIL). `%on-user-secure-submessage` (secure-sedp.lisp:221): decode via `%decode-secured-region-into` (ENCRYPT → the reused RX buf; SIGN → bounds), synthesize the re-dispatch datagram in the reused `secure-rx-buf` (write the 20-byte header + the recovered submessage), `%handle-datagram … t`; the reused buffer is safe (the inner data_protection DATA registers its own distinct ZA-1 decode loan; the buffer's lifetime spans only the recursive call).

- [ ] **Step 1: failing test** — assert metadata_protection (submessage) round-trips byte-exact via the pooled path (`run-security-encrypted-pubsub-test` with metadata_protection ON, or a focused test), a multi-submessage datagram, AND a bytes-consed check that a steady-state metadata_protection send conses 0 (SBCL) for the wrap.
- [ ] **Step 2:** run → bytes-consed FAILs (still allocating).
- [ ] **Step 3:** rewire `%maybe-wrap-user-submessages` + `%wrap-one-user-submessage` + `%on-user-secure-submessage`.
- [ ] **Step 4:** green; the metadata_protection e2e round-trips byte-exact; the submessage wrap + the re-dispatch bytes-consed → 0 (SBCL); the secure-discovery e2es (which exercise the re-dispatch) pass. Security-OFF / metadata-NONE byte-identical (the NONE short-circuit preserved).
- [ ] **Step 5: full gates + commit** — `make test-clasp test-sbcl corpus fuzz gate-hotpath gate-types mem`; `git commit -m "feat(security): WP-DDS-SECURITY-ZEROALLOC-AEAD — T4(ZA-2) submessage dataplane borrow (pooled scratch, drop +8192 + per-submessage subseq) + decode re-dispatch reused RX buf (M7/P6 Slice 2)"`.

---

## Task 5: live make-mem arm + exhaustion backpressure

**Files:** Modify `src/dds-tests/gen-test.lisp` (or `security-test.lisp`) — extend the ZA-1 T5c/T5d harness.

**Interfaces:** Consumes T3+T4 (the pooled SRTPS + submessage paths).

**Method:** add mem arms driving steady-state secured send+receive with (a) rtps_protection ON and (b) metadata_protection ON, over reused buffers, asserting bytes-consed/iter delta over the non-secured baseline == 0 on SBCL (Clasp smokes). Add an exhaustion test: the send-scratch pool empty → `%maybe-wrap-*` returns NIL (fail-closed drop) / the send path applies backpressure, never a GC fallback (bytes-consed bounded under exhaustion). Wire into `make mem`.

- [ ] **Step 1:** add the arms (metadata_protection + rtps_protection, send + receive) + the exhaustion test → run `make mem` → the new arms report the pre-fix number if run before T3/T4 (here they should be ~0 since T3/T4 landed).
- [ ] **Step 2:** confirm each arm reports **0 B/sample over baseline** on SBCL; the exhaustion test shows RESOURCE_LIMITS/drop with bounded bytes-consed (no GC).
- [ ] **Step 3: gates + commit** — `make test-clasp test-sbcl mem`; `git commit -m "test(security): WP-DDS-SECURITY-ZEROALLOC-AEAD — T5(ZA-2) live mem arms (metadata_protection + rtps_protection send+receive 0 over baseline) + exhaustion-backpressure-not-GC (M7/P6 Slice 2)"`.

---

## Task 6: Capstone — ADR 0039 + docs + final gates

**Files:** Create `docs/adr/0039-zero-alloc-aead-slice2.md`; Modify `docs/adr/0036-dds-security-secure-discovery.md` (flip Carry-3 to fully resolved, common path), `docs/adr/0038-zero-alloc-aead.md` (mark residual (a) submessage+whole-RTPS resolved), `README.md`, `docs/verification.csv`, `docs/wiki/security.md`.

- [ ] **Step 1:** ADR 0039 — the GMAC-into + the `-into` core for the submessage/whole-RTPS tiers + the per-node send-scratch pool + the RX-buffer reuse; the measurements (before→0); scope (common ENCRYPT/SIGN path zero-alloc; **origin-auth deferred** — receiver-specific MACs stay allocating, documented); flip ADR-0036 Carry-3 to fully-resolved-common-path + update ADR-0038 residual (a). Follow the 0036/0037/0038 ADR format.
- [ ] **Step 2:** README P6/NFR-MEM row + verification.csv rows + wiki §3.x (the submessage/RTPS tiers now zero-alloc; the origin-auth deferral).
- [ ] **Step 3: final dual-impl gate sweep** — `make build` (SBCL+Clasp), `make test-clasp test-sbcl corpus fuzz gate-hotpath gate-types mem`; record results.
- [ ] **Step 4: commit** — `git commit -m "docs(security): WP-DDS-SECURITY-ZEROALLOC-AEAD — Slice 2 capstone: ADR 0039 + ADR-0036 Carry-3 fully resolved (common path) + README/verification/wiki; submessage + whole-RTPS AEAD tiers zero-alloc; final dual-impl gates green (M7/P6 Slice 2)"`.

---

## Notes for the executor

- **Order:** T1 → T2 → T3 → T4 → T5 → T6. T2 depends on T1; T3/T4 depend on T2 (and share the T3 pool); T5 depends on T3+T4.
- **The invariant:** the T2/T4 + T1 crypto-header + ZA-1 payload byte-exact goldens stay green UNCHANGED. If any corpus byte changes, the `-into` core diverged from `%encode-secured-region` — fix the core, never the corpus.
- **Aliasing:** the send wrap reads the plaintext from `tx-msg[off..]` and writes the bracket into a SEPARATE pooled scratch, THEN `replace`s into `tx-msg` — no in-place aliasing (the bracket is +56 larger). The `-into` core's ENCRYPT in-place-GCM aliases only WITHIN the scratch (ZA-1 case (b)), never the caller's plaintext.
- **Origin-auth:** `receivers` non-empty keeps the allocating `%compute-receiver-macs` path — do NOT zero-alloc it in ZA-2 (deferred, documented).
- **Clasp first** for every `make test-*`; the known live-socket flake is the only acceptable Clasp full-suite abort.
- **The security-test file** for the new tests is `src/dds-tests/security-test.lisp`; register names in the `echo-test.lisp` dispatch alist next to the other `security-*`/`secured-*` entries.
