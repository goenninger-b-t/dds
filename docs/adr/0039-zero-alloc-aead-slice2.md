# ADR 0039 — Zero-alloc AEAD Slice 2: the `metadata_protection` (submessage) + `rtps_protection` (whole-RTPS) tiers (M7/P6 Slice-2 hardening)

- **Status:** Accepted (M7/P6; WP-DDS-SECURITY-ZEROALLOC-AEAD Slice 2, 2026-07-02)
- **Relates to:** ADR 0038 (Slice 1 — the `data_protection` serialized-payload tier **and the shared into-buffer
  foundation** this slice REUSES wholesale: the into-buffer AEAD FFI `aes-256-gcm-{seal,open}-into`,
  `dds.pal:static-sap+`, the per-`key-material` session-key cache `%km-session-key-at`, `%km-next-iv-suffix-into`,
  `%put-u32-be-at`, the arena buffer-pool pattern, and the wrapper trick that makes the byte-exact corpus prove the
  into-buffer core); ADR 0036 (Slice 4 — **Carry 3** [zero-alloc into-buffer AEAD on the data path] is **flipped to
  FULLY RESOLVED** here for the two remaining tiers → all three AEAD tiers zero-alloc; and the submessage /
  whole-RTPS codec cores [`%encode/%decode-secured-region`] + the dataplane wraps [`%maybe-wrap-srtps`,
  `%maybe-wrap-user-submessages`] this slice makes zero-alloc); ADR 0025 (DARE — the `dds-dare` AES-256-GCM /
  GMAC OpenSSL FFI); ADR 0034 (the auth key-material GC-heap deferral, carried forward unchanged);
  ADR 0037 (Slice 5 — the Fast-DDS interop wire this slice leaves byte-identical); the operating contract §4
  (hot-path purity; static-arena, RESOURCE_LIMITS-not-GC on exhaustion; bounds-check even at `(safety 0)`;
  clean-room, no wire constant from memory); NFR-MEM (steady state allocates **zero** bytes/sample); NFR-SEC-POSTURE
  (bounds-checked, fail-closed, fuzzed); NFR-PORT (Clasp + SBCL both validate, Clasp first; no reader conditionals
  outside `dds-pal/`); FR-SEC-2 (no hand-rolled crypto).
- **Standards:** OMG DDS-Security 1.1 §8.5.1.7–.9 (`encode/decode_data{writer,reader}_submessage`; the
  `SEC_PREFIX`(0x31) / `SEC_BODY`(0x30) / `SEC_POSTFIX`(0x32) sandwich); §8.5.1.10–.12 (`encode/decode_rtps_message`;
  the `SRTPS_PREFIX`(0x33) / `SRTPS_POSTFIX`(0x34) whole-datagram sandwich over the SAME shared region engine, RTPS
  Header verbatim); §9.5.3.3.1 (SecureDataHeader / CryptoHeader layout — `transformation_kind`(4) ∥
  `transformation_key_id`(4) ∥ `session_id`(4) ∥ `init_vector_suffix`(8)); §9.5.3.3.3 (SecureDataTag, 4-align);
  §9.5.3.3.4.2 (the session-key KDF); §9.5.3.3.4.3 (the 12-byte GCM nonce = `session_id ‖ init_vector_suffix`, **and**
  the receiver-specific MAC / origin authentication); §9.5.3.3.4.4/.5 (`crypto_content`). NIST SP 800-38D (AES-GCM +
  the pt-len-0 GMAC case). The existing byte-exact submessage / whole-RTPS / origin-auth / crypto-header corpora +
  NIST SP 800-38D Test Case 16 are the wire oracles. **No RTI Connext source, headers, or generated code was ever
  read** (clean-room; the into-buffer GMAC reproduces the allocating GMAC — and NIST — byte-for-byte).

---

## Context

ADR 0038 made the **`data_protection` (serialized-payload)** AEAD tier zero-alloc and, more importantly, built the
**shared into-buffer foundation** — an into-buffer AEAD FFI, `dds.pal:static-sap+`, a session-key cache, the
into-buffer-codec + thin-wrapper pattern, and the arena buffer-pool pattern. It scoped itself honestly to that one
tier: ADR-0036 **Carry 3** was left **PARTIALLY** resolved, with the other two AEAD tiers explicitly carried to
Slice 2. Those two tiers — **submessage (`metadata_protection`, §8.5.1.7–.9)** and **whole-RTPS
(`rtps_protection`, §8.5.1.10–.12, the ~2.2 KB/datagram dominant cost)** — still allocated per datagram: they ran
through the *allocating* shared core `%encode/%decode-secured-region` (which called the allocating `aes-256-gcm-seal`
/`-open`, `make-array`'d its scratch + `→octets` return + parse buffers), and the dataplane wraps `%maybe-wrap-srtps`
/ `%maybe-wrap-user-submessages` `subseq`'d their inputs and `alloc-static`'d a per-call `(+ len 8192)` scratch.

This slice makes both tiers allocate **zero GC-heap bytes/sample** on the live secured path (send **and** receive),
by REUSING the ADR-0038 foundation — one new SIGN-path FFI arm (a GMAC-into confirmation), an into-buffer codec
core (`%encode/%decode-secured-region-into`) over which the existing entries become thin wrappers, and five per-node
static scratch pools wired into the dataplane. Because `encode/decode-rtps-message` are pure delegations to the
shared region core, fixing the core fixes the whole-RTPS tier for free.

This ADR documents the **WP-DDS-SECURITY-ZEROALLOC-AEAD Slice 2 (ZA-2)** work package as built, from the
controller's commit-by-commit ledger (base `2f85940` off `main` … `dc04ffa` T5) on
`wp-dds-security-zeroalloc-aead-s2`.

---

## Scope — read this before the numbers (no overclaim)

**This slice makes the common ENCRYPT/SIGN, empty-receivers path of the submessage + whole-RTPS tiers zero-alloc,
send and receive.** With ADR-0038's `data_protection` tier, **all three AEAD tiers are now zero-alloc** on that
common path.

**Origin authentication (receiver-specific MACs, `..._WITH_ORIGIN_AUTHENTICATION`) is NOT made zero-alloc here.**
It remains the **deferred allocating fallback** — off the common empty-receivers path (the corpora and the e2e use
no origin-auth). The `-into` cores fall back to the allocating `%compute-receiver-macs` path when `receivers` is
non-empty (still written into the out-buffer, but it may allocate). **Do NOT read this as "origin-auth is
zero-alloc."** Zero-alloc-ing it needs a receiver-session-key cache parallel to `%km-session-key-at` + footer-region
MAC writes + a per-receiver GMAC-into (Residual (a)).

The **ZA-1 non-tier residuals** (key-material foreign-hardening, ZC × `rtps_protection` SHMEM cleartext,
saved-image foreign-pointer re-resolve, PAL atomics stubs) are **unchanged/open** — they are not specific to these
tiers and stay tracked under ADR 0038 (Residual (d)).

---

## Decision — as-built architecture

Five tasks (T1–T5), each its own commit + a two-stage review, holding the our-to-our-green + wire-byte-identical
invariant on both impls (Clasp first) after every step. Every `before → after` figure below is from the ledger
(SBCL `dds.pal:bytes-consed`; Clasp `bytes-consed` is 0 → the measured arms self-skip/smoke while the structural
asserts run on both — NFR-PORT). Commit chain: T1 `f7abac7` · T2 core `56d53a6` + AAD-region fix `f5ff0a8` · T3
core `9b0f735` + RX-race fix `6f272b5` · (`main` merged at `75ab3b2` — see the note below) · T4 core `7b9511e` +
pass-through-drop fix `6292744` · T5 `dc04ffa`.

### 1. GMAC-into confirmation for the SIGN branch (`src/dds-dare/primitives.lisp`, T1)

The SIGN (integrity-only) branch needs a pure GMAC tag with **no plaintext output**. T1 established that the ZA-1
`aes-256-gcm-seal-into` **already** computes exactly this for `pt-len = 0`: the existing pt/ct-len guards skip the
EVP `EncryptUpdate(PT)` / `DecryptUpdate(CT)` step and run AAD + Final + GET_TAG/SET_TAG only — i.e. the ZA-1 FFI
already supported the SIGN GMAC-into. So T1 added no EVP logic: it added **four KAT arms** proving `seal-into` with
`pt-len 0` + a non-empty AAD produces a tag byte-identical to the allocating `aes-256-gcm-seal` GMAC; `open-into`
verifies (T); a tampered tag → NIL; and an AAD-overlaps-OUT case is safe (EVP consumes AAD before GET_TAG,
confirmed by `:aes-gcm-gmac-overlap-out`), plus docstrings citing §9.5.3.3.4.3. Byte-identical, no wire change.

### 2. Into-buffer codec core + thin allocating wrappers + the AAD-region generalization (`src/dds-security/crypto/submessage.lisp`, `rtps-message.lisp`, T2 + T2-fix)

- `%encode-secured-region-into (out-buf out-off km mode plain plain-off plain-len receivers prefix-kind postfix-kind)
  → length` and `%decode-secured-region-into (pt-out pt-off km secured secured-off secured-len sign-walk-p)` — the
  zero-alloc cores. They build/parse the `PREFIX ‖ CryptoHeader ‖ (SEC_BODY[ct] | verbatim) ‖ POSTFIX[tag(+rsm)]`
  bracket by **raw offset** (no cursor struct — a `dds.core.buffer:cursor` heap-conses per call, the ZA-1 finding),
  byte-identical to the allocating `%encode/%decode-secured-region`. Geometry: hdr4 / sid12 / iv16 / mid24 / ct32;
  the 12-byte GCM nonce = the in-place CryptoHeader `session_id ‖ iv_suffix` sub-slice; `%km-session-key-at` (cached)
  + `aes-256-gcm-seal-into` seals ct+tag (ENCRYPT) or GMAC-into the tag (SIGN); `%put-u32-be-at` for `crypto_content`
  length + `rsm_count`; the `ct-pad = (−|ct|) mod 4` + the footer 4-align preserved. ENCRYPT bracket overhead **+56 B**
  (ct 32 B forward of the plaintext), SIGN **+48 B** (verbatim 24 B forward). No `make-array`/`subseq`/`alloc-static`.
- The existing `%encode/%decode-secured-region` + `%encode/%decode-secured-submessage` + the six
  `encode/decode-{datawriter,datareader,rtps}-{sub,}message` entries become **thin allocating wrappers** over the
  core (temp buffer → core → subseq), so the T2/T4 corpora exercise the core → byte-identity for free (the ZA-1
  trick). `encode/decode-rtps-message` are unchanged pure delegations → the whole-RTPS tier is fixed by the core.
- **T2-fix — the SIGN-decode AAD-region generalization (the load-bearing correctness fix).** The first cut of the
  SIGN decode passed `open-into` a **full-vector** AAD, so `%decode-secured-region-into`'s SIGN branch had to
  `(subseq secured region-off …)` to hand it the verbatim sub-range — one cons per datagram/submessage on the
  `rtps_protection = SIGN` / `metadata_protection = SIGN` RX path, defeating the "both tiers incl. SIGN" goal. The
  fix generalized **`aes-256-gcm-open-into` AND (in T3) `-seal-into`** with `&optional (aad-off 0) (aad-len (length
  aad))` — an **AAD region**: the AAD SAP is pinned via `with-pointer-to-vector-data` + `cffi:inc-pointer` at the
  offset, bounds-checked `(<= (+ aad-off aad-len) (length aad))`, zero cons, backward-compatible (existing callers
  byte-identical). SIGN encode/decode now GMAC over a **sub-range** with no subseq. **SIGN decode-into 49.14 →
  0.0000 B/call** (SBCL, 4000 iters); the DARE KAT + all corpora byte-identical UNCHANGED.
- An **oracle-pin** test (`%za2-region-into-combo`) pins the core output `equalp` to the FROZEN INDEPENDENT T2/T4
  goldens (88 / 80 / 100 / 92) — non-tautological (it pins the core, not the wrapper) — for both the SEC (submessage)
  and SRTPS (whole-RTPS) bracket kinds, ENCRYPT and SIGN. No golden was edited.

### 3. SRTPS (whole-RTPS) dataplane borrow + the per-thread RX-race fix (`src/dds-disc/{disc,dataplane}.lisp`, T3 + T3-fix)

- `%maybe-wrap-srtps` now `%encode-secured-region-into`s the `[20,len)` region (input **by offset**, no subseq) into
  a buffer borrowed from a **per-node send-scratch pool**, then `replace`s into the reused `tx-msg` in place; the
  per-call `alloc-static (+ len 8192)` is gone. Pool exhaustion → NIL (fail-closed drop, the existing
  required-but-failed contract) — never GC. Send-path alias-free: the plaintext is read from `tx-msg`, the bracket
  written into a SEPARATE scratch, then replaced back (the bracket is +56 larger). **SRTPS send 196.56 → 0.00.**
- **T3-fix — the shared-RX-buffer race (the review-caught Important).** The core landed with a single per-node
  `secure-rx-buf` written (decode-into) + read (replace) across up to **three** concurrent receiver threads
  (unicast / multicast / SHMEM) on the ENCRYPT RX path, with no sync — thread A could copy thread B's plaintext →
  wrong-sample delivery (bounded to authenticated, validly-sized peers, so not a security/memory bypass, but real and
  against the repo's fresh-per-call pattern). Fixed by a **pooled RX scratch** (`%with-secure-rx-scratch`): each
  decode borrows a **distinct** buffer per thread (keeps zero-alloc, no shared sink). This is the **secure-rx** pool
  (decode OUTPUT).

**(The `main` merge at `75ab3b2`.)** Between T3 and T4 the slice paused to fold in a `main` fix: a
`:rxo-incompatible-match` test flake — root-caused NOT to a production RxO bug but to a **non-hermetic test** (a
foreign `rtiddsspy` on the shared domain 0 inflating an exact match-count assert). The fix was test-domain
hermeticity only (configurable domain + peer-GUID-scoped match counting; no production change), shipped to `main`
and merged in. `:rxo-incompatible-match` passes on this branch.

### 4. Submessage (`metadata_protection`) multi-bracket dataplane borrow + the pass-through pre-scan (`src/dds-disc/{dataplane,secure-sedp}.lisp`, T4 + T4-fix)

- `%maybe-wrap-user-submessages` walks `[20,len)` and wraps each protectable user submessage via the `-into` core
  directly into a buffer borrowed from a **dedicated per-node submessage-scratch pool** (element-bytes ~10240, sized
  for the ~+56-octet-per-submessage bracket expansion; **distinct** from the send-scratch pool), dropping the
  `(make-octet-buffer (+ len 8192))` + the per-submessage `(subseq …)`; INFO_* pass-through via a raw copy; then
  `replace`s into `tx-msg` in place. `%on-user-secure-submessage`'s decode re-dispatch reuses a pooled RX buffer.
  **metadata send 196–213 → 0; metadata RX decode 98 → 0.**
- **T4-fix — the pass-through-drop-on-exhaustion regression (the review-caught Important).** The core acquired the
  scratch BEFORE checking whether anything needed wrapping, so on pool exhaustion it **dropped a pass-through
  datagram** (all INFO_*/declined submessages — needs no protection); the old code never dropped a no-wrap datagram.
  Fixed with a **zero-alloc pre-scan** of `[20,len)` (raw offset, no cons) that runs when the scratch is
  unavailable: **none protectable → return len** (pass-through, byte-identical); **some protectable → NIL**
  (fail-closed). Crucially it is **DRY** with the wrap loop — `%user-submessage-protectable-p` (the
  `writer-p`/`reader-p` AND resolver-returns-KM predicate) and `%submessage-extent` are shared by BOTH the wrap path
  AND the pre-scan, so the two **cannot diverge** (closing the security-critical under-detect risk of a pre-scan that
  silently protects less than the wrap loop would).

### 5. Live `make mem` arms + the RX INPUT residuals (`src/dds-disc/secure-sedp.lisp`, `src/dds-tests/*`, T5)

- **Four deterministic live `make mem` arms** (`run-secured-dataplane-mem-test`, wired into `make mem`): metadata +
  rtps × send + receive, each reporting `plain=.. secured=.. → delta B/sample`, all **0.0000 B/sample over the
  non-secured baseline** on SBCL (Clasp smokes). So **both tiers are zero-alloc send AND receive, end-to-end.**
- Closing that loop required eliminating two RX-INPUT residuals the send-side work had left:
  - **bracket-rx pool** (decode INPUT): the pre-T5 `%handle-datagram` `make-array`'d the SEC bracket vector per user
    `SEC_PREFIX`. Replaced by a pooled per-thread bracket scratch (`%with-bracket-rx-scratch`).
  - **key-id-rx pool** (the 2nd residual): reading the §9.5.3.3.1 4-octet `transformation_key_id` for the
    `equalp`-keyed resolvers was a per-datagram `subseq`. Replaced by a pooled 4-octet per-thread scratch
    (`%secure-bracket-key-id-into`). (A `dynamic-extent` stack array cannot serve — this SBCL heap-allocates
    dynamic-extent *specialized* `(unsigned-byte 8)` arrays, and the resolvers require a specialized array; see
    Residual (b).)
- **Exhaustion → fail-closed drop, never GC** (asserted for send AND receive): a drained send/submsg-scratch pool →
  the required wrap returns NIL (RESOURCE_LIMITS backpressure); a drained bracket-rx pool → a metadata datagram is
  dropped (its on-data hook never fires — a `make-array` GC fallback would have delivered it) then delivered once the
  pool is released (non-vacuous). The drop lands only on **reliable/retried** paths (reliable PVMS + secure-SEDP,
  ACKNACK-repairable / re-solicited), never on the best-effort plain-DATA PSM auth (which is PLAIN DATA, not a SEC
  bracket, so it never touches these pools).

### The five per-node scratch pools

All five are **foreign/static** (arena + `make-buffer-pool`), **lazy-carved** on the first secured send/receive (zero
static memory when no secured traffic occurs), **per-thread-distinct** borrows via the one DRY `%with-scratch`
macro (a double-checked carve under a dedicated per-pool lock, then acquire/release per operation → a distinct buffer
per concurrent thread, no shared sink), and **torn down in `stop-node`**. Capacity is `*srtps-send-scratch-capacity*`
(default 8) — comfortably over the ≤3 receiver threads + the concurrent sender threads (publish caller / receiver
ACKNACK / async sender / flow scheduler).

| Pool | Role | Element bytes | Replaces |
|---|---|---|---|
| `send-scratch` | SRTPS wrap output (`%maybe-wrap-srtps`) | datagram-sized (~10240) | the per-call `alloc-static (+ len 8192)` + the `[20,len)` subseq |
| `submsg-scratch` | multi-bracket submessage wrap output (`%maybe-wrap-user-submessages`) | ~10240 (sized for +56/submessage) | the `(make-octet-buffer (+ len 8192))` + per-submessage subseq |
| `secure-rx` | decode OUTPUT (SRTPS unwrap / re-dispatch), distinct per unwrap | datagram-sized | the shared per-node `secure-rx-buf` (T3 race fix) |
| `bracket-rx` | decode INPUT — the SEC bracket sub-region copy | datagram-sized | the per-`SEC_PREFIX` `make-array` (T5) |
| `key-id-rx` | the 4-octet `transformation_key_id` scratch | 4 | the per-datagram key_id `subseq` (T5) |

---

## The proof (the DoD)

- **`make mem` security-ON Slice-2 arms (SBCL), all 0.0000:** `meta-send`, `meta-recv`, `rtps-send`, `rtps-recv` all
  report `delta 0.0000 B/sample` over the non-secured baseline (deterministic — the transform is measured in
  isolation over reused buffers + the per-node pools, so there is no cross-node framing / GC-boundary noise; the
  arms assert `< 1.0` on SBCL, smoke on Clasp). Component before → after (from the ledger): SRTPS send 196.56 → 0.00;
  metadata send 196–213 → 0; metadata RX decode 98 → 0; SIGN decode-into 49.14 → 0.0000.
- **Exhaustion = backpressure, never GC (both sides):** send/submsg-scratch drained → the required wrap fails-closed
  NIL (RESOURCE_LIMITS); bracket-rx drained → the metadata datagram is dropped then delivered on release
  (non-vacuous). No heap fallback either side.
- **Wire byte-identical throughout:** the T2 submessage (ENCRYPT 88 / SIGN 80), T4 whole-RTPS (ENCRYPT 100 / SIGN
  92), origin-auth (128 / 120), T1 crypto-header/footer, and **every** ZA-1 payload byte-exact corpus stay green
  **UNCHANGED** (no regeneration); the allocating entries route through the `-into` cores and the oracle-pin pins the
  core to the frozen goldens. The DARE / NIST GMAC KAT is byte-identical. The diff is the FFI AAD-region arm + the
  into-buffer cores + the five pools + the dataplane rewiring + tests + docs — **no wire change**.
- **Honest scope:** the arms measure the cost of enabling the tier's transform OVER the non-secured baseline — the
  re-dispatch that then delivers a recovered PLAIN submessage IS the non-secured baseline and is excluded (it conses
  no more than receiving that plain submessage always did). Origin-auth is not measured (deferred allocating).

---

## Consequences

- **NFR-MEM:** `make mem` now covers **all three AEAD tiers** and reports 0.0000 for `data_protection` (ADR 0038) +
  `metadata_protection` + `rtps_protection` (this ADR), encode + decode, send + receive. This **fully resolves
  ADR-0036 Carry 3** (common ENCRYPT/SIGN path) and marks ADR-0038 Residual (a) RESOLVED.
- **NFR-SEC-POSTURE:** the `-into` cores bounds-check every offset/length against the input extent before reading
  (O(1) checks that hold at `(safety 0)`), the SIGN (offset,len) bounds are validated within `secured`, and decode is
  fail-closed (NIL, no plaintext, no re-dispatch on failure); the pass-through pre-scan shares its protectability
  predicate with the wrap loop (no under-detect); the submessage / rtps-message fuzz arms still pass; pool exhaustion
  is a graceful RESOURCE_LIMITS drop, not a crash.
- **FR-SEC-2:** no hand-rolled crypto — AES-256-GCM / GMAC via `dds-dare` (OpenSSL EVP), the into-buffer entries the
  same EVP calls writing through caller SAPs, NIST-KAT byte-identical.
- **NFR-PORT:** no new PAL primitive (the AAD-region rides the ZA-1 `static-sap+` FFI); no reader conditionals
  outside `dds-pal/`. Clasp + SBCL both validate (Clasp first); the measured-alloc arms self-skip on Clasp
  (`bytes-consed` 0) while the structural exhaustion / fail-closed asserts run on both.
- **Hot-path purity:** the codec cores + the five pools use `defstruct` + monomorphic functions + the DRY
  `%with-scratch` macro; no per-sample CLOS dispatch. `gate-hotpath` green.
- **Default-OFF / byte-identical:** security-OFF, and any tier = NONE, keep the plain path byte-identical (the wrap is
  a no-op when the resolver is absent; the pre-scan returns len).
- **Gates (final sweep, both impls, Clasp first):** see §Gate sweep below.

---

## Residual carries (recorded, NOT fixed here)

**(a) Origin authentication (receiver-specific MACs) zero-alloc — ✅ RESOLVED (WP-SECURITY-ORIGIN-AUTH-ZEROALLOC,
2026-07-02; live-path residual closed in the same WP).** The `..._WITH_ORIGIN_AUTHENTICATION` tier (a
per-matched-receiver GMAC under the receiver's key, §9.5.3.3.4.3) is now zero GC-heap alloc/sample on the **live
secured datagram path, send AND receive** — closing the last allocating AEAD path (all three tiers + origin-auth now
zero-alloc). Two layers had to go zero-alloc, and the first cut only did one of them:
- **The AEAD transform** (the receiver-MAC encode/decode). As predicted here, it took exactly a receiver-session-key
  cache parallel to `%km-session-key-at` (`%km-receiver-session-key-at` + three cache slots on `key-material`,
  single-slot / fence-published — the master key is part of the discriminant so a wrong-key probe never shares a
  slot), footer-region MAC writes by offset, and a per-receiver GMAC-into: encode via `%put-receiver-macs-into`
  (`aes-256-gcm-seal-into` `pt-len 0` straight into the CryptoFooter over the in-place `common_mac`/nonce), decode via
  `%verify-receiver-mac-into` (find the entry by offset, verify its GMAC in place via `aes-256-gcm-open-into`
  `ct-len 0`).
- **The receiver-descriptor RESOLVER** (the live-path residual, closed here). The transform above is genuinely
  zero-alloc, but the `dds.dcps` origin-auth resolvers that FEED it — `cm-rtps-encode-receivers` /
  `cm-rtps-decode-receiver` (whole-RTPS, per datagram) and the secure-SEDP `cm-secure-sedp-{encode,decode}-receiver`
  pair — still consed the `(list (cons receiver_specific_key_id . master_receiver_specific_key))` descriptor **per
  call**: the SEND `(list (cons …))` = 32.10 B/datagram, the RECV `(cons …)` = 16.05 B/datagram (SBCL, escaping-sink
  microbench). The fix MEMOIZES that descriptor list on the `key-material` — one `cached-receiver-descriptor-list`
  slot, built once from the IMMUTABLE receiver fields, cache-probed first so the hit path is a pure slot load +
  ACQUIRE fence (release-fence-published on the one-time cold build), exposed as `dds.security:km-receiver-descriptor`
  / `km-receiver-descriptor-list` and returned by all four resolvers. Invalidation is structural: re-keying mints a
  NEW `key-material` (fresh empty cache) and participant loss drops the KM (and its cache), so a stale descriptor is
  impossible — the exact `%km-session-key-at` invalidation model. Pure control-plane caching: same descriptor content,
  same key per datagram, wire unchanged. **Before → after: SEND 32.10 → 0.00, RECV 16.05 → 0.00 B/datagram.**

Wire byte-identical (the T3 `128`/`120` corpus stays green unchanged); receiver-MAC gate unchanged (bad/absent MAC →
fail-closed drop). **Proof (honest, live-path):** the `make mem` `oauth-send`/`oauth-recv` arms now DRIVE the real
memoized resolver (`dds.security:km-receiver-descriptor{-list}`, the exact call the installed `cm-rtps-*-receiver{s}`
make) INSIDE the measured window — not a pre-built stub list — so they measure the **live origin-auth datagram path
(resolver + transform)** and still report `delta 0.0000 B/sample` (SBCL; Clasp smokes). The first cold-cache fill
amortizes off the measured window; the reported 0.0000 is warmed steady-state (matching the `%km-session-key-at`
convention). `run-security-origin-auth-test` block (4) proves the `-into` verify entries round-trip + fail-closed
(non-vacuous), and `run-security-crypto-manager-test` drives the T10 `cm-rtps-*` resolvers through the memoized path.
The old allocating `%compute-receiver-macs` / `%verify-receiver-mac` / `%parse-sec-postfix-mac` are retained as
byte-identity reference implementations. **No residual remains — both send and receive are closed.**

**(b) `key-id-rx` third pool vs a packed-fixnum key — ACCEPTED AS DESIGNED (WP-ADR-SMALL-CARRIES C1, 2026-07-03;
not an open residual).** The 4-octet `transformation_key_id` scratch is a third per-node RX pool because a
`dynamic-extent` stack array does not stack-allocate for a *specialized* `(unsigned-byte 8)` array on this SBCL, and
the `equalp`-keyed resolvers (`cm-*-by-key-id`, secure-SEDP DECODE) require a specialized array. **The pool is the
accepted design:** it is **bounded** (4 bytes × capacity, the same `*srtps-send-scratch-capacity*` headroom as the
other four pools), **per-thread-distinct** (each receiver thread borrows its own buffer via the one DRY
`%with-scratch` macro — no shared sink, no race), **zero-alloc** on the hit path (a pool borrow, not a `subseq`),
torn down at `stop-node`, and self-healing (an allocating heap-4-array fallback on carve failure — correct,
byte-identical). The alternative that drops the pool — re-keying every resolver by the 4 octets packed into a fixnum
— was **assessed and rejected as high-ripple / low-value**: the fixnum key would ripple through the crypto-manager
key_id index **and ~12 test lambdas** (every `equalp`-keyed decode resolver + its fixtures) for no allocation,
correctness, or wire benefit over the already-bounded, already-zero-alloc pool. No code change; recorded as the
settled decision.

**(c) The `meta-recv` mem arm defense-in-depth. — RESOLVED (WP-ADR-SMALL-CARRIES C2, 2026-07-03).** The `meta-recv`
arm formerly inlined the RX transform (pooled bracket extract + stack-free key_id read + resolve + distinct-pool
decode-into) rather than driving the production `%on-secure-submessage` hook, so a future alloc slipping into the
dispatch WRAPPER (`%on-secure-submessage` / `%on-user-secure-submessage`) would not be caught by `make mem` — only by
the e2e secure-discovery tests, which do not measure allocation. **Closed by C2:** the arm now drives the REAL
`%on-secure-submessage` via a DIFFERENTIAL that cancels the re-dispatch delivery cost the capstone was worried about
— BASE = `%handle-datagram` on the recovered PLAIN datagram (the non-secured baseline: parse/deliver, no transform);
SEC = the `%with-bracket-rx-scratch` copy (mirroring `%handle-datagram`) + `%on-secure-submessage` (key-id-rx resolve
→ `%on-user-secure-submessage` decode into secure-rx → the SAME re-dispatch). The identical re-dispatch cancels, so
the delta is the dispatcher's OWN alloc. **The defense-in-depth immediately paid off: it surfaced a real ~49 B/sample
residual** — `%on-user-secure-submessage` consed a `dds.core.buffer:cursor` per received sample solely to write the
20-octet RTPS Header before re-dispatch (a zero-alloc regression the isolated arm never saw). **Fixed** with a
zero-alloc raw-offset `dds.rtps.message:write-header-into` (byte-identical to `write-header`, mirroring
`put-info-src-into`), so the user metadata_protection RECEIVE path is genuinely zero-alloc. To keep the delta HONEST,
BASE re-dispatches `RXFIXED` — a datagram built by the SAME decode + `write-header-into` — so the two `%handle-datagram`
re-dispatches are byte-identical and cancel exactly. **The SEC pooled RX ops add 0 real B/sample; `meta-recv` reports a
stable ~0.16 B/sample through the real dispatcher** (SBCL; Clasp smokes) — that residual is **one 64 KB GC-region quantum
amortized over 400 k iters** (`bytes-consed` rounds to the GC boundary the large ~176 B cancelling re-dispatch crosses;
it scales as 65536/n, proving it is measurement quantization, NOT a per-sample alloc), well under the `< 1.0` NFR-MEM
gate. **A second finding, honestly recorded:** an EXACT `0.0000` is NOT achievable while the ~176 B re-dispatch is inside
the measured window (the GC quantum is irreducible for any practical iter count) — which VALIDATES the capstone's
deferral rationale; the quantization is amortized (not stubbed) rather than the re-dispatch excluded. No stub, no wire
change — the recovered header is byte-identical, the corpora + KAT stay green unchanged.

**(d) The ZA-1 non-tier residuals — unchanged/open (tracked under ADR 0038).** Not specific to these two tiers, so
not touched here: KeyMaterial GC-heap → foreign + zeroize (ADR-0034 deferral); Zero-Copy × `rtps_protection` SHMEM
cleartext (ADR-0036 Carry 10); saved-image foreign-pointer staleness — **RESOLVED (WP-ADR-SMALL-CARRIES C3):** the
`load-time-value`-cached EVP pointers went stale across `save-lisp-and-die`; `%ossl-sym` now resolves through a
re-resolvable box and an image-restart hook (`%dare-reresolve-foreign-pointers`, registered via the new portable
`dds.pal:register-image-restart-hook` — SBCL `*init-hooks*` / Clasp `core:*initialize-hooks*`) re-resolves every box
+ the cipher on startup (ADR 0038 Residual (d)); the M0 PAL atomics stubs (`dds.pal:cas`/`atomic-incf` unimplemented
→ the send-refcount uses the writer lock). Also carried from
ADR 0038 Residual (a): when a future `rtps_protection` **rekeying** (session_id rotation) lands, it must confirm the
decode receiver stays single-threaded per km OR harden `%km-session-key-at`'s two-slot publish against a
concurrent-different-session_id tear (the fence protocol is tear-safe only while session_id is effectively constant
per km).

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
| 1-HARDENING | Zero-alloc AEAD: the `data_protection` tier + the shared into-buffer foundation (ADR 0038) | LANDED |
| **2-ZEROALLOC (this ADR)** | **Zero-alloc AEAD: the `metadata_protection` (submessage) + `rtps_protection` (whole-RTPS) tiers → all three AEAD tiers zero-alloc (ADR 0039)** | **LANDED** |

---

## Gate sweep (final, both impls, Clasp first)

- `make build` (Clasp + SBCL): PASS.
- `make test-clasp` / `make test-sbcl`: **394 / 394** (the sweep's Clasp full-suite run was clean — no NFR-PORT
  live-socket-flake abort this run; `:rxo-incompatible-match` fixed → passes).
- `make corpus`: PASS (M1 byte-exact XCDR placeholder — unchanged; the security byte-exact corpora run under `make test`).
- `make fuzz` (both impls): PASS (incl. the submessage §8.5.1.7-.9 / origin-auth §9.5.3.3.4.3 / rtps-message
  §8.5.1.10-.12 security arms, 2500 iters each, prod + `(safety 0)`).
- `make gate-hotpath`: PASS (8 hot-path files clean).
- `make gate-types`: PASS (all 2132 defuns ftype-declared).
- `make mem`: **0.0000 all arms** — the four ZA-2 arms `meta-send` / `meta-recv` / `rtps-send` / `rtps-recv` each
  `delta=0.0000 B/sample`; plus the ZA-1 `aead-encode`/`-decode`/`-encode-live`/`-live-rx` 0.0000 and `aead-live-pub`
  delta 0.3278 B/sample (< 2.0 GC-quantum); the `secured-region-into` ENCODE + SIGN-decode-into cores 0.0000 B/call;
  exhaustion fail-closes (metadata + SRTPS send → NIL; bracket-rx receive → drop-then-deliver) with no GC fallback.
- `make bench`: **N/A** — this WP is an allocation change; the before/after IS `make mem`. The wire and the CDR hot
  path are byte-identical, so latency/throughput is unchanged. The per-component `before → after` B/sample figures are
  in this ADR.

---

## References

- Design spec: `docs/superpowers/specs/2026-07-01-zero-alloc-aead-slice2-design.md`; plan:
  `docs/superpowers/plans/2026-07-01-zero-alloc-aead-slice2.md`
- `src/dds-dare/primitives.lisp` — `aes-256-gcm-{seal,open}-into` `&optional aad-off aad-len` (the AAD-region
  generalization) + the pt-len-0 GMAC-into
- `src/dds-security/crypto/submessage.lisp` — `%encode/%decode-secured-region-into` cores + the thin allocating
  wrappers + the six `-into` entries; `src/dds-security/crypto/rtps-message.lisp` — `encode/decode-rtps-message-into`
- `src/dds-disc/disc.lisp` — the five per-node scratch pools + `%with-scratch` / `%with-{send,secure-rx,bracket-rx,key-id-rx}-scratch` + `*srtps-send-scratch-capacity*` + init/teardown
- `src/dds-disc/dataplane.lisp` — `%maybe-wrap-srtps` + `%maybe-wrap-user-submessages` + `%user-submessage-protectable-p` / `%submessage-extent` (DRY, wrap + pre-scan) over the pooled scratch
- `src/dds-disc/secure-sedp.lisp` — `%on-user-secure-submessage` re-dispatch over the pooled RX buffers + `run-secured-dataplane-mem-test` (the four live arms + exhaustion)
- `src/dds-tests/{dare,security}-test.lisp` — the GMAC-into KAT arm + the `%za2-region-into-combo` oracle-pin + the zero-alloc region-into tests
- `docs/wiki/security.md` §3.4 — the zero-alloc secured-send/receive pools + the secured-read contract
- ADR 0038 (Slice 1 + the shared foundation), ADR 0036 (Carry 3, flipped fully resolved here), ADR 0025 (DARE FFI), ADR 0034 (key-material deferral), ADR 0037 (Fast-DDS interop wire)
