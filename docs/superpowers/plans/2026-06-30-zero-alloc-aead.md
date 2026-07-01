# Zero-Alloc AEAD (Slice 1: data_protection tier) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the data_protection (serialized-payload) AES-256-GCM tier allocate zero GC-heap bytes/sample in steady state, proven by a new security-ON `make mem` arm, with the wire output byte-identical (the byte-exact corpus + NIST KAT stay green).

**Architecture:** Add into-buffer FFI entries that write the EVP ciphertext/tag/plaintext through a caller's static-vector SAP (no `make-array` outputs); cache the per-KeyMaterial session key (it is constant for a fixed `session_id`, so the per-sample KDF is removed); add an into-buffer codec core that builds/parses the SecuredPayload in a caller-provided static buffer (the GCM nonce is the in-place `session_id‖iv_suffix` header sub-slice, so no nonce buffer); refactor the existing allocating `encode/decode-serialized-payload` into thin wrappers over the core so the byte-exact corpus proves byte-identity for free; wire the live data_protection path to the core; add `run-mem-test-secure`.

**Tech Stack:** Common Lisp (SBCL + Clasp), CFFI over OpenSSL EVP (`src/dds-dare`), the PAL static allocator (`dds.pal:alloc-static`/`static-pointer`), `dds.core.buffer` octet-buffers, the `defun*`/`defstruct*` macros.

**Branch:** `wp-dds-security-zeroalloc-aead` (create from `main`); squash-merge to `main` at the end.

## Global Constraints

- **Byte-identical wire:** this is an allocation change, NOT a wire change. The NIST AES-GCM KAT (`run-dare-aes-gcm-kat-test`) and every byte-exact security corpus (`run-security-secured-payload-corpus-test`, `run-security-secured-payload-pad-corpus-test`, the crypto-header / submessage / rtps goldens) stay green **unchanged**. NEVER regenerate a corpus or weaken/delete a test.
- **our-to-our green BOTH impls (Clasp first) after every task:** `make test-clasp` + `make test-sbcl` + `make corpus` + `make fuzz` + `make gate-hotpath` + `make gate-types` + `make mem`. Clasp may abort only at the known NFR-PORT live-socket flake `[SDP-SEC-PREFIX-ON-WIRE]`/`[SDP-BYTE-EXACT]` (re-run / isolation-verify, don't chase).
- **Hot-path purity:** no CLOS dispatch, no per-sample object instantiation on the codec/FFI path; `defstruct` + monomorphic functions only.
- **Static memory:** anything addressed by a raw SAP is foreign/static (`dds.pal:alloc-static`), never a GC-heap array. `static-vectors` are foreign-allocated with a GC-stable SAP — no extra pinning is needed for the EVP call.
- **Bounds-checked + fail-closed receive even at `(safety 0)`:** every offset/length is validated against the input extent before reading; `*-open-into` / `decode-*-into` return NIL on auth-failure or malformed input and leave NO readable plaintext in the output buffer; the T10 empty-AAD `find_key` integrity gate (wire kind+key_id must equal the KM) is preserved.
- **`defun*`/`defstruct*` + full `ftype` on every function; one-line comments only; no reader conditionals (`#+sbcl`/`#+clasp`) outside `dds-pal/`.**
- **No AI-assistant attribution anywhere; cite "the operating contract §N", never the config filename. SBOM auto-regenerates via the pre-commit hook (never hand-edit). Clean-room: no RTI source.**
- **Docs in lockstep:** every new exported symbol gets a docstring (with the spec clause for wire constants); ADR 0038 at the capstone.

---

## File Structure

- `src/dds-dare/primitives.lisp` — add `aes-256-gcm-seal-into`, `aes-256-gcm-open-into` (clones of the existing entries; outputs via SAP). The existing `aes-256-gcm-seal`/`-open` are **unchanged**.
- `src/dds-dare/packages.lisp` — export the two new symbols from `dds.dare`.
- `src/dds-security/key-material.lisp` — add the session-key cache slots to the `key-material` defstruct + `%km-session-key-at`.
- `src/dds-security/transform.lisp` — add `%km-next-iv-suffix-into`, `encode-serialized-payload-into`, `decode-serialized-payload-into`; refactor `%seal-with-km`/`%open-with-km` to use the cache; refactor `encode/decode-serialized-payload` into wrappers over the core.
- `src/dds-security/packages.lisp` — export `encode-serialized-payload-into` / `decode-serialized-payload-into`.
- `src/dds-tests/dare-test.lisp` — add the `-into` KAT arm to `run-dare-aes-gcm-kat-test`.
- `src/dds-tests/gen-test.lisp` (or the security test file) — add `run-mem-test-secure`; call it from `run-mem-test` (or wire it into the `mem` target).
- `src/dds-dcps/crypto-manager.lisp` + `src/dds-disc/dataplane.lisp` — Task 5 wires the live data_protection encode/decode call sites to the core.

---

## Task 1: Into-buffer AES-GCM FFI

**Files:**
- Modify: `src/dds-dare/primitives.lisp` (add after `aes-256-gcm-open`, ~line 340)
- Modify: `src/dds-dare/packages.lisp` (export the two symbols)
- Test: `src/dds-tests/dare-test.lisp` (extend `run-dare-aes-gcm-kat-test`, ~line 131)

**Interfaces:**
- Produces:
  - `aes-256-gcm-seal-into (out ct-off tag-off key nonce-vec nonce-off aad pt pt-off pt-len) → (eql t)` — AES-256-GCM seal writing `pt-len` ciphertext octets into `out[ct-off..]` and the 16-byte tag into `out[tag-off..]` through `out`'s static SAP; nonce = `nonce-vec[nonce-off..+12]`; plaintext = `pt[pt-off..+pt-len]`; AAD authenticated. `out` MUST be a static (`alloc-static`-backed) vector. No `make-array`. Zeroizes the foreign key buffer; signals on EVP error.
  - `aes-256-gcm-open-into (pt-out pt-off key nonce-vec nonce-off aad ct-vec ct-off ct-len tag-vec tag-off) → (or (eql t) null)` — AES-256-GCM open writing `ct-len` plaintext octets into `pt-out[pt-off..]` (static SAP) on auth-success → T; on failure → NIL with NO readable plaintext written. nonce = `nonce-vec[nonce-off..+12]`, ciphertext = `ct-vec[ct-off..+ct-len]`, tag = `tag-vec[tag-off..+16]`.
- Consumes: `dds.pal:static-pointer`, the existing `%ossl-sym` + `+aes-256-gcm-key-len+`/`+aes-gcm-nonce-len+`/`+aes-gcm-tag-len+`/`+gcm-ctrl-*+` constants (all already in `primitives.lisp`).

**Method:** clone the existing `aes-256-gcm-seal` (primitives.lisp:150) body verbatim, then make exactly these changes: (1) delete the two `(make-array …)` output allocations (`ciphertext`, `tag`); (2) the EVP ciphertext output pointer is `(cffi:inc-pointer (dds.pal:static-pointer out) ct-off)` and the tag is extracted into `(cffi:inc-pointer (dds.pal:static-pointer out) tag-off)` — write directly through `out`'s SAP instead of into `ct-ptr`/`tag-ptr`+copy-out; (3) the nonce copy-in reads `nonce-vec[nonce-off + i]`; the plaintext copy-in reads `pt[pt-off + i]` for `i < pt-len`; (4) return `t`. Inputs (key/nonce/aad/pt) keep the existing `with-foreign-pointer` copy-in staging (stack-foreign, non-consing). Same EVP calls in the same order ⇒ byte-identical output. Mirror the same changes for `aes-256-gcm-open-into` from `aes-256-gcm-open` (primitives.lisp:266): write plaintext through `pt-out`'s SAP at `pt-off`; on auth failure (the `EVP_DecryptFinal_ex` rc≠1 branch) zero the written region and return NIL; on success return `t`.

- [ ] **Step 1: Write the failing test** — extend `run-dare-aes-gcm-kat-test` (after the existing seal/open KAT assertions, before the final `t`):

```lisp
    ;; into-buffer variants must be byte-identical to the allocating entries (NIST TC16)
    (let* ((out (dds.pal:alloc-static (+ 60 16)))      ; ct(60) || tag(16)
           (nonce-s (dds.pal:alloc-static 12))
           (pt-s (dds.pal:alloc-static 60)))
      (replace nonce-s nonce) (replace pt-s pt)
      (dds.dare:aes-256-gcm-seal-into out 0 60 key nonce-s 0 aad pt-s 0 60)
      (%check :aes-gcm-seal-into-ct  (equalp (subseq out 0 60) expected-ct) "seal-into: CT must match NIST KAT")
      (%check :aes-gcm-seal-into-tag (equalp (subseq out 60 76) expected-tag) "seal-into: tag must match NIST KAT")
      (let ((pt-out (dds.pal:alloc-static 60)))
        (%check :aes-gcm-open-into-ok (eq t (dds.dare:aes-256-gcm-open-into pt-out 0 key nonce-s 0 aad out 0 60 out 60))
                "open-into: must return T for valid (ct,tag)")
        (%check :aes-gcm-open-into-rt (equalp pt-out pt) "open-into: plaintext must round-trip")
        (setf (aref out 60) (logxor (aref out 60) 1))   ; tamper tag
        (%check :aes-gcm-open-into-tamper
                (null (dds.dare:aes-256-gcm-open-into pt-out 0 key nonce-s 0 aad out 0 60 out 60))
                "open-into: tag tamper must return NIL (fail-closed)")
        (dds.pal:free-static pt-out))
      (dds.pal:free-static out) (dds.pal:free-static nonce-s) (dds.pal:free-static pt-s))
```

- [ ] **Step 2: Run the test, verify it fails** — `make test-sbcl 2>&1 | grep -iE 'seal-into|open-into|undefined'` → FAIL/undefined (`aes-256-gcm-seal-into` not defined).
- [ ] **Step 3: Implement** `aes-256-gcm-seal-into` + `aes-256-gcm-open-into` per Method; export both from `dds.dare` in `src/dds-dare/packages.lisp`. Full `ftype`, one-line comments, docstrings citing NIST SP 800-38D.
- [ ] **Step 4: Run the test, verify it passes** — `make test-sbcl 2>&1 | grep -iE 'aes-gcm'` → all `aes-gcm-*` checks PASS; the existing `:aes-gcm-ct-kat`/`:aes-gcm-tag-kat` still PASS (allocating entries unchanged).
- [ ] **Step 5: Gates + commit** — `make test-clasp` (Clasp first) then `make test-sbcl gate-hotpath gate-types`; commit:
```bash
git add src/dds-dare/primitives.lisp src/dds-dare/packages.lisp src/dds-tests/dare-test.lisp
git commit -m "feat(security): WP-DDS-SECURITY-ZEROALLOC-AEAD — into-buffer aes-256-gcm-seal-into/open-into (SAP outputs, NIST-KAT byte-identical) (M7/P6 Slice 1)"
```

---

## Task 2: Session-key cache on KeyMaterial

**Files:**
- Modify: `src/dds-security/key-material.lisp` (defstruct `key-material` ~line 23; add `%km-session-key-at`)
- Modify: `src/dds-security/transform.lisp` (`%seal-with-km` :84, `%open-with-km` :99)

**Interfaces:**
- Produces: `%km-session-key-at (km session-id-vec session-id-off) → (simple-array (unsigned-byte 8) (32))` — returns the cached session key when `session-id-vec[off..off+4]` matches the KM's cached id (byte-compared IN PLACE, no allocation); else derives (`derive-session-key` over `(subseq session-id-vec off (+ off 4))`), caches, returns. Lock-free + zero-alloc on the hit path; the rare miss re-derives (a benign same-value race is harmless — master key+salt+session-id fully determine the key). Taking (vec, off) lets BOTH encode (vec = `+fixed-session-id+`, off 0) and decode (vec = the `secured` input, off 8) reach it without slicing a per-sample session_id.
- Consumes: `derive-session-key` (crypto.lisp:211).

- [ ] **Step 1: Write the failing test** — add to the security suite (e.g. a new `run-security-session-key-cache-test`, registered in the dispatch table):

```lisp
(defun* run-security-session-key-cache-test ()
    (function () t)
  "The session-key cache returns the SAME key as a fresh derive, and reuses it for a repeated session_id."
  (let* ((km (make-test-key-material))
         (sid (copy-seq +fixed-session-id+))
         (direct (derive-session-key (key-material-master-sender-key km)
                                     (key-material-master-salt km) sid))
         (k1 (%km-session-key-at km sid 0))
         (k2 (%km-session-key-at km sid 0)))
    (%check :skcache-correct (equalp k1 direct) "cached key must equal a fresh derive")
    (%check :skcache-reused  (eq k1 k2) "second call with the same session_id must return the SAME object (cache hit)")
    t))
```

- [ ] **Step 2: Run, verify it fails** — `make test-sbcl 2>&1 | grep -iE 'skcache|%km-session-key|undefined'` → FAIL (undefined).
- [ ] **Step 3: Implement.** Add two slots to the `key-material` defstruct (after `iv-counter-lock`):
```lisp
  (cached-session-id  nil :type (or null (simple-array (unsigned-byte 8) (*))))
  (cached-session-key nil :type (or null (simple-array (unsigned-byte 8) (32))))
```
Add `%km-session-key-at` (byte-compares the 4-octet session_id at `session-id-vec[off..off+4]`, zero-alloc on hit):
```lisp
(defun* %km-session-key-at (km session-id-vec session-id-off)
    (function (key-material (simple-array (unsigned-byte 8) (*)) fixnum) (simple-array (unsigned-byte 8) (32)))
  "Cached §9.5.3.3.4.2 session key for KM at the 4-octet session_id in SESSION-ID-VEC[OFF..OFF+4]. The key is
   constant for a fixed master key + salt + session_id, so it is derived once and reused (the per-sample KDF is
   removed). Hit path is lock-free + zero-alloc (the cached id is byte-compared in place); a miss re-derives +
   caches (a benign same-value race is harmless)."
  (let ((cid (key-material-cached-session-id km)))
    (if (and cid (= (length cid) 4)
             (= (aref cid 0) (aref session-id-vec session-id-off))
             (= (aref cid 1) (aref session-id-vec (+ session-id-off 1)))
             (= (aref cid 2) (aref session-id-vec (+ session-id-off 2)))
             (= (aref cid 3) (aref session-id-vec (+ session-id-off 3))))
        (key-material-cached-session-key km)
        (let* ((sid (subseq session-id-vec session-id-off (+ session-id-off 4)))   ; miss only (once per session_id)
               (k (derive-session-key (key-material-master-sender-key km)
                                      (key-material-master-salt km) sid)))
          (setf (key-material-cached-session-key km) k
                (key-material-cached-session-id km) sid)
          k))))
```
Change `%seal-with-km` / `%open-with-km` to call `(%km-session-key-at km session-id 0)` in place of the inline `(derive-session-key …)` (they already hold `session-id` as a 4-octet vector).

- [ ] **Step 4: Run, verify it passes** — `make test-sbcl 2>&1 | grep -iE 'skcache'` → PASS; the existing payload round-trip + corpus tests still PASS (the cache returns the identical key, so wire bytes are unchanged).
- [ ] **Step 5: Gates + commit** — `make test-clasp test-sbcl corpus gate-types`; commit:
```bash
git add src/dds-security/key-material.lisp src/dds-security/transform.lisp src/dds-tests/<security-test-file>.lisp
git commit -m "feat(security): WP-DDS-SECURITY-ZEROALLOC-AEAD — per-KeyMaterial session-key cache (derive-once; removes the per-sample KDF) (M7/P6 Slice 1)"
```

---

## Task 3: Into-buffer serialized-payload codec core + wrappers

**Files:**
- Modify: `src/dds-security/transform.lisp` (add `%km-next-iv-suffix-into`, `encode-serialized-payload-into`, `decode-serialized-payload-into`; refactor `encode/decode-serialized-payload` :105/:132 into wrappers)
- Modify: `src/dds-security/packages.lisp` (export the two `-into` symbols)

**Interfaces:**
- Produces:
  - `%km-next-iv-suffix-into (km vec off) → (eql t)` — claim the next monotonic counter under the lock and write its 8-byte big-endian encoding into `vec[off..+8]` (no `make-array`).
  - `encode-serialized-payload-into (out-buf km plaintext) → fixnum` — build the §9.5.3.3 SecuredPayload into `out-buf` (a static `octet-buffer`) starting at position 0, returning the total length. Same byte layout as `serialize-secured-payload`. No GC-heap allocation.
  - `decode-serialized-payload-into (pt-out km secured) → (or fixnum null)` — recover the plaintext into `pt-out` (a static `octet-buffer`); returns the plaintext length, or NIL fail-closed. No GC-heap allocation.
- Consumes: Task 1 (`aes-256-gcm-seal-into`/`-open-into`), Task 2 (`%km-session-key-at`), the cursor serializers (`serialize-crypto-header`/`-content`/`-footer`, `parse-crypto-header`/`-content`/`-footer`), `+empty-octets+`, `+fixed-session-id+`, the `+secure-data-header-len+`(20) / `+crypto-content-length-len+`(4) / `+common-mac-len+`(16) / `+secure-data-tag-len+` layout constants.

**Layout note (verified):** SecureDataHeader = `kind(4)‖key_id(4)‖session_id(4)‖iv_suffix(8)` = 20 octets, so the 12-byte GCM nonce is exactly `out-buf[8..20]` after the header is written — pass `nonce-vec=out-buf-vec, nonce-off=8` to the FFI; no nonce buffer. SecuredPayload = `header(20) ‖ ct_len(u32 BE) ‖ ct(N) ‖ tag(16) ‖ pad((-N) mod 4) ‖ rsm_count(u32 BE)=0`; ct starts at offset 24, tag at `24+N`.

- [ ] **Step 1: Write the failing test** — add `run-security-payload-into-test` (registered in the dispatch table):

```lisp
(defun* run-security-payload-into-test ()
    (function () t)
  "encode-serialized-payload-into produces byte-identical output to the allocating entry, and
   decode-serialized-payload-into round-trips; over-short input fails closed."
  (let* ((km (make-test-key-material))
         (km2 (make-test-key-material))               ; fresh counter -> same iv on first encode
         (pt  (map '(simple-array (unsigned-byte 8) (*)) #'char-code "zero-alloc payload!"))
         (golden (encode-serialized-payload km pt))    ; allocating entry, iv-counter 0
         (out (dds.core.buffer:make-octet-buffer (+ 64 (length pt))))
         (len (encode-serialized-payload-into out km2 pt))) ; into entry, iv-counter 0
    (%check :payload-into-byte-identical
            (equalp (subseq (dds.core.buffer:octet-buffer-vec out) 0 len) golden)
            "encode-into must be byte-identical to the allocating encode for the same iv-counter")
    (let* ((pt-out (dds.core.buffer:make-octet-buffer 256))
           (plen (decode-serialized-payload-into pt-out km2 (subseq (dds.core.buffer:octet-buffer-vec out) 0 len))))
      (%check :payload-into-decode (and plen (equalp (subseq (dds.core.buffer:octet-buffer-vec pt-out) 0 plen) pt))
              "decode-into must round-trip the plaintext")
      (%check :payload-into-failclosed
              (null (decode-serialized-payload-into pt-out km2 (make-array 8 :element-type '(unsigned-byte 8))))
              "decode-into on a too-short input must return NIL (fail-closed)")
      (dds.core.buffer:free-static-buffer pt-out))   ; or dds.pal:free-static of the vec, per the buffer API
    (dds.core.buffer:free-static-buffer out)
    t))
```
(Use the project's octet-buffer free idiom — `(dds.pal:free-static (dds.core.buffer:octet-buffer-vec buf))` — if there is no `free-static-buffer`.)

- [ ] **Step 2: Run, verify it fails** — `make test-sbcl 2>&1 | grep -iE 'payload-into|encode-serialized-payload-into|undefined'` → FAIL (undefined).
- [ ] **Step 3: Implement the core.**
  - `%km-next-iv-suffix-into (km vec off)`: under `(key-material-iv-counter-lock km)` read+increment the counter `v`; write `v` big-endian into `vec[off..off+8]` (`(setf (aref vec (+ off (- 7 i))) (logand (ash v (* i -8)) #xff))`); return `t`.
  - `encode-serialized-payload-into (out-buf km plaintext)`: let `vec = (octet-buffer-vec out-buf)`, `cur = (cursor out-buf :little)`. Write the CryptoHeader via the cursor: `serialize-crypto-header` writes kind, key_id, then session_id (= the 4 zero bytes of `+fixed-session-id+`) and a placeholder iv_suffix; then overwrite the iv_suffix in place with `%km-next-iv-suffix-into(km, vec, 12)` (header offset 12) — OR write kind+key_id via cursor then `session_id` zeros + `%km-next-iv-suffix-into(vec,12)` directly, whichever keeps the header bytes identical to `serialize-secured-payload`. Write `ct_len = (length plaintext)` as u32 BE at offset 20 (`%put-u32-be`). Call `aes-256-gcm-seal-into(vec, 24, (+ 24 (length plaintext)), (%km-session-key-at km +fixed-session-id+ 0), vec, 8, +empty-octets+, plaintext, 0, (length plaintext))`. Write the footer pad `((-N) mod 4)` zero octets after the tag, then `rsm_count=0` u32 BE. Return the total length `(+ 24 N tag(16) pad rsm(4))`. (The plaintext must be readable by the FFI copy-in; if it is a GC vector the FFI stages it via `with-foreign-pointer`, non-consing.)
  - `decode-serialized-payload-into (pt-out km secured)`: validate `(length secured) >= 20+4+16+4` (min); read `ct_len` (u32 BE at offset 20) and validate `24 + ct_len + 16 <= (length secured)` and the pad/rsm tail; the `find_key` gate: byte-compare `secured[0..4]` to `(key-material-transformation-kind km)` and `secured[4..8]` to `(key-material-sender-key-id km)` with a no-alloc loop → NIL on mismatch; call `aes-256-gcm-open-into((octet-buffer-vec pt-out), 0, (%km-session-key-at km secured 8), secured, 8, +empty-octets+, secured, 24, ct_len, secured, (+ 24 ct_len))`; return `ct_len` on T, else NIL. All checks before any read; on NIL leave no readable plaintext. Wrap the body in `handler-case (… (error () nil))` to stay fail-closed (mirrors the existing decode). The session key is `(%km-session-key-at km secured 8)` — byte-compared in place against the cache, zero-alloc on hit (Task 2); the nonce is the same `secured[8..20]` sub-slice passed to the FFI, so no session_id vector is materialized per sample.
  - Refactor the wrappers: `encode-serialized-payload (km plaintext)` → allocate a temp `out-buf = (make-octet-buffer (+ 64 (length plaintext)))`, `len = (encode-serialized-payload-into out-buf km plaintext)`, return `(subseq (octet-buffer-vec out-buf) 0 len)` (free the temp). `decode-serialized-payload (km secured)` → temp `pt-out = (make-octet-buffer (length secured))`, `plen = (decode-serialized-payload-into pt-out km secured)`, return `(and plen (subseq (octet-buffer-vec pt-out) 0 plen))` (free the temp). Export the two `-into` symbols.

- [ ] **Step 4: Run, verify it passes** — `make test-sbcl 2>&1 | grep -iE 'payload-into|secured-payload|pad-secured'` → the new `:payload-into-*` PASS **and** the existing byte-exact corpora (`:secured-payload-byte-exact`, `:pad-secured-payload-byte-exact`, `:pad-secured-payload-pad-zero`) PASS unchanged (proves the wrappers-over-core kept the wire identical).
- [ ] **Step 5: Full gates + commit** — `make test-clasp test-sbcl corpus fuzz gate-hotpath gate-types`; commit:
```bash
git add src/dds-security/transform.lisp src/dds-security/packages.lisp src/dds-tests/<security-test-file>.lisp
git commit -m "feat(security): WP-DDS-SECURITY-ZEROALLOC-AEAD — into-buffer serialized-payload codec core (nonce = in-place header sub-slice) + allocating wrappers (corpus byte-identical) (M7/P6 Slice 1)"
```

---

## Task 4: Security-ON `make mem` arm (the 0.0000 proof)

**Files:**
- Modify: `src/dds-tests/gen-test.lisp` (add `run-mem-test-secure`; call it from `run-mem-test` so the `mem` target covers it)

**Interfaces:**
- Consumes: Task 3 (`encode-serialized-payload-into`/`decode-serialized-payload-into`), `make-test-key-material`, `dds.core.buffer:make-octet-buffer`, `dds.pal:bytes-consed`, the `run-mem-test` `measure`/`%check :zero-alloc` pattern (gen-test.lisp:273).

- [ ] **Step 1: Write the failing test** — add `run-mem-test-secure`, modeled on `run-mem-test`:

```lisp
(defun* run-mem-test-secure ()
    (function () t)
  "Measured zero-alloc data_protection AEAD encode + decode (NFR-MEM, security-ON). SBCL asserts
   bytes-consed/iter < 1.0; Clasp smokes (bytes-consed is 0). Closes the gap that make mem never
   covered the security path (ADR-0036 Carry-3)."
  (handler-case (dds.dare:dare-available-p)
    (dds.dare:dare-unavailable (c)
      (format t "~&  [mem-secure] SKIP — AES-GCM not available: ~a~%" (dds.dare:dare-unavailable-reason c))
      (return-from run-mem-test-secure t)))
  (let* ((km (dds.security:make-test-key-material))
         (pt (map '(simple-array (unsigned-byte 8) (*)) #'char-code "zero-alloc steady-state payload"))
         (out (dds.core.buffer:make-octet-buffer (+ 64 (length pt))))
         (ptout (dds.core.buffer:make-octet-buffer 256))
         (iters 100000) (slen 0))
    (setf slen (dds.security:encode-serialized-payload-into out km pt))           ; warm up
    (dds.security:decode-serialized-payload-into ptout km (subseq (dds.core.buffer:octet-buffer-vec out) 0 slen))
    (flet ((measure (label thunk)
             (declare (type function thunk))
             (let ((before (dds.pal:bytes-consed)))
               (dotimes (i iters) (funcall thunk))
               (let* ((delta (- (dds.pal:bytes-consed) before)) (per (/ (float delta) iters)))
                 (format t "~&  mem[~11a]: ~9d bytes / ~d iters = ~,4f bytes/sample (~a)~%"
                         label delta iters per (dds.pal:pal-impl-name))
                 (when (eq (dds.pal:pal-impl-name) :sbcl)
                   (%check :zero-alloc-secure (< per 1.0)
                           (format nil "~a: ~,4f bytes/sample (expected ~~0)" label per)))))))
      (measure "aead-encode" (lambda () (dds.security:encode-serialized-payload-into out km pt)))
      ;; decode over a fixed sealed blob copied once into a reused static input buffer (no per-iter alloc)
      (let ((sealed (dds.core.buffer:make-octet-buffer slen)))
        (replace (dds.core.buffer:octet-buffer-vec sealed) (dds.core.buffer:octet-buffer-vec out) :end2 slen)
        (measure "aead-decode"
                 (lambda () (dds.security:decode-serialized-payload-into ptout km (dds.core.buffer:octet-buffer-vec sealed))))
        (dds.pal:free-static (dds.core.buffer:octet-buffer-vec sealed))))
    (dds.pal:free-static (dds.core.buffer:octet-buffer-vec out))
    (dds.pal:free-static (dds.core.buffer:octet-buffer-vec ptout))
    t))
```
Then add `(run-mem-test-secure)` at the end of `run-mem-test` (before its final `t`) so `make mem` runs it. (NOTE: `decode-serialized-payload-into` must accept the sealed input as a plain `(simple-array (unsigned-byte 8) (*))` — its `secured` parameter is a vector, consistent with Task 3.)

- [ ] **Step 2: Run, verify it fails the RIGHT way** — `make mem 2>&1 | grep -iE 'aead-encode|aead-decode|zero-alloc-secure'`. Before any zero-alloc work is wrong, expect a non-zero `bytes/sample` and a FAILED `:zero-alloc-secure`. (If Tasks 1-3 are already done it should PASS — that is the success condition; this step documents the proof.)
- [ ] **Step 3: If non-zero, eliminate the residual** — chase any remaining per-iter `make-array`/`subseq`/`copy-seq` in the encode/decode-into path (e.g. a stray nonce/session-id/field allocation) until SBCL reports `0.0000`. Do NOT relax the `< 1.0` threshold.
- [ ] **Step 4: Run, verify it passes** — `make mem 2>&1 | grep -iE 'aead'` → `aead-encode` and `aead-decode` both `0.0000 bytes/sample`, `:zero-alloc-secure` PASS (SBCL); Clasp smokes.
- [ ] **Step 5: Gates + commit** — `make test-clasp test-sbcl mem`; commit:
```bash
git add src/dds-tests/gen-test.lisp
git commit -m "feat(security): WP-DDS-SECURITY-ZEROALLOC-AEAD — security-ON make-mem arm (data_protection AEAD encode/decode 0.0000 B/sample) (M7/P6 Slice 1)"
```

---

## Task 5: Wire the live data_protection path to the core

**Files:**
- Modify: `src/dds-dcps/crypto-manager.lisp` (the `crypto-keys` encode/decode resolver path used for data_protection, ~line 377)
- Modify: `src/dds-disc/dataplane.lisp` (the data_protection encode call in the publish path ~line 1204, and the decode call in the receive path ~line 1614)

**Interfaces:**
- Consumes: Task 3 (`encode-serialized-payload-into`/`decode-serialized-payload-into`). Produces: no new exported symbol (an internal hot-path rewire).

**Method:** locate the live call sites of `encode-serialized-payload` (publish, data_protection on) and `decode-serialized-payload` (receive). Replace them with the `-into` core called over a reused static buffer: a per-writer/per-reader `octet-buffer` slot, or an arena `pool-acquire`/`pool-release` buffer (follow the existing per-node reusable-scratch pattern, e.g. `disc-node-tx-msg`). The data_protection-OFF and security-OFF paths MUST stay byte-identical (the core is only reached when data_protection is engaged). The allocating wrappers remain for any non-hot caller.

- [ ] **Step 1: Identify + characterize** — `grep -rn "encode-serialized-payload\|decode-serialized-payload" src/dds-dcps src/dds-disc` ; confirm the hot publish/receive call sites and whether a reused buffer is already in scope there.
- [ ] **Step 2: Rewire the publish call site** to `encode-serialized-payload-into` over a reused buffer; keep the produced SecuredPayload bytes identical (it already is — same core).
- [ ] **Step 3: Rewire the receive call site** to `decode-serialized-payload-into` over a reused plaintext buffer; preserve fail-closed (NIL → drop).
- [ ] **Step 4: Verify the e2e** — `make test-sbcl 2>&1 | grep -iE 'encrypted-pubsub|data-protect|secure'` → the data_protection e2e (`run-security-encrypted-pubsub-test` and the secure-discovery protected e2es) PASS, proving the wired live path round-trips. Re-run `make mem` (still 0.0000).
- [ ] **Step 5: Full gates + commit** — `make test-clasp test-sbcl corpus fuzz gate-hotpath gate-types mem`; commit:
```bash
git add src/dds-dcps/crypto-manager.lisp src/dds-disc/dataplane.lisp
git commit -m "feat(security): WP-DDS-SECURITY-ZEROALLOC-AEAD — wire the live data_protection publish/receive path to the into-buffer core over a reused buffer (security-OFF byte-identical) (M7/P6 Slice 1)"
```

---

## Task 5 (EXPANDED 2026-06-30): live-path payload pooling — 4 sub-tasks

The original Task 5 (call-site swap to a reused buffer) is SUPERSEDED: the payload is retained by reference (encode→HistoryCache for retransmit/KEEP_LAST; decode→`disc-node-samples` drained by the app thread), so a reused buffer corrupts/races. Owner chose (2026-06-30) full pooling so the LIVE secured path is zero-alloc. Detailed design + lifecycle anchors: `.superpowers/sdd/pooling-design.md`. Four sub-tasks, in order (T5a/T5b independent after T5a-pre; T5c last):

- **T5a-pre — encode release-safety (HIGH risk, first).** Add a refcount(+generation) to `cache-change` (mirror `zerocopy-pool.lisp:16-17`): a send plan/thunk acquires a ref on the payload, releases it after copying into the datagram; the pooled buffer returns to the pool only when evicted AND refcount==0. Lands behaviorally-neutral (no pooling yet) + testable in isolation (a change is not releasable while a send is pending).
- **T5a — encode payload pool.** Per-node/per-writer `make-buffer-pool` (element-bytes `44+max+3`, capacity depth×instances + in-flight headroom); `publish-sample` encodes via `encode-serialized-payload-into` into a pooled buffer; `%hc-remove-change` `pool-release`s it (gated by T5a-pre); exhaustion → existing `:timeout` backpressure, never GC. Security-OFF byte-identical.
- **T5b — decode loaned plaintext (MED-HIGH; app-API change).** `%deliver-user-sample` decodes via `decode-serialized-payload-into` into a pooled buffer; store a length-tagged handle in `disc-node-samples`; secured loan-capable reads return a loan via the `dr-loans` registry shape; `return-loan` `pool-release`s it. Secured reads must adopt `take-loaned`/`return-loan` (document the read-contract change). New non-SAP pool plumbing (not the SHMEM ZC slot). Exhaustion → SAMPLE_REJECTED/backpressure, never GC.
- **T5c — live-path mem arm + exhaustion-backpressure proof.** perftest secured live path asserts 0.0000 B/sample (pub+sub, security ON); a test that pool exhaustion yields RESOURCE_LIMITS/`:timeout` (writer) + SAMPLE_REJECTED/loan-backpressure (reader), never a GC fallback; verification.csv row.

---

## Task 6: Capstone — ADR 0038 + docs + final gate sweep

**Files:**
- Create: `docs/adr/0038-zero-alloc-aead.md`
- Modify: `docs/adr/0036-dds-security-secure-discovery.md` (flip Carry-3 status for the payload tier), `docs/wiki/security.md`, `docs/verification.csv`, `docs/provenance.md` (if any clean-room corroboration was needed)

- [ ] **Step 1: Write ADR 0038** — the into-buffer FFI + session-key cache + codec-core foundation; the security-ON mem arm (0.0000 for the data_protection tier); the byte-invariance proof (wrappers-over-core + NIST-KAT-into arm); record that submessage + whole-RTPS tiers + dataplane borrow are slice 2, and key-material foreign-hardening + ZC×rtps_protection-SHMEM are later slices. Follow the ADR format of 0036/0037 (Status/Relates-to/Standards/Context/Decision/Consequences). Cite the operating contract §N (never the config filename); no AI-assistant attribution.
- [ ] **Step 2: Update ADR-0036 Carry-3** to "data_protection tier resolved in ADR 0038; submessage + whole-RTPS carried to slice 2"; add the verification.csv row + the wiki note (security-ON `make mem` now 0.0000 for data_protection).
- [ ] **Step 3: Final dual-impl gate sweep** — `make build` (SBCL + Clasp), `make test-clasp test-sbcl corpus fuzz gate-hotpath gate-types mem`. Record the results.
- [ ] **Step 4: Commit** — docstrings confirmed on every new exported symbol; commit:
```bash
git add docs/adr/0038-zero-alloc-aead.md docs/adr/0036-dds-security-secure-discovery.md docs/wiki/security.md docs/verification.csv
git commit -m "docs(security): WP-DDS-SECURITY-ZEROALLOC-AEAD — Slice 1 capstone: ADR 0038 + ADR-0036 Carry-3 flip + wiki/verification; data_protection AEAD 0.0000 B/sample, wire byte-identical (M7/P6 Slice 1)"
```

---

## Task 1b: Zero-cons AES-GCM FFI (added 2026-06-30 after the zero-cons-FFI spike)

The spike (`.superpowers/sdd/spike-zerocons-ffi.md`) found the into-buffer FFI from Task 1 still conses ~770 B/iter — **~91% from `%ossl-sym` doing a `cffi:foreign-symbol-pointer` lookup ~10×/call**, the rest from boxed-SAP outputs + variable `with-foreign-pointer` input scratch. A prototype reached **0.000 B/iter on SBCL with the NIST KAT byte-identical**. This runs AFTER Task 3, BEFORE Task 4 (so T4's mem arm can assert 0.0000). Two bisectable sub-tasks; the spike report is the detailed brief.

### Task 1b-i: cache the EVP function pointers (≈91% of the win, small)
**Files:** Modify `src/dds-dare/primitives.lisp`. Cache each EVP symbol pointer once via `(load-time-value (cffi:foreign-symbol-pointer "EVP_…") t)` (and cache the `EVP_aes_256_gcm` cipher pointer) instead of calling `%ossl-sym` per EVP call. Pure ANSI+CFFI; stays in dds-dare; no contract change. Keep the NIST KAT byte-identical. Measure the residual (expect ~80 B/iter after this). our-to-our green both impls.

### Task 1b-ii: `dds.pal:static-sap+` + zero-box outputs/inputs (the last ~80 B → 0)
**Files:** Modify `src/dds-pal/pal-sbcl.lisp` + `src/dds-pal/pal-clasp.lisp` + the PAL package/contract (additive export of `static-sap+`) + `src/dds-dare/primitives.lisp`. Add `dds.pal:static-sap+ (vec offset) → sap` — an INLINE fn with internal `(safety 0)` returning the SAP at `vec[offset]` without boxing (SBCL `sb-sys:sap+`/`vector-sap`; Clasp `cffi:inc-pointer` over `static-vector-pointer` — Clasp `bytes-consed` is 0 so correctness, not zero-box, is the bar there). Rewrite the `seal-into`/`open-into` output writes to use it (drop boxed `static-pointer`+`inc-pointer`); use a cached null pointer + constant/static input scratch so no per-call SAP is boxed. The inline-fn-with-internal-(safety 0) keeps dds-dare's own bounds + key-zeroize + fail-closed-wipe checks intact (do NOT add whole-function safety 0 — the spike showed it does not help and would drop the security checks). **Preserve byte-for-byte:** the key-zeroization and the fail-closed plaintext wipe must be unchanged in effect; the NIST KAT byte-identical. Measure SBCL ~0.000 B/iter for both entries. This is an ADDITIVE PAL-contract change — record `static-sap+` in ADR 0038 (T6). our-to-our green both impls.

**DoD for Task 1b:** `aes-256-gcm-seal-into` + `aes-256-gcm-open-into` measure ~0.000 B/iter on SBCL (focused bytes-consed loop); NIST KAT + every byte-exact corpus green UNCHANGED; fail-closed wipe + key-zeroize preserved; both impls green.

---

## Notes for the executor

- **Order matters:** T1 (FFI) → T2 (cache) → T3 (core) → T4 (mem proof) → T5 (live wiring) → T6 (capstone). The mem proof (T4) validates the foundation before the live integration (T5).
- **The single most important invariant:** every byte-exact corpus + the NIST KAT stay green **unchanged**. If a corpus byte changes, STOP — the core diverged from `serialize-secured-payload`; fix the core, do not touch the corpus.
- **Clasp first** for every `make test-*`; the known live-socket flake is the only acceptable Clasp full-suite abort (re-run / isolation-verify).
- **The exact security-test file** for the new unit tests (`run-security-session-key-cache-test`, `run-security-payload-into-test`) is `src/dds-tests/security-test.lisp` (where the payload corpus tests live) + register the names in the `echo-test.lisp` dispatch alist next to the other `security-*` entries.
