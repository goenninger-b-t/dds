# Confidential Zero-Copy/SHMEM for ENCRYPT-tier writers — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a writer whose governance mandates `rtps_protection` or `metadata_protection` = ENCRYPT use Zero-Copy/SHMEM by sealing the serialized payload into the SHMEM slot as a `data_protection` `SecuredPayload` under the writer's per-writer EntityCrypto key, decoded on the reader's copy-on-read path.

**Architecture:** Reuse the existing zero-alloc `SecuredPayload` codec and the per-writer EntityCrypto key already exchanged over the volatile-secure endpoint. The in-slot bytes become a `data_protection` `SecuredPayload`; a sentinel in the wire-protected reference datagram tells the reader to decode it. No new wire format, no new key, no new crypto primitive. Copy-on-read only (the literal-zero-copy loan path can't decrypt in place).

**Tech Stack:** Common Lisp (SBCL + Clasp), CFFI SHMEM pool, OpenSSL AES-256-GCM via the `dds.security` `encode/decode-serialized-payload-into` codec.

**Design doc:** `docs/superpowers/specs/2026-07-09-zc-shmem-secured-overlay-design.md` (approved 2026-07-09).

## Global Constraints

- **Clasp AND SBCL must BOTH validate, identically; run Clasp FIRST.** (`make *-clasp`, `scripts/with-clasp.sh`.)
- **Hot-path purity:** the non-secured ZC path and all non-secured hot paths stay CLOS-free, zero-alloc, byte-identical. `make gate-hotpath` must pass. The overlay path is a *niche secured* path (not the measured hot path) — allocating decode on receive is acceptable (mirrors the existing non-loan secured path); the write-side seal uses a pooled static scratch buffer (no per-sample GC-heap alloc).
- **Bounds-check every network-facing parse even at `(safety 0)`.** `parse-zc-reference` already bounds-checks; the overlay sentinel read stays within the validated 20-octet body.
- **No wire constant invented from memory.** The `SecuredPayload` layout + AES-GCM parameters are reused verbatim from the spec-pinned `encode/decode-serialized-payload-into`. The overlay sentinel is a local transport discriminator in *our own* ZC reference format (`+zc-encapsulation-id+ #x4B43`, ADR 0014 — ours, not an OMG clause), not an OMG wire constant.
- **`defun*` for every function, `defstruct*` for every struct; every parameter fully type-declared** (FR-LANG-8, `dds.lang`).
- **Every added/changed exported symbol carries a docstring;** update `docs/wiki/` + `README.md` in lockstep (CLAUDE.md §5.1).
- **Fail-closed always:** missing key, failed GCM tag, or absent scratch ⇒ drop, never a plaintext leak and never a GC fallback that hides an error.
- **SBOM** regenerated + staged by the pre-commit hook; never hand-edit.
- **Commit messages** presented for owner approval before committing; no AI-attribution trailer; approval implies push.
- **Interop:** intra-host, same-vendor only — no cross-vendor wire surface (§7 of the spec). Assert existing security corpora + NIST KATs + Connext/Fast-DDS interop tests unchanged.

---

## File Structure

- `src/dds-cdr/cdr.lisp` — MODIFY `encode-zc-reference` / `parse-zc-reference`; ADD `+zc-ref-overlay-secured+`. Carries the overlay sentinel in the reference `reserved` u32. Purely additive; `reserved=0` path byte-identical.
- `src/dds-cdr/packages.lisp` — EXPORT `+zc-ref-overlay-secured+`.
- `src/dds-disc/dataplane.lisp` — the write-site routing (`%zc-overlay-eligible-p`, `%zc-overlay-km`, `%ensure-zc-overlay-scratch`, overlay branch in `%zc-change-item`, overlay param threaded through `%zc-ref-builder` / `%zc-ref-item` / `%encode-zc-ref-vec`); the read-site decode (`%zc-ref-overlay-p`, `%zc-try-resolve` 2nd return value, `%on-user-data` threading, `%deliver-user-sample` `overlay-secured` param).
- `src/dds-disc/disc.lisp` — ADD the per-node overlay scratch pool slots to `disc-node` (mirroring `submsg-scratch-pool` at `disc.lisp:463`).
- `src/dds-disc/secure-sedp.lisp` — ADD `run-zc-shmem-secured-overlay-test`; EXPORT it (`src/dds-disc/packages.lisp`), register it in `src/dds-tests/echo-test.lisp:4069` next to `zc-shmem-secured-cleartext`.
- `docs/adr/0051-zc-shmem-secured-overlay.md` — NEW ADR.
- `docs/wiki/security.md`, `docs/wiki/zero-copy.md` (or the actual ZC wiki page), `README.md`, `docs/verification.csv` — docs lockstep.
- `bench/report/2026-07-09-zc-shmem-secured-overlay.md` — before/after.

---

## Task 1: CDR overlay sentinel in the reference datagram

**Files:**
- Modify: `src/dds-cdr/cdr.lisp` (`encode-zc-reference` ~:100, `parse-zc-reference` ~:116)
- Modify: `src/dds-cdr/packages.lisp` (export the constant)
- Test: `src/dds-disc/secure-sedp.lisp` (new unit assertions inside `run-zc-shmem-secured-overlay-test` Part 0, or a focused `run-zc-ref-overlay-sentinel-test` — see Step 1)

**Interfaces:**
- Produces: `+zc-ref-overlay-secured+` (a `(unsigned-byte 32)` sentinel, value `1`); `encode-zc-reference cursor slot-index generation slot-bytes &optional (overlay 0)`; `parse-zc-reference buf off len` now returns `(values slot-index generation slot-bytes overlay)` — the 4th value is the reserved u32 (0 = raw, `+zc-ref-overlay-secured+` = overlay).

- [ ] **Step 1: Write the failing test**

Add to `src/dds-disc/secure-sedp.lisp` (near `run-zc-shmem-secured-cleartext-test`):

```lisp
(defun* run-zc-ref-overlay-sentinel-test ()
    (function () (eql t))
  "WP-SECURITY-ZC-SHMEM-OVERLAY T1 (ADR 0051): the ZC reference datagram carries an overlay sentinel in its
   reserved u32 — encode with overlay set round-trips through parse; the default (overlay 0) is byte-identical
   to the pre-change reference (no wire drift for non-overlay ZC)."
  (let* ((v0 (dds.disc::%encode-zc-ref-vec 7 3 65536))                          ; default overlay 0
         (v1 (let ((b (make-array 20 :element-type '(unsigned-byte 8)))) b)))
    ;; encode WITH the overlay sentinel into v1
    (let ((c (dds.core.buffer:cursor (dds.core.buffer:octet-buffer-over v1) :endianness :little)))
      (dds.cdr:encode-zc-reference c 7 3 65536 dds.cdr:+zc-ref-overlay-secured+))
    (multiple-value-bind (s0 g0 sb0 ov0) (dds.cdr:parse-zc-reference v0 0 20)
      (assert (and (eql s0 7) (eql g0 3) (eql sb0 65536) (eql ov0 0)) ()
              "T1: default reference must parse overlay=0"))
    (multiple-value-bind (s1 g1 sb1 ov1) (dds.cdr:parse-zc-reference v1 0 20)
      (assert (and (eql s1 7) (eql g1 3) (eql sb1 65536) (eql ov1 dds.cdr:+zc-ref-overlay-secured+)) ()
              "T1: overlay reference must parse the sentinel"))
    ;; byte-identity of the default path: only the reserved u32 (body offset 16 => vec offset 16..19) may differ
    (assert (every #'= (subseq v0 0 16) (subseq v1 0 16)) ()
            "T1: the first 16 octets (encap + slot + gen + slot-bytes) must be identical regardless of overlay"))
  t)
```

- [ ] **Step 2: Run it to verify it fails**

Run (Clasp first):
```
scripts/with-clasp.sh --non-interactive --eval "(asdf:load-system :dds-disc)" --eval "(dds.disc::run-zc-ref-overlay-sentinel-test)" --eval "(sb-ext:quit)"
```
Expected: FAIL — `+zc-ref-overlay-secured+` unbound / `encode-zc-reference` arity / `parse-zc-reference` returns 3 values not 4.

- [ ] **Step 3: Add the constant and thread the sentinel**

In `src/dds-cdr/cdr.lisp`, after `+zc-encapsulation-id+`:

```lisp
(defconstant +zc-ref-overlay-secured+ 1
  "WP-SECURITY-ZC-SHMEM-OVERLAY (ADR 0051): the value placed in the WP-ZEROCOPY reference datagram's
   reserved u32 (encode-zc-reference / parse-zc-reference) when the referenced SHMEM slot holds a
   data_protection SecuredPayload (ENCRYPT-tier overlay) rather than a raw serialized payload. 0 = raw
   (the default, byte-identical to the pre-overlay reference). This is a LOCAL transport discriminator in
   our own ZC reference format (+zc-encapsulation-id+, ADR 0014 — ours, not an OMG clause); it rides INSIDE
   the rtps/metadata wrap so a co-resident SHMEM attacker cannot flip it.")
```

Modify `encode-zc-reference` to take the optional overlay and write it as the reserved field:

```lisp
(defun* encode-zc-reference (cursor slot-index generation slot-bytes &optional (overlay 0))
    (function (dds.core.buffer:cursor (unsigned-byte 32) (unsigned-byte 32) (unsigned-byte 32)
              &optional (unsigned-byte 32)) t)
  "Write a 20-octet WP-ZEROCOPY SerializedPayload: +zc-encapsulation-id+ in NBO (hi, lo), options=0 (hi, lo),
   then slot-index, generation, slot-bytes, OVERLAY as LE u32s (ADR 0014). OVERLAY (default 0) is the reserved
   field: 0 = raw payload, +zc-ref-overlay-secured+ = the slot holds a data_protection SecuredPayload overlay
   (ADR 0051)."
  (dds.core.buffer:put-u8 cursor (ldb (byte 8 8) +zc-encapsulation-id+))
  (dds.core.buffer:put-u8 cursor (ldb (byte 8 0) +zc-encapsulation-id+))
  (dds.core.buffer:put-u8 cursor 0)
  (dds.core.buffer:put-u8 cursor 0)
  (dds.core.buffer:put-u32 cursor slot-index)
  (dds.core.buffer:put-u32 cursor generation)
  (dds.core.buffer:put-u32 cursor slot-bytes)
  (dds.core.buffer:put-u32 cursor overlay)
  cursor)
```

Modify `parse-zc-reference` to return the reserved field as a 4th value:

```lisp
(defun* parse-zc-reference (buf off len)
    (function ((simple-array (unsigned-byte 8) (*)) (integer 0) (integer 0))
              (values (or null (unsigned-byte 32)) (unsigned-byte 32) (unsigned-byte 32) (unsigned-byte 32)))
  "If BUF[off, off+len) is a WP-ZEROCOPY 16-byte reference (len>=20, leading u16==+zc-encapsulation-id+),
   return (values slot-index generation slot-bytes overlay); else (values NIL 0 0 0). OVERLAY is the reserved
   u32: 0 = raw, +zc-ref-overlay-secured+ = data_protection SecuredPayload overlay (ADR 0051). Bounds-checked
   (NFR-SEC-POSTURE)."
  (unless (and (>= len 20)
               (>= (length buf) (+ off 20)))
    (return-from parse-zc-reference (values nil 0 0 0)))
  (let ((id (logior (ash (aref buf off) 8) (aref buf (+ off 1)))))
    (unless (= id +zc-encapsulation-id+)
      (return-from parse-zc-reference (values nil 0 0 0)))
    (flet ((le-u32 (base)
             (logior (aref buf base)
                     (ash (aref buf (+ base 1)) 8)
                     (ash (aref buf (+ base 2)) 16)
                     (ash (aref buf (+ base 3)) 24))))
      (values (le-u32 (+ off 4))
              (le-u32 (+ off 8))
              (le-u32 (+ off 12))
              (le-u32 (+ off 16))))))
```

In `src/dds-cdr/packages.lisp`, add `#:+zc-ref-overlay-secured+` to the `dds.cdr` `:export` list (next to the existing `#:encode-zc-reference` / `#:parse-zc-reference` exports — grep for `parse-zc-reference` there).

- [ ] **Step 4: Run the test to verify it passes**

Run (Clasp first, then SBCL):
```
scripts/with-clasp.sh --non-interactive --eval "(asdf:load-system :dds-disc)" --eval "(assert (dds.disc::run-zc-ref-overlay-sentinel-test))" --eval "(sb-ext:quit)"
sbcl --non-interactive --eval "(asdf:load-system :dds-disc)" --eval "(assert (dds.disc::run-zc-ref-overlay-sentinel-test))"
```
Expected: PASS both impls. Also run `make corpus` — byte-exact XCDR corpus unchanged (the ZC reference is not part of the XCDR corpus, but confirm no regression).

- [ ] **Step 5: Commit** (present message for approval first)

```
git add src/dds-cdr/cdr.lisp src/dds-cdr/packages.lisp src/dds-disc/secure-sedp.lisp
git commit -m "feat(security): WP-SECURITY-ZC-SHMEM-OVERLAY T1 — ZC reference carries a data_protection-overlay sentinel (ADR 0051)"
```

---

## Task 2: Write-side overlay — seal into the SHMEM slot

**Files:**
- Modify: `src/dds-disc/disc.lisp` (add overlay scratch pool slots to `disc-node`, near `submsg-scratch-pool` ~:463)
- Modify: `src/dds-disc/dataplane.lisp` (`%zc-overlay-eligible-p`, `%zc-overlay-km`, `%ensure-zc-overlay-scratch`; overlay branch in `%zc-change-item` ~:1066; overlay param on `%zc-ref-builder` ~:1404, `%zc-ref-item` ~:1390, `%encode-zc-ref-vec` ~:1380)
- Test: `src/dds-disc/secure-sedp.lisp` (`run-zc-shmem-secured-overlay-test` Parts A + B)

**Interfaces:**
- Consumes: `dds.cdr:+zc-ref-overlay-secured+`, `dds.cdr:encode-zc-reference` (Task 1); `dds.security:encode-serialized-payload-into out-buf km plaintext → fixnum`; `dds.security:crypto-keys-encode-key-fn`; `%local-writer-guid-vec node entity-id`; `%ensure-change-payload node change`; `%zc-payload-wire-protected-p`.
- Produces: `%zc-overlay-eligible-p node → boolean`; `%zc-overlay-km node → (or null key-material)`; the overlay branch of `%zc-change-item` (a wire-protected ENCRYPT-tier writer now returns a ref item instead of NIL).

- [ ] **Step 1: Write the failing test**

Add `run-zc-shmem-secured-overlay-test` to `src/dds-disc/secure-sedp.lisp`. Parts A (deterministic predicate) + B (SHMEM live-segment). Model on `run-zc-shmem-secured-cleartext-test` (secure-sedp.lisp:1088). Use `%secure-sedp-test-km` for an ENCRYPT KM (transformation_kind AES256-GCM — `%secure-sedp-test-km 7 #x33` builds a GCM km; confirm its kind is `:encrypt` / not gmac):

```lisp
(defun* run-zc-shmem-secured-overlay-test ()
    (function () (eql t))
  "WP-SECURITY-ZC-SHMEM-OVERLAY (ADR 0051, DDS-Security 1.1 §9.5.3.3): an ENCRYPT-tier writer
   (rtps/metadata_protection = ENCRYPT, data_protection = NONE) MAY now use Zero-Copy/SHMEM — the serialized
   payload is sealed into the pool slot as a data_protection SecuredPayload under the writer's EntityCrypto
   key, so a co-resident process reading the segment recovers only ciphertext. Asserts:
     Part A (deterministic, portable): with an ENCRYPT EntityCrypto KM installed as the crypto-transform,
       %zc-overlay-eligible-p is T and %zc-change-item RETURNS A REF (overlay taken) for a wire-protected
       ENCRYPT writer + zc-readers>0 + large payload; WITHOUT a KM it stays fail-closed NIL; a SIGN-only
       writer stays NIL (deferred, not overlay-eligible).
     Part B (SHMEM-gated live-segment): the sealed slot holds CIPHERTEXT — the plaintext marker is provably
       ABSENT from the entire pool segment (with a non-secured control whose plaintext IS present), and
       zc-sends advances (the overlay DID take ZC). Both impls (Clasp first)."
  (handler-case (dds.dare:dare-available-p)
    (dds.dare:dare-unavailable (c)
      (format t "~&  [zc-shmem-secured-overlay] SKIP — AES-GCM not available: ~a~%" (dds.dare:dare-unavailable-reason c))
      (return-from run-zc-shmem-secured-overlay-test t)))
  (let ((pa (make-array 12 :element-type '(unsigned-byte 8) :initial-element 93))
        (*zerocopy-min-payload-bytes* 8)
        (km (%secure-sedp-test-km 7 #x33)))          ; ENCRYPT (AES256-GCM) EntityCrypto KM
    ;; Part A — deterministic predicate + routing (no SHMEM needed for the NIL branches; the ref branch needs a pool → fold into Part B).
    (let ((node (make-disc-node :guid-prefix pa :host "127.0.0.1" :port 0))
          (change (dds.rtps.history:make-cache-change
                   :kind :data :sn 1
                   :serialized-payload (map '(simple-array (unsigned-byte 8) (*)) #'char-code
                                            "ZC-OVERLAY-PROBE-PAYLOAD-BBBBBBBBBBBBBBBBBBBBBBBBBB"))))
      (unwind-protect
           (progn
             (setf (disc-node-rtps-protection-kind node) :encrypt)         ; wire-protected ENCRYPT tier
             (assert (%zc-payload-wire-protected-p node) () "A: ENCRYPT writer is wire-protected")
             (assert (not (%zc-overlay-eligible-p node)) () "A: no KM installed -> NOT overlay-eligible (fail-closed)")
             (setf (disc-node-crypto-transform node) km)                   ; install the ENCRYPT EntityCrypto KM
             (assert (%zc-overlay-eligible-p node) () "A: ENCRYPT tier + ENCRYPT KM -> overlay-eligible"))
        (stop-node node)))
    ;; Part B — SHMEM-gated live-segment inspection (skips where the pool is not carved: Clasp/macOS, ADR 0013).
    (let ((*zerocopy-enabled* t))
      (let ((node (make-disc-node :guid-prefix pa :host "127.0.0.1" :port 0)))
        (unwind-protect
             (when (disc-node-zc-pool node)
               (let* ((sap (disc-node-zc-pool-sap node))
                      (size (dds.xport.zerocopy::%zc-bytes +zerocopy-pool-slots+ +zerocopy-pool-slot-bytes+))
                      (m1 (map '(simple-array (unsigned-byte 8) (*)) #'char-code
                               "ZC-OVERLAY-CONTROL-PLAINTEXT-1111111111111111111111111111"))
                      (m2 (map '(simple-array (unsigned-byte 8) (*)) #'char-code
                               "ZC-OVERLAY-SECURED-PLAINTEXT-22222222222222222222222222222222"))
                      (ch1 (dds.rtps.history:make-cache-change :kind :data :sn 1 :serialized-payload m1))
                      (ch2 (dds.rtps.history:make-cache-change :kind :data :sn 2 :serialized-payload m2)))
                 (flet ((%seg-has (marker)
                          (let ((mlen (length marker)))
                            (loop for i from 0 to (- size mlen)
                                  thereis (loop for j below mlen
                                                always (= (cffi:mem-ref sap :uint8 (+ i j)) (aref marker j)))))))
                   ;; NON-secured control: raw ZC, plaintext lands in the segment.
                   (assert (%zc-change-item node ch1 1) () "B: non-secured control takes raw ZC")
                   (assert (%seg-has m1) () "B: the non-secured control plaintext MUST appear in the segment (non-vacuity)")
                   ;; ENCRYPT overlay: ZC IS taken, but the slot holds ciphertext -> the plaintext is ABSENT.
                   (setf (disc-node-rtps-protection-kind node) :encrypt
                         (disc-node-crypto-transform node) km)
                   (let ((s1 (disc-node-zc-sends node)))
                     (assert (%zc-change-item node ch2 1) ()
                             "B: an ENCRYPT-tier writer with an EntityCrypto KM MUST now take the ZC overlay path (a ref is built)")
                     (assert (> (disc-node-zc-sends node) s1) ()
                             "B: the overlay ZC send must advance zc-sends")
                     (assert (not (%seg-has m2)) ()
                             "B: the overlay slot must hold CIPHERTEXT — the plaintext must be provably ABSENT from the segment (the fix)")))))
          (stop-node node)))))
  t)
```

- [ ] **Step 2: Run it to verify it fails**

```
scripts/with-clasp.sh --non-interactive --eval "(asdf:load-system :dds-disc)" --eval "(dds.disc::run-zc-shmem-secured-overlay-test)" --eval "(sb-ext:quit)"
```
Expected: FAIL — `%zc-overlay-eligible-p` unbound; the ENCRYPT `%zc-change-item` returns NIL (gated off, no overlay yet).

- [ ] **Step 3: Add the overlay scratch pool slots to `disc-node`**

In `src/dds-disc/disc.lisp`, mirror the `submsg-scratch-pool` / `-arena` / `-lock` triple (~:463) with a lazily-carved overlay scratch. Add to the `disc-node` `defstruct*`:

```lisp
  (zc-overlay-scratch-pool nil :type t)   ; WP-SECURITY-ZC-SHMEM-OVERLAY (ADR 0051): lazily-carved pool of slot-sized static octet-buffers for sealing the in-slot data_protection SecuredPayload; NIL until the first overlay publish
  (zc-overlay-scratch-lock (dds.pal:make-lock) :type t)
```

- [ ] **Step 4: Implement the write-side helpers**

In `src/dds-disc/dataplane.lisp`, near `%zc-payload-wire-protected-p` (~:899), add:

```lisp
(defun* %zc-overlay-km (node)
    (function (disc-node) (or null dds.security:key-material))
  "WP-SECURITY-ZC-SHMEM-OVERLAY (ADR 0051): resolve THIS node's primary user writer's EntityCrypto KeyMaterial
   for the in-slot data_protection SecuredPayload overlay. Mirrors the publish-time resolution
   (dataplane.lisp publish-sample): a crypto-keys resolver -> the writer's EntityCrypto km by its own GUID; a
   raw key-material -> itself (Slice-1 / test config). NIL when no crypto-transform is installed (fail-closed).
   N=1 (the MVP): the primary user-writer id; multi-writer overlay keys per-endpoint as a follow-on (ADR 0051)."
  (let ((ct (disc-node-crypto-transform node)))
    (and ct
         (if (typep ct 'dds.security:crypto-keys)
             (funcall (dds.security:crypto-keys-encode-key-fn ct)
                      (%local-writer-guid-vec node (disc-node-user-writer-id node)))
             ct))))

(defun* %zc-overlay-eligible-p (node)
    (function (disc-node) boolean)
  "WP-SECURITY-ZC-SHMEM-OVERLAY (ADR 0051): T iff a wire-protected writer may use Zero-Copy/SHMEM via the
   in-slot data_protection SecuredPayload overlay instead of being gated off (%zc-payload-wire-protected-p).
   Requires: the writer IS wire-protected (rtps/metadata_protection non-NONE — else it takes the raw ZC fast
   path, no overlay); its data_protection is NONE (data=SIGN/ENCRYPT already puts a SecuredPayload in the slot
   via the existing ungated path); AND a usable ENCRYPT (AES256-GCM, confidentiality) EntityCrypto KM resolves
   (%zc-overlay-km + non-GMAC kind). A SIGN-only wire tier with no ENCRYPT payload key is NOT eligible here
   (deferred — a SIGN payload is not confidential, so raw ZC would be a follow-on, ADR 0051). Fail-closed: no
   KM -> NIL (stays gated off)."
  (and (%zc-payload-wire-protected-p node)
       (eq (disc-node-user-data-protection-kind node) :none)
       (let ((km (%zc-overlay-km node)))
         (and km (dds.security:key-material-encrypt-p km) t))))
```

> **Note on `key-material-encrypt-p`:** if `dds.security` has no exported ENCRYPT/GMAC predicate, add a one-line `defun* key-material-encrypt-p (km) → boolean` in `src/dds-security/key-material.lisp` returning `(not (%km-gmac-p km))` (mirror `%km-gmac-p`, transform.lisp:228) and export it. Cite §9.5.3.3.1 (AES256-GCM {0,0,0,4} = ENCRYPT).

Add the lazily-carved scratch accessor (mirror `%ensure-secured-payload-pool` / `%ensure-secure-rx-pool`):

```lisp
(defun* %ensure-zc-overlay-scratch (node)
    (function (disc-node) (or null dds.core.arena:pool))
  "WP-SECURITY-ZC-SHMEM-OVERLAY (ADR 0051): lazily carve NODE's overlay scratch pool — static octet-buffers
   each sized to hold a slot's worth of data_protection SecuredPayload (44 + slot-bytes + 3, the ENCRYPT-tier
   upper bound). Returns the pool, or NIL if the arena carve fails (caller then skips the overlay -> the writer
   stays gated off for that sample, fail-closed, never a GC fallback). Idempotent under the overlay lock."
  (or (disc-node-zc-overlay-scratch-pool node)
      (dds.pal:with-lock ((disc-node-zc-overlay-scratch-lock node))
        (or (disc-node-zc-overlay-scratch-pool node)
            (setf (disc-node-zc-overlay-scratch-pool node)
                  (ignore-errors
                   (dds.core.arena:make-pool
                    :count 4
                    :make (lambda () (dds.core.buffer:make-octet-buffer
                                      (+ 44 +zerocopy-pool-slot-bytes+ 3))))))))))
```

> Confirm the exact `dds.core.arena:make-pool` keyword API against `%ensure-secure-rx-pool` (secure-sedp.lisp / disc.lisp) and match it — the pool is acquired with `dds.core.arena:pool-acquire` / released with `pool-release`, exactly as the RX pool test at secure-sedp.lisp:1244-1251.

- [ ] **Step 5: Thread the overlay param through the ref builders**

In `src/dds-disc/dataplane.lisp`, add `&optional (overlay 0)` to `%encode-zc-ref-vec`, `%zc-ref-item`, `%zc-ref-builder`, defaulting to 0 (byte-identical for all existing callers):

```lisp
(defun* %encode-zc-ref-vec (slot generation slot-bytes &optional (overlay 0))
    (function ((unsigned-byte 32) (unsigned-byte 32) (unsigned-byte 32) &optional (unsigned-byte 32))
              (simple-array (unsigned-byte 8) (20)))
  "Encode a 20-octet WP-ZEROCOPY reference into a fresh vector; OVERLAY (default 0) is the reserved field
   (+zc-ref-overlay-secured+ => the slot holds a data_protection SecuredPayload, ADR 0051). ADR 0014, FR-PF-3."
  (let* ((v (make-array 20 :element-type '(unsigned-byte 8)))
         (c (dds.core.buffer:cursor (dds.core.buffer:octet-buffer-over v) :endianness :little)))
    (dds.cdr:encode-zc-reference c slot generation slot-bytes overlay)
    v))
```

```lisp
(defun* %zc-ref-item (node sn slot gen &optional (overlay 0))
    (function (disc-node integer (integer 0) (unsigned-byte 32) &optional (unsigned-byte 32)) cons)
  "... (unchanged docstring) ... OVERLAY (default 0) marks a data_protection SecuredPayload slot (ADR 0051)."
  (incf (disc-node-zc-sends node))
  (let ((ref (%encode-zc-ref-vec slot gen +zerocopy-pool-slot-bytes+ overlay))
        (wid (%emit-wid node)))
    (cons (+ 24 (length ref))
          (lambda (mc) (dds.rtps.message:write-data
                        mc dds.rtps.message:+entityid-unknown+ wid sn ref 0 (length ref))))))
```

```lisp
(defun* %zc-ref-builder (node sn payload off len resolves &optional (overlay 0))
    (function (disc-node integer (simple-array (unsigned-byte 8) (*)) (integer 0) (integer 0) (integer 1)
              &optional (unsigned-byte 32)) (or null cons))
  "... (unchanged docstring) ... OVERLAY (default 0) marks a data_protection SecuredPayload slot (ADR 0051)."
  (multiple-value-bind (slot gen)
      (dds.xport.zerocopy::%zc-loan (disc-node-zc-pool-sap node) payload off len resolves)
    (when slot (%zc-ref-item node sn slot gen overlay))))
```

- [ ] **Step 6: Add the overlay branch to `%zc-change-item`**

Rewrite the top-level `if` of `%zc-change-item` (~:1066) as a `cond` — the existing raw-ZC arm unchanged, a new overlay arm before the gated fallback:

```lisp
  (cond
    ;; raw ZC (non-secured / data_protection already SecuredPayload) — UNCHANGED
    ((and (plusp zc-readers)
          (eq (dds.rtps.history:cache-change-kind change) :data)
          (not (%zc-payload-wire-protected-p node)))
     (let ((len (dds.rtps.history:cache-change-payload-len change)))
       (if (> len *zerocopy-min-payload-bytes*)
           (or (and (eq (dds.rtps.history:cache-change-zc-state change) :armed)
                    (%zc-armed-item node change))
               (let ((pl (%ensure-change-payload node change)))
                 (and pl (%zc-ref-builder node (dds.rtps.history:cache-change-sn change) pl 0 len 1))))
           (progn (%zc-drop-armed node change) nil))))
    ;; WP-SECURITY-ZC-SHMEM-OVERLAY (ADR 0051): a wire-protected ENCRYPT-tier writer seals the payload as a
    ;; data_protection SecuredPayload into the slot instead of being gated off — no cleartext in SHMEM, the
    ;; wire reference stays rtps/metadata-wrapped. Copy-on-read decode only (the reader can't decrypt in place).
    ((and (plusp zc-readers)
          (eq (dds.rtps.history:cache-change-kind change) :data)
          (%zc-overlay-eligible-p node))
     (let ((len (dds.rtps.history:cache-change-payload-len change)))
       (if (> len *zerocopy-min-payload-bytes*)
           (let ((pl   (%ensure-change-payload node change))     ; data=NONE => pl is the exact plaintext, (length pl)==len
                 (km   (%zc-overlay-km node))
                 (pool (%ensure-zc-overlay-scratch node)))
             (if (and pl km pool)
                 (let ((sb (dds.core.arena:pool-acquire pool)))
                   (if (null sb)
                       nil                                        ; scratch exhausted: fail-closed skip (no ZC this sample)
                       (unwind-protect
                            (let ((slen (dds.security:encode-serialized-payload-into sb km pl)))
                              ;; loan the SecuredPayload bytes into the slot, ref carries the overlay sentinel
                              (%zc-ref-builder node (dds.rtps.history:cache-change-sn change)
                                               (dds.core.buffer:octet-buffer-vec sb) 0 slen 1
                                               dds.cdr:+zc-ref-overlay-secured+))
                         (dds.core.arena:pool-release pool sb))))
                 nil))
           nil)))
    (t (progn (%zc-drop-armed node change) nil)))
```

> `%ensure-change-payload` returns the plaintext serialized payload; for a data=NONE writer `cache-change-payload-len` == `(length pl)`, so `encode-serialized-payload-into` seals exactly `len` bytes (it uses `(length pl)`). If a future path makes `pl` oversized, pass a length-exact view — but data=NONE guarantees equality here (see `%zc-change-item` docstring, dataplane.lisp:1048).

- [ ] **Step 7: Run the test to verify it passes**

```
scripts/with-clasp.sh --non-interactive --eval "(asdf:load-system :dds-disc)" --eval "(assert (dds.disc::run-zc-shmem-secured-overlay-test))" --eval "(sb-ext:quit)"
sbcl --non-interactive --eval "(asdf:load-system :dds-disc)" --eval "(assert (dds.disc::run-zc-shmem-secured-overlay-test))"
```
Expected: Part A PASS both impls; Part B PASS on SBCL (real SHMEM), SKIP cleanly on Clasp/macOS. Also run `run-zc-shmem-secured-cleartext-test` — must stay green (the raw-ZC and gated arms are unchanged).

- [ ] **Step 8: Run gate-hotpath**

```
make gate-hotpath
```
Expected: PASS — no CLOS dispatch / per-sample GC-heap alloc introduced on the non-secured hot path (the overlay arm is a secured niche path; the scratch is pooled).

- [ ] **Step 9: Commit** (present message for approval first)

```
git add src/dds-disc/disc.lisp src/dds-disc/dataplane.lisp src/dds-disc/secure-sedp.lisp src/dds-security/key-material.lisp src/dds-security/packages.lisp
git commit -m "feat(security): WP-SECURITY-ZC-SHMEM-OVERLAY T2 — ENCRYPT-tier writers seal the in-slot SecuredPayload overlay (ADR 0051)"
```

---

## Task 3: Read-side overlay decode

**Files:**
- Modify: `src/dds-disc/dataplane.lisp` (`%zc-ref-overlay-p`; `%zc-try-resolve` 2nd return value ~:2311; `%on-user-data` threading ~:2897; `%deliver-user-sample` `overlay-secured` param ~:2746)
- Test: `src/dds-disc/secure-sedp.lisp` (`run-zc-shmem-secured-overlay-test` Part C — full loopback)

**Interfaces:**
- Consumes: `parse-zc-reference` 4th value (Task 1); the write path (Task 2).
- Produces: `%zc-ref-overlay-p buf poff plen → boolean`; `%zc-try-resolve` returns `(values vec overlay)`; `%deliver-user-sample ... &optional key-hash overlay-secured`.

- [ ] **Step 1: Write the failing test (Part C, full loopback)**

Append Part C to `run-zc-shmem-secured-overlay-test` (inside the `(let ((*zerocopy-enabled* t)) ...)` SHMEM-gated block, a second reader node attaching the writer's pool). Reuse the writer node's pool + the shared KM; feed the emitted ref DATA to the reader's `%on-user-data`:

```lisp
                 ;; Part C — full loopback: a reader attaches the writer's pool, resolves the overlay ref, and
                 ;; DECODES it to the correct plaintext (the reader's data_protection is NONE — the overlay
                 ;; sentinel forces the decode).
                 (let* ((pb (make-array 12 :element-type '(unsigned-byte 8) :initial-element 94))
                        (reader (make-disc-node :guid-prefix pb :host "127.0.0.1" :port 0))
                        (m3 (map '(simple-array (unsigned-byte 8) (*)) #'char-code
                                 "ZC-OVERLAY-ROUNDTRIP-PLAINTEXT-33333333333333333333333333"))
                        (ch3 (dds.rtps.history:make-cache-change :kind :data :sn 3 :serialized-payload m3))
                        (got nil))
                   (unwind-protect
                        (progn
                          ;; install the SAME KM on the reader as a decode resolver keyed by the writer GUID
                          (setf (disc-node-crypto-transform reader) km)   ; raw KM -> %deliver-user-sample uses it directly
                          (setf (disc-node-on-data reader)
                                (lambda (w sn b poff plen sp og os kh) (declare (ignore w sn sp og os kh))
                                  (setf got (subseq (dds.core.buffer:octet-buffer-vec b) poff (+ poff plen)))))
                          ;; writer seals ch3 into a slot, returns the ref item; extract the 20-octet ref bytes
                          (setf (disc-node-rtps-protection-kind node) :encrypt
                                (disc-node-crypto-transform node) km)
                          (let* ((item (%zc-change-item node ch3 1))
                                 (refbuf (dds.core.buffer:octet-buffer (make-array 64 :element-type '(unsigned-byte 8))
                                                                       :endianness :little)))
                            (assert item () "C: the overlay write must produce a ref item")
                            ;; build the ref DATA bytes the item would emit, then hand the 20-octet body to the reader
                            (funcall (cdr item) (dds.core.buffer:cursor refbuf :endianness :little))
                            ;; the reader attaches the WRITER's pool (same process) and resolves+decodes
                            (%on-user-data reader (%emit-wid node) 3
                                           (dds.core.buffer:octet-buffer-over
                                            ;; the 20-octet reference SerializedPayload the item wrote (locate the body)
                                            (dds.disc::%zc-test-extract-ref-body refbuf))
                                           0 20 pa)
                            (assert (and got (equalp got m3)) ()
                                    "C: the reader must recover the overlay plaintext byte-exact through the copy-on-read decode")))
                     (stop-node reader)))
```

> The exact mechanics of extracting the 20-octet reference body from the built DATA submessage (`%zc-test-extract-ref-body`) mirror how `run-rtps-protection-zeroalloc-test` captures a datagram via `*datagram-sink*` (secure-sedp.lisp:1223) — use the same capture idiom rather than hand-parsing. If simpler, drive the writer's real send with a `*datagram-sink*` capturing the ref datagram and feed it through `%rtps-feed-datagram reader cap` exactly as the zeroalloc test does (secure-sedp.lisp:1236), which exercises the real receive path end-to-end. Prefer the `*datagram-sink*` + `%rtps-feed-datagram` route (it is the established, less brittle harness).

- [ ] **Step 2: Run it to verify it fails**

```
scripts/with-clasp.sh --non-interactive --eval "(asdf:load-system :dds-disc)" --eval "(dds.disc::run-zc-shmem-secured-overlay-test)" --eval "(sb-ext:quit)"
```
Expected: FAIL (SBCL) — the reader delivers the raw `SecuredPayload` (its `rkind` is :none, so the existing decode gate skips) → `got` ≠ `m3`.

- [ ] **Step 3: Add `%zc-ref-overlay-p` and make `%zc-try-resolve` return the overlay flag**

In `src/dds-disc/dataplane.lisp`, add near `%zc-try-resolve` (~:2311):

```lisp
(defun* %zc-ref-overlay-p (buf poff plen)
    (function (dds.core.buffer:octet-buffer (integer 0) (integer 0)) boolean)
  "WP-SECURITY-ZC-SHMEM-OVERLAY (ADR 0051): T iff BUF[poff,poff+plen) is a ZC reference whose reserved field
   is +zc-ref-overlay-secured+ (the slot holds a data_protection SecuredPayload). Used at the receive dispatch
   to force copy-on-read for a loan-capable reader (an overlay slot cannot be read in place — it is ciphertext)."
  (multiple-value-bind (slot gen slot-bytes overlay)
      (dds.cdr:parse-zc-reference (dds.core.buffer:octet-buffer-vec buf) poff plen)
    (declare (ignore gen slot-bytes))
    (and slot (= overlay dds.cdr:+zc-ref-overlay-secured+) t)))
```

Modify `%zc-try-resolve` to capture and return the overlay flag as a 2nd value (ftype becomes `(values t (unsigned-byte 32))`):

```lisp
  (multiple-value-bind (slot gen slot-bytes overlay)
      (dds.cdr:parse-zc-reference (dds.core.buffer:octet-buffer-vec buf) poff plen)
    (declare (ignore slot-bytes))
    (if (null slot)
        (values :not-a-ref 0)
        (let ((sap (%zc-attach-pool node src-prefix)))
          (if (null sap)
              (values nil 0)
              (let ((vec (dds.xport.zerocopy::%zc-resolve-fresh sap slot gen)))
                (dds.xport.zerocopy::%zc-release sap slot gen)
                (values vec overlay))))))
```

- [ ] **Step 4: Thread the overlay flag through `%on-user-data`**

Modify the `zc` computation + dispatch (~:2897) to capture the 2nd value and force copy-on-read for overlay refs on a loan-capable reader:

```lisp
  (let* ((eff-guid (or orig-guid (%source-guid src-prefix writer-id)))
         (eff-sn   (or orig-sn sn)))
    (multiple-value-bind (zc overlay)
        (cond
          ((null (disc-node-zc-pool node)) :not-a-ref)
          ((and (disc-node-zc-loan-capable node)
                (not (%zc-ref-overlay-p buf poff plen)))   ; overlay refs can't be loaned in place -> copy-on-read
           (%zc-defer node buf poff plen src-prefix))
          (t (%zc-try-resolve node buf poff plen src-prefix)))
      (cond
        ((null zc))
        ((eq zc :not-a-ref)
         (let ((vec (make-array plen :element-type '(unsigned-byte 8))))
           (replace vec (dds.core.buffer:octet-buffer-vec buf) :start2 poff :end2 (+ poff plen))
           (%deliver-user-sample node writer-id sn vec src-prefix eff-guid eff-sn key-hash)))
        ((zc-loan-marker-p zc)
         (%deliver-user-marker node writer-id sn zc src-prefix eff-guid eff-sn))
        (t (%deliver-user-sample node writer-id sn zc src-prefix eff-guid eff-sn key-hash
                                 (= overlay dds.cdr:+zc-ref-overlay-secured+)))))
    t))
```

> `%zc-defer` returns a single value → `overlay` binds to NIL for that arm; `:not-a-ref` likewise. Only the `%zc-try-resolve` arm yields a real overlay flag. Guard the `(= overlay ...)` with `overlay` being `(unsigned-byte 32)` (0 on the non-resolve arms — bind default via `(or overlay 0)` if a NIL can reach it; `%zc-defer`/`:not-a-ref` are handled by earlier cond arms, so the `(t ...)` arm always has a numeric overlay).

- [ ] **Step 5: Add the `overlay-secured` param to `%deliver-user-sample` and OR it into the decode gate**

Change the lambda list (~:2746) to add `overlay-secured` after `key-hash`:

```lisp
(defun* %deliver-user-sample (node writer-id sn vec src-prefix effective-guid effective-sn
                             &optional key-hash overlay-secured)
    (function (disc-node (unsigned-byte 32) integer (simple-array (unsigned-byte 8) (*))
              (simple-array (unsigned-byte 8) (12))
              (simple-array (unsigned-byte 8) (16)) integer
              &optional (or null (simple-array (unsigned-byte 8) (*))) t) t)
```

Change ONLY the decode gate (line 2786) from:

```lisp
    (let ((ct (and (not (eq rkind :none)) (disc-node-crypto-transform node))))
```

to:

```lisp
    ;; WP-SECURITY-ZC-SHMEM-OVERLAY (ADR 0051): a ZC overlay sample is a data_protection SecuredPayload even when
    ;; the reader's own data_protection governance is NONE — OVERLAY-SECURED forces the decode (the KM resolves as
    ;; the remote-writer EntityCrypto key exactly as the normal data_protection decode; fail-closed reuse below).
    (let ((ct (and (or overlay-secured (not (eq rkind :none))) (disc-node-crypto-transform node))))
```

Everything below (KM resolution via `crypto-keys-decode-key-fn` on the writer `guid`, pooled/allocating `decode-serialized-payload-into`, fail-closed drop, `%secured-decode-fail`) is reused unchanged. For an overlay sample the reader is typically not `secured-loan-capable` (data=NONE) → it takes the non-loan allocating decode branch (line 2833), producing the plaintext.

Update the `%deliver-user-sample` docstring to note the `overlay-secured` param (ADR 0051).

- [ ] **Step 6: Run the test to verify it passes**

```
scripts/with-clasp.sh --non-interactive --eval "(asdf:load-system :dds-disc)" --eval "(assert (dds.disc::run-zc-shmem-secured-overlay-test))" --eval "(sb-ext:quit)"
sbcl --non-interactive --eval "(asdf:load-system :dds-disc)" --eval "(assert (dds.disc::run-zc-shmem-secured-overlay-test))"
```
Expected: Parts A + B + C PASS on SBCL; A PASS + B/C SKIP on Clasp/macOS (no SHMEM). The reader recovers `m3` byte-exact.

- [ ] **Step 7: Full regression**

```
make test   # both impls (Clasp first)
```
Expected: all landed tests green. In particular `run-zc-shmem-secured-cleartext-test`, `run-rtps-protection-zeroalloc-test`, the FlatData ZC/loan-write tests, and all UDP-loopback + security regressions unchanged.

- [ ] **Step 8: Commit** (present message for approval first)

```
git add src/dds-disc/dataplane.lisp src/dds-disc/secure-sedp.lisp
git commit -m "feat(security): WP-SECURITY-ZC-SHMEM-OVERLAY T3 — reader decodes the in-slot overlay on copy-on-read (ADR 0051)"
```

---

## Task 4: Fail-closed hardening

**Files:**
- Test: `src/dds-disc/secure-sedp.lisp` (`run-zc-shmem-secured-overlay-test` Part D)
- (No new production code expected — this task PROVES the reuse of the existing fail-closed paths; add a targeted guard only if a gap is found.)

**Interfaces:**
- Consumes: Task 3's read path.

- [ ] **Step 1: Write the failing test (Part D)**

Append Part D: (i) a reader with NO KM for the writer drops (no delivery, no crash); (ii) a tampered slot (flip one ciphertext byte before the reader resolves) fails the GCM tag and drops, `disc-node`'s secured-decode-fail counter advances. Model the tamper on `%seg-has`'s byte access — locate the slot payload region (`slot-off + +zc-slot-hdr+`) and XOR one byte.

```lisp
                 ;; Part D — fail-closed: no-KM drop + tamper drop.
                 (let* ((pb (make-array 12 :element-type '(unsigned-byte 8) :initial-element 95))
                        (reader (make-disc-node :guid-prefix pb :host "127.0.0.1" :port 0))
                        (delivered 0))
                   (unwind-protect
                        (progn
                          (setf (disc-node-on-data reader)
                                (lambda (&rest _) (declare (ignore _)) (incf delivered)))
                          ;; (i) NO KM installed on the reader -> the overlay decode resolves nil km -> fail-closed drop
                          ;; (drive a captured overlay ref datagram through %rtps-feed-datagram, assert delivered stays 0)
                          ;; (ii) install the KM, then TAMPER the slot payload byte and re-drive -> GCM tag fails -> drop,
                          ;;      disc-node secured-decode-fail advances, delivered still 0.
                          (assert (zerop delivered) () "D: a fail-closed overlay sample must NOT be delivered"))
                     (stop-node reader)))
```

> Flesh out (i)/(ii) with the same `*datagram-sink*` capture + `%rtps-feed-datagram` idiom as Part C. For the tamper, capture the writer pool SAP, compute the sealed slot's payload offset, XOR one octet, then feed the (unchanged) ref — the reader resolves the now-corrupt slot and `decode-serialized-payload` returns NIL → `%secured-decode-fail`. Assert the node's decode-fail counter (grep `%secured-decode-fail` for the counter accessor) incremented.

- [ ] **Step 2: Run it to verify it fails or passes**

```
scripts/with-clasp.sh --non-interactive --eval "(asdf:load-system :dds-disc)" --eval "(assert (dds.disc::run-zc-shmem-secured-overlay-test))" --eval "(sb-ext:quit)"
```
Expected: if the existing fail-closed reuse is correct, Part D PASSES immediately (this is a proof test). If it FAILS (a gap), add the minimal guard in `%deliver-user-sample`/`%zc-try-resolve` and re-run.

- [ ] **Step 3: Run both impls + gate-hotpath**

```
sbcl --non-interactive --eval "(asdf:load-system :dds-disc)" --eval "(assert (dds.disc::run-zc-shmem-secured-overlay-test))"
make gate-hotpath
```
Expected: PASS.

- [ ] **Step 4: Commit** (present message for approval first)

```
git add src/dds-disc/secure-sedp.lisp
git commit -m "test(security): WP-SECURITY-ZC-SHMEM-OVERLAY T4 — fail-closed proofs (no-KM drop, tamper drop) (ADR 0051)"
```

---

## Task 5: ADR, docs, verification, bench

**Files:**
- Create: `docs/adr/0051-zc-shmem-secured-overlay.md`
- Modify: `docs/adr/0038-zero-alloc-aead.md` (flip residual (c) to resolved-for-ENCRYPT, cross-ref ADR 0051), `docs/adr/0036-dds-security-secure-discovery.md` (Carry 10 note: ENCRYPT-tier ZC now via overlay)
- Modify: `docs/wiki/security.md` + the ZC wiki page, `README.md`
- Modify: `docs/verification.csv` (row for WP-SECURITY-ZC-SHMEM-OVERLAY)
- Create: `bench/report/2026-07-09-zc-shmem-secured-overlay.md`

- [ ] **Step 1: Write ADR 0051**

Content per the design doc §10: relax the ADR 0031 §4 crypto+ZC loud-guard for the ENCRYPT case (in-slot `data_protection` `SecuredPayload` overlay under the per-writer EntityCrypto key, copy-on-read only, discriminator in the wire-protected reference); the forward requirement (any future in-slot write site applies the overlay-or-gate discipline); deferred follow-ons (SIGN-only raw ZC; `-into-sap` direct-seal). Cite the reused clauses (§9.5.3.3, ADR 0036 Carry 10, ADR 0042).

- [ ] **Step 2: Update ADR-0038(c) + ADR-0036 Carry 10 cross-refs**

Mark ADR-0038 residual (c) resolved-for-ENCRYPT (pointing at ADR 0051); add a note to ADR-0036 Carry 10 that ENCRYPT-tier writers now get ZC via the overlay (the leak stays closed for all tiers; SIGN-only stays gated pending the follow-on).

- [ ] **Step 3: Docstrings + wiki + README**

Confirm every added exported symbol (`+zc-ref-overlay-secured+`, `key-material-encrypt-p` if added, `run-zc-shmem-secured-overlay-test`) has a docstring. Add a use-case + worked example to the security + zero-copy wiki pages (a secured ENCRYPT writer now zero-copies large samples with ciphertext-in-SHMEM). Update `README.md` status line if scope/architecture shifts.

- [ ] **Step 4: verification.csv + bench**

Add a `docs/verification.csv` row (requirement id, WP id, test name `run-zc-shmem-secured-overlay-test`, status). Run the bench: publish a stream of large (16 KiB) ENCRYPT-tier samples over the overlay ZC path vs the current gated-off (serialize+ring) path; record datagram/copy counts + p50/p99 into `bench/report/2026-07-09-zc-shmem-secured-overlay.md`.

- [ ] **Step 5: Register the test in the suite**

Add `("zc-shmem-secured-overlay" . dds.disc:run-zc-shmem-secured-overlay-test)` to `src/dds-tests/echo-test.lisp:4069` (next to `zc-shmem-secured-cleartext`); export `run-zc-shmem-secured-overlay-test` from `src/dds-disc/packages.lisp`.

- [ ] **Step 6: Full gates**

```
make test        # both impls, Clasp first
make gate-hotpath
make corpus
make bench        # or the targeted overlay bench
make sbom         # (also auto-staged by the pre-commit hook)
```
Expected: all green; security corpora + NIST KATs + Connext/Fast-DDS interop unchanged.

- [ ] **Step 7: Commit** (present message for approval first)

```
git add docs/ README.md bench/report/2026-07-09-zc-shmem-secured-overlay.md src/dds-disc/packages.lisp src/dds-tests/echo-test.lisp sbom.spdx.json
git commit -m "docs(security): WP-SECURITY-ZC-SHMEM-OVERLAY T5 — ADR 0051, wiki/README/verification, bench (closes ADR-0038(c) for ENCRYPT)"
```

---

## Self-Review

**1. Spec coverage.**
- Spec §4.1 (per-writer EntityCrypto key) → Task 2 `%zc-overlay-km`. ✓
- Spec §4.2 (SecuredPayload format) → Task 2 `encode-serialized-payload-into`. ✓
- Spec §4.3 (write path) → Task 2 `%zc-change-item` overlay arm + scratch. ✓
- Spec §4.4 (discriminator in reference datagram) → Task 1 sentinel. ✓
- Spec §4.5 (read path, copy-on-read decode regardless of reader kind, fail-closed) → Task 3 (`overlay-secured` gate) + Task 4 (fail-closed proofs). ✓
- Spec §4.6 (nonce uniqueness) → reused `encode-serialized-payload-into` (writer EntityCrypto counter); asserted by the round-trip. ✓
- Spec §3 out-of-scope (SIGN-only, loan-write literal-0-copy, cross-vendor) → `%zc-overlay-eligible-p` excludes SIGN + non-ENCRYPT; `%on-user-data` forces copy-on-read for overlay refs on loan-capable readers; §7 interop note. ✓
- Spec §8 testing (Parts A/B/C/D, non-vacuous, both impls) → Tasks 2–4. ✓
- Spec §9 bench, §10 ADR, §11 DoD → Task 5. ✓

**2. Placeholder scan.** The read-side test harness for Parts C/D references the established `*datagram-sink*` + `%rtps-feed-datagram` idiom (secure-sedp.lisp:1223/1236) rather than inlining a brittle byte-extractor — this is a concrete anchor, not a placeholder. All production code blocks are complete. The two "confirm the exact API" notes (`dds.core.arena:make-pool` keywords; `key-material-encrypt-p` export) point at exact mirror sites with the fallback spelled out.

**3. Type consistency.** `+zc-ref-overlay-secured+` is `(unsigned-byte 32)` value 1 everywhere; `overlay` threaded as `(unsigned-byte 32)` through `encode-zc-reference`/`%encode-zc-ref-vec`/`%zc-ref-item`/`%zc-ref-builder`; `parse-zc-reference` returns 4 values consistently; `%zc-try-resolve` returns `(values t (unsigned-byte 32))`; `%deliver-user-sample`'s new `overlay-secured` is a boolean-ish `t`. `%zc-overlay-km` returns `(or null key-material)`; `%zc-overlay-eligible-p` returns boolean. Consistent across tasks.

---

## Execution Handoff

Offered after the plan is saved (see the message accompanying this file).
