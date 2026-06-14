# WP-FLATDATA — FlatData binding (FINAL fixed-size v1) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

> **AFK / R6 GATE:** Written autonomously (owner AFK, 2026-06-14) as the design package for review. **Do NOT execute (write feature code) until the owner has reviewed + approved the spec `docs/superpowers/specs/2026-06-14-wp-flatdata-design.md` + this plan** (brainstorming HARD-GATE; FlatData is R6 patent-gated). Every new FlatData symbol/file carries `;;;; NOT cleared for ship — pending counsel (R6); see ADR 0015.` Clean-room from FR-PF-4 + the OMG XCDR spec; no RTI source. No AI attribution.

**Goal:** For a `:flatdata t`-annotated FINAL all-fixed-size type, the in-memory buffer == the XCDR2 SerializedPayload; the compiler emits Offset accessors (read/modify in place); serialize/deserialize cost is zero (NFR-PERF-7); composed with WP-ZEROCOPY the reader reads fields from the writer's SHMEM slot with literal 0 copies.

**Architecture:** Extend `define-dds-type` (dds-gen/dsl.lisp): for `:flatdata t` + all-fixed-size-scalar members, compute compile-time XCDR2 field offsets (fold the existing `cdr-size-align` rules at macro time), emit `<name>-<field>-fd` get/`setf` accessors over a foreign buffer at `4 + offset` (4 = encapsulation header), a `make-<name>-flatdata` constructor, and a `flatdata-layout` in the type-support `flatdata-offset` hook. serialize=identity, deserialize=read-in-place. The ZC writer pools the FlatData buffer directly (no serialize); the ZC reader hands the slot SAP to the app via accessors (no deserialize copy).

**Tech Stack:** Common Lisp (SBCL + Clasp), the `dds.gen` DSL, `dds.cdr` (offsets/encapsulation + fixed-offset put/get), `dds.core.buffer`/`dds.pal` (foreign buffers/SAP), `dds.types` type-support, the WP-ZEROCOPY pool/dataplane.

**Authoritative spec:** `docs/superpowers/specs/2026-06-14-wp-flatdata-design.md`. **Conventions:** `defun*`+full ftype; generated code emits ftype decls (FR-LANG-8); one-line comments; XCDR2-LE; bounds-check the untrusted received buffer; no reader conditionals outside dds-pal; SBOM auto-staged; FR-LANG-7 bench; R6 markers; commit autonomously with each task's message.

## Verified grounding (from dsl.lisp + cdr)
- `define-dds-type (name options &body members)` (dsl.lisp:86): OPTIONS plist (`:extensibility`, default `:final`; FINAL-only enforced at :108). `%parse-member` → plists with `:kind :scalar`, `:align`, `:size`, `:var`, `:put`/`:get` (dsl.lisp:33-71). `*dds-type-map*` (dsl.lisp:3-16) has per-type `align`+`size` (`:var` for string).
- XCDR2 offset rule: `%ssize` threads `pos` via `(dds.cdr:cdr-size-align pos align mode)` then `(incf pos size)` (dsl.lisp:148-166). For FlatData I fold the SAME rule at macro time (all sizes constant). `dds.cdr:cdr-size-align` caps alignment per XCDR2 (FR-CDR-2). The emitted ser/deser/ssize/keyhash/type-support machinery (dsl.lisp:112-232) is UNCHANGED for non-flatdata types (additive).
- A SerializedPayload = `[representation-id:u16][options:u16][XCDR2 body]` (dds.cdr `make-encapsulation-header`). FlatData buffer = that, fields at `4 + body-offset`.
- type-support `flatdata-offset`/`flatdata-builder` slots exist (type-support.lisp:24-25), nil today.
- WP-ZEROCOPY: `%zc-loan`/`%zc-resolve` (zerocopy-pool.lisp); the reader resolve + writer pool-store hooks in dataplane.lisp (`%zc-change-item`/`%on-user-data`); the matched type-support is reachable at those hooks.

## File structure
- **Modify** `src/dds-gen/dsl.lisp`: `:flatdata` option, the all-fixed-size check, compile-time offset fold, the accessor/constructor/layout emit (the bulk of the WP). Keep it a focused addition to the existing macro (it's already ~230 lines; the FlatData emit is a `(when flatdata ...)` block + 2-3 helper functions).
- **Modify** `src/dds-types/type-support.lisp` (+ packages): a `flatdata-layout` defstruct* (`size`, `encap-offset`, `fields` alist `(name offset getter setter)`); export it + the `make-<>`/accessors. (The hook slot already exists.)
- **Modify** `src/dds-cdr/cdr.lisp` (if needed): a fixed-offset put/get helper if the existing primitives don't cleanly write at an absolute cursor position (they take a cursor — set position then put/get; confirm).
- **Modify** `src/dds-disc/dataplane.lisp`: the ZC writer/reader FlatData fast path (pool the buffer directly / hand the slot SAP via accessors — 0 copy).
- **Test**: `src/dds-tests/echo-test.lisp` (DSL + accessor + byte-exact-vs-classic-serialize + NFR-PERF-7 alloc), `integration-test.lisp` (ZC+FlatData 0-copy e2e), `pbt-test.lisp` (untrusted-buffer fuzz). **Bench**: `src/dds-bench/perftest.lisp` + `Makefile`. **Docs**: `docs/adr/0015-flatdata.md`, wiki, verification, provenance.

---

# Phase A — ADR 0015 + `:flatdata` recognition + fixed-size gate

### Task A1: ADR 0015 + `:flatdata` option + the all-fixed-size compile check
**Files:** Create `docs/adr/0015-flatdata.md`; Modify `src/dds-gen/dsl.lisp`.
- [ ] **Step 1: ADR 0015** (match ADR 0014 style): WP-FLATDATA FINAL fixed-size v1 (FR-PF-4, NFR-PERF-7); **R6 build-now/gate-ship, per-type opt-in (`:flatdata t`), NOT-cleared-for-ship pending counsel**; the design (buffer==payload, compile-time offsets, Offset accessors, serialize=identity, ZC read-in-place); clean-room (FR-PF-4 + OMG XCDR). No pinned wire constants (the layout IS standard XCDR2; only the opt-in is ours).
- [ ] **Step 2: failing test** `run-flatdata-rejects-variable-test` (register `("flatdata-rejects-variable" . ...)`): `(macroexpand-1 '(define-dds-type ... (:flatdata t) (s :string)))` signals a compile error mentioning "FlatData v1 requires ... fixed-size". (Use `handler-case`/`(nth-value 1 (ignore-errors (macroexpand-1 ...)))`.)
- [ ] **Step 3:** in `define-dds-type` (dsl.lisp:93-110 area), read `(getf options :flatdata)`; when true, after the existing FINAL check, `(when (some (lambda (m) (or (getf m :var) (not (eq (getf m :kind) :scalar)))) parsed) (error "define-dds-type: :flatdata v1 requires FINAL + fixed-size scalar members; got ~s" <m>))`. (No accessors yet — just the gate.)
- [ ] **Step 4:** run the test (the reject path) SBCL+Clasp → passes; a non-flatdata type still compiles (regression). Full suite green.
- [ ] **Step 5: commit** `feat(gen): WP-FLATDATA :flatdata option + FINAL-fixed-size compile gate + ADR 0015 (FR-PF-4, R6)`

---

# Phase B — compile-time offsets + Offset accessors + layout

### Task B1: compile-time XCDR2 offset fold + the flatdata-layout struct
**Files:** Modify `src/dds-types/type-support.lisp` (+ packages); `src/dds-gen/dsl.lisp` (a `%flatdata-offsets` helper).
- [ ] **Step 1:** add to type-support.lisp:
```lisp
(defstruct* (flatdata-layout (:constructor make-flatdata-layout))
  "WP-FLATDATA fixed-size layout (FR-PF-4): the total SerializedPayload SIZE (encap header + XCDR2 body),
   the ENCAP-OFFSET (4), and per-field (name offset getter setter) for in-place access. NOT cleared for ship
   — pending counsel (R6); see ADR 0015."
  (size 0 :type (integer 0)) (encap-offset 4 :type (integer 0)) (fields '() :type list))
```
   Export `flatdata-layout`/`make-flatdata-layout`/accessors. (`type-support-flatdata-offset` already holds it.)
- [ ] **Step 2:** in dsl.lisp add a macro-time helper computing each member's XCDR2 body offset (mirror `%ssize`'s align rule, but constant-folded). Pure arithmetic over `(getf m :align)`/`(getf m :size)` with the XCDR2 alignment cap (match `cdr-size-align`'s cap — read it; XCDR2 caps at 4):
```lisp
(defun* %flatdata-offsets (parsed)
    (function (list) (values list (integer 0)))
  "Return (values ((slot . body-offset) ...) total-body-size) for FINAL fixed-size scalar members, using
   the XCDR2 alignment rule (cap 4) — the compile-time form of %ssize. All members must be fixed-size."
  (let ((pos 0) (out '()))
    (dolist (m parsed)
      (let ((a (min (getf m :align) 4)))           ; XCDR2 alignment cap (FR-CDR-2); confirm vs cdr-size-align
        (setf pos (* (ceiling pos a) a))
        (push (cons (getf m :slot) pos) out)
        (incf pos (getf m :size))))
    (values (nreverse out) (* (ceiling pos 4) 4)))) ; body padded to 4 (XCDR2)
```
- [ ] **Step 3: test** `run-flatdata-offsets-test` (register): for a `(define-dds-type ... (:flatdata t) (a :u8)(b :u32)(c :u64))`, assert the computed offsets match the XCDR2 layout the classic `serialize` produces (a@0, b@4, c@8 — confirm vs an actual `serialize` of `{a b c}` into a buffer + inspecting where each lands). This pins in-memory==wire.
- [ ] **Step 4:** run SBCL+Clasp; commit `feat(gen): WP-FLATDATA compile-time XCDR2 offsets + flatdata-layout (FR-PF-4, R6)`

### Task B2: emit Offset accessors + the constructor + wire the layout into type-support
**Files:** Modify `src/dds-gen/dsl.lisp` (the `(when flatdata ...)` emit block).
- [ ] **Step 1: failing test** `run-flatdata-accessor-test` (register): a `:flatdata t` type; `(make-<name>-flatdata)` returns a buffer of `+<name>-flatdata-size+`; `(setf (<name>-a-fd buf) 7)` then `(<name>-a-fd buf)` = 7 for each field; AND the buffer bytes (after the 4-byte encap header) equal the classic `serialize` of the equivalent struct (byte-exact in-memory==wire).
- [ ] **Step 2:** in `define-dds-type`, when `:flatdata t`, after computing `%flatdata-offsets`, emit:
  - `(defconstant +<name>-flatdata-size+ <4 + total-body>)`.
  - per field, a getter `(<name>-<field>-fd buf)` + a `(setf (<name>-<field>-fd buf) v)` that set a cursor on `buf` to `(+ 4 offset)` and call the member's `:get`/`:put` (XCDR2-LE) — reuse `dds.cdr` (set cursor position + put/get; the same `:put`/`:get` the struct codec uses, so the bytes match exactly). Emit ftype decls (FR-LANG-8).
  - `(make-<name>-flatdata &optional buf)`: allocate (`dds.core.buffer:make-octet-buffer +<name>-flatdata-size+`) or wrap `buf`; write the XCDR2-LE encapsulation header (the same id the classic `serialize` uses — read how the engine wraps payloads; if the classic path writes the encap header at send-time not in `serialize`, then FlatData writes it here so the buffer is the complete payload). Return the buffer.
  - In the `make-type-support` form, set `:flatdata-offset (make-flatdata-layout :size +<name>-flatdata-size+ :fields (list (list "a" <off> #'<name>-a-fd #'(setf <name>-a-fd)) ...))`.
- [ ] **Step 3:** run; the accessor round-trip + byte-exact-vs-serialize pass SBCL+Clasp; non-flatdata types unchanged. Commit `feat(gen): WP-FLATDATA Offset accessors + constructor + type-support layout (FR-PF-4, R6)`

---

# Phase C — serialize=identity / deserialize=read-in-place

### Task C1: FlatData serialize=identity + deserialize=read-in-place + NFR-PERF-7 0-alloc test
**Files:** Modify `src/dds-gen/dsl.lisp` (the type-support `:serialize`/`:deserialize` for flatdata types).
- [ ] For a `:flatdata t` type, override the emitted `:serialize`/`:deserialize`/`:serialized-size` in the type-support: `serialize` = "the sample IS the buffer" (write/copy the buffer's bytes to the output cursor, or — for zero-copy — the engine uses the buffer directly; serialized-size = `+<name>-flatdata-size+`); `deserialize` = wrap the received payload buffer as the sample (read-in-place, no field copy). Keep the classic struct `serialize`/`deserialize` ALSO emitted (for non-FlatData use / interop), but the type-support points at the FlatData identity path when `:flatdata t`.
- [ ] **Test** `run-flatdata-zero-alloc-test` (register): build a FlatData sample, `serialize` + `deserialize` via the type-support, assert (via `dds.pal:bytes-consed`, SBCL) **~0 bytes/sample** (NFR-PERF-7) AND a round-trip through the classic path yields equal field values (interop: a FlatData buffer deserializes correctly via the classic deserializer, and vice versa — proving in-memory==wire). Commit `feat(gen): WP-FLATDATA serialize=identity / deserialize=read-in-place — 0 ser/deser cost (NFR-PERF-7, R6)`

---

# Phase D — WP-ZEROCOPY read-in-place integration (literal 0-copy)

### Task D1: ZC writer pools the FlatData buffer directly; ZC reader reads the slot in place
**Files:** Modify `src/dds-disc/dataplane.lisp` (the `%zc-change-item` writer hook + the `%on-user-data` reader resolve).
- [ ] **Writer:** when the matched type is FlatData (`type-support-flatdata-offset` non-nil) AND ZC is engaged, the published `payload` IS already the FlatData SerializedPayload → store it in the pool slot with **no extra serialize/copy** (it already is the bytes). (Mostly already true since publish-sample gets the serialized payload; assert no double-serialize for FlatData.)
- [ ] **Reader:** when resolving a zc-ref for a FlatData type, instead of copying the slot payload into a fresh sink vector (the WP-ZEROCOPY v1 behavior), hand the **slot SAP region directly** to the on-data delivery as a read-in-place FlatData sample (the app reads fields via the Offset accessors on the slot SAP) — **0 copy**. Bounds: validate `slot len == +<type>-flatdata-size+` before exposing (untrusted; fixed size). Release the slot AFTER the app is done reading (the loan lifetime extends across the read — for best-effort v1, the refcount holds the slot until release; document the read-then-release ordering so the slot isn't force-reclaimed mid-read — the generation guard already catches it).
- [ ] **Test** `run-flatdata-zerocopy-test` (register, SBCL; pass-skip Clasp/macOS): a FlatData type over ZC end-to-end → the reader reads fields correctly from the slot AND the per-sample bytes-consed drops to ~0 (vs the WP-ZEROCOPY-only deserialize-into-sink). This is the headline NFR-PERF-7 + 0-intra-host-copy result. Commit `feat(disc): WP-FLATDATA over Zero-Copy — reader reads slot in place, 0 copies (FR-PF-3/4, NFR-PERF-7, R6)`

---

# Phase E — bench, fuzz, docs

### Task E1: FlatData bench (NFR-PERF-7) + untrusted-buffer fuzz
- [ ] `run-bench-flatdata` (perftest.lisp): FlatData ser/deser cost (≈0) vs the classic codec for the same type; FlatData+ZC large-sample bytes/sample (≈0) vs WP-ZEROCOPY-only. `make bench-flatdata` → `bench/report/2026-06-14-wp-flatdata.md`. Honest (FR-LANG-7).
- [ ] Fuzz `fuzz-flatdata-wrap` (pbt-test.lisp): feed the deserialize/read-in-place path a buffer of wrong length / bad encap → reject (no OOB accessor read). Commit `bench(gen): WP-FLATDATA 0-cost ser/deser + 0-copy-over-ZC + fuzz (NFR-PERF-7, FR-LANG-7, R6)`

### Task E2: docs (ADR 0015 finalize, wiki, verification, provenance)
- [ ] ADR 0015 "Final design (as implemented)"; README P4 (FlatData, default per-type opt-in, R6 NOT-cleared-for-ship, NFR-PERF-7 0-cost, FINAL-fixed-size v1, Builder/variable-size follow-up); `docs/wiki/` (the type-system/cdr page: FlatData annotation + accessors + the ZC 0-copy composition); verification.csv FR-PF-4 row; provenance entry (clean-room FR-PF-4 + OMG XCDR). Commit `docs(gen): WP-FLATDATA ADR 0015 final + wiki + README + verification + provenance (FR-PF-4, R6, §5.1)`

---

## Self-review
- **Spec coverage:** opt-in `:flatdata`→A1; fixed-size gate→A1; compile-time offsets→B1; Offset accessors + constructor + layout→B2; serialize=identity/deserialize=read-in-place + NFR-PERF-7→C1; ZC read-in-place 0-copy→D1; bench/fuzz→E1; docs/ADR/provenance/R6→A1/E2; in-memory==wire proven by byte-exact-vs-classic-serialize→B2/C1. All covered.
- **Placeholder scan:** the two genuinely-must-confirm-at-impl points carry explicit "confirm vs cdr-size-align / vs how the engine writes the encap header" instructions, not TODOs. The `%flatdata-offsets` XCDR2 cap (min align 4) must be verified against `dds.cdr:cdr-size-align` at B1 (flagged) — if the codebase's XCDR2 cap differs, match it (the byte-exact-vs-serialize test in B2 is the oracle).
- **Type consistency:** `flatdata-layout` (size/encap-offset/fields), `%flatdata-offsets` (values offsets total), `<name>-<field>-fd` accessors, `+<name>-flatdata-size+`, `make-<name>-flatdata` — consistent A→E.
- **Open (for owner review, from the spec's AFK decisions):** the buffer/arena ownership + free discipline for `make-<name>-flatdata` (B2 — I spec'd a plain octet-buffer; a pooled/arena variant may be preferred); the app-facing ZC loan-write API (deferred). The byte-exact-vs-classic-serialize test (B2) is the correctness oracle for the whole in-memory==wire claim.
- **R6:** opt-in `:flatdata` annotation is the gate (no type is FlatData unless annotated); NOT-cleared-for-ship marker on every FlatData symbol/file; clean-room; no execution until owner approves (AFK).
