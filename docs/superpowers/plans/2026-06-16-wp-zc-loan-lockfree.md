# WP-ZC-LOAN-LOCKFREE Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Take the literal-0-copy loaned RX path to literal 0-alloc — the per-sample pool `acquire` + `release` go lock-free (eliminating the ~31 GC-bytes/sample CFFI mutex cons), so the reader's loan path allocates 0 GC-heap bytes and copies 0 bytes.

**Architecture:** A loaned slot is held at `refcount>0` and force-reclaim skips it (shipped, ADR 0017) ⇒ its header/payload are stable while held ⇒ the reader path needs only cross-process visibility, provided by the **generation field as a release/acquire sync variable**. `%zc-loan` writes payload→release-fence→generation-last; `%zc-acquire-for-read` is acquire-fence + generation-validate (no mutex); `%zc-release` is a `cas-sap-u64` full-barrier refcount-decrement (no mutex, no freelist); the freelist is dropped (writer scans `refcount==0`). Writer keeps its mutex (loan/scan is writer-side).

**Tech Stack:** Common Lisp (SBCL; ZC SBCL-only). `dds.pal` (`fence`, `cas-sap-u64`, `load-sap-u32`, `store-sap-u64`), `dds.xport.zerocopy` (the pool).

**Authoritative spec:** `docs/superpowers/specs/2026-06-16-wp-zc-loan-lockfree-design.md`. **Conventions:** `defun*`+full ftype; one-line comments; the reader path 0-alloc/CLOS-free; bounds-check the untrusted ref even at `(safety 0)`; no reader conditionals outside `dds-pal/`; **R6 marker** `NOT cleared for ship — pending counsel (R6); see ADR 0018`; default-off; SBOM auto-staged; FR-LANG-7 bench; commit autonomously per task; **no AI-assistant / co-author / Generated-with attribution** anywhere.

## Verified grounding (from the code)
- `src/dds-xport/zerocopy-pool.lisp`: slot hdr 32B {refcount@0:u32, generation@4:u32, len@8:u32, pubseq@16:u64}; `%zc-loan` (lines 106-127) under the pshared-mutex stores **generation FIRST (121)** then copies the payload **LAST (125)** — MUST reorder for the lock-free reader; `%zc-take-free-or-reclaim` (85-104) pops the freelist head, else scans the lowest-pubseq `refcount==0` slot; `%zc-release` (129-154) mutex + generation-check + `(plusp rc)` decrement + freelist-push on the `(= 1 rc)` edge (the `len` field overlays the freelist 'next', `+zc-off-free-head+`); `%zc-acquire-for-read` (167+) mutex + generation-validate + len-clamp + return view (no copy); `%zc-slot-payload-len` (156-165) clamps `min(recorded-len, slot-bytes)`.
- `dds.pal`: `fence` (real, from WP-SHMEM M1 — **confirm it honors a release/acquire/memory `:kind`, not a no-op**), `cas-sap-u64` (SBCL `sb-ext:cas` on `sb-sys:sap-ref-64`, full barrier), `load-sap-u32`/`load-sap-u64`/`store-sap-u64`.
- Regression guard: `zerocopy-end-to-end`, `flatdata-zerocopy`, `zc-pool-*`, `zc-resolve-drop`, `dcps-loan-roundtrip`, `loan-read-return-take`, the resolve fuzz, `make zc-xproc`.

## File structure
- **Modify** `src/dds-xport/zerocopy-pool.lisp` (the loan/acquire/release/scan + drop freelist) + `src/dds-xport/packages.lisp` (no new exports likely).
- **Possibly Modify** `src/dds-pal/*` if `fence` doesn't honor the needed `:kind` (a [Critical] prerequisite).
- **Create** `docs/adr/0018-zc-loan-lockfree.md`. **Test**: `src/dds-tests/echo-test.lisp` + `integration-test.lisp` + `pbt-test.lisp`. **Bench**: `bench/report/2026-06-16-wp-zc-loan-lockfree.md`. **Docs**: README, `docs/wiki/`, `docs/verification.csv`, `docs/provenance.md`.

---

# Phase A — drop the freelist + reorder %zc-loan (still mutex'd; safe intermediate)

### Task A1: ADR 0018 + drop the freelist (writer always-scans) + reorder %zc-loan writes + release-no-freelist-push
**Files:** Create `docs/adr/0018-zc-loan-lockfree.md`; Modify `src/dds-xport/zerocopy-pool.lisp`.
- [ ] **Step 1: ADR 0018** (match ADR 0017): WP-ZC-LOAN-LOCKFREE (NFR-PERF-7) — lock-free 0-alloc loaned RX; the safety invariant (refcount>0 holds the slot stable, force-reclaim skips it); the generation release/acquire handshake; the `%zc-loan` reorder; lock-free acquire + `cas`-decf release; drop the freelist; **R6** default-off + NOT-cleared-for-ship; SBCL-only; clean-room. Status: Proposed (finalized Phase C).
- [ ] **Step 2:** Confirm `dds.pal:fence` honors `:release`/`:acquire` (or a full `:memory` barrier) — if it's a no-op for the needed kind, fix the PAL first (a prerequisite; note it).
- [ ] **Step 3:** Reorder `%zc-loan` (under the writer mutex): set len/refcount/pubseq, **copy the payload**, then `(dds.pal:fence :release)` (or the real kind), then **store the generation LAST**. Drop the freelist: remove `+zc-off-free-head+` init + the freelist-pop branch in `%zc-take-free-or-reclaim` (it becomes always-scan-lowest-pubseq-`refcount==0`); remove the freelist-push in `%zc-release` (it just decrements under the mutex for now — Phase B makes it lock-free). The `len` field no longer overlays 'next'.
- [ ] **Step 4: test** `run-zc-loan-nofreelist-test` (register, SBCL): loan/release cycles reuse slots correctly without the freelist (the writer scans); the lowest-pubseq `refcount==0` slot is reclaimed oldest-first. Run the FULL WP-ZEROCOPY suite (`zerocopy-end-to-end`, `flatdata-zerocopy`, `zc-pool-*`, `zc-resolve-drop`, `dcps-loan-roundtrip`, `loan-read-return-take`) SBCL+Clasp → green (the writer-scan + no-freelist release work under the mutex; the reorder doesn't change the bytes). `make zc-xproc` PASS.
- [ ] **Step 5: commit** `feat(xport): WP-ZC-LOAN-LOCKFREE drop freelist (writer scans refcount==0) + reorder %zc-loan payload-before-generation + ADR 0018 (NFR-PERF-7, R6)`

---

# Phase B — go lock-free (acquire + release) — the memory-ordering crux

### Task B1: lock-free `%zc-acquire-for-read` (fenced read) + lock-free `%zc-release` (cas-decf)
**Files:** Modify `src/dds-xport/zerocopy-pool.lisp`.
- [ ] **Step 1: failing tests** (register, SBCL): `run-zc-lockfree-acquire-test` — `%zc-acquire-for-read` (now no mutex) returns a byte-exact view (read via the slot SAP); a stale/forged generation ⇒ NIL; a forged len ⇒ clamped (no OOB). `run-zc-lockfree-release-test` — `%zc-release` (now no mutex) atomically decrements; double-return is a safe no-op (no underflow); a stale-generation release is a no-op; the slot frees at refcount 0 (the writer reuses it).
- [ ] **Step 2:** `%zc-acquire-for-read`: drop the mutex; read generation (`load-sap-u32`), `(dds.pal:fence :acquire)`, validate `= generation`, clamp len, return the view. `%zc-release`: drop the mutex + the freelist push; a `cas-sap-u64` retry loop on the refcount+generation u64 @slot (LE: `(gen<<32)|rc`): read old, extract rc/gen, `(unless (= gen expected) return NIL)`, `(unless (plusp rc) return T)`, `new=(gen<<32)|(1- rc)`, `cas-sap-u64`; loop on mismatch; the CAS is a full barrier (the reader's reads happen-before refcount→0). Confirm the LE bit layout (refcount low 32, generation high 32) against the slot header offsets.
- [ ] **Step 3: 0-alloc + visibility tests:** assert (via `dds.pal:bytes-consed`) that `%zc-acquire-for-read` + `%zc-release` each cons **0 bytes** (the headline). `run-dcps-loan-roundtrip-test` + `run-loan-read-return-take-test` + `run-flatdata-zc-loan-e2e-test` stay green (byte-exact). **`make zc-xproc` PASS** (the real cross-process release/acquire handshake — the genuine test of the fence pairing). 
- [ ] **Step 4: stress** `run-zc-lockfree-stress-test` (SBCL): N reader threads acquire+read+return while the writer loans+scans+force-reclaims — no torn read, no refcount underflow/leak, no slot overwritten under a reader, the held view stays byte-correct; bounded (no-hang). Run the full suite + gates. Commit `feat(xport): WP-ZC-LOAN-LOCKFREE lock-free fenced-read acquire + cas-decf release — 0-alloc loaned RX (NFR-PERF-7, R6)`

---

# Phase C — 0-alloc-RX bench + docs

### Task C1: bench + docs
- [ ] `run-bench-zc-loan-lockfree` + `make bench-zc-loan-lockfree` → `bench/report/2026-06-16-wp-zc-loan-lockfree.md`: the loaned RX per-sample bytes-consed **~0 (lock-free) vs ~31 (prior mutex'd loan)**; the writer loan cost O(slots)-scan vs the prior O(1) freelist (honest — the reader RX is the win, the writer pays a small scan); the pool-size sensitivity of the scan. Add the Makefile target.
- [ ] Docs: ADR 0018 final (as-built — the reorder, the handshake, the cas-decf, the freelist drop, the writer-scan bench); README P4 (the loaned RX is now literal 0-alloc + 0-copy, R6, SBCL-only); `docs/wiki/` (the lock-free pool note + the release/acquire handshake); verification.csv (NFR-PERF-7 row); provenance (clean-room — standard lock-free release/acquire + the WP-SHMEM ring pattern). Commit `bench(xport): WP-ZC-LOAN-LOCKFREE 0-alloc RX bench + ADR 0018 final + docs (NFR-PERF-7, FR-LANG-7, R6, §5.1)`

---

## Self-review
- **Spec coverage:** drop-freelist + reorder→A1; lock-free acquire + cas-decf release→B1; 0-alloc proof + cross-process + stress→B1; bench/docs→C1. All covered.
- **Placeholder scan:** the `fence` `:kind` confirm (A1 Step 2) is a real prerequisite, not a TODO; the LE bit-layout confirm (B1) is the implementer's check; the byte-exact + zc-xproc + stress tests are the oracles.
- **Type consistency:** `%zc-loan`→`(values (or null (integer 0)) (unsigned-byte 32))`, `%zc-acquire-for-read`→the view tuple, `%zc-release`→T/NIL (now lock-free), `%zc-take-free-or-reclaim`→`(or null (integer 0))` (always-scan). Consistent A→C.
- **Binary gates:** memory-ordering (the publish handshake — payload→release-fence→generation-last vs generation-load→acquire-fence→payload; the cas-decf full-barrier reader-reads-before-reclaim) is the correctness crux — Phase B's review must trace it; the cross-process `zc-xproc` is the genuine test; the stress test guards the lock-free race; the WP-ZEROCOPY suite guards the copy-path regression. Default-off / R6 throughout.
- **Order rationale:** Phase A (drop freelist + reorder, still mutex'd) is a safe intermediate proven by the WP-ZEROCOPY suite; Phase B removes the mutex (the lock-free crux) guarded by zc-xproc + the stress test.
