# WP-FLATDATA-ZC-LOAN Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Literal-0-copy RX for FlatData over Zero-Copy — a same-host FlatData reader reads fields directly from the writer's SHMEM slot via an explicit loan/return_loan API (0 intra-host copies on RX), removing the v1 safe-single-copy.

**Architecture:** Defer ZC-ref resolution from the disc receiver thread to the DCPS read path (where the type is known). For a reader DCPS marks `zc-loan-capable` (FlatData topic + ZC on), the disc stores the unresolved ref (slot stays loaned via the writer's `refcount=readers`); DCPS `take-loaned`/`read-loaned` hands the app a `flatdata-view` over the live slot SAP (read via SAP-mode Offset accessors) + tracks it; `return-loan` releases (`%zc-release`). Non-loan-capable/non-FlatData/non-ZC paths unchanged.

**Tech Stack:** Common Lisp (SBCL; ZC is SBCL-only per ADR 0013). `dds.pal` (SAP refs), `dds.core.buffer` (buffer-sap), `dds.gen` DSL (FlatData accessors), `dds.types` (type-support/flatdata-view), `dds.xport.zerocopy` (pool loan), `dds.disc` (defer), `dds.dcps` (loan API).

**Authoritative spec:** `docs/superpowers/specs/2026-06-16-wp-flatdata-zc-loan-design.md`. **Conventions:** `defun*`+full ftype (FR-LANG-8); one-line comments; SAP accessors + loan path 0-alloc/CLOS-free (NFR-MEM/NFR-CLOS); bounds-check untrusted cross-process slot bytes even at `(safety 0)`; no reader conditionals outside `dds-pal/`; **R6 marker** `NOT cleared for ship — pending counsel (R6); see ADR 0017` on every new symbol/path (this IS the FlatData+ZC 0-copy mechanism); default-off (`*zerocopy-enabled*` + `:flatdata t`); SBOM auto-staged; FR-LANG-7 bench; commit autonomously per task; **no AI-assistant / co-author / Generated-with attribution** anywhere.

## Verified grounding (from the Explore)
- **PAL** (`src/dds-pal/pal-contract.lisp:23`, `pal-sbcl.lisp:102-122`, `pal-clasp.lisp:123-147`): exports only `load-sap-u64`/`store-sap-u64`/`cas-sap-u64`. SBCL = `sb-sys:sap-ref-{8,16,32,64}`; Clasp `cas-sap-u64` signals `pal-unimplemented`. Need `load-sap-u8/u16/u32` (SBCL native; Clasp = `pal-unimplemented` gap, ZC never runs there).
- **buffer** (`src/dds-core/buffer.lisp:11-15,32-35`): `octet-buffer {vec (static-vector), capacity}`; `buffer-sap` = `static-pointer(octet-buffer-vec)` EXISTS but is UNEXPORTED.
- **FlatData accessors** (`src/dds-gen/dsl.lisp:116-134` form-builders, `:279-312` emit): `%flatdata-getter-form vec base nbytes signed-p bool-p` → `(logior (ash (aref VEC (+ base i)) (* 8 i)) ...)` + signed/bool wrap; emitted `(defun <name>-<field>-fd (buf) ... (let ((vec (octet-buffer-vec buf))) <getter-form>))`; `make-<name>-flatdata`, `+<name>-flatdata-size+`, `flatdata-layout {size, encap-offset=4, fields}` in `type-support` `flatdata-offset`.
- **ZC pool** (`src/dds-xport/zerocopy-pool.lisp`): slot hdr 32B {refcount@0:u32, generation@4:u32, len@8:u32, pubseq@16:u64}; `%zc-loan` sets `refcount=readers` + bumps generation; `%zc-take-free-or-reclaim` picks lowest-pubseq when freelist empty (does NOT currently check refcount); `%zc-resolve-fresh` copies under the mutex; `%zc-release` validates generation + decrements, freelist at 0; `%zc-slot-payload-len` clamps `min(recorded-len, slot-bytes)`.
- **disc ZC path** (`src/dds-disc/dataplane.lisp` ~818 `%zc-try-resolve`, ~840-861 `%on-user-data`): the receiver thread resolves (copy) + `%zc-release`s, stores the owned vec in `disc-node-samples`.
- **DCPS read** (`src/dds-dcps/entities.lisp` ~835 `%drain-one-sample`, ~933-976 read/take, ~189-197 `%deserialize-sample` frees the RX buffer): copy-into-`dr-cache`, NO loan/return_loan; type-support reachable at `%drain` via `(topic-type-support (dr-topic dr))`.

## File structure
- **Modify** `src/dds-pal/pal-contract.lisp` + `pal-sbcl.lisp` + `pal-clasp.lisp` (the `load-sap-u8/u16/u32`), `src/dds-core/buffer.lisp` + its packages (export `buffer-sap`).
- **Modify** `src/dds-gen/dsl.lisp` (SAP-mode accessor dispatch), `src/dds-types/type-support.lisp` + packages (`flatdata-view` struct + a per-reader view freelist).
- **Modify** `src/dds-xport/zerocopy-pool.lisp` + packages (`%zc-acquire-for-read`, force-reclaim refcount skip, idempotent release).
- **Modify** `src/dds-disc/dataplane.lisp` + `disc.lisp` + packages (defer-for-loan-capable, the `zc-loan-capable` flag).
- **Modify** `src/dds-dcps/entities.lisp` + packages (`take-loaned`/`read-loaned`/`return-loan` + loan registry + loan-capable wiring + reader-close returns loans).
- **Create** `docs/adr/0017-flatdata-zc-loan.md`. **Test**: `src/dds-tests/echo-test.lisp` + `integration-test.lisp` + `pbt-test.lisp`. **Bench**: `bench/report/2026-06-16-wp-flatdata-zc-loan.md`. **Docs**: README, `docs/wiki/`, `docs/verification.csv`, `docs/provenance.md`.

---

# Phase A — PAL SAP refs + buffer-sap export + ADR 0017

### Task A1: `load-sap-u8/u16/u32` + export `buffer-sap` + ADR 0017
**Files:** Modify `src/dds-pal/pal-contract.lisp`, `pal-sbcl.lisp`, `pal-clasp.lisp`, `src/dds-core/buffer.lisp` (packages); Create `docs/adr/0017-flatdata-zc-loan.md`.
- [ ] **Step 1: ADR 0017** (match ADR 0014/0015 style): WP-FLATDATA-ZC-LOAN (FR-PF-3/4, NFR-PERF-7); **R6 build-now/gate-ship** (default-off `*zerocopy-enabled*` + `:flatdata t`; NOT-cleared-for-ship marker); the design (defer-to-DCPS, per-reader loan-capable flag, loan/return_loan, slot held via refcount, force-reclaim skips refcount>0); the loan API = OMG DDS read()/return_loan() read-by-reference; SBCL-only (NFR-PORT); clean-room. List consumers of the new symbols.
- [ ] **Step 2: failing test** `run-sap-ref-test` (register): alloc an octet-buffer, write known bytes via the existing aref path, then read u8/u16/u32 at offsets via `dds.pal:load-sap-u8/u16/u32` on `(dds.core.buffer:buffer-sap buf)` and assert they equal the LE composition of the bytes (byte-exact). SBCL.
- [ ] **Step 3:** add to the PAL contract `load-sap-u8`, `load-sap-u16`, `load-sap-u32` (each `(function (t (integer 0)) (unsigned-byte N))`). SBCL: `(sb-sys:sap-ref-8 sap off)` / `-16` / `-32`. Clasp: signal `pal-unimplemented` (NFR-PORT gap — ZC never runs on Clasp; mirror `cas-sap-u64`). Export from `dds.pal`. Export `dds.core.buffer:buffer-sap`.
- [ ] **Step 4:** run SBCL → pass; full suite SBCL+Clasp no regression (Clasp doesn't call the new fns). `make gate-types` + `make gate-hotpath` PASS.
- [ ] **Step 5: commit** `feat(pal): WP-FLATDATA-ZC-LOAN load-sap-u8/u16/u32 + export buffer-sap + ADR 0017 (FR-PF-3/4, R6)`

---

# Phase B — SAP-mode FlatData accessors + flatdata-view

### Task B1: `flatdata-view` struct + a SAP getter form
**Files:** Modify `src/dds-types/type-support.lisp` (+ packages); `src/dds-gen/dsl.lisp`.
- [ ] **Step 1:** add `flatdata-view` to type-support.lisp (R6-marked):
```lisp
(defstruct* (flatdata-view (:constructor make-flatdata-view))
  "WP-FLATDATA-ZC-LOAN read-in-place view over a live ZC SHMEM slot (FR-PF-3/4): SLOT-SAP + BASE-OFFSET (=4,
   past the encap header) for the SAP-mode Offset accessors, LEN (validated >= +size+), and SLOT-HANDLE
   (sap+slot-index+generation) for return-loan. NOT cleared for ship — pending counsel (R6); see ADR 0017."
  (slot-sap nil :type t) (base-offset 4 :type (integer 0)) (len 0 :type (integer 0))
  (pool-sap nil :type t) (slot-index 0 :type (integer 0)) (generation 0 :type (unsigned-byte 32)))
```
   Export it + accessors + a freelist helper (a per-reader view pool to avoid per-sample alloc — `make`/recycle).
- [ ] **Step 2:** add `%flatdata-sap-getter-form sap base nbytes signed-p bool-p` to dsl.lisp — the SAP twin of `%flatdata-getter-form`, byte-exact: read each byte via `(dds.pal:load-sap-u8 ,sap (+ ,base i))` and compose identically (logior/ash; signed two's-complement; bool /=0). (Or use `load-sap-u16/u32` for the aligned whole-field read — but per-byte u8 compose is simplest + matches the aref form exactly; confirm byte-exact either way.) Test `run-flatdata-sap-getter-test`: a `:flatdata t` value built in an octet-buffer; read each field via the SAP getter form over `buffer-sap` at `4+offset`; assert == the aref accessor. Commit `feat(gen): WP-FLATDATA-ZC-LOAN flatdata-view + SAP getter form, byte-exact to aref (FR-PF-3/4, R6)`

### Task B2: re-emit `<name>-<field>-fd` to dispatch owned-buffer vs flatdata-view
**Files:** Modify `src/dds-gen/dsl.lisp` (the accessor emit).
- [ ] **Step 1: failing test** `run-flatdata-view-accessor-test` (register): for a `:flatdata t` type, `(make-<name>-flatdata)` + set fields (owned path) read back correctly (unchanged); AND a `flatdata-view` over the SAME buffer's SAP (base 4) read via the SAME `<name>-<field>-fd` returns the same values (the dispatch view path). All widths + signed + bool.
- [ ] **Step 2:** re-emit the getter `<name>-<field>-fd` to dispatch:
```lisp
(defun ,(fd-acc m) (x)
  ,docstring  ; ... NOT cleared for ship (R6) ...
  (dds.pal:with-hot-optimizations
    (if (dds.types:flatdata-view-p x)
        (let ((sap (dds.types:flatdata-view-slot-sap x))
              (base (+ (dds.types:flatdata-view-base-offset x) ,body-offset)))
          ,(%flatdata-sap-getter-form 'sap 'base nbytes signed-p bool-p))
        (let ((vec (dds.core.buffer:octet-buffer-vec x)))
          (declare (type (simple-array (unsigned-byte 8) (*)) vec))
          ,(%flatdata-getter-form 'vec base nbytes signed-p bool-p)))))   ; EXACT shipped owned logic
```
   Widen the ftype to `(function ((or octet-buffer flatdata-view) ...) ltype)`. The owned branch is BYTE-IDENTICAL to the shipped accessor (the regression guard = the existing FlatData byte-exact + 0-alloc tests must still pass). Setters stay owned-buffer-only (a view is read-only RX; document — writing a loaned slot is out of scope).
- [ ] **Step 3:** run; the existing FlatData tests (byte-exact, 0-alloc, accessor) + the new view test pass SBCL+Clasp; `make gate-hotpath` + `make mem` PASS (the dispatch is a predicted struct-type branch, still 0-alloc on both paths). Commit `feat(gen): WP-FLATDATA-ZC-LOAN <name>-<field>-fd dispatches owned-buffer vs flatdata-view (one surface), shipped owned path byte-preserved (FR-PF-3/4, R6)`

---

# Phase C — ZC pool reader-loan

### Task C1: `%zc-acquire-for-read` + force-reclaim skips refcount>0 + idempotent release
**Files:** Modify `src/dds-xport/zerocopy-pool.lisp` (+ packages).
- [ ] **Step 1: failing tests** `run-zc-loan-acquire-test` / `run-zc-reclaim-skips-loaned-test` (register, SBCL): (a) loan a slot (refcount=1), `%zc-acquire-for-read` returns a `flatdata-view`-able handle (pool-sap+slot+gen+len, no copy) whose payload bytes (read via the slot SAP) equal the loaned payload; (b) with the slot loaned (refcount>0), exhaust the pool with more loans → `%zc-take-free-or-reclaim` does NOT reclaim the refcount>0 slot (the held view's bytes stay intact) and `%zc-loan` returns NIL when none are reclaimable (pool-full); (c) `%zc-release` of the held slot frees it (refcount→0 → reusable); a SECOND `%zc-release` (double-return) is a safe validated no-op.
- [ ] **Step 2:** implement `%zc-acquire-for-read(sap, slot-index, generation)` → under the mutex: validate `slot-index < count`, `generation == hdr-generation`, `len ≥` the caller's expected min (the DCPS passes `+<name>-flatdata-size+`; or return len + let DCPS validate) → return `(values pool-sap slot-index generation len payload-base)` WITHOUT copying (refcount already set by the writer's `%zc-loan`). Modify `%zc-take-free-or-reclaim`: when scanning for the lowest-pubseq slot to reclaim, **only consider `refcount==0` slots**; if none free AND none refcount==0 → return NIL (caller = `%zc-loan` → writer non-ZC fallback). Make `%zc-release` idempotent (generation-validated; a stale/already-freed slot → no-op, no double-decrement).
- [ ] **Step 3:** run SBCL; the existing ZC suite (`zerocopy-end-to-end`, `shmem-end-to-end`, `run-flatdata-zerocopy-test`, the resolve fuzz) still green (force-reclaim-skip-refcount must not break the copy path — the non-loan refcount window is tiny + under the mutex). `make gate-hotpath` + `gate-types` PASS. Commit `feat(xport): WP-FLATDATA-ZC-LOAN %zc-acquire-for-read + force-reclaim skips refcount>0 + idempotent release (FR-PF-3, R6)`

---

# Phase D — disc defer-resolution for loan-capable readers

### Task D1: defer the ZC ref (don't resolve/release) for loan-capable readers
**Files:** Modify `src/dds-disc/dataplane.lisp`, `disc.lisp` (+ packages).
- [ ] **Step 1: failing test** `run-zc-defer-test` (register, SBCL): a disc-node reader marked `zc-loan-capable` receiving a ZC ref → the disc stores the UNRESOLVED ref (a marker the DCPS layer resolves), does NOT `%zc-release` it (the slot stays loaned, refcount intact); a NON-loan-capable reader → the existing resolve-copy-release (unchanged). Assert via the slot's refcount + what `disc-node-samples` holds.
- [ ] **Step 2:** add a `zc-loan-capable` boolean slot to the disc-node (or per-reader). In `%on-user-data`/`%zc-try-resolve`: when the receiving reader is `zc-loan-capable` AND the payload is a ZC ref, store the unresolved ref (e.g. a `(:zc-ref pool-name slot gen len)` marker, or the raw ref bytes + the resolved pool-sap) in `disc-node-samples` WITHOUT resolving/releasing; otherwise the current path. Keep the disc otherwise type-opaque (it checks only the boolean). Document the slot-lifetime contract (the slot is now released by DCPS return-loan, not the receiver thread).
- [ ] **Step 3:** run SBCL; non-loan-capable ZC + the full ZC suite unchanged (byte-identical). `make gate-hotpath` PASS. Commit `feat(disc): WP-FLATDATA-ZC-LOAN defer ZC resolution for loan-capable readers (no receiver-thread release) (FR-PF-3, R6)`

---

# Phase E — DCPS loan API + loan-capable wiring

### Task E1: `take-loaned`/`read-loaned`/`return-loan` + loan registry + loan-capable wiring
**Files:** Modify `src/dds-dcps/entities.lisp` (+ packages).
- [ ] **Step 1: failing test** `run-dcps-loan-roundtrip-test` (register, SBCL): a FlatData topic + ZC on; DCPS creates a reader (auto-marked `zc-loan-capable`); a writer publishes over ZC; `take-loaned(dr)` returns `flatdata-view` loan(s); the app reads fields via `<name>-<field>-fd` on the view == published values (0-copy); `return-loan(dr, loans)` releases them (the slot becomes reusable — the writer can loan it again); reader-close with an outstanding loan returns it (no refcount leak).
- [ ] **Step 2:** implement in entities.lisp:
  - `take-loaned(dr)` / `read-loaned(dr)`: `%drain` pending; for each FlatData-ZC ref sample (the deferred marker from Phase D), call `%zc-acquire-for-read` (validate `len ≥ +<type>-flatdata-size+`), build a `flatdata-view` (from the per-reader view freelist), record it in the reader's **loan registry**, and return the views + SampleInfo. (A non-ZC / non-FlatData sample mixed in is delivered copy-backed, registry entry = nil for it.)
  - `return-loan(dr, loans)`: for each loaned view, `%zc-release(pool-sap, slot, gen)` + recycle the view to the freelist + clear the registry entry; idempotent (a view already returned → no-op).
  - Reader close / `stop-node`: `return-loan` all outstanding registry entries (no leaked refcount).
  - **Loan-capable wiring:** when creating a reader on a `:flatdata t` topic with `*zerocopy-enabled*`, set the disc-node/reader `zc-loan-capable` (Phase D's flag).
- [ ] **Step 3:** run SBCL; full suite no regression; the copy-based read/take path unchanged (loan API is additive). `make gate-hotpath` + `gate-types` + `mem` PASS. Commit `feat(dcps): WP-FLATDATA-ZC-LOAN take-loaned/read-loaned/return-loan + loan registry + loan-capable wiring (FR-PF-3/4, R6)`

---

# Phase F — integration (literal-0-copy e2e + 2-proc), bench, fuzz, docs

### Task F1: literal-0-copy e2e + concurrency stress + untrusted-wrap fuzz
**Files:** `src/dds-tests/integration-test.lisp`, `pbt-test.lisp`.
- [ ] `run-flatdata-zc-loan-e2e-test` (SBCL; pass-skip if SHMEM-by-name unreliable): end-to-end FlatData over ZC with the loan API — the reader reads fields from the slot, correct values, AND the RX per-sample bytes-consed is **literal ~0** (no owned vector; vs the v1 single-copy ~80 — the headline NFR-PERF-7 result). A `make zc-xproc`-style 2-process variant if feasible.
- [ ] `run-flatdata-zc-loan-stress-test` (SBCL): the slot lifetime spanning receiver-thread → user-thread `take-loaned` → app `return-loan`, with a concurrent writer loaning + force-reclaiming → no UAF / no torn read / no refcount leak; a held loan blocks reclaim (writer falls back) + stays valid; pool-full → fallback; a leaked loan degrades to fallback (no wedge).
- [ ] `fuzz-flatdata-zc-loan-wrap` (pbt-test.lisp, in `make fuzz`): forged ref (bad slot/generation/len, len < +size+) → `%zc-acquire-for-read` fails/clamps, never OOB into/past the slot (even at `(safety 0)`). Commit `test(dcps): WP-FLATDATA-ZC-LOAN literal-0-copy e2e + concurrency stress + untrusted-wrap fuzz (FR-PF-3/4, NFR-SEC, R6)`

### Task F2: bench + docs
- [ ] `run-bench-flatdata-zc-loan` + `make bench-flatdata-zc-loan` → `bench/report/2026-06-16-wp-flatdata-zc-loan.md`: RX bytes/sample literal ~0 (loan) vs ~80 (v1 single-copy) vs ~65552 (ZC-v1 sink); the loan/return overhead; honest (FR-LANG-7). Commit `bench(dcps): WP-FLATDATA-ZC-LOAN literal-0-copy RX bench (NFR-PERF-7, FR-LANG-7, R6)`
- [ ] Docs: ADR 0017 final (as-built); README P4 (FlatData+ZC literal-0-copy via loan/return_loan, R6, SBCL-only, the follow-ups: reliable-ZC-loan, loan-write API, leak-detection); `docs/wiki/` (the loan API + a worked take-loaned/return-loan example + the 0-copy composition); verification.csv FR-PF-3/4 row; provenance (clean-room — DDS loan model + OMG XCDR; FlatData+ZC concept R6). Commit `docs(dcps): WP-FLATDATA-ZC-LOAN ADR 0017 final + README + wiki + verification + provenance (FR-PF-3/4, R6, §5.1)`

---

## Self-review
- **Spec coverage:** PAL SAP refs + buffer-sap→A1; flatdata-view + SAP getter→B1; dispatch accessor (owned byte-preserved)→B2; pool acquire-for-read + reclaim-skip + idempotent release→C1; disc defer→D1; DCPS loan API + registry + wiring→E1; e2e/stress/fuzz→F1; bench/docs→F2. All covered.
- **Placeholder scan:** the confirm-points carry explicit "byte-exact to aref / confirm force-reclaim-skip doesn't break the copy path" notes, not TODOs. The byte-exact-vs-aref test (B1/B2) is the accessor oracle; the existing FlatData byte-exact/0-alloc tests are the owned-path regression guard.
- **Type consistency:** `flatdata-view {slot-sap, base-offset, len, pool-sap, slot-index, generation}`; `load-sap-u8/u16/u32`; `<name>-<field>-fd : (or octet-buffer flatdata-view) -> ltype`; `%zc-acquire-for-read -> (values pool-sap slot gen len base)`; `take-loaned`/`return-loan`. Consistent A→F.
- **Binary gates:** correctness/stability — force-reclaim-skips-refcount>0 (C1) protects the loaned slot (no overwrite UAF); the slot lifetime spans the handoff (D1/E1) with reader-close returning loans (no leak); the stress test (F1) exercises the 3-way receiver/user/writer interaction; bounds + fuzz (F1) for untrusted slot bytes. Wire-unchanged ⇒ off/non-FlatData byte-identical (D1/E1 regression).
- **Hot-path:** SAP accessors + the dispatch branch + the loan path 0-alloc/CLOS-free (gate-hotpath/mem); the view is freelisted (no per-sample alloc). **R6** marker throughout; default-off.
- **Open (flag at review):** the accessor dispatch re-emits the shipped `<name>-<field>-fd` (owned path byte-preserved) — the existing FlatData tests are the hard regression guard; if the dispatch branch perturbs 0-alloc on the owned path, fall back to separate `-fd-view` accessors (the spec's rejected alt).
