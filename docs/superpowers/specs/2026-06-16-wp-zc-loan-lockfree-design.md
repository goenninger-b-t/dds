# WP-ZC-LOAN-LOCKFREE — lock-free 0-alloc loaned RX (FlatData over Zero-Copy) — design

**Goal (NFR-PERF-7, NFR-MEM).** Take the literal-0-copy loaned RX path from ~31 GC-bytes/sample to **literal
0-alloc**: the residue is the CFFI `pthread_mutex_lock`/`unlock` cons in the per-sample pool **acquire**
(`%zc-acquire-for-read`) and **release** (`%zc-release`). Both become lock-free, so the reader's per-sample
loan path (acquire + read + return) allocates **0 GC-heap bytes** and copies 0 bytes.

## R6 — PATENT GATE (same as WP-FLATDATA-ZC-LOAN)
This is the FlatData+Zero-Copy 0-copy loan path; gated behind `dds.disc:*zerocopy-enabled*` (default OFF) +
the `:flatdata t` opt-in; the `NOT cleared for ship — pending counsel (R6); see ADR 0018` marker on the new
lock-free codegen. Clean-room (FR-PF-3/4 + the OMG read()/return_loan() model + standard lock-free release/
acquire). SBCL-only (ZC is an NFR-PORT gap on Clasp; the lock-free path is SBCL).

## The safety invariant this rests on
A loaned slot is held at `refcount>0` (the writer's `%zc-loan` sets `refcount=readers`; a reader-loan holds
its count until `%zc-release`) and **force-reclaim skips `refcount>0`** (already shipped, ADR 0017). So while
held, the writer never reclaims or rewrites the slot — its generation, len, and payload are **stable**. The
acquire therefore needs no mutual exclusion, only cross-process **visibility**, which the **generation field
provides as a release/acquire synchronization variable** (the proven WP-SHMEM ring pattern).

## Design — three lock-free changes + drop the freelist (all in `src/dds-xport/zerocopy-pool.lisp`)

### 1. `%zc-loan` — reorder writes + release-fence (THE correctness crux)
Currently (lines 119-125) the writer, under its mutex, stores **generation first** then copies the payload
**last**. For a lock-free reader this is inverted. Reorder so the **generation is the LAST store**, preceded
by a **release-fence**:
```
take/scan a refcount==0 slot (under the writer mutex — writer keeps the mutex)
  set len, set refcount=readers, stamp pubseq
  copy the payload into the slot           ; payload written FIRST
  (dds.pal:fence :release)                 ; release-fence: publish the payload (+ len/refcount/pubseq)
  store generation (bumped) LAST           ; the release-store that publishes everything above
```
The generation store is the single release point. (The writer keeps its mutex for mutual exclusion vs other
writers/force-reclaim; the fence + generation-last is what synchronizes with the *lock-free reader*, which no
longer shares the mutex.)

### 2. `%zc-acquire-for-read` — lock-free fenced read
Drop the `pshared-lock`/`unlock`. Read the generation (acquire), then `(dds.pal:fence :acquire)`, then read
len + return the view:
```
(when (>= slot-index count) → NIL)
g := load-sap-u32 generation@slot
(dds.pal:fence :acquire)                   ; acquire-fence: pair with the writer's release → payload visible
(unless (= g generation) → NIL)            ; generation = the sync var AND the untrusted-ref validation
len := min(load-sap-u32 len@slot, slot-bytes)   ; clamp (OOB-safe on a forged ref)
→ (values pool-sap slot-index generation len payload-base)   ; no copy, no mutex, 0-alloc
```
The generation acquire-load + acquire-fence synchronizes-with the writer's release-fence + generation-store
(crux #1) ⇒ the payload the writer wrote-before is visible. A stale/forged ref ⇒ generation mismatch ⇒ NIL.

### 3. `%zc-release` — lock-free atomic decrement (`cas-sap-u64`)
Drop the mutex + the freelist push. The refcount (u32 @0) and generation (u32 @4) share one u64 @0
(LE: `(gen << 32) | refcount`). Atomically decrement the refcount sub-field via a `cas-sap-u64` retry loop,
guarded by `generation == expected` AND `refcount > 0`:
```
loop:
  old := load-sap-u64 (refcount+generation)@slot
  (extract rc = low32, gen = high32)
  (unless (= gen generation) → return NIL)        ; stale/reclaimed → no-op
  (unless (plusp rc) → return T)                  ; already 0 → double-return no-op (no underflow)
  new := (gen<<32) | (rc-1)
  (when (= old (cas-sap-u64 @slot old new)) → return T)   ; CAS is a full barrier: the reader's payload
                                                          ; reads happen-before refcount→0
  ; else retry
```
`sb-ext:cas` is a full barrier, so the reader's prior payload reads complete before `refcount` reaches 0; the
writer reclaims only `refcount==0` slots, so it never overwrites a slot a reader is still reading. **Double-
return-safe** (the `plusp rc` + generation guards) — a second return, or a reader-close after the app
returned, is a validated no-op.

### 4. Drop the freelist
With the release no longer pushing to the freelist, the freelist would drain and go stale. Remove it: pool
init no longer builds it; `%zc-take-free-or-reclaim` becomes **always-scan** — pick the lowest-pubseq
`refcount==0` slot (the existing reclaim branch, now the only branch). The writer's loan is **O(slots)** (was
O(1) freelist-pop) — writer-side, amortized; benched (FR-LANG-7). The `len` field no longer double-duties as
the freelist 'next'. The writer's `refcount` scan reads a **coherent u32** (a u32 read/write is atomic on the
targets); a concurrent reader decrement it races just defers that slot's reclaim by at most one loan (the
writer sees the old value, skips, finds another or falls back) — never a torn read or corruption.

## Scope (owner-chosen): acquire + release both lock-free (full 0-alloc RX)
This converts the **whole pool's** release + slot-acquisition (the copy path's release too), not just the
loan path — so the shipped WP-ZEROCOPY copy path's release becomes the same lock-free `cas`-decrement and the
writer scans `refcount==0`. The WP-ZEROCOPY suite + `zc-xproc` are the regression guard.

## Memory-ordering correctness (the binary gate — review this hardest)
- **Publish (writer→reader):** writer writes payload → `fence :release` → generation-store (last); reader
  generation-load → `fence :acquire` → reads payload. The generation is the release/acquire sync variable
  (mirrors the WP-SHMEM ring's cursor handshake). Without the crux-#1 reorder, a reader could see a new
  generation before the payload — a torn read; the reorder + fences close it.
- **Reclaim-after-release (reader→writer):** the reader's payload reads happen-before the `cas`-decrement-to-0
  (CAS full barrier); the writer reclaims only `refcount==0`, so it never overwrites a slot mid-read.
- **Writer/reader refcount race:** the writer's scan reads a coherent u32 refcount; a racing lock-free
  decrement defers reclaim by ≤1 loan, never corrupts.
- `dds.pal:fence` must provide real `:release`/`:acquire` barriers on SBCL (confirm it's not a no-op — the
  WP-SHMEM M1 atomics implemented it; verify the `:kind` is honored). If `fence` is a no-op for a `:kind`,
  that's a [Critical] to fix in the PAL first.

## Testing / acceptance (oracle = the bytes + the 0-alloc measurement + cross-process; FR-LANG-7)
- **0-alloc RX (the headline):** the loaned RX per-sample (acquire + read + return) bytes-consed is now
  **literal ~0** (vs the ~31 mutex residue) — bench it; assert ~0 on SBCL.
- **Byte-exact:** the loaned view's field reads still equal the published values (the lock-free acquire reads
  the same bytes; the reorder doesn't change the wire). `run-dcps-loan-roundtrip-test` + `run-flatdata-zc-
  loan-e2e-test` stay green.
- **Cross-process visibility (the real test of the handshake):** `make zc-xproc` (2 OS processes) must stay
  byte-exact — this exercises the genuine cross-process release/acquire (a same-process test can't prove the
  fence pairing). If feasible, add a loan variant of the xproc harness; else the existing xproc + the
  reasoning + the stress test cover it.
- **Lock-free release race / stress:** N reader threads acquiring + returning while the writer loans +
  scans/force-reclaims — no torn read, no refcount underflow/leak, no double-free, no slot overwritten under a
  reader; the held view stays byte-correct. Bounded; SBCL.
- **Double-return:** still safe (the `cas` guards) — `run-loan-read-return-take-test` green.
- **Regression:** the WP-ZEROCOPY copy path (now lock-free release + writer-scan) — `zerocopy-end-to-end`,
  `flatdata-zerocopy`, `zc-pool-*`, `zc-resolve-drop`, the resolve fuzz — all green both impls; off /
  non-FlatData byte-identical.
- **Writer loan bench:** O(1)→O(slots) loan scan — report the writer-side cost at the default pool size
  (honest; the reader RX is the win, the writer pays a small scan).
- Gates green SBCL; `make mem`; the fuzz (forged ref → the lock-free acquire still clamps, no OOB at (safety 0)).

## Out of scope (follow-ups)
- A lock-free freelist (CAS stack) to restore the writer's O(1) loan while keeping lock-free release — the
  scope-fork's rejected (most-intricate) option; revisit only if the O(slots) scan benches as a real cost.
- The other queued M5/P4 WPs (reliable-ZC-loan, per-key/keyed-FlatData, sender-error resilience).

## Decisions baked in (brainstorming 2026-06-16 — confirm at spec review)
1. **Acquire + release both lock-free** (owner-chosen) — full 0-alloc RX; drop the freelist; writer scans.
2. The generation is the release/acquire sync variable; `%zc-loan` reorders to payload→release-fence→
   generation-last; the acquire is acquire-fence + generation-validate; the release is a `cas-sap-u64`
   full-barrier decrement.
3. Writer keeps its mutex (loan/scan is writer-side, amortized); the READER path is fully lock-free.
4. SBCL-only; R6 default-off; ADR 0018.
