# ADR 0018 — WP-ZC-LOAN-LOCKFREE: lock-free 0-alloc loaned RX (FlatData over Zero-Copy)

- **Status:** **Accepted — Phases A–C delivered.** **Phase A** (the `%zc-loan`
  payload→release-fence→generation-last reorder that makes the generation the single publication point for the
  lock-free reader, and the **freelist drop** — `%zc-take-free-or-reclaim` always-scans the lowest-pubseq
  `refcount==0` slot, pool-init builds no freelist). **Phase B**: the lock-free `%zc-acquire-for-read`
  (generation acquire-load → `fence :acquire` → validate → clamped fenced read, 0-copy/0-alloc) and the
  lock-free `%zc-release` — **a direct `cas-sap-u32` decrement of the refcount sub-field** (it CASes ONLY the
  u32 refcount cell @+0, reading the generation @+4 once up front for the stale-ref check; `zerop rc` +
  generation-match guards make it double-return-safe; the `sb-ext:cas` / arm64 `CASAL` full barrier orders the
  reader's payload reads before `refcount→0`). **Phase C** (this commit): the writer-loan O(slots)-scan bench +
  finalization — `dds.tests:run-bench-zc-loan-lockfree` / `make bench-zc-loan-lockfree`, the
  `bench/report/2026-06-16-wp-zc-loan-lockfree.md` report. **As-built, all proven:** the literal-0-alloc RX
  (acquire 0 B + release 0 B, the e2e loaned RX **measured 0 B/sample**, the progression `65552 → 79 → 31 →
  0`); the **generation release/acquire handshake verified real on arm64** (`fence` → `DMB SY`, the CAS →
  `CASAL`, both disassembled from SBCL's own VOPs — a real store/load barrier + a full-barrier atomic, not a
  no-op) **and byte-exact cross-process** (`make zc-xproc`); the lock-free fenced-read acquire; the
  `cas-sap-u32` refcount-decrement release (0-alloc at ANY generation — the Phase-B bignum-overlay defect was
  found + fixed); the freelist dropped + the writer O(slots) scan (benched honestly — ~106 ns/loan at 2 slots
  → ~1801 ns at 128, the O(slots) sensitivity); the lock-free release-race stress. The lock-free release/
  acquire use the SBCL-only `cas-sap-u32` / `load-sap-u32` PAL primitives, so the ZC pool unit tests that
  exercise them are SBCL-gated (ZC is an NFR-PORT gap on Clasp, ADR 0013); the mutex'd copy-resolve paths
  stay Clasp-portable.
- **Phase-B amendment (0-alloc at ANY generation).** The release was first written as a `cas-sap-u64` over the
  combined `(generation<<32)|refcount` word (the refcount in the low 32, generation in the high 32). Review
  found a **latent NFR-MEM defect**: once a slot's generation reaches ~`2^30`, the combined u64 exceeds
  `most-positive-fixnum` (`2^62-1`), so the `load-sap-u64`/`ldb`/`dpb` overlay **boxed a bignum** — the
  "0-alloc release" silently regressed to ~32 GC-bytes/sample on a long-running writer (measured: 0 B at a
  small generation, **32 B at generation `2^30`/`2^31`** with the overlay; **0 B at every generation** after
  the fix). The fix CASes the **u32 refcount sub-field directly** via the new `cas-sap-u32` PAL primitive
  (`sb-ext:cas` over `sb-sys:sap-ref-32`, disassembled to arm64 `CASAL` — a 32-bit full-barrier atomic, so the
  acquire+release ordering is **identical** to the u64 CAS; only the operand width changes). The combined word
  is never materialised, so all refcount arithmetic stays `(unsigned-byte 32)` ⇒ fixnum ⇒ 0-alloc at any
  generation; the generation @+4 is untouched by construction (a separate u32 read, sound because a held
  slot's generation is stable while `refcount>0`). The memory-ordering handshake is unchanged.
- **Deciders:** A0 (integrator)
- **Amends:** nothing frozen — `%zc-loan` / `%zc-take-free-or-reclaim` / `%zc-release` are internal
  (`dds.xport.zerocopy::`) symbols; no exported interface symbol changed. The exported `%zc-free-count` keeps
  its name + signature; its docstring is updated (it now counts `refcount==0` reclaimable slots, the freelist
  having been dropped — behaviorally identical for every existing assertion: a released slot is reclaimable, a
  held slot is not, a double-release does not change the count).
- **Requires:** WP-FLATDATA-ZC-LOAN complete (ADR 0017, FR-PF-3/4); the WP-SHMEM M1 real PAL `fence`
  (ADR 0013) — `dds.pal:fence :release` / `:acquire` provide real store/load barriers on SBCL.
- **Feature:** FR-PF-3 (Zero-Copy) + FR-PF-4 (FlatData), **NFR-PERF-7** (fixed-size sample
  serialize/deserialize ≈ 0 — the residual ~31 GC-bytes/sample of the loaned RX is the CFFI pool-mutex cons;
  this WP drives it to literal ~0).

## R6 — PATENT GATE (same as WP-FLATDATA-ZC-LOAN, ADR 0017)

WP-ZC-LOAN-LOCKFREE IS the FlatData + Zero-Copy literal-0-copy loan path (the mechanism RTI's patents touch —
REQUIREMENTS §NFR-IP, R6); it only makes the **release/acquire of that already-R6-gated path** lock-free. The
patent posture is unchanged from ADR 0017.

**Owner ruling: build-now / gate-the-ship, engineering-first.**

- **Default OFF, twice.** The whole path stays gated behind `dds.disc:*zerocopy-enabled*` (default `nil`,
  ADR 0014) **and** the per-type `:flatdata t` opt-in (default codegen untouched, ADR 0015). With either off
  the data path is byte-identical to today; the lock-free loan path never engages. The **non-FlatData /
  non-ZC copy path is byte-identical** — this WP changes only the order of the writer's slot stores (the wire
  bytes are unchanged) and the writer's slot-acquisition strategy (freelist → scan).
- Every WP-ZC-LOAN-LOCKFREE symbol/path carries the marker:
  `NOT cleared for ship — pending counsel (R6); see ADR 0018.`
- **Clean-room** from FR-PF-3 / FR-PF-4 + the OMG XCDR layout + the OMG DDS `read()`/`take()` +
  `return_loan()` read-by-reference model + the standard release/acquire publication protocol — **no RTI
  source/headers/`rtiddsgen` output consulted.**
- Engineering-first + provenance: counsel does the authoritative claim clearance before any
  `*zerocopy-enabled*`-on FlatData-loan ship. This ADR records provenance + design-around notes for counsel.

## The safety invariant this rests on

A loaned slot is held at `refcount > 0` (the writer's `%zc-loan` sets `refcount = matched-readers`; a
reader-loan holds its count until `%zc-release`) and **force-reclaim skips `refcount > 0` slots** (already
shipped, ADR 0017). So **while a slot is loaned the writer never reclaims it nor rewrites it** — its
generation, len, and payload are **stable**. A lock-free reader therefore needs no mutual exclusion against
the writer, only cross-process **visibility** of the writer's slot stores, which the **generation field
provides as a release/acquire synchronization variable** (the proven WP-SHMEM M1 ring-cursor pattern). This
is what makes the Phase-B lock-free acquire correct, and it is what the Phase-A reorder is the prerequisite
for.

## Context

WP-FLATDATA-ZC-LOAN (ADR 0017) delivered the literal-0-copy loaned RX: the reader reads fields directly off
the writer's SHMEM slot, 0 intra-host copies. The residual per-sample GC allocation (~31 bytes) is the CFFI
`pthread_mutex_lock`/`unlock` cons taken by the pool **acquire** (`%zc-acquire-for-read`) and **release**
(`%zc-release`) — payload-independent, and the v1 single-copy path pays it too. ADR 0017's *Out of scope*
flagged this explicitly: because a loaned slot's header is stable while held, the acquire could validate the
generation **lock-free** (a fenced read instead of the pool mutex), eliminating the per-sample mutex cons → a
genuinely 0-alloc loaned RX, deferred pending a careful fenced-read design + a bench.

WP-ZC-LOAN-LOCKFREE is that work. The **owner-chosen scope** (brainstorming 2026-06-16) is **acquire +
release both lock-free** — the full 0-alloc RX, which converts the whole pool's release (the copy path's
release too), so the WP-ZEROCOPY copy path's release becomes the same lock-free `cas`-decrement and the writer
scans `refcount==0`. The WP-ZEROCOPY suite + `zc-xproc` are the regression guard. The work is staged: the
**Phase-A reorder + freelist-drop (this ADR's first commit) is the safe mutex'd intermediate**; Phase B makes
the reader path lock-free.

## Design — the generation is the release/acquire sync variable

### Phase A (this commit) — reorder `%zc-loan` + drop the freelist

**1. `%zc-loan` — reorder writes + a release-fence (the correctness crux).** Previously the writer, under its
mutex, stored the **generation first** then copied the payload **last**. For a lock-free reader that order is
inverted — a reader could observe the new generation before the payload it names, a torn read. Reorder so the
**generation is the LAST store**, preceded by a **release-fence**:

```
take/scan a refcount==0 slot (under the writer mutex — the writer keeps the mutex)
  set len, set refcount=readers, stamp pubseq
  copy the payload into the slot           ; payload written FIRST
  (dds.pal:fence :release)                 ; release-fence: publish payload (+ len/refcount/pubseq)
  store generation (bumped) LAST           ; the release-store that publishes everything above
```

The generation store is the single release point. The writer keeps its mutex for mutual exclusion **vs other
writers / force-reclaim**; the fence + generation-last is what synchronizes-with the **lock-free reader** (it
does not share the mutex). On SBCL `dds.pal:fence :release` is a real `sb-thread:barrier (:write)` store
barrier (WP-SHMEM M1, ADR 0013) — confirmed real + kind-honoring, not a no-op.

**2. Drop the freelist.** With the release no longer pushing to the freelist (Phase B's lock-free `cas`-decf
cannot maintain a freelist without a second CAS), the freelist would drain and go stale. Remove it now, in
the safe mutex'd intermediate, so Phase B is a localized change:

- **pool-init** builds no freelist (no `+zc-off-free-head+` init; the slot `len` field no longer overlays a
  freelist 'next').
- **`%zc-take-free-or-reclaim`** becomes **always-scan**: pick the lowest-pubseq `refcount==0` slot (the
  existing reclaim branch, now the only branch). The writer's loan is **O(slots)** (was O(1) freelist-pop) —
  writer-side, amortized; benched at Phase C (FR-LANG-7).
- **`%zc-release`** decrements `refcount` under the mutex (the `(plusp rc)` double-return guard kept) with
  **no freelist push** — the `(= 1 rc)` freelist-push edge is removed. A slot becomes reclaimable simply by
  reaching `refcount == 0`; the writer's next scan finds it.

The writer's `refcount` scan reads a **coherent u32** (a u32 read/write is atomic on the targets); a
concurrent reader decrement races just defers that slot's reclaim by **at most one loan** (the writer sees the
old value, skips, finds another or falls back to non-ZC) — never a torn read or corruption.

### Phase B (delivered) — lock-free acquire + `cas`-decf release

- **`%zc-acquire-for-read`** drops the pool mutex: read the generation (acquire), `(dds.pal:fence :acquire)`,
  validate `generation == expected` (the sync var AND the untrusted-ref check), clamp `len` to slot-bytes,
  return the view — 0 copy, 0 mutex, 0 alloc. The generation acquire-load + acquire-fence synchronizes-with
  the Phase-A writer release-fence + generation-store ⇒ the payload is visible. A stale/forged ref ⇒
  generation mismatch ⇒ NIL.
- **`%zc-release`** drops the mutex: it CASes the **u32 refcount cell @0 directly** via a `cas-sap-u32` retry
  loop, after reading the generation @4 ONCE up front for the stale-ref check (`generation == expected`, else
  NIL with no decrement — the generation is stable while `refcount>0`, so the separate read can't race). The
  loop guard is `refcount > 0` (a `zerop` → return T no-op). `sb-ext:cas` (arm64 `CASAL`) is a full barrier,
  so the reader's payload reads happen-before `refcount → 0`; the writer reclaims only `refcount == 0`, so it
  never overwrites a slot mid-read. Double-return-safe. The earlier `cas-sap-u64` overlay of the combined
  `(gen<<32)|refcount` word was **dropped** — it boxed a bignum at generation ≥ ~`2^30` (see the Phase-B
  amendment above); the direct u32 CAS is 0-alloc at every generation and the generation @4 is untouched.

## Memory-ordering correctness (the binary gate)

- **Publish (writer→reader):** writer writes payload → `fence :release` → generation-store (last); reader
  generation-load → `fence :acquire` → reads payload. The generation is the release/acquire sync variable
  (mirrors the WP-SHMEM ring's cursor handshake). Without the Phase-A reorder a reader could see a new
  generation before the payload — a torn read; the reorder + fences close it. **Phase A establishes the
  writer half; Phase B adds the reader half.**
- **Reclaim-after-release (reader→writer, Phase B):** the reader's payload reads happen-before the
  `cas`-decrement-to-0 (CAS full barrier); the writer reclaims only `refcount == 0`, so it never overwrites a
  slot mid-read.
- **Writer/reader refcount race:** the writer's scan reads a coherent u32 refcount; a racing decrement defers
  reclaim by ≤1 loan, never corrupts.
- `dds.pal:fence` provides real `:release` / `:acquire` barriers on SBCL — confirmed by reading
  `pal-sbcl.lisp` (`:release` → `sb-thread:barrier (:write)`, `:acquire` → `sb-thread:barrier (:read)`, made
  real in WP-SHMEM M1). Not a no-op for the kinds used here; no PAL fix was needed.

## SBCL-only

Zero-Copy is SBCL-only (the SHMEM by-name-attach + foreign-SAP atomics NFR-PORT gap, ADR 0013); the loan path
never runs on Clasp. The lock-free path (Phase B `cas-sap-u32`) is likewise SBCL. The Phase-A reorder +
freelist-drop run under the existing mutex on the existing SBCL-only ZC path; on Clasp the ZC tests pass-skip
(`shm-attach-by-name-reliable-p` / `:sbcl` guards), so the freelist drop is a clean gap there, not a
half-implementation.

## Consumers (of the changed code)

- `src/dds-xport/zerocopy-pool.lisp` — `%zc-init` (no freelist build), `%zc-take-free-or-reclaim`
  (always-scan), `%zc-loan` (payload→fence→generation-last), `%zc-release` (decrement, no freelist push),
  `%zc-free-count` (counts `refcount==0` slots), and the now-unused freelist constants
  (`+zc-off-free-head+`, `+zc-free-end+`) retained with a one-line "unused since the freelist was dropped"
  note (no dangling reads) (Phase A, this ADR)
- `src/dds-tests/echo-test.lisp` — `run-zc-loan-nofreelist-test` (the writer-scan reuse + oldest-first
  reclaim + all-loaned ⇒ NIL, sans the freelist) (Phase A); the lock-free acquire/release race + stress +
  0-alloc bench (Phase B/C); `run-zc-lockfree-release-biggen-test` (Phase-B amendment — asserts the release is
  0-alloc at generation `2^31`, the regression that FAILS at ~32 B against the dropped u64-overlay)
- `src/dds-pal/{pal-contract,pal-sbcl,pal-clasp}.lisp` — the new `cas-sap-u32` PAL primitive (SBCL `sb-ext:cas`
  over `sb-sys:sap-ref-32` = arm64 `CASAL`; Clasp `pal-unimplemented`; exported from `dds.pal`) backing the
  direct-u32-refcount release (Phase-B amendment)

## Provenance

Implemented clean-room from FR-PF-3 / FR-PF-4 + the OMG XCDR fixed-size layout + the OMG DDS `read()`/`take()`
+ `return_loan()` read-by-reference model + the **standard release/acquire publication protocol** (a release
store of a generation/version word after the payload, paired with an acquire load before the consumer reads —
textbook lock-free single-producer publication, the same handshake this project already uses for the WP-SHMEM
ring cursor). The payload→release-fence→generation-last reorder, the always-scan reclaim, the no-freelist
release, and the (Phase B) `cas-sap-u32` refcount decrement are this project's own design derived from first
principles + the OMG loan model + the WP-SHMEM ring pattern; no RTI source, headers, or `rtiddsgen` output
consulted. Provenance logged in `docs/provenance.md`.

**NOT cleared for ship — pending counsel (R6).**

## Consequences

- No exported interface symbol changed; `%zc-free-count` keeps its name + signature (docstring updated).
- No existing behaviour changed when `*zerocopy-enabled*` is nil or a type is not `:flatdata t` (the
  defaults) — byte-identical to today. The wire bytes are unchanged in all cases (the reorder is of the
  writer's local slot stores, not of any transmitted submessage).
- The writer's loan is now O(slots) (a `refcount==0` scan) instead of O(1) (a freelist pop) — a small
  writer-side cost benched honestly at Phase C; the reader RX 0-alloc is the win.
- `docs/verification.csv` FR-PF-3 / FR-PF-4 / NFR-PERF-7 rows are updated at Phase C with the literal-0-alloc
  RX bench + the lock-free release-race stress result.

## Out of scope / follow-ups

- A lock-free freelist (a CAS stack) to restore the writer's O(1) loan while keeping a lock-free release —
  the rejected (most-intricate) option; revisit only if the O(slots) scan benches as a real cost.
- The other queued M5/P4 WPs (reliable-ZC-loan, per-key/keyed-FlatData, sender-error resilience).

**NOT cleared for ship — pending counsel (R6); see the R6 — PATENT GATE section above.**
