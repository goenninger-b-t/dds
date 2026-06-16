# ADR 0017 — WP-FLATDATA-ZC-LOAN: literal-0-copy RX (FlatData over Zero-Copy) via an explicit loan / return_loan read API

- **Status:** Accepted — **Phases A–F delivered** (PAL SAP reads, SAP-mode FlatData accessors + `flatdata-view`,
  ZC pool reader-loan + force-reclaim `refcount>0` skip + idempotent `%zc-release`, the DCPS
  `take-loaned`/`read-loaned`/`return-loan` loan API + per-reader registry + freelist, the loan-capable wiring +
  the disc receiver-thread store-unresolved/do-not-release branch, and **Phase F** the literal-0-copy RX
  headline bench + a concurrency lifetime stress test + the untrusted loan-acquire fuzz + docs finalization). The
  literal-0-copy round-trip is proven byte-exact by the `dcps-loan-roundtrip` + `loan-read-return-take` +
  `flatdata-zc-loan-e2e` tests; the concurrency-lifetime safety property (no UAF / no torn read / no refcount
  leak under a concurrent writer churning the pool while a loan is held) by `flatdata-zc-loan-stress`; the
  untrusted loan-acquire bounds by the `flatdata-zc-loan-acquire` fuzz (`make fuzz`). **The literal-0-copy RX
  headline (the `bytes-consed` measurement, `make bench-flatdata-zc-loan` →
  `bench/report/2026-06-16-wp-flatdata-zc-loan.md`): the per-sample RX allocation drops to the bare pool-mutex
  acquire (~32 GC bytes/sample, payload-independent — the SAME cost the v1 single-copy pays) with NO owned
  delivery vector, vs the FlatData+ZC v1 single-copy ~79 (the mutex + the ~47-octet owned vector) and the
  WP-ZEROCOPY-v1 sink+re-copy ~65551 — the progression `65551 → 79 → 32`.** HONEST (FR-LANG-7): the eliminated
  per-sample owned vector is the win; the loan API ADDS the explicit `%zc-acquire-for-read` + `%zc-release` calls
  + the app's `return-loan` obligation (a real cost, not a free lunch). NOT cleared for ship — pending counsel
  (R6).
- **Deciders:** A0 (integrator)
- **Amends:** nothing frozen — purely additive; no existing interface symbol changed
- **Requires:** WP-ZEROCOPY complete (ADR 0014, FR-PF-3); WP-FLATDATA complete (ADR 0015, FR-PF-4);
  PAL foreign-SAP read primitives (this ADR, Phase A)
- **Feature:** FR-PF-3 (Zero-Copy) + FR-PF-4 (FlatData), NFR-PERF-7 (fixed-size sample serialize/deserialize ≈ 0)

## R6 — PATENT GATE (defining constraint)

WP-FLATDATA-ZC-LOAN IS the **FlatData + Zero-Copy literal-0-copy mechanism** RTI's patents touch
(REQUIREMENTS §NFR-IP, R6) — the composition of the two already-R6-gated differentiators (ADR 0014,
ADR 0015) into a read-in-place slot view with no RX copy at all.

**Owner ruling: build-now / gate-the-ship, engineering-first.**

- **Default OFF, twice.** The whole path is gated behind the existing `dds.disc:*zerocopy-enabled*`
  (default `nil`, ADR 0014) **and** the per-type `:flatdata t` opt-in (default codegen untouched,
  ADR 0015). With either off the data path is byte-identical to today; literal-0-copy never engages.
- Every WP-FLATDATA-ZC-LOAN symbol/path carries the marker:
  `NOT cleared for ship — pending counsel (R6); see ADR 0017.` (Each new file carries it as a header.)
- **Clean-room** from FR-PF-3 / FR-PF-4 + the OMG XCDR layout + the OMG DDS `read()`/`take()` +
  `return_loan()` read-by-reference model only — **no RTI source/headers/`rtiddsgen` output consulted.**
- Engineering-first + provenance: counsel does the authoritative claim clearance before any
  `*zerocopy-enabled*`-on FlatData-loan ship. This ADR records provenance + design-around notes for counsel.

## Context

WP-ZEROCOPY (ADR 0014) places a large same-host sample in a per-writer SHMEM pool slot and transmits a
16-byte reference; the reader resolves the reference and copies the slot into an owned vector.
WP-FLATDATA (ADR 0015) makes a FINAL fixed-size type's sample **equal** its XCDR2 SerializedPayload, with
compile-time Offset accessors. Their **Phase-D composition** — the reader reading fields **directly from the
writer's slot, literal 0 intra-host copies** — was **deferred** (ADR 0015 *Phase D outcome*) because four
individually-fatal blockers made a literal slot view a cross-process use-after-free in a best-effort v1:

1. **No SAP→field read primitive.** The FlatData accessors read a Lisp `(simple-array (unsigned-byte 8))`,
   not a raw SHMEM SAP — there was no PAL primitive to read a fixed-width scalar at an offset off a SAP.
2. **The disc receiver thread resolved + copied + released the slot before the app read it** — the slot
   lifetime could not span the later DCPS user-thread read.
3. **Force-reclaim could overwrite a held view** — `%zc-take-free-or-reclaim` evicts the oldest slot under
   pool pressure (the generation guard *detects* but does not *prevent* the overwrite of a held view).
4. **The dataplane is type-opaque** — `dds.disc` never sees the FlatData type-support, so it cannot decide
   to defer the copy.

WP-FLATDATA-ZC-LOAN removes all four and delivers the literal-0-copy RX. The **wire is unchanged**: the
existing `+zc-encapsulation-id+` (0x4B43) reference encapsulation + the SEDP ZC-capable PID are reused;
literal-0-copy is a **local read-path optimization**, not a new wire format (a conforming peer interoperates
over the normal copied path).

## Design

**Defer ZC resolution to DCPS (where the type is known).** For a reader DCPS has marked **loan-capable**
(a `:flatdata t` topic with `*zerocopy-enabled*` on at reader creation):

- The disc **receiver thread** stores the **unresolved** ZC reference (not a copy) for a loan-capable
  reader and **does not release** the slot; the slot stays loaned via the writer's `refcount = matched
  readers` (set at `%zc-loan`). Non-loan-capable / non-FlatData / non-ZC paths are **unchanged**
  (today's resolve-copy-release on the receiver thread). The disc stays type-opaque — it checks only a
  per-reader boolean `zc-loan-capable`.
- DCPS `take-loaned` / `read-loaned` (user thread, where `topic-type-support` ⇒ FlatData is visible) hands
  the app a **`flatdata-view`** sample — a tiny fixed struct `{slot-sap, base-offset (=4), len,
  slot-handle (sap + slot-index + generation, for return)}` over the live slot — and records it in a
  per-reader **loan registry**. The view struct is drawn from a per-reader freelist (no per-sample GC alloc).
- The app reads fields via the **SAP-mode Offset accessors** directly on the slot — **0 copies.** The
  generated `<name>-<field>-fd` is re-emitted to take EITHER an owned `octet-buffer` OR a `flatdata-view`,
  via a single struct-type branch at the top (a predicted `typep`/struct-type test — 0-alloc, no generic
  dispatch); the owned-buffer branch keeps the **exact shipped aref logic** (byte-preserved, the existing
  FlatData byte-exact + 0-alloc tests remain the regression guard). One accessor surface for loaned vs owned.
- `return-loan(dr, loans)` releases each recorded view (`%zc-release` → `refcount` → 0 → freelist),
  clearing the registry entries; a no-op for any copy-backed sample mixed in (uniform API). Closing the
  reader / `stop-node` returns all outstanding loans (no leaked refcounts).

**Safety (binary gate; cross-process untrusted SHMEM).**

- **Reclaim protection (the key safety change):** a loaned slot has `refcount > 0`, and **force-reclaim
  skips `refcount > 0` slots** (`%zc-take-free-or-reclaim` only reclaims `refcount == 0`) — a loaned slot
  can never be overwritten under the app's read. Pool-full (no free + none reclaimable because all are
  loaned) ⇒ `%zc-loan` returns NIL ⇒ the writer **falls back to non-ZC** (copy) for that sample
  (lost-tolerant, never blocks).
- **Bounds + generation:** `%zc-acquire-for-read(sap, slot, gen)` validates the generation, the slot index
  against K, and `len ≥ +<name>-flatdata-size+` before exposing the view; the SAP-mode accessors read at
  compile-time-constant offsets within `+size+` — never an OOB read into/past the slot, even at `(safety 0)`.
  A stale ref (slot reclaimed before acquire) ⇒ the loan fails ⇒ the sample is dropped (best-effort). The
  untrusted wrap is fuzzed.
- **`return-loan` idempotent / double-return-safe** (generation-validated `%zc-release`); reader-close
  returns all outstanding loans.
- **Trust model (documented):** the writer does not mutate a slot once loaned (it moves to a new slot); the
  pool-header geometry is trusted (the pre-existing WP-ZEROCOPY assumption, ADR 0014 / ADR 0015 *Safety*). A
  malicious co-located writer is out of scope for the best-effort v1 (the whole feature is
  `*zerocopy-enabled*`-OFF + R6 not-cleared-for-ship; header-geometry hardening is part of the security pass
  before any ZC-on ship).

The loan API mirrors the OMG DDS DCPS **read() / take() + return_loan()** read-by-reference contract
(DDS 1.4 §2.2.2.5 — the standard zero-copy read model: a borrowed sample sequence the app returns).

**SBCL-only.** Zero-Copy is SBCL-only (the SHMEM by-name-attach + foreign-SAP atomics NFR-PORT gap, ADR
0013); the loan path therefore never runs on Clasp. The PAL SAP read primitives signal `pal-unimplemented`
on Clasp (a documented NFR-PORT gap, like `cas-sap-u64`), so the loan path is a clean gap there, not a
half-implementation.

## Phases

- **A — PAL SAP reads + `buffer-sap` export (this Phase, Task A1).** Add `load-sap-u8/u16/u32` to the PAL
  contract (the FlatData fixed-size scalar widths; i8/i16/i32/i64/bool compose from these + the existing
  `load-sap-u64`, exactly as the aref accessors compose two's-complement/bool). SBCL =
  `sb-sys:sap-ref-{8,16,32}`; Clasp = `pal-unimplemented` (NFR-PORT gap). Export
  `dds.core.buffer:buffer-sap` (already defined: `static-pointer(octet-buffer-vec)`). A byte-exact
  little-endian SAP-read unit test (`run-sap-ref-test`), SBCL-pass / Clasp-skip.
- **B — SAP-mode FlatData accessors + `flatdata-view`** (`src/dds-gen/dsl.lisp`,
  `src/dds-types/type-support.lisp`): the single-branch `<name>-<field>-fd` over a `flatdata-view`,
  byte-exact to the existing aref read.
- **C — ZC pool reader-loan** (`src/dds-xport/zerocopy-pool.lisp`): `%zc-acquire-for-read`, the
  force-reclaim `refcount > 0` skip, idempotent `%zc-release`.
- **D — DCPS loan API** (`src/dds-dcps/entities.lisp`): `take-loaned` / `read-loaned` / `return-loan` + the
  per-reader loan registry.
- **E — loan-capable wiring** (`src/dds-dcps/entities.lisp` → `src/dds-disc/*`): the per-reader
  `zc-loan-capable` flag + the disc receiver-thread store-unresolved/do-not-release branch.
- **F — bench (literal-0-copy proof) + lifetime stress + loan-acquire fuzz + docs; finalize this ADR (DONE).**
  `run-flatdata-zc-loan-e2e-test` (the full DCPS `take-loaned`/read/`return-loan` loop + the literal-0-copy RX
  headline `~32 → ~79 → ~65551` bytes-consed progression), `run-flatdata-zc-loan-stress-test` (the concurrency
  lifetime safety property under REAL threads — a held loan stays byte-correct while a writer churns
  loan/force-reclaim, pool-full ⇒ non-ZC fallback, no refcount leak after return, a leaked loan degrades to
  fallback + reader-close still returns it), `fuzz-flatdata-zc-loan-wrap` (the untrusted loan-acquire path —
  forged slot/generation/recorded-len ⇒ NIL or a slot-clamped view, never an OOB SAP read even at `(safety 0)`),
  `run-bench-flatdata-zc-loan` (`make bench-flatdata-zc-loan` → `bench/report/2026-06-16-wp-flatdata-zc-loan.md`,
  the HONEST headline + the loan/return per-sample overhead). Cross-process FlatData-over-ZC stays covered by
  `make zc-xproc` (the 16-byte reference resolves across two OS processes; literal-0-copy is a LOCAL read
  optimization — the wire is byte-identical, so no separate loan-variant cross-process harness is needed).

## Consumers (of the new symbols)

- `src/dds-pal/pal-contract.lisp` — `load-sap-u8` / `load-sap-u16` / `load-sap-u32` (contract + exports);
  `src/dds-pal/pal-sbcl.lisp` — the `sb-sys:sap-ref-*` impls; `src/dds-pal/pal-clasp.lisp` — the
  `pal-unimplemented` NFR-PORT stubs (Phase A, this ADR)
- `src/dds-core/buffer.lisp` / `src/dds-core/packages.lisp` — `dds.core.buffer:buffer-sap` export
  (already defined; exported here) (Phase A)
- `src/dds-gen/dsl.lisp`, `src/dds-types/type-support.lisp` — the SAP-mode FlatData Offset accessors over a
  `flatdata-view` (consume the PAL SAP reads + `buffer-sap`) (Phase B)
- `src/dds-xport/zerocopy-pool.lisp` — `%zc-acquire-for-read` / the force-reclaim `refcount > 0` skip /
  idempotent `%zc-release` (Phase C)
- `src/dds-dcps/entities.lisp` — the DCPS `take-loaned` / `read-loaned` / `return-loan` loan API + the
  per-reader loan registry + the `zc-loan-capable` flag (Phase D / E)
- `src/dds-disc/*` — the receiver-thread store-unresolved / do-not-release branch for a loan-capable reader
  (Phase E)
- `src/dds-tests/echo-test.lisp` — `run-sap-ref-test` (Phase A); the byte-exact loaned-read + literal-0-copy
  + reclaim-protection + return_loan tests (Phases B–E); `run-bench-flatdata-zc-loan` + the `%fd-zc-loan-rx-bytes`
  / `%fd-zc-loan-cycle-bytes` / `%bench-ratio` helpers (Phase F)
- `src/dds-tests/integration-test.lisp` — `run-flatdata-zc-loan-e2e-test` (the literal-0-copy headline) +
  `run-flatdata-zc-loan-stress-test` (the concurrency lifetime safety property) (Phase F)
- `src/dds-tests/pbt-test.lisp` — `fuzz-flatdata-zc-loan-wrap` (the untrusted loan-acquire fuzz, in `make fuzz`)
  (Phase F)

## Provenance

Implemented clean-room from FR-PF-3 / FR-PF-4 + the OMG XCDR 1.3 fixed-size layout rules + the OMG DDS 1.4
`read()`/`take()` + `return_loan()` read-by-reference model; no RTI source, headers, or `rtiddsgen` output
consulted. The PAL foreign-SAP fixed-width reads are this project's own thin wrappers over the host Lisp's
documented SAP-ref primitives; the loan/return-by-reference flow, the per-reader `zc-loan-capable` targeting,
the refcount-spanning slot lifetime, and the force-reclaim `refcount > 0` skip are this project's own design
derived from first principles + the OMG loan model. Provenance logged in `docs/provenance.md`.

**NOT cleared for ship — pending counsel (R6).**

## Consequences

- Three new exported PAL symbols (`load-sap-u8/u16/u32`) + one newly-exported buffer symbol
  (`dds.core.buffer:buffer-sap`); all additive, SBCL-backed / Clasp-NFR-PORT-gapped.
- No existing interface symbol changed; no existing behaviour changed when `*zerocopy-enabled*` is nil or a
  type is not `:flatdata t` (the defaults) — byte-identical to today.
- `docs/verification.csv` FR-PF-3 / FR-PF-4 literal-0-copy row: the Phase-F literal-0-copy bench (RX allocation
  = the bare mutex acquire, NO owned vector — `bytes-consed` progression `65551 → 79 → 32`) + the 2-process
  FlatData-over-ZC exchange (`make zc-xproc`) both pass; the row records the as-built.
- No migration burden: purely additive.

## Reliable-ZC-loan — delivered (scope A), verified + hardened (WP-RELIABLE-ZC, 2026-06-16)

The "Reliable-ZC-loan" follow-up below has been **delivered as scope A** (verify + harden + test); it is no
longer a follow-up. The as-built model (grounded in code, then proven by five SBCL reliability tests +
one latent-bug fix — `make test`, 211 green both impls):

- **Reliable ZC delivery rides the existing reliable path; there is no separate reliability gate** — a ZC
  sample on a RELIABLE writer has a SequenceNumber, is NACKable and retransmittable like any DATA. The writer
  **HistoryCache stores the FULL payload** for every change (ZC or not); the 16-byte ZC reference is
  **regenerated per-send** (`%zc-change-item` → `%zc-loan`) for the initial push.
- **A NACK retransmits the SN.** As-built, the ACKNACK retransmit path **copy-falls-back**: it re-emits the
  full retained HistoryCache payload (byte-exact, no loss), it does **not** re-loan a ZC reference
  (`%on-user-acknack` omits the `zc-readers` argument that the initial-push path passes, so the resend takes
  the normal full-payload DATA branch). A loan-capable reader delivers that retransmit **as an owned copy**
  (a non-`flatdata-view` sample, `NIL` loan), not a view. Reliability (ultimate byte-exact delivery) holds;
  the ZC win is simply not re-applied on the repair leg. (Verified by `run-reliable-zc-retransmit-test`.)
- **The reader ACK/NACKs a ZC ref as a normal DATA** — `reader-on-data` marks the SN received, `reader-acknack`
  ACKs/NACKs identically. A loan-capable reader stores the unresolved `zc-loan-marker` but its ACK bookkeeping
  is unchanged. The reader ACKs on **receive** (reliable completion); the app holds the loan until
  `return-loan` (read lifetime).
- **The loan composes with reliability via the refcount.** The writer purges the HistoryCache change on
  full-ACK (RTPS 2.5 §8.4.1), freeing the HC copy — but the loaned **slot** stays held by the reader's
  refcount (force-reclaim skips `refcount > 0`), so a loaned slot **outlives the HC purge** until
  `return-loan`. No use-after-free. (Verified by `run-reliable-zc-slot-outlives-purge-test`.)
- **The ZC win is reader-RX (0-copy / 0-alloc) + wire (16-byte ref).** The **writer keeps the HistoryCache
  full-payload copy** (needed for retransmit and for any non-ZC / remote reader) — this **writer-side
  double-storage** (the slot copy plus the HC copy) is the **v1 cost**, recorded honestly (FR-LANG-7). The
  writer-side is **not** zero-copy under reliability.
- A saturated pool ⇒ `%zc-loan` NIL ⇒ the writer sends the full payload ⇒ the loan-capable reader delivers it
  as a copy, never a silent drop (`run-reliable-zc-poolfull-fallback-test`); a single `take-loaned` returns a
  ZC view and a fallback copy interleaved, both byte-exact (`run-reliable-zc-mixed-test`); a RELIABLE and a
  BEST_EFFORT ZC writer each deliver a loan view identically (`run-reliable-zc-qos-test`).
- **Latent bug found + fixed (beyond reliable-ZC, a real correctness fix):** `make-reader-qos` /
  `make-writer-qos` prepended their reliability **default** ahead of the caller's `&rest` args, so a duplicate
  `:reliability` resolved to the default (HyperSpec 3.4.1.4 — the leftmost keyword wins). A
  RELIABLE-requesting reader silently advertised BEST_EFFORT, was excluded from the writer's
  `%matched-reader-keys` purge set, and the writer never purged its HistoryCache on full-ACK for it →
  **unbounded HC growth** (NFR-MEM). Fixed (the caller's keyword now wins — append the default *after* args);
  commit `0a03bf5`. Surfaced by the slot-outlives-purge scenario.

The **scope-B follow-ups** (deferred) are listed below.

## Out of scope / follow-ups

- **Re-loan-on-retransmit (scope B).** Make the ACKNACK repair leg re-send a ZC reference instead of the full
  HistoryCache copy. This needs per-peer `%zc-readers` resolution on the retransmit path so the slot refcount
  stays exactly 1 per resolving destination — otherwise a resend that fans to multiple peers would
  double-count (and later double-free) the loan. (The initial-push path already resolves `zc-readers`;
  `%on-user-acknack` does not.)
- **True writer-side reliable ZC (scope B).** When all matched readers are same-host ZC-capable, the
  HistoryCache change **references the slot** (no full-payload copy), the slot retained until ACK
  (writer-hold released on purge) and not reclaimed while loaned, and the retransmit re-sends the ref to the
  retained slot. Eliminates the v1 writer-side double-storage; conditional (any non-ZC / remote reader forces
  the copy) + a bigger HC↔pool change. Deferred.
- **The app-facing ZC loan-WRITE API** (app writes directly into a pool slot, removing the remaining TX
  app→slot copy) — the write-side dual of this WP; separate follow-up.
- **Loan-leak detection / max-loan-age / a hard loan cap** — v1 degrades gracefully to non-ZC; active leak
  management is later.
- **Variable-size / Builder FlatData over ZC** (FlatData v1 is FINAL fixed-size; that restriction stands);
  keyed FlatData (v1 is NO_KEY only).
- **Clasp ZC** (NFR-PORT gap — UDP, no ZC, no loan).
- **Lock-free / 0-alloc loan acquire.** The loaned RX path's residual ~31 GC-bytes/sample is the CFFI
  pool-mutex (`pthread_mutex_lock`) cost — payload-independent, and the v1 single-copy pays it too. Because a
  loaned slot is held at `refcount > 0` and force-reclaim skips it, the slot header is stable while the loan is
  held, so `%zc-acquire-for-read` could validate the generation **lock-free** (a fenced read instead of taking
  the pool mutex), eliminating the per-sample mutex-cons → a genuinely 0-alloc loaned RX. Deferred: needs a
  careful fenced-read design + a bench.
- **Multi-loan-capable-reader-per-participant constraint (documented invariant).** The slot refcount is 1 per
  destination participant and the `zc-loan-marker` is stored once per source-GUID→SN on the `disc-node` (which
  holds a single `user-reader`). The v1 loan model therefore assumes **one loan-capable reader per `disc-node`**;
  two loan-capable readers sharing one node would let the first `return-loan` (`refcount` 1→0) free a slot the
  second still views (a cross-reader use-after-free). Unreachable as-built (one reader per node), but it MUST be
  a documented precondition for the reliable / multi-reader follow-up, which would need refcount-per-reader or
  per-reader loan markers.

**NOT cleared for ship — pending counsel (R6); see the R6 — PATENT GATE section above.**
