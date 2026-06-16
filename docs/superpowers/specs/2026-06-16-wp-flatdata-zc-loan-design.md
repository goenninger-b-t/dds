# WP-FLATDATA-ZC-LOAN — literal-0-copy RX (FlatData over Zero-Copy) — design

**Goal (FR-PF-3/4, NFR-PERF-7).** Complete the deferred FlatData-over-Zero-Copy differentiator: a FlatData
reader on the same host reads fields **directly from the writer's SHMEM pool slot — literal 0 intra-host
copies** — via an explicit **loan / return_loan** read API. This removes the WP-ZEROCOPY+FlatData v1
"safe single copy" (~80 GC-bytes/sample) on the RX path, taking it to literal ~0.

## R6 — PATENT GATE (same posture as WP-ZEROCOPY + WP-FLATDATA)
This IS the FlatData+Zero-Copy literal-0-copy mechanism RTI patents touch (REQUIREMENTS §NFR-IP; R6).
**Build-now / gate-the-ship:** gated behind the existing `dds.disc:*zerocopy-enabled*` (default OFF) **and**
the per-type `:flatdata t` opt-in; every new symbol/path carries the
**`NOT cleared for ship — pending counsel (R6); see ADR 0017`** marker; clean-room from FR-PF-3/4 + the OMG
DDS read()/return_loan() model + the OMG XCDR layout; counsel clears before ship.

## Relationship to WP-FLATDATA + WP-ZEROCOPY
WP-FLATDATA (ADR 0015) gives a FlatData type's sample == its XCDR2 SerializedPayload with compile-time Offset
accessors; WP-ZEROCOPY (ADR 0014) places a large same-host sample in a per-writer SHMEM pool and publishes a
16-byte reference. Their composition was **deferred at FlatData Phase D** because four blockers made a literal
slot-view unsafe: (1) no SAP→Lisp-array primitive so the `aref` accessors couldn't read a raw SHMEM SAP; (2)
the disc receiver thread resolved+copied+**released the slot before** the DCPS user thread read it; (3)
force-reclaim could overwrite a held view; (4) the dataplane is type-opaque. This WP removes all four. The
**wire is unchanged** — the existing 0x4B43 ZC reference encapsulation + SEDP ZC-capable PID are reused;
literal-0-copy is a **local read optimization**, not a new wire format.

## Architecture — defer ZC resolution to DCPS (where the type is known)
Today the disc **receiver thread** resolves a ZC ref, copies the slot into an owned vector, and `%zc-release`s
it — so the slot lifetime cannot span the app read. New flow, for a reader DCPS has marked
**loan-capable** (a FlatData topic + ZC on):
- the disc receiver thread stores the **unresolved** ZC ref (not a copy) in `disc-node-samples`; the slot stays
  loaned via the writer's `refcount = matched-readers` (set at `%zc-loan`);
- DCPS `take-loaned`/`read-loaned` (user thread, where `topic-type-support` ⇒ FlatData is visible) hands the
  app a **slot-view** sample (a `flatdata-view` over the live slot SAP) + records it in a per-reader loan
  registry;
- the app reads fields via the **SAP-mode Offset accessors** directly on the slot — **0 copies**;
- `return-loan` releases each view (`%zc-release` → `refcount`→0 → freelist).
Non-loan-capable / non-FlatData / non-ZC paths are **unchanged** (resolve-copy-release on the receiver thread).

## Components
1. **PAL SAP refs (SBCL) + buffer-sap export** (`src/dds-pal/*`, `src/dds-core/buffer.lisp`). Add to the PAL
   contract `load-sap-u8/u16/u32` (the FlatData fixed-size scalar widths; i8/i16/i32/i64/bool compose from the
   unsigned reads + the existing `load-sap-u64`, exactly as the aref accessors compose two's-complement/bool).
   SBCL = `sb-sys:sap-ref-{8,16,32}`; Clasp = NFR-PORT gap (signals `pal-unimplemented`, like `cas-sap-u64`) —
   ZC is already SBCL-only (ADR 0013), so the loan path never runs on Clasp. Export `dds.core.buffer:buffer-sap`
   (already defined: `static-pointer(octet-buffer-vec)`).
2. **SAP-mode FlatData accessors + `flatdata-view`** (`src/dds-gen/dsl.lisp`, `src/dds-types/type-support.lisp`).
   For a `:flatdata t` type, additionally emit accessors that read a field at a `(sap, base)` via the PAL SAP
   refs — **byte-exact to the existing aref read** (same XCDR2-LE composition; the byte-exact oracle is the
   existing FlatData buffer). The loaned sample is a tiny `flatdata-view` struct `{slot-sap, base-offset (=4),
   len, slot-handle (sap+slot-index+generation for return)}`. **Accessor surface (one decision, pinned):** the
   generated `<name>-<field>-fd` is re-emitted to take EITHER an owned `octet-buffer` OR a `flatdata-view`, via
   a single struct-type branch at the top (`(if (flatdata-view-p x) <SAP path> <aref path>)`) — so app code is
   identical for loaned vs owned FlatData samples (one surface). The owned-buffer branch keeps the **exact
   shipped aref logic** (byte-preserved), so the existing FlatData byte-exact + 0-alloc tests must still pass
   unchanged (the regression guard); the view branch is the SAP read (byte-exact by construction + new tests).
   The branch is a predicted struct-type test — 0-alloc, no generic dispatch. (Alt considered: separate
   `-fd-view` accessors leaving the shipped accessor literally untouched — rejected for app ergonomics; the
   single-branch dispatch is the chosen trade-off, with the shipped owned path re-verified byte-identical.)
3. **ZC pool reader-loan** (`src/dds-xport/zerocopy-pool.lisp`). `%zc-acquire-for-read(sap, slot, gen)` →
   validate generation + bounds + `len ≥ +size+`, return a view handle **without copying** (the writer already
   set `refcount = readers`). **force-reclaim MUST skip `refcount>0` slots** (`%zc-take-free-or-reclaim` only
   reclaims `refcount==0` — the key safety change: a loaned slot can never be overwritten under the app's read).
   Pool-full (no free + none reclaimable because all are loaned) ⇒ `%zc-loan` returns NIL ⇒ the writer **falls
   back to non-ZC** (copy) for that sample (lost-tolerant, never blocks). `%zc-release` (exists) is the loan
   return; make it **idempotent / double-return-safe** (a second release of an already-freed/regenerated slot
   is a validated no-op).
4. **DCPS loan API** (`src/dds-dcps/entities.lisp`). `take-loaned(dr)` / `read-loaned(dr)` → drain pending
   samples; for a FlatData-ZC ref, produce a `flatdata-view` loan (via `%zc-acquire-for-read`) and record it in
   a per-reader **loan registry**; return the loaned views (+ SampleInfo). `return-loan(dr, loans)` → release
   each recorded view (`%zc-release`), clearing the registry entries; a no-op for any copy-backed sample mixed
   in (uniform API). Closing the reader / `stop-node` returns all outstanding loans (no leaked refcounts).
5. **Loan-capable wiring** (`src/dds-dcps/entities.lisp` → `src/dds-disc/*`). When DCPS creates a reader on a
   `:flatdata t` topic with ZC enabled, it sets a **boolean `zc-loan-capable`** on the disc-node/reader. The
   disc (otherwise type-opaque) checks only this boolean: a ZC ref to a loan-capable reader ⇒ store the
   unresolved ref + DO NOT release; else ⇒ today's resolve-copy-release. Keeps the shipped non-FlatData ZC path
   byte-unchanged.

## Decisions baked in (from brainstorming 2026-06-16 — confirm at spec review)
1. **Explicit loan + return_loan** read-by-reference API (owner-chosen) — mirrors OMG DDS `take()`/`return_loan()`.
2. **Best-effort first** (matches WP-ZEROCOPY v1); reliable-ZC-loan is a follow-up.
3. **Targeting via the per-reader `zc-loan-capable` flag** (not deferring all ZC resolution) — non-FlatData ZC
   stays byte-unchanged.
4. **Graceful loan-leak degradation:** an app that never returns a loan pins a slot → eventually pool-full →
   non-ZC fallback (no crash, no wedge); a max-loan-age / leak-warning is a follow-up.
5. **SAP accessors additive + SBCL-only** (ZC is SBCL-only); single-branch dispatch in `<name>-<field>-fd` so
   the app uses one accessor surface.
6. **R6-gated** (default-off via `*zerocopy-enabled*` + `:flatdata t`; NOT-cleared-for-ship marker).

## Memory / hot-path (NFR-MEM, NFR-CLOS)
The SAP-mode accessors are raw `sap-ref` + arithmetic — **0-alloc, CLOS-free** (the dispatch is a single
`typep`/struct-type branch, not generic dispatch). The `flatdata-view` is a small fixed struct drawn from a
per-reader pool/freelist (no per-sample GC-heap alloc — the loan registry reuses view structs). The literal-0
RX is the headline: no owned delivery vector. gate-hotpath covers the accessor + the loan path.

## Safety (binary gate; cross-process untrusted SHMEM)
- **Reclaim protection:** a loaned slot has `refcount>0` and force-reclaim skips it ⇒ no overwrite under the
  app's read. The generation guard detects a stale ref at acquire (a slot reclaimed before acquire ⇒ the loan
  fails ⇒ the sample is dropped, best-effort).
- **Bounds:** `%zc-acquire-for-read` validates `len ≥ +<name>-flatdata-size+` and the slot extent before
  exposing; the SAP-accessors read at compile-time-constant offsets within `+size+`; never an OOB read into/
  past the slot, even at `(safety 0)` (manual guards). Fuzz the untrusted wrap.
- **Trust model (documented, R6/ADR):** the writer does not mutate a slot once loaned (it moves to a new slot);
  the pool-header geometry is trusted (pre-existing WP-ZEROCOPY assumption). A malicious co-located writer is
  out of scope for the best-effort v1 (whole feature `*zerocopy-enabled*`-OFF + R6 not-cleared-for-ship).
- **`return-loan` idempotent / double-return-safe** (generation-validated `%zc-release`); reader-close returns
  all outstanding loans (no refcount leak that would wedge the writer's pool).
- **Lifetime across threads:** the slot is held (refcount) from the writer's `%zc-loan` through the disc
  receiver-thread store, the DCPS user-thread `take-loaned`, the app's reads, until `return-loan` — no UAF
  (the receiver thread no longer releases for loan-capable readers; the slot survives the handoff).

## OMG DDS / RTPS spec-compliance
The **wire is unchanged** (the 0x4B43 ZC reference + SEDP ZC-capable PID are reused; off ⇒ byte-identical) —
this is a **local read-path optimization**, additive on conforming behavior. The loan/return_loan API mirrors
the OMG DDS DCPS **read()/take() + return_loan()** read-by-reference contract (DDS 1.4 §2.2.2.5 — the standard
zero-copy read model; a borrowed sample sequence the app returns). The FlatData byte layout IS XCDR2, so a
conforming peer interoperates over the normal (copied) path; the literal-0-copy transport is ours/SHMEM
(WP-ZEROCOPY). No invented wire constant.

## Testing / acceptance (oracle = the bytes + the 0-copy measurement; FR-LANG-7)
- **Byte-exact loaned read:** a FlatData writer publishes over ZC; the reader `take-loaned`s; the loaned
  `flatdata-view`'s SAP-accessor field reads EQUAL the published values (the writer's FlatData buffer is the
  oracle) — for unsigned/signed/bool/all widths.
- **Literal 0-copy (the headline, NFR-PERF-7):** the RX per-sample bytes-consed drops to **~0** (no owned
  delivery vector) vs the WP-ZEROCOPY+FlatData v1 single-copy (~80). Bench it honestly.
- **Real 2-process:** a `make zc-xproc`-style cross-process FlatData exchange — the subscriber reads fields
  from the publisher's slot, 0-copy, correct values.
- **Reclaim protection:** a loaned slot is NOT force-reclaimed while held (fill the pool while holding a loan →
  the writer falls back to non-ZC, the held view stays valid + correct); pool-full ⇒ non-ZC fallback (no
  block, no crash).
- **return_loan:** release → the slot is reusable (the writer loans it again); double-return is a safe no-op;
  a leaked loan degrades to non-ZC fallback (no wedge); reader-close returns outstanding loans.
- **Untrusted-wrap fuzz:** forged ref (bad slot/generation/len) ⇒ the loan fails / clamps, never OOB.
- **Off / non-FlatData byte-identical:** `*zerocopy-enabled*` off, or a non-FlatData ZC type, ⇒ the existing
  WP-ZEROCOPY path + wire are byte-unchanged (the full ZC/interop suite green).
- **Concurrency:** the slot lifetime spanning receiver-thread → user-thread → app `return-loan`, with a
  concurrent writer loaning/force-reclaiming — no UAF / no torn read / no refcount leak (SBCL stress).
- Gates green SBCL (ZC is SBCL-only; Clasp skips the loan path, full suite otherwise green); behind the
  per-type opt-in + `*zerocopy-enabled*`; R6 marker throughout.

## Out of scope (v1 — follow-ups)
- **Reliable-ZC-loan** (the slot held until ACKed AND not loaned) — best-effort first.
- **The app-facing ZC loan-WRITE API** (app writes directly into a pool slot, removing the remaining TX
  app→slot copy) — the write-side dual of this WP; separate follow-up.
- **Loan-leak detection / max-loan-age / a hard loan cap** — v1 degrades gracefully to non-ZC; active leak
  management is later.
- **Clasp ZC** (NFR-PORT gap — UDP, no ZC, no loan).
- **Variable-size / Builder FlatData over ZC** (FlatData v1 is FINAL fixed-size; that restriction stands).
