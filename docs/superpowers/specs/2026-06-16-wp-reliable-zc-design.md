# WP-RELIABLE-ZC — verify + harden + test reliable Zero-Copy loan delivery — design

**Goal (FR-PF-3/4, FR-RTPS reliability).** Prove the FlatData-over-Zero-Copy literal-0-copy **loan** path is
correctly delivered under **RELIABLE** reliability (retransmit on loss, no silent data loss), fix the real
gaps the proof reveals, and document the model. This is **scope A** (verify+harden+test); the
true-writer-side-ZC (eliminating the HC's full-payload copy when all readers are same-host ZC) is the
deferred **scope B** follow-up.

## R6
The ZC loan path is R6 patent-gated; gated behind `dds.disc:*zerocopy-enabled*` (default OFF) + `:flatdata t`;
new tests/docs carry `NOT cleared for ship — pending counsel (R6); see ADR 0017/0018`. SBCL-only (ZC is an
NFR-PORT gap on Clasp). Clean-room.

## The reliability model (as-grounded — this WP confirms + hardens it, doesn't redesign it)
Verified by code inspection (the grounding report): reliable ZC delivery already rides the existing reliable
path. The model:
- **The writer HistoryCache stores the FULL payload** for every change (`reliable.lisp` `writer-write`), ZC or
  not. The 16-byte ZC reference is **regenerated per-send** (`%zc-change-item`→`%zc-ref-builder`→`%zc-loan`) —
  for the initial push AND each retransmit.
- **A NACK retransmits the SN** (`writer-on-acknack`→`%send-changes-packed`→`%changes-datagram-plan`): the
  retransmit re-runs the ZC decision and **re-loans a fresh slot from the still-retained full payload**; if the
  pool is saturated, `%zc-loan` returns NIL and the writer **falls back to sending the full payload** — still
  reliably delivered, just copied (not ZC) for that send.
- **The reader treats a ZC ref as a normal DATA**: `reader-on-data` marks the SN received; `reader-acknack`
  ACKs / NACKs a gap identically. A **loan-capable** reader stores the unresolved `zc-loan-marker` but still
  marks the SN received (ACK bookkeeping is identical).
- **The loan composes with reliability via the refcount**: the reader ACKs on *receive* (reliable completion);
  the app holds the loan until `return-loan` (read lifetime). The writer purges the HC change on full-ACK
  (frees the HC copy), but the SLOT stays held by the reader's refcount (force-reclaim skips refcount>0) until
  `return-loan` — so a loaned slot **outlives the HC purge**, which is correct.
- **The ZC win is reader-RX (0-copy/0-alloc) + wire (16-byte ref)**; the writer keeps the HC full-payload copy
  (needed for retransmit and for any non-ZC/remote reader). The writer-side double-storage is the v1 cost
  (scope B removes it conditionally).
- **No reliability gate is needed**: ZC already rides the writer's reliability QoS (a ZC sample on a RELIABLE
  writer has an SN, is NACKable, retransmittable). This WP confirms + documents that.

## What this WP delivers
A reliability test suite that exercises the above end-to-end on SBCL, plus fixes for any gap it reveals, plus
docs. The suite IS the deliverable (proving reliability is the goal); the harden is whatever the tests expose.

## Test scenarios (the acceptance — each: write, run, fix-the-gap-if-it-fails, pass)
1. **Reliable retransmit of a ZC loan sample.** A RELIABLE writer + a same-host loan-capable ZC reader; drop
   the first ZC ref-DATA (`*debug-drop-sample-numbers*`); on the next HEARTBEAT the reader NACKs; the writer
   retransmits → re-loans a fresh slot from the retained full payload → sends a new ref; the reader resolves
   the re-loaned ref and `take-loaned` reads the field values **byte-exact** (reliable, no loss). Assert the
   reader ultimately receives the sample.
2. **Pool-full → copy-fallback delivered correctly to a loan-capable reader.** Saturate the ZC pool (hold
   loans on all slots), then publish/retransmit a ZC-eligible sample → `%zc-loan` NIL → the writer falls back
   to the full payload → the loan-capable reader receives a NORMAL (non-marker) sample → `take-loaned` returns
   it **as a copy** (not a view), byte-exact. (This is the most likely gap: `take-loaned`/`%drain-one-loan`
   must handle a non-marker sample mixed in — deliver it copy-backed, not error/skip. Harden if it fails.)
3. **Mixed loan-markers + fallback-copies in one `take-loaned`.** A loan-capable reader receives some ZC
   markers (→ views) and some fallback copies (→ copies); `take-loaned` returns all correctly; `return-loan`
   releases the views (no-op for the copies).
4. **The slot outlives the HC purge.** ACK a ZC loan sample (the writer purges the HC change) while the reader
   still holds the loan; assert the loaned view still reads correctly (the refcount holds the slot past the
   purge) until `return-loan`, then the slot frees.
5. **A best-effort vs reliable ZC writer** both deliver a ZC loan sample correctly (confirm ZC rides the QoS;
   no gate). Off / non-ZC byte-identical (regression).

## Likely harden points (fix only if a test exposes them)
- `take-loaned`/`%drain-one-loan` delivering a **fallback-copy** (non-`zc-loan-marker`) sample to a
  loan-capable reader — must return it as a copy, not assume every drained sample is a marker.
- The retransmit re-loan interacting with the loan-capable defer (the receiver thread defers the re-loaned ref
  the same as the first).
- Any place a saturated-pool fallback under RELIABLE could silently drop rather than copy-deliver.

## Out of scope (scope B follow-up)
- **True writer-side reliable ZC** — when all matched readers are same-host ZC-capable, the HC change
  references the slot (no full-payload copy), the slot retained until ACK (writer-hold released on purge) +
  not reclaimed while loaned, retransmit re-sends the ref to the retained slot. Eliminates the writer-side
  double-storage; conditional (any non-ZC/remote reader forces the copy) + a bigger HC↔pool change. Deferred.
- Reliable-ZC over the network (ZC is same-host SHMEM; a remote reliable reader gets the full payload, already
  reliable).

## Testing / acceptance
- The 5 scenarios PASS on SBCL (pass-skip Clasp — ZC SBCL-only). Any gap found is fixed + regression-tested.
- The existing ZC + reliable suites unchanged (`zerocopy-end-to-end`, `flatdata-zc-loan-*`, the reliable
  retransmit tests, `dcps-loan-roundtrip`, `zc-xproc`) — green both impls.
- Gates green; `make mem`/`gate-hotpath` unaffected (the loan RX path is unchanged unless a harden touches it
  — re-verify 0-alloc if so).

## Decisions baked in (brainstorming 2026-06-16 — confirm at spec review)
1. **Scope A** (verify+harden+test; owner-chosen) — scope B (writer-side no-double-copy) deferred.
2. Reliable ZC delivery rides the existing reliable path (HC full payload + retransmit re-loan / copy
   fallback); the loan composes via refcount; no reliability gate; the ZC win is reader-RX + wire.
3. R6; SBCL-only.
