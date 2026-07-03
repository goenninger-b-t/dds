# ADR 0041 — M0 generic PAL atomics closed (`dds.pal:cas` / `atomic-incf` over an `atomic-cell`); the cache-change send-refcount stays lock-guarded

- **Status:** Accepted (WP-PAL-ATOMICS, 2026-07-03)
- **Deciders:** A0 (integrator)
- **Amends:** ADR 0002 (the frozen L0 `DDS.PAL` contract, §7.6) — additive + a stub-closing refinement of the two pre-existing generic atomics symbols (no consumer migration; they had no callers). ADR 0013 (PAL SHMEM + M1 atomics) left the generic `cas`/`atomic-incf` as M0 stubs "in place (no callers)"; this ADR closes them.
- **Resolves:** ADR 0038 Residual **(e)** "M0 atomics stubs" and the identical carry in ADR 0039 (`dds.pal:cas`/`atomic-incf` unimplemented → the send-refcount uses the writer lock).
- **Requires:** REQUIREMENTS NFR-PORT (Clasp + SBCL both validate, Clasp first; no reader conditionals outside `dds-pal/`); NFR-CLOS / NFR-MEM (hot-path purity + zero steady-state allocation); the operating contract §4 (release-safety) and §6 (no performance change without a before/after measurement).

---

## Context

Two L0 symbols, `dds.pal:cas` and `dds.pal:atomic-incf`, shipped in M0 as stubs that signal
`pal-unimplemented`. ADR 0013 diagnosed why and deliberately left them: their frozen signature took a
runtime **`place-fn`** (a first argument that is a *function* accessing some place), and a runtime
place-fn indirection **cannot be lowered to a single hardware atomic instruction** — the native RMW
primitives on both target impls (SBCL `sb-ext:cas`/`sb-ext:atomic-incf`, Clasp `mp:cas`/`mp:atomic-incf`)
are **place-form macros** that must see a *compile-time-known* place. ADR 0013 instead added the
SAP-targeted `cas-sap-u64`/`atomic-incf-sap-u64` for the SHMEM ring's foreign cells (SBCL-only; a
documented Clasp NFR-PORT gap), and the generic pair stayed stubbed.

The one place the generic atomics were wanted is the WP-DDS-SECURITY-ZEROALLOC-AEAD (T5a) cache-change
**send-refcount** (`dds.rtps.history:cache-change` slot `send-refcount`, the operating contract §4
release-safety gate that keeps a pooled secured-payload buffer from being recycled while an in-flight or
deferred send still has to copy it). Because the atomics were stubbed, T5a used the existing per-writer
lock (`rtps-writer-lock`) for every refcount access — sanctioned by ADR 0038 as an interim, with a carry
to "revisit the refcount to lock-free CAS when the PAL atomics land." This WP lands the atomics and makes
that revisit an **informed** decision, not an automatic rewrite.

## Decision

### 1. Close the generic atomics over a concrete `atomic-cell`

The fix for the non-lowerable `place-fn` is a **concrete PAL cell whose slot place is compile-time
known**. `dds.pal` now defines an impl-agnostic `atomic-cell` struct (`pal-contract.lisp`) with a single
`(unsigned-byte 64)` slot `value`, and the two generic ops become ordinary functions that internally
target that fixed slot place:

| Symbol | Signature | Semantics |
|---|---|---|
| `dds.pal:make-atomic-cell` | `(&key value)` | Construct a cell (VALUE defaults 0). |
| `dds.pal:atomic-cell-value` | `(cell)` | Read the live value — a **plain (relaxed) load**; use `cas`/`atomic-incf` for an atomic RMW and `fence` for standalone ordering. |
| `dds.pal:cas` | `(cell old new) → prev` | Full-barrier compare-and-swap of the slot; returns the **PREVIOUS** value (the swap succeeded iff the return is `=` OLD). Matches the SAP sibling `cas-sap-u64`. |
| `dds.pal:atomic-incf` | `(cell &optional (delta 1)) → new` | Full-barrier fetch-add of a **signed** fixnum DELTA modulo 2^64; returns the **NEW** value (a negative DELTA decrements). Matches the SAP sibling `atomic-incf-sap-u64`. |

**Verified primitive mapping (probed on the installed builds, 2026-07-03 — not from memory):**

- A single **`(unsigned-byte 64)`** struct slot is the one representation that supports BOTH ops on BOTH
  impls. (A `fixnum` slot was insufficient: SBCL's `sb-ext:atomic-incf` rejects a `fixnum`-typed slot at
  compile time — it requires an `sb-ext:word`/`(unsigned-byte 64)` slot — although `sb-ext:cas` accepts
  either.)
- **SBCL** — `sb-ext:cas` returns the previous value; `sb-ext:atomic-incf` returns the **OLD** value
  (fetch-add), normalized to the new here by `(logand (+ old delta) #xFFFF…FFFF)`. Both are full barriers
  (LOCK-prefixed / arm64 CAS(AL)). A negative delta is accepted (modular).
- **Clasp** — `mp:cas` returns the previous value; `mp:atomic-incf` returns the **NEW** value directly
  (masked to 64 bits for the uniform contract). A known struct-slot place lowers through `core:acas`;
  unlike a raw foreign cell (no atomic expander — the ADR 0013 Clasp gap), a Lisp struct slot is fine.

The reader conditionals stay confined to `pal-sbcl.lisp` / `pal-clasp.lisp`; the `atomic-cell` struct is
identical on both, so it lives in `pal-contract.lisp` with no conditional.

**Atomicity is proven, not asserted:** `dds-tests` gains `run-pal-atomics-test` (registered `pal-atomics`,
runs on BOTH impls — unlike the SBCL-only SAP-atomics test): single-thread correctness of `atomic-incf`
(returns the new value, signed delta) and `cas` (returns the previous value, succeeds on match / no-op on
mismatch), plus a **concurrency** proof — 8 threads each `atomic-incf` a shared cell 100 000 times and the
final value is asserted `=` 800 000 (no lost updates ⇒ genuine atomicity). Green on Clasp and SBCL.

### 2. The send-refcount stays lock-guarded (assessed, not defaulted)

**Decision: do NOT rewire the send-refcount to lock-free atomics. Keep it lock-guarded, and land the new
atomics as a tested PAL API for a future genuinely-lock-free consumer.**

The assessment (the whole point of this WP's step 2) read every refcount access site:

- **Acquire** — `writer-capture-unsent`, `writer-acquire-sample`, `writer-on-acknack`
  (`src/dds-rtps/reliable.lisp`): each `(incf send-refcount)` is **already inside `%with-writer-lock`**,
  and the lock is held there for *other* reasons — reading/advancing the per-reader `unsent-base`
  watermark and looking the change up in the HistoryCache. The increment is deliberately *atomic with that
  read* (T5a): one critical section spanning {find-change, take-ref} so a concurrent eviction cannot
  recycle the pooled buffer in between.
- **Release** — `writer-release-change-ref(s)` (`src/dds-rtps/reliable.lisp`): each decrement is paired
  under the same lock with `hc-try-release-pooled`, which mutates the pool free-list and the change's
  `pooled-buffer`/`evicted` slots — those need the lock regardless of the refcount.
- **Releasable check** — `cache-change-releasable-p`, `hc-try-release-pooled`, `%hc-remove-change`
  (`src/dds-rtps/history.lisp`): the `refcount = 0` due-check is read/acted-on under the same lock so it
  cannot race an acquire; the change struct itself documents `send-refcount` as "mutated only under the
  owning writer's lock."
- **Acquire/release sites in the dataplane** (`src/dds-disc/dataplane.lisp`) call the `reliable.lisp`
  primitives above; none takes the lock *for the refcount*.

Therefore **no site takes the writer lock just for the refcount** — the lock is already held for the
surrounding unsent-read / cache-lookup / pool-release at every single access. A lock-free atomic refcount
would deliver a **zero** contention win (the lock is held anyway) while **introducing a correctness
hazard**: the releasable-check (`refcount = 0`) would then race a concurrent acquire (`0 → 1`) — the
exact TOCTOU the single-lock design closes by construction. The refcount is one field of a larger
invariant — `{send-refcount, evicted, pooled-buffer, pool free-list, unsent-base}` — that must be mutated
as a unit; making one field lock-free while the rest stay lock-guarded yields a partially-lock-free
structure that is both harder to reason about and actually racy (a use-after-free: eviction releases the
buffer while a just-acquired send-ref still copies it). Keeping the whole invariant under one lock is the
**correct** concurrency conclusion, not a punt.

Because the refcount code is **unchanged**, there is **no hot-path change and no bench** is warranted (the
operating contract §6): `make mem` stays `0.0000` on every secured zero-alloc arm, and the byte-exact
corpora / KAT are untouched. The new atomics are nonetheless a real, tested capability, available for a
future lock-free consumer (e.g. an MPSC ring) where a site *would* otherwise take a lock solely for a
counter.

## Consumers

`dds.pal` exports three new symbols (`atomic-cell`, `make-atomic-cell`, `atomic-cell-value`) and closes the
two existing stubs (`cas`, `atomic-incf`). No production consumer changes: the send-refcount keeps its
`rtps-writer-lock` guard. The only new caller is `dds-tests:run-pal-atomics-test`.

## Provenance

Implemented from the SBCL manual (Atomic Operations: `sb-ext:cas`, `sb-ext:atomic-incf`) and the Clasp
`mp:` atomics documentation (`mp:cas`, `mp:atomic-incf`, `core:acas`), verified by direct probes on the
installed builds. Nothing copied from any external implementation.

## Consequences

- The M0 `DDS.PAL` atomics surface is complete on both landed impls: generic `cas`/`atomic-incf` (both
  impls, over `atomic-cell`) + the SAP-targeted hot-path atomics (SBCL; documented Clasp NFR-PORT gap,
  ADR 0013). `docs/verification.csv` `DDS.PAL` row advances accordingly.
- ADR 0038 Residual (e) and the ADR 0039 carry are **resolved**: the stub is closed and the refcount
  decision is recorded (lock-guarded, with the rationale above).
- No wire change, no codec change, no hot-path change; corpora + KAT + `make mem` unchanged.
