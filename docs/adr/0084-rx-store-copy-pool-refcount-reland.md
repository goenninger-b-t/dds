# ADR 0084 — RX store-copy pool, refcounted re-land (safe-by-construction lifetime)

- **Status:** ⚠️ **WITHDRAWN, UNIMPLEMENTED (2026-07-24) — its root diagnosis is WRONG. See ADR 0085.**
  Retained as the record of a rejected design. This ADR blames a *use-after-release retention* — "a holder
  reads a correctly-released, recycled buffer" — and prescribes refcounting. The corruption it was written
  to fix is a wild **WRITE** into SBCL's dynamic space (clobbered object headers; gencgc "sees junk"), and a
  read cannot clobber an object header, so the refcount would not have fixed it. The real defect was that
  `rtps-reader` had no lock while up to three receiver threads drove it (ADR 0085). The RX store-copy pool
  was only a *trigger*, and it re-lands unchanged in substance. Do not implement anything below.
- **Date:** 2026-07-24
- **Requirements:** NFR-MEM (0 bytes/sample), NFR-PERF-3 (peer GC-tail), NFR-SEC-POSTURE, **NFR-STABILITY (binary gate: no heap corruption)**
- **Relates to:** ADR 0078 (the reverted pool — read its "Why this was reverted"); ADR 0062 (allocation budget); the T5b secured decode pool (the pattern that is safe *because* its exposure is narrow)
- **Supersedes:** ADR 0078's release/lifetime discipline (NOT its core idea — the extent-carrying pooled `octet-buffer` is retained)

## Context — what the re-land investigation established (2026-07-24, on a real Linux box)

ADR 0078 pooled the receiver's per-sample store copy and **corrupts the heap on Linux**; it was reverted. The
2026-07-24 re-land reproduced it on `goedews01` (Linux x86_64, SBCL 2.2.9) — a clean-tree baseline is green,
the pool is **5/8 corrupt** — and made two findings that this ADR is built on:

1. **A double-release was found and fixed** (branch `rx-store-pool-reland`). Instrumentation (a per-node
   checked-out set + a backtrace on any misuse) pinned it: `node-return-all-rx-store-buffers` (teardown)
   released a buffer reachable from **two** store entries (aliasing), returning it **twice** → a duplicated
   free-list slot → `widetag 0`. **Fixed** by tracking buffer lifetime in a per-node `rx-store-checkout` set
   and making release **idempotent / exactly-once** (return to the pool only if still checked out). Post-fix:
   **zero** pool violations fire — the double-release is genuinely gone.

2. **The corruption PERSISTS anyway** (4/8), now **silent to the pool instrumentation** — `RELAY-COLLECT got
   1/3` (the durability relay — the exact symptom ADR 0078 named as unresolved), `IS-REVIVED`, a `Memory
   fault`, `widetag 0x9`. Silent-to-instrumentation + durability-clustered ⇒ a **use-after-release RETENTION**
   (a holder reads a correctly-released, recycled buffer), not a double-release.

**Root diagnosis.** The copy path hands the pooled buffer (or its backing static vec) to **multiple holders
with divergent lifetimes** — the sample store, N≥2 shared readers, and something on the durability
relay/republish path — and ADR 0078's **single-owner release** (return the buffer when *the store entry* is
dropped) is unsound whenever any *other* holder outlives that drop. The buffer is off-heap `alloc-static`, so
a recycled/aliased read is a wild read/write, and reclaim-then-scavenge is a GC fault. This is why "the copy
path's exposure is far wider than the secured path's" (ADR 0078): the T5b decode pool has ONE holder (the
loan), so single-owner release is sound there.

## Decision — refcounted lifetime, with LEAK-ON-UNCERTAINTY as the safety property

A pooled store buffer returns to the pool **only when a reference count reaches zero**, where every holder
increments on take and decrements on done. The load-bearing safety inversion:

> **A missed decrement LEAKS the buffer (bounded: the pool drains and the copy falls back to `make-array` —
> byte-identical, ADR 0078's own degradation); a missed/premature decrement CORRUPTS. So the discipline is:
> decrement ONLY from a holder you are certain has finished; when in doubt, do not decrement.**

This converts the failure mode from **heap corruption (a binary-gate stability failure)** into a **bounded
leak (a perf regression the fallback absorbs)** — the only acceptable trade for an off-heap hot-path buffer.

### The refcount lives beside the buffer, not in the store
Add a parallel per-node table `rx-store-refcount` (`octet-buffer -> fixnum`), or a `refcount` slot on the
pooled `octet-buffer` (it is a distinct type already, ADR 0078). Guarded by `rx-store-pool-lock`. Acquire sets
count = 1 (the receiver holds it during the copy). Then, atomically at store-insert, the count is set to the
number of holders that will outlive the receive (see below), and the receiver's initial +1 is dropped.

### The holders that must be accounted for (each +1 on take, -1 on done)
1. **The sample store entry** — +1 at store-insert; -1 at the SINGLE drop choke (`%purge-secured-sample`,
   reached by `node-consume-sample` and teardown). This already exists as the exactly-once release site.
2. **N≥2 shared-topic readers** — the store deliberately does not purge until the last reader drains
   (`node-sole-consumer-p`, ADR 0048). The store entry's single -1 at the final drain already represents all N;
   **no per-reader count needed** as long as the drop choke fires exactly once at the last drain. (Verify.)
3. **The reliable engine** — `reader-on-data` `(declare (ignore payload))`, records presence only → **NOT a
   holder** (audited 2026-07-24). No count.
4. **The durability relay / republish** — reads `node-sample` (NORMALISED copy) → *should* not be a holder, yet
   `RELAY-COLLECT` fails. **This is the unpinned holder.** The design REQUIRES pinning it (next section) and,
   if it retains the buffer or reads it after the store-drop, giving it an explicit +1/-1 around its use — or,
   preferably, proving it only ever touches the normalised copy and fixing whatever makes it not.
5. **Teardown** — returns exactly the still-referenced set (the checkout set from the double-release fix),
   each buffer once. Compatible with refcounts (teardown is the terminal decrement of every survivor).

### Pinning the residual holder BEFORE writing inc/dec — poison-on-release (a diagnostic, not the fix)
On every real return-to-pool, **fill the buffer's vec with a poison byte (e.g. `#xA5`) and set its capacity to
a sentinel**. A use-after-release then reads poison / a sentinel extent — a **deterministic, localised** wrong
value at the holder's read site (the `RELAY-COLLECT` / durability test will surface poisoned bytes or a
sentinel-length read) instead of a random later heap fault. That backtrace pins holder #4 exactly, the same
way the checkout-set instrumentation pinned the double-release. Only then are the inc/dec points written.

## Validation (mandatory, on Linux — macOS cannot see this class, ADR 0078)
- The `rsync -> goedews01 -> repro-loop.sh N` loop is the oracle. The bug is intermittent (~50%); a fix needs
  a **long green streak** (≥ 20 clean full-suite runs, no `widetag`/`Memory fault`/data-loss), not 3.
- Keep the checkout-set instrumentation + add poison during bring-up; **strip all `#+sbcl` debug before merge.**
- A leak is acceptable and observable (pool high-water → fallback); assert it stays bounded across a
  create/destroy participant loop (mirrors `node-return-all-loans`).

## Consequences
- Correct-by-construction against the *stability* gate: the worst case is a bounded leak, never corruption.
- More bookkeeping than single-owner release (a refcount table + inc/dec at ~5 sites) — off the steady hot
  path (the counts change at store-insert and drain, not per-octet).
- If, after pinning holder #4, the inc/dec cannot be made provably sound for the durability path, the fallback
  is ADR 0078's own conclusion: **drop the copy-path pool** (the ~36 B/sample stays; status quo is correct).

## Salvage regardless of this ADR's fate
- **`pool-release` bounds-guard (Fix A)** — a release when the free list is full was an unguarded OOB heap
  write at `(safety 0)`; it now no-ops. This hardens **every** pool (secured decode, TX), not just this one,
  and is independent of the copy-path pool decision. **Recommend landing it on `main` on its own.**
- The **idempotent exactly-once release from a checkout set** is the correct release primitive and is retained
  by this design.

## Alternatives considered
- **Single-owner release (ADR 0078)** — unsound here; multiple holders. Rejected (this ADR exists because of it).
- **Epoch/RCU deferred reclamation** — reclaim only at a quiescent point where no holder can reference a
  retired buffer. Avoids enumerating holders, but the "quiescent point" for the async receiver + the drain +
  the durability relay is hard to define correctly, and RCU is error-prone. Refcount-with-leak-on-uncertainty
  is simpler and its failure mode is a bounded leak. Revisit only if refcounting proves intractable.
- **Drop the copy-path pool** — the safe status quo; the fallback if refcounting does not converge.
