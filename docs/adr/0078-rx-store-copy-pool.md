# ADR 0078 — the receiver's store-copy is drawn from an arena pool and carries its own extent

- **Status:** REVERTED 2026-07-21 (heap corruption on Linux — see "Why this was reverted")
- **Date:** 2026-07-21
- **Requirements:** NFR-MEM (0 bytes/sample), NFR-PERF-3 (the peer GC-tail), NFR-PERF-8, NFR-SEC-POSTURE (the payload extent is the bounds check)
- **Relates to:** ADR 0062 (the allocation budget); WP-DDS-SECURITY-ZEROALLOC-AEAD T5a/T5b (the payload + decode pools this mirrors); ADR 0073 (the drain already decodes in place); ADR 0077 (the TX-side struct pool)
- **Contract touched:** `disc-node` gains `rx-store-arena` / `rx-store-pool` / `rx-store-pool-lock` / `rx-store-element-bytes`. `dds.disc:node-sample` and `node-sample-by-sn` keep their documented contract (an exact-length payload vector) and now **normalise** a pooled entry by copying it out. New export `dds.disc:node-sample-raw` — the verbatim store entry, for the one hot consumer (the DCPS drain). New special `dds.disc:*rx-store-pool-capacity*`. No wire change; no DCPS/DDS API change.

## Context

After the five allocation slices of 2026-07-21 (ADR 0073–0077) the end-to-end floor sits at ~1887 B/sample
(30 000-sample bench, arm64). The residual is a distributed tail of small allocations — except one.

Every received copy-path (non-Zero-Copy, non-secured-loan) sample is copied out of the reusable receive
datagram buffer into a **fresh GC-heap vector**, `src/dds-disc/dataplane.lisp` `%on-user-data`:

```lisp
((eq zc :not-a-ref)
 (let ((vec (make-array plen :element-type '(unsigned-byte 8))))   ; <- per sample, on the GC heap
   (replace vec (dds.core.buffer:octet-buffer-vec buf) :start2 poff :end2 (+ poff plen))
   (%deliver-user-sample node writer-id sn vec ...)))
```

The copy itself is **necessary**: the receive buffer is reused by the next datagram, while the sample must
survive in the node store until the user thread drains it. What is not necessary is that its memory be
allocated per sample and on the GC heap. This is also the **last allocation on the receive path that scales
with payload size** — at 4 KB samples it is 4 KB of garbage per sample, which is precisely the garbage that
drives the peer's GC and owns the latency tail (ADR 0062).

Measured, A/B in one session, `mem-per-sample :samples 30000` (the larger count amortises the per-run fixed
cost; the arm is otherwise reproducible to ±0.07 B):

| arm | B/sample |
|---|---|
| baseline | 1887.15 – 1887.22 |
| the copy vector reused | 1850.03 – 1854.45 |

**≈ −36 B/sample at zero payload**, and linear in payload size thereafter.

### Why this could not just reuse the TX pool pattern verbatim

An arena pool hands out **fixed-size** buffers (`make-buffer-pool` carves `capacity` × `element-bytes`), but
the store previously held a vector whose length **was** the payload extent — and that extent is load-bearing
in two places:

1. **Security.** `%deserialize-payload` is bounds-checked against the buffer extent (`buffer.lisp:70,81`
   check `octet-buffer-capacity`). Handing the decoder a 16 KB buffer holding a 12-byte payload would let a
   truncated/hostile payload read past its own end into the *previous sample's* bytes — an over-read and an
   information disclosure (NFR-SEC-POSTURE).
2. **Durability.** `dds-durability/service.lisp` persists *and* re-publishes `node-sample`'s result; an
   over-long buffer would be written to the store verbatim.

## Decision

**The pooled buffer carries its own extent, and it is a distinct type.**

The pool's element is a `dds.core.buffer:octet-buffer`, whose `capacity` slot is set to the exact `plen` at
acquire. That single fact resolves both problems above:

- `%deserialize-payload` takes an `octet-buffer` and bounds-checks against `capacity` — so the extent
  enforced is **exactly** `plen`, byte-identical to the pre-pool vector. The drain needs no scratch wrapper
  and no repointing; the stored buffer *is* the bounds. (This is the same move `%drain-one-secured` already
  makes for the secured decode loan.)
- A pooled entry is an `octet-buffer`, **not** a vector. A consumer that does not know about pooling cannot
  silently read the wrong length — the type is different. This is the safety property: **fail to compile /
  fail loudly, never read garbage.**

Concretely:

- **Carve** (`%ensure-rx-store-pool`) — lazy, on the first copy-path receive, double-checked under
  `rx-store-pool-lock`; `element-bytes = (+ 4 *plain-payload-max-bytes* 8)` (the same bound the TX allocating
  fallback uses, so one knob governs both directions), `capacity = *rx-store-pool-capacity*` (64). On
  arena exhaustion it leaves the pool NIL and every receive falls back to `make-array` — byte-identical,
  never an error, never a silent GC-heap claim of a zero it did not achieve (NFR-MEM).
- **Acquire** (`%rx-store-acquire`) — NIL when there is no pool, when the pool is exhausted, or when
  `plen` exceeds the element size; the caller then allocates exactly as before. **Exhaustion is never data
  loss here** — unlike the secured decode pool (which must reject to keep its loan accounting sound), this
  buffer is copied out at the drain, so degrading to an allocation is correct and invisible.
- **Gates** — two, both about a secured node, and neither subsumes the other:
  1. **No crypto-transform.** The secured branch of `%deliver-user-sample` feeds `vec` to
     `decode-serialized-payload` as ciphertext and needs the exact extent. If a live handshake installs a
     transform between that test and the decode, `%deliver-user-sample` **degrades**: it returns the pooled
     buffer and materialises the exact-length vector, taking the pre-pool path unchanged.
  2. **Not secured-loan-capable.** `node-take-loaned` hands the store's *values* to the application, under a
     contract of "a `secured-loan-handle`, or a bare plaintext vector for any non-loan sample mixed in" —
     and every caller dispatches on `secured-loan-handle-p` alone. A pooled buffer arriving there would be
     read as a bare vector: a type confusion. It is reachable in the window where a node has been marked
     loan-capable but the handshake has not yet installed its transform, which is exactly why gate 1 does
     not cover it. Such a node's steady state is the loan path, already pooled by T5b, so excluding it
     costs nothing. The invariant is stated at `node-take-loaned` so relaxing the gate cannot silently
     reintroduce the confusion.

  Secured receive is therefore byte-identical and keeps its own T5b decode pool.
- **Release** — at `%purge-secured-sample`, the **single choke** through which every (GUID, SN) store entry
  is dropped (`node-consume-sample` for the copy path, `%secured-loan-release` for the loan path). Riding
  the existing choke means every present *and future* drop path returns the buffer. A sample that is
  dedup-rejected (never stored) is released on that arm of `%deliver-user-sample`, mirroring the loan path.
- **Teardown** — `stop-node` returns every pooled buffer still held by a store entry
  (`node-return-all-rx-store-buffers`) and *then* tears the arena down, after the receiver threads are
  joined. The return is **not optional**: `teardown-arena` frees a pool by walking its SLOTS, and
  `pool-acquire` NILs the slot it hands out, so a checked-out buffer is not in them and its foreign memory
  would leak — proportional to samples left undrained times participant churn. The secured decode pool has
  always had the identical hazard and has always handled it the identical way (`node-return-all-loans`,
  whose docstring states the rule). **This was got wrong in the first cut of this ADR**, which asserted the
  opposite ("the pool owns its buffers, so an entry resident at teardown is freed with the arena"); CI's red
  run prompted re-reading `teardown-arena`, which says otherwise in three lines of code.
  A raw freelist of `alloc-static` vectors is still the worse option, but for the surviving reason: the
  store is heterogeneous — vectors, loan handles, ZC markers — so a sweep could not tell which entries it
  owned, whereas a pooled buffer is identifiable by its type.

**`node-sample` keeps its contract.** It is documented as "the received payload for composite sample KEY",
and ~20 tests plus the durability relay depend on that being an exact-length vector. It now copies a pooled
entry out. That costs an allocation, but it is not on any hot path — the one hot consumer, the DCPS drain,
uses the new verbatim accessor `node-sample-raw` and dispatches on the type, as it already does for
`zc-loan-marker` and `secured-loan-handle`.

## Consequences

- ~**−36 B/sample** at zero payload; linear in payload thereafter (a 4 KB sample stops producing a 4 KB
  garbage copy per receive). The arm64 gate-mem ceiling drops accordingly.
- ~1.05 MB of static arena per receiving participant, carved lazily on first copy-path receive.
- Payloads larger than `(+ 4 *plain-payload-max-bytes* 8)` (16 396 B) keep allocating — the documented,
  bounded degradation, identical to the TX pool's own bound.
- With **two or more same-topic readers** the node store is shared and `node-consume-sample` deliberately
  does not purge (ADR 0048 / `node-sole-consumer-p`: purging on the first reader's drain would delete the
  sample out from under the second). Such an entry pins its pooled buffer until the participant is torn
  down; once the pool is drained every further receive falls back to `make-array` — i.e. exactly today's
  behaviour, bounded, never unbounded and never incorrect. The pre-existing store leak that causes it is
  unchanged by this ADR and remains the tracked follow-on (a per-sample remaining-consumers refcount).
- Single-owner release discipline is inherited from the store itself: an entry is dropped exactly once, by
  exactly one owner, under the node lock. `%rx-store-release` additionally refuses to push into a full pool,
  so a hypothetical double release degrades to a leaked slot rather than corrupting the pool.

## Why this was reverted

**This design causes heap corruption on Linux.** It was reverted from `main` the day it landed. The
mechanism is not fully pinned down; the isolation is, and that was enough to stop shipping it.

CI went red intermittently on `async-emit-fault-survives`, which I initially could not distinguish from a
flake — it did not reproduce on macOS (0/12), and the CI evidence (0 failures in ~9 runs before, 3 in 9
after) was not statistically significant. On a real Linux box (Ubuntu 24.04, x86_64, the same OS family and
arch as CI) it reproduced, and isolation settled it. Same tree, same fixes, **the pool as the only variable**:

| arm | full-suite runs |
|---|---|
| pre-ADR-0078 | **3/3 pass**, 574 tests, 0 corruption |
| pool **enabled** | **1/3 pass** — one `RELAY-COLLECT` failure, one GC heap corruption |
| pool **disabled**, same tree | **3/3 pass**, 575 tests, 0 corruption |

The corruption presents as `CORRUPTION WARNING ... Memory fault` inside `garbage_collect_generation ->
scav_vector_t`, and as `fatal error ... no transport function for object ... (widetag 0)` — in both cases
the GC walking a reference that is no longer a valid object, on a receiver thread.

**One cause was found and fixed and was NOT sufficient.** `teardown-arena` frees a pool by walking its
SLOTS, and `pool-acquire` NILs the slot it hands out — so a buffer still checked out is never freed. The
first cut of this ADR asserted the opposite. Returning the buffers at teardown without also DROPPING the
store entry then made it worse, not better: the entry became a reference to freed static memory, and a
static vector is a Lisp-visible object, so the next GC to scavenge the still-reachable table faults.
Detaching the entry before returning the buffer removed the `CORRUPTION WARNING`s, but a second corruption
signature survived — so at least one more retention or aliasing path exists that this design has not
accounted for.

**What a re-landing would have to establish**, not assume: every site that can retain a pooled buffer past
its release; an audit of `pool-release`, which at `(safety 0)` writes `(svref slots top)` with **no bounds
check**, so a double release is an out-of-bounds heap write rather than a detectable error; and the
`RELAY-COLLECT` failure, which suggests the durability relay's view of the store is affected too. The
underlying idea — a pooled buffer carrying its own extent in `capacity`, so the buffer is its own bounds
check and a pooled entry is a distinct type — is sound and worth keeping. The lifetime discipline around it
was not, and the copy path's exposure is far wider than the secured path's, which is why the same pattern
has been safe there for months.

**The lesson worth carrying:** macOS could not see any of this — 12 standalone runs and a full green suite
locally, three times over. CI/Linux caught it, and only a real Linux box could isolate it. That is now the
third class of defect in this repo that only Linux could see, after uninitialised memory on the wire and a
stack that could not shut down.

## Alternatives rejected

- **A heap freelist of exact-length vectors** — zero ripple (the store keeps holding exact-length vectors),
  but it puts a hot-path buffer pool on the GC heap, contradicting the operating contract §4 ("all hot-path
  buffers/pools come from an off-heap/foreign arena"). Rejected as a silent divergence.
- **A freelist of `dds.pal:alloc-static` vectors keyed by exact length** — contract-compliant and
  zero-ripple, but static memory needs an explicit free and the store holds three different value types, so
  teardown could not tell which entries it owned; a participant create/destroy loop would leak foreign
  memory unboundedly. The pool-owns-its-buffers property is the whole point.
- **Sizing the pool's element to the first observed `plen`** so the stored vector stays exact-length — this
  would win fully on the fixed-size benchmark and deliver nothing for any variable-size payload. Rejected:
  it optimises the gate rather than the system.
- **A seventh parallel (GUID → SN → plen) table** — works, but adds a hash insert per sample and, worse,
  leaves the stored value a *vector that is longer than its payload*, so any consumer that forgot the new
  table would silently read trailing bytes. The typed buffer cannot fail that way.
