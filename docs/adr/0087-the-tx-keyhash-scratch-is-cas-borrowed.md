# ADR 0087 — the TX key-hash serialization scratch is CAS-borrowed, not locked and not per-writer-owned

- **Status:** Accepted
- **Date:** 2026-07-26
- **Requirements:** NFR-MEM (0 bytes/sample), NFR-PERF-3 (the peer GC-tail), NFR-PERF-8
- **Relates to:** ADR 0075 (pooled the *reader's* key-hash serialization scratch — this is its TX twin); ADR 0076 (pooled the reader's key-hash *result*, which this ADR deliberately does **not** do on TX); ADR 0062 (the allocation campaign); ADR 0041 (the PAL atomics this uses)
- **Contract touched:** `data-writer` gains two internal slots (`keyhash-scratch`, `keyhash-busy`). New internal `%writer-keyhash-scratch`, and `%make-keyhash-scratch` factored out of the existing `%reader-keyhash-scratch`. All `dds.dcps::`-internal — **no exported symbol, no wire byte, and no QoS behaviour changes.**

## Context

The RX drain stopped allocating its key-hash scratch in ADR 0075. **The TX write path never did**, and
`%instance-handle`'s own docstring said so plainly: *"NIL allocates fresh, byte-identical (every TX /
register / unkeyed caller)."*

A KEEP_LAST **keyed** writer computes an instance handle on **every** `write()` — `%write-key-hash` →
`%instance-handle` with no scratch — which per call did `make-octet-buffer` (a foreign/static alloc + zero)
→ build a cursor → serialize the key → `free-static`, plus a fresh 16-octet result array.

Measured in isolation on the bench type (`perf-data`, keyed `:i32`, n=200 000):

| arm | B/call |
|---|---|
| TX today — no scratch | **112.0** |
| reusable cursor, fresh result array | **32.1** |
| reusable cursor **and** reusable result array | **0.0** |

One call per sample, so ~80 B/sample was available from the scratch alone. The phase split at the time put
TX at 746.9 B/sample of a 1852.2 B/sample total, so this is ~11 % of the TX phase.

## Decision

**Reuse the serialization scratch. Do NOT reuse the result array. Guard the scratch with a CAS try-lock.**

Three decisions, each forced by a different constraint:

### 1. The scratch is reused — it is retained by nothing

The cursor and its 256-octet buffer are internal to the key serialization and dead the moment the handle
is computed (today they are explicitly `free-static`'d). Reusing them is invisible outside the call.
Byte-equivalence was *verified*, not assumed: 200 000 reuses of one cursor produce handles byte-identical
to the freshly-allocated path.

`%make-keyhash-scratch` is factored out so the reader's scratch (ADR 0075) and the writer's are one
definition of the shape — including the `:big` endianness, which is not a free choice: the key-hash is
always serialized big-endian regardless of the payload's representation (RTPS 2.5 §9.6.4.8).

### 2. The RESULT array is NOT reused — it is retained twice

This is the part that looks like a missed 32 B and is not. The handle `%write-key-hash` returns is
**retained on three paths**:

- it is threaded onto the data `CacheChange` as `instance-key-hash`, where KEEP_LAST uses it for
  **per-instance eviction** (ADR 0019, DDS 1.4 §2.2.3.18);
- it is used as an **`equalp` hash key** into `dw-instances` on an instance's first write; and
- when the writer has a **finite offered DEADLINE**, `%deadline-touch-writer` passes it on to
  `%deadline-arm-instance`, which keys `dw-deadline-timers` by it (`%deadline-disarm-instance` then
  does `gethash`/`remhash` on that same key). Under the default DURATION_INFINITE this path arms
  nothing, so it is a *conditional* third retention — which makes it worse, not better: a recycled
  array would be safe until someone configured a DEADLINE.

Recycling one array across writes would therefore (a) make every change in the history share a single
handle object, so KEEP_LAST would evict against whichever instance was written last, and (b) mutate a live
hash key in place. Both are **silent mis-attribution**, not crashes — the worst failure class this
codebase has.

ADR 0076 solved the equivalent problem on RX with a *stable-handle indirection*: compute into a transient
array, look the instance up, then retain the instance-rec's **existing stable** handle. That works on TX
too, but it needs a writer-side handle→stable-handle mapping (`dw-instances` currently maps handle→sample,
so its keys *are* the stable handles but are not reachable from a lookup). That is a separate slice with a
separate hazard surface; it is recorded as the follow-on rather than smuggled into this one.

### 3. The guard is a CAS try-lock, not a lock and not an unguarded per-writer buffer

**A DataWriter may be written concurrently.** DDS 1.4 §2.2.2.4.2.11 places no single-thread restriction on
`write()`, and this codebase already assumes it: `writer-acquire-payload-buffer` takes the writer lock
precisely so the payload pool's free-list is *"never torn by a concurrent release"*.

That rules out the reader's approach directly. `%reader-keyhash-scratch` is safe only because the drain is
single-threaded per reader — a discipline the writer has no equivalent of. Two threads serializing keys
through one 256-octet buffer would interleave and produce a **wrong instance handle**.

Three options were considered:

- **A per-writer buffer, unguarded** — rejected: silent corruption under concurrent write.
- **Take a lock** (the existing `dw-status-lock`, or a new one) — rejected: it puts a *new* blocking
  acquire on the write path to save an allocation, and `%write-key-hash` runs before the publish, so it
  would be a second lock per write.
- **A CAS try-lock** (chosen): `dds.pal:cas` the writer's `keyhash-busy` cell 0→1. The winner uses the
  scratch under `unwind-protect`; a loser calls `%instance-handle` with no scratch — **exactly today's
  code path, byte-identical**. Never blocks, never spins, allocates nothing when uncontended.

This mirrors the fail-safe idiom `publish-sample-into` already uses ("no pool / exhausted → degrade to
allocating, never drop"): the fast path is an optimisation that can always decline.

`dds.pal:cas` operates on `(unsigned-byte 64)`, so the cell is a **flag**, not the scratch object itself —
the scratch stays in an ordinary slot, reachable only by the flag's winner.

## Consequences

**Measured, `gate-mem` (60 000 samples, the only oracle):**

| | B/sample |
|---|---|
| before | 1852.2 |
| after | **1769.8** |
| **delta** | **−82.4** |

The isolated sizing predicted −79.9; the end-to-end gate moved −82.4. The model held, which is the check
that the win is real rather than a re-attribution between phases.

- **Uncontended cost:** two CAS operations per keyed KEEP_LAST write. No allocation, no blocking.
- **Contended cost:** none beyond today — the loser runs the pre-existing allocating path.
- **A KEEP_ALL writer is unaffected** (it never computes a handle) and an **unkeyed** type is unaffected
  (it returns the shared `+instance-handle-nil+`).
- **The remaining 32 B/sample** of the TX key-hash is the retained result array, open as the follow-on
  described in §2.
- **Ceilings lowered** for both architectures — `bench/mem-ceiling.txt`. Per that file's own warning,
  banking a win on one arch and leaving the other stale makes the ratchet fail *on improvement* in CI, so
  both rows were measured directly rather than one predicted from the other.

## Falsification

The slice is guarded by three assertions added to `run-keeplast-keyhash-threaded-test`, each aimed at a
specific way it could go wrong rather than at the happy path:

- **`tx-keyhash-not-aliased`** — two instances written in sequence must hold **distinct, non-aliased**
  handle objects. The first handle is captured *by reference*, so if the result array is ever pooled too,
  the second write overwrites the first change's handle in place and this fails. This is the guard on
  decision §2, and it is the test that must not be weakened to a `copy-seq`.
- **`tx-keyhash-fallback-identical`** — with `keyhash-busy` held (forcing the contended path), the handle
  must be byte-identical to the scratch path.
- **`tx-keyhash-lock-released`** — `keyhash-busy` must be 0 after a write. A leaked try-lock is invisible
  to every correctness test: handles stay right and the writer silently allocates forever after. Without
  this assertion the optimisation could regress to zero with the suite fully green.
