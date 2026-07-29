# ADR 0095 — The arena is an accounting fiction; make it real

- **Status:** **Accepted** — owner decision, 2026-07-29: **option (a), the per-participant sub-arena** (§4).
- **Date:** 2026-07-29
- **Requirements at stake:** **FR-PF-7 (MUST)** — *"all hot-path memory comes from the static,
  startup-allocated, non-GC'd arena sized by `*static-arena-bytes*`"*; **NFR-MEM**; **NFR-DET**.
- **Relates to:** ADR 0002 (froze `DDS.CORE.ARENA` as an L1 contract), ADR 0062 (the allocation ratchet),
  ADR 0064 (arena exhaustion is a STATUS, not a condition), ADR 0077/0087/0093 (the pools that carve from it)
- **Provoked by:** the owner's standing directive — *"we still need to get down to 0 per sample with full
  preallocation on the arena"* — after sixteen slices took the measured path from 1550/1342 to 558/350
  B/sample **without touching the arena half of it at all**.

---

## 1. The finding

**FR-PF-7 describes an arena this stack does not have.** Not "does not have yet" — the machinery named
`DDS.CORE.ARENA` does something else, and six facts establish it. Every one is from the source, not
inference:

1. **There is no single arena. There are ten.** Every production `init-arena` call is a *per-pool* call
   sized to that one pool: `(init-arena :bytes (* eb (1+ cap)))`, at `disc.lisp:2589`, `:2633`, `:2673`,
   `dataplane.lisp:108`, `:153`, `:1107`, `:4225`, `:4259`, `:4321`. Each `%ensure-*-pool` builds its own.

2. **`*static-arena-bytes*` is dead in production.** It is the budget FR-PF-7 names, it defaults to 64 MiB —
   and **every production caller passes an explicit `:bytes`**, so the default is never read outside tests.
   The variable that is supposed to bound all hot-path memory bounds nothing.

3. **Nothing is startup-allocated.** The carves are lazy (`%ensure-…`, first use), so the first datagram or
   sample of each kind pays `capacity × alloc-static` at an arbitrary moment, and a pool never exercised is
   never carved. FR-PF-7's word is *startup-allocated*; NFR-DET is the reason it matters.

4. **The arena is not an allocator.** `make-buffer-pool` bump-increments a counter and then calls
   `make-octet-buffer` **once per slot**, i.e. one independent `dds.pal:alloc-static` per buffer. There is
   no contiguous region, no arena block, nothing that could be freed as a unit. `arena-bytes-used` is
   bookkeeping over allocations someone else owns.

5. **The largest static buffers bypass it entirely.** `make-octet-buffer` goes straight to
   `dds.pal:alloc-static`. Every receiver thread's **64 KiB** receive buffer, `tx-msg`, `rx-tx-msg`,
   `async-tx-msg` and the SHMEM sink are allocated that way — off-heap, correct, and **outside any budget**.
   In a 3-receiver node that is ~192 KiB of hot-path memory the arena has never heard of.

6. **`make mem` does not assert any of this.** The operating contract §6 lists it as *"assert hot-path
   workload runs entirely from the static arena, no heap fallback, high-water < budget"*. It runs
   `run-mem-test`, which measures the **codec in isolation** and reports ~0 B/iter — a real assertion about
   something else. This is the same shape as the eight gates found broken earlier in this project: **a claim
   about a gate that the gate does not make.** (`docs/wiki/getting-started.md` already describes `make mem`
   honestly; the operating-contract line is the stale one.)

**None of this is a defect in the shipped behaviour.** The pools work, exhaustion degrades correctly, and
the campaign's measured numbers are real. What is false is the *property* FR-PF-7 asserts, and the
determinism argument that rests on it.

## 2. Why it matters beyond tidiness

- **NFR-DET.** "Startup-allocated" is the whole determinism claim. Lazy carves move a `capacity × alloc`
  burst onto the first sample of a kind — exactly the latency tail a static-memory design exists to remove.
- **RESOURCE_LIMITS is unenforceable at the process level.** Exhaustion today means *one pool's private
  budget* was hit. There is no answer to "has this process exceeded its static-memory budget?", because no
  component knows the total. A user who sets `*static-arena-bytes*` gets **no** behaviour change.
- **It cannot be audited.** `arena-report` reports one mini-arena. There is no process-wide high-water,
  so "high-water < budget" cannot be checked by anyone, gate or human.

## 3. Decision

Make the arena what FR-PF-7 says it is, in four vertical slices, each independently demonstrable and each
measured on `make gate-mem` before the next starts.

**Slice 1 — one arena, and a gate that can fail.** Introduce a process-wide arena created once from
`*static-arena-bytes*`, and route all ten `%ensure-*-pool` carves to it. Add **`make gate-arena`**, which
runs a real workload and asserts: exactly one arena; every pool carved from it; process high-water < budget;
zero carve failures. **Falsify it first** (shrink `*static-arena-bytes*` until it goes red) — per the
standing rule that a green gate proves nothing until it has been seen to fail.

**Slice 2 — startup-allocated.** Carve at participant/node creation instead of first use, so the cost lands
at init. Keep the lazy path as the fallback for pools whose size is not known until first use, and say which
those are.

**Slice 3 — the bypass.** Draw the receive/TX scratch buffers from the arena instead of bare `alloc-static`,
so the ~192 KiB per node is inside the budget. This is the slice that makes "all hot-path memory" true.

**Slice 4 — global exhaustion.** `*static-arena-bytes*` becomes a real ceiling: a carve that would exceed it
returns the ADR 0064 status, the engine maps it to RESOURCE_LIMITS, and a test exercises a deliberately
too-small budget end to end.

Also, in slice 1: **correct the operating contract's `make mem` line**, or point it at `gate-arena`. A gate
description that overstates what it checks is worse than no description.

## 4. The teardown question — DECIDED: option (a)

> **Owner, 2026-07-29:** *"Option (a)"*

**Slice 1 has a teardown hazard, and it is not incidental.** The arena is bump-allocated with no way to
return a carve; today that is harmless because each pool owns its own arena and `teardown-arena` frees the
lot. With one shared arena, **a participant create/delete cycle leaks budget** — carve on create, nothing
reclaimed on delete — so a long-running process that churns participants eventually cannot carve.

Three ways out, and this is a design choice, not a detail:

- **(a) Per-participant sub-arena — CHOSEN.** Each participant carves a slab from the process arena and
  sub-carves within it; delete returns the slab. Keeps the global budget real and makes teardown exact, and
  it matches how participants already own their pools.

  **As built the slab is DEMAND-GROWN, not fixed.** A sub-arena is a charge account against its parent: a
  carve charges the parent (so the ONE global budget is what is really enforced) and adds to the
  sub-arena's `reserved`; teardown returns exactly `reserved`. That is faithful to (a) and strictly better
  than a fixed slab, because it needs no per-participant size guess and no new tuning knob — a guess that
  is too small breaks carving, one that is too large silently shrinks the process budget.
- **(b) Free-list of carves.** *Rejected.* More machinery, and fragmentation becomes a real failure mode.
- **(c) Accept and document.** *Rejected.* Cheapest, but it leaves a documented leak in the component whose
  entire purpose is bounded memory, in a stack that ships a durability service intended to run for months.

## 5. What this does *not* claim

It does not claim a per-sample allocation win. The arena work is about **where hot-path memory lives and
whether its budget is real**, not about the bytes/sample the ratchet tracks; slices 1–3 may well measure
0.0 B/sample on `gate-mem` and still be the point. The two halves of the owner's directive are separate: the
sixteen shipped slices drove *GC-heap* allocation down 64–74 %; this drives *static* memory into one
audited, startup-allocated, bounded region.

## 6. Consequences

- `DDS.CORE.ARENA` is a **frozen L1 contract** (ADR 0002). Slice 1 adds to it (a process-arena accessor);
  slices 2–4 change carve timing and exhaustion semantics. Consumers: the ten `%ensure-*-pool` sites, plus
  `dds.core.buffer:make-octet-buffer`'s callers in slice 3. No wire behaviour changes in any slice.
- Tests that call `init-arena` directly (≈20 sites, all in `dds-tests`) keep working — the per-arena
  constructor stays; production stops using it.
- Clasp: `alloc-static` is PAL-provided on both implementations, so no new portability gap is expected.
  Slice 3 touches the buffer layer, which is where a gap would show up; it will be checked there.
