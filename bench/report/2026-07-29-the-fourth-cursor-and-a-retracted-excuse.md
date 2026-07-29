# The fourth cursor — and a retracted excuse

**NFR-MEM / FR-PF-7 · arm64 (Apple silicon), SBCL · `make gate-mem`, 60000 samples, own process per arm**

| | before | after | delta |
|---|---|---|---|
| COPY | 641.0 | **592.9** / 590.8 / 591.8 | **−48.1** |
| RETURN | 432.4 | **383.3** / 385.5 / 385.5 | **−47.9** |

Ceilings lowered **670 → 625** (COPY) and **460 → 415** (RETURN). **The RETURN arm is under 400.**
x86_64 keeps its dash.

## The excuse, and why it was wrong

Two slices ago the TX payload serializer's cursor was **deliberately left alone**, with this reasoning
recorded in the commit and the report:

> `writer-acquire-payload-buffer` hands out a *different* pooled buffer per write, so an `EQ`-keyed cache
> would miss; a per-writer cursor is the shared-mutable-scratch hazard two application threads writing one
> DataWriter would hit.

**The first clause is false.** `pool-acquire` is a **LIFO stack** — it pops from the top and `pool-release`
pushes back — so `acquire → release → acquire` returns *the same buffer*. A single-slot `EQ`-keyed cache
hits in steady state, not misses.

**The second clause was the right worry aimed at the wrong object.** A per-writer *keyhash* scratch does
need the CAS try-lock it has (ADR 0087), because two threads serializing keys through **one shared buffer**
interleave into a wrong instance handle. But the payload pool hands each concurrent writer a **distinct**
buffer, so two threads can never be handed the same cursor: the second's `EQ` test fails and it allocates,
exactly as before. **Safe by construction, and no lock needed** — the very property the `EQ` test was
introduced for three slices earlier, not noticed here.

Worth recording as a failure mode: **a plausible-sounding reason not to look is more expensive than a wrong
fix, because nothing measures it.** This one cost 48 B/sample for two slices, and it survived precisely
because it was written down confidently.

## The fix

`%cursor-reuse` moves from `dds.disc` to its proper home, **`dds.core.buffer:cursor-reuse`** (exported,
additive — no existing signature changes, no consumer migrates), and all four sites now share the one
definition rather than the alternative of a `dds.disc::`-qualified reach into another package's internals
or a copied six-line helper. The DataWriter gains a `payload-cursor` slot; the serializer macro takes the
writer and threads it through.

## The cursor, closed out

| site | slice | where its cursor lives |
|---|---|---|
| inbound datagram parse | A | per receiver **thread** (`rx-context`) |
| ACKNACK reply build | H | second slot in the same context — the inbound cursor is *live* during dispatch |
| TX send fast path | N | beside the node's `tx-msg`, no more shared than that buffer |
| **TX payload serializer** | **O** | **per DataWriter, separated by the pool's distinct buffers** |

**Four sites, ~193 B/sample, one six-word structure.** It was never a hot algorithm — it was the same
small object, consed in four places, none of which needed it to be fresh.

## Verification

SBCL 623/623, Clasp 623/623, `gate-hotpath` PASS, `gate-nocond` PASS, `gate-types` PASS (3201 defuns
ftype-declared), `gate-mem` PASS with both ceilings lowered. Predicted 48 B/sample; measured **−48.1 /
−47.9**.

## Session position — fifteen slices

| | start | now | total |
|---|---|---|---|
| COPY | 1550.0 | **590.8** | **−959.2 (−61.9 %)** |
| RETURN | 1342.2 | **383.3** | **−958.9 (−71.4 %)** |

The RETURN arm began the *previous* session at 1740.

## What is left

- **`%drain-one-sample` (~95) is BLOCKED by owner ruling** until the "a take is not a loan" ECR is decided:
  who owns the decoded payload *is* the take-vs-loan question.
- `node-collect-pending-samples`' key conses (~16); the ACKNACK handler and the send trigger, neither
  re-bisected since the slices that changed them.
- **The arena half of the directive remains untouched** — everything so far removes or caches GC-heap
  allocation rather than drawing hot-path memory from `*static-arena-bytes*`.
