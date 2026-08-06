# The per-decode cursor, and a prediction that was wrong the same way twice

**NFR-MEM / ADR 0105 slice 1, Task 7 · macOS/arm64, SBCL · `make gate-mem`, 60 000 samples per arm, three
runs per arm, quiet machine**

## The number

**arm64**

| arm | before | after | delta |
|---|---|---|---|
| COPY (take, samples dropped) | 512.1 / 511.1 / 511.0 | **463.0 / 464.1 / 463.0** | **−47.6** |
| RETURN (take + `return-loan`) | 304.7 / 302.5 / 302.5 | **254.5 / 255.5 / 255.5** | **−47.6** |

**x86_64**, on the real box

| arm | before | after | delta |
|---|---|---|---|
| COPY | 544.8 … 545.7 | **496.0 … 497.1** | **−48.3** |
| RETURN | 353.6 … 355.0 | **306.3 … 308.6** | **−47.0** |

Ceilings: arm64 `538 → 488` and `320 → 269`; x86_64 COPY `573 → 522`, RETURN stays a dash. This was the
largest single allocation left on the receive path, and the whole 48 B is gone on all four arms.

Two of the x86_64 runs are excluded as instrument artefacts (RETURN 964.5 and 133202.0, on runs whose COPY
read normally) — the per-process intermittent characterised in `bench/mem-ceiling.txt`, now observed at
×2.4, ×16, ×196 and ×435.

## What was allocating

`%deserialize-payload` opened with

```lisp
(let ((rc (dds.core.buffer:cursor ob :endianness :little))) ...)
```

— a fresh six-word `cursor` struct per decoded sample, 48.16 B. The reader now carries one
(`dr-decode-cursor`), obtained through `%reader-decode-cursor`, and `%deserialize-payload` offers it to
`cursor-reuse`.

## The part worth reading: the plan told me to build something that wasn't needed

The slice plan's Task 7 said, in its own words:

> `cursor-reuse`'s `EQ` test **will miss here** — the ADR 0078 store pool hands out a different buffer each
> time. Add a **repoint-in-place** variant that resets the cursor onto a new buffer without allocating, and
> document why the `EQ` guard cannot be used.

That is wrong, and it is wrong in **exactly** the way the identical claim about the TX payload serializer
was wrong nine days earlier. From `bench/mem-ceiling.txt`, 2026-07-29:

> It had been deferred on the claim that an EQ-keyed cache "would miss" because the payload pool hands out a
> different buffer per write; **THAT CLAIM WAS WRONG** — pool-acquire is a LIFO stack, so
> acquire→release→acquire returns the SAME buffer and one slot hits in steady state.

`%rx-store-acquire` draws from the same `dds.core.arena` pool primitive: `pool-acquire` pops from a stack
top, `pool-release` pushes back. With one sample in flight — the steady state this gate measures — the same
`octet-buffer` object comes back every time. And the two *non*-pooled decode paths pass a per-reader scratch
buffer that is **repointed** at new bytes rather than reallocated, so their buffer identity never changes at
all.

So all three engine paths hit the `EQ` test as it stands. No repoint-in-place variant, no new entry point,
no bypass of the safety property — the guard the plan wanted removed is the thing that does the work. The
measured 48 B is the proof it hits: had it missed, the number would not have moved.

**The general lesson is not "the plan was wrong" but that this claim has now been made twice about the same
pool primitive and been false both times.** Check the acquire discipline before believing a buffer is fresh.

## What the change actually rests on

`%deserialize-payload` offers the cursor rather than trusting it:

```lisp
(let ((rc (dds.core.buffer:cursor-reuse cursor ob))) ...)
```

so a cursor over a different buffer, a cursor left at a non-zero position, and `NIL` are all handled by the
one guard. That is why the function needs no precondition on its `cursor` argument, and why the engine's
callers cannot get it wrong. The caching half lives in `%reader-decode-cursor`, and it matters: without the
`setf`, a miss would allocate and discard, so a reader whose first decode missed would allocate forever.

Per-**reader**, not per-thread, is the right grain: every decode runs under that reader's cache lock, so two
threads can never share the cursor, while two readers draining concurrently each have their own.

## The falsification

`run-decode-cursor-reuse-test` is new, and it is a unit arm over the two functions with no participants —
deliberately, because the engine paths exercise this on every sample yet **cannot distinguish "reused
correctly" from "allocated a fresh one"**, which is the property that had to be pinned.

| sabotage | result |
|---|---|
| `cursor-reuse` never reuses | RED `:dcr-reused` — the only failure an assertion here can see |
| `%deserialize-payload` trusts the cursor instead of offering it to `cursor-reuse` | RED `buffer-overflow: need 1 octet(s), 0 remaining` |
| reuse without resetting the position | the same overflow, on the **second** decode |

⭐ Two of the three are caught by the **codec's own bounds check**, not by an assertion in the test. That is
NFR-SEC-POSTURE earning its keep: a wrong-buffer or wrong-position cursor fails loudly at the bound instead
of quietly decoding whatever happens to be there, so neither can degrade into a silent wrong-bytes read.
