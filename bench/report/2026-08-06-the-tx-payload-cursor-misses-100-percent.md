# The TX payload cursor misses its cache 100 % of the time — and the obvious fix is a race

**NFR-MEM / ADR 0105 slice 2 · macOS/arm64, SBCL · no-peer writer, 20 000–40 000 writes**

## The finding

The ~80 B/sample write-path core splits, by `bytes-consed` windows placed inside `publish-sample-into`:

```
SPLIT2 total=78.6  serialize=47.5  publish-sample=31.1  rest-of-write=0.0
```

**`serialize` is 47.5 B/sample** — and it is documented as **zero**: *"WP-PERF: serialize STRAIGHT INTO the
writer's arena-pooled buffer — 0 bytes/sample on TX."* 47.5 B is a **`cursor`**, the same six-word struct
this campaign has now chased at five sites.

Instrumenting the EQ test in `%with-sample-serializer-into` directly:

```
CURSOR hits=0 misses=20000  (100.0% miss)
```

**Not "usually misses". Never hits.** `cursor-reuse` allocates a fresh cursor on every single write, so the
per-DataWriter cursor cache added on 2026-07-29 has never done anything in this configuration.

## Why the earlier premise was false

`bench/mem-ceiling.txt` records the 2026-07-29 reasoning:

> *"pool-acquire is a LIFO stack, so acquire→release→acquire returns the SAME buffer and one slot hits in
> steady state."*

That is true only if nothing **retains** the buffer across the next acquire. The HistoryCache does exactly
that: a change owns its pooled payload buffer until it is **evicted**, and `cache-change-evicted` gates the
release. So with KEEP_LAST depth 1 the order is not acquire→release→acquire but:

| write | acquires | still held | released |
|---|---|---|---|
| N | B₁ | — | — |
| N+1 | B₂ (B₁ is still change N's) | B₁, B₂ | B₁, as change N is evicted |
| N+2 | B₁ | B₂, B₁ | B₂ |

The pool **alternates** between two buffers forever, and a **one-slot** EQ cache keyed on buffer identity
can never hit. The sequence is LIFO exactly as claimed; the claim simply omitted the retention.

⭐ **The generalisation:** *acquire→release→acquire returns the same object only when nothing holds the
object across the next acquire.* Any retaining consumer — a history cache, a queue, an in-flight send —
turns a one-slot identity cache into a 100 % miss. Check the RETAINER, not just the pool discipline.

## ⚠️ The obvious fix is a concurrency bug, and the 100 % miss is currently what prevents it

The tempting repair is a **repoint-in-place** cursor: keep the one cursor, point it at whatever buffer
arrives, never allocate. **That would be wrong here**, and for a reason the current behaviour hides:

DDS places no single-thread restriction on `DataWriter::write` (§2.2.2.4.2.11) — which is why the keyhash
path guards its scratch with a CAS try-lock. Today, two concurrent writers each **miss** the cursor cache
and each get their **own fresh cursor**, so they serialize into their own pooled buffers safely. **The
allocation is buying thread-safety by accident.** Repointing one shared cursor would let two threads
serialize into two different pooled buffers through one cursor — an interleaved, silently corrupt payload,
which is precisely the failure `cursor-reuse`'s EQ test exists to prevent.

**The design that is both zero-alloc and safe is a cursor per POOLED BUFFER** — carve them with the pool,
so a thread holding a distinct buffer necessarily holds a distinct cursor and the lookup is always a hit
with no identity test at all. That is a change to the payload pool and wants its own ADR.

## ⭐ The symmetry with ADR 0105 Task 7, which is the day's sharpest lesson

This morning the slice plan demanded a **repoint-in-place variant** for the **RX** decode cursor, asserting
`cursor-reuse`'s EQ test "will miss here". It was wrong: the RX test **hits**, and the −47.6 B/sample win
came from keeping the guard.

The site where a repoint genuinely *is* needed is the **TX** payload cursor — the one whose ancestor claim
said the EQ test works. **Both predictions were exactly inverted**, and in both cases the deciding fact was
not the pool's discipline but **who retains the buffer**:

| | premise | reality | why |
|---|---|---|---|
| RX decode cursor | "the EQ test will miss" | **hits** | nothing retains the store buffer across the next acquire |
| TX payload cursor | "one slot hits in steady state" | **misses 100 %** | the HistoryCache retains the buffer until eviction |

## The other half: `writer-write` = 32.8 B/sample

A second window, around `publish-sample`'s call to `writer-write`, closes the write path:

```
SPLIT3 total=80.3  writer-write=32.8  everything-else=47.5
SPLIT3 total=81.9  writer-write=32.8  everything-else=49.1
```

So the ~80 B core is **fully attributed**: ~47.5 B the payload cursor, ~32.8 B the HistoryCache add. That
also cross-checks the profiler's split (60.4 % / 39.6 %) by a second, independent method.

Reading `hc-add-change` → `%hc-store` → **`%hc-index-append`**:

```lisp
(setf (gethash key (history-cache-instances hc))
      (nconc (gethash key (history-cache-instances hc)) (list sn)))
```

**`(list sn)` is one cons per write, `nconc`'d onto the per-instance bucket's tail** — 16 B, and *exactly*
the defect fixed on the reader side hours earlier in ADR 0105 Task 6a (`dr-cache`'s spine cell, appended
with `(nconc … (list cs))`). The writer-side twin was never looked at. ⭐ The fix pattern is already proven
and its hazards already written down: unlink in place, pool the cells, and only the site that unlinks may
park one.

⚠️ **The other ~16 B of the 32.8 is NOT yet pinned to a line** and is not being guessed at here. The
change struct itself is already pooled (`change-freelist`, ADR 0077) and a steady-state hash insert/remove
pair should not allocate, so it is something else in the `writer-write` subtree.

## Status

The write path is fully attributed and **nothing is fixed**:

| item | B/sample | state |
|---|---|---|
| TX payload cursor, 100 % cache miss | ~47.5 | diagnosed; fix wants an ADR (a cursor per POOLED BUFFER — a repoint would be a race) |
| `%hc-index-append`'s `(list sn)` | ~16 | diagnosed; the ADR 0105 Task 6a pattern applies directly |
| the rest of `writer-write` | ~16 | **not attributed** |
