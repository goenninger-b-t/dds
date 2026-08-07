# ADR 0107 — The TX payload cursor: three options, one measurement, and a safety obligation

- **Status:** ⛔ **REJECTED (§8).** Its premise was measured on an unrepresentative workload. The cache it set out to replace hits **99.7 %** in a real drained workload, and implementing option C moved `gate-mem` by **zero**.
- **Date:** 2026-08-07
- **Requirement:** NFR-MEM (0 bytes/sample steady state)
- **Evidence:** `bench/report/2026-08-06-the-tx-payload-cursor-misses-100-percent.md`

---

## 1. The problem

`%with-sample-serializer-into` builds a `cursor` per write and its reuse cache **misses 100 % of the
time** — measured `hits=0 misses=20000`. That is **47.5 B/sample**, the largest single item left on the
write path, and the per-DataWriter cursor cache added on 2026-07-29 has never done anything.

The cache cannot work as written: it is a **one-slot** identity cache, and the HistoryCache **retains** a
change's pooled payload buffer until eviction, so KEEP_LAST-1 alternates between two buffers forever.

⚠️ **And the 100 % miss is currently load-bearing.** DDS 1.4 §2.2.2.4.2.11 puts no single-thread
restriction on `write`. Today two concurrent writers each miss and each get their **own** cursor, so they
serialize into their own pooled buffers safely. **Any fix that shares one cursor reintroduces a race** —
and this repo shipped exactly that class of defect in ADR 0106 one day earlier
([[every-gate-green-and-i-shipped-a-race]]), past every gate, because no test writes from two threads.

## 2. Option A — repoint one cursor in place. ⛔ REJECTED

Keep the per-writer cursor and point it at whatever buffer arrives. Zero-alloc, one line — **and a race**:
two concurrent writers would serialize into two different pooled buffers through one cursor. Rejected on
the same grounds ADR 0106's defect was fixed on.

## 3. Option B — a cursor per POOLED BUFFER

Give each pooled payload buffer its own cursor, so a thread holding a distinct buffer necessarily holds a
distinct cursor. **Safe by construction, no identity test needed, always a hit.**

Cost, measured: `octet-buffer` has **2 slots** (2 header + 2 = 4 words = 32 B). A third takes it to 5 words,
rounded to **6 = 48 B** — **+16 B per octet-buffer**. Paid **once per pooled buffer**, not per sample,
*provided* no hot path allocates an `octet-buffer` per sample. The engine's scratch wrappers are all
created once (`dr-deser-scratch`, `dw-keyhash-scratch`, …) and the write-path measurement shows no
per-sample octet-buffer allocation — but that is a property to **verify with `gate-mem`, not assume**.

⚠️ Layering: a buffer would know about a cursor over itself, while `cursor` already holds a `buffer`. Not
fatal, but it couples `dds.core.buffer`'s most fundamental struct to its reader.

## 4. Option C — make the cursor STACK-ALLOCATED. ⭐ Recommended, and it is free

Measured on this build (200 000 iterations, plain 4-slot struct):

| variant | B/iter |
|---|---|
| **inline** constructor + `dynamic-extent` | **0.00** |
| **inline** constructor, no `dynamic-extent` | **0.00** |
| **not**-inline constructor + `dynamic-extent` | 48.23 |

⭐ **The deciding factor is INLINING THE CONSTRUCTOR, not the `dynamic-extent` declaration.** With the
constructor inlined and the object not escaping, SBCL stack-allocates (or elides) it outright. `dds.core`'s
`%make-cursor` is **not** declaimed inline today, which is why the earlier `dynamic-extent` experiment on
the real cursor measured 47.83 vs 47.90 — no effect at all.

This option beats B on every axis that matters: **no new state, no layering change, no shared object, and
therefore no concurrency argument to get wrong.** The cursor becomes per-call and private by construction —
which is the strongest possible answer to §1's race, not a mitigation of it.

## 5. ⛔ THE OBLIGATION THAT MUST BE DISCHARGED BEFORE IMPLEMENTING C

`%ser-into` serializes through `(funcall ser sample wc mode)` — a **type-support vtable slot**, i.e. an
unknown function to the compiler. SBCL therefore **cannot prove** the cursor does not escape, and will not
stack-allocate it on its own. An explicit `dynamic-extent` declaration makes it do so anyway — **it is an
assertion the compiler cannot verify, and if any serializer retains the cursor it becomes a
use-after-return.**

So option C is only correct once this is established, by reading, for **every** implementation reachable
through that slot:

1. the generated classic-struct `serialize-<name>` (`dds-gen/dsl.lisp`);
2. the generated **FlatData** serializer, including its RX/TX transcode paths;
3. the **secured** encode path (`encode-serialized-payload-into`), which re-encodes into its own pool
   buffer and may wrap the cursor;
4. `dds.cdr:make-encapsulation-header` / `finalize-encapsulation-options`, which **return** the cursor
   (returning is harmless; storing is not).

**Anything that stores the cursor in a slot, closes over it in a retained closure, or hands it to another
thread disqualifies option C** for that path — in which case the write path must select per type-support,
or fall back to option B.

## 6. Verification, when it is implemented

- The no-peer writer probe: keyed+reliable ~95 → expect ~47 (seconds per iteration, no discovery).
- `gate-mem` all three arms, both architectures, ceilings re-banked.
- ⛔ **`run-writer-handle-race-test` must stay green** — the concurrent-writer arm added after ADR 0106's
  race. For option C it should also be extended to assert **payload correctness** under concurrency (each
  writer's bytes arrive intact), because a cursor lifetime bug corrupts payloads rather than handles.
- A falsification that a reviewer can check: with the `dynamic-extent` removed, the win disappears; with a
  serializer that deliberately retains the cursor, the arm must fail.

---

## 7. The §5 obligation, DISCHARGED

Every implementation reachable through the `type-support :serialize` vtable slot was read. **None retains
the cursor.**

| # | implementation | retains the cursor? |
|---|---|---|
| 1 | generated classic-struct `serialize-<name>`, including the `:appendable` / `:mutable` DHEADER backpatching | **no** — the cursor is passed down to the `put-*` forms and nested serializers; the backpatch captures `cursor-position` **integers**, never the cursor |
| 2 | generated FlatData `serialize-<name>-fd` | **no** — one `put-octets`, then it returns the *sample* |
| 3 | secured `encode-serialized-payload-into` | **never receives a cursor at all** — its signature is `(octet-buffer key-material (simple-array (unsigned-byte 8) (*)))`; it works from the finished plaintext, outside the cursor's extent |
| 4 | `make-encapsulation-header` / `finalize-encapsulation-options` | **no** — they *return* the cursor, which is not retaining it |
| 5 | the `dds.cdr` / `dds.core.buffer` `put-*` primitives | **no** — a tree-wide grep for a cursor variable stored into a slot, pushed onto a list, or assigned to a global finds nothing |

Also checked: every `lambda` in `dds-gen/dsl.lisp` is **macroexpansion-time** (`mapcar`/`every`/`find-if`
over the parsed member list) or a vtable closure over the sample **pool** — none closes over a cursor, so
no emitted serializer can smuggle one out in a retained closure.

### ⭐ The one escape that exists is the cache that does not work

`%ser-into` itself stores the cursor:

```lisp
(let ((wc (setf (dw-payload-cursor ,w) (cursor-reuse (dw-payload-cursor ,w) buf)))) …)
```

That `setf` **is** the escape — and it is precisely the 100 %-missing cache option C deletes. So the
obligation is not merely discharged; **the change that makes the cursor stack-allocatable is the same change
that removes the only thing keeping it alive.** Nothing else has to move.

**Status → Accepted in principle.** One gate remains before implementation, from §6: extend
`run-writer-handle-race-test` to assert **payload correctness** under concurrent writers (each writer's
bytes arrive intact), because a cursor-lifetime bug corrupts payloads rather than handles and would
otherwise be quieter than the ADR 0106 race was.


---

## 8. ⛔ REJECTED — the premise was measured on a workload with no reader

Option C was implemented in full (`%make-cursor` declaimed inline, the cache `setf` deleted, the cursor
declared `dynamic-extent`). On the **no-peer** writer probe it did exactly what §4 predicted:

| arm | before | after |
|---|---|---|
| keyed + reliable | 95.0 / 91.7 | **46.0 / 43.7** |
| unkeyed + reliable | 80.8 / 79.7 | **31.7 / 31.7** |
| keyed + best-effort | 79.7 / 80.8 | **31.7 / 32.8** |

**And `gate-mem` did not move at all** — 431.4 / 223.9 / 192.2 before and after, identical to the decimal.

The contradiction is the finding. Instrumenting the cache's hit rate in the **real** workload — write, then
**take** each sample, which is what `gate-mem` and any application do:

```
HM-REAL (write+take) hits=20443 misses=57      ->  99.7 % HIT
HM-REAL (:into)      hits=20433 misses=67      ->  99.7 % HIT
```

**The cache works.** §1's `hits=0 misses=20000` was real but came from a probe with **no reader**: nothing
ever consumed a sample, so the HistoryCache held each change's pooled buffer until the *next* write evicted
it, the pool alternated two buffers forever, and a one-slot identity cache could never hit. Give the samples
a consumer and the buffer is released before the next acquire — so the pool returns the same buffer and the
cache hits.

⭐ **The 2026-07-29 "pool-acquire is a LIFO stack, so one slot hits in steady state" claim was RIGHT**, and
my [[check-the-acquire-discipline-before-believing-a-buffer-is-fresh]] follow-up calling it "wrong at the TX
site" was itself wrong. LIFO *plus a consumer* is the steady state; my probe removed the consumer.

### What this invalidates, and what survives

- ⛔ **Invalidated:** "the TX payload cursor costs 47.5 B/sample". It costs that only when samples are never
  consumed. In a drained workload it costs ~0.
- ⛔ **Invalidated:** the no-peer write-path split (serialize 47.5 + `writer-write` 32.8). Both halves were
  measured without a reader.
- ✅ **Survives:** the *real*-workload split — `SPLIT total=225 write=127.8 take=97.2` — because that probe
  had a reader. The write path really is ~128 B/sample in the workload the gate measures; its **internal**
  breakdown is now unknown again.
- ✅ **Survives:** §4's measurement that inlining the constructor, not `dynamic-extent`, is what enables
  stack allocation. That is a true and reusable fact about this build.

**Not implemented, and not to be revived without a real-workload measurement first.** Replacing a
99.7 %-effective cache with a `dynamic-extent` assertion the compiler cannot verify would trade a working
mechanism for an unverifiable one and buy nothing.
