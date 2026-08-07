# ADR 0107 — The TX payload cursor: three options, one measurement, and a safety obligation

- **Status:** Accepted in principle — the §5 obligation is DISCHARGED (§7). Not yet implemented: one test gate remains (§7 tail).
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
