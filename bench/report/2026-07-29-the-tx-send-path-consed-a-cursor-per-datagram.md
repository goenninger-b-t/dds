# The TX send path consed a cursor per datagram

**NFR-MEM / FR-PF-7 · arm64 (Apple silicon), SBCL · `make gate-mem`, 60000 samples, own process per arm**

| | before | after | delta |
|---|---|---|---|
| COPY | 687.9 | **641.0** / 639.9 / 641.0 | **−46.9** |
| RETURN | 481.6 | **432.4** / 431.4 / 431.4 | **−49.2** |

Ceilings lowered **720 → 670** (COPY) and **510 → 460** (RETURN). x86_64 keeps its dash.

## The TX path, re-measured

Not re-bisected since the three slices that changed it, so it was measured again before choosing. The map
is now completely different from the one that started this work:

| TX block | then | now |
|---|---|---|
| `%build-key-hash-iq` | 131.1 | **0.00** ✔ cached per instance |
| `writer-write` | 173.7 | **13.1** ✔ `flet` + the returned change |
| **send trigger** | 26.2 | **104.9** ← this slice |
| **the serializer funcall** | 0.00 | **49.2** |
| acquire / liveliness / app-ack / tx-rep / clock | 0.00 | 0.00 |

Two of those moved *up*. That is not a regression — it is the earlier windows having been charged to
neighbouring phases, and it is the fourth demonstration that these probes rank but do not size.

## The defect — the same 48 bytes, a fourth time

```lisp
(let ((mc (dds.core.buffer:cursor buf :endianness :little))    ; 48 B, every datagram
      (wid (%emit-wid node)))
  (write-header mc (disc-node-guid-prefix node))
  (%write-change-submessage node change wid mc)
  (when hb-first (%write-hb-submessage hb-first hb-last hb-count wid mc))
  (%send-raw-buf node buf (cursor-position mc) host port shmem-dest dest-prefix))
```

This is `%send-changes-packed`'s single-datagram fast path, which emits **one datagram per sample**. The
cursor is the same six-word structure this campaign has now removed from the inbound datagram parse, the
ACKNACK reply, and here.

## The fix, and an honest note on its safety argument

The cursor is paired with the node's `tx-msg` scratch buffer and reused through `%cursor-reuse` — the same
helper, with the same `EQ` test, as the two receive-side slices.

**The safety argument here is weaker than theirs, and worth stating plainly rather than glossing.** The
receive-side cursors are per receiver *thread*, so they are private by construction. This one hangs off the
node, beside the buffer it reads. What makes it sound is that **it is no more shared than that buffer**:
whatever discipline lets a thread write into `tx-msg` lets it use a cursor over `tx-msg`, and two threads
racing here would already be corrupting the buffer's contents, cursor or no cursor. The `EQ` test then
covers the one case that genuinely differs — the async sender owns its own `async-tx-msg`, and arriving
with it yields a fresh cursor rather than a cursor pointing into the wrong buffer.

The receiver threads deliberately do **not** use this slot; each has its own in its `rx-context`, because
they run concurrently with each other and with the user thread.

## Verification

SBCL 623/623, Clasp 623/623, `gate-hotpath` PASS, `gate-nocond` PASS, `gate-mem` PASS with both ceilings
lowered. Predicted 48 B/sample; measured **−46.9 / −49.2**.

## Session position — fourteen slices

| | start | now | total |
|---|---|---|---|
| COPY | 1550.0 | **639.9** | **−910.1 (−58.7 %)** |
| RETURN | 1342.2 | **431.4** | **−910.8 (−67.9 %)** |

## The cursor, four sites, one still open

| site | status |
|---|---|
| inbound datagram parse | ✔ per receiver thread |
| ACKNACK reply build | ✔ second slot in the same context |
| TX send fast path | ✔ this slice |
| **the TX payload serializer** | **✘ still 49.2 B/sample** |

The last one is open for the reason recorded when it was deferred: `writer-acquire-payload-buffer` hands
out a *different* pooled buffer per write, so an `EQ`-keyed cache would miss; a per-writer cursor is the
shared-mutable-scratch hazard two application threads writing one DataWriter would hit; and declaring it
`dynamic-extent` would hand a stack-allocated structure to `type-support-serialize`, a **pluggable**
extension point — safe by audit, not by construction. It wants the cursor to belong to the pooled buffer,
which is a `dds.core.buffer` contract change and therefore an ADR.

## What else is left

- **`%drain-one-sample` (~95) is BLOCKED by owner ruling** until the "a take is not a loan" ECR is decided.
- `node-collect-pending-samples`' key conses (~16), and whatever remains in the ACKNACK handler.
- **The arena half of the directive remains untouched.**
