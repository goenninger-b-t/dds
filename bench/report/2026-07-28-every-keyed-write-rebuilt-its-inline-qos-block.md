# Every keyed write rebuilt its inline-QoS block

**NFR-MEM / FR-PF-7 · arm64 (Apple silicon), SBCL · `make gate-mem`, 60000 samples, own process per arm**

| | before | after | delta |
|---|---|---|---|
| COPY | 1182.7 | **1057.3** / 1056.3 / 1055.5 | **−125.4** |
| RETURN | 976.1 | **848.0** / 846.8 / 848.2 | **−128.1** |

Ceilings lowered **1215 → 1090** (COPY) and **1010 → 880** (RETURN). x86_64 keeps its dash.

## The TX path, fully attributed

Same method as the receive-pipeline bisect: `bytes-consed` windows around each phase of `%write-sample-1`,
`publish-sample-into` and `publish-sample`. The parts sum to the whole exactly.

| block | B/sample |
|---|---|
| `%write-key-hash` | 98.3 — **retracted, see below: really ~32, probably less** |
| **`publish-sample` → `%build-key-hash-iq`** | **131.1** ← this slice |
| `publish-sample` → `writer-write` | 173.7 |
| `publish-sample` → send trigger | 26.2 |
| the serializer funcall, payload-buffer acquire, `%writer-tx-rep`, `realtime-ns`, `assert-liveliness`, the app-ack arm, the deadline touch, the instance tail | **0.00** |
| **TX total** | **429.3** |

Two things worth recording from that table. **The serializer measures 0.00**, confirming at the source that
the previous slice's `dynamic-extent` `flet` really does stack-allocate. And **the key-hash chain —
`%write-key-hash` + `%build-key-hash-iq` — was 229 B/sample, over half of TX**, for a keyed writer.

## The defect

```lisp
(defun* %build-key-hash-iq (key-hash) ...
  (let* ((scratch (make-array 24 :element-type '(unsigned-byte 8) :initial-element 0))   ; 40 B
         (buf (dds.core.buffer:octet-buffer-over scratch))                               ; 32 B
         (mc (dds.core.buffer:cursor buf :endianness :little)))                          ; 48 B
    ...))
```

Three fresh objects — **128 B/call measured** — to lay down twenty-four bytes: a 4-octet PID header, the 16
hash octets, a 4-octet sentinel (RTPS 2.5 §9.6.4.8).

Its docstring said *"Off the hot path — only publish-sample callers that opt in via a non-nil key-hash call
this."* That is true for an **unkeyed** writer, which never calls it, and false for a **keyed** one, where
every single write passes a key-hash. The stale assumption is why this sat unexamined while smaller items
were chased. The docstring now says which case is which, with the measured number.

## The fix

The block is a **pure function of the key hash — that is, of the instance** — and a writer has few
instances and writes many samples. So: a 16-slot direct-mapped cache on the node.

The entry **validates itself**. The block's octets `[4,20)` *are* the hash it was built from, so a hit is
sixteen comparisons against the caller's own key hash and **no separate key is stored beside it**.

Sharing is sound for the reason this campaign keeps re-deriving: the block is **write-once**. It is
retained by every `CacheChange` that carries it and emitted verbatim on retransmits, and nothing ever
writes into one, so a slot is only ever *replaced*. Two samples of one instance now share a block where
they held equal copies.

Concurrency needs no lock: a simple-vector slot store is a single word, every entry is validated against
the caller's own key hash before use, and two threads racing a miss both produce a correct block. A
collision — or a writer with more live instances than slots — degrades to the pre-cache allocation, never
to a wrong block.

## Verification

SBCL 623/623, Clasp 623/623, `gate-hotpath` PASS, `gate-nocond` PASS, `gate-mem` PASS with both ceilings
lowered. Predicted ~131 B/sample; measured **−125.4 / −128.1**.

## What is next in TX

- **`writer-write` — 173.7 B/sample**, the largest remaining item in the TX table: the CacheChange and its
  HistoryCache insert. ⚠️ Treat that figure the way the retraction below says to treat any window number.

## ⚠️ RETRACTION: `%write-key-hash`'s 98.3 was an instrument artifact

The table above first read **98.3 B/sample** for `%write-key-hash`, against a docstring stating its
residual is ~32 B — the deliberately fresh result array, which is retained on three paths (the CacheChange,
the `dw-instances` key, the deadline-timer key) and so cannot be recycled without ADR 0076's stable-handle
indirection. That discrepancy was flagged rather than acted on. **Chasing it was right, and the docstring
won.**

Re-run with five *nested* windows inside `%write-key-hash` — the `keeplast-p` test, both CAS halves, the
scratch accessor, the `%instance-handle` call — and **every one of them reads 0.00, including the outer
window that had read 95.91.** The type's key is a single `:i32`, four octets, so the generated key-hash
takes the ≤16-direct path (`replace out vec`) and never touches `subseq`/`md5`; the only allocation it can
make is the 32 B result array, and even that is below what this instrument resolves.

The 98.3 was charge that landed in that window because it was **the first probe after a stretch of
unprobed code** — the benchmark loop and `write-sample`'s entry. `get-bytes-consed` moves in TLAB-sized
jumps, so a window is charged when the refill lands in it, not when the object is allocated.

**This is the fourth demonstration this session, and the rule has earned its capitals: RANK WITH THE
WINDOWS, SIZE WITH THE GATE.** Three times a window *under*-reported a win (cursor, prefix, reader-keys);
here it invented one. The six shipped slices were all sized by `make gate-mem`, which is why every one of
them landed within a few percent of its prediction — and the predictions themselves came from *reading the
source* (48 B struct, 32 B vector, 3 objects ≈ 128 B), not from the windows.

## Session position

Six slices, every one measured end-to-end against the gate:

| | start | now | total |
|---|---|---|---|
| COPY | 1550.0 | **1057.3** | **−492.7 (−31.8 %)** |
| RETURN | 1342.2 | **848.0** | **−494.2 (−36.8 %)** |
