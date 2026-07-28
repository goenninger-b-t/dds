# The ACKNACK reply consed a cursor per send

**NFR-MEM / FR-PF-7 · arm64 (Apple silicon), SBCL · `make gate-mem`, 60000 samples, own process per arm**

| | before | after | delta |
|---|---|---|---|
| COPY | 927.8 | **880.5** / 879.3 / 882.3 | **−47.3** |
| RETURN | 724.1 | **673.8** / 676.0 / 674.9 | **−50.3** |

Ceilings lowered **960 → 915** (COPY) and **755 → 706** (RETURN). x86_64 keeps its dash.

## How it was found

Not by a probe. The previous slice's report ended with a suggestion — *"a `lambda` passed to a function
that only ever funcalls it is a `dynamic-extent` `flet` waiting to happen; it is worth grepping for the
rest"* — so the grep was run over the hot-path files. It did **not** find another heap closure worth
fixing (the remaining ones are one-time hook installers, created at node setup). It found this instead:

```lisp
(defun* %send-msg-buf (node buf build-fn host port &optional dest-prefix) ...
  (let ((mc (dds.core.buffer:cursor buf :endianness :little)))    ; 48 B, every send
    (dds.rtps.message:write-header mc (disc-node-guid-prefix node))
    (funcall build-fn mc)
    (%send-raw-buf node buf (dds.core.buffer:cursor-position mc) host port nil dest-prefix)))
```

**The third appearance of the same 48-byte structure this session** — after the inbound datagram cursor and
the TX serializer's. A receiver thread answers every inbound HEARTBEAT with an ACKNACK from inside dispatch,
so this runs about once per sample.

## The fix

The receiver thread already carries an `rx-context` (cursor, prefix cache, GUID cache), bound to
`*rx-context*` per datagram. This adds a **second cursor slot** to it and takes the build cursor from there.

**The second slot is not tidiness, it is correctness.** The reply is built *while the inbound datagram is
being dispatched* — `%on-user-heartbeat` answers from inside the dispatch loop — so the inbound cursor is
**live** at that moment. Sharing one cursor between the parse and the reply would corrupt the parse. The
distinct slot is what makes the reuse safe rather than merely cheap.

Everything else is the machinery already proven twice: an `EQ` test on the buffer, so a caller that supplies
a different buffer pays the pre-existing allocation and never gets a wrong parse; and `NIL` off the receiver
thread, so every other caller of `%send-msg-buf` — discovery, bootstrap, the user-thread APP_ACK — is
byte-identical.

The reuse logic itself is now one function, `%cursor-reuse`, shared by the inbound and reply paths rather
than written twice.

## Verification

SBCL 623/623, Clasp 623/623, `gate-hotpath` PASS, `gate-nocond` PASS, `gate-mem` PASS with both ceilings
lowered. Predicted ~49 B/sample (48 × 1.025 ACKNACKs); measured **−47.3 / −50.3**.

## Session position — eight slices

| | start | now | total |
|---|---|---|---|
| COPY | 1550.0 | **880.5** | **−669.5 (−43.2 %)** |
| RETURN | 1342.2 | **673.8** | **−668.4 (−49.8 %)** |

**The RETURN arm is at half of where the session started.** Every slice was predicted by reading the
source and sized by `make gate-mem`; none was sized by a probe window.

Counting the shapes rather than the slices, the whole session reduces to three defects repeated:

1. **A per-call object that could be reused** — the same 48 B `cursor`, three times (inbound datagram, TX
   serializer, ACKNACK reply).
2. **A rebuilt value that changes only on a discovery event, or only per instance** — the source prefix,
   the source GUID, `%matched-reader-keys`, the PID_KEY_HASH inline-QoS block. All fixed as **write-once
   caches**, never scratches, because every one of them is retained by its callers.
3. **A closure where a `dynamic-extent` `flet` would do** — the TX serializer, `writer-write`'s change
   builder (which also carried a closed-over *mutable*, a heap value cell of its own).

## What is left

The receive pipeline's `%deliver-user-sample` and the take path. **The arena half of the directive remains
untouched**: everything so far removes or caches GC-heap allocation rather than drawing hot-path memory
from `*static-arena-bytes*`.
