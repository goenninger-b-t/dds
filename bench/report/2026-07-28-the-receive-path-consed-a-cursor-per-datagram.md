# The receive path consed a cursor per datagram

**NFR-MEM / FR-PF-7 · arm64 (Apple silicon), SBCL · `make gate-mem`, 60000 samples, own process per arm**

| | before | after | delta |
|---|---|---|---|
| COPY | 1550.0 | **1452.6** / 1456.6 / 1452.6 | **−97.4** |
| RETURN | 1342.2 | **1244.6** / 1245.7 / 1245.2 | **−97.6** |

Ceilings lowered **1585 → 1490** (COPY) and **1375 → 1280** (RETURN). x86_64 not measured here; its row
keeps the dash by design (an arch's row is only ever lowered from a measurement taken ON that arch —
ADR 0087 moved the two arches by −82.4 vs −125.4, ADR 0088 by −27.7 vs −72.9).

---

## Where the bytes were: the receive pipeline, fully attributed

The receive pipeline (`%handle-datagram`) was **676 B/sample, 51 %** of the remaining 1342. This bisect
attributes all of it. Method: a `bytes-consed` window around the whole datagram, one per submessage id
inside the dispatch closure, and one per prologue expression — so the residual is a *computed* number and
not a place for anything to hide.

| block | B/sample | B/call | calls/sample |
|---|---|---|---|
| HEARTBEAT handler | 216.3 | 210.9 | 1.026 |
| ACKNACK handler | 193.3 | 188.3 | 1.026 |
| DATA handler | 114.7 | 111.6 | 1.028 |
| **prologue: the cursor** | **101.6** | **49.5** | **2.054** |
| prologue: `%source-prefix` | 62.3 | 30.3 | 2.054 |
| INFO_TS handler, `enforce-rtps` | 0.00 | 0.00 | — |
| **whole datagram** | **688.1** | 334.9 | 2.054 |

**The parts sum to the whole: 193.30 + 216.27 + 114.66 + 101.58 + 62.25 = 688.06.** Unattributed residual
**0.00 B/sample**. Two datagrams per sample (one DATA, one ACKNACK) and four submessages (INFO_TS + DATA +
HEARTBEAT in one, ACKNACK in the other).

## The defect

```lisp
(let* ((cursor (dds.core.buffer:cursor buf :endianness :little))   ; 48 B, every datagram
       (src-prefix (%source-prefix buf))
       ...
```

A `cursor` is four slots — buffer, pos, origin, endianness — so **48 bytes** as a 6-word SBCL structure,
consed on **every inbound datagram** on the receiver thread and dead the moment the datagram is dispatched.
At 2.054 datagrams/sample that is **98.4 B/sample predicted**; measured **−97.4 / −97.6**, i.e. the model
and the machine agree to within 1 %.

## The fix, and why it is safe *by construction*

Each receiver thread reuses **one** receive buffer for its entire life — `start-udp-receiver` allocates a
single 64 KiB `octet-buffer` inside the spawned thread and calls back with it for every datagram; the SHMEM
receiver calls back with the transport's single `sink`. So **one cursor per receiver thread serves every
datagram that thread will ever handle**, and `start-node` gives each of its three receivers (unicast,
multicast, SHMEM) its own cursor cell.

The lifetime argument does not rest on an audit of who might retain a cursor. **A cursor is a position over
a buffer whose contents the next datagram overwrites, so retaining one across datagrams is already
meaningless** — anything doing it is broken today, before this change. That is what makes the reuse safe
rather than merely observed-to-work.

Two details keep it honest rather than assumed:

- **The cell is per-lambda, never per-node.** Three receiver threads sharing one cursor would interleave
  three positions over three different buffers. `disc-node-rx-tx-msg` is per-node scratch that receiver
  threads write; this deliberately is not.
- **`%rx-cursor` EQ-tests the buffer.** A caller that hands over a *different* buffer gets a fresh cursor
  and simply pays the pre-existing allocation. The transports' one-buffer-per-thread discipline is thereby
  a property the code checks, not an assumption it inherits — and a future transport that batches into
  rotating buffers degrades to today's cost instead of corrupting a parse.
- **The SRTPS re-dispatch threads the same cursor.** The recursion re-resets it, and the outer frame
  returns without touching its own binding again.

`rx-cursor` is optional and defaults to `NIL` (allocate one), so every non-receiver caller — the tests —
is byte-identical to before.

## What is left, ranked

`%source-prefix` is the sibling defect and the next slice: a fresh 12-octet array per datagram (32 B ×
2.054 = **66 B/sample**). It is **not** the same fix — the prefix is copied out of the buffer *precisely so
it can be retained* (`writer-lookup-key`'s cache, `(cons src-prefix dest)`, the DCPS active-reader set), so
a reused mutable scratch would be a use-after-mutate. It wants the ADR 0088 shape instead: compare the
datagram's 12 octets against a cached canonical prefix without allocating, and hand back the **cached,
write-once** array on a hit.

Inside the three handlers the split is noisier — the probe windows reattribute charge between neighbours,
because `get-bytes-consed` moves in TLAB-sized jumps and a window is charged when the refill lands in it,
not when the object is allocated. Ranked but **to be confirmed by the end-to-end gate, never by the window
alone**: `%deliver-user-sample` (~135, and *all* of the DATA handler — every other expression in
`%on-user-data` measured 0.00), the ACKNACK emit `%send-msg-buf` (~98), `%matched-reader-keys` (~49, a list
rebuilt per ACKNACK), `parse-acknack-body` (~55, likely the SequenceNumberSet bitmap), `writer-purge-acked`
(~56), `reader-on-heartbeat` (~29), the `(list (cons src-prefix dest))` peers list (~23).

## Measurement note

The whole-datagram and per-submessage totals are stable across runs (688.1 vs 678.5 with the finer probes
in place) but the *split between adjacent windows* drifts by tens of bytes — `%source-prefix` read 30.3 and
then 52.6 B/call for an allocation that is exactly 32 B. **Rank with the windows; size with the end-to-end
gate.** The cursor was the one block stable to within 0.3 B/call across both instrumented builds, which is
why it went first.
