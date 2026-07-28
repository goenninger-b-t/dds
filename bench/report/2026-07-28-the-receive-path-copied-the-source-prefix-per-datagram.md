# The receive path copied the source prefix out of every datagram

**NFR-MEM / FR-PF-7 · arm64 (Apple silicon), SBCL · `make gate-mem`, 60000 samples, own process per arm**

| | before | after | delta |
|---|---|---|---|
| COPY | 1452.6 | **1389.3** / 1389.3 / 1389.1 | **−63.3** |
| RETURN | 1244.6 | **1183.8** / 1181.8 / 1181.6 | **−62.8** |

Ceilings lowered **1490 → 1420** (COPY) and **1280 → 1215** (RETURN). x86_64 keeps its dash — an arch's
row is only ever lowered from a measurement taken on that arch.

The sibling of the cursor slice
([2026-07-28-the-receive-path-consed-a-cursor-per-datagram](2026-07-28-the-receive-path-consed-a-cursor-per-datagram.md)),
and the second of the two prologue blocks that bisect measured at 101.6 and 62.3 B/sample. Together the two
slices take the receive pipeline from **688 → 524 B/sample** and the end-to-end figure from **1550.0 →
1389.3** (COPY) and **1342.2 → 1183.8** (RETURN).

## The defect

```lisp
(defun* %source-prefix (buf) ...
  (let ((p (make-array 12 :element-type '(unsigned-byte 8))))   ; 32 B, every datagram
    (replace p (dds.core.buffer:octet-buffer-vec buf) :start2 8 :end2 20)
    p))
```

Twelve octets in a two-word-header SBCL vector is **32 bytes**, built on every inbound datagram to answer
one question the datagram had already answered: *which peer sent this?* At 2.054 datagrams/sample that is
**65.7 B/sample predicted**; measured **−63.3 / −62.8**.

## Why this is NOT the cursor fix

The cursor could simply be reused because it is scratch that nothing can validly retain. **The prefix is
the opposite: it is copied out of the receive buffer precisely SO THAT it can be retained.** Its holders
outlive the datagram by design —

- `writer-lookup-key`'s reader-proxy key (ADR 0088), which the DCPS side may keep as its active-reader set
  key (ADR 0089) — documented there as safe *because the entry is written once and never mutated*;
- `(cons src-prefix dest)`, the ACKNACK peer list;
- `%record-participant`'s participant record;
- `SampleInfo.publication_handle`, which aliases a GUID built from it (ADR 0090 A3b).

A recycled mutable scratch buffer would turn every one of those into a **use-after-mutate**: the retained
"key" would silently become whichever peer sent the next datagram. That failure is invisible at the point
of the bug and arbitrarily far away at the point of the symptom, which is exactly the class this campaign
has been paying for.

## The fix: a write-once cache, in the ADR 0088 shape

Each receiver thread owns a **16-slot direct-mapped cache** of prefixes it has already seen, indexed by the
low four bits of the XOR of the prefix's last four octets — the participant-discriminating end of the
guidPrefix (RTPS 2.5 §9.4.4).

- **Hit:** twelve `aref` comparisons against the header in place (`%prefix-equal-header-p`) — the whole
  point is to answer *"same peer?"* without building the answer — and the **cached** array is returned.
- **Miss or collision:** allocate exactly as before, and store it. A collision is not a fault; the losing
  peer's next datagram simply re-allocates, which is what **every** datagram did before.

**An entry is written once, at creation, and a slot is only ever REPLACED — never mutated.** So a retained
reference stays valid for as long as its holder wants it, and an evicted peer's next datagram mints a new,
equal array. That is the same invariant ADR 0088 relies on, applied on the receive side.

Identity cannot be depended on in either direction, and that is worth stating because it is what makes the
change safe rather than merely tested: **before this cache every datagram yielded a fresh array**, so no
consumer can have been `eq`-keying one — it would have missed 100 % of the time. Caching can only turn
misses into hits. A grep confirms the other half: no consumer writes into a prefix (every `replace` naming
one has it as the *source*).

## Structure

Both slices' scratch now lives in one per-receiver `rx-context` (cursor + prefix cache), so
`%handle-datagram`'s argument list stops growing as further per-datagram scratch is eliminated. The context
is per-**lambda**, never per-node: the unicast, multicast and SHMEM receivers run concurrently over three
different buffers, and a shared context would interleave one cursor's position across all three. `NIL`
restores the per-datagram allocation everywhere it is accepted, so every non-receiver caller — the tests —
is byte-identical.

A buffer shorter than the 20-octet header falls through to the uncached `%source-prefix` verbatim, so this
adds no new read of a runt datagram.

## Verification

SBCL 623/623, Clasp 623/623, `gate-hotpath` PASS, `gate-nocond` PASS, `gate-mem` PASS with both ceilings
lowered.

## What is left in the receive pipeline

524 B/sample, all of it now inside the three submessage handlers: `%deliver-user-sample` (~135, and *all*
of the DATA handler), the ACKNACK emit `%send-msg-buf` (~98), `parse-acknack-body` (~55, likely the
SequenceNumberSet bitmap), `writer-purge-acked` (~56), `%matched-reader-keys` (~49, a list rebuilt per
ACKNACK), `reader-on-heartbeat` (~29), the peers list (~23). Those window figures **rank** the work; they
do not size it — `get-bytes-consed` moves in TLAB-sized jumps, so a window is charged when the refill lands
in it, not when the object is allocated. Size every one of them with the end-to-end gate, as these two were.
