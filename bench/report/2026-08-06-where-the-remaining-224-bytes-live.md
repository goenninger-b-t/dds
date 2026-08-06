# Where the `into` arm's remaining 224 B/sample live

**NFR-MEM / ADR 0105 slice 2, attribution · macOS/arm64, SBCL · 60 000 samples, quiet machine**

Slice 1 closed with the `take-into` arm at **~224 B/sample** and the exit criterion (a genuine zero) unmet.
`mode :fixed-copy` established that **~239 B/sample of the old 463 was the access path** and that the
remaining ~224 is not. This locates the rest, so slice 2 starts from evidence rather than a guess.

## The answer

| where | B/sample | how it was isolated |
|---|---|---|
| **the WRITE path** | **~123** | one participant, a writer, **no reader anywhere** |
| per-sample RX work, on arrival | ~97 | the take window minus the empty-poll cost |
| the send to a real destination | ~5 | the write window (127.8) minus writer-only (~123) |
| **`take-into` polling itself** | **0.0** | `take-into` against a reader that never receives |

**The write path is the majority — and it needs no peer at all to reproduce.** No discovery, no second
participant, no timing, no polling: a bare writer calling `write-sample` in a loop allocates ~123 B/sample.
That makes slice 2's iteration loop seconds long instead of a full bench run.

**`take-into` on an idle reader allocates literally nothing.** The drain, the three-mask selection, the
in-place unlink and the cell pooling are collectively at zero per call — so the ~97 B on the read side is
work that only happens when a sample is actually *there* (the receiver thread's per-datagram handling and
the delivery/decode), not the access machinery slice 1 rebuilt.

## Where in the write path it is *not*

`write-sample` → `%publish-one` already serializes **straight into the writer's arena-pooled buffer** through
a `dynamic-extent` `flet` (ADR 0072), and `%write-key-hash` writes the keyhash through reused per-writer
scratches (ADR 0087). Both are documented as 0 B/sample and the measurement is consistent with that. So the
~123 B is **downstream of DCPS** — in `publish-sample-into` / `writer-write` / the HistoryCache — which is
where slice 2 should read next, per "size from the source".

## Method, and the caveat that matters

The first cut split the measured cycle into two `bytes-consed` windows, one around `write-sample` and one
around the take loop:

```
SPLIT total=225.0 write=127.8 take=97.2 rest=0.0 polls/sample=1.01
SPLIT total=223.9 write=127.8 take=96.1 rest=0.0 polls/sample=1.00
```

⚠️ **`bytes-consed` is WHOLE-PROCESS, and the receiver thread runs concurrently — during the take poll.** So
the `take` window charges the receiver thread's allocation to itself, and `rest = 0.0` only means nothing
allocated *outside* the two windows, not that the receiver thread is free. A window split alone therefore
cannot separate "the user thread's take" from "the receiver thread". The two bracketing probes are what make
the numbers mean something, because neither has a concurrent peer to be charged into it:

```lisp
;; writer-only: no reader exists, so nothing else can allocate into the window
(dotimes (i samples) (dds.dcps:write-sample dw sample))          ; => WRITERONLY 124.5 / 121.2

;; empty poll: a reader that will never receive — the per-CALL cost with no sample in it
(dotimes (i samples) (dds.dcps:take-into dr data infos))         ; => EMPTYPOLL 0.0 / 0.0
```

Both were run twice; `EMPTYPOLL` was 0.0 on both, `WRITERONLY` 124.5 then 121.2.

This follows the campaign's standing rule — **windows RANK, the source SIZES, `gate-mem` CONFIRMS** — and
adds one to it: **a window shared with a concurrent thread ranks the pair, not the part.** Bracket it with a
workload that has no peer, or the number is a sum you cannot split.
