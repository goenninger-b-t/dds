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

## Inside the write path: a three-way bisect, no peer, no code edited

The arms differ **only** by public knobs — the type's `@key` and the writer QoS — so each difference names a
sub-path without touching engine code. Two runs each; arm B was identical to 0.1 B.

| arm | B/sample | what the difference names |
|---|---|---|
| A keyed + reliable | 122.3 / 123.4 | the baseline |
| B **unkeyed** + reliable | **79.7 / 79.7** | A − B = **~43 B is the KEYED path** |
| C keyed + **best-effort** | 111.4 / 112.5 | A − C = **~11 B is RELIABLE bookkeeping** |

So the write path is roughly **~80 B common core + ~43 B keyed + ~11 B reliable**.

(KEEP_ALL is deliberately not an arm: with no reader nothing is ever acked, so the cache would grow without
bound and the growth would dominate the reading instead of measuring eviction.)

### ~32 of the keyed 43 B is already diagnosed, in `%write-key-hash`'s own docstring

> *"The RESULT array is still allocated fresh, **deliberately**: the handle is RETAINED on THREE paths —
> threaded onto the CacheChange for KEEP_LAST per-instance eviction; used as a `dw-instances` EQUALP hash
> key; and, when the offered DEADLINE is finite, passed on by `%deadline-touch-writer` as the
> `dw-deadline-timers` key. Recycling it would alias every change's handle and mutate live keys. … Only the
> SCRATCH is reusable; **closing the remaining 32 B needs the ADR 0076 stable-handle indirection on the
> writer side**."*

That is the campaign's RETAINED question already answered correctly: **retained ⇒ a write-once per-instance
cache, never a scratch.** The RX drain has done exactly this since ADR 0076 — compute into a transient
scratch, use it only for the instance lookup, then read the *stable* handle off the record. A writer has few
instances and many writes, so the TX twin is the same shape.

**It is not a drive-by change, and it should not be attempted as one.** `dw-instances` maps
`handle → key-sample`, and Common Lisp gives no way to read a hash entry's stored *key* back — so the stable
handle has to be reachable some other way (widen the value, intern through a second table, or cache the last
handle). That alters a documented value shape at five sites, which needs an ADR. And the docstring names the
sharpest hazard itself: the DEADLINE retention path is **conditional** — under the default
`DURATION_INFINITE` it arms nothing, so a wrongly-recycled handle would look correct until someone
configured a finite DEADLINE.

## After ADR 0106: the core enumerated down to TWO sites

ADR 0106 closed ~32 of the keyed 43. Re-bisected, the write path is now ~80 B common core + ~12 keyed
residue + ~12 reliable — so the **core is the whole remaining story**, and it is present *unkeyed* and
*best-effort*, i.e. it is neither the keyhash nor the reliable bookkeeping.

`sb-sprof :mode :alloc` over 40 000 no-peer writes finds **exactly two** allocating sites:

| site | % of alloc events |
|---|---|
| `DDS.DISC:PUBLISH-SAMPLE-INTO` | **60.4** |
| `DDS.RTPS.HISTORY:HC-ADD-CHANGE` | **39.6** |

48 sampled regions ≈ 3072 kB over 40 000 writes = **~78.6 B/sample**, which is the ~80 B core — so the two
sites account for it, split roughly **~47 B** and **~31 B**.

⚠️ Used strictly to ENUMERATE. The profiler charges callee allocation to caller frames and ranks EVENTS not
BYTES ([[dds-allocation-campaign-lessons]]); with only two frames the list is trustworthy as a *list*, and
nothing here is sized from its ordering.

### The leading candidate, and a gate that does not catch it

`publish-sample-into`'s pooled arm is **`handler-case` nested inside `unwind-protect`**:

```lisp
(unwind-protect
     (handler-case (let ((len (funcall serialize-fn buf))) …)
       (dds.core.buffer:buffer-overflow () …))
  (unless committed (writer-release-payload-buffer writer buf)))
```

That is precisely the ADR 0098 shape — *"no single construct allocates; only the NESTING does"*, measured
there at 16 B/call, and the reason `%ensure-secured-payload-pool` a few lines below carries a comment about
an NLX through a writer lock heap-allocating the handler closure **on every call**.

⛔ **`make gate-nlx` — the gate built for exactly this defect — does NOT flag this site.** It passes with
*"26 to go in the ratcheted set"* and its output names no `dataplane.lisp` line. So either the site is
outside the gate's scanned set or its form-walker does not match this shape. **That gap is worth more than
the bytes**: the gate exists so this pattern cannot reappear, and here it is on the hottest write path.

**Not yet verified as the cause** — it is a hypothesis with two independent supports (the profiler ranks the
frame first; the shape is a documented, measured defect). Confirm by A/B, per the campaign rule that the
source sizes and `gate-mem` confirms.

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
