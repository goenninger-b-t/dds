# WP-1 — the cross-stack parity harness, and what the first measurement found

2026-07-11. Base `4f859c3`. SBCL, macOS arm64, UDPv4 loopback, 256-byte payload unless stated.

## Why this harness exists

Every `NFR-PERF-1…9` target is a **ratio against RTI Connext on identical hardware**, and that
side-by-side run had never been done. The existing `perftest.lisp` measures an **in-process** pair at the
**`dds.disc` engine layer** with **pre-serialized** payloads. Two things make those numbers uncomparable to
a foreign stack, and both flatter us:

1. **in-process** — no real wire, no second process, and no foreign peer can substitute for either end;
2. **engine-layer** — `publish-sample` takes octets that are *already serialized*, so the measured path
   **excludes type-support serialization**. Connext's `DataWriter::write` includes it.

`xperf.lisp` therefore measures the **DCPS path** (`write-sample` → the generated codec runs → the engine
sends) across **real processes**, with an **interchangeable responder**: ours, Connext, or Fast DDS. Same
topic, same type, same QoS, same payload ladder, same wait strategy (a listener on both sides), same clock,
same percentile rule. That is what makes the ratio honest.

## Finding 1 — the DCPS layer, not the wire, is the bottleneck

| path | p50 one-way | consed/sample |
|---|---|---|
| engine layer (`dds.disc`, pre-serialized, in-process) | **17.5 µs** | 11.9 KB |
| **DCPS layer, in-process** | **430 µs** | **112 KB** |
| DCPS layer, cross-process | 580 µs | 56 KB |

The process boundary costs ~115 µs. **The DCPS layer adds ~410 µs *in-process*, and conses ~100 KB per
sample.** The engine is respectable; the layer every application actually uses is 25× slower than it. That
is why the M5 exit gate looked green — nobody had ever measured the application path.

Ruled out as an artifact: RELIABLE + KEEP_LAST 1 making the writer block on the previous sample's ACK (the
engine bench deliberately uses KEEP_ALL for exactly that reason). It is not the cause — KEEP_ALL 453 µs vs
KEEP_LAST 489 µs.

## Finding 2 — `hc-min-seq` / `hc-max-seq` were O(n) scans on the WRITE path — **FIXED**

A profile of `write-sample` put **80 % of its CPU** in `hc-max-seq` + `hc-min-seq`, with SBCL's *generic*
arithmetic (`TWO-ARG-<` / `TWO-ARG->`) dominating self-time. Both were full `maphash` scans of the change
table, and both are read on the **write** path (the reliable writer's firstSN/lastSN for every HEARTBEAT).
So a write was O(stored) — **quadratic** for any writer whose history is non-trivial: a slow or bursty
reader, KEEP_ALL, a repair backlog.

Fixed: the SN extent is maintained **incrementally** at the two chokepoints (`%hc-store` /
`%hc-remove-change`), so `hc-min-seq`/`hc-max-seq` are **O(1)** reads. A removal rescans **only** when the
removed SN *was* an endpoint (rare — purges remove the lowest, evictions the oldest). SNs are now
**fixnum**-typed, which also takes the comparisons off the generic-arithmetic path (RTPS 2.5 §8.3.5.4
`SequenceNumber_t` is 64-bit; a 62-bit fixnum bounds it at 4.6e18 — 146 000 years at 1 M samples/s).

| `write-sample` (256 B, growing KEEP_ALL history) | before | after |
|---|---|---|
| per call | **62.0 µs** | **4.0 µs** | 
| | | **15× faster** |

**Honest note.** The 62 µs figure came from a microbench with *no peer*, so nothing was ever ACKed and the
history grew unbounded — my own test setup made it quadratic. The defect is real (it bites any writer with
a non-trivial history), but it is **not** what makes the live round-trip slow: with a peer ACKing, the cache
stays small, and the round-trip is **unchanged at 430 µs**. Reporting the 15× without this caveat would have
been dishonest.

## Finding 3 — the DCPS path allocates two buffers **per sample**. This is the real target.

`%serialize-sample`, on **every** `write-sample`:

```lisp
(buf (dds.core.buffer:make-octet-buffer cap))   ; foreign/static alloc + zero — PER SAMPLE
(funcall (type-support-serialize ts) sample wc mode)
(out (make-array len :element-type '(unsigned-byte 8)))   ; fresh HEAP vector — PER SAMPLE
(replace out (octet-buffer-vec buf) :end1 len)            ; memcpy
(dds.pal:free-static (octet-buffer-vec buf))              ; free — PER SAMPLE
```

Two buffer allocations, a zeroing, a memcpy and a free, per sample — matching the profile's `__bzero`,
`%MAKE-OCTET-BUFFER` and `ALLOCATE-VECTOR-ON-HEAP`. The receive path does the same
(`make-octet-buffer` at `entities.lisp:490`).

This is the exact inverse of the operating contract: *"all hot-path buffers/pools come from an off-heap
arena allocated once at startup… steady state allocates **zero** bytes/sample"* (NFR-MEM, NFR-PERF-8). The
**engine** honours that. The **DCPS layer never did** — which is both the ~100 KB/sample and, through GC,
the 6–7 ms `p99.99` tail.

The mechanism to fix it **already exists and is proven**: the secured path (T5a) routes payloads through
`history-cache-payload-pool` + `cache-change-pooled-buffer` with release-on-eviction. The plain DCPS path
must use the same pool rather than `make-octet-buffer`/`make-array`/`free-static` per sample. That is a
reuse, not new machinery.

## Where this leaves the 5 % target

The owner's requirement (within **5 %** of Connext, non-negotiable) is far stricter than `REQUIREMENTS.md`
§7 itself (1.5× p50, 2× p99, **3×** p99.99 — with NFR-PERF-3 rated *low confidence*, "a GC'd runtime cannot,
in general, match a pre-alloc C++ stack on tail latency").

- **p50 at 5 %** looks reachable *once the DCPS path is zero-alloc*: the engine already does 17.5 µs, which
  is in the right neighbourhood for a DDS loopback round-trip.
- **p99.99 at 5 %** requires **zero GC on the measured path — not less GC**. At 112 KB/sample it is
  hopeless; at 0 bytes/sample it is arguable. This is the requirement that will decide whether the target is
  met, and it is an *architectural* outcome, not a tuning one.
- **`declaim` is not the lever.** `(optimize (speed 3) (safety 0))` and `ftype`s buy constant factors;
  Finding 3 is an allocation-per-sample defect and Finding 2 was an algorithmic one. Declarations helped
  Finding 2 (they took the SN comparisons off generic arithmetic) and will help again — but they are the
  finish, not the fix.

## Next (WP-8, now the main event)

1. **Zero-alloc the DCPS TX path**: serialize into a per-writer arena-pooled buffer; hand the engine the
   pooled buffer (reuse the T5a `payload-pool` + `pooled-buffer` + release-on-eviction machinery).
2. **Zero-alloc the DCPS RX path**: same, for deserialize/`take-samples`.
3. Re-measure; then and only then chase constant factors with declarations.
4. **Build the Connext reference peer (WP-1.T2)** and produce the ratio table — the evidence the owner
   requires. Until it exists we do not know what "good" is on this hardware.
