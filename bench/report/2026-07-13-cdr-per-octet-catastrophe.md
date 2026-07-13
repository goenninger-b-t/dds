# The profile paid off: the CDR codec was copying payloads ONE FUNCALL PER OCTET, and the size function was looping per octet TO COMPUTE A NUMBER

2026-07-13. SBCL, macOS arm64, cross-process echo, 41 ns clock (`f1ad628`). Baseline = `f1ad628`.

This is the result of #23 (profile the median path). Two defects found, both in the CDR/codegen layer, both
linear in payload size, both on EVERY sample in BOTH directions.

## How they were found

The new 41 ns clock made a segment profile possible for the first time. Key structural fact: the DCPS
listener fires INLINE on the disc receiver thread (`%on-participant-sample` -> `%wake-reader-data` ->
`on_data_available`), so the responder's entire turnaround is one thread and can be timestamped directly.
**There is no thread handoff to blame** — a condvar wakeup had been the prime suspect and it does not exist.

```
RESPONDER IN-STACK TURNAROUND (before)      p50 ns
  %drain (collect + deserialize)             4 916
  take-samples (select + copy)                 875
  %serialize-sample (alone)                  2 792   <-- serialising 256 BYTES
  write-sample (serialize + engine + sendto) 5 959
```

2 792 ns to serialise a 256-byte payload is ~11 ns PER OCTET. That is not a constant factor; it is a loop.

## Defect 1 — the sequence codec funcalls a closure per element

`cdr-put-sequence` / `cdr-get-sequence-typed` call `(funcall elem-writer c v mode)` **once per element**, each
call redoing `cdr-align`, a bounds check and a cursor bump. For a `sequence<octet>` that is one indirect call
per BYTE. Measured, perfectly linear:

| payload | serialize | deserialize | ns/octet |
|---|---|---|---|
| 256 B | 3 166 ns | 1 983 ns | 12.4 |
| 1 KB | 12 194 ns | 7 546 ns | 11.9 |
| 16 KB | **204 802 ns** | **114 953 ns** | 12.5 |

At 16 KB the codec alone burned **320 µs** — which *was* essentially the entire measured 16 KB round trip.

**Fix:** `cdr-put-octet-sequence` / `cdr-get-octet-sequence` — one `REPLACE` (memcpy) via the already-existing,
already-bounds-checked `dds.core.buffer:put-octets`/`get-octets`. The codegen emits them when the element is
`:u8`/`:byte`/`:octet` (NOT `:i8` — signed elements need per-element two's-complement conversion).
Byte-identical on the wire: an octet has alignment 1, so there is no inter-element padding to reproduce.
`check-room` still runs BEFORE the result vector is allocated, so a hostile count still signals
`buffer-overflow` rather than attempting a 4 GB allocation (NFR-SEC-POSTURE unchanged).

## Defect 2 — the SIZE function looped per element, to compute a number

Worse, and it ran on every write. The generated serialized-size function was:

```lisp
(loop repeat (length (data sample))                    ; 16384 iterations for a 16 KB sequence
      do (setf pos (cdr-size-align pos elt-align mode)) ; generic arithmetic, per octet
         (incf pos elt-size))
```

**~107 µs per write at 16 KB — ~90 % of `%serialize-sample` — spent computing an integer.**

**Fix:** closed form. Every supported element type has `(size MOD effective-align) = 0` (`u8` 1/1, `u16` 2/2,
`u32` 4/4, `u64` 8/8 — and 8 mod 4 = 0 under XCDR2's 4-byte alignment cap, FR-CDR-2), so once the FIRST
element is aligned every later element starts already aligned: align once, then add `n * size`.

Proven equivalent, not assumed: **64 000 combinations** (every element align/size pair × both XCDR modes ×
40 starting offsets × 200 lengths) — **0 mismatches**.

## Result — codec

| payload | serialize | | deserialize | |
|---|---|---|---|---|
| | before | **after** | before | **after** |
| 256 B | 3 166 ns | **153 ns** (20×) | 1 983 ns | **192 ns** (10×) |
| 4 KB | 49 176 ns | **425 ns** (116×) | 29 716 ns | **591 ns** (50×) |
| 16 KB | 204 802 ns | **2 616 ns** (78×) | 114 953 ns | **2 013 ns** (57×) |
| 63 KB | 455 605 ns | **5 101 ns** (89×) | — | **5 135 ns** |

Round-trip byte-identical at every size. 563/563 on BOTH impls — including the byte-exact XCDR vector tests,
which are the wire oracle.

## Result — end-to-end one-way latency (256 B–16 KB)

| payload | before | **after** | Connext | ratio now (was) |
|---|---|---|---|---|
| 256 B | 21 187 ns | **17 833 ns** | 7 041 | **2.5×** (was 3.2×) |
| 1 KB | 35 500 ns | **21 437 ns** | 6 854 | **3.1×** (was 15×) |
| 4 KB | 87 500 ns | **37 167 ns** | 9 270 | **4.0×** (was **65×**) |
| 16 KB | 262 000 ns | **97 708 ns** | 11 729 | **8.3×** (was **114×**) |

## What now dominates — the honest next target

```
RESPONDER IN-STACK TURNAROUND (after)       p50 ns
  %drain (collect + deserialize)             3 250   <-- deserialize is now ~200 ns; ~3 000 is DRAIN/ENGINE
  take-samples (select + copy)                 917
  %serialize-sample (alone)                    250   <-- fixed
  write-sample (serialize + engine + sendto) 5 250   <-- only 250 ns is serialize; ~5 000 is ENGINE + sendto
```

The codec is no longer the bottleneck. **The RTPS engine and the send syscall are**: ~5 µs inside
`write-sample` beyond serialisation, and ~3 µs inside `%drain` beyond deserialisation. That is the next
profile target — not the codec, and still not `declaim`.

## CORRECTION to an earlier report

`bench/report/2026-07-13-specialized-sequence-decode.md` (WP-8.T4) reported "mean 256 B: 7760 ns -> 5968 ns
(-23 %)". **That column is `bytes-per-sample`, not mean latency** — I misread the harness output. The number
is real but it is ALLOCATION (7 760 B -> 5 968 B/sample), not a latency mean. It corroborates the allocation
work; it is not a latency result. No conclusion in that report depended on it (its headline was that the
allocation fix bought NO latency, which stands).

## Gates

`make test` 563/563 SBCL · `make test-clasp` 563/563 Clasp · `gate-hotpath` PASS · `gate-types` PASS (2849).
