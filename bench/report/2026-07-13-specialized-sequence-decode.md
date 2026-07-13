# WP-8.T4 — the decoded sequence was 8 bytes per octet. Fixed. It bought NO latency.

2026-07-13. SBCL 2.6.5, macOS arm64, UDPv4 loopback, cross-process echo, RELIABLE / KEEP_ALL / VOLATILE /
XCDR2. Baseline = `46aa047`, measured in the SAME session alternating via `git stash`.

## The defect (a CDR-layer bug, surfacing as a DCPS receive-path cost)

`dds.cdr:cdr-get-sequence` allocated the decoded sequence with a bare `(make-array n)`. In Common Lisp that
is a **`simple-vector` — one machine word (8 B) per element, whatever the element type**. So every
`sequence<octet>` we have ever received cost **8 bytes of heap per octet**:

| payload | heap to hold it (before) | after |
|---|---|---|
| 256 B | ~2 064 B | ~272 B |
| 16 KB | ~131 KB | ~16 KB |
| 63 KB | ~504 KB | ~63 KB |

It was the single largest allocation on the receive path, and it had nothing to do with the drain, the
`sample-info`, or the reader cache — the places WP-8.T3's report predicted it would be. The codegen already
knew the element's Lisp type (`(unsigned-byte 8)` for `:u8`, from the DSL type map); it simply was not
passing it to the decoder.

Fix: `cdr-get-sequence-typed` takes the element type and allocates a specialized vector. The generated codec
passes it as a compile-time constant at each call site. `cdr-get-sequence` remains as the unspecialized
entry point (element-type `T`) and now delegates, so there is one implementation.

## Allocation — the win is real

| | baseline `46aa047` | with T4 |
|---|---|---|
| `%deserialize-sample`, 256 B (microbench, no network) | 2 186.9 B/call | **391.8 B/call** (5.6x) |
| ...of which `%deserialize-payload` | 2 122.6 B | — |
| `%drain`, live echo, per sample | 2 583, 2 899 B | **823, 993 B** |

Decoded sequence type is now `(SIMPLE-ARRAY (UNSIGNED-BYTE 8) (256))`, round-trip `equalp`-identical.
(Live-echo node store was 97–99 in the T4 runs vs 36 in the baseline runs — a LARGER store, and still 3x
less allocation, so the improvement is not a small-store artifact.)

## Latency — NO win. My prediction was wrong.

| metric | baseline `46aa047` | with T4 |
|---|---|---|
| p50, 256 B | 21 500 / 22 000 ns | 22 000 / 22 000 ns — **unchanged** |
| p99, 256 B | 54 500 / 29 000 ns | 56 500 / 47 000 ns — **unchanged (noisy both arms)** |
| mean, 256 B | 7 760 ns | **5 968 ns (-23 %)** |
| p50, 16 KB | 262 000 ns | 279 500 ns — **unchanged** |

**Cutting the decoder's garbage by 5.6x (and ~8x at large payloads) moved the MEAN and nothing else.**

The WP-1 ratio table and the WP-8 plan both asserted that the remaining ~7.8 KB/sample of RX allocation was
"the p50/p99 lever". **That is now disproven.** SBCL allocation is a pointer bump — it was never on a single
round-trip's critical path; it drives GC *frequency*, which shows up in the mean and (eventually) the tail,
not in the median. **The remaining ~3x median gap to Connext is NOT allocation-bound.** Where it actually
lives — syscall/wakeup path, thread handoff, the reliable-engine state machine — is now the open question,
and it must be found by profiling the latency path, not by removing more garbage.

## Why this still ships

1. It fixes a plainly broken primitive: 8 B of heap per octet of wire data.
2. NFR-MEM / NFR-PERF-8 (0 bytes/sample steady state) — a large step, on its own terms.
3. GC pressure is what the TAIL depends on, and the tail claim is currently withdrawn (see
   `2026-07-12-connext-parity-ratio-table.md`). Less garbage is a precondition for re-establishing it.
4. **Security (NFR-SEC-POSTURE): it removes an 8x memory amplification.** `check-room` bounds the element
   COUNT against the remaining buffer extent, but each counted element was costing 8 B of heap — so a peer
   sending a 63 KB octet sequence forced ~504 KB of allocation. The amplification factor is now 1x.

## Gates

`make test` 563/563 SBCL · `make test-clasp` 563/563 Clasp · `gate-hotpath` PASS · `gate-types` PASS (2845
ftype-declared) · `make mem` PASS · `make fuzz` PASS (the CDR/RTPS parser fuzzers, prod + safety-0 arms —
this change touches a network-facing parser).
