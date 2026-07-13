# The SHMEM ring copied payloads BYTE-BY-BYTE into shared memory. 4 KB one-way 37.0 -> 17.3 µs (2.1×)

2026-07-13. SBCL, macOS arm64, cross-process echo. Continuation of #23. Baseline `294fe93`.

## The defect — the same class as the CDR codec, in a different file

`%lane-enqueue` wrote the payload into the shared-memory ring one octet at a time, and `%lane-drain` read it
back out the same way:

```lisp
;; enqueue
(dotimes (i len) (setf (cffi:mem-ref sap :uint8 (+ data pos 4 i)) (aref payload (+ off i))))
;; drain
(dotimes (i len) (setf (aref vec i) (cffi:mem-ref sap :uint8 (+ data pos 4 i))))
```

Found by reading the transport while investigating the syscall budget — the moment the CDR per-octet defect
(`046de42`) was fixed, this one stood out as the same shape somewhere else.

Replaced by `dds.pal:sap-copy-in` / `sap-copy-out`: a **memcpy** when the source/destination vector is
`ALLOC-STATIC`-backed (every production payload is arena/static-backed), falling back to the element-wise
loop only for a GC-heap vector (which is what the unit tests pass). The `memcpy` pointer is **cached at
load** (`*memcpy-fp*`) — a by-name foreign call on Clasp re-resolves the symbol every call (~3.8 µs of
dlsym), the lesson from the clock work (`f1ad628`).

Bounds checks are untouched: the drain still validates the record length against `max-record` and the
committed extent BEFORE copying (NFR-SEC-POSTURE).

## Result — one-way p50, same-session A/B

| payload | before (per-byte) | **after (memcpy)** | |
|---|---|---|---|
| 256 B | 16 979 / 18 062 ns | 18 208 / 16 146 ns | **unchanged** |
| 4 KB | 36 625 / 37 354 ns | **17 062 / 17 479 ns** | **2.1×** |

`%shmem-send` itself: 2 832 → 2 096 ns at 256 B.

## Why 256 B did not move, and what that teaches

SBCL compiles `(setf (cffi:mem-ref sap :uint8 …))` into a **direct store** — about **2.9 ns/byte**, not the
~11 ns/byte the CDR codec suffered. (The codec's cost was the `funcall`-per-element *indirection*, not the
store itself.) So at 256 B the loop cost only ~736 ns — real, but below this harness's noise. At 4 KB it is
~12 µs, which is exactly the win observed; at 63 KB the loop would be ~190 µs.

**The lesson: a per-byte loop is not automatically catastrophic — measure which kind you have.** The same
syntactic shape cost 11 ns/byte in one place and 2.9 ns/byte in another, a 4× difference that decides whether
a fix is worth anything at small payloads.

## Standing vs Connext after this (one-way p50)

| payload | ours | Connext | ratio | ratio at session start |
|---|---|---|---|---|
| 256 B | ~16–18 µs | 7 041 ns | ~2.4× | 3.2× |
| 4 KB | **17.3 µs** | 9 270 ns | **1.87×** | **65×** |

## A stall at 16 KB — PRE-EXISTING, not caused by this change

The 16 KB run intermittently fails with `no echo within 5 s`. **Reproduced on the unmodified baseline**, so
it is not a regression from this work — but it is real, and it is intermittent (16 KB measured 97.7 µs
successfully earlier the same day). Most likely the already-tracked responder-stall bug (#15). Recorded here
so the next large-payload measurement is not mistaken for a fresh regression.

## Gates

`make test` 563/563 SBCL · `make test-clasp` 563/563 Clasp · `gate-hotpath` PASS · `gate-types` PASS (2853) ·
`make fuzz` PASS.
