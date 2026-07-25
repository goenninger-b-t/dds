# The relay dedup gate scanned 65 536 hash keys per sample, and a peer could ask it to

**Date:** 2026-07-25 · **Follows:** ADR 0085 (`bench/report/2026-07-24-reliable-reader-lock.md`) · **Box:** dev box, Apple silicon (arm64), SBCL · **Requirements:** NFR-SEC-POSTURE, NFR-MEM, FR-RTPS (RTPS 2.5 §8.3.5.4)

## What was wrong

`reader-dedup-accept-p` is the exactly-once gate for relay-forwarded samples. It kept the
delivered-but-not-yet-contiguous sequence numbers in an EQL hash table (`above`), capped at
`*max-gap-range*` entries, and enforced that cap by shedding the highest entry:

```lisp
(when (> (hash-table-count above) *max-gap-range*)
  (let ((max-sn (loop for k being each hash-key of above maximize k)))   ; O(cap), EVERY CALL
    (remhash max-sn above)))
```

`*max-gap-range*` ships at **65 536**. Once the set is at cap that is a 65 536-key scan **per sample**.

It is not a private inefficiency. This path is entered for any sample carrying
`PID_ORIGINAL_WRITER_INFO`, and both the origin GUID and the sequence number come out of a DATA's inline
QoS — off the wire. A peer that streams sequence numbers above the watermark drives the scan directly, so
a single sender can saturate a receiver thread. Same for memory: the origin table was keyed by that
wire-supplied GUID with **no cap at all**, so unbounded origins × up to 65 536 entries each.

## What changed

- `above` becomes a **circular bit window** over `(lo, lo+window]`, indexed `(mod sn window)`. Test a bit,
  set a bit, advance `lo` through the run it completed. No scan, no shed. `window` is frozen per origin so
  a later rebind of `*max-gap-range*` cannot reindex a live window.
- The window is **allocated lazily, and in-order traffic never allocates it**: `sn = lo+1` just advances `lo`.
- An SN beyond `lo+window` is **accepted but not recorded** — the same bounded residual the shed had (a
  benign duplicate if it re-arrives), and never silent loss.
- New `*max-dedup-origins*` (256) caps the wire-keyed origin table. At the cap a new origin is refused and
  its samples are **accepted untracked**, never dropped; tracked origins are never evicted. Refusals are
  counted and readable via `reader-dedup-origins-refused`.

## Measured — 300 000 calls per arm, three repeats, `dds.pal:monotonic-ns`

| arm | before | after |
|---|---|---|
| **far-above SNs (the remote-drivable case)** | **146 401 / 142 369 / 144 440 ns** | **35.7 / 34.8 / 35.6 ns** |
| in-order steady state | 55.7 / 55.6 / 55.0 ns | **34.3 / 35.9 / 34.5 ns** |
| in-window out-of-order fill | — | 40.9 / 41.2 / 41.1 ns |

**≈ 4 100× on the pathological arm** (146 µs → 36 ns), and the *ordinary* path got ~1.6× faster too,
because in-order delivery no longer touches a hash table at all.

Memory per origin at cap drops from up to 65 536 hash entries to a **65 536-bit window = 8 KB**, and the
number of origins is now bounded rather than attacker-chosen.

## Falsified, not assumed

- `dedup-origin-cap` fails with the cap removed (the table grows past it and nothing is counted).
- The pre-existing `original-writer-dedup` and `dedup-cap` tests pin the observable semantics — including
  the exact watermark path `lo=4 → lo=8` across a withheld gap SN, and the shed entry's re-admission — and
  both stay green unchanged. The bit window was designed to reproduce that behaviour, not to redefine it.
- `dedup-inorder-no-window` is strengthened from "the out-of-order set is empty" to "the window is never
  even allocated".
