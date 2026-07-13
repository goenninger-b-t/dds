# The reliable writer STABLE-SORTed its entire history cache on every write. 1.1 ms/write at a 20k backlog.

2026-07-13. SBCL, macOS arm64. Continuation of #23. Baseline = `046de42`.

## How it was found

A sampling profile (`sb-sprof`, `:mode :cpu`) of `write-sample` with a live matched reliable reader:

```
  Nr  Self%  Cum%   Function
   1  14.0   14.1   HC-CHANGES-FOR-READER
   2  10.8   52.8   (LABELS SB-IMPL::RECUR :IN SB-IMPL::STABLE-SORT-LIST)   <-- sorting, per write
   3  10.3          foreign function __sendto
   4   9.9          foreign function __ulock_wait2
   5   9.8          <                                                        <-- generic compare
   6   9.7          CACHE-CHANGE-SN
   7   9.2          foreign function __ulock_wake
   8   7.3          SB-IMPL::MERGE-LISTS*
   9   5.0          SB-KERNEL:TWO-ARG-<
  12    -    60.7   %CHANGES-FROM
```

## The defect

```lisp
(defun* hc-changes-for-reader (hc reader-proxy)          ; the SEND path called this
  (let ((changes '()))
    (maphash (lambda (sn ch) (push ch changes)) (history-cache-changes hc))   ; the WHOLE cache
    (sort changes #'< :key #'cache-change-sn)))                               ; ... then SORT it

(defun* %changes-from (writer base)                      ; ... and then throw most of it away
  (loop for ch in (hc-changes-for-reader (rtps-writer-hc writer) nil)
        when (>= (cache-change-sn ch) base) collect ch))
```

**Every write maphash'd the entire history cache, STABLE-SORTed the whole change list with generic `<`, and
then filtered it down to the suffix it actually wanted.** Under RELIABLE/KEEP_ALL the cache holds every
change until the reader ACKs, so the sorted list grows with the unacked backlog — O(n log n) per write, over
a backlog that grows because writes are outrunning ACKs. It is the same class of defect as the receive-side
quadratic drain (`46aa047`): re-deriving sorted state from scratch on every operation.

## The fix

`hc-changes-from (hc base)` — ask the cache for the RANGE, which is what the send path always wanted.

Changes are stored under a monotone SN (RTPS 2.5 §8.3.5.4) and the `[min-seq, max-seq]` extent is already
maintained incrementally, so ascending order needs **no sort at all**: walk the extent DOWNWARD from
`max-seq` and `push`, which yields ascending order directly. Holes (KEEP_LAST eviction) cost one failed
`gethash` each and cons nothing. Starting at `(max base min-seq)` means an ACKed prefix is never visited.
`hc-changes-for-reader` is retained for tests/tools that genuinely want every change, and now delegates to
the range query (one implementation, no second sort).

## Result — sustained write throughput (live reliable reader, 256 B)

| back-to-back writes | before | after | |
|---|---|---|---|
| 5 000 | 281 292 ns/write (3 555 writes/s) | **7 925 ns/write (126 181 writes/s)** | **35×** |
| 20 000 | **1 108 830 ns/write** (902 writes/s) | **88 038 ns/write** (11 359 writes/s) | **12.6×** |

At a 20 000-sample unacked backlog the old writer took **1.1 MILLISECONDS per write**. That is a throughput
collapse, and it is exactly the regime a reliable writer under load lives in.

The profile after the fix shows the sort completely gone — `__sendto` (the unavoidable syscall) is now 57.9 %
of the write path, and `HC-CHANGES-FOR-READER` / `STABLE-SORT-LIST` / `MERGE-LISTS*` / `CACHE-CHANGE-SN` /
generic `<` have all left the profile.

## What it does NOT buy — stated plainly

**Single-in-flight one-way latency at 256 B is UNCHANGED** (~20 µs; runs of 17.4 / 20.4 / 22.6 µs vs
17.8 / 18.3 / 21.2 before — inside the run-to-run noise of this harness).

That is not a contradiction, it is the microbenchmark trap that has now caught me three times in this
programme: with ONE sample in flight the reader ACKs immediately, the history cache holds 1–2 changes, and
sorting a 2-element list costs nothing. The `sb-sprof` run that exposed the defect wrote 40 000 samples
flat-out, so ACKs fell behind, the backlog grew to thousands, and the sort dominated. **The defect is real,
the fix is real, and it is a THROUGHPUT/burst fix — not a latency fix.** Anyone reading the profile alone
would have mis-sold this as a latency win.

## Remaining

`hc-changes-from` is O(changes-to-send). The after-numbers still degrade with backlog (7 925 → 88 038
ns/write from 5 k to 20 k), so an O(backlog) term remains somewhere on the push path (suspect: the repair /
HEARTBEAT path re-collecting unacked changes). Not chased here; logged as follow-on.

## Gates

`make test` 563/563 SBCL · `make test-clasp` 563/563 Clasp · `gate-hotpath` PASS · `gate-types` PASS (2850).
