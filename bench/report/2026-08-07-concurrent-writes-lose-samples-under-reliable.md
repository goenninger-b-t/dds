# ⛔ Concurrent writes on one DataWriter LOSE samples under RELIABLE — pre-existing, unattributed

**Conformance / FR-QOS · macOS/arm64, SBCL · two participants, one topic, RELIABLE + KEEP_ALL both sides**

## The finding

Four threads writing 30 samples each to **one** DataWriter — 120 distinct instances, RELIABLE and KEEP_ALL
on both ends, loopback — deliver **fewer than 120** samples to the reader, permanently.

| tree | 4 threads × 30 | 1 thread × 120 |
|---|---|---|
| this tree (`65777d6`) | 113, 116, 107, 107, 108, 111, 112 | **120, 120** |
| `43fa6e0` — **before** any of this campaign's work | **119, 66, 102, 112, 115** | **120** |

**Single-threaded always delivers everything. Concurrent writing loses 4–54 of 120.** Raising the settle
budget from 4 s to **30 s** changes nothing (107 both times), so this is not slow delivery — the samples
never arrive.

**It is PRE-EXISTING.** The `43fa6e0` column is the tree as it stood before ADR 0105 slice 1, ADR 0106 and
everything else this campaign landed; its worst run (66/120, a 45 % loss) is worse than anything measured on
the current tree. Nothing here is a regression from the allocation work.

## Why nothing caught it

⛔ **Until 2026-08-07 there was no concurrent-writer test in the suite at all.** Every one of the 643 tests
writes from a single thread. DDS 1.4 §2.2.2.4.2.11 places **no** single-thread restriction on
`DataWriter::write` — it is a supported, ordinary usage — and the middleware guards its per-writer scratches
with a CAS try-lock precisely because concurrent writes are expected. The behaviour under that usage had
simply never been observed.

The arm added for ADR 0106's race (`run-writer-handle-race-test`) was writer-only; extending it with a
reader is what surfaced this.

## What is NOT the cause

- **Not sequence-number assignment.** `%writer-add-bounded` bumps the SN and calls `hc-add-change` inside
  `%with-writer-lock`, so two threads cannot collide on an SN or race the cache insert.
- **Not payload corruption.** Every sample that *does* arrive is internally consistent — the arm writes
  `k = v+1` and no delivered sample has ever violated it across every run above.
- **Not reader-side resource limits.** KEEP_ALL with no `max_samples` on both ends; the reader's
  `samples-available` simply never reaches 120.
- **Not this campaign.** See the `43fa6e0` column.

## Status: OPEN, and deliberately not gated

`run-writer-handle-race-test` asserts **payload integrity** (what it exists for, and what a cursor-lifetime
bug would break) and explicitly does **not** assert delivery completeness. Landing a count assertion would
be a permanently-red gate for a defect that arm does not fix, and the standing order allows exactly two
options — fix the failure or delete the test, never gate it. So the property is recorded here with a
reproducer rather than asserted in a red test.

**The reproducer** (standalone, no test-suite dependency — runs on any commit, which is how the baseline
column was obtained):

```lisp
;; N threads × M writes to ONE DataWriter, RELIABLE + KEEP_ALL, then count what the reader received.
(dotimes (tid threads)
  (let ((tid tid))
    (push (dds.pal:spawn (lambda ()
                           (dotimes (i per-thread)
                             (dds.dcps:write-sample dw (make-cprobe :k (+ 1 (* tid 1000) i)
                                                                    :v (+ (* tid 1000) i)))))
                         :name "cp")
          ths)))
(dolist (th ths) (dds.pal:join th))
;; settle, then: (dds.dcps:samples-available dr)  =>  < (* threads per-thread)
```

**Next step is a TX/RX split**, not a guess: instrument whether the lost samples ever reach the wire
(writer HistoryCache contents and datagrams sent vs the reader's received-marker set). The two candidate
neighbourhoods are the per-writer send path under concurrency and the reliable repair loop — but this
report does not pick one, because the campaign's own rule is that a ranking is not an attribution.
