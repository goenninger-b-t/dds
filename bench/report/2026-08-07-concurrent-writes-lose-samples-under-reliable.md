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

## LOCATED: the DCPS drain uses a per-writer HIGH-WATER MARK, and drops anything that arrives below it

The TX/RX split settles it. Every write is accepted, and the lost samples **do arrive** — they sit
undrained in the reader's node store:

```
SPLIT want=120 write-ok=120 write-notok=0 reader-node-store=4 dcps-available=111
SPLIT want=120 write-ok=120 write-notok=0 reader-node-store=8 dcps-available=96
```

`write-ok=120/120` — nothing is refused at the API. And the node store is **not empty at the end**: the
drain consumes what it delivers, so a residue means samples the RTPS engine received and the DCPS drain
never took.

The mechanism is `%data-pending-p`:

```lisp
(> sn (max (gethash g (dr-drained dr) 0)
           (dds.disc:node-reader-join-watermark-unlocked node rid g)))
```

**`dr-drained` is a per-writer HIGH-WATER MARK, not a delivered-set**, and `%reader-advance-drained`
advances it with `(max sn prior)`. So a sample is delivered only if its SN is **strictly greater** than the
highest SN drained so far for that writer. Once SN 50 has been drained, SN 45 arriving afterwards is not
"pending" — it is silently skipped, forever. RELIABLE cannot rescue it: the sample is already in the
reader's store; it is the DCPS drain that refuses it.

⭐ **The code already knew a lower SN can arrive late.** `%reader-advance-drained`'s own docstring says:

> *"Pure reordering (a lower SN arriving late) never jumps forward, so it is conservatively not counted (a
> false SAMPLE_LOST is the worse error)."*

That reasoning was applied to the **SAMPLE_LOST status** and never to **delivery**. Reordering was
understood, and the watermark that decides whether a sample is delivered at all was left unable to tolerate
it.

## Why single-threaded writing hides it completely

One thread completes each `write-sample` — serialize, add to the HistoryCache, send — before starting the
next, so SNs arrive in order and the high-water never overtakes a sample still in flight. Concurrent
writers interleave their sends, so a thread that took a **lower** SN can put it on the wire **after** a
thread that took a higher one. The reader drains the higher SN, the watermark jumps, and the lower one is
dead on arrival. That is why the loss scales with thread count and why 643 single-threaded tests never saw
it.

## The fix is a design decision, not a patch

An exactly-once record that tolerates reordering is a **delivered-set**, or a high-water plus a bounded
gap-set — which is exactly the shape the RTPS reliable *reader* state already keeps for its own
acknowledgement bookkeeping. Making `dr-drained` such a structure changes a per-sample hot-path lookup and
its memory profile, so it wants its own ADR and its own measurement rather than an improvised edit at the
end of a long session.

⚠️ **Do not "fix" it by simply lowering or removing the watermark test** — it is what makes the drain
exactly-once. Weakening it re-delivers samples instead of losing them, which is the worse conformance
error.
