# ADR 0108 — The drain's exactly-once record must tolerate reordering: a WINDOW, not a high-water mark

- **Status:** Proposed — analysis only. ⛔ **The code change was implemented, measured, and REVERTED** (§7): it does not fix the defect and no delivery improvement could be demonstrated.
- **Date:** 2026-08-07
- **Requirement:** FR-QOS (RELIABILITY), DDS 1.4 §2.2.3.14 — a RELIABLE reader receives every sample
- **Evidence:** `bench/report/2026-08-07-concurrent-writes-lose-samples-under-reliable.md`
- **Severity:** conformance defect, **pre-existing** (reproduced at `43fa6e0`)

---

## 1. The defect

`%data-pending-p` decides delivery with

```lisp
(> sn (max (gethash g (dr-drained dr) 0) join-watermark))
```

`dr-drained` is a **per-writer high-water mark**. A sample is delivered only if its SN exceeds the highest
SN drained so far for that writer, so once SN 50 is drained, **SN 45 arriving later is silently skipped
forever** — it sits undrained in the reader's node store while the application never sees it.

Measured: four threads × 30 writes to one DataWriter, RELIABLE + KEEP_ALL, deliver **107–116 of 120** (and
119/66/102/112/115 at `43fa6e0`). Single-threaded delivers 120/120 always, because one thread finishes each
`write-sample` before the next, so SNs arrive in order.

DDS 1.4 §2.2.2.4.2.11 places no single-thread restriction on `write`. This is ordinary supported usage.

⭐ The reordering was already understood — `%reader-advance-drained`'s docstring reasons about *"a lower SN
arriving late"* — but only for the **SAMPLE_LOST status**, never for **delivery**.

## 2. The decision

Replace the per-writer high-water **integer** with a small per-writer **window**: the high-water plus a
fixed-width bitmap of the SNs immediately below it.

```
drain-rec := (hw . mask)     ; mask bit i set  <=>  SN (hw - i) has been drained,  0 <= i < 30
```

- **delivered?(sn)** — `sn > hw` ⇒ no. `hw - sn >= 30` ⇒ yes (outside the window; see §4). Otherwise
  `(logbitp (- hw sn) mask)`.
- **note(sn)** — `sn > hw` ⇒ shift the mask left by `sn - hw`, set bit 0, `hw := sn`. Otherwise set bit
  `hw - sn`.

A sample that arrives out of order is now still pending, and is delivered exactly once.

## 3. ⛔ THE INVARIANT THIS MUST NOT BREAK — the Zero-Copy refcount's memory safety

`dds-disc` counts *eligible drainers* for a ZC loan's refcount using **`SN > join-watermark` alone**, and
`disc.lisp` states why that is safe:

> *"this omits the dcps-layer `dr-drained` term … and `dr-drained` can only RAISE the effective watermark;
> hence this count is a **SUPERSET** of the true drainers (`SN > max(dr-drained, wm)` implies `SN > wm`) and
> **NEVER a subset** — it can OVER-count"*

An over-count is safe (the slot is released late); an **under**-count is a cross-reader use-after-free.

So the new predicate **must keep `(> sn join-watermark)` as a hard, separate conjunct**:

```lisp
(and (> sn join-watermark)              ; UNCHANGED — preserves the ZC superset property
     (not (delivered-p rec sn)))        ; replaces (> sn high-water)
```

Written this way every DCPS drainer still satisfies `SN > wm`, so the eligible count remains a superset.
⛔ **Folding the watermark into the window would break that argument silently.**

## 4. Why a bounded window rather than a delivered-set

A full delivered-set is unbounded per writer — a leak on a long-lived reader, and NFR-MEM forbids
per-sample growth. A window is O(1) and bounded, and it is the shape the RTPS reliable *reader* already uses
for its own acknowledgement bookkeeping (a base plus a `SequenceNumberSet` bitmap, RTPS 2.5 §8.3.5.5).

**Width 30, deliberately.** The mask must stay a **fixnum** or the hot path allocates: with a 30-bit mask
and a shift below 30, the intermediate `(ash mask shift)` is under 2⁶⁰ and fits SBCL's 62-bit fixnum. A
64-bit mask would make the shift a bignum and put allocation back on the per-sample path — the exact cost
this campaign has spent the day removing.

A sample more than 30 SNs below the high-water is treated as delivered, i.e. **exactly today's behaviour**,
now confined to reordering deeper than any reliable in-flight window rather than applying to *all*
reordering.

## 5. Cost

- Per **writer**, not per sample: one 2-slot record (32 B) instead of a fixnum. O(matched writers).
- Per **sample**: the common in-order case tests `sn > hw` first and never consults the mask — the same
  single comparison as today. `gate-mem` must confirm all three arms are unmoved.

## 6. Verification

- The reproducer must deliver **120/120** on 4 threads × 30, repeatedly, and single-threaded must stay
  120/120.
- `run-writer-handle-race-test` gains the **delivery-count assertion** that was deliberately withheld while
  the defect was open — it becomes assertable exactly when this lands.
- Falsification: with the window narrowed to 0 (a pure high-water again) the count assertion must go red.
- `gate-mem` all three arms + both arches, unmoved; full suites on all three platforms.
- ⛔ A ZC arm must stay green (the §3 invariant): the existing Zero-Copy loan tests, run explicitly.


---

## 7. ⛔ IMPLEMENTED, MEASURED, AND REVERTED — the high-water is only ONE of several mechanisms

The §2 window was implemented in full (a `drain-rec` of high-water + a 30-bit fixnum mask, the §3
join-watermark conjunct preserved) and measured on the reproducer. **It does not fix the defect.**

| tree | 4 threads × 30, repeated |
|---|---|
| before | 113, 116, 107, 107, 108, 111, 112 |
| with the window | 89, 117, **120**, 115, 118 |

One run delivered everything; another delivered **89**, worse than anything measured before it. The variance
swamps any effect, so **no improvement can be claimed** — and this project does not land hot-path changes to
exactly-once machinery on an undemonstrated benefit.

### What the instrumentation proved, and it is the useful part

Counting reorder depth and out-of-window skips per run:

```
CONC got=97   DEPTH max-reorder-depth=22  out-of-window-skips=0
CONC got=118  DEPTH max-reorder-depth=90  out-of-window-skips=3000
```

⭐ **The first run lost 23 samples with a maximum reorder depth of 22 and ZERO out-of-window skips** — the
window covered every reordering that occurred, and the samples were lost anyway. **That falsifies "the
high-water is the cause" as a complete explanation**, whatever the width. Widening the window cannot help.

### A third mechanism, also pre-existing

Two runs died with `CDR codec error: unknown representation id #x5254`. **0x52 0x54 is `RT`, the first two
bytes of the RTPS magic** — the decoder is reading a *datagram header* as a SerializedPayload, i.e. a
payload reference pointing at recycled or wrong bytes. It appeared **before** this ADR existed (the first
run of the extended concurrent arm), so it is not caused by the window.

### Where that leaves it

At least **three** distinct mechanisms are in play under concurrent writes: the high-water (real, fixed by
§2, insufficient), something that loses samples with no reordering-window involvement at all, and an
intermittent RX payload-reference corruption. The §2 window remains the right *structure* — a high-water
cannot express "delivered" — but it should land only as part of a fix that is demonstrated end-to-end,
not before the other mechanisms are understood.

**§3's ZC invariant stands regardless** and must be honoured by any future attempt: the join-watermark has
to remain its own conjunct, or the Zero-Copy refcount's superset property breaks silently.
