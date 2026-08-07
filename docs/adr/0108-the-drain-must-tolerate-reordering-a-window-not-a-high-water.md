# ADR 0108 — The drain's exactly-once record must tolerate reordering: a WINDOW, not a high-water mark

- **Status:** **Accepted** (revised — the first attempt, a 30-bit shifted mask, was implemented, measured,
  reverted, and is kept in §7 as the record of why)
- **Date:** 2026-08-07
- **Requirement:** FR-QOS (RELIABILITY), DDS 1.4 §2.2.3.14 — a RELIABLE reader receives every sample
- **Evidence:** `bench/report/2026-08-07-two-defects-under-concurrent-writes.md`
- **Severity:** conformance defect, **pre-existing** (reproduced at `43fa6e0`)
- **Related:** **ADR 0109** — the second, independent defect. Neither fix works without the other.

---

## 1. The defect

`%data-pending-p` decided delivery with

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

Replace the per-writer high-water **integer** with a per-writer **circular delivered-set window**: a
high-water plus a fixed 1024-bit bitmap indexed by `SN mod 1024`.

```
drain-rec := (hw . bits)      ; bits: (simple-array (unsigned-byte 64) (16)), bit (sn mod 1024) = delivered
```

- **delivered?(sn)** — `sn > hw` ⇒ no. `hw - sn >= 1024` ⇒ yes (older than the window; see §4). Otherwise
  the bit at `sn mod 1024`.
- **note(sn)** — `sn > hw` ⇒ **clear** the bits the window scrolled past (the SNs in `(hw, sn)`, which are
  not delivered and whose bit positions still hold verdicts from one full window earlier), set `sn`'s bit,
  `hw := sn`. Otherwise just set `sn`'s bit.

This is the anti-replay-window shape of RFC 4303 Appendix A2. It is **circular**, so advancing the
high-water never shifts the bitmap — the in-order step (`sn = hw + 1`) scrolls past nothing, clears
nothing, and touches exactly one bit.

## 3. ⛔ THE INVARIANT THIS MUST NOT BREAK — the Zero-Copy refcount's memory safety

`dds-disc` counts *eligible drainers* for a ZC loan's refcount using **`SN > join-watermark` alone**, and
`disc.lisp` states why that is safe:

> *"this omits the dcps-layer `dr-drained` term … and `dr-drained` can only RAISE the effective watermark;
> hence this count is a **SUPERSET** of the true drainers (`SN > max(dr-drained, wm)` implies `SN > wm`) and
> **NEVER a subset** — it can OVER-count"*

An over-count is safe (the slot is released late); an **under**-count is a cross-reader use-after-free.

So the new predicate **keeps `(> sn join-watermark)` as a hard, separate conjunct**:

```lisp
(and (> sn join-watermark)              ; UNCHANGED — preserves the ZC superset property
     (not (delivered-p rec sn)))        ; replaces (> sn high-water)
```

Written this way every DCPS drainer still satisfies `SN > wm`, so the eligible count remains a superset.
⛔ **Folding the watermark into the window would break that argument silently.**

Note the window makes *more* readers drain than before, never fewer — previously-skipped reordered samples
now drain — and every one of them already satisfied the watermark conjunct, so the superset holds a
fortiori.

## 4. Why a bounded circular window rather than a delivered-set

A full delivered-set is unbounded per writer — a leak on a long-lived reader, and NFR-MEM forbids
per-sample growth. A window is O(1) and bounded, and it is the shape the RTPS reliable *reader* already uses
for its own acknowledgement bookkeeping (a base plus a `SequenceNumberSet` bitmap, RTPS 2.5 §8.3.5.5).

**Width 1024, from measurement.** The first attempt used 30 — sized so a shifted mask stayed inside a
fixnum — and **that was too narrow**: instrumentation measured reordering **90 sequence numbers deep** on
four threads, and a 30-wide window recovered only part of the loss (UDP went 93–96 → 101–111, not 120).
1024 bits is 16 words = **128 octets per matched writer**, allocated once, never per sample. The circular
form removes the shift entirely, so the fixnum constraint that forced 30 no longer applies at all.

A sample more than 1024 SNs below the high-water is treated as delivered, i.e. **exactly the pre-window
behaviour**, now confined to reordering deeper than any plausible in-flight reliable window.

## 5. Cost

- Per **writer**, not per sample: one cons + one 128-octet bitmap. O(matched writers).
- Per **sample**: the common in-order case tests `sn > hw` first and never touches the bitmap — the same
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

## 7. ⛔ THE FIRST ATTEMPT — implemented, measured, reverted (kept as the record)

The original §2 proposed a **30-bit fixnum mask, shifted on advance**. It was implemented in full (the §3
join-watermark conjunct preserved) and measured on the reproducer. **It did not fix the defect.**

| tree | 4 threads × 30, repeated |
|---|---|
| before | 113, 116, 107, 107, 108, 111, 112 |
| with the 30-bit window | 89, 117, **120**, 115, 118 |

One run delivered everything; another delivered **89**, worse than anything measured before it. The variance
swamped any effect, so no improvement could be claimed, and it was reverted rather than shipped on an
undemonstrated benefit.

### What the instrumentation proved, and it is the useful part

```
CONC got=97   DEPTH max-reorder-depth=22  out-of-window-skips=0
CONC got=118  DEPTH max-reorder-depth=90  out-of-window-skips=3000
```

⭐ **The first run lost 23 samples with a maximum reorder depth of 22 and ZERO out-of-window skips** — the
window covered every reordering that occurred, and the samples were lost anyway. That was read at the time
as *"the high-water is not the whole cause, whatever the width"*, and half of that was right.

## 8. Why it failed, and why that was TWO things at once

The reading in §7 was correct that something else was also losing samples, and wrong to conclude the
window's *width* did not matter. **Both were true, and each hid the other:**

1. **ADR 0109 — the SHMEM lane enqueue was racing.** `%lane-enqueue` is a single-producer ring and the send
   path entered it from every writer thread; two producers resolved the same ring position and one datagram
   was destroyed outright. That loses samples with **no reordering at all**, which is exactly the
   "depth 22, zero out-of-window skips, 23 lost" signature above. No drain-side fix could ever have
   recovered a datagram that was never in the ring.
2. **The width was genuinely too small.** Depth 90 > 30. Once ADR 0109 was fixed, the 30-bit window still
   left UDP at 101–111 of 120; widening to 1024 took it to **120/120**.

⭐ **The methodological lesson: with two independent defects in one path, fixing either alone shows nothing,
and the natural inference from "my fix changed nothing" — that the diagnosis was wrong — is itself wrong.**
A transport bisect (SHMEM on vs off) separated them in one run and should have been the first move: it
showed the loss on *both* transports (so a transport-independent cause exists) *and* corruption on only one
(so a transport-specific cause also exists).

## 9. As-built

`+drain-window-bits+` 1024 / `+drain-window-words+` 16 / `drain-bitmap` / `%drain-bit-ref` /
`%drain-bit-put` / `%make-drain-record` / `%drained-delivered-p` / `%drained-note` in `dds-dcps/entities.lisp`,
with `%reader-advance-drained` and `%data-pending-p` rewritten onto them.

Measured with ADR 0109 also applied, 4 threads × 30, one DataWriter, RELIABLE + KEEP_ALL:

| arm | before both fixes | after both fixes |
|---|---|---|
| UDP (`*shmem-enabled*` NIL) | 96, 94, 95, 93, 120 | **120 × 8** |
| SHMEM | 111, 42, 108, 98, 104 (+1 run corrupt in 5) | 120 ×7, 113 (no corruption in 16) |
