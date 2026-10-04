# SHMEM lane poisoning: the cursor checks cost 2–8 ns per record on SBCL, 11–24 ns on AllegroCL

**WP-0.7 · ADR 0119 · NFR-SEC-POSTURE / FR-LANG-7 · Linux x86_64 (Intel Xeon Gold 5122 @ 3.60 GHz, 16
threads), SBCL 2.2.9.debian and AllegroCL 11.0 (alisp) · isolated ring primitives, nothing else running
on the host**

This is a **correctness** change with a measured cost. It is not an optimisation. The report exists because
`%lane-drain` and `%lane-enqueue` sit in a gate-hotpath file, and the operating contract requires a
before/after number for any hot-path change, including when the number goes the wrong way.

## What changed on the hot path

- `%lane-drain`, per record: an alignment test `(logtest pos 7)` and an extent test `(> (+ pos 4)
  capacity)` before the length read; a pad-versus-committed test on a skip marker; one extra branch splitting
  the old combined length check into `:bad-record-length` and `:record-overruns-commit`; and `r` advanced
  *before* the handler call instead of after it.
- `%lane-drain`, per call: an `unwind-protect` around the record loop (the read cursor is stored on every
  exit), a `w < r` test, and the record bound computed from the trusted capacity instead of loaded from the
  shared header. That replaces one shared-memory load with a subtraction.
- `%lane-enqueue`, per record: one `(logtest w 7)`. The lane count comes from the caller instead of a
  header load.
- `shmem-receive-drain`, per lane per wake: one `svref` of the poison vector.

No allocation was added. The two per-lane vectors are allocated once, when the transport is created.

## Method

This is an interleaved A/B in **one process per implementation**. HEAD's `%lane-enqueue` and `%lane-drain`
were copied verbatim and renamed `old-lane-enqueue` / `old-lane-drain`. They were compiled under the same
`defun*` (so the same declarations and optimisation policy as the system), with `compile-file` on both Lisps.
Each arm drives one lane of a 65 536-octet ring in a static (`alloc-static`) region, with a 64-octet
static-backed payload. Each pass enqueues BATCH records and then makes one drain call. There are 2 000
warm-up passes and then the timed loop: 1 000 000 passes at batch 1, 20 000 passes at batch 64. The arms
alternate BEFORE, AFTER, BEFORE, … five times. `ns/record` is `monotonic-ns` over the loop divided by the
records delivered, and it **includes the enqueue** (a drain cannot be timed without records to drain).
`B/record` is the `bytes-consed` delta.

The harness is in the repository: `bench/shmem-lane-ab/old-ring.lisp` (the BEFORE arm, HEAD's two
functions with only the names changed, checked with `diff`) and `bench/shmem-lane-ab/ab-bench.lisp` (the
loop above). Reproduce with `bench/shmem-lane-ab/run.sh ./scripts/with-sbcl.sh` or
`bench/shmem-lane-ab/run.sh ./scripts/with-allegro.sh`.

The two tables directly below are the first run, made before review. Review then changed `%lane-enqueue`'s
record bound from `(> (+ 4 len) capacity)` to `(> len (- capacity 8))` (ADR 0119 §3), one compare replaced by
one compare. The re-run with the committed harness on the final code is in
[Re-run on the final code](#re-run-on-the-final-code-committed-harness), and the end-to-end `make
bench-shmem` before/after is in [End to end](#end-to-end-make-bench-shmem-sbcl).

## SBCL 2.2.9 — ns per record (enqueue + drain), 5 interleaved runs

| batch | arm | run 1 | run 2 | run 3 | run 4 | run 5 | **median** | B/record |
|---|---|---|---|---|---|---|---|---|
| 1 | before | 347.26 | 358.25 | 347.61 | 348.08 | 343.33 | **347.61** | 0.0000 |
| 1 | after | 352.40 | 346.71 | 349.72 | 350.34 | 349.62 | **349.72** | 0.0000 |
| 64 | before | 273.20 | 268.56 | 272.93 | 272.85 | 271.92 | **272.85** | 0.0000 |
| 64 | after | 292.49 | 280.66 | 280.93 | 280.90 | 280.73 | **280.90** | 0.0000 |

- **batch 1: +2.1 ns/record (+0.6 %).** The run-to-run spread is 15 ns, so this is inside the noise.
- **batch 64: +8.1 ns/record (+3.0 %).** The difference is consistent: every AFTER run is above every
  BEFORE run. At batch 64 the per-record checks dominate the per-call `unwind-protect`, which is the
  expected shape.
- **0 B/record in both arms**, and SBCL's counter is exact.

## AllegroCL 11.0 — ns per record (enqueue + drain), 5 interleaved runs

| batch | arm | run 1 | run 2 | run 3 | run 4 | run 5 | **median** |
|---|---|---|---|---|---|---|---|
| 1 | before | 1121.62 | 1191.22 | 1150.92 | 1177.20 | 1167.85 | **1167.85** |
| 1 | after | 1174.42 | 1194.52 | 1175.74 | 1181.30 | 1195.51 | **1181.30** |
| 64 | before | 1014.17 | 1040.95 | 1017.85 | 1041.00 | 1015.22 | **1017.85** |
| 64 | after | 1019.84 | 1031.14 | 1027.23 | 1033.39 | 1030.98 | **1030.98** |

- **batch 1: +13.5 ns/record (+1.2 %). batch 64: +13.1 ns/record (+1.3 %).** The spread within each arm is
  27–70 ns, so the medians move by less than one run's spread.
- `B/record` printed 0.0000 in both arms, but that zero is uninformative. On AllegroCL,
  `dds.pal:bytes-consed` does not move for this workload: `run-bench-shmem`'s docstring in
  `src/dds-bench/perftest.lisp` documents the gap, and WP-0.12's gate-mem canary is designed to expose it.
  So **no allocation claim is made for AllegroCL here**, and the column is left out rather than shown as a
  misleading zero. The allocation argument for AllegroCL is structural: the diff adds no allocating form to
  the per-record path, and gate-hotpath passes.
- AllegroCL's ring primitive costs about 3.4× SBCL's in absolute terms, with or without this change. That
  gap already existed; this change did not introduce it.

## Re-run on the final code (committed harness)

`bench/shmem-lane-ab/run.sh`, one process per implementation, 5 interleaved runs, same host, nothing else
running. ns per record (enqueue + drain):

| Lisp | batch | before runs | after runs | before **median** | after **median** | delta |
|---|---|---|---|---|---|---|
| SBCL | 1 | 343.69 342.65 343.30 343.95 343.40 | 344.53 346.18 344.99 344.66 345.25 | **343.40** | **344.99** | +1.6 ns (+0.5 %) |
| SBCL | 64 | 272.75 272.28 273.31 272.96 272.13 | 277.16 282.78 277.28 277.17 277.77 | **272.75** | **277.28** | +4.5 ns (+1.7 %) |
| AllegroCL | 1 | 1189.19 1098.16 1092.20 1092.27 1092.61 | 1116.95 1118.87 1113.32 1118.38 1116.27 | **1092.61** | **1116.95** | +24.3 ns (+2.2 %) |
| AllegroCL | 64 | 998.99 962.23 959.33 976.25 966.20 | 991.18 977.23 970.79 976.99 973.53 | **966.20** | **976.99** | +10.8 ns (+1.1 %) |

SBCL: 0 B/record in both arms. AllegroCL: no allocation claim, for the reason given above. The direction
and the order of magnitude match the first run (SBCL a few ns per record, AllegroCL one to two per cent).

## End to end: `make bench-shmem` (SBCL)

`make bench-shmem` (`run-bench-shmem`, default `LATSAMPLES=10000`, `THRUSAMPLES=20000`) was run on a
`git archive` export of HEAD 78895e0 (before) and on this working tree (after), alternating, in two series:
six unpinned pairs, then four pairs pinned with `taskset -c 2-5`. Medians over each series; SHMEM columns
only (the UDP columns do not touch the changed code and are shown as a noise reference).

| row | series | before median | after median | before range | after range |
|---|---|---|---|---|---|
| SHM p50 latency 16 B (ns) | unpinned ×6 | 15 182 | 15 594 | 13 245–18 133 | 13 412–18 244 |
| SHM p50 latency 64 B (ns) | unpinned ×6 | 16 113 | 16 022 | 14 557–17 818 | 14 415–17 965 |
| SHM p50 latency 256 B (ns) | unpinned ×6 | 13 930 | 17 536 | 13 490–17 778 | 13 863–17 951 |
| SHM p50 latency 1024 B (ns) | unpinned ×6 | 14 390 | 18 394 | 13 323–18 156 | 13 992–19 005 |
| SHM p50 latency 16 B (ns) | pinned ×4 | 16 572 | 17 550 | 14 944–18 060 | 15 396–18 948 |
| SHM p50 latency 64 B (ns) | pinned ×4 | 16 545 | 18 536 | 15 561–19 497 | 16 915–19 842 |
| SHM p50 latency 256 B (ns) | pinned ×4 | 17 949 | 16 938 | 16 649–18 496 | 15 271–21 250 |
| SHM p50 latency 1024 B (ns) | pinned ×4 | 17 770 | 16 606 | 15 272–20 651 | 14 090–19 226 |
| SHM samples/s 64 B batch 1 | unpinned ×6 | 92 214 | 90 098 | 76 359–100 323 | 65 526–98 840 |
| SHM samples/s 64 B batch 100 | unpinned ×6 | 186 375 | 193 118 | 106 988–228 038 | 139 744–281 572 |
| SHM samples/s 256 B batch 1 | unpinned ×6 | 90 796 | 74 304 | 75 544–105 579 | 69 848–80 732 |
| SHM samples/s 1024 B batch 1 | unpinned ×6 | 105 984 | 90 448 | 94 434–115 732 | 79 409–113 258 |
| SHM samples/s 64 B batch 1 | pinned ×4 | 63 908 | 73 825 | 59 735–78 474 | 68 334–84 769 |
| SHM samples/s 64 B batch 100 | pinned ×4 | 211 621 | 170 154 | 98 337–282 216 | 140 725–336 347 |
| SHM samples/s 256 B batch 1 | pinned ×4 | 75 646 | 64 162 | 69 203–82 144 | 59 476–84 468 |
| SHM samples/s 1024 B batch 1 | pinned ×4 | 86 954 | 93 361 | 78 594–99 105 | 85 553–99 624 |

SHMEM bytes-consed per sample (whole path, all threads) is unchanged: 3 216–3 330 B at 16/64 B, about
3 700 B at 256 B and about 5 230 B at 1024 B in both arms. That allocation predates this change and lies
outside the ring primitives.

**What this shows.** The end-to-end bench cannot resolve a change of a few ns per record. Its p50 is
bimodal (runs land near 13.5 µs or near 17.5 µs in both arms), and the run-to-run spread within one arm is
20–60 % on throughput. Rows move in both directions between the series: 256 B and 1024 B latency is worse
after in the unpinned series and better after in the pinned one, and 1024 B throughput reverses the same
way. One row is lower after in **both** series: 256 B one-way throughput, by 18 % unpinned and 15 % pinned.
The ranges overlap in both series, and the pinned UDP arm, which does not run the changed code, also
dropped 10 % between the same runs (90 777 → 81 212 samples/s). The isolated A/B bounds the ring-primitive
cost at about 5 ns per record on SBCL, which is 0.04 % of the roughly 13 µs per sample at that rate and
cannot account for an effect of that size. That row is recorded here as **unresolved noise, not as a
demonstrated regression**. If a later run reproduces it with a tighter method, it needs its own
investigation.

## In context

The SHMEM one-way latency of this transport is measured in microseconds. The docstring of
`*shmem-rx-spin-iterations*` records 11.8 µs p50 at 256 B, measured on the earlier macOS development host,
not on this one. At that order of magnitude, +8 ns per record on SBCL is under 0.1 %.
Two things are bought for it:

1. **An out-of-bounds read is closed.** HEAD's drain raised SIGBUS on both implementations for a read
   cursor of `capacity - 1/2/3` on a lane ending at end-of-file (ADR 0119 §7).
2. **A silent, permanent wedge is closed, and it was a CPU burn as well.** A detected corruption used to
   leave the lane stuck with `w ≠ r`, so the receiver never parked and spun at full CPU. Now the lane is
   poisoned, counted, logged once and quarantined, and its sender falls back to UDP.

## Where the 8 ns could go if it ever matters

`(> (+ pos 4) capacity)` is implied by the alignment test whenever the capacity is a multiple of 8, which
`%ring-init` enforces. It is kept because the work package names it and it is one compare. Hoisting the
alignment test from per-record to a single check of `r` on entry would also be sound, because the record
loop only ever adds 8-aligned spans and skip pads. Neither is done here: making a security check cheaper
should be its own measured change, not bundled with the fix.
