# The Connext ratio table, current (supersedes 2026-07-12)

2026-07-13, `83efe14`. SBCL, macOS arm64, both stacks cross-process, RELIABLE / KEEP_ALL / VOLATILE, single
in-flight, one-way := RTT/2, 4000 samples + 500 warmup, nearest-rank percentiles by the identical rule.
**Both stacks on their default transport (SHMEM for same-host).** Ours with the shipped default
`*shmem-rx-spin-iterations*` = 1000.

## Median — the headline

| payload | ours p50 | Connext p50 | **ratio** | ratio at session start |
|---|---|---|---|---|
| 32 B | 9 250 ns | 6 333 ns | **1.46×** | 1.91× |
| 256 B | 9 625 ns | 6 896 ns | **1.40×** | 3.20× |
| 1 KB | 9 437 ns | 7 062 ns | **1.34×** | **15.2×** |
| 4 KB | 11 208 ns | 7 062 ns | **1.59×** | **65×** |
| 16 KB | **stalls** (bug #15) | 8 062 ns | — | 114× |

**We are now 1.34–1.59× of Connext on the median from 32 B to 4 KB**, against 1.9×–114× at the start of the
day. The 5 % mandate (≤1.05×) is **still not met**, but the gap is now ~2.5–4 µs, not a factor of 15–114.

## p99

| payload | ours | Connext | ratio |
|---|---|---|---|
| 32 B | 20 750 ns | 14 187 ns | 1.46× |
| 256 B | 24 395 ns | 16 250 ns | 1.50× |
| 1 KB | 21 500 ns | 15 416 ns | 1.39× |
| 4 KB | 24 229 ns | 14 958 ns | 1.62× |

Tracks the median. Nothing pathological.

## THE TAIL — we are 15–60× WORSE, and this is now the biggest single weakness

At 4000 samples the nearest-rank p99.99 **is** the max, so these are the worst observed samples:

| payload | ours | Connext |
|---|---|---|
| 32 B | **9 293 708 ns** | 173 104 ns |
| 256 B | **10 112 500 ns** | 227 625 ns |
| 1 KB | **9 315 542 ns** | 160 042 ns |
| 4 KB | **9 604 583 ns** | 194 354 ns |

**Our worst sample is ~9–10 ms. Connext's is ~0.16–0.6 ms.** A ~9 ms outlier on every run, at every payload
size, is the signature of a **GC pause**, not of jitter — and `REQUIREMENTS.md` §7 predicted exactly this
("a GC'd runtime cannot, in general, match a pre-alloc C++ stack on tail latency").

This is the honest state of the withdrawn tail claim (#14): the earlier "we beat Connext's tail by 2.2×" was
never real, and the truth is the opposite — **we lose the tail by more than an order of magnitude.** The spin
fix removed the *scheduler* jitter (run-to-run spread collapsed to ±40 ns, p99 improved), but it cannot touch
a GC pause. Driving the remaining steady-state allocation to zero is the only lever that will.

## What is blocked

**16 KB stalls** (`no echo within 5 s`) — bug #15, pre-existing and intermittent, reproduced on an unmodified
baseline. It blocks the large-payload row entirely, which is precisely where the codec and SHMEM fixes should
look best (4 KB alone went 65× → 1.59×).

## Caveats

Single machine, single-in-flight, loopback. This box measured 16–32 µs for identical code earlier in the day;
the spin has since made our numbers very stable (±40 ns), but Connext's runs carry the usual noise. The
payload sizes changed slightly with ADR 0061 (a non-4-aligned body now carries 1–3 more octets) — immaterial
at these sizes, but the numbers are not bit-comparable with the 2026-07-12 table.
