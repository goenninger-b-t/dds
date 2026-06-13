# M5 / P4 — Performance differentiators — milestone plan

Authoritative sources: REQUIREMENTS.md §P4 (FR-PF-*, NFR-PERF table, NFR-MEM), IMPLEMENTATION-PLAN.md
§M5 (build order, WP list, exit gate, R6). This plan opens M5; it does NOT begin a WP until the owner
picks the starting point and rules on the patent gate (below).

## M5 exit gate (IMPLEMENTATION-PLAN §M5)
NFR-PERF-1,4,5,6,7,8 met on **SBCL + AllegroCL**; NFR-PERF-2 met; NFR-PERF-3 measured + gap documented;
Zero-Copy and FlatData interop-validated with Connext where wire-compatible; pre-allocation mode shows
**0 bytes/sample** steady-state (allocation counters) on SBCL+Allegro; hot-path workload runs entirely
from the static arena (high-water within `*static-arena-bytes*`).

## Two gating realities (decide first)

1. **Measurement is the milestone.** Every P4 acceptance is an NFR-PERF number, and FR-LANG-7 forbids
   landing a perf change without a before/after bench. `make bench` is currently a stub. So a minimal
   **perftest + allocation harness (WP-PERFTEST)** is a prerequisite for *quantifying* batching and
   everything after it — it is the natural WP-0 even though the plan lists features first.
2. **Patent gate (R6, gating P4 ship).** FR-PF-3 Zero-Copy-over-SHMEM and FR-PF-4 FlatData mirror RTI's
   patented mechanisms; REQUIREMENTS §NFR-IP + IMPLEMENTATION-PLAN R6 mandate **counsel review before
   shipping** these two. I cannot clear patents. The owner must choose how to sequence them.

## Work packages (IMPLEMENTATION-PLAN build order) + patent status

| # | WP | FR | Patent-gated? | Dep |
|---|----|----|----|-----|
| 0 | **WP-PERFTEST** — latency PING/PONG (one-way), max-throughput, latency-vs-throughput, alloc/GC counters; parity report vs Connext on identical HW | NFR-PERF-1..9, FR-LANG-7 | no | stable L4–L7 (have it) |
| 1 | **WP-BATCH** — multiple SAMPLES per DATA submessage payload (RTI-style batch), small-sample throughput | FR (P4), NFR-PERF-4 | no | WP-PERFTEST |
| 2 | **WP-ASYNC** — sender thread/queue decoupled from write() + token-bucket flow controllers | FR-PF-2 | no | WP-BATCH |
| 3 | **WP-FRAGPACE** — DATA_FRAG fragmentation pacing (coordinate w/ the reliable engine) | FR-PF-2 | no | WP-ASYNC; DATA_FRAG (done) |
| 4 | **WP-SHMEM** — shared-memory transport for intra-host (PAL SHMEM segment create/attach) | FR-XPORT-2 | no (transport itself) | transport record (have it) |
| 5 | **WP-ZEROCOPY** — writer SHMEM segment + ~16-byte references, loan/return pool | FR-PF-3 | **YES — legal review before ship** | WP-SHMEM |
| 6 | **WP-FLATDATA** — in-memory == wire layout; compiler emits Offset accessors + Builder | FR-PF-4 | **YES — legal review before ship** | WP-GEN (A5) |
| 7 | **WP-LZ4** — serialization-time LZ4 compression | FR (P4) | no | LZ4 binding (new dep) |

`0-alloc steady state` (NFR-PERF-8 / NFR-MEM) and the static-arena high-water assertion are cross-cutting
acceptance criteria checked by WP-PERFTEST for every feature.

## Recommended sequence
WP-PERFTEST (measure) → WP-BATCH → WP-ASYNC → WP-FRAGPACE → WP-SHMEM → WP-LZ4 →
[**legal gate**] → WP-ZEROCOPY → WP-FLATDATA. This front-loads measurement, ships every
patent-clean feature first, and quarantines the two encumbered WPs behind the legal review so the
milestone is not blocked waiting on counsel.

## Module layout (IMPLEMENTATION-PLAN §ASDF)
`dds-bench/` (WP-PERFTEST), `dds-feat-batching/`, `dds-feat-async/`, `dds-xport-shmem/`,
`dds-feat-zerocopy/`, `dds-feat-flatdata/`, `dds-feat-lz4/` — each its own ASDF system, A10/A9/A5 roles.

## Process (unchanged)
Per WP: brainstorm→spec→plan→subagent execute; contract-first (freeze the WP interface before fan-out);
two reviews/task; before/after bench in `bench/report/`; commits presented for approval; clean-room;
wire-is-oracle; gates green on SBCL+Clasp (Allegro where the licensed build is available — flag if not).

## Owner decisions (2026-06-13)
- **Starting WP = WP-PERFTEST** (measurement-first). In progress.
- **Patent gate = design-now/gate-the-ship**: WP-ZEROCOPY + WP-FLATDATA are built behind an off-by-default
  flag with provenance + an explicit "NOT cleared for ship — pending counsel (R6)" marker, ready for when
  legal clears them. They still come LAST (after the patent-clean WPs).

## Open questions for the owner
1. **AllegroCL** is a co-equal M5 pacesetter and the exit gate names SBCL+Allegro. Is the licensed
   Allegro build available in this environment? (If not, M5 perf gates run SBCL-only with a documented
   Allegro gap, mirroring the Clasp NFR-PORT latitude.)
2. **Patent gate**: defer WP-ZEROCOPY + WP-FLATDATA until counsel clears them (recommended), or
   build-now/gate-ship, or skip for this milestone.
3. **Starting WP**: WP-PERFTEST (measurement-first, recommended) or WP-BATCH (plan's first feature).
