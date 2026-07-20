# TX send-plan flattening — single-datagram fast path (ADR 0062, task #29)

**Date:** 2026-07-20 · **Arch:** arm64 (Apple Silicon) · **Impl:** SBCL · **Oracle:** `./scripts/gate-mem.sh`
(`dds.bench:mem-per-sample`, two co-located participants over the default SHMEM transport, reliable).

## Change

`%send-changes-packed` gains a fast path for the common case — exactly one small non-ZC change (+ the
optional trailing HEARTBEAT) fitting a single budget-bounded datagram to one destination — that writes the
datagram directly and skips `%changes-datagram-plan`'s `items` list, `%pack-plan` group list, per-group
`(lambda …)` closure, and the `state`/dest conses. The `%data-builder` closure body was factored into a
named `%write-change-submessage` (+ `%change-submessage-size`) so the fast path and the plan use the same
writers and size arithmetic — byte-identical by construction, and DRY. Works on both UDP and SHMEM
(`shmem-dest` is threaded to `%send-raw-buf`; the datagram bytes are transport-independent).

## Measurement — `gate-mem` A/B (`*tx-fast-path*` toggle), default SHMEM harness

| arm (samples=5000, warmup=500) | bytes/sample |
|---|---:|
| FAST-OFF (forced plan path) — run 1 | 3577.5 |
| FAST-OFF (forced plan path) — run 2 | 3577.6 |
| FAST-ON (fast path) — run 1 | 3276.0 |
| FAST-ON (fast path) — run 2 | 3315.5 |
| **official `gate-mem` (FAST-ON default)** | **3298.0** |

**Win: −262 B/sample (3560 baseline → 3298), ~7.4 % of the per-sample budget.** Well above the ±~22 B
measurement noise. arm64 ceiling ratcheted **3600 → 3360** (`bench/mem-ceiling.txt`).

## Correctness

- `run-tx-fast-path-equivalence-test` (new): the fast-path datagram sequence is byte-identical to the
  `*tx-fast-path*`-NIL forced-plan sequence (captured via `*datagram-sink*`), and is ONE datagram of
  1 DATA + 1 HEARTBEAT.
- `run-flow-step-equivalence-test`, `run-coalesce-pack-test` unchanged and green.
- 567/567 SBCL + Clasp; gate-build (clean cache, both impls) + gate-types + gate-nocond (0) green.

## Note

The first cut gated on `(null shmem-dest)` (UDP only) and measured as a no-op — because `mem-per-sample`
routes over SHMEM by default, so the UDP-only branch never fired. The corrected, transport-agnostic fast
path fires and banks the win. See ADR 0062 "LANDED / the near-miss" for the lesson: prove the flag's branch
is *reached in the harness* before trusting a null A/B.
