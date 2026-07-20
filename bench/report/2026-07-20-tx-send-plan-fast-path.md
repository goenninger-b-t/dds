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

## Slice 2 (same day) — inline HEARTBEAT on the fast path: −87 B (3298 → 3211)

Re-profiling (`sb-sprof :mode :alloc`) after slice 1 put `%push-one-writer-changes` at #1 (10.6 % self): it
built a fresh HEARTBEAT pack closure per send (`%heartbeat-builder`). The fast path now writes the HB inline
(`%write-hb-submessage`, extracted DRY); the closure is built lazily only on the plan fallback.

| arm (samples=5000, warmup=500) | bytes/sample |
|---|---:|
| FAST-OFF (plan) | 3577.6 |
| FAST-ON (HB inline) — run 1 | 3250.1 |
| FAST-ON (HB inline) — run 2 | 3242.9 |
| FAST-ON (HB inline) — run 3 | 3250.1 |
| **official `gate-mem`** | **3210.8** |

**Cumulative: 3560 → 3211 = −349 B/sample (~10 %)** across the two slices. arm64 ceiling ratcheted 3360 → 3290.
`%send-changes-packed`'s HB param went `(SIZE . closure)` → three `hb-first/last/count` ints; both callers
updated; 568/568 both impls, byte-identity + corpus green.

## Slice 3 (same day) — memoize the send-destination union: −66 B (3211 → 3145)

`%match-destinations-prefixed` (matched-participant locators ∪ static peers) rebuilt the whole list —
`subseq` ×2 per endpoint + `find`/`member` + conses — on every send / HB / ACKNACK / retransmit (6 callers),
for a value that changes only on match/unmatch or a participant's advertised locators. Now memoized per
`want-readers` on the node, invalidated wholesale (the `reader-routes-cache` pattern) — a stale destination
is silent mis-delivery, so invalidation is coarse and gated.

| arm (samples=5000, warmup=500) | bytes/sample |
|---|---:|
| MEMO-OFF (global, all threads) | ~3225 |
| MEMO-ON (A/B, cache-forever ceiling) | ~3125 |
| **official `gate-mem` (shipped, invalidating)** | **3145.2** |

**Cumulative: 3560 → 3145 = −415 B/sample (~11.7%)** across the three slices. arm64 ceiling 3290 → 3220.
Invalidation gated by `run-match-dest-cache-invalidation-test` (deterministic) + the live late-joiner /
N-reader integration tests. 568+/568+ both impls; corpus green.

### Measurement lesson (again): the flag must be effective where the code runs

The first destination A/B `let`-bound the memo flag on the main thread and read as a no-op — but
`%match-destinations-prefixed` runs on the receiver/TX threads (the ACKNACK path), which a thread-local
dynamic binding never reaches. Only setting the special **globally** (visible to all threads) revealed the
~100 B. Same family as the slice-1 SHMEM-vs-UDP miss: prove the flag's effect reaches the code before trusting
a null A/B.

## Slice 4 (same day) — memoize the TX push grouping: −185 B (3145 → ~2960)

`%reader-push-targets` (per-destination reader-key grouping the TX push builds every send) memoized per topic
on the node, reusing slice 3's `%invalidate-dest-cache` + generation. **gate-mem 3145 → 2948–2970**
(biggest slice). **Cumulative 3560 → ~2960 = −600 B/sample (~17%).** arm64 ceiling 3220 → 3030.

**This slice caught a real latent silent-mis-delivery bug.** Both dest memos read `disc-node-matches`, but the
match funnel invalidates (via `%reader-route-add`) ONLY for a matched remote *writer*; a matched remote
*reader* (our writer's new push target) reached only `%record-match`, which didn't invalidate — so a reader
matching a writer that had already sent would be silently dropped. Happy-path tests miss it (memo populated
after all matches); `run-push-spdp-peer-isolation-test` caught it on both impls. Fixed by invalidating in
`%record-match` (the choke point) + a `%record-match` assertion in the invalidation test. The full-suite run
is the gate that earned its keep here.

## Note

The first cut gated on `(null shmem-dest)` (UDP only) and measured as a no-op — because `mem-per-sample`
routes over SHMEM by default, so the UDP-only branch never fired. The corrected, transport-agnostic fast
path fires and banks the win. See ADR 0062 "LANDED / the near-miss" for the lesson: prove the flag's branch
is *reached in the harness* before trusting a null A/B.
