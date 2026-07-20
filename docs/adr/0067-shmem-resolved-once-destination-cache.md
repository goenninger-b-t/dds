# ADR 0067 — the SHMEM sender resolves its destination once, not per datagram

- **Status:** Accepted
- **Date:** 2026-07-20
- **Requirements:** NFR-MEM, NFR-PERF-8, FR-XPORT-2, NFR-SEC-POSTURE
- **Relates to:** ADR 0062 (the allocation budget), 0065/0066 (the UDP datagram-syscall slices)
- **Contract touched:** `DDS.XPORT.SHMEM` internals only — `%attach-for` now returns a `shmem-dest`;
  `*shmem-dest-cache*` and `run-shmem-dest-cache-test` added. No public API, no ring format change.

## Context

ADR 0065 and 0066 removed the per-datagram allocation from the UDP send and receive paths. That changed
which transport is expensive. A free A/B — flip the existing `dds.disc:*shmem-enabled*` and re-measure,
no code change — showed:

| transport | B/sample |
|---|---|
| SHMEM (the default, and what `gate-mem` measures) | **2577.3** |
| pure UDP | **2446.4** |

**The intra-host transport that exists for speed had become 131 B/sample more expensive than the network
one.** Not because SHMEM regressed — because UDP got cheap and nobody re-looked.

Reading `%shmem-send` rather than the profiler found why. Per datagram it did:

```lisp
(let* ((sap (dds.pal:shm-sap dest))                      ; boxes a pointer, every send
       (lane (%claim-lane sap (shmem-transport-token st))))  ; ...and this
```

`%claim-lane`'s **own docstring says "One-time, off the hot path"** — and it was being called on every
single datagram. Per send it took the segment's **pshared mutex**, scanned every lane descriptor with
`load-sap-u64`, and ran an `unwind-protect` (whose cleanup closure is the `CLEANUP-FUN-0` frame that shows
up in the allocation profile). It returns the *existing* lane for a known token, so all of that work was
re-deriving a value that had not changed since the first send to that destination.

A docstring that says "off the hot path" is not a fact about the code; it is a claim, and this one had
been false for as long as the send path has existed.

## Decision

**Resolve the destination once and cache the whole resolution.** `%attach-for` now returns a `shmem-dest`
— `segment`, `sap`, `lane` — stored in the existing `attach-cache` under the same key the attach already
used. The steady-state send reads three slots.

**Why this adds no new invalidation surface, which is the whole argument for it:** the SAP and the lane
have *exactly the same lifetime as the attach itself*. The SAP is the mapping's address; the lane is owned
by our token until the segment is destroyed. They go stale precisely when the cached segment does — and
the existing cache already handles that (a failed attach is not cached, "the peer may come back"). Caching
them in one cell means there is no second thing to invalidate and no way for the three to disagree.

**A failed lane claim stays retryable.** Every lane can legitimately be taken. On that path the segment is
still cached — we hold the mapping and must detach it at close, so dropping it would leak — while `lane`
stays `NIL`, and the next send re-attempts the claim (`(or lane (setf lane (%claim-lane …)))`).

`*shmem-dest-cache*` (default T) keeps the per-send re-derivation as the A/B lever and as an escape hatch.

## The hazard, and how it is gated

**A wrong cached lane is SILENT MIS-DELIVERY.** Two senders writing the same ring lane do not fail — they
interleave and corrupt each other's records. Delivery alone does not prove correctness here, so
`run-shmem-dest-cache-test` asserts the invariant directly, with two senders driving one receiver:

1. each sender's cached lane is claimed and **stable across many sends** (the memo is used, not silently
   re-claimed);
2. the two senders hold **distinct** lanes;
3. the memo **agrees with the authority** — a fresh `%claim-lane` for that token returns the cached lane,
   so a cache that drifted from the ring's own ownership table goes red;
4. every record from both senders arrives with its payload intact.

**The test was falsified before being trusted** (the standing rule — a green gate nobody has seen go red
proves nothing): forcing `%claim-lane` to return 0 for everyone makes it fail with *"two senders must hold
DISTINCT lanes (0 vs 0)"*, which is exactly the mis-delivery scenario.

## Consequences

- **`gate-mem` 2621.0 → 2533.6** (A/B, flag set globally). Reproduced 2533.7 three times — a notably
  tighter band than the UDP slices. arm64 ceiling 2710 → **2600**.
- Cumulative under ADR 0062: **3560 → 2534, −1026 B/sample (−29 %)**.
- Latency benefits too, though that is not what was measured here: a pshared mutex acquire and a lane scan
  leave the per-datagram send path.
- **x86_64 ceiling is not lowered here** — it cannot be measured on the arm64 dev box; per the process note
  in `bench/mem-ceiling.txt` the CI number is read and that row lowered in an immediate follow-up.

## What this ADR does NOT do

- It does not change the ring format, the record layout, the Dekker wake handshake, or the drain.
- It does not touch `%claim-lane` itself — the four direct unit tests of claim/reuse/full still apply, and
  it remains the authority the cache is checked against.
- It does not address the SHMEM **receive** side (`shmem-receive-drain` boxes a SAP per drain), nor the
  remaining `dispatch-message` / `%handle-datagram` block, which is now the largest receiver-thread item.
