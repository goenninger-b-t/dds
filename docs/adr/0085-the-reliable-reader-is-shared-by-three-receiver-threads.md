# ADR 0085 — the reliable reader is shared by three receiver threads, and was unsynchronized

- **Status:** ACCEPTED (2026-07-24)
- **Requirements:** NFR-STABILITY (binary gate: no heap corruption), FR-RTPS reliability (RTPS 2.5 §8.3.5.4 exactly-once), NFR-MEM (the raw-pointer rule), NFR-SEC-POSTURE
- **Supersedes:** the **root diagnosis** of ADR 0084 (the refcount re-land) — which is hereby withdrawn, unimplemented. Corrects a load-bearing factual premise in **ADR 0078**.
- **Relates to:** ADR 0078 (the reverted RX store-copy pool), ADR 0084 (the refcount design), ADR 0048 (N-reader routing)

## Context — two ADRs blamed the wrong thing

ADR 0078 pooled the receiver's per-sample store copy and was reverted the day it landed for **heap
corruption on Linux**. ADR 0084 re-diagnosed the residual as a *use-after-release retention* — "a holder
reads a correctly-released, recycled buffer" — and specified a refcounted lifetime to fix it.

Neither diagnosis survives contact with the evidence.

### What the crash logs actually say

Every failure is SBCL's collector dying on a **clobbered object in the dynamic space**:

```
no transport function for object 0x1006b2806f (widetag 0x9)
no transport function for object 0x1005f0aeef (widetag 0x6d)
CORRUPTION WARNING ... Memory fault ... scav_vector_t
```

and, once gencgc was told to validate the whole heap on every collection
(`(setf (sb-alien:extern-alien "verify_gens" char) 0)`):

```
post-GC failure
Ptr 0x10021f8e47 @ 1001df8d68 (lispobj 1001df8d43,pg959) sees junk      (x6)
GC invariant lost, file "verify.inc", line 318
```

Six structure instances holding cons pointers into one clobbered region. **This is a wild WRITE into the
Lisp heap.** A retention that merely *reads* a recycled buffer cannot clobber an object header, so ADR
0084's mechanism cannot produce this signature and its refcount would not have fixed it.

### Three facts that eliminate the pool as the writer

1. **`alloc-static` memory is not in the dynamic space.** Measured on the failing box: a static vector sits
   at `0x56BA22AC716F` (the glibc heap); SBCL's dynamic space is `[0x1000000000, 0x1040000000)`;
   `heap-allocated-p` returns NIL for it. Every corrupted address was `0x10…`. A write through a pooled
   buffer — even one past its end — lands in the malloc heap and **physically cannot** reach a Lisp object.
2. **There is no global `(safety 0)`.** ADR 0078 attributed the corruption to `pool-release` writing
   `(svref slots top)` "at `(safety 0)`, one past the vector". The repository declares no global optimize
   policy at all — only three tiny local sites — so `arena.lisp` compiles at SBCL's default **safety 1**,
   where `svref` is bounds-checked and an overrun signals. That write was never unchecked. (The bounds
   guard added for it is still correct hardening for every pool and is retained; it simply was not the bug.)
3. **A same-tree A/B, GC verification armed, pool as the only variable:**

   | arm | full-suite runs |
   |---|---|
   | pool **off** (`*rx-store-pool-enabled*` NIL) | **6/6 clean**, 602 tests each |
   | pool **on** | **5/10 corrupt** |

   So the pool is a real **trigger** — but by (1) it is not the writer.

Two further recorded beliefs were also wrong: the corruption is **not durability-clustered** (one run died
at test 21 of 602, in `log-corpus`), and it is **always** on a receiver thread inside `%deliver-user-sample`.

## The actual defect

`disc.lisp` states it plainly: *"start-node runs up to THREE receiver threads (unicast / multicast / SHMEM)
all feeding `%handle-datagram`"*. Those threads land in `reader-on-data` / `reader-dedup-accept-p` /
`reader-on-heartbeat` / `reader-on-gap` **with no enclosing lock**, and `rtps-reader` had **no lock at all**
— one `with-lock` in nine hundred lines, and it belonged to the writer side.

`reliable.lisp` documented the assumption it was violating, in the `acknack-bitmap` slot comment:
*"single-mutator, same receiver-thread discipline as RECEIVED"*, and again in `reader-acknack`:
*"the single-receiver-thread-per-proxy discipline (the same that lets RECEIVED be a lock-free hash)"*.
**That discipline does not exist.** It was true when the reader had one transport.

The consequences are of two kinds, and both are real:

- **Memory unsafety.** `rtps-reader-proxies`, `rtps-reader-dedup-map`, each `writer-proxy-received` and
  `-reassembly`, and each `dedup-origin-above` are plain hash tables mutated concurrently. Two colliding
  `PUTHASH`es that meet an internal rehash publish a half-built index/kv vector, which the collector then
  walks as a live object. `PUTHASH/EQ`, `PUTHASH/EQUALP` and `GROW-HASH-TABLE` are the top frames of
  **every** crash in this investigation.
- **Protocol incorrectness.** Every reader entry point is a compound read-modify-write:
  `(or (gethash k) (setf (gethash k) …))` in `get-writer-proxy`, the seen-test-then-mark in
  `reader-dedup-accept-p`, the `(when (> sn last-sn) (setf last-sn sn))` in `reader-on-data`. Interleaved,
  they drop a WriterProxy along with every received-SN marker written into it (the reader then NACKs
  samples it already holds), drop a dedup-origin, or **accept the same (GUID, SN) twice — double delivery,
  breaking the exactly-once guarantee of RTPS 2.5 §8.3.5.4.**

**Why the pool triggered it.** The pool removes ~36 B/sample of GC-heap garbage from the receive path. That
changes collection cadence and thread interleaving, which is enough to turn a latent race into a firing one.
This is the ordinary way a performance change "causes" someone else's concurrency bug.

## Decision

**`rtps-reader` gets a lock, taken by all twelve reader entry points.** `get-writer-proxy` splits into a
locked shell and `%get-writer-proxy`, the unlocked core the other entry points call while already holding
it. One lock buys both missing properties: **memory safety** (no two threads inside a table at once, so no
half-built vector for the collector to walk) and **atomicity** of the compound read-modify-writes.

The lock is a **leaf**: L4 cannot call back into the disc layer, so it can never nest inside another of our
locks and has no ordering hazard. Verified: no reader entry point calls another.

**Per-impl synchronized tables were tried first and rejected — measured, not assumed.** The first cut used
SBCL `:synchronized` / Clasp `:thread-safe` tables for the memory-safety half *plus* the lock for atomicity,
on the reasoning that they buy different things. They do, but only while some access path is unlocked; once
every entry point holds the lock the tables are already serialized and the synchronization is a redundant
inner lock per operation. It cost **4x more** — +150 ns/sample against +31 ns/sample for the lock alone
(`bench/report/2026-07-24-reliable-reader-lock.md`) — for no additional safety, so it and the PAL primitive
added for it were removed. Confirmed no unlocked access justifies keeping it: nothing outside
`reliable.lisp` touches those tables except single-threaded tests, and the invariant is stated on the structs.

### The RX store-copy pool is exonerated and re-lands

With the race fixed, the pool is no longer implicated in any corruption. It re-lands as designed in ADR 0078
(the extent-carrying pooled `octet-buffer`, the single-choke release, the teardown return), plus the
exactly-once release from a per-node checkout set that the 2026-07-24 investigation added, plus a new
documented kill-switch **`dds.disc:*rx-store-pool-enabled*`** — because attributing a stability defect to a
pool requires a same-tree A/B, and an operator who hits one needs an off switch that is not a recompile.

### The NFR-MEM raw-pointer rule becomes enforced, not documented

Auditing `static-pointer`'s callers for a dynamic-space writer found a genuine one:
`dds.log:make-udp-syslog-sink` passed each syslog line's freshly-consed UTF-8 octets — a **GC-heap vector**
— straight to `udp-send-to`, which hands the kernel a raw pointer. `run-log-syslog-test` did the same with
a 2048-byte heap receive buffer, where `recvfrom(2)` **writes**.

`udp-send-to` and `udp-recv` now take the raw path **only if `static-vector-p` holds**, and fall back to the
GC-safe `sb-bsd-sockets` path otherwise — exactly the choice `sap-copy-out` has always made. One predicate
per datagram; the hot dataplane passes PAL-backed buffers and is unchanged.

## Validation

- **Linux (`goedews01`, x86_64, SBCL 2.2.9), GC verification armed** (`verify_gens=0`,
  `bytes-consed-between-gcs` 8 MB), pool ON, race fixed: **20 runs, ZERO corruption events**, against a
  5/10 corruption rate before. Two of those 20 runs failed on a *discovery* timeout — `endpoints did not
  match before publish` and `perftest: nodes failed to match`, both with zero corruption markers. Those are
  an artifact of the verification harness itself, not of the fix: `verify_gens=0` walks the entire heap on
  every collection, and several tests give discovery a fixed 2-second budget
  (`loop repeat 100 … (sleep 0.02)`) that a long verify pause can blow. Confirmed by re-running the
  **normal** harness, no GC verification, on the same tree: **8/8 clean, 603 tests each**.
- **macOS (arm64):** 603 tests green on **both** SBCL and Clasp.
- **A falsifiable regression test**, `reader-concurrent-receivers`: four threads drive one reader over the
  same 500 SNs and assert exactly-once accepts, a single WriterProxy, no lost SN marker, and a correct
  LAST-SN. **Seen red** with the lock removed — 503, 519 and 502 accepts for 500 SNs across three runs,
  i.e. observed double delivery — and green with it.
- **Live cross-vendor interop**, both directions against RTI Connext 7.3.1 (the strict oracle) and Fast DDS,
  including fragmentation: Connext→us 342 samples and 20 reassembled large samples, us→Connext 253 accepted
  and 14 fragmented, plus both Fast DDS legs.
- **Live cross-machine**, our stack on both ends over the LAN, 400 samples each way (`interop/reader-lock-xmachine/`):
  **zero duplicate sequence numbers in either direction** — the exactly-once property the unsynchronized
  reader broke, checked against real network traffic rather than a unit harness.

## Consequences

- One uncontended lock acquisition per received sample on the reader path: **+31 ns/sample**, ~0.1% of an
  end-to-end latency measured in tens of microseconds. Correctness is a binary gate and performance the
  optimization target (operating contract §3.2). Measured in `bench/report/2026-07-24-reliable-reader-lock.md`.
- The reader-side docstrings that appealed to a single-receiver-thread discipline are corrected in place.
- The corruption class this closes is one only Linux could see — the fourth such, after uninitialised memory
  on the wire, a stack that could not shut down, and ADR 0078's own revert.

## Lessons that generalise

- **A green gate proves nothing until it has been seen red.** The concurrency test was written to fail first.
- **Read the crash, not the summary.** Two ADRs' worth of diagnosis rested on a signature nobody had matched
  against a mechanism: a *read* was blamed for a *write*, and `(safety 0)` was assumed rather than grepped.
- **`verify_gens=0` is the tool for this class.** It converts "a random crash three minutes later" into "the
  first collection after the write, with the offending object named".
- **A documented invariant is not an enforced one.** Both defects here — the receiver-thread discipline and
  the raw-pointer rule — were correctly written down and silently violated. Where a predicate can check it
  cheaply, it should.
