# ADR 0062 — Drive per-sample allocation to zero: the budget, and the two claims it falsifies

- **Status:** Accepted (measurement + plan). The individual mechanisms below are NOT yet implemented; each lands under its own commit with a before/after.
- **Date:** 2026-07-13
- **Requirements:** NFR-MEM (0 bytes/sample steady state), NFR-PERF-8, NFR-PERF-3 (p99.99 within 5 % of Connext)
- **Supersedes the working assumption of:** the WP-8 task-#29 note ("attack the RX deserialization products"), and the "zero-alloc TX" claim of `c89aae0`.

## Context

The ~10 ms latency tail is a **GC pause in the peer**, caused by our per-sample garbage
(`bench/report/2026-07-13-the-tail-is-the-peers-gc.md`): silence that GC and the worst sample collapses
from 9.9 ms to 100 µs, which **beats Connext's ~200 µs**. The tail is therefore not a latency problem to
be tuned; it is an allocation problem to be eliminated. Nothing else — spin, syscall count, `declaim` —
can touch it, and a larger nursery only defers a bigger pause.

`89bf344` + `1801f3c` cut steady state **5603 → 3882 B/sample (−31 %)**. The tail did **not** move
(~10–12 ms in both A/B arms). That is the expected result and it is the point of this ADR: **a GC does
not care that you allocate 31 % less. Only zero stops it.**

## The measurement that reframes the work

Before designing anything, the per-round-trip budget was split by phase with `bytes-consed` deltas on the
pinger (which performs exactly one `write-sample` and one drain per round trip). At **zero payload**
(n=4000), total **3440 B/sample**:

| phase | bytes | share |
|---|---|---|
| `write-sample` — **TX**, user thread | **1312 B** | **38 %** |
| receiver threads + engine | **1833 B** | **53 %** |
| `take-samples` — RX drain, user thread | 295 B | 9 % |

At 256 B payload the totals are 1594 / 2590 / — of 4192 B. (The 256 B `take-samples` figure reads as ~0
only because the bench's listener already drained on the receiver thread; that work is inside the 2590.)

### This falsifies two things we believed

1. **"Zero-alloc TX" is false.** `c89aae0` shipped as *"WP-8.T1 zero-alloc TX"*: `publish-sample-into`
   serializes into an arena-pooled buffer the CacheChange owns. The pooling is real and it works — but
   **`write-sample` still allocates 1312 B at ZERO payload**, i.e. with no payload to serialize at all.
   The pool removed the *payload* allocation and left everything around it. TX is the single largest
   identifiable phase, and we had it recorded as solved.

2. **The RX deserialization products are NOT the problem.** The prior task-#29 note directed the next
   engineer at `%drain-one-sample` / `%deserialize-sample` and warned about loan semantics. A full
   code-level inventory of the DCPS receive path accounts for only **~400 B** — and the measurement agrees
   (295 B). An ADR for a pooled, loan-safe, zero-alloc RX path — which is what this ADR was opened to be —
   would have been a large, hazardous change (it collides with `read`/`take` aliasing, the WaitSet query
   predicates that run user code over `dr-cache` on another thread, `instance-rec-key-sample` retaining
   sample #1 of every instance forever, and the N≥2-reader shared-store leak) **for 9 % of the problem.**
   We are not doing that now.

### And it falsifies the instrument

`sb-sprof :mode :alloc` is **not reliable for byte attribution** in this stack. Twice it pointed at
frames whose real cost was nothing like their share:

- `dispatch-message` profiled at **8.2 %**; removing its per-datagram allocation was worth **84 B** (2 %).
- `call-with-mutex` profiled at **12.4 %** of the TX user thread; a direct measurement of
  `dds.pal:with-lock` shows **0.0 bytes per acquisition** (SBCL stack-allocates the thunk). There was
  nothing to fix.

The profiler is useful to *find candidate sites*. It must not be used to *size* them. **Size every
candidate with a `bytes-consed` delta before writing a line of code.** The prior session's profile was
also stale (its #1 item, `%writer-add-bounded` at "21 %", now measures 1.6 %).

## Decision

1. **Attack in measured order: TX (38 %) and the receiver threads/engine (53 %) first. RX-drain (9 %)
   last, and only if zero is still not reached.** Reverse of the inherited plan.

2. **Every step is sized with a `bytes-consed` delta before it is written, and carries a before/after in
   `bench/report/` (operating contract §5).** No allocation work lands on a profiler share.

3. **The NFR-MEM debt is enumerated in the source, not in a profile.** `make gate-hotpath` now scans the
   hot-path files for heap allocation (it previously scanned for CLOS only, which is why `message.lisp`
   could allocate a 12-octet guidPrefix per datagram while sitting in the certified-clean list). Every
   allocating form must carry a `; HOTPATH-ALLOC(CLASS): reason` marker; an unmarked one **fails the
   build**. The `TRACKED` class means *real per-sample allocation, known debt, being driven to zero*, and
   the gate **prints the outstanding TRACKED set on every run**. It is 11 forms today. The gate falsifies
   itself on every run (it plants an unmarked allocation and asserts the scan rejects it).

4. **Loan-safe RX pooling is DEFERRED, not rejected.** If TX + engine reach zero and the residual RX 295 B
   still triggers a GC, we revisit. The machinery to do it already exists and must be REUSED, not
   reinvented: the per-reader loan registries and `dr-view-freelist` recycling, the repointable
   `secured-scratch` octet-buffer, `secured-loan-handle-return-count`'s multi-reader deferral, the ZC
   `%zc-bump` refcount, and `dds.core.arena`'s `make-buffer-pool` / `pool-acquire` / `pool-release`
   (already proven on TX via `publish-sample-into` and on RX via the secured decode pool).

5. **The type-support contract stays FROZEN.** `%instance-handle` allocates a 16-octet keyhash per sample
   and it is *retained* (as a `dr-instances` / `dr-instance-recs` hash key and in the `sample-info`), so a
   `key-hash-into` variant would change a frozen contract. At ~32 B it is not worth it. Revisit only if it
   is the last thing standing between us and zero.

6. **`%source-prefix`'s per-datagram 12-octet allocation is NOT converted to a shared scratch.** An audit
   confirms every consumer copies before retaining (via `%source-guid`'s fresh 16-octet array, or one of
   ten explicit `copy-seq` stores), so a reused buffer would be safe **today** — but only because
   `%handle-datagram` is re-entrant on the SRTPS path and the inner datagram's header bytes [8,20) happen
   to be byte-identical to the outer's. That is an aliasing coincidence in the **security** path, not an
   invariant. ADR 0060's lesson stands: *a deferral justified by "nothing currently exercises this path"
   is only as durable as the reason nothing exercises it.* Declined for ~5 % of a budget whose tail will
   not move either way.

## ⚠️ CORRECTION (2026-07-14) — THE PER-SITE NUMBERS ARE INFLATED; `gate-mem` IS THE ORACLE

**Ground truth:** `%reader-routes-for` measured **328 B/sample** with the callee-wrapping harness. Memoizing
it — eliminating essentially all of it (called **2.00×/sample**, memo hits **100 %**, never invalidated in
steady state) — moved the real total by **88 B** (3648 → 3560, `gate-mem`). Its true cost was ~48 B/call
(a `copy-list` + two conses). **The harness over-reported by ~3.5×.**

**I do not know the mechanism and will not invent one.** My first guess — the wrapper's `&rest`/`apply`
consing an argument list — is **DISPROVEN**: the exact harness shape measures **0.0 B/call**. I published
that guess as a correction *before testing the real shape*, which is exactly the error this section exists
to warn about.

**What holds:** the **TOTALS** are sound (measured unwrapped; `gate-mem` reproduces them). The **per-site
numbers RANK candidates but do not SIZE them.** Every claimed win must be confirmed end-to-end by
`gate-mem`.

Third instrument to mislead on this task (after `sb-sprof`, twice). Corollary to the rule: *size with a
`bytes-consed` delta — then verify the delta against `gate-mem`, because the delta can be wrong too.*

## The TX budget, MEASURED (2026-07-14) — the "size it first" step, done

`bench/report/2026-07-14-the-tx-allocation-budget-measured.md`. `bytes-consed` deltas around each callee,
payload = 0, n = 3000. Total round-trip 3648 B/sample.

| site | B/sample | what it is |
|---|---|---|
| `%send-changes-packed` | **349** | a per-sample datagram **PLAN of closures** (`%changes-datagram-plan` returns "a list of (BUILD-THUNK . SHMEM-DEST), each BUILD-THUNK a lambda"). The common case — one small change + optional HEARTBEAT to one destination — can be sent directly with no plan and no closures. **Byte-identical wire is the gate.** |
| `%capture-push-groups` | **197** | per-send structs/lists for the **Zero-Copy multi-dest refcount** machinery, which is **off by default**. Same class as `312db1b`. (`writer-capture-unsent` is needed regardless — do not skip it.) |
| `writer-write` | **196** | the `cache-change` struct. Pooling it is a **design change** — a change is retained until ACKed. |
| `%write-key-hash` | **175** | the generated keyhash, KEEP_LAST only. RETAINED ⇒ touches the **frozen type-support contract** (§5). |
| `hc-add-change`, `writer-acquire-payload-buffer` | **0** | **the arena pooling from `c89aae0` genuinely works.** It removed the *payload* allocation and left everything around it — which is exactly why "zero-alloc TX" was recorded as done while `write-sample` still costs 1.3 KB with nothing to serialize. |

## The RX budget, MEASURED (2026-07-14) — the whole 3648 B is now accounted for

| bucket | B/sample | share |
|---|---|---|
| **RX `%handle-datagram`** (receiver thread) | **1420** | 39 % |
| **TX `write-sample`** (user thread) | 1376 | 38 % |
| **USER `%drain`** (the take path) | 808 | 22 % |

| RX site | B/sample | what it is |
|---|---|---|
| **`%reader-routes-for`** | **328** | **THE BIGGEST RX ITEM.** A `copy-list` + a freshly-consed `(rid . reader)` list on EVERY data/heartbeat/gap handler call — for a value that changes only on match/unmatch. **It memoizes, but a STALE ROUTE IS SILENT MIS-DELIVERY** (data lost, or delivered to a dead reader). Correctness hazard, not a perf one: drive invalidation from the choke points that already exist (`%fire-unmatch` is now the single unmatch funnel, ADR 0063 §3) and gate it on the LIVE re-match repro, not just the unit suite. |
| `%on-user-heartbeat` | 393 | **A CONTROL message costs as much as the DATA** (`%on-user-data` is also 393). Nobody would have looked here. |
| `%deliver-user-sample` | 349 | |
| `%deserialize-sample` | 218 | the RX products — loan semantics (§4) |
| `%on-user-acknack` | 175 | |
| `%source-guid` | 131 | a fresh 16-octet GUID, several times per datagram. **CAUTION: its result IS RETAINED** (the key for the reader-proxy, the sample store, and the instance tables), so it cannot become a shared scratch. |
| `reader-on-data` | **0** | the reliable reader itself is clean |

**Every one of the top items is now sized and scoped. `make gate-mem` ratchets the total (ceiling 3800,
measured 3648), so no step can silently lose its win.** Highest value next: `%reader-routes-for` (328 B) and
the TX send-plan flattening (349 B) — together ~19 % — but BOTH have a correctness invariant to preserve
(stale-route mis-delivery; byte-identical wire), so neither is a quick edit.

## LANDED (2026-07-20) — the SHMEM sender resolved its destination per datagram, −87 B (2621 → 2534)

Full decision in **ADR 0067**; measurement in
`bench/report/2026-07-20-shmem-cost-more-than-udp-and-reclaimed-its-lane-per-datagram.md`.

Once 0065/0066 made UDP send+recv ~0 B/call, a FREE A/B (flip the existing `dds.disc:*shmem-enabled*`, no
code change) showed **SHMEM 2577.3 vs pure UDP 2446.4** — the intra-host transport that exists for SPEED
had become 131 B/sample more expensive than the network one. It had not regressed; UDP got cheap and
nothing re-ranked the transports.

`%shmem-send` re-derived its destination on EVERY datagram: `(shm-sap dest)` boxes a pointer, and
`%claim-lane` — **whose own docstring says "One-time, off the hot path"** — took the segment's pshared
MUTEX, scanned every lane descriptor and ran an `unwind-protect`, all to return the lane it had already
returned for the same token. Now resolved once into a `shmem-dest` (segment+sap+lane) cached in the
EXISTING attach cache: all three share the attach's lifetime, so they go stale together and there is no
second thing to invalidate. arm64 ceiling 2710 → 2600; cumulative **3560 → 2534, −29 %**.

⚠️ A wrong cached lane is SILENT MIS-DELIVERY (two senders on one lane interleave rather than fail), so
`run-shmem-dest-cache-test` asserts lanes are claimed, stable, DISTINCT, and agree with a fresh
`%claim-lane` — and was FALSIFIED first (force lane 0 for everyone ⇒ red).

**A docstring claiming "off the hot path" is a claim, not a fact. Check it.**

## LANDED (2026-07-20) — the SECOND receiver-thread slice: raw recvfrom(2), −87 B (2730 → ~2630)

Full decision in **ADR 0066**; measurement in `bench/report/2026-07-20-the-receive-path-built-a-sender-address-nobody-read.md`.

`udp-recv` went through `sb-bsd-sockets:socket-receive`, which builds a sockaddr for the SENDER and
converts it to a Lisp address on every datagram — **304.6 B/call isolated, for a value nothing reads**
(RTPS identifies a source by GuidPrefix, never by IP; `start-udp-receiver` takes `(nth-value 0 …)` and both
other callers `(declare (ignore addr senderport))`). Now `recvfrom(2)` with `src_addr = NULL`: 0.0 B/call.

**The syscall swap was the easy half.** The receiver thread exits today *because `socket-receive` signals*
on a closed socket; `recvfrom` returns −1, so a naive port spins forever and `stop-node`'s join hangs — the
"stack could not shut down on Linux" defect. Probed, not assumed: a thread parked in raw `recvfrom` is NOT
woken by `tcp-shutdown` on Darwin (`ENOTCONN` on an unconnected UDP socket — the probe HUNG), and
`socket-close` resets the fd slot to −1 on BOTH impls, so a fresh-read fd gives `EBADF` with no fd-reuse
exposure. The loop exits on NEGATIVE, never on zero (a legal zero-length datagram would otherwise let any
peer kill a receiver thread, NFR-SEC-POSTURE). `udp-transport-recv`'s `(values (integer 0) t t)` was widened
to `(values integer t t)` — at `(safety 0)` a non-negative declaration folds a caller's `(minusp size)`
check away.

304.6 B/call → −87 end-to-end: the **fourth** per-site over-report (~3.5×). Rule unchanged.

## LANDED (2026-07-20) — the FIRST RECEIVER-THREAD slice: raw sendto(2), −175 B (2883 → 2730)

Full decision in **ADR 0065**; measurement in `bench/report/2026-07-20-the-acknack-reparsed-its-destination-ip-per-datagram.md`.

Re-splitting the budget by probing each phase of the measurement cycle put **44 % on the RECEIVER
THREADS** (1267 B), 30 % on TX (873 B), 20 % on the take that returns the sample (590 B) and 5 % on an
empty take (153 B). `(sleep 0.0002)` allocates 0 B on the calling thread, which makes the sleep window a
clean receiver-thread probe; a writer-idle control arm costs exactly the two empty takes, so 93 % of
`gate-mem` is genuinely marginal per-sample cost.

**This corrects the scoping note that preceded it**, which attributed ~1883 B (65 %) to the user
drain/take path and named it the target — it had counted the whole poll region as user-thread work. The
take path is 590 B. The distinction decides what to do next: loan-safe RX pooling carries five hazards
(read/take aliasing, the WaitSet cross-thread drain, `instance-rec-key-sample` retention, the N≥2-reader
shared-store leak, the KEEP_LAST loan UAF guard) and the receiver thread carries none of them.

With exactly 1 DATA + 1 ACKNACK per sample (counter deltas), the whole per-datagram send cost is paid
once per sample. `udp-send-to` was `(socket-send … :address (list (%parse-ipv4 host) port))` — **the
dotted-quad destination STRING re-parsed on every datagram**, ~262 B of `parse-integer` consing, plus
~98 B of `socket-send` keyword/generic/alien overhead. It now fills a per-thread foreign `sockaddr_in`
and calls `sendto(2)` through a pre-resolved pointer: 0 B/call isolated, **−175 B end-to-end**, wire
bytes unchanged. arm64 ceiling 2950 → 2800.

The isolated 360 B/call over-predicted the 175 B end-to-end delta by ~2× — the **third** per-site
over-report. §"CORRECTION" below stands: per-site numbers RANK, `gate-mem` SIZES.

## LANDED (2026-07-20) — TX allocation: ~−680 B/sample (3560 → ~2883)

### Slice 5 — single-destination push fast path (skip the %zc-push-group struct): −90 B (~2960 → 2883)

`%capture-push-groups` builds a `%zc-push-group` struct (+ the `groups` / `all-changes` lists) per destination
to freeze every dest's unsent set up front for the ADR 0047 cross-group ZC-refcount stability. For the common
case — exactly ONE `%reader-push-targets` group — that freeze is a no-op (no change reaches ≥2 groups, so the
shared-ZC table is `+no-shared-zc-refs+`). `%push-one-writer-changes` now emits that case directly: capture the
one group's unsent set, send, release — no struct, no lists. `gate-mem` A/B (`*tx-single-group*`): OFF ~2976 →
ON ~2883, −90 B. Byte-identical — proven three ways: the new `run-tx-single-group-equivalence-test`
(`*tx-single-group*` T vs NIL via `*datagram-sink*`), the existing `run-flow-step-equivalence-test` (this
single-group path vs the general `%node-datagram-plan` path), and the live n-reader / same-topic delivery
tests. arm64 ceiling 3030 → 2950.

### Slice 4 — memoize the TX push grouping (%reader-push-targets): −185 B (3145 → ~2960)

### Slice 4 — memoize the TX push grouping (%reader-push-targets): −185 B (3145 → ~2960)

`%reader-push-targets` (the per-destination `((host . port) . matched-reader-GUID-keys)` grouping the TX push
builds on every send via `%capture-push-groups`) rebuilt from scratch — `copy-seq` per reader GUID + `subseq`
+ `find`/`assoc` — for a value that changes only on match/unmatch or a participant's locators. Memoized per
`topic` on the node (`reader-push-cache`), reusing slice 3's `%invalidate-dest-cache` + `match-dest-generation`
verbatim. `gate-mem` 3145 → ~2960 (biggest single slice — this grouping conses more than the ACKNACK-dest set).

**This slice surfaced — and fixed — a real latent invalidation gap (the suite earned its keep).** The
`match-dest-cache` (slice 3) and this `reader-push-cache` both read `%matched-endpoints` (= `disc-node-matches`).
The match funnel `%match-remote-endpoint` invalidates via `%reader-route-add` ONLY for a matched remote WRITER
(`(when writer-p …)`); a matched remote READER — our writer's NEW push target — reaches only `%record-match`,
which did NOT invalidate. So a reader matching a writer that had already sent (populating the memo) would be
**silently dropped**. The happy-path delivery tests miss it (they populate the memo AFTER all matches; the
durability late-joiner replays via a direct-to-reader path), but `run-push-spdp-peer-isolation-test` (which
raw-`clrhash`es `disc-node-matches`) failed on BOTH impls. Fix: `%record-match` now calls `%invalidate-dest-cache`
on a first-time match (the choke point for the remote-reader case), and `run-match-dest-cache-invalidation-test`
gained a `%record-match` assertion. NB slice 3 shipped with this latent gap — it was correct only because
`match-dest-cache` happened never to be populated before a first match in practice; it is now genuinely covered.

### Slice 3 — memoize the send-destination union: −66 B (3211 → 3145)

### Slice 3 — memoize the send-destination union: −66 B (3211 → 3145)

`%match-destinations-prefixed` (the matched-participant-locators ∪ static-peers set, each a
`(DEST-PREFIX . (HOST . PORT))`) was rebuilt from scratch — `subseq` ×2 per matched endpoint + `find`/`member`
+ fresh conses — on **every** send / HEARTBEAT / ACKNACK / retransmit (6 hot-path callers), for a value that
changes only on match/unmatch or a discovered participant's advertised locators. Now MEMOIZED per
`want-readers` on the node (`match-dest-cache`), mirroring the `reader-routes-cache` pattern exactly:
resolve outside the node lock (the sub-reads take it), a generation race-guard (`match-dest-generation`,
store only if unchanged), and **coarse wholesale invalidation** — a STALE DESTINATION IS SILENT MIS-DELIVERY.

Invalidation surface (broader than routes, which depend only on matches): `%invalidate-dest-cache` is called
from `%invalidate-route-cache` (so every match/unmatch/prune site covers it) AND from the SPDP handler on
every announce (a locator update — right beside the existing `%invalidate-shmem-dest`). Static PEERS are
immutable after `make-disc-node` in production (set once, before the first send), so they need no site. A/B
(memo cache-forever) was ~100 B; the shipped invalidating version is −66 B (the ~1 Hz SPDP announces
re-resolve periodically). Gated by a deterministic invalidation unit test
(`run-match-dest-cache-invalidation-test`) **plus** the live late-joiner / N-reader integration tests (a
reader joining after the writer has been sending must still receive — a stale memo silently drops it).

### Slice 2 — inline HEARTBEAT on the fast path: −87 B (3298 → 3211)

### Slice 2 — inline HEARTBEAT on the fast path: −87 B (3298 → 3211)

Re-profiling after slice 1 (below) showed `%send-changes-packed` gone from the top-25 allocators and
`%push-one-writer-changes` risen to #1 (10.6 % self). The cause: it built a fresh HEARTBEAT **pack closure**
per send (`%heartbeat-builder` → `(cons 32 (lambda (mc) …))`), inside the per-destination `dolist`. The TX
fast path (slice 1) `funcall`ed that closure but did not eliminate it. Fixed by passing the HB as raw
`(first last count)` down to `%send-changes-packed` and writing it **inline** via a new `%write-hb-submessage`
(extracted from `%heartbeat-builder`'s body, shared DRY); the pack closure is now built **lazily only on the
plan fallback** (`(and hb-first (%heartbeat-builder …))`), never on the common path. `gate-mem` A/B:
**FAST-OFF 3577.6 → FAST-ON ~3247 B** (official `gate-mem` 3210.8); byte-identical (the same
`%write-hb-submessage` bytes; `run-tx-fast-path-equivalence-test` still green). arm64 ceiling 3360 → 3290.
The `%send-changes-packed` signature took the HB `(SIZE . closure)` param → three `hb-first/last/count`
integers; both callers (`%push-one-writer-changes`, `%on-user-acknack` retransmit) updated.

### Slice 1 — TX send-plan flattening: −262 B/sample (3560 → 3298)

`%send-changes-packed` now emits the common case — exactly one small non-ZC change (+ the optional trailing
HEARTBEAT) fitting a single budget-bounded datagram to one destination — **directly**, skipping
`%changes-datagram-plan`'s `items` / `%pack-plan` group / per-group closure / `state`-cons allocation. The
`%data-builder` closure body was extracted into a named `%write-change-submessage` (+ a `%change-submessage-size`)
so the fast path and the plan share the exact same writers and size arithmetic (DRY) — **byte-identical by
construction**, pinned by `run-tx-fast-path-equivalence-test` (captures the fast path vs `*tx-fast-path*`-NIL
forced-plan via `*datagram-sink*` and asserts equality). `gate-mem` A/B on the default harness:
**FAST-OFF 3577.6 B, FAST-ON 3298.0 B — −262 B/sample (~7.4 %)**; arm64 ceiling ratcheted 3600 → 3360.

### ⚠️ The near-miss that this section corrects — VERIFY THE FAST PATH IS *REACHED IN THE HARNESS*

The first cut of this optimization gated on `(null shmem-dest)` (UDP only). Its A/B measured **FAST-ON 3582 /
FAST-OFF 3538** — apparent noise — and it was wrongly written up as a *rejected, gate-mem-neutral dud* ("SBCL
stack-allocates the closures"). **That conclusion was false.** `mem-per-sample` runs TWO co-located
participants on one host, and `*shmem-enabled*` is **T by default on SBCL**, so the user DATA rides the
**SHMEM** transport — `%send-changes-packed` is called with a *non-nil* `shmem-dest`, so the UDP-only fast
path **never fired**. The A/B was plan-vs-plan; "no difference" meant "never executed," not "no win." Passing
`shmem-dest` through to `%send-raw-buf` (the datagram bytes are transport-independent; only the send target
differs) made it fire, and the real win appeared immediately.

**Lesson (a fifth way to be misled): a `*flag*` A/B is only valid once you have PROVEN the flag's branch
executes in the measurement harness.** An `sb-sprof :mode :alloc` profile of `mem-per-sample` shows live
SHMEM frames (`%CLAIM-LANE`, `%LANE-DRAIN`, `%SHMEM-SEND`) — that is the tell that the harness is not on UDP.
Confirm the branch is taken (a counter, or an assertion that the precondition holds) before trusting a null A/B.

**Still mandatory:** size every candidate with a `*flag*` A/B against `gate-mem` BEFORE implementing (the
per-site table *ranks*, it does not *size*) — AND confirm the flag's branch is reached on the SHMEM path.
Remaining ranked candidates: TX `%capture-push-groups` 197, `writer-write` 196, `%write-key-hash` 175; RX
`%on-user-heartbeat` 393, `%deliver-user-sample` 349, `%deserialize-sample` 218.

## Consequences

- The remaining path to NFR-MEM is **TX-first**, and it starts by asking why `write-sample` costs 1312 B
  with nothing to serialize. Candidate sites (to be **sized before being touched**):
  `publish-sample-into`'s non-payload allocations, `%push-one-writer-changes`, the `cache-change` struct
  and its history `puthash`, `%instance-handle`, and the inline-QoS StatusInfo/KeyHash scratch buffers
  (`message.lisp:582`, `:614` — both now `TRACKED`).
- **NFR-PERF-3 (p99.99 within 5 %) remains blocked on this and only this.** The median is 1.34–1.59× of
  Connext; the tail is 15–60× worse *solely* because of the GC. We do not get to claim the tail until a
  measured workload allocates zero.
- Two prior claims in the record are wrong and are corrected here: "zero-alloc TX" (`c89aae0`) and the
  task-#29 direction to attack the RX products. Both are cited above so the next reader does not re-derive
  them.

## Provenance / authority

The read/take + `return_loan` read-by-reference ownership model is asserted in this repo by
**ADR 0017 §Decision** and **`REQUIREMENTS.md` FR-PF-3** ("reader maps and reads in place; loan/return
sample-pool ownership model"). The repo ships the DCPS **IDL** (`docs/specs/dds_rtf2_dcps.idl` —
`return_loan` signature only), not the DDS 1.4 prose, so **no OMG clause number is cited here for
buffer recycling after `return_loan`.** Per the operating contract, a constant or clause is never
reconstructed from memory: if that authority is needed when item 4 is revisited, read the clause.
