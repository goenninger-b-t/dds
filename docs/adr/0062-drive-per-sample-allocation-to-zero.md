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

## ⚠️ AND THE PER-SITE INSTRUMENT LIED TOO (correction, 2026-07-14)

The callee-wrapping harness used `(lambda (&rest args) ... (apply orig args))`. **`&rest` conses an argument
list per call — 32.0 B/call measured, for a 2-arg function; a direct call is 0.0 B.** Every per-site figure
below therefore includes the wrapper's own allocation.

**The TOTALS are sound** (3648 B/sample was measured unwrapped, and `gate-mem` reproduces it). **The
per-site numbers are UPPER BOUNDS, not costs.** Memoizing `%reader-routes-for` — whose wrapped cost read
328 B — moved the ground truth by **88 B**. The rest was the wrapper measuring itself.

**Third instrument to mislead this task** (after `sb-sprof`'s byte attribution, twice). The rule gains a
corollary: *size every candidate with a `bytes-consed` delta — and verify the delta measures the code, not
the measurement.* **`gate-mem`'s end-to-end number is the only oracle for a claimed win.**

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
