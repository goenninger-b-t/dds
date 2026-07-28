# ADR 0093 — the copy path becomes a loan (NFR-MEM 0 B/sample on the measured path)

- **Status:** **Accepted** — owner decision taken 2026-07-28, ADR accepted 2026-07-28 (operating contract
  §7.2: an ADR that touches a frozen contract is written and accepted before implementation).
- **Date:** 2026-07-28
- **Requirements:** NFR-MEM (steady state allocates **zero** bytes/sample), FR-PF-7 (pre-allocation mode),
  NFR-PERF-3, NFR-PERF-8, FR-LANG-5 (no data-path consing)
- **Relates to:** ADR 0062 §4 (which deferred this as the hazardous half of the RX work), ADR 0017 (the
  FlatData/ZC loan contract this generalises), ADR 0038 (i) (the secured decode loan — the second loan kind
  already in `return-loan`), ADR 0073 / 0075 / 0076 / 0078 (the RX-pooling slices already landed),
  ADR 0087 / 0088 (the most recent allocation slices, and the arch-divergence rule)
- **Contract touched:** **`DDS.DCPS` app-facing.** `take-samples` and the take-family return samples the
  application **should** `return-loan` — the return is what makes the path zero-alloc, and NOT returning is
  safe (the wrapper is simply never recycled and the next delivery allocates, i.e. the pre-slice
  behaviour). `read-samples` is unchanged. Consumers in §6, as-built in §9.

---

## 1. The decision

**Option 1: extend the loan contract to the copy path.** `take` hands back a pooled sample; the application
returns it. This is what makes NFR-MEM's 0 B/sample reachable on the path `gate-mem` actually measures.

**The fallback is Option 2** — redefine the target as *0 on the loan path, a stated bounded floor on the
copy path* — and it may be taken **only** on the owner's stated condition:

> fully instrumented code and actual measurements, with deductions on the root cause.

⚠️ **That condition is a gate, not a formality.** Option 2 may not be reached by argument, by estimate, or
by a slice that merely turned out awkward. Falling back requires *instrumented code that exists*, *numbers
that were measured*, and *a named root cause* for why the residual cannot be removed. "It looks hard" is
not a measurement. This ADR is the place that record lands.

## 2. Why zero is not reachable today

The copy-path drain hands the application a **retained heap struct**, and three more objects follow it into
the reader cache. Per delivered sample, all four are retained (`src/dds-dcps/entities.lisp`):

| what | site | why retained |
|---|---|---|
| the deserialized `data` struct | `%drain-one-sample` | handed to the application as `cached-sample-data` |
| `make-sample-info` (13 slots) | `%drain-one-sample` tail | lives in `dr-cache`, returned to the app |
| `make-cached-sample` | `%drain-one-sample` tail | the app-visible unit itself |
| the `(list …)` cons `nconc`'d onto `dr-cache` | `%drain-one-sample` tail | the cache spine |

**You cannot pool an object whose lifetime the application controls.** DDS `read` is non-destructive and
the app may hold samples indefinitely, so today none of the four can be recycled — a hard floor of roughly
**200–290 B/sample**, essentially the whole take-hit phase. The only way through it is to make the
lifetime explicit, which is what a loan is.

## 3. What is ALREADY done — do not re-plan it

The 2026-07-20 scoping plan's **Phase A is complete**, and the machinery this ADR needs exists:

- **The decode is already in place, zero-alloc.** `%deserialize-sample` decodes through the reused
  per-reader `dr-deser-scratch` wrapper (ADR 0073); an RX-store-pooled buffer skips the wrapper entirely
  and is decoded in place by `%deserialize-payload` (ADR 0078, re-landed); the instance handle is
  serialized and written in place through `%reader-keyhash-scratch` / `%reader-keyhash-out`
  (ADR 0075/0076). **None of these allocate.**
- **`return-loan` already dispatches TWO loan kinds by strict type** — a `flatdata-view` to `%zc-release`
  + `dr-view-freelist` recycle, a `dds.disc:secured-loan-handle` to `node-return-loan` — each invalidating
  its `dr-cache` entry *before* the underlying buffer is recycled. **This is the extension point: the
  pooled copy sample is a third arm, not a new mechanism.**
- **`deserialize-into-<name>` is already generated** (`src/dds-gen/dsl.lisp`) and **deliberately unused** by
  this path, precisely because it needs a pooled target — i.e. it needs this ADR.
- **`sample-pool` / `sample-pool-acquire` / `sample-pool-release`** exist in `dds-types`, with
  `type-support-sample-pool-alloc` / `-free` hooks, already used by TX.

So this is not a green-field pooling project. It is **wiring an existing loan contract onto a fourth
producer**, plus the one genuinely hard part (the data struct) and the hazards below.

## 4. The design

**Everything comes from the pool at DRAIN time; recycling happens on return.** Three recycle triggers,
mirroring what the ZC loan path already does:

1. `return-loan` of a taken sample — the ordinary path;
2. KEEP_LAST eviction of a sample the application does **not** hold;
3. reader close (`return-all-loans`), which already sweeps both existing registries.

`read` remains non-destructive and stays in the cache; a `:read`-held sample is never recycled under the
application (the guard `%reader-keeplast-drop-oldest-loan` already implements exactly this for views, and
extends).

⚠️ **Be honest about the boundary: this makes the TAKE path zero, not `read`.** An application that
`read`s and holds indefinitely still pins its samples — correctly, because that is what `read` means.
`gate-mem` measures `take`, so the gate reaches ~0; the claim we may make afterwards is *"0 B/sample on the
take path"*, never an unqualified "0 B/sample". Stating that now prevents discovering it at the end.

## 5. The five hazards — all verified present in the current code

Each **constrains the design**; none is hypothetical.

| # | hazard | site (verified 2026-07-28) | how it is handled |
|---|---|---|---|
| 1 | **read/take aliasing** — `%select-samples` returns the SAME `cached-sample` objects, no defensive copy; `take` removes them from the cache, `read` leaves them | `entities.lisp:3119` | THE reason a loan contract is required at all: the lifetime becomes explicit instead of implied |
| 2 | **`dr-cache` is mutated from THREE thread contexts with no synchronisation whatever** — the application (read/take/samples-available), whatever thread calls `wait-set-wait` (its predicate `%drain`s, and `ws-lock` excludes no taker), and the discovery/announcer thread (`%on-disc-unmatch` → `%on-writer-vanished`; `%spin-once` → `%autopurge-sweep`) | `conditions.lisp:197, 207`; `entities.lisp` `%on-writer-vanished`, `%autopurge-sweep` | ✅ **SLICE 3 — FIXED.** A per-reader cache lock; see §10 |
| 3 | **`instance-rec-key-sample` retains sample #1 per instance FOREVER** for `get_key_value` | `entities.lisp:454, 1972, 2966` | ✅ **SLICE 4 — the wrapper carrying it is PINNED** and never recycled. ⭐ Costs **O(instances), not O(samples)**, so it amortises to ~0 and does not block the target. See §11 |
| 4 | **N≥2 same-topic readers leak the shared store sample** — purge is gated on `node-sole-consumer-p` | `entities.lisp:2987–2990`, `dataplane.lisp:3038` | a per-sample remaining-consumers refcount (the `%zc-bump` pattern). A real existing bug **and** a prerequisite for correct multi-reader recycling |
| 5 | **KEEP_LAST loan UAF guard** — never releases an app-held `:read` view | `entities.lisp:2235` | ✅ satisfied by construction: a pooled wrapper is recycled **only** by an explicit `return-loan`, never by cache eviction (§9) |

## 6. The contract change — consumers and migration

**Changed:** `take-samples`, `take-instance`, `take-next-instance`, `take-next-sample` return samples the
application **should** `return-loan`. ⚠️ **SHOULD, not MUST — and that is the as-built contract (§9).**
Because a missed return degrades gracefully, this is not a breaking change: existing callers keep working
unchanged and simply do not get the win. **Unchanged:** `read-samples` and the read-family; `return-loan` /
`return-all-loans` keep their signatures (a third dispatch arm is additive); `take-loaned` / `read-loaned`
are already loan-based.

**Migration for an application:** wrap a take in `unwind-protect` and `return-loan` the result — the shape
FlatData/ZC users already write. A missed return is **bounded and self-limiting**, not a crash: the pool
falls back to allocating, exactly as the writer's ZC pool degrades gracefully today.

**In-repo consumers** (the migration this ADR commits to doing in the same work): every `take-samples` call
site in `src/dds-tests/`, `src/dds-bench/`, the Shapes/interop drivers under `interop/`, and the durability
service's collect loop. The enumeration is a **prerequisite of slice 1**, done by grep at implementation
time and recorded here — not estimated now.

## 7. Plan — vertical slices, each independently `gate-mem`-measurable

Phase A being done, and per the VSD rule (thinnest end-to-end slice first, through every layer):

- **Slice 1 (MVP, end-to-end) — ✅ DONE, −171 B/sample.** See §9.
- **Slice 2 — ✅ DONE.** The **N≥2 remaining-consumers refcount** (hazard 4). `disc-node-sample-consumers`
  records K at store time **only when K ≥ 2**, and `node-consume-sample` decrements it, purging on the last
  drain; an absent entry means one consumer, so the common case is byte-identical and free. `%drain-one-sample`
  now purges unconditionally — the multi-reader question moved into the engine, where the store lives.
  This fixes a **real pre-existing leak**: `node-sole-consumer-p` refused to purge whenever two same-topic
  readers shared the store, so those samples were retained *forever* — the unbounded leak and O(stored)
  drain that `node-consume-sample` exists to prevent, reinstated for every multi-reader participant.
  Over-counting only re-leaks; under-counting would delete an undrained sample, so `routes` (a superset of
  the drainers) is the safe side. `node-sole-consumer-p` is kept as a query but gates nothing.
  Falsified both ways: ignoring the refcount turns `:adr93s-held-for-b` red (data loss); restoring the old
  gate turns `:adr93s-freed` red (the leak, holding 4). 621/621 both impls, gate-mem unchanged.
  ⚠️ Test-writing trap found here: `samples-available` **drains**, so polling it on the second reader
  consumes that reader's share before the assertion — the first cut reported a leak-fix that had not
  happened.
- **Slice 3 — ✅ DONE.** Hazard 2 was **not** safe; serialised. See §10.
- **Slice 4 — ✅ DONE, −32.5 B/sample.** See §11.

Each slice: rank by profile, size by a `*flag*` A/B **set globally** (a `let` binding is thread-local and
reads as a no-op on the receiver/user threads — the trap that produced two false "duds" in the campaign),
then validate on both impls plus `make interop`. RX is receive-side, so **the correctness gate is DELIVERY**
(the copy/loan/secured + n-reader/same-topic/keeplast/late-joiner suites), not byte-identity.

## 8. Measurement discipline

- `gate-mem` (60 000 samples, live two-participant DCPS over SHMEM) is the **only** oracle. Per-site
  harnesses over-report and are for ranking only.
- ⚠️ **Bank each win on the arch you measured, and check the other.** arm64 and x86_64 move by materially
  different amounts (ADR 0087: −82.4 vs −125.4; ADR 0088: −27.7 vs −72.9) and neither may be derived from
  the other. Lowering only one row leaves the other stale and makes CI **fail on improvement** — which has
  already happened once.
- Current position: **arm64 1739 B/sample (ceiling 1775)**, **x86_64 1704.5 (ceiling 1740)**; phase split
  arm64 receiver ~790 / TX ~668 / take-hit ~291. Slices 1 and 4 target the take-hit phase; the receiver and
  TX phases are separate work and are **not** covered by this ADR.

## 9. Slice 1 as built (2026-07-28) — **−171 B/sample**

`take-samples` hands back wrappers the application returns with `return-loan`; a returned wrapper is parked
on a per-reader pool and reused. `return-loan` gains a third dispatch arm; the two existing arms are
unchanged and the new one delegates to them, so each loan kind keeps exactly one release path.

| arm (arm64, SBCL, payload 0, 3 runs each) | mean B/sample |
|---|---|
| baseline — no `return-loan` (pre-ADR-0093 workload) | 1738.8 |
| application returns, pooling **OFF** | 1739.2 |
| application returns, pooling **ON** | **1568.1** |

**The `return-loan` call itself is free** (baseline ≈ pooling-OFF), so the whole delta is the recycling.

**Three things the implementation learned that the plan did not contain:**

1. **The pair is pooled as ONE object.** A parked wrapper keeps its `sample-info` attached, so one pop
   yields both. Two separate pools would have needed two pops and a link.
2. **A list freelist ate a fifth of its own win.** `push`/`pop` conses 2 conses = 32 B/sample against a
   ~144 B prize (measured 1600.1 with lists vs 1568.1 with a `simple-vector` stack). *A pool whose
   bookkeeping allocates is not a pool.* The pool is also **capped** (`*rx-wrapper-pool-capacity*`, 64):
   steady state needs one, and an unbounded freelist is a leak wearing an optimisation's clothes.
3. **The A/B lever leaked while it was off** — `%recycle-*` ran unconditionally while acquire was gated, so
   every return pushed onto a pool nothing drew from (+33.5 B/sample, unbounded growth). Caught only
   because the OFF arm was *measured* rather than assumed. **A lever must be a true no-op on both ends.**

⚠️ **The in-repo call-site migration promised in §6 is NOT done, and does not need to be.** Because a
missed return degrades gracefully, the 50 `take-samples` sites in `dds-tests` / `dds-shapes` / `dds-bench` /
`interop` keep working unchanged; migrating them is a per-site *benefit*, not a correctness prerequisite.
Only `mem-per-sample` was given the return (behind `:return-loans`, default NIL) so the slice could be
sized. Calling that migration a prerequisite in §6 was wrong.

**The win IS ratcheted, on arm64 — `gate-mem` measures BOTH workloads** (owner directive, same day). Rather
than flipping one default and re-baselining everything, the gate now runs **two arms** and carries **two
ceilings per arch**:

| arm | workload | arm64 ceiling |
|---|---|---|
| **COPY** | the application takes samples and drops them — the legacy arm, so every historical row stays comparable | 1775 |
| **RETURN** | the application `return-loan`s each sample, i.e. honours this ADR's contract | **1600** |

Measuring only COPY would have left this slice's −171 B permanently unratcheted and free to regress
silently. **Each arm runs in its own process on its own domain** — sharing either lets the arms discover
each other and reads high (§9 finding 3). An arch whose RETURN ceiling is `-` is still **measured and
reported**, with the row to paste in, but not gated: so **x86_64 prints the number it needs instead of
going red**, and nobody is tempted to predict it from arm64. Filling that dash needs a run on x86_64 —
the one follow-up that remains.

**The gate is falsified three ways**, each seen red: a RETURN regression fails; a RETURN *improvement*
fails and demands a lower ceiling; a `-` ceiling reports without failing.

**Correctness gate.** The risk is a partially re-initialised recycled struct handing the application a
*previous* sample's field: silent, and invisible to any allocation gate. The `rx-wrapper-pool` test poisons
all 13 `sample-info` slots on a parked struct and asserts none survives. It observes the struct at **drain**
time, because `%select-samples` legitimately re-stamps three of the slots at selection (DDS 1.4
§2.2.2.5.4) — testing through `take` would have covered 10 of 13 *while appearing to cover all of them*.
Falsified both ways: dropping one slot from the re-init turns `:adr93-no-stale-sn` red and nothing else;
never recycling turns `:adr93-reused` red.

## 10. Slice 3 as built (2026-07-28) — hazard 2 was real, and worse than "unproven"

The reader cache was built on `%drain`'s claim that both streams are drained on the user thread "so the
reader cache + instance-recs are never mutated off-thread (S2)", and on `dr-keyhash-scratch`'s that the
take path is "single-threaded-per-reader". **Both were false**, and there is no lock anywhere on the
reader: `dr-cache` is `setf`/`nconc`'d at ~10 sites from the three contexts in §5 hazard 2.

**Fixed with a per-reader cache lock** (`%with-reader-cache`), taken by `%drain`, `%select-samples`,
`return-loan`, `take-loaned`/`read-loaned`, `samples-available`, the WaitSet predicates
(`%count-matching`, `%count-matching-query`), `%on-writer-vanished` and `%autopurge-sweep`.

- **Lock order: cache lock OUTER, node lock INNER.** Safe against the discovery path because dds.disc
  fires `on-unmatch` *outside* the node lock (`%prune-participant-locked` hands its removed matches out
  first). Nothing takes the node lock and then the cache lock.
- **Not recursive**, so the two callers that arrive already holding it — the KEEP_LAST loan drop inside
  `%drain`, and `return-loan` recursing into a wrapper's backing loan — go through
  `%return-loan-unlocked`.
- **Drain and select are two separate critical sections, deliberately.** The safety property needed is
  that no list mutation interleaves with another and that a wrapper handed out is out of the cache before
  it can be recycled; both hold per-section. Holding one lock across a whole read/take would serialise
  more for no safety gain. Two concurrent takers may each miss samples the other got — DDS never promised
  otherwise — but neither corrupts.

⚠️ **This was not only a slice-4 prerequisite: slice 1 had already made it a CRASH.** Before slice 1 the
race lost or duplicated samples. After it, `%recycle-delivery` clears a returned wrapper's `data`, so a
concurrent taker holding that wrapper reads `NIL` — falsified exactly so: with the lock removed, the test
dies with `TYPE-ERROR: NIL is not SHAPE-TYPE` on a taker thread and the process takes a **fatal sig10**.
So commits `3aed0a1`..`508ae5e` carry a narrow crash window for an application that both takes from two
threads on one reader **and** returns its loans. Narrow, but real, and introduced here rather than
inherited.

**Test** `reader-cache-race`: two threads take from one reader while a writer publishes 200 keyed samples;
the union must be exactly those 200 with no duplicate. Falsified by disabling the lock (process dies).
622/622 both impls; **gate-mem unchanged** — the lock costs no allocation.

## 11. Slice 4 as built (2026-07-28) — **−32.5 B/sample**, and the pin is the point

`deserialize-into-<name>` had been generated for every type since the FlatData work and **deliberately
unused** — it needs a pooled target, which is what this ADR introduced. It is now bound on the type-support
as `:deserialize-into` (NIL for FlatData, whose into-variant fills a *buffer*, not a struct) and the drain
decodes into a struct popped from a **per-reader** pool.

| | RETURN B/sample (3 runs, arm64) | mean |
|---|---|---|
| after slice 1 | 1569.5 · 1567.2 · 1567.6 | 1568.1 |
| **after slice 4** | 1534.9 · 1534.0 · 1536.3 | **1535.1** |

Ceiling lowered 1600 → **1570**. Cumulative vs the non-returning arm: **~203 B/sample** (1738 → 1535). The
win is modest beside slice 1's 171 because `gate-mem`'s type is small at payload 0 — this removes *one
struct per sample*, so it scales with the type.

**Per-reader, not the existing per-type `dds.types:sample-pool`:** that pool is shared across readers (so
it would need its own lock, outside the slice-3 reader lock) and its `sample-pool-release` has **no bounds
guard** — releasing past capacity writes out of the backing vector. Per-reader is also what makes the pool
type-safe without a check: one reader has exactly one type.

**⚠️ Hazard 3 is the whole slice.** The first sample of each instance is retained *forever* by its
`instance-rec` as the `get_key_value` key holder. Had it returned to the pool, a later delivery would
decode into it and **silently rewrite the key of an instance the application can still query** — a
correct-looking API handing back another sample's data. So that wrapper is **pinned** and never recycled;
the pool loses one struct per *instance*, which is O(instances) and amortises to nothing.

Every non-delivery path hands the popped struct straight back (decode failure, filter miss,
RESOURCE_LIMITS reject, both EXCLUSIVE drops). Missing one would not corrupt anything — it would quietly
drain the pool until it stopped helping.

A half-written struct left by a *failed* decode is harmless: the generated `deserialize-into` resets every
slot to its default before the walk, so the next use rewrites it wholesale.

**Falsified:** ignoring the pin turns `:adr93p-not-recycled-key` red. 623/623 both impls; **corpus 0
mismatches on both** — the code generator changed, so byte-exactness was the thing to check.

## 12. Two known-unknowns carried in, not papered over

- **A ~65 KB per-run allocation** inside the measured window, 0–3 times per run, still unexplained. At
  60 000 samples it amortises to ~1 B so the gate is not perturbed — but it is a real, possibly leaking,
  steady-state allocation nobody has chased. If the take-hit phase approaches zero it becomes visible.
- **SBCL boxing** is the likeliest hidden constant (closures, `&rest`, u64s crossing the fixnum range). The
  ADR 0088 closure bug was exactly that class and was invisible to every correctness test — only `gate-mem`
  caught it.
