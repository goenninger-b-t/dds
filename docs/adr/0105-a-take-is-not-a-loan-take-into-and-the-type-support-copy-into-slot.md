# ADR 0105 — A take is not a loan: `take-into` / `read-into`, and a `copy-into` slot on `type-support`

- **Status:** **Accepted** — owner accepted 2026-08-06 by directing execution of the slice-1 plan
  (`docs/superpowers/plans/2026-08-06-adr-0105-slice-1.md`). Implementation may proceed.
- **Date:** 2026-08-06
- **Owner ECR (2026-07-28, verbatim):** *"Differentiate between take and loan. A take is not a loan. And a
  take still must be 0 consing and not allocating memory due to being in the hot path."*
- **Requirements:** **NFR-MEM** (steady state allocates zero bytes/sample), FR-PF-7, NFR-PERF-8, FR-LANG-5,
  NFR-SEC-POSTURE (the growth ceiling), NFR-CLOS (why the copier is a vtable slot, not a generic function).
- **Contract touched:** **`DDS.TYPES:TYPE-SUPPORT` — an M0-FROZEN interface contract**
  (`IMPLEMENTATION-PLAN.md` §3.2 / §7.3). Consumers + migration in §6.
- **Amends:** **ADR 0093** (which made the copy path a loan). Does **not** supersede it — the loan variant
  stays and is unchanged.
- **Design document:** `docs/superpowers/specs/2026-08-06-take-vs-loan-design.md` (the reasoning, the
  verification record, and the hazard analysis; this ADR is the decision and the contract).

---

## 1. The decision

Add a **second, non-loan access operation** rather than changing what `take-samples` does:

```lisp
(dds.dcps:take-into dr data infos &key states where view-states instance-states max-samples)
  ⇒ (values count status)
(dds.dcps:read-into dr data infos &key …)          ; the non-destructive twin
```

The application allocates the `data` and `infos` vectors **once** and reuses them; the operation fills them
**in place** and returns how many elements it wrote. **No loan, no return obligation.**

**Why this shape and not two renamed operations:** DDS 1.4 does not define take and loan as two operations.
§2.2.2.5.3.8 selects loan-vs-copy from the state of the collection **the caller passes in** — `max_len == 0`
loans (`owns = FALSE`, `return_loan` required), `max_len > 0 && owns == TRUE` copies into the application's
storage, and `max_len > 0 && owns == FALSE` is `PRECONDITION_NOT_MET` *"to avoid the potential hard-to-detect
memory leaks caused by an application forgetting to return the loan."* Our `take-samples` is **neither**: it
returns a fresh list of middleware-owned wrappers. `take-into` is the missing `owns == TRUE` variant.

**`read-into` ships in the same slice, not later.** §2.2.2.5.3.8 is the *read* clause and take inherits it;
shipping only `take-into` would leave `read` with no `owns == TRUE` variant — a conformance gap.

## 2. Owner decisions this ADR records (do not re-litigate)

| decision | consequence |
|---|---|
| **The zero is ABSOLUTE** — application storage included | rules out returning a list (a list conses); the destination *and* the result container are app-owned and reused |
| **App-supplied vectors + a count**, not a visitor form | mirrors DDS's `data_values` / `sample_infos` pair, so the conformance story is a clause mapping |
| **Capacity GROWS ONCE on overflow, in chunks, to a ceiling** | §5; past the ceiling the sample is **refused and counted**, never truncated |
| **Never recycle a struct that was handed out** | §4.1 — the `read`-then-`take-into` hazard |
| **Slice 1 is WIDENED until the arm reads genuinely 0** | §7 — it carries five further RX allocations, not just the API |

## 3. The contract

`data` and `infos` are application-allocated simple-vectors of type-correct sample structs and `sample-info`
structs. `max_len` is `(length data)` in this PSM; there is no separate argument.

| condition | result | clause |
|---|---|---|
| `(/= (length data) (length infos))` | `PRECONDITION_NOT_MET` | rule 1 — the collections must agree, one-to-one |
| `max-samples > (length data)`, excluding `LENGTH_UNLIMITED` | `PRECONDITION_NOT_MET` | rule 5, third bullet |
| a loan-capable (ZC / FlatData / secured) reader, in slice 1 | `PRECONDITION_NOT_MET` | §4.4 |
| disabled reader | `:not-enabled` | §2.2.2.1.1.7 |
| nothing selected | `count = 0` + `NO_DATA` | §2.2.2.5.3 |

Nothing signals: `(values count status)` throughout (`gate-nocond` ratchet is at 0).

**At an index whose sample has `valid_data = FALSE`, NOTHING in the destination sample is meaningful — not
even the key fields.** The middleware wrapper carries `data = NIL` there (`entities.lisp:2254`, `2258`), so
there is nothing to copy and the destination is left exactly as the previous call left it: it holds some
*earlier* sample's fields, and on a multi-instance reader that is a **different instance's key**. With
`take-samples` the application sees a literal `NIL` it cannot miss; a pre-allocated destination cannot. The
instance is identified **solely** by `SampleInfo.instance_handle` (with `get_key_value` available to turn
that handle into a key sample). Spec-legal, but a real divergence: it is part of the documented contract,
and the copy step must not fault on a NIL source.

⚠️ **An earlier draft of this clause said "only the key fields are meaningful", and that was wrong in a way
its own test could not see** — the test disposed the same instance whose sample the destination last held,
so a stale key and a correctly-filled key were indistinguishable. The arm now establishes a *second*
instance in between, and asserts the destination's key is the **other** instance's.

## 4. The mechanism, and the hazards that shape it

⚠️ **Decode is LAZY and happens inside the take call** — `take-samples` → `%drain` (`entities.lisp:3512`) →
`%drain-unlocked` (`3280`) → `%drain-one-sample` (`3156`), which holds the only deserialise sites. The
receiver thread is **wake-only** (`%wake-reader-data`; `conditions.lisp:76-82` only signals condvars). *An
earlier draft of the design asserted the opposite and was refuted against the code.*

`take-into` therefore **cannot** deserialise straight into the application's struct: `%drain` and
`%select-samples` are deliberately separate critical sections (`entities.lisp:3477-3482`), so at decode time
neither the destination slot nor even whether the sample will be selected is known. **The copy stays.** What
makes zero reachable is that the decoded sample is already in a *middleware-owned pooled struct*
(`%rx-data-pop`, `3192`) at the moment of the copy, so it can be recycled with no application involvement —
which the loan variant, by definition, cannot do.

### 4.1 `read` then `take-into` must not rewrite the application's already-read samples

`read-samples` is non-destructive and returns the cache's **own** wrappers (`3457`); they stay in `dr-cache`
with `sample-state = :read`, and the default mask `+any-sample-states+` is `(:read :not-read)`
(`statuses.lisp:149`). So a later `take-into` re-selects them and would recycle structs the application still
holds. `%recycle-delivery`'s docstring (`591-597`) states it is deliberately never called on cache eviction
for exactly this reason.

**Decision: a `was-exposed` bit on `cached-sample`**, set whenever a wrapper is handed to the application by
any read/take path. `take-into` recycles only structs whose bit is clear. State-mask semantics are untouched;
a previously-read sample is still *taken*, merely not recycled, so that one allocates.

⚠️ **"ANY READ/TAKE PATH" IS THREE PATHS, NOT ONE, AND THE FIRST CUT WIRED ONLY ONE.** The set is exactly the
set `%note-accessed` is called from — its docstring already enumerated them: `%select-samples-unlocked`
(`read-samples` / `take-samples` and the six `_instance`/`_next` entries), **`take-loaned`** and
**`read-loaned`**. `read-loaned` is the dangerous member and it is not the obvious one:

- it hands the application the middleware's **pooled deserialized struct**, exactly as `read-samples` does;
- it **leaves the wrapper in `dr-cache`**, so the default `(:read :not-read)` mask re-selects it; and
- for a plain copy-backed sample it registers **nothing** in `dr-loans` / `dr-secured-loans`, so §4.4's
  outstanding-loan refusal — the guard that would otherwise have covered for the missing latch — does not
  fire.

Measured on the working tree with the latch set only in `%select-samples-unlocked`: after `read-loaned`, a
`take-into` was accepted, recycled the struct, and the next delivery decoded into it — the application's held
sample went from `v=7 tag="held"` to `v=100 tag="ovr100"` with no error and no test red.
`take-loaned` needs the latch only for symmetry (it empties `dr-cache`, so its wrappers are unreachable to a
later selection); it is set there anyway, because the rule is *a sample leaving the middleware latches*, not
*a sample whose omission currently bites latches*.

⚠️ **It is a BIT, not a slot, and that is measured rather than stylistic.** It shares one packed `flags` slot
with ADR 0093's `data-pinned` (`+cs-flag-was-exposed+` / `+cs-flag-data-pinned+`). Added as its own boolean
slot it took `cached-sample` from **47.8 B to 63.9 B** on SBCL/arm64 (4-slot vs 5-slot defstruct, measured),
and the **COPY arm allocates one wrapper per sample** — it never returns a loan, so it never recycles — which
cost a measured **+17 B/sample on precisely the arm this ECR exists to drive to zero**, while RETURN (which
recycles) was unaffected. **A future third per-wrapper boolean is free as a flag and costs 16 B/sample as a
slot.** The asymmetry between the two arms is the diagnostic: a per-wrapper cost shows up only where wrappers
are not recycled.

### 4.2 Copy and recycle happen INSIDE the reader cache lock

`%rx-data-pop` / `%rx-data-push` (`558-583`) are unsynchronised read-modify-writes on plain slots, and every
current caller reaches them under `%with-reader-cache`. Three contexts already mutate reader state, **and
`on_data_available` listeners run on the receiver thread** (`2276`, `3794`) with shipped code calling take
from inside them (`xperf.lisp:54`, `61`). Recycling outside the lock races two threads onto one struct — the
ADR 0085 shape. The safe implementation and the zero-cons implementation coincide.

### 4.3 Extend the existing selection core; do not reimplement it

A private loop would have to replicate the three-mask predicate (`3441`), the §2.2.2.5.4 view/instance-state
snapshot stamping (`3448-3451`), `%note-accessed` for APP-ACK (`3454`), `%release-secured-copy-loan` (`3455`)
and the `touched` → `dr-instances` marking (`3452`, `3459`) — or silently lose them.

### 4.4 Arms slice 1 REFUSES

`deserialize-into-<name>` is **already** the live drain path (bound `dsl.lisp:1294`, funcalled
`entities.lisp:813-816`) — this is not its first consumer. Three arms are excluded from it and each is where
a copy path still allocates: **Zero-Copy/FlatData** (`%drain-one-loan` puts a `flatdata-view`, not a struct,
into `cached-sample-data` at `2934` and registers it in `dr-loans` — copying and pooling that would never
`%zc-release`, **recreating the ADR 0096 slot leak**), the **DDS-Security decode loan**, and **FlatData types
generally** (never bind the slot). `take-into` refuses a loan-capable reader in slice 1; widening is slice 3.

### 4.5 Recycle THROUGH `%recycle-delivery`, never by pushing the struct back

`%drain-one-sample` pins the first delivered struct per instance as that instance's key holder (`3244-3246`),
honoured on recycle via `cached-sample-data-pinned` (`609`). Bypassing it rewrites the instance's key under
`get_key_value` on the next delivery — silent, application-visible, covered by no existing test.

⚠️ **The destructive half is NOT atomic, and slice 1 records that rather than hiding it.** The recycle for
sample *i* runs inside the copy loop while the `dr-cache` commit runs after it, so a non-local exit part-way
through leaves earlier wrappers **both** parked on the wrapper pool **and** still listed in the cache — one
wrapper describing two samples, plus a `valid_data = T` entry whose `data` is `NIL`. That state was
*reproduced* on the working tree, reached by the most ordinary application mistake (a destination vector of
zeros). §6.1's destination validation closes **every trigger the middleware controls**; what remains is an
application-supplied `WHERE` predicate that itself signals, which is out of contract for every access
operation here and harmless for the list-returning ones because they do nothing destructive before their own
commit. Making it unconditionally atomic means deferring the recycles past the commit — a hot-path change,
which under `FR-LANG-7` needs a before/after measurement, so it is **slice 2 work**, not an unmeasured
tidy-up.

### 4.6 Not a hazard — recorded so it is not re-investigated

Multiple readers sharing one store sample is already safe: each decodes its own struct and the entry is
purged on the last drain via the `disc-node-sample-consumers` refcount (`dataplane.lisp:3234-3260`).

## 5. Variable-size capacity (slice 2)

Growth is **whole chunks, never exact-fit** (ADR 0102 rejected exact-fit because the budget then creeps up
one allocation at a time until the ceiling means nothing), monotone, never shrinking, to a per-reader ceiling.
Past the ceiling the sample is **refused and counted** (ADR 0101's reject-don't-fall-back ruling).

⚠️ **"Never shrinking" is not implementable in slice 1's representation, and slice 1 does not pretend it is.**
A `:sequence` member's slot type is the unspecialised `vector` and a `:string` member's is `string`
(`dsl.lisp` `%parse-member`) — **no fill pointer, so capacity and logical length are the same number.** A
destination longer than the source can therefore be made to *read* at the source's length only by allocating.
Slice 1's `%copy-seq-into` (`src/dds-gen/runtime.lisp`) consequently reuses **only** on an exact length +
element-type match and allocates once otherwise, and says so; it does **not** claim a longer destination is
free. Splitting capacity from length — a fill-pointered/adjustable slot representation, or a companion length
slot — is **part of slice 2's work**, not a detail of it, because monotone growth is meaningless without it.

⚠️ **The element-type test in that function is a correctness guard, not a tuning knob.** Because the slot type
is the unspecialised `vector`, an application may legally pre-size a destination as `(unsigned-byte 8)`;
`replace`-ing a `(signed-byte 32)` source into it signals a `TYPE-ERROR` **after partially overwriting the
destination** — a Lisp condition escaping `src/`, which the standing order forbids outright. A representation
mismatch falls to the allocating branch instead.

⚠️ **The growth is remote-drivable** — a peer chooses the payload sizes and therefore our high-water mark.
The ceiling is the security control, not a tuning knob (NFR-SEC-POSTURE resource-exhaustion class).

⚠️ **There is no standard DDS status for refusing an over-large sample.** `SampleRejectedStatusKind`'s
documented kinds are all **count**-based (instances / samples / samples-per-instance) — verified against the
spec text, not recalled. The refusal is therefore reported as the generic `OUT_OF_RESOURCES`, or through a
**vendor status bit chosen clear of the OMG 0–14 range entirely** (the ADR 0080 `UNADDRESSABLE_PEER`
precedent), via `%notify-status`, never printed. DDS 1.4 leaves bits 3 and 4 unassigned *inside* the OMG
range: a vendor bit must **not** be parked in those holes.

## 6. THE CONTRACT CHANGE — every consumer, and the migration

**`type-support` gains one slot:**

```lisp
;; ADR 0105: (src dst) -> fills DST from SRC in place, DEEP for every reference slot. NIL for a
;; FlatData type (its sample IS a buffer, so take-into refuses such a reader in slice 1).
(copy-into nil :type (or null function))
```

and the generator emits a per-type `copy-into-<name>` bound to it.

**`type-support` gains a SECOND slot, added during slice 1's review and recorded here rather than left
silent:**

```lisp
;; ADR 0105: the generated <name>-P structure predicate. take-into VALIDATES each application-supplied
;; destination element with it. Bound for EVERY type, FlatData included.
(sample-p nil :type (or null function))
```

**Why a predicate had to exist at all, and why NIL-testing was not enough.** `copy-into-<name>` is declaimed
`(function (<name> <name>) <name>)` and `%copy-sample-info-into` is `(sample-info sample-info)`;
`entities.lisp` carries no `(safety 0)`, so a wrong-typed destination element makes SBCL signal a
**`TYPE-ERROR` out of the middle of the copy loop** — a Lisp condition escaping `src/`, which the standing
order forbids outright, and which `gate-nocond` cannot see because it is raised by a type declaration in
generated code rather than by a signalling form. It is not a theoretical shape: `(make-array 32)` is the
obvious reading of "vectors the application allocates once", and SBCL fills a simple-vector with **zeros**,
so the *first* element faults. A NIL test would therefore not have caught the most likely mistake — hence a
type predicate, not a null check. `take-into` validates indices `0..max_samples-1` of both vectors up front
and returns `PRECONDITION_NOT_MET`; elements past that bound are deliberately not examined, and that is
asserted too.

The generator now names the predicate explicitly (`(:predicate <name>-p)`) instead of relying on
`defstruct`'s default, so the vtable binding does not depend on where the symbol happens to intern. The
emitted name is identical to the previous default, so existing users of `mline-p` / `mpoint-p` are
unaffected.

**Why a vtable slot and not a generic function:** the hot path is CLOS-free (NFR-CLOS); a `defgeneric`
copier is barred outright. The `type-support` struct *is* the manual vtable (`IMPLEMENTATION-PLAN.md` §7.3).

**Why not CL's default `COPY-<NAME>`:** it is a **shallow** copier — it allocates a fresh struct and
**aliases** every string/sequence/nested slot into it, which is precisely the aliasing hazard this ADR
exists to prevent.

**Why not `type-support-sample-pool-alloc` / `-free`:** those hooks are **dead in the engine and were
deliberately rejected** (`entities.lisp:177`) — the per-type pool is shared across readers, and
`sample-pool-release` had no bounds guard. *(That guard is now fixed, `1eb4c31`.)* Recycling uses the
per-reader `dr-data-pool`.

### 6.1 Consumers — measured, not estimated

| consumer | impact |
|---|---|
| `src/dds-gen/dsl.lisp` — the **only production constructor** | binds the new slot; emits `copy-into-<name>` |
| `src/dds-types/type-support.lisp` (defstruct) + `packages.lisp` (export) | **two** slots + their exports |
| `src/dds-tests/xtypes-test.lisp` ×2, `src/dds-tests/integration-test.lisp` ×1 | **no change** — see below |
| every reader of the other 18 slots | **no change** |

**The migration is empty for both slots, and that is a property of the change, not an accident.**
`make-type-support` is a keyword constructor, so an added slot defaults to `NIL` in every existing call. **Precedent: ADR 0093 slice 4
added the `deserialize-into` slot to this same frozen struct the same way** (`type-support.lisp:39`). The
frozen-contract gate applies because the struct shape is frozen — not because the change breaks anyone.

⚠️ **What a consumer MUST NOT assume:** `copy-into` is `NIL` for a FlatData type, exactly as
`deserialize-into` is, and both new slots are `NIL` on any hand-built `type-support`. A caller must test
them, not assume they are bound. `%access-into` refuses a reader whose type-support lacks **either**, in one
clause: without `sample-p` the destinations cannot be validated, so proceeding would mean skipping a refusal
the contract promises.

## 7. Slices

**Slice 1's exit criterion is a genuinely-0 arm** (owner decision). `take-into` alone does not get there —
five further per-sample allocations remain, measured on arm64 SBCL 2.6.5:

| site | what | B/sample |
|---|---|---|
| `dataplane.lisp:4700` | `(cons guid sn)` per pending key | 16.05 |
| `entities.lisp:800` | fresh 4-slot `cursor` per decode | 48.16 |
| `entities.lisp:3251-3253` | `(list …)` cell `nconc`'d onto `dr-cache` | 16.05 |
| `entities.lisp:3457` | `(push cs out)` per selected sample | 16.05 |
| ~~`entities.lisp:3452`~~ | ~~`(pushnew h touched :test #'equalp)`~~ — **DONE, Task 5**: measured **−16.2 COPY / −14.2 RETURN** | ~~16.05~~ |

≈**112 B/sample**, of which only the `out` cons falls out of `take-into` itself. The cursor needs a
**repoint-in-place** variant: `cursor-reuse`'s `EQ` test misses here because the ADR 0078 pool hands out a
different buffer each time.

**Internal order — separate, independently measured sub-steps.** The receive path is where the ADR 0078 heap
corruption lived; no big-bang edit.

1. `copy-into-<name>` + the slot + the `was-exposed` bit
2. `take-into` / `read-into` on the plain drain arm, refusing loan-capable readers
3. the `out` cons · 4. the `touched` cons, the `dr-cache` cell, the pending-key cons · 5. the cursor
6. the new bench type + the `gate-mem` arm, then bank the ceiling

### 7.1 The measurement does not exist yet — and this is the sharpest risk

`mem-per-sample` is hardwired to `perf-data` (`xperf.lisp:277`), which is **not fixed-size**
(`(data (:sequence :octet))`); a zero-length sequence still costs a measured **15.73 B/sample**. Slice 1 adds
a **fixed-size bench type with a ≤16-octet key**, its own arm and its own domain.

⚠️ **The key bound is load-bearing.** A fixed-size type whose key is a string or exceeds 16 octets takes the
MD5 branch (`dsl.lisp:610-612`), measured at **255.6 B/call** on `shape-type` — and neither `dsl.lisp` nor
`md5.lisp` is in `HOTPATH_FILES`, so the tracked inventory would never reveal it.

`bench/mem-ceiling.txt` gains a fourth column, `<arch> <copy> <return> <into>`. A 4th field is silently
ignored by today's parser, so the file edit is backward-compatible — but the reader must add the new column
**with the same empty→dash default and numeric-or-dash guard as the existing ones**, or an absent value
coerces to `0` and the arm becomes a permanently-green no-op.

### 7.2 Later slices

| slice | scope |
|---|---|
| 2 | variable-size fields: chunked grow-once, the ceiling, the refusal status (§5) |
| 3 | the loan-capable arms §4.4 refuses |
| 4 | the ECR's naming half — the operation called *take* stops being a loan |

**Slice 4's surface is measured: 54 occurrences on 53 lines.** ADR 0093 §6's enumeration is prose and its §9
retracts it; `src/dds-durability/` is **not** a consumer. Three of the 54 are not tests —
`src/dds-dcps/conditions.lisp:305`, `src/dds-log/collector.lisp:51`, and **`scripts/gate-arena.sh:70`**,
which means a rename **breaks a quality gate** that no test run would catch. `take-into` / `read-into` are
free; `take-loaned` / `read-loaned` are **not** available as a rename target (they are the FlatData-ZC *and*
DDS-Security decode loan API, return `(values data loans)` of raw data, skip the enabled check and the
state-mask/WHERE filtering, and are gated pending counsel).

## 8. Verification

Every gate falsified and seen red: the copy is a real deep copy (not an alias) · every slot copied, observed
**at the copy** rather than through a later read (ADR 0093 covered 10 of 13 slots *while appearing to cover
all*) · `read`-then-`take-into` leaves read samples intact · `get_key_value` survives · a loan-capable reader
is refused · an invalid-data index does not fault and leaves the destination untouched · both spec refusals ·
a `take-into` from an `on_data_available` listener · the ratcheted zero arm · and both existing `gate-mem`
rows unchanged.

### 8.1 What slice 1's review added, each falsified

| arm | falsified by | observed red |
|---|---|---|
| `read-loaned` then `take-into` (§4.1's third path) | deleting the latch in `read-loaned` | `:tie-latched` |
| …and its payload | deleting the `was-exposed` test in the recycle guard | `:tie-not-corrupted` — the held sample read `v=100 tag="overwrite"` |
| destination elements validated | deleting the `%into-destinations-ready-p` clause | `:ti-dest-zeros`; with samples cached, `TYPE-ERROR` + a wrapper in **both** cache and pool |
| the destination-length bound | `(or max-samples (length data))` → `max-samples` | unhandled `TYPE-ERROR` (index past the app's vector) |
| the same bound, the form §7 names | `(< n max)` → `(<= n max)` | unhandled `INVALID-ARRAY-INDEX-ERROR` |
| the `dr-loans` half of the loan refusal | deleting that disjunct | `:ti-outstanding-zc-loan-refused` |
| the NIL-source guard | deleting `(when d …)` | unhandled `TYPE-ERROR` |
| the invalid-data arm's own precondition | removing the intervening second instance | `:ti-invalid-setup` |
| `take-into` from a listener, **writer-vanished** path | putting the wake back inside `%with-reader-cache` | `:til-no-conditions` — `(:EXIT (:CONDITION SIMPLE-ERROR))` |

⚠️ **The listener requirement found a PRE-EXISTING defect that this ADR's own §4.2 had assumed away.**
§4.2 cites `on_data_available` listeners calling take as the justification for doing the copy and the recycle
inside the reader cache lock — but `%on-writer-vanished` fired that notification **from inside**
`%with-reader-cache`, which is not recursive, so a matched remote writer merely vanishing threw
`"Recursive lock attempt"` into the discovery thread of any application using the listener idiom. It hit
`take-samples` identically and had nothing to do with `take-into`; it survived because the *other* two firing
sites are outside the lock and nothing exercised this one. The notification is now collected inside the
critical section and fired after it — the discipline `%prune-participant-locked` already uses for the node
lock — and both firing paths are exercised.

### 8.2 Task 5 — the `touched` cons, and the spec violation its obvious fix would have been

The scratch list existed only to **defer** the `dr-instances` marking past the selection pass, and that
deferral *is* DDS 1.4 §2.2.2.5.1.4: `%snapshot-view-state` reads what the marking writes, so marking inside
the loop makes the **second** sample of a newly-accessed instance report `NOT_NEW` within the one call that
first accessed it, and changes what a `view_states` mask selects half-way through that same call. Deleting
the pass and the scratch together — the obvious simplification — is therefore a conformance regression, and
it was **checked, not assumed**: the sabotage printed `(:NEW :NOT-NEW)`.

**Nothing in the suite covered it.** Every other view-state assertion returns one sample per instance per
call, so all of them stay green while the ordering is broken. `run-view-state-snapshot-test` is new and
covers all four access paths in both directions:

| arm | falsified by | observed red |
|---|---|---|
| the ordering, list path | marking inside the selection loop | `:vss-list-both-new` — `(:NEW :NOT-NEW)` |
| the ordering, into path | the same, with the list arm suppressed | `:vss-into-both-new` — `:NEW / :NOT-NEW` |
| the marking still happens, list path | deleting its second pass | `:vss-list-then-not-new` |
| the marking still happens, into path | deleting its second pass | `:vss-into-then-not-new` |
| `take-loaned` marks | deleting its second pass | `:vss-loaned-take-marked` |
| `read-loaned` marks | deleting its second pass | `:vss-loaned-read-marked` |

The first two and the last four are **opposite** failures, so neither moving the pass into the loop nor
deleting it can be green.

**The per-reader scratch vector the slice plan prescribed was not needed.** The marking is idempotent, so
each path walks the set it has **already materialised** — the wrapper list it is about to return, the
SampleInfo vector it has just filled, or `dr-cache` itself for the loan paths, whose selection *is* the whole
cache. That leaves no new reader state and no growth bound to argue about. Residue, recorded in
`%mark-instance-accessed`'s docstring rather than checked: into-mode reads back **application-owned**
storage, so an application that puts the same `sample-info` object at two indices loses the first instance's
marking — already-broken usage (two indices cannot hold two samples), and enforcing distinctness would cost
an O(n²) `EQ` scan per call.

The same edit removed a real duplication: both loan paths carried their own inline copy of the view-state
rule instead of calling `%snapshot-view-state`, whose docstring already claimed to be its single definition.

**Cross-DDS interop:** `take-into` changes **no wire surface**. The per-feature interop rule is discharged by
no-regression against the existing Connext 7.3.1 and Fast DDS legs, stated rather than skipped.

## 9. Provenance

Every file:line here was verified against the working tree on 2026-08-06 by a parallel verification pass
(34 findings: 19 confirmed, 8 refuted, 7 partial). **Three refutations changed this design** — decode is not
on the receiver thread (§4), `deserialize-into-<name>` is already live (§4.4), and the `read`/`take-into`
aliasing hazard (§4.1), which no earlier draft contained. Two more corrected its numbers: the ≈112 B floor
(§7) and the absence of a standard status for an over-large sample (§5).

A second review pass over slice 1's Tasks 3–4 (2026-08-06) produced the amendments in §3, §4.1, §4.5, §6 and
§8.1. Each was **reproduced against the working tree before being accepted** — the `read-loaned` corruption,
the escaping `TYPE-ERROR` with the doubly-owned wrapper, and the recursive-lock error — and each fix was then
seen red with the fix removed. Two review recommendations were **not** taken and are recorded instead of
being silently dropped: making the destructive half unconditionally atomic (§4.5 — a hot-path change owing a
measurement, so slice 2), and earning a real Zero-Copy loan for the `dr-loans` refusal arm rather than
planting one (the registry membership *is* the predicate the production check reads, and a planted entry
tests it without making the arm depend on a live SHMEM fixture; the arm's stale claim that a real loan would
have required a platform-gated test — false since ADR 0103 closed the Clasp gap — has been removed).
