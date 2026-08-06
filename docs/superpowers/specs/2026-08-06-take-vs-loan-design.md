# Design — a take is not a loan (`take-into` / `read-into`)

- **Date:** 2026-08-06
- **Owner ECR (2026-07-28, verbatim):** *"Differentiate between take and loan. A take is not a loan. And a
  take still must be 0 consing and not allocating memory due to being in the hot path."*
- **Requirements:** NFR-MEM (steady state allocates **zero** bytes/sample), FR-PF-7, NFR-PERF-8, FR-LANG-5.
- **Amends:** ADR 0093 (which made the copy path a loan). Does **not** supersede it — the loan variant stays.
- **Status:** design approved 2026-08-06. **Superseded as the authority by
  [ADR 0105](../../adr/0105-a-take-is-not-a-loan-take-into-and-the-type-support-copy-into-slot.md)** — that
  ADR carries the decision, the frozen-contract change and the consumer list, and must be **Accepted before
  any code**. This document remains the reasoning, the hazard analysis and the verification record behind it;
  where the two differ, the ADR wins.

---

## 1. What the spec actually says, and why it reframes the ECR

DDS 1.4 does **not** define take and loan as two operations. There is one `read`/`take`, and loan-vs-copy is
selected by the state of the collection **the application passes in** (§2.2.2.5.3.8, rules 1–5):

| caller's collection | behaviour |
|---|---|
| `max_len == 0` | middleware **loans** its buffers, `owns = FALSE`, application **must** `return_loan` |
| `max_len > 0`, `owns == TRUE` | middleware **copies** into the application's own storage — no loan, no return |
| `max_len > 0`, `owns == FALSE` | **`PRECONDITION_NOT_MET`** — *"avoids the potential hard-to-detect memory leaks caused by an application forgetting to return the loan"* |

Our `take-samples` is **neither variant**: it returns a fresh list of middleware-owned `cached-sample`s.
ADR 0093 made them recyclable *if* returned, but the application cannot supply storage and is not required
to return. That is a loan that does not look like one — exactly the conflation the ECR names, and the spec
already prescribes the cure.

**Owner decision (2026-08-06): the zero is absolute** — nothing anywhere allocates per sample, the
application's destination included. So the destination *and* the result container are application-owned and
reused; a returned list is ruled out because building one conses.

## 2. The contract

```lisp
(dds.dcps:take-into dr data infos &key states where view-states instance-states max-samples)
  ⇒ (values count status)
(dds.dcps:read-into dr data infos &key …)          ; the non-destructive twin
```

`data` and `infos` are application-allocated simple-vectors of type-correct sample structs and
`sample-info` structs, allocated **once** and reused. `take-into` fills elements `0 … count-1` **in place**
and returns how many it wrote. No loan, no return obligation.

`read-into` ships in the same slice, not later: §2.2.2.5.3.8 is the **read** clause and take inherits it, so
shipping only `take-into` would leave `read` with no `owns == TRUE` variant — a conformance gap.

### 2.1 Refusals, pinned to the clause

| condition | result | clause |
|---|---|---|
| `(/= (length data) (length infos))` | `PRECONDITION_NOT_MET` | rule 1 — the two collections must agree and be one-to-one |
| `max-samples > (length data)`, excluding `LENGTH_UNLIMITED` | `PRECONDITION_NOT_MET` | rule 5, third bullet |
| disabled reader | `:not-enabled` | §2.2.2.1.1.7 |
| nothing selected | `count = 0` + `NO_DATA` | §2.2.2.5.3 |

`max_len` is `(length data)` in this PSM; there is no separate argument. Nothing signals a condition —
`(values count status)` throughout, per the standing no-conditions rule (`gate-nocond` ratchet is at 0).

## 3. Mechanism — corrected

⚠️ **An earlier draft of this design claimed the decoded sample is produced on the receiver thread. That is
false and was refuted against the code.** Decode is **lazy and happens inside the take call**:
`take-samples` → `%drain` (`entities.lisp:3512`) → `%drain-unlocked` (`3280`) → `%drain-one-sample` (`3156`),
which holds the only deserialise sites (`3200`, `3201`, `2998`). The receiver thread is **wake-only**:
`%on-participant-sample` → `%deliver-data-on-readers` → `%wake-reader-data`, and `%notify-reader-conditions`
(`conditions.lisp:76-82`) only signals condvars.

The conclusion survives on a different footing: **at the moment `take-into` would copy, the decoded sample is
already sitting in a middleware-owned pooled struct** (`%rx-data-pop`, `entities.lisp:3192`, decoded into at
`3200`). So the shape is:

```
wire → %drain-one-sample → pooled decoded struct ──┬─ take-samples → app holds it  → return-loan recycles   (loan)
                                                   └─ take-into    → copy into app → recycle under the lock  (copy)
```

`take-into` cannot deserialise straight into the application's struct: `%drain` and `%select-samples` are
**deliberately separate critical sections** (`entities.lisp:3477-3482`), so at decode time neither the target
slot nor even whether the sample will be selected is known. The copy stays.

## 4. The hazards, and what each forces

Each was verified present in the code; none is hypothetical.

### 4.1 ⛔ `read` then `take-into` would rewrite the application's already-read samples

`read-samples` is non-destructive and returns the cache's **own** `cached-sample` objects
(`%select-samples-unlocked` pushes the iterated `cs`, `entities.lisp:3457`). They stay in `dr-cache` with
`sample-state = :read`, and the default mask `+any-sample-states+` is `(:read :not-read)`
(`statuses.lisp:149`) — so a later `take-into` re-selects them, copies them out, and would recycle structs
the application is still holding. `%recycle-delivery`'s docstring (`entities.lisp:591-597`) says it is
deliberately never called on cache eviction for exactly this reason.

**Decision (owner, 2026-08-06): never recycle a struct that has been handed out.** A `was-exposed` bit is set
on `cached-sample` whenever a wrapper is returned to the application by any read/take path; `take-into`
recycles only structs whose bit is clear. DDS state-mask semantics are untouched, `%recycle-delivery`'s
invariant is preserved rather than contradicted, and the cost is one bit-test per sample. A previously-read
sample is still *taken*; it is simply not recycled, so that one sample allocates.

### 4.2 Recycling must happen **inside the cache lock**

`dr-data-pool-top` / `dr-wrapper-pool-top` are plain slots and `%rx-data-pop` / `%rx-data-push`
(`entities.lisp:558-583`) are unsynchronised read-modify-writes. Every current caller reaches them under
`%with-reader-cache`. Three contexts already mutate reader state — the application thread, whatever thread
called `wait-set-wait` (`conditions.lisp:199-200`), and the discovery/announcer thread — **and
`on_data_available` listeners run on the receiver thread** (`entities.lisp:2276`, `3794`) with real code
calling take from inside them (`xperf.lisp:54`, `61`). Recycling outside the lock races two threads onto one
struct. This is the ADR 0085 shape; the safe implementation and the zero-cons implementation coincide: **copy
and recycle inside the `%select-samples-unlocked` loop, under the cache lock.**

### 4.3 `take-into` must extend the existing selection core, not reimplement it

A private selection loop would have to replicate five behaviours or silently lose them: the three-mask
predicate (`3441`), the view/instance-state snapshot stamping §2.2.2.5.4 requires (`3448-3451`),
`%note-accessed` for APP-ACK acknowledgeability (`3454`), `%release-secured-copy-loan` (`3455`), and the
`touched` → `dr-instances` marking (`3452`, `3459`). Extend the core with a *write-into-these-vectors* mode.

### 4.4 Drain arms `take-into` must refuse

`deserialize-into-<name>` is **already the live drain path** (bound `dsl.lisp:1294`, funcalled
`entities.lisp:813-816`) — this design is not its first consumer. Three arms are excluded from it, and each
is where a copy path still allocates:

| arm | why `take-into` refuses it in slice 1 |
|---|---|
| **Zero-Copy / FlatData** | `%drain-one-loan` puts a `flatdata-view`, not a struct, into `cached-sample-data` (`entities.lisp:2934`) and registers it in `dr-loans`. Copying and pooling that would push a view into a struct pool and never `%zc-release` — **recreating the ADR 0096 slot leak**, one slot lost per sample until Zero-Copy silently degrades |
| **DDS-Security decode loan** | safe *only* if the existing selection core is reused, because the loan is released at `entities.lisp:3455` |
| **FlatData types generally** | never bind the `deserialize-into` slot at all (`dsl.lisp:1294`) |

`take-into` returns `PRECONDITION_NOT_MET` on a loan-capable reader in slice 1. Widening is a later slice.

### 4.5 Invalid-data samples

`%enqueue-instance-notification` builds wrappers with `:data nil` / `:valid-data nil` (`entities.lisp:2254`,
`2258`). With `take-samples` the application receives a literal `NIL` it cannot miss; with `take-into` the
application's pre-allocated struct at that index would otherwise keep the **previous** sample's contents.
Spec-legal (`valid_data = FALSE` means read the key fields only) but a real divergence: the copy must not
fault on a NIL source, and the contract must state that at such an index only the key fields are meaningful.

### 4.6 The `get_key_value` pin

`%drain-one-sample` retains the first delivered struct per instance as the instance's key holder
(`entities.lisp:3244-3246`), honoured on recycle via `cached-sample-data-pinned` (`609`, set at `3259`).
`take-into` must recycle **through `%recycle-delivery`**, never by pushing the struct back directly, or it
rewrites the instance's key under `get_key_value` on the next delivery — silent, application-visible, and
covered by no existing test.

### 4.7 Not a hazard — recorded so it is not re-investigated

Multiple readers sharing one store sample is **already safe**: each reader decodes its own struct from the
shared entry and the entry is purged on the last drain via the `disc-node-sample-consumers` refcount
(`dataplane.lisp:3234-3260`). There is no cross-reader struct sharing to break.

## 5. Contract changes this requires

1. **`type-support` gains a `copy-into` slot** and the generator emits a per-type `copy-into-<name>`.
   ⚠️ The `type-support` struct shape is an **M0-frozen interface contract** (`IMPLEMENTATION-PLAN.md:94`,
   §7.3) — this is ADR-gated with a consumer list, not an implementation detail. A `defgeneric` copier is
   barred by the hot-path CLOS rule, so a monomorphic function through the manual vtable is the only option.
2. **Do not reach for CL's default `COPY-<NAME>`.** It is a *shallow* copier that aliases every
   string/sequence/nested slot — the aliasing hazard this design exists to avoid.
3. **Do not route recycling through `type-support-sample-pool-alloc/free`.** Those hooks are **dead in the
   engine and were deliberately rejected** (`entities.lisp:177`): the per-type pool is shared across readers,
   and `sample-pool-release` (`type-support.lisp:118-124`) had **no bounds guard** — `(setf (svref … top) obj)`
   with `top` unchecked. Use the per-reader `dr-data-pool`.
   ✅ *That missing guard was a real latent defect found while verifying this design, and is **fixed
   separately** (`sample-pool-release` now refuses an over-release with `:pool-overflow`; test
   `sample-pool-overflow`, falsified). ⚠️ Its consequence was **measured, not assumed**: the repo compiles at
   SBCL's default safety 1, where `svref` is bounds-checked, so the un-guarded release **signalled** rather
   than corrupting the heap — a condition escaping a pool release, which violates the no-conditions rule,
   and a genuine OOB write only at safety 0. The identical "(safety 0) OOB" claim about ADR 0078 was false
   for the same reason.*
4. **`sample-info` array slots are aliases onto write-once immutable arrays.** `instance-handle` and
   `publication-handle` are `copy-seq`'d **once per instance** (`entities.lisp:2238`), never per sample. A
   per-sample deep copy would cost a measured **+63.6 B/sample** and kill the target. `take-into` must
   `replace` into application-preallocated 16-octet arrays, or keep the alias — it must **not** introduce a
   per-sample copy, and it must never make either target mutable.

## 6. Variable-size fields — capacity (slice 2)

**Owner decision: grow once on overflow, then reuse.** Growth is in **whole chunks, never exact-fit** — ADR
0102 rejected exact-fit because the budget then creeps up one allocation at a time until the ceiling means
nothing — monotone, never shrinking, up to a per-reader ceiling. Past the ceiling the sample is **refused and
counted**, never truncated and never silently degraded (ADR 0101's reject-don't-fall-back ruling).

⚠️ **This growth is remote-drivable**: a peer chooses the payload sizes and therefore our high-water mark.
The ceiling is the security control, not a tuning knob (NFR-SEC-POSTURE resource-exhaustion class).

⚠️ **There is no standard DDS status for refusing an over-large sample.** `SampleRejectedStatusKind`'s
documented kinds are all **count**-based (instances / samples / samples-per-instance). Verified against the
spec text. So the refusal is reported either as the generic `OUT_OF_RESOURCES` or through a **vendor status
bit chosen clear of the OMG 0–14 range entirely** (the ADR 0080 `UNADDRESSABLE_PEER` precedent) — reported
through `%notify-status`, never printed. Note DDS 1.4 leaves bits 3 and 4 unassigned *inside* the OMG range:
a vendor bit must **not** be parked in those holes.

## 7. What "zero" honestly means, and what slice 1 covers

**Owner decision: widen slice 1 until the number is genuinely 0.** `take-into` alone does not get there —
five per-sample allocations remain that it never touches (measured on arm64 SBCL 2.6.5):

| site | what | B/sample |
|---|---|---|
| `dataplane.lisp:4700` | `(cons guid sn)` per pending key | 16.05 |
| `entities.lisp:800` | fresh 4-slot `cursor` per decode | 48.16 |
| `entities.lisp:3251-3253` | `(list …)` cell `nconc`'d onto `dr-cache` | 16.05 |
| `entities.lisp:3457` | `(push cs out)` per selected sample | 16.05 |
| `entities.lisp:3452` | `(pushnew h touched :test #'equalp)` | 16.05 |

**≈112 B/sample floor on the RX half**, of which only the `out` cons is removed by `take-into` itself. The
cursor is the same six-word struct the allocation campaign already eliminated at four other sites, but
`cursor-reuse`'s `EQ` test will **miss** here because the ADR 0078 pool hands out a different buffer each
time — it needs a repoint-in-place variant.

Slice 1 therefore carries all five, plus the API. Its exit criterion is a genuinely-0 arm. Its **internal
order** is separate, independently-measured sub-steps — the receive path is where the ADR 0078 heap
corruption lived, so no big-bang edit:

1. `copy-into-<name>` + the `type-support` slot (ADR-gated) + the `was-exposed` bit
2. `take-into` / `read-into` on the plain drain arm, refusing loan-capable readers
3. the `out` cons (falls out of filling vectors in place)
4. the `touched` cons · the `dr-cache` list cell · the pending-key cons
5. the cursor repoint-in-place variant
6. the new bench type + the `gate-mem` arm, then bank the ceiling

### 7.1 The measurement does not exist yet

`gate-mem`'s `mem-per-sample` is hardwired to `perf-data` (`xperf.lisp:277`), which is **not fixed-size** —
`(data (:sequence :octet))` — and a zero-length sequence still costs a measured **15.73 B/sample**. Slice 1
must add a **fixed-size bench type with a ≤16-octet key** and its own arm and domain.

⚠️ **The key bound is load-bearing.** A fixed-size type whose key is a string or exceeds 16 octets takes the
MD5 branch (`dsl.lisp:610-612`), measured at **255.6 B/call** on `shape-type` — and neither `dsl.lisp` nor
`md5.lisp` is in `HOTPATH_FILES`, so the tracked inventory would never reveal it. Without the `keymax ≤ 16`
condition stated, slice 1 silently ships a 255 B/sample allocation.

### 7.2 The ceiling file

`bench/mem-ceiling.txt` becomes `<arch> <copy> <return> <into>`. A 4th field is **silently ignored** by
today's parser, so the file edit is backward-compatible — but the reader must add
`CEILING_INTO=$(awk '{print $4}')` **with the same empty→dash default as the existing columns**. Without it
the existing 3-field `x86_64 1740 -` row yields an empty ceiling, awk coerces it to `0`, and the ratchet
fails with a bogus *"INTO ALLOCATION REGRESSED … > ceiling 0"* (reproduced during verification). Mirror the
numeric-or-dash guard too, or a typo turns the new arm into a permanently-green no-op — precisely the failure
the ratchet exists to prevent.

## 8. Testing — every gate falsified, seen red

1. **The copy is a real deep copy, not an alias.** Take, let a later take recycle the pooled struct, assert
   the earlier data is intact. *Falsify:* assign the slot instead of deep-copying → red.
2. **Every slot is copied.** Poison all destination slots, `take-into`, assert no poison survives — observed
   **at the copy**, not through a later read. ADR 0093 learned this: testing through `take` covered 10 of 13
   slots *while appearing to cover all*.
3. **`read` then `take-into` does not corrupt the read samples** (§4.1). *Falsify:* clear the `was-exposed`
   bit → the previously-read sample changes underneath the application.
4. **`get_key_value` survives** a take-into cycle (§4.6). *Falsify:* recycle directly instead of through
   `%recycle-delivery`.
5. **A loan-capable reader is refused**, not silently mishandled (§4.4) — the ADR 0096 leak class.
6. **Invalid-data index** carries key fields only and does not fault (§4.5).
7. **The two spec refusals**, each falsified independently.
8. **Concurrency:** `take-into` from an `on_data_available` listener on the receiver thread, concurrent with
   an application-thread take on the same reader. *Falsify:* recycle outside the cache lock → two threads
   race `dr-data-pool-top` (ADR 0085 shape).
9. **The zero claim:** the new ratcheted arm. *Falsify:* disable recycle-after-copy → red.
10. **The loan path does not move:** existing tests green, both existing `gate-mem` rows unchanged.

**Cross-DDS interop:** `take-into` changes **no wire surface** — it is a local API shape. The per-feature
interop rule is discharged by no-regression against the existing Connext 7.3.1 and Fast DDS legs, stated
explicitly rather than quietly skipped.

## 9. Later slices

| slice | scope |
|---|---|
| **2** | variable-size fields: chunked grow-once, the ceiling, the refusal status (§6) |
| **3** | the loan-capable (ZC / FlatData / secured) arms §4.4 refuses |
| **4** | the ECR's naming half — the operation called *take* stops being a loan |

**Slice 4's migration surface is measured, not estimated: 54 occurrences on 53 lines.** ADR 0093 §6's
enumeration is prose and §9 explicitly retracts it; `src/dds-durability/` is **not** a consumer. Three of the
54 are **not tests** — `src/dds-dcps/conditions.lisp:305`, `src/dds-log/collector.lisp:51`, and
`scripts/gate-arena.sh:70`. That last one means a rename **breaks a quality gate**, which no test run would
catch. The names `take-into` / `read-into` are free (no collision). `take-loaned` / `read-loaned` are **not**
available as a rename target: they are the FlatData-ZC *and* DDS-Security decode loan API, return
`(values data loans)` of raw data rather than wrappers, skip the enabled check and the state-mask/WHERE
filtering, and are gated pending counsel.

## 10. Provenance of the claims in this document

Every file:line above was verified against the working tree on 2026-08-06 by a parallel verification pass
(34 findings: 19 confirmed, 8 refuted, 7 partial). **Three refutations changed this design:** decode is not
on the receiver thread (§3); `deserialize-into-<name>` is already live (§4.4); and the `read`/`take-into`
aliasing hazard (§4.1), which no earlier draft had. Two more corrected its numbers: the ≈112 B floor (§7) and
the absence of a standard status for an over-large sample (§6).
