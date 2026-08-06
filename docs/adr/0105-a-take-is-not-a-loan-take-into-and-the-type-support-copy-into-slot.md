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

**At an index whose sample has `valid_data = FALSE`** only the key fields are meaningful. The middleware
wrapper carries `data = NIL` there (`entities.lisp:2254`, `2258`); with `take-samples` the application sees a
literal `NIL` it cannot miss, but a pre-allocated destination would otherwise retain the **previous**
sample's contents. Spec-legal, but a real divergence: it is part of the documented contract, and the copy
step must not fault on a NIL source.

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

### 4.6 Not a hazard — recorded so it is not re-investigated

Multiple readers sharing one store sample is already safe: each decodes its own struct and the entry is
purged on the last drain via the `disc-node-sample-consumers` refcount (`dataplane.lisp:3234-3260`).

## 5. Variable-size capacity (slice 2)

Growth is **whole chunks, never exact-fit** (ADR 0102 rejected exact-fit because the budget then creeps up
one allocation at a time until the ceiling means nothing), monotone, never shrinking, to a per-reader ceiling.
Past the ceiling the sample is **refused and counted** (ADR 0101's reject-don't-fall-back ruling).

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
| `src/dds-types/type-support.lisp` (defstruct) + `packages.lisp` (export) | the slot + its export |
| `src/dds-tests/xtypes-test.lisp` ×2, `src/dds-tests/integration-test.lisp` ×1 | **no change** — see below |
| every reader of the other 18 slots | **no change** |

**The migration is empty, and that is a property of the change, not an accident.** `make-type-support` is a
keyword constructor, so an added slot defaults to `NIL` in every existing call. **Precedent: ADR 0093 slice 4
added the `deserialize-into` slot to this same frozen struct the same way** (`type-support.lisp:39`). The
frozen-contract gate applies because the struct shape is frozen — not because the change breaks anyone.

⚠️ **What a consumer MUST NOT assume:** `copy-into` is `NIL` for a FlatData type, exactly as
`deserialize-into` is. A caller must test it, not assume it is bound.

## 7. Slices

**Slice 1's exit criterion is a genuinely-0 arm** (owner decision). `take-into` alone does not get there —
five further per-sample allocations remain, measured on arm64 SBCL 2.6.5:

| site | what | B/sample |
|---|---|---|
| `dataplane.lisp:4700` | `(cons guid sn)` per pending key | 16.05 |
| `entities.lisp:800` | fresh 4-slot `cursor` per decode | 48.16 |
| `entities.lisp:3251-3253` | `(list …)` cell `nconc`'d onto `dr-cache` | 16.05 |
| `entities.lisp:3457` | `(push cs out)` per selected sample | 16.05 |
| `entities.lisp:3452` | `(pushnew h touched :test #'equalp)` | 16.05 |

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
is refused · an invalid-data index carries key fields only and does not fault · both spec refusals · a
concurrent `take-into` from an `on_data_available` listener on the receiver thread · the ratcheted zero arm ·
and both existing `gate-mem` rows unchanged.

**Cross-DDS interop:** `take-into` changes **no wire surface**. The per-feature interop rule is discharged by
no-regression against the existing Connext 7.3.1 and Fast DDS legs, stated rather than skipped.

## 9. Provenance

Every file:line here was verified against the working tree on 2026-08-06 by a parallel verification pass
(34 findings: 19 confirmed, 8 refuted, 7 partial). **Three refutations changed this design** — decode is not
on the receiver thread (§4), `deserialize-into-<name>` is already live (§4.4), and the `read`/`take-into`
aliasing hazard (§4.1), which no earlier draft contained. Two more corrected its numbers: the ≈112 B floor
(§7) and the absence of a standard status for an over-large sample (§5).
