# ADR 0057 — A legacy TypeObject's bounds are not evidence: the type gate must never reject on them

Status: Accepted
Date: 2026-07-11
Work package: WP-DCPS-API-COMPLETION Slice S7 (found by the S7 live-interop gate; fixed in-slice)
Relates to: ADR 0009 (PID_TYPE_OBJECT_LB: type matching by name + structural assignability, never by minimal-hash equality — this ADR removes the *second* way that rung could false-reject); ADR 0010 / FR-TYPE-4 (the gated-matching contract); ADR 0056 (S7 autonomous discovery — the live cadence interop is what surfaced this)

## 1. Context — a false REJECT that blocked every outbound interop leg

The S7 live cross-vendor interop found that **our DCPS `DataWriter` never matched a foreign
`DataReader`** — not Connext 7.3.1's, not Fast DDS's. `matched=0`, zero samples delivered, both
vendors. The inbound direction (a vendor writer → our reader) worked fine, which is why no earlier
slice caught it: every previous live leg exercised our *reader*.

It was **not** an S7 regression — the spin-driven (non-autonomous) path reproduced it identically.
Two independent causes, both confirmed on the wire:

1. **DATA_REPRESENTATION (correct behaviour, documented for the harness).** Our DCPS writer defaults
   to offering XCDR2 only; a stock Connext/Fast DDS shapes reader advertises XCDR1 only.
   DATA_REPRESENTATION *is* an RxO policy (XTypes 1.3 §7.6.3.1.1), so the reject is right —
   `OFFERED_INCOMPATIBLE_QOS` fired with `last_policy_id = 23`. The interop runners now carry a
   `:data-representation` knob (as `run-publisher` already did) instead of silently not matching.

2. **The type gate false-rejected the peer (the bug fixed here).** With representations aligned, the
   match *still* did not happen. The gate logged
   `type-gate[Square/ShapeType]: INCOMPATIBLE — legacy-TypeObject assignability`. Clearing the gate
   hook made the same writer match instantly (`matched=0 → 2`).

### Root cause

A stock Connext peer advertises its type **only** via the vendor legacy parameter
`PID_TYPE_OBJECT_LB` (0x8021) — no `PID_TYPE_INFORMATION`, no TypeConsistencyEnforcement (ADR 0009
§Context.1). Two spec rules then fire against that legacy model:

- **The assumed DISALLOW.** XTypes 1.3 §7.6.3.4.1: when introspecting a remote endpoint that provides
  no `TypeConsistencyEnforcementQosPolicy`, the Service *shall assume* `DISALLOW_TYPE_COERCION`. For a
  remote **reader** (whose policy governs, and which we cannot read) the gate therefore demanded type
  **equivalence** (`struct-equivalent-p`).
- **The key sub-bound rule.** XTypes §7.2.4.4.8: for a key member, T1's bound must be ≥ T2's — a rule
  `ignore_string_bounds` deliberately does **not** relax.

Both compare **bounds**. And a legacy TypeObject's bounds are **not the peer's type**: `rtiddsgen`
**silently bounds an unbounded `string` at 255** (ADR 0009 §Context.2 — already recorded, never wired
into the gate's reasoning). The canonical interop `ShapeType` declares `@key string color`
(unbounded); Connext announces it as a **255-bounded key**. Measured, live:

```
OUR LOCAL shape-type : color  KIND 112 (TI_STRING8_SMALL)  BOUND 0    (unbounded)
PEER (Connext C_Shape): color KIND 112 (TI_STRING8_SMALL)  BOUND 255  (rtiddsgen artifact)
```

Every other member matched exactly (same extensibility, ids 0–3, names, kinds, key flags). So the gate
rejected a peer using **the very same type**, on a bound the peer's *code generator* invented.

Two things make this decisive rather than a judgment call:

- **The peer reaches the opposite conclusion.** Connext — enforcing type consistency on *its* reader,
  as DDS requires — matched us and decoded 268 of our samples correctly. §7.6.3.4.1's own stated
  rationale for the DISALLOW assumption is that conformant and non-conformant implementations must
  reach the **same** conclusion. Applying it to a lossy artifact achieves the exact opposite.
- **"Just bound our type at 255" is not a fix.** Fast DDS's `fastddsgen` keeps the string *unbounded*
  (their `ShapeType.idl` says so explicitly, and it is the apples-to-apples oracle for our type).
  Bounding ours to match rtiddsgen would merely move the false-reject to the other vendor. The defect
  is not in our type declaration; it is in trusting a generator artifact as type evidence. And it is
  general: **any** user type with an unbounded key string would be false-rejected against Connext.

This is the worst bug class we recognise (a false REJECT), and it is precisely the interop regression
ADR 0009 was written to prevent — it simply arrived through a second door that ADR left open.

## 2. Decision

**Bounds parsed from a legacy `PID_TYPE_OBJECT_LB` are treated as NO EVIDENCE. The legacy rung
assesses by ASSIGNABILITY with ALL bounds ignored, and can never reject on a bound.**

- New `%gate-assess-legacy` (`src/dds-dcps/type-gate.lisp`) replaces the `%gate-assess` derivation for
  the legacy rung: reader-side `is-assignable-from` writer-side (direction from the remote GUID's
  entityKind) under `ALLOW_TYPE_COERCION` with `ignore_sequence_bounds`, `ignore_string_bounds`, **and**
  `ignore-key-bounds` all set. It never runs an equivalence test.
- New `ignore-key-bounds` field on `dds.types:assignability-options` (**default NIL = the spec rule**,
  so every other caller is byte-identical). It relaxes the §7.2.4.4.8 key sub-bound check, which the
  spec's own `ignore_*` flags cannot. It is **not** settable from `TYPE_CONSISTENCY_ENFORCEMENT` (it is
  not a DDS QoS field) — only the legacy gate rung sets it.
- **The gate is not disarmed.** Extensibility, member count, ids, names, kinds, key *flags* and
  `must_understand` all still reject exactly as before. Only invented bounds stop counting.

### Consequence, recorded explicitly

Against a legacy-only peer, an explicit local `DISALLOW_TYPE_COERCION` **cannot be honoured soundly**
and is downgraded to this assessment (the verdict is logged via `*type-compat-log*`). Judging type
*equivalence* from a representation the peer's generator demonstrably alters is not possible; refusing
to guess is the honest behaviour. A peer that publishes real `PID_TYPE_INFORMATION` is unaffected — it
still goes through the full hash/TypeLookup/assignability ladder under its real TCE.

## 3. Verification

- **Regression test** `dcps-type-gate-legacy-reader` (RED before the fix, GREEN after), pinned to the
  **live captured** Connext 7.3.1 `C_Shape` `PID_TYPE_OBJECT_LB` (docs/provenance.md, 2026-06-11):
  (a) it gates `:compatible` against our identically-declared type despite the artifact bound, in both
  the reader and writer directions; (b) the **same** captured LB against a genuinely different local
  type (`shapesize` retyped i32→i64) still gates `:incompatible` — bounds are ignored, the gate is not
  disarmed.
- **Live cross-vendor, both vendors, both directions** (all with the S7 announcer driving discovery and
  **no** `spin` call anywhere — `interop/autodiscovery/README.md`):

  | Leg | Before | After |
  |---|---|---|
  | our writer → **Connext** reader | matched 0, **0 samples** | matched 1, **27 samples** |
  | our writer → **Fast DDS** reader | matched 0, **0 samples** | matched 1, **29 samples** |
  | **Connext** writer → our reader | 252 samples | 252 samples (unchanged) |
  | **Fast DDS** writer → our reader | 131 samples | 131 samples (unchanged) |

- 558/558 tests green on **both** Clasp and SBCL; `gate-hotpath` + `gate-types` green. The gate is
  control-plane only — no hot-path change, no wire-format change.

## 4. Alternatives considered

- **Bound our `color` at 255 to match rtiddsgen.** Rejected: it fixes exactly one type against exactly
  one vendor and breaks the other (Fast DDS keeps it unbounded), and leaves every user type with an
  unbounded key string still false-rejected against Connext. Treats the symptom, not the cause.
- **Fail the legacy rung fully open (always `:compatible`).** Rejected: it would also stop rejecting
  genuinely different types, throwing away the assignability signal ADR 0009 deliberately kept. The
  fix ignores *bounds*, not *structure*.
- **Honour the assumed DISALLOW and accept non-interop.** Rejected: it is a false REJECT, it makes our
  writers unable to talk to any stock vendor reader, and it puts us in direct disagreement with the
  peer's own matching decision — the outcome §7.6.3.4.1 exists to prevent.
