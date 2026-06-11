# ADR 0011 — Live Connext legacy-TypeObject gating: the ADR 0010 DoD is met

- **Status:** Accepted (2026-06-11, owner decision)
- **Deciders:** Owner + A0 (integrator)
- **Completes:** the ADR 0010 amended M4 exit gate clause "type-compatibility assessment
  interoperates with Connext via its legacy TypeObject announcement"; the legacy-TypeObject
  plan Task 6.1 (the live bidirectional acceptance test).
- **Evidence:** live RTI Connext 7.3.1 (`interop/connext/typeobject-corpus/corpus_pub 0 Square
  C_Shape`) vs the DCPS-level gated subscriber `dds.shapes:run-gated-subscriber` (`make
  gated-sub`), loopback, 2026-06-11. Raw run logs were captured; the gate-verdict lines,
  match counts and sample counts are reproduced below.

## Context

ADR 0009 retired minimal-hash gating against Connext (RTI never sends `PID_TYPE_INFORMATION`
0x0075; it announces only its vendor `PID_TYPE_OBJECT_LB` 0x8021). ADR 0010 confirmed Connext
implements no standard TypeLookup service and amended the M4 gate so that **Connext
type-compatibility gating comes from a structural parse of the legacy 0x8021 TypeObject**. The
parser (`dds.types:parse-legacy-type-object`) and its FAIL-OPEN DCPS rung
(`dds.dcps:%gate-legacy-type-object`) landed offline (Stage 5, test `dcps-legacy-gate`, 91
green). This ADR records the remaining DoD: that the rung fires correctly against a **live**
Connext peer.

## Gate-path finding

The standalone `dds.shapes:run-subscriber` builds a **bare `dds.disc` disc-node** — the
type-gate is installed only on **DCPS** participants (`dds.dcps:%install-type-gate`, called
from `create-participant`). The bare harness therefore has no gate. To exercise the gate
live, a new **DCPS-level** gated subscriber `dds.shapes:run-gated-subscriber` was added: it
`create-participant`s (gate installed), binds a chosen local type-support under the wire
topic/type-name via `create-topic`, `create-datareader`s, and drains over real UDP. The gate
fires on the disc receiver thread as Connext's SEDP `DATA(w)` is matched.

## Decision

The live acceptance test passes; the ADR 0010 DoD is **met**.

**Step 1 — compatible, live.** Local `shape-type` (color string@key; x/y/shapesize i32) under
wire `Square`/`C_Shape` vs Connext `corpus_pub 0 Square C_Shape`:

```
; type-gate[Square/C_Shape]: COMPATIBLE — legacy-TypeObject assignability
[gated-sub] MATCHED 1 remote endpoint(s) (gate verdict :compatible).
[gated-sub] stopped: received 25 sample(s); matched=1; INCONSISTENT_TOPIC total=0.
```

The gate inflated + parsed Connext's real 0x8021 (232 octets → 536 inflated; fingerprint
`C_Shape color shapesize …`, cross-checked live via `run-corpus-capture-subscriber`), ran
`struct-assignable-from`, returned `:compatible`; the endpoints matched and 25 C_Shape samples
(`color=BLUE x=50 y=50 shapesize=30`) were delivered from Connext.

**Step 2 — incompatible, live (the key proof).** Same Connext peer; local `shape-mismatch`
(shapesize retyped i32→i64, same id, different primitive kind → NOT assignable, Table 15):

```
; type-gate[Square/C_Shape]: INCOMPATIBLE — legacy-TypeObject assignability
[gated-sub] INCONSISTENT_TOPIC total=1 (gate verdict :incompatible -> REJECTED, no data).
[gated-sub] stopped: received 0 sample(s); matched=0; INCONSISTENT_TOPIC total=1.
```

The gate parsed Connext's TypeObject, `struct-assignable-from` returned NIL, our side raised
INCONSISTENT_TOPIC and did NOT match → zero samples delivered.

**Step 3 — no false-reject (cardinal).** Re-running Step 1 after Step 2 still gates
`:compatible`, matches 1 endpoint, delivers 20 samples, INCONSISTENT_TOPIC=0. A genuinely
compatible Connext peer is never spuriously rejected.

**Fail-open preserved.** The unchanged offline suite (91 green SBCL, incl. `dcps-legacy-gate`
cases 3/4: `:unsupported`/uninflatable LB → `:compatible`) proves a non-model legacy parse
never rejects; this live test does not regress it.

## Consequences

- A reliable RTPS reader buffers wire samples regardless of the **DDS** match verdict (match
  bookkeeping and the data plane are separate engine concerns). After an `:incompatible`
  verdict the reader's cache can hold C_Shape bytes the local incompatible codec cannot
  deserialize; `run-gated-subscriber` guards the `take-samples` drain with a `handler-case`
  (a parse error on an undeliverable wire sample is logged and skipped, never fatal). DDS
  semantics are unaffected: `SUBSCRIPTION_MATCHED` stays 0 and no sample is surfaced to the
  application. Suppressing the wire-level buffering for an unmatched reader is an engine
  follow-up, out of scope here.
- Consumers: `docs/verification.csv` (FR-TYPE-4 + FR-IO rows), `docs/MILESTONES.md` (M4),
  `README.md`, `docs/wiki/{type-system,dcps,discovery}.md`,
  `interop/connext/typeobject-corpus/README.md`. Migration: none (new harness entry +
  Makefile target only; no shipped behavior changed).
