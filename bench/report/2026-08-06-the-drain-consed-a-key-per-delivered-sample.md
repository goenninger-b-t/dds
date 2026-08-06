# The drain consed a composite key per delivered sample — and only one of the two streams could stop

**NFR-MEM / ADR 0105 slice 1, Task 6b · macOS/arm64, SBCL · `make gate-mem`, 60 000 samples per arm, three
runs per arm, nothing else on the machine**

## The number

| arm | before | after | delta |
|---|---|---|---|
| COPY (take, samples dropped) | 543.8 / 543.8 / 542.7 | **522.3 / 528.5 / 528.5** | **−15.3** |
| RETURN (take + `return-loan`) | 337.5 / 337.5 / 335.3 | **320.0 / 318.9 / 320.0** | **−16.4** |

Ceilings lowered `571 → 555` and `355 → 337` (arm64). Predicted 16 B/sample — one cons per delivered
sample — and both arms landed on it. A confirming run at the new ceilings reads 527.4 / 320.0, PASS.

x86_64, measured on the real box: COPY `578.1 → 561.3–562.5` (−16.2), RETURN `385.6 → 369.0–370.9` (−16.1).
The COPY ceiling stays at 609 and RETURN stays a dash.

## An unrelated finding this measurement turned up, recorded in full in `bench/mem-ceiling.txt`

Eleven back-to-back runs on an idle box (verified by `ps`: one process, load 1.00) produced **three
blowups in 22 arm-runs** — COPY once at 109883.6 (×196) and RETURN twice at 896.1 and 5892.8 — each on a
run where the *other* arm read perfectly normal. That falsifies the reasoning recorded for the x86_64
RETURN dash on both counts: the blowup does reproduce on the box, and it is not RETURN-specific. Each arm
runs in its own SBCL process, so a per-process intermittent inflates exactly one arm and looks
arm-specific from a single CI sample. Predates this change and is unaffected by it.

## What was allocating

`node-collect-pending-samples` walks the node's two-level sample store and pushes the composite
`(GUID . SN)` key of every entry the reader still considers pending:

```lisp
(vector-push-extend (cons guid sn) out)
```

`out` is already the reader's own adjustable vector, reused across drains — but its *elements* were not. In
the steady state exactly one sample is pending per drain, so this was exactly one cons per delivered
sample. Now the element is reused too: `aref` ignores the fill pointer (CLHS 15.1.2), so index *i* still
holds the cons this vector carried there before the reset, and its `car`/`cdr` are overwritten. The
allocation becomes grow-once.

## The half that must NOT do this, which is the whole point

The two collectors are twins and were literally the same code. Reusing the key conses is sound for the
**data** stream and a silent corruption for the **lifecycle** stream, and the asymmetry is not a judgement
call — it is a fact about who retains what:

- Every data-key consumer (`node-sample-raw` / `-writer` / `-writer-guid` / `-timestamp` / `-key-hash` /
  `-key-sn`, `%arbitrate-owner`, `%drain-one-loan`, `%drain-one-secured`) uses the key only as
  `(car key)` / `(cdr key)` for a two-level lookup, and none stores it. That stream's exactly-once record
  is `dr-drained`, a GUID-keyed table of fixnum high-water marks — it holds no keys at all.
- `%drain-one-lifecycle` opens with `(push key (dr-lifecycle-drained dr))`. **The lifecycle stream's
  exactly-once record *is* a list of these very conses**, held for the reader's lifetime. Rewriting one
  makes an already-consumed dispose read as pending again.

So the shared helper takes the decision as an explicit argument, and both call sites carry the argument for
why they differ. A dispose is rare, so the lifecycle stream keeps paying a cons on a path that is not the
steady state.

## The falsification, and the first attempt at it that was blind

`run-lifecycle-drained-identity-test` is new. With the lifecycle collector flipped to reuse, **all eight
existing dispose / unregister / instance-state arms stayed green** — the suite could not see the defect at
all, which is why the arm had to be written before the claim could be trusted.

⚠️ **The first version of the new test was green under the sabotage too, and the reason is worth recording.**
`%drain-one-lifecycle` enqueues an invalid-data notification **only when the instance state actually
transitions** (DDS 1.4 §2.2.2.5.1.4 — these no-data samples surface a *change* of state). Re-applying a
dispose to an instance that is already `NOT_ALIVE_DISPOSED` therefore does nothing observable: the
corruption was really happening and left no trace at the API. The arm now **revives instance k=1 with a
fresh write** between the two disposes, so the re-applied dispose has a state to change:

| | result |
|---|---|
| lifecycle collector reuses its conses | **RED** — `:ldi-second-dispose`, *"got 2, of which 1 carry k=1's handle"* |
| as shipped | PASS |

Which pass shows it depends on `maphash`'s unspecified iteration order, so the arm pins both: the second
dispose's drain must deliver exactly one notification, and the pass after it must deliver nothing and leave
k=1 `ALIVE`.

That last assertion is also the honest way to state what this protects — not an internal identity check but
a DDS property: **a dispose the reader has already consumed must never come back and re-dispose a revived
instance.**
