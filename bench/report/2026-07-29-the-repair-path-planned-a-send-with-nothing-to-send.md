# The repair path planned a send with nothing to send

**NFR-MEM / FR-PF-7 · arm64 (Apple silicon), SBCL · `make gate-mem`, 60000 samples, own process per arm**

| | before | after | delta |
|---|---|---|---|
| COPY | 592.9 | **560.2** / 558.0 / 560.2 | **−32.7** |
| RETURN | 383.3 | **349.5** / 352.8 / 350.6 | **−33.8** |

Ceilings lowered **625 → 590** (COPY) and **415 → 385** (RETURN). x86_64 keeps its dash.

## The measurement is now exact

The phase split ran twice on different domains and returned **bit-identical** numbers:

```
PHASE-SPLIT  TX 81.9  MISS 0.0  SLEEP(receiver) 131.1  HIT 196.5  TOTAL 409.5
PHASE-SPLIT  TX 81.9  MISS 0.0  SLEEP(receiver) 131.1  HIT 196.5  TOTAL 409.5
```

Early in this campaign the same harness varied by tens of bytes between runs. It does not any more, because
most of what varied — the empty-poll allocations, the per-datagram scratch — is gone. The instrument got
sharper as a side effect of the work.

The receive pipeline re-bisected to **131.1 B/sample** (from 688), residual 0.01: ACKNACK **81.9**,
HEARTBEAT 32.8, DATA 16.4, prologue 0.00. Inside the ACKNACK handler: `%send-changes-packed` **29.5**,
`writer-purge-acked` 19.7, and **everything else 0.00** — the parse, the writer lookup,
`writer-on-acknack`, the destination resolve, `%matched-reader-keys`, the reliability notify.

## The defect

```lisp
(let ((state (cons (cons host port)
                   (%changes-datagram-plan node buf changes ...))))
  (loop while (cdr state) do (setf state (nth-value 2 (%emit-next-datagram ...)))))
```

The ACKNACK repair path calls `%send-changes-packed` **once per sample** with an **empty resend list** —
the steady-state ACKNACK acknowledges everything and repairs nothing — and **no HEARTBEAT**. A datagram
needs at least one submessage, so the plan is empty and the loop emits nothing. The state pair was consed,
and the planner walked, purely to discover there was no work.

The fix is the guard that says so:

```lisp
(when (and (null changes) (null hb-first))
  (return-from %send-changes-packed t))
```

Nothing to send is a **no-op**, not a plan.

## Verification

SBCL 623/623, Clasp 623/623, `gate-hotpath` PASS, `gate-nocond` PASS, `gate-mem` PASS with both ceilings
lowered. Predicted ~30 B/sample (two conses plus the planner walk); measured **−32.7 / −33.8**.

## Session position — sixteen slices

| | start | now | total |
|---|---|---|---|
| COPY | 1550.0 | **558.0** | **−992.0 (−64.0 %)** |
| RETURN | 1342.2 | **349.5** | **−992.7 (−74.0 %)** |

## Where the remaining ~350 sits

| block | B/sample |
|---|---|
| take (`HIT`) | 196.5 |
| receiver | 131.1 → ~98 after this slice |
| TX | 81.9 |

- **About half the take is `%drain-one-sample`, BLOCKED by owner ruling** until the "a take is not a loan"
  ECR is decided — who owns the decoded payload *is* the take-vs-loan question.
- Unblocked and measured: `writer-purge-acked` (19.7), `node-collect-pending-samples`' key conses (~16),
  HEARTBEAT (32.8) and DATA (16.4) handlers, TX (81.9) — none of the last three bisected internally since
  the slices that changed them.
- **The arena half of the directive remains untouched.**
