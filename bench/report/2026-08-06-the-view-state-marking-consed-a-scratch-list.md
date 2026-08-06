# The view-state marking consed a scratch list to defer itself

**NFR-MEM / ADR 0105 slice 1, Task 5 · `make gate-mem`, 60 000 samples per arm, three runs per arm, nothing
else on the machine · macOS/arm64 SBCL, and x86_64 on the real Linux box (192.168.2.180, SBCL 2.2.9.debian
— never emulated)**

## The number

**arm64**

| arm | before | after | delta |
|---|---|---|---|
| COPY (take, samples dropped) | 558.0 / 560.2 / 560.2 | **543.8 / 543.8 / 542.7** | **−16.2** |
| RETURN (take + `return-loan`) | 349.5 / 352.8 / 350.6 | **337.5 / 337.5 / 335.3** | **−14.2** |

**x86_64**

| arm | before | after | delta |
|---|---|---|---|
| COPY | 593.0 / 594.2 / 594.3 | **579.1 / 578.1 / 578.1** | **−15.4** |
| RETURN | 401.6 / 401.9 / 402.5 | **386.7 / 385.6 / 386.8** | **−15.4** |

Predicted **16 B/sample** from the source — one cons, the bench writing one sample of one instance per take
— and all four arms landed inside the instrument's ~3 B session-scale spread of it. This is one of the
campaign's rare slices where the two architectures moved by the *same* amount, which is what a single fixed
cons should do.

Ceilings: arm64 `590 → 571` and `385 → 355`; x86_64 COPY `625 → 609`. A confirming run at each new ceiling
PASSes (arm64 546.0 / 334.2; box 578-ish). **x86_64 RETURN stays a dash** — three more quiet-box readings do
not answer the open CI question that dash records, and re-banking off them would repeat the error it was
put there for.

## What was allocating

Four access paths — `%select-samples-unlocked` in list mode and in ADR 0105's into-mode, `take-loaned`, and
`read-loaned` — each accumulated the instance handles it had selected into a fresh list:

```lisp
(pushnew h touched :test #'equalp)      ; per selected sample, in the pass
...
(dolist (h touched) (setf (gethash h (dr-instances dr)) t))   ; after the pass
```

That is one cons per selected **instance** per call, plus an `equalp` scan of the list — a 16-octet array
comparison — per selected **sample**.

## Why the two-phase shape had to survive intact

The deferral is not an implementation detail, it **is** DDS 1.4 §2.2.2.5.1.4. `%snapshot-view-state` reads
`dr-instances`, so marking an instance inside the selection loop makes the **second** sample of a
newly-accessed instance report `NOT_NEW` within the very call that first accessed it, and changes what a
`view_states` mask selects half-way through that call. Every sample one access call returns must see the
state as it stood on entry.

The obvious "simplification" — mark in the loop, delete the second pass — was therefore refused. What went
is only the **scratch**: the marking is idempotent, so each path now walks the set it had already
materialised — the wrapper list it is about to return, the SampleInfo vector it has just filled, or
`dr-cache` itself for the loan paths, whose selection *is* the whole cache. No new state, no growth bound to
argue about, and the write half now lives in one place (`%mark-instance-accessed`) instead of four.

The same edit also removed a real duplication: both loan paths carried their own inline copy of the view
state rule (`(if (gethash handle (dr-instances dr)) :not-new :new)`) rather than calling
`%snapshot-view-state`, whose docstring already claimed to be the single definition.

## The falsification, which is the part worth trusting

`run-view-state-snapshot-test` is new, and the suite had **no** arm for this ordering: every other
view-state assertion in it returns one sample per instance per call, so all of them stay green while the
ordering is broken. Six sabotages, each seen red on its own check:

| sabotage | check that went RED | observed |
|---|---|---|
| mark inside the selection loop | `:vss-list-both-new` | `(:NEW :NOT-NEW)` |
| the same, list arm suppressed | `:vss-into-both-new` | `:NEW / :NOT-NEW` |
| delete the list second pass | `:vss-list-then-not-new` | `(:NEW :NEW)` |
| delete the into second pass | `:vss-into-then-not-new` | `:NEW` |
| delete `take-loaned`'s second pass | `:vss-loaned-take-marked` | `:NEW` |
| delete `read-loaned`'s second pass | `:vss-loaned-read-marked` | `:NEW` |

The first two and the last four are opposite failures — marking too early and not marking at all — so
neither moving the pass into the loop nor deleting it can be green.
