# The TX path consed a closure per write

**NFR-MEM / FR-PF-7 · arm64 (Apple silicon), SBCL · `make gate-mem`, 60000 samples, own process per arm**

| | before | after | delta |
|---|---|---|---|
| COPY | 1232.0 | **1182.7** / 1181.9 / 1182.2 | **−49.3** |
| RETURN | 1017.8 | **976.1** / 975.9 / 975.9 | **−41.7** |

Ceilings lowered **1265 → 1215** (COPY) and **1055 → 1010** (RETURN). **The RETURN arm is now under 1000
bytes per sample.** x86_64 keeps its dash.

## Why the write path, now

The receive pipeline started this session at 688 B/sample and is under 330 after four slices, so the phase
split was re-measured before choosing a target:

```
PHASE-SPLIT  TX 507.8  MISS 0.0  SLEEP(receiver) 360.4  HIT 180.2  TOTAL 1048.4
PHASE-SPLIT  TX 589.7  MISS 0.0  SLEEP(receiver) 360.4  HIT  81.9  TOTAL 1032.0
```

**TX is now the dominant block.** (`MISS` — a take that finds nothing — is a clean 0.0; the receiver window
is stable at 360.4 across both runs; the TX/HIT boundary is not trustworthy, as the earlier campaign
already found, but their sum is: ~680.)

## The defect

```lisp
(defun* %sample-serializer-into (ts sample rep) ...
  (multiple-value-bind (mode encap) (%rep->codec rep ...)
    (let ((ser (dds.types:type-support-serialize ts)))
      (lambda (buf) ...))))                       ; RETURNED -> necessarily heap-allocated
```

**A closure that is *returned* must be heap-allocated** — SBCL cannot stack-allocate through the escape.
This one captures four values (`sample`, `ser`, `mode`, `encap`), so header + code + 4 cells ≈ **48 bytes,
on every write**, for an object that dies inside the very next call.

The irony is that this function exists *entirely* as an allocation fix: it was introduced so the payload
could be serialized straight into an arena-pooled buffer instead of allocating a static buffer, a heap
vector, a copy and a free. It removed those and then quietly paid a closure for the privilege.

## The fix

It becomes a **macro** that binds the serializer as an `flet` declared `dynamic-extent`, so it stack-allocates:

```lisp
(%with-sample-serializer-into (%ser-into ts sample rep)
  (dds.disc:publish-sample-into node #'%ser-into kh (dw-entity-id dw) ts-ns))
```

This is sound because `publish-sample-into` is a **pure downward-funarg consumer**: it funcalls the
serializer in its pooled arm and in its `allocating` fallback — itself a local `labels` that never escapes
— and stores it nowhere. That is precisely the contract ADR 0072's idiom requires, and the same one the
per-ACKNACK `%build-acknack` builder already relies on a few files away.

A macro rather than a copied `flet`: there is exactly one call site today, but the definition stays in one
place, with its docstring, so the next caller cannot reintroduce the heap closure by pasting the lambda.
The superseded function was **deleted**, not left renamed — dead code that still compiles is a trap.

Framing is unchanged: same `%rep->codec`, same encapsulation header, same finalize, same wire bytes. The
FlatData/non-XCDR2 transcoding case still routes to the allocating path, as before.

## What is still in the write path

The same `flet` body creates a **`(cursor buf :endianness :little)` per write** — the identical 48 B
structure this session removed from the receive side. It is deliberately **not** fixed here: the receive-side
fix worked because each receiver thread owns one buffer for life, whereas `writer-acquire-payload-buffer`
hands out a different pooled buffer per write, and the two obvious shortcuts are both unsound. A per-writer
cursor is the shared-mutable-scratch hazard two application threads writing one DataWriter would hit (the
same reason a per-writer clock scratch was rejected). Declaring the cursor `dynamic-extent` would hand a
stack-allocated structure to `type-support-serialize` — a **pluggable** extension point, so "no
implementation retains it" is an audit, not a construction. It wants the cursor to belong to the pooled
buffer, which is a `dds.core.buffer` contract change and therefore an ADR.

## Verification

SBCL 623/623, Clasp 623/623, `gate-hotpath` PASS, `gate-nocond` PASS, `gate-mem` PASS with both ceilings
lowered.

## Session position

Five slices, every one measured end-to-end against the gate:

| | start | now | total |
|---|---|---|---|
| COPY | 1550.0 | **1182.7** | **−367.3 (−23.7 %)** |
| RETURN | 1342.2 | **976.1** | **−366.1 (−27.3 %)** |
