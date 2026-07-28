# writer-write consed a closure and a value cell per sample

**NFR-MEM / FR-PF-7 · arm64 (Apple silicon), SBCL · `make gate-mem`, 60000 samples, own process per arm**

| | before | after | delta |
|---|---|---|---|
| COPY | 1057.3 | **927.8** / 926.7 / 928.4 | **−129.5** |
| RETURN | 848.0 | **724.1** / 721.9 / 721.9 | **−123.9** |

Ceilings lowered **1090 → 960** (COPY) and **880 → 755** (RETURN). **Both arms are now under 1000 bytes per
sample.** x86_64 keeps its dash.

## The defect — two allocations, one line

```lisp
(let ((change nil))                                        ; MUTABLE + closed over -> heap value cell
  (values (%writer-add-bounded
           writer (lambda (sn) (setf change (hc-data-change   ; captures ELEVEN variables -> ~104 B
                                             (rtps-writer-hc writer) sn payload key-hash inline-qos
                                             pooled-buffer pooled-len zc-slot zc-gen zc-pinned zc-len))))
          change))
```

1. **The lambda is heap-allocated.** It captures eleven variables — `change`, `writer`, `payload`,
   `key-hash`, `inline-qos`, `pooled-buffer`, `pooled-len`, `zc-slot`, `zc-gen`, `zc-pinned`, `zc-len` —
   so two header words plus eleven value words ≈ **104 bytes on every write**. SBCL does not infer
   dynamic extent for a closure handed to a function it cannot see into; it has to be told.

2. **`change` costs a heap value cell of its own.** A variable that is both closed over *and assigned*
   cannot live in a register or on the stack in SBCL — it is boxed into a value cell. This is the trap
   recorded earlier in the campaign, where the same shape measured 123.5 B/sample elsewhere.

The second one is the interesting half, because the mutable variable exists **only to smuggle a value out
of the callback** — `%writer-add-bounded` returns the sequence number, and `writer-write` also needs the
`CacheChange`.

## The fix

**The closure becomes an `flet` declared `dynamic-extent`** (ADR 0072). `%writer-add-bounded` funcalls
`make-change` exactly once, under the writer lock, and stores it nowhere — a pure downward funarg — so it
stack-allocates. Same idiom, same justification, as the TX serializer slice and the per-ACKNACK builder.

**The mutable capture is deleted rather than made cheaper.** `%writer-add-bounded` had the change in hand
all along:

```lisp
(let* ((sn (incf (rtps-writer-last-sn writer)))
       (change (funcall make-change sn))
       (evicted (nth-value 1 (hc-add-change hc change))))
  ...
  (values sn change))
```

It now returns `(values SN CHANGE)`, and the `:timeout` arm returns `(values :timeout nil)` — exactly what
`writer-write` reported before. Withholding a value that was already computed is what made the caller pay
a value cell per sample to get it back out.

`writer-lifecycle-change`, the sibling caller, wraps its call in `VALUES` to truncate the new second value:
a lifecycle change's SN is its whole documented contract. Its own lambda is **deliberately left alone** —
it is a dispose/unregister, a control-path operation, and no measurement here would justify touching it.
Same shape, different path; noted so the next reader knows it was seen, not missed.

## Verification

SBCL 623/623, Clasp 623/623, `gate-hotpath` PASS, `gate-nocond` PASS, `gate-mem` PASS with both ceilings
lowered. Predicted ~120 B/sample (104 + 16); measured **−129.5 / −123.9**.

## Session position

Seven slices, every one sized by the gate:

| | start | now | total |
|---|---|---|---|
| COPY | 1550.0 | **927.8** | **−622.2 (−40.1 %)** |
| RETURN | 1342.2 | **724.1** | **−618.1 (−46.1 %)** |

Three of the seven were the same defect in three places — **a closure or a captured mutable where a
stack-allocated `flet` would do**. The TX serializer (48 B), this one (120 B), and, in the opposite
direction, every write-once cache that replaced a rebuilt object. It is worth grepping for the rest:
a `lambda` passed to a function that only ever funcalls it is a `dynamic-extent` `flet` waiting to happen.

## What is left

The receive pipeline's `%deliver-user-sample` (~115 B/sample by window, so treat as a rank not a size) and
the ACKNACK emit. **The arena half of the directive is still untouched** — everything so far removes or
caches GC-heap allocation rather than drawing hot-path memory from `*static-arena-bytes*`.
