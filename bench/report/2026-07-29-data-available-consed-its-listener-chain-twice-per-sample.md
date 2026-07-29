# DATA_AVAILABLE consed its listener chain twice per sample

**NFR-MEM / FR-PF-7 · arm64 (Apple silicon), SBCL · `make gate-mem`, 60000 samples, own process per arm**

| | before | after | delta |
|---|---|---|---|
| COPY | 796.0 | **719.6** / 720.7 / 720.7 | **−76.4** |
| RETURN | 594.1 | **513.3** / 513.3 / 514.4 | **−80.8** |

Ceilings lowered **835 → 750** (COPY) and **625 → 545** (RETURN). x86_64 keeps its dash.

## How it was localised

The receive-pipeline bisect put the DATA handler at **91.7 B/sample** and showed every expression in
`%on-user-data` outside `%deliver-user-sample` at 0.00. Four windows inside `%deliver-user-sample` then
gave an unusually clean answer:

| | B/call | B/sample |
|---|---|---|
| `reader-on-data` | 0.00 | 0.00 |
| `reader-dedup-accept-p` | 0.00 | 0.00 |
| the whole store, under the node lock (7 puthashes, 3 `%inner-table` lookups, `%record-sample-*`) | 0.00 | 0.00 |
| **`(funcall (disc-node-on-sample node))` — the DATA_AVAILABLE notify** | **89.49** | **91.73** |

**91.73 is the DATA handler's entire cost.** The store — the thing that *looked* like the expensive part,
and the reason the previous report called this "data-structure work" — allocates nothing.

## The defect

```lisp
(defun* %listener-ancestry (entity) ...
  (typecase entity
    (data-reader (let ((s (dr-subscriber entity))) (list entity s (sub-participant s))))
    (subscriber  (list entity (sub-participant entity)))
    ...))
```

The listener-propagation chain (DDS 1.4 §2.2.4.1) was returned as a **freshly consed list**, and the
DATA_AVAILABLE path runs the lookup **twice per sample** on the receiver thread — once on the Subscriber
for `DATA_ON_READERS` precedence, once on the DataReader for `DATA_AVAILABLE`. Two conses plus three:
**five conses, 80 bytes per sample**, to build two lists that are immediately walked and dropped.

Worse, it is spent to discover that **there is usually no listener at all**: the walk exists to find the
most-specific *installed and enabled* listener, and a benchmark — or any application using WaitSets rather
than listeners — has none. The chain was built to be searched and found empty.

## The fix

`%listener-ancestry` becomes `%map-listener-ancestry`, which **walks** the chain instead of materialising
it: at most three entities, shape fixed per entity type, so `(or (funcall fn entity) (funcall fn parent)
(funcall fn grandparent))` covers it with short-circuiting that preserves the "stop at the first enabled
listener" rule exactly. `%find-enabled-listener` passes its per-entity test as an `flet` declared
`dynamic-extent` — sound because the mapper funcalls it and stores it nowhere.

It had exactly **one caller**, so this is a replacement rather than an addition; nothing keeps the
list-building version alive.

## Verification

SBCL 623/623, Clasp 623/623, `gate-hotpath` PASS, `gate-nocond` PASS, `gate-mem` PASS with both ceilings
lowered. Predicted ~80 B/sample (5 conses); measured **−76.4 / −80.8**.

## Session position — eleven slices

| | start | now | total |
|---|---|---|---|
| COPY | 1550.0 | **719.6** | **−830.4 (−53.6 %)** |
| RETURN | 1342.2 | **513.3** | **−828.9 (−61.8 %)** |

Both arms are now below anything this campaign has recorded — the RETURN arm started the *previous*
session at 1740.

## A correction to the previous report

That report concluded the remaining allocation was "inside `%deliver-user-sample`'s two-level sample store,
the reader-proxy `equalp` lookups, and the drain — data-structure work, not per-call fixes". **The store
part was wrong**: it measures 0.00, and the DATA handler's whole cost was one consed list in the DCPS
notification layer, which is exactly a per-call fix of the kind already harvested nine times.

The lesson is the one this campaign keeps re-learning from the other side: **the store was never measured,
it was inferred.** Reading the code suggested seven puthashes must cost something; the probe showed they
cost nothing, because SBCL hash tables do not cons per entry once sized and the inner-table lookups hit.

## What is left

The receive pipeline should now be ~155 B/sample (ACKNACK 98.3, HEARTBEAT 55.7, DATA ~0). Neither has been
bisected internally since their last slices. Untouched: **the arena half of the directive**, and the queued
**ECR** — whose arm, COPY, sits ~206 B/sample above RETURN.
