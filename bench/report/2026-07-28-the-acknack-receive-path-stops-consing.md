# The ACKNACK receive path stops consing

**NFR-MEM / FR-PF-7 · arm64 (Apple silicon), SBCL · `make gate-mem`, 60000 samples, own process per arm**

| | before | after | delta |
|---|---|---|---|
| COPY | 880.5 | **820.6** / 818.9 / 819.1 | **−59.9** |
| RETURN | 673.8 | **607.2** / 609.4 / 608.3 | **−66.6** |

Ceilings lowered **915 → 850** (COPY) and **706 → 640** (RETURN). x86_64 keeps its dash.

## How the targets were chosen

Not by a probe window, and not by reading code at random. **`make gate-hotpath` already maintains the
inventory** — it prints `NFR-MEM DEBT — 11 TRACKED per-sample/per-datagram allocation(s) remain (ADR
0062)` with file, line and a comment saying what each one is. Cross-referencing that list against *this*
workload (a keyed `:i32`, a zero-length octet sequence, reliable KEEP_LAST) shows only five of the eleven
can fire, and two of those are in the ACKNACK receive path — which runs once per sample.

The lesson is worth the sentence: **the project had already written down where its remaining allocation
was.** Several slices of this session were spent measuring toward a list that existed.

## Defect 1 — a one-element list built to be taken apart

```lisp
(peers (if dest (list (cons src-prefix dest)) (%match-destinations-prefixed node t))))
(dolist (pd peers)
  (let ((peer (cdr pd)))
    (%send-changes-packed ... (car peer) (cdr peer) ... (car pd))
    (when gaps (%send-user-gap ... (car peer) (cdr peer) (car pd)))))
```

On the normal path `dest` is resolved, so this **conses a list and a cons — 32 B per inbound ACKNACK, per
sample** — purely to hand a one-element list to a `dolist` that immediately destructures it back into the
two values it was built from.

It now repairs to that peer **directly**, with the shared body in an `flet` declared `dynamic-extent` (ADR
0072) so both arms use one definition and no closure is consed. The undiscovered-prefix fan-out still walks
the prefixed destination list, which is memoized already.

## Defect 2 — a fresh SequenceNumberSet bitmap per inbound ACKNACK

`read-sequence-number-set` allocated `(make-array (max 1 m) :element-type '(unsigned-byte 32))` on every
parse — one of the eleven tracked items, and on this workload it fires once per sample.

It now takes an **optional caller-owned scratch**, and the receiver thread's `rx-context` carries one sized
to the spec maximum (256 bits = 8 words, RTPS 2.5 §9.4.2.6), so it fits any legal set.

**Three things make that sound, and they are the whole argument:**

- **The consumer provably does not retain it.** `writer-on-acknack` walks the bits under the writer lock
  (`dotimes` + `seqnum-set-bit-p`) and stores nothing; `bitmap` is used nowhere else in `%on-user-acknack`.
- **It is threaded from that one call site and never defaulted on inside the parser.** `parse-acknack-body`
  and `read-sequence-number-set` are shared with GAP and NACK_FRAG parsing and with the TypeLookup and
  PVMS ACKNACK paths. A scratch defaulted *inside* the parser would silently apply to consumers nobody
  audited — safe by audit, which this project has already rejected once on principle (ADR 0088). Passing it
  from the site that established the property keeps every other caller byte-identical.
- **No zeroing is needed.** The parse fills exactly the `M` words the wire declared, and every consumer
  bounds its walk by `numBits`, which is `≤ M*32`. Stale words beyond `M` are never read.

Note the contrast with the rest of this session: the prefix, GUID and inline-QoS caches are **write-once
caches** precisely because their values *are* retained. This one is a **reused scratch**, because this
value is not. Getting that distinction wrong in either direction is the bug.

## Verification

SBCL 623/623, Clasp 623/623, `gate-hotpath` PASS, `gate-nocond` PASS, `gate-mem` PASS with both ceilings
lowered. Predicted ~64 B/sample (32 + 32); measured **−59.9 / −66.6**.

The tracked-debt count stays at 11: the bitmap line still allocates for every caller that passes no
scratch, which is the honest state — the allocation is gone from the per-sample path, not from the codebase.

## Session position — nine slices

| | start | now | total |
|---|---|---|---|
| COPY | 1550.0 | **820.6** | **−729.4 (−47.1 %)** |
| RETURN | 1342.2 | **607.2** | **−735.0 (−54.8 %)** |

Phase split at the start of this slice: `TX ~205 · receiver 311.3 · take-hit ~155` (the receiver window is
stable across runs; the TX/HIT boundary is not, but their sum is).

## What is left

`%deliver-user-sample` and the take path — and the take path is where the **ECR** ("a take is not a loan")
lands, since the COPY arm *is* take-without-loan and still sits ~213 B/sample above RETURN. **The arena
half of the directive remains untouched.**
