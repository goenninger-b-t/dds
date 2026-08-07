# Concurrent writes on one DataWriter: TWO defects, each of which hid the other

**Conformance / FR-QOS + FR-XPORT-2 · macOS/arm64, SBCL · two participants, one topic, RELIABLE + KEEP_ALL**
**ADR 0108 (the DCPS drain window) + ADR 0109 (the SHMEM lane-enqueue race)**

---

## The result

Four threads × 30 writes to **one** DataWriter, 120 distinct instances:

| arm | before | after both fixes |
|---|---|---|
| UDP (`*shmem-enabled*` NIL) | 96, 94, 95, 93, 120 | 120 ×8, and 6 of 8 in a later probe |
| SHMEM (default) | 111, **42**, 108, 98, 104 — **1 run in 5 died on payload corruption** | 120 ×7, 113 — **no corruption in 40+ trials** |

## The method that mattered: a TRANSPORT BISECT, first

The single most productive step was running the reproducer with `*shmem-enabled*` bound to NIL and to T in
one process. It separated the two defects immediately:

- the loss appeared on **both** transports ⇒ a transport-independent cause exists (ADR 0108);
- the corruption appeared on **only one** ⇒ a transport-specific cause also exists (ADR 0109).

⭐ Without that split, each fix looks like it does nothing, because the other defect is still active. ADR
0108's first attempt was reverted for exactly that reason — see its §7/§8.

## Defect 1 — the drain's exactly-once record was a HIGH-WATER MARK (ADR 0108)

`%data-pending-p` gated delivery on `(> sn (max high-water join-watermark))`. A high-water answers "already
delivered" for **every** SN below itself, so a reordered lower SN — routine under concurrent writes — was
skipped forever, sitting undrained in the reader's node store.

Replaced with a **circular 1024-bit delivered-set window** (the RFC 4303 Appendix A2 anti-replay shape).
1024 was chosen from measurement: the observed reorder depth was **90**, and the first attempt's 30-bit
window left UDP at 101–111 of 120 for precisely that reason.

⛔ The ZC join-watermark stays a **separate conjunct** — `dds-disc` counts eligible ZC drainers with
`SN > wm` alone and is safe only because that count is a superset (`disc.lisp:895`). Folding it into the
window would break a memory-safety argument silently.

## Defect 2 — the SHMEM lane enqueue is SINGLE-PRODUCER and had many producers (ADR 0109)

`%lane-enqueue` reads the write cursor, memcpys the record at that position, then publishes cursor+span —
three non-atomic steps. `%shmem-send` called it with **no mutual exclusion**, and a lane is claimed per
*participant*, so every thread of one participant shares one. Two producers resolve the same position, the
second memcpy destroys the first record, and the cursor advances by one span for two writes.

That is a datagram **destroyed outright** — a loss with no reordering at all — and, when the spans differ, a
consumer that resumes mid-record and decodes a datagram header as a payload: the observed
`unknown representation id #x5254`, where **`0x52 0x54` is `RT`**, the RTPS magic.

Fixed with a lock on the **destination** (one per lane, so different peers stay concurrent), not held across
the futex wake.

## What each fix is worth ALONE — neither is sufficient

| tree | SHMEM arm |
|---|---|
| neither fix | 111, 42, 108, 98, 104 (1 corrupt in 5) |
| ADR 0109 only | 102, 110, 53, 110, 114, 102 (no corruption) |
| both | 120 ×7, 113 |

⭐ **ADR 0109 alone removes the corruption but not the loss; ADR 0108 alone was measured as no improvement
at all.** Two defects in one path make each other's fix look worthless.

## ⛔ STILL OPEN — a THIRD defect, newly characterised, NOT fixed here

The workload is still not deterministic. Instrumented probes:

```
got=120 distinct=119 dups=((1017 . 2)) missing=1
got=91  distinct=90  dups=((2008 . 2)) missing=30
```

**One instance delivered TWICE while another never arrives.** Since every sample satisfies `k = v+1` by
construction and a duplicate is internally consistent, the existing payload-integrity assertion **cannot**
see it — one sample's bytes are carried under another's sequence number, so both copies are well-formed.

⭐ **The old high-water was HIDING this**: the count never reached 120 anyway, so a duplicate inside the
loss was invisible. Fixing defect 1 is what made it observable.

What has been **excluded** by measurement, not by argument:

| candidate | evidence |
|---|---|
| the drain window itself | its clear loop only touches SNs strictly **above** the old high-water, which cannot have been delivered; and the duplicate is two **distinct SNs**, which no drain record can dedupe |
| the SHMEM ring filling | failing trials had `enq-full=0`; trials with `enq-full=293` delivered 120/120 |
| `%lane-drain` wedging on a bad length | `drain-bail=0` in every trial |
| the receiver thread swallowing an error | `swallow=0` in every failing trial |
| the TX payload buffer being shared | `writer-acquire-payload-buffer` acquires under `%with-writer-lock`; the non-pooled path allocates a fresh buffer per call |

Also open and distinct: on the **SHMEM** transport the residual loss shows `reader-node-store=0` — the
missing samples **never arrived**, so that part is a wire/repair fault, not a drain fault. One probe instead
showed 80 samples arrived and stayed undrained, which points at the ZC **join-watermark** (a mechanism that
engages only on a loan-capable node, i.e. SHMEM — which is why this residual is SHMEM-specific).

## What is asserted in the suite, and what deliberately is not

`run-drain-window-test` pins ADR 0108 **directly on the drain record**, deterministically, and every
assertion was falsified: reverting `%drained-delivered-p` to a bare high-water turns `DW-REORDERED-PENDING`
red, and deleting the clear-on-advance turns `DW-WRAP-NOT-STALE` red.

⚠️ An **earlier version of the wrap fixture stayed GREEN under that second sabotage** — it advanced the
high-water by a full window width, which takes the wholesale-reset branch and never reaches the clear loop.
The fixture now advances twice, each strictly inside one width. *A sabotage that cannot reach the sabotaged
code proves nothing.*

An end-to-end delivery-count assertion is **not** landed: with the third defect open it would be flaky, and
the standing order allows exactly two options — fix the failure or delete the test, never gate it. The
reproducer lives here instead.
