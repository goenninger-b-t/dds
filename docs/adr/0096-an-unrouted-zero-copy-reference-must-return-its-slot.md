# ADR 0096 — An unrouted Zero-Copy reference must return its slot; and the writer was not double-delivering

- **Status:** **Proposed** — §3 and §4 are implemented and falsified; **§5 needs an owner decision** before it
  is written.
- **Date:** 2026-07-29
- **Requirements at stake:** **FR-PF-3 / FR-PF-4** (Zero-Copy + FlatData-over-ZC), **NFR-MEM** (a bounded pool
  that stays bounded), **NFR-DET**.
- **Relates to:** ADR 0014 (the Zero-Copy pool), ADR 0017 (the reader-side loan/defer), ADR 0042
  (loan-write), ADR 0047 (the cross-destination shared slot), ADR 0048 §17.7 (the frozen-joiner refcount
  leak — the same defect class, the other cause).
- **Provoked by:** `MD-E2E-P2-VIEW`, the ONE test still red on Linux x86_64 after the CI rebuild (`b69951d`)
  made 418 previously-unrun tests visible.

---

## 1. The retraction

The prior session recorded this diagnosis, and it was carried forward as the approved next task:

> The writer emits **both a ZC reference and a full payload for the same change to the same reader**. Dedup
> keeps whichever lands first […] a race, not a quirk. The invariant is violated in the multi-destination
> path.

**The byte evidence was right; the causality was backwards, and the fix it implied would have been wrong.**
A ZC reference and a full payload do both reach the reader, but the writer is not choosing to send both. The
sequence, measured on real Linux x86_64 in the Docker harness, is:

1. the writer sends the sample as a **Zero-Copy reference** — once per destination, exactly as designed;
2. the receiving participant **has no reader route for that writer yet**, so `%deliver-user-marker` drops the
   marker (`canon` NIL) *and never calls `reader-on-data`*;
3. its reliable reader therefore still has a hole at that SN, so the next HEARTBEAT makes it **ACKNACK**;
4. `%on-user-acknack` repairs the hole with the **retained full payload** (`zc-readers` 0 — by design, ADR
   0042: a retransmit never re-emits the slot);
5. the app takes an `OCTET-BUFFER` for a sample the writer sent as a reference.

Step 2 is the cause. Steps 3–5 are RTPS reliability doing precisely its job. **There is no writer defect
here to fix** — an ACKNACK-driven retransmit of a sample the reader really did not have is not a
double-delivery, and `%send-changes-packed`'s "exactly one of {ref, full payload} reaches each reader" is a
statement about ONE push pass, which still holds.

The probe that settled it printed, per received DATA, the node prefix, the payload's first octets, and the
branch `%on-user-data` took:

```
PROBE-RX node=4742039AA414EE… plen=20 rxbuf=65536 first=4B43 pool=T loan-capable=T defer=MARKER
PROBE-MARKER node=4742039AA414EE… sn=1 routes=0 canon=NIL          <- the ref parsed, attached, and was DROPPED
PROBE-REPAIR: SN (1) -> 127.0.0.1:38777
PROBE-RX node=4742039AA414EE… plen=20 rxbuf=65536 first=0007 …     <- the repair, as a full payload
```

`defer=MARKER` with `routes=0` is the whole finding: the reference was valid, the pool attached, the marker
was built — and there was nobody to give it to.

## 2. Why there was nobody to give it to: matching is not symmetric

A writer matches a remote reader when it processes that reader's **SEDP subscription**. A reader matches a
remote writer when *it* processes that writer's **SEDP publication**. These are two independent exchanges
with independent completion times. So a writer can — routinely does — resolve a destination as matched, and
push to it, before that destination has routed the writer back.

`%reader-routes-for` is deliberately strict about this (ADR 0048): once DCPS owns matching, an empty route
means NO READER, and the sample is dropped rather than handed to the primary. That strictness is correct and
must stay — it is what made the RxO gates binding instead of advisory. The consequence is simply that the
opening samples of every fresh pairing can be dropped and then repaired.

`MD-E2E-P2-VIEW` waited only for **p1** to see two ZC-eligible push groups and then wrote. It never waited
for p2/p3 to match p1's writer. On macOS that window closes fast enough that the ref usually lands routed;
on Linux it did not, so the test was red every run. It had never passed on Linux — it landed 2026-07-05 and
CI did not exist until 2026-07-14.

## 3. THE REAL DEFECT: the dropped reference never gave the slot back

The writer's `%zc-loan` presets **one refcount hold per destination participant** (`%zc-ref-builder`
RESOLVES=1, or `%shared-loan-for` N for the ADR 0047 shared slot). That hold is discharged by that
participant's single drainer, at `return-loan`.

**An unrouted marker has no drainer, and nothing released the hold.** The slot stayed held for the life of
the process. Every unrouted reference — i.e. the opening samples of every fresh pairing, plus every sample
an RxO gate refuses — permanently consumed one slot out of `+zerocopy-pool-slots+`. Once the pool saturates,
`%zc-loan` returns NIL, the send path falls back to the full payload, and **Zero-Copy silently stops
happening** with no error, no status, and no counter. That is the defect worth fixing, and it is the one
this ADR closes.

**Fix:** `%deliver-user-marker` `%zc-release-marker`s a marker it did not store because there was no route.

**The deduped-duplicate arm deliberately does NOT release, and that asymmetry is the point.** A duplicate
reference carries no second hold: the writer loans one hold per participant and never re-loans on repair
(the ACKNACK path sends the retained full payload with `zc-readers` 0), so a wire duplicate is the *same*
slot at the *same* generation. Releasing there would discharge the hold the STORED marker's drainer still
owes, freeing the slot under the app's in-place read — a cross-process use-after-free, strictly worse than
the leak it would close. Leaking on that arm is the safe direction and it is unreachable in this stack.

This is the third instance of a pattern `%deliver-user-sample` already applies twice (release the pooled RX
buffer, release the secured loan handle, on the same drop). It is also the same defect class as ADR 0048
§17.7 — a hold nobody owes — reached by a different route.

**Falsified.** `run-zc-unrouted-release-test` is deterministic and single-process, and has two arms:

| arm | assertion | without the fix |
|---|---|---|
| UNROUTED (no local reader) | nothing stored **and** refcount back to 0 | **RED** — `ZC-UNROUTED-RELEASED` |
| ROUTED (control) | the marker IS stored **and** the slot STAYS held | green |

The ROUTED arm is what keeps the fix honest: an unconditional release passes the first arm and fails the
second. Both arms confirmed on Linux x86_64.

## 4. The test's missing precondition

`MD-E2E-P2-VIEW` asserts a zero-copy **delivery**. A matched receiver is a precondition of that, so the test
now waits for — and asserts — `matched-count` on p2 and p3 before writing, exactly as `b69951d` gave the
delivery wait and the ZC preconditions their own assertions. This is not gating a failure: the test was
racing a precondition it never stated, and an assertion that cannot distinguish its own failure modes is a
defective assertion.

**Measured, five independent processes on Linux x86_64, one variable at a time:**

| tree | result |
|---|---|
| `b69951d` (baseline) | FAIL 5/5 — `MD-E2E-P2-VIEW`, `first is OCTET-BUFFER` |
| baseline + precondition only (engine untouched) | **PASS 5/5** |
| precondition + §3 leak fix | **PASS 5/5** |

The second row is why §5 is a separate slice rather than part of this one.

## 5. OPEN — a real writer defect found on the way, deliberately NOT shipped here

**Reliability control traffic to a same-host SHMEM peer travels UDP while that peer's DATA travels SHMEM.**
`%send-msg-buf` hard-passes NIL for `shmem-dest`, so the periodic HEARTBEAT (`%push-heartbeat`), the
late-joiner prompt HEARTBEAT (`%writer-durability-init`), the ACKNACK repair and its GAP (`%on-user-acknack`)
all go over UDP even when `%shmem-dest` resolves for that destination — which the probe confirms it does. The
coalesced push path already carries `shmem-dest` correctly; these senders simply never had the parameter.

The hazard is ordering: the SHMEM ring and the UDP socket are drained by **two different receiver threads**,
so a HEARTBEAT can overtake the DATA it announces and make a reader NACK a sample sitting unread in the ring
— manufacturing exactly the duplicate §1 retracts, this time for real. Putting the control traffic on the
destination's own lane would also make the *right* delivery win by construction: a repair queued behind an
unread reference is processed after it, so the reference is stored and the repair is deduped.

**It is not shipped because it is unmeasured.** A working patch exists (threading `shmem-dest` through
`%send-msg-buf` / `%send-user-heartbeat` / `%send-user-gap` and resolving it at the three call sites via a
NIL-safe `%prefix-shmem-dest`), and with it the repairs above demonstrably moved from UDP to SHMEM — but with
§4 in place no NACK occurs in this test at all, so there is no red-to-green to point at. Under the operating
contract that is not enough to land a behavioural change affecting every reliable writer with a same-host
peer. It needs its own slice, its own repro, and an owner decision.

## 6. Consequences

- One less silent degradation mode: a long-running writer no longer bleeds pool slots to peers that arrive,
  are refused, or are slow to route it.
- The strict "empty route means no reader" rule of ADR 0048 keeps its teeth; this ADR only makes its
  resource accounting correct.
- `%zc-release-marker` is now the single named place where the receiver hands a hold back without a drainer.
  Any future drop path added to `%deliver-user-marker` must decide, explicitly, whether a drainer owes that
  release — the ROUTED arm of the new test is the guard.
- The Docker Linux harness is what made all of this visible; the diagnosis took one run once the assertions
  named their own causes.
