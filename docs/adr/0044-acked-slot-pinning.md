# ADR 0044 — Acked-slot pinning: eliminate the loan-write retained-payload heap allocation for eligible reliable writers

Status: Accepted (R6 — NOT cleared for ship, pending counsel; layered on the patent-gated Zero-Copy path, ADR 0014/0017/0042)
Date: 2026-07-04
WP: WP-ACKED-SLOT-PINNING (ADR 0042 §Follow-ups; lifts the explicit v1 non-goal "we do not widen slot lifetime into retransmit territory")
Requirements: FR-PF-4, FR-LANG-7, NFR-MEM; correctness/stability binary gates (the operating contract §4)

## 1. Context

WP-FLATDATA-LOAN-WRITE (ADR 0042) shipped the app-facing zero-copy TX loan: the app writes a
FlatData sample straight into a SHMEM Zero-Copy pool slot and `write-loaned` publishes it. To serve
retransmission / non-ZC / extra-ZC destinations, `write-loaned` ALWAYS materialises a RETAINED
SerializedPayload — a straight slot→heap copy of the whole sample (`%loan-write-payload`,
`entities.lisp`), stashed in the writer HistoryCache. That per-write heap vector is why v1
`write-loaned` is NOT 0-GC (ADR 0042 §5, the DCPS-cycle bench arm).

This ADR removes that allocation for an ELIGIBLE writer by **pinning** the committed pool slot (holding
a dedicated TX refcount) until every matched reliable reader has ACKed the sequence number, then
releasing it. Retransmit / non-ZC / extra-ZC sends read the still-pinned slot ON DEMAND (a copy only
WHEN such a send actually happens — rare — instead of on EVERY write).

## 2. The governing principle (a correctness binary gate)

Pinning is a **BOUNDED, BEST-EFFORT OPTIMISATION layered on top of the always-correct retained-payload
path.** The retained-payload materialisation is NOT removed — it remains the mandatory fallback,
taken whenever the writer is ineligible OR the pin budget is exhausted OR any interleaving is unclear.
Every existing reliable/ZC/non-ZC/late-joiner path behaves identically; the ONLY observable delta is
fewer heap allocations for eligible writers (and the bench win). When unsure, fall back — never risk a
correctness gate for the allocation win.

## 3. Eligibility matrix (pin ONLY when ALL hold)

PIN-ELIGIBLE (`node-loan-write-pin-capable-p`, checked at `write-loaned` time):
- the slot-backed loan path already applied (`node-loan-write-eligible-p` — so security-clear +
  size-in-range are guaranteed: a secured/oversize/undersize/no-pool/saturated write never reaches here);
- DURABILITY = `:volatile`, OR a FINALIZED writer (`rtps-writer-finalized`) of any durability
  (durability-finalize declared "no more late-joiners", so the full-ACK purge is re-enabled);
- there is ≥1 MATCHED RELIABLE READER (`%matched-reader-keys` non-empty). This is the necessary-and-
  sufficient condition that the pin will be RELEASED: the pin drops at the full-ACK purge, which is
  driven by reliable readers' ACKNACKs. It also subsumes writer-reliability (RxO: a reliable reader can
  only match a reliable writer). A best-effort reader never ACKs, so it is correctly excluded.

MANDATORY FALLBACK (eager retained payload = exactly today's behaviour):
- best-effort writer / no matched reliable reader (nothing would ever release the pin);
- un-finalized TRANSIENT_LOCAL (a late joiner could need the sample arbitrarily later — infeasible to
  pin with 32 slots);
- pin budget exhausted (decided atomically at the pin site, `publish-sample`);
- everything that already falls back at loan time (secured, oversize, undersize, no pool, saturation).

KEEP_LAST vs KEEP_ALL: both may pin. A KEEP_LAST early eviction (`hc-add-change`, `history.lisp`)
drops a change BEFORE ack; the pin release fires from that eviction path too (the sample is superseded,
no retransmit owed — correct to release early).

## 4. The refcount lifecycle (the crux)

The Zero-Copy pool has 32 slots (`+zerocopy-pool-slots+`); a slot is reclaimable ONLY at refcount==0
(`%zc-take-free-or-reclaim`). Pinning holds slots longer, so:

### 4.1 Two DISTINCT refcount holds on one u32

For a pinned change the slot carries **refcount = 2**:
- **the DELIVERY hold** (+1): today's armed-slot semantics, unchanged. `loan-sample` →
  `%zc-loan-acquire ... readers=1` sets it. The send site's `%zc-armed-item`/`writer-zc-claim`
  (one-shot `:armed`→`:consumed`) transfers it to the resolving reader, whose `%zc-release`
  (return-loan / resolve, possibly a different thread/process) drops it. If never emitted (fallback
  decision / sweep), `%zc-drop-armed`/`writer-zc-unarm` (`:armed`→`:released`) drops it.
- **the TX PIN hold** (+1): NEW. Added at `publish-sample` AFTER a successful `writer-write`, via
  `%zc-pin` (an atomic `cas-sap-u32` INCREMENT of the refcount sub-field, generation-guarded, floored —
  never pins a refcount==0/stale slot). Released at the full-ACK purge and every other change-drop site.

The two holds are SEPARATE so the reader's `return-loan` cannot free the slot before the writer's
ACK-release (the writer still needs the slot live to serve a retransmit until the reader ACKs).

### 4.2 Release order is non-deterministic; the release is two-gate, idempotent, floored

The reader's `return-loan` (`%zc-release`) and the writer's ACK-purge (the pin release, also
`%zc-release`) run on different threads with no ordering. Each hold is released by exactly ONE
`%zc-release` (each a floored `cas-sap-u32` decrement that is a validated no-op at 0). Whichever hits
refcount 0 LAST frees the slot. This is structurally identical to the existing
`send-refcount` + `evicted` + `hc-try-release-pooled` two-gate machinery (`history.lisp`): the pin
release REUSES that pattern (`hc-try-release-pinned`, a sibling of `hc-try-release-pooled`), NOT a
parallel invention. Each hold's ONE-SHOT is guaranteed by a state flag:
- the delivery hold by `zc-state` (`:armed`→`:consumed`|`:released`, under the writer lock);
- the pin hold by `zc-pinned` (a boolean flipped T→NIL exactly once, under the writer lock, inside the
  removal choke).

### 4.3 The slot survives its HistoryCache change being purged

`writer-purge-acked` computes the min-across-readers acked-base and calls `hc-purge-below` →
`%hc-remove-change` — the SINGLE change-removal choke. `%hc-remove-change` now also calls
`hc-try-release-pinned`, which (under the writer lock the caller already holds) flips `zc-pinned`
T→NIL once and funcalls the HistoryCache's `zc-release-fn` closure (installed by the disc layer at
`enable-publisher`) to `%zc-release` the pin hold + decrement the live-pin budget counter. Because the
pin hold kept refcount ≥1, the slot outlived the purge exactly as
`run-reliable-zc-slot-outlives-purge-test` proves for the reader's delivery hold; here we mirror it for
the TX pin.

Layering: `hc-try-release-pinned` lives in `dds.rtps.history`, which may NOT depend on
`dds.xport.zerocopy`; it funcalls an opaque closure (`history-cache-zc-release-fn`) the disc layer
installs — the same indirection `payload-pool` uses. No lock is taken in the closure (it is
`%zc-release` + an atomic-cell decrement, both lock-free), so there is NO lock-ordering hazard against
the writer lock it runs under.

### 4.3a The pin defers on `send-refcount` — symmetric with the pooled buffer (I1)

`hc-try-release-pinned` releases the pin ONLY when the change is BOTH `evicted` AND `releasable-p`
(`send-refcount == 0`) — the SAME two-condition defer-gate `hc-try-release-pooled` uses, and load-bearing
for the SAME reason: a captured send build-thunk may still resolve the pinned slot **by reference**
(`%ensure-change-payload` reads the live slot), so the pin — which keeps the slot's generation frozen and
refcount ≥ 1 — must OUTLIVE any in-flight/deferred send-ref. Without this, a KEEP_LAST supersession (or
purge) that removes the change while a sender thread holds a send-ref would release the pin, let the slot
be reclaimed + generation-bumped, and a concurrent resolve would then fail (a stale-generation NIL) —
which, if the datagram plan ignored the NIL, would put a NIL payload with a nonzero length onto the wire
(a sender-thread crash / malformed datagram; the generation guard prevents *wrong bytes* but not the
NIL). So a change EVICTED while send-referenced DEFERS its pin release to the LAST send-ref drop, retried
from BOTH triggers that can make it due — the eviction choke (`%hc-remove-change`) and the send-ref drop
(`writer-release-change-ref` / `writer-release-change-refs`, next to the pooled retry). No pin leaks: every
send-ref is released in an `unwind-protect` after its send, so the deferred pin always fires.

### 4.4 Every change-drop site releases the pin exactly once

- **Full-ACK purge** — `writer-purge-acked` → `hc-purge-below` → `%hc-remove-change` → the choke.
- **KEEP_LAST early eviction** — `hc-add-change` (superseded before ack) → `%hc-remove-change` → the
  choke. Correct: no retransmit is owed for a superseded change.
- **Dispose / any `hc-remove-change`** — → `%hc-remove-change` → the choke.
- **`publish-sample` :timeout** — the change was never stored (the choke never runs), so the pin was
  never taken (the `%zc-pin` runs AFTER a confirmed `writer-write`); the existing timeout path releases
  the delivery hold. Nothing extra owed.
- **Node teardown (`stop-node`)** — the pool segment is `%zc-destroy`ed + unlinked, so any still-held
  pin is moot (no reader can observe an unlinked segment). The live-pin budget counter dies with the
  node.

The `zc-pinned` one-shot flag makes every route idempotent: a change removed once, then swept/removed
again, releases the pin exactly once (mirroring the floored `%zc-release`).

## 5. Retransmit / non-ZC / extra-ZC byte-source (on-demand slot read)

A pinned change carries NO retained SerializedPayload (`serialized-payload` is NIL; the true length is
recorded in `zc-len`, so `cache-change-payload-len` and the ZC eligibility gate work without touching
the slot). The FIRST ZC-eligible destination is served by the pre-committed slot's ref
(`%zc-armed-item`, no bytes needed). Every OTHER send — a non-ZC destination, an extra ZC destination,
a retransmit (which passes `zc-readers=0`), or a large-sample DATA_FRAG series — needs the bytes, so it
resolves the pinned slot ON DEMAND via `%ensure-change-payload`:
- `%zc-resolve-fresh` reads the slot's payload (generation-guarded, under the pool mutex, clamped to
  slot-bytes) into a fresh heap vector — byte-IDENTICAL to what `%loan-write-payload` would have
  produced (both copy `size` octets from the payload base of the self-describing slot);
- the resolved vector is cached onto the change (`serialized-payload`), so a subsequent send reuses it
  and the change thereafter behaves like a fallback change (LAZY retained payload = "materialise only
  when a non-pure-ZC send actually needs it", vs today's eager-on-every-write).

The slot is guaranteed live for that read because the pin hold keeps refcount ≥1 AND the pin release
DEFERS on any outstanding send-ref (§4.3a): the datagram plan is built while `writer-capture-unsent` /
`writer-acquire-sample` hold a send-ref on the change, so the pin cannot be released during the resolve.
A legitimate retransmit happens only because the reader NACKed (has not ACKed) ⇒ the pin has not been
released. `%zc-resolve-fresh`'s generation guard makes even a theoretical concurrent reclaim SAFE (it
returns NIL). **Defense in depth:** the main datagram plan's non-ZC/large branch USES the resolve return
value — a `:data` change whose resolve returns NIL is SKIPPED (a best-effort dropped datagram the reader
re-NACKs), never a NIL payload with a nonzero length onto the wire; the `%zc-change-item` fresh-loan
fallback and `%on-user-nack-frag` already guard the same way. So the ADR's "NIL resolve is a dropped
datagram, never a crash" claim holds on every send path.

Re-emitting the slot REF on retransmit (instead of reading bytes) needs per-(reader×SN) refcount
accounting and is OUT of scope v1 (an ADR 0042 remaining follow-on); on-demand read is the simple
correct v1.

## 6. Pin budget (bounded)

`dds.disc:*zc-pin-budget*` (default **16**) caps the number of slots simultaneously pinned per node.
16 leaves at least half of the 32-slot pool for fresh classic loans + RX loans, so pinning never
starves them. `disc-node-zc-pin-count` (a PAL `atomic-cell`) tracks the live pinned count: incremented
(under the pin's `%zc-pin`) at grant, decremented (in the `zc-release-fn`) at every pin release. At
budget, a new eligible write RESOLVES the retained payload on demand from its still-armed slot and takes
the fallback (`zc-pinned` NIL) — no error, no starvation, traffic flows. The counter is advisory (a
resource heuristic, not a correctness gate): a stale read can only over/under-count by the number of
concurrent releases, both of which degrade gracefully (a released hold only makes room).

## 7. Accounting summary (one pinned change, one ZC reader, no loss)

```
loan-sample      %zc-loan-acquire readers=1     refcount 1   (delivery hold)
publish-sample   %zc-pin (grant, budget++)      refcount 2   (delivery + PIN)
push             %zc-armed-item / writer-zc-claim :armed->:consumed   (delivery -> reader)
reader resolve   %zc-release                    refcount 1   (delivery hold gone; pin holds)
reader ACK       writer-purge-acked -> %hc-remove-change -> hc-try-release-pinned
                 zc-pinned T->NIL, %zc-release, budget--   refcount 0 -> slot reclaimable
```
Reverse order (ACK-purge before the reader returns the loan): the pin release drops 2→1; the reader's
later `return-loan` drops 1→0. Either order frees the slot exactly once, no UAF, no leak.

## 8. Known bounded degradations (documented, not bugs)

- A reliable reader that matches then LEAVES before acking: the pin for its in-flight samples is not
  released by a purge (no keys) until KEEP_LAST eviction / budget saturation / teardown. Bounded by the
  16-slot budget (further writes fall back). A pin-release-on-unmatch is a follow-on.
- Reliable writer matched to only best-effort readers: `%matched-reader-keys` is empty ⇒ never
  pin-capable ⇒ eager retained payload (today's behaviour). No leak.

## 9. Consequences

- `write-loaned` for an eligible writer no longer allocates the per-write retained SerializedPayload
  (the headline: `+<type>-flatdata-size+` GC bytes/sample eliminated for the pinned case).
- No wire byte changes on any path: the FIRST-ZC-dest ref, the fallback DATA/DATA_FRAG, and the
  retransmit all emit the SAME bytes as before (the on-demand read reconstructs the identical retained
  payload).
- Consumers touched: `dds.xport.zerocopy` (`%zc-pin`); `dds.rtps.history` (`cache-change` +2 fields,
  `history-cache` +1 field, `hc-try-release-pinned`, the choke); `dds.rtps.reliable` (`writer-write`
  pin params); `dds.disc` (`*zc-pin-budget*`, `disc-node-zc-pin-count`, `node-loan-write-pin-capable-p`,
  `publish-sample` pin path, `%ensure-change-payload`, the send-plan/NACK_FRAG on-demand reads,
  `enable-publisher` release-fn install); `dds.dcps` (`write-loaned` pin/fallback branch). All additive
  and behind the pin-eligibility gate — a non-eligible write is byte-and-alloc-identical to ADR 0042.
- ADR 0042 §Follow-up "retained-payload elimination" is resolved by this ADR; the multi-ZC-destination
  per-dest refcount and the slot-ref-retransmit remain follow-ons.
