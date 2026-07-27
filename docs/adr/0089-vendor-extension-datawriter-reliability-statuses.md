# ADR 0089 — vendor-extension DataWriter reliability statuses, and the three registrations a status needs

- **Status:** **Accepted.** Implemented, unit-tested, falsified, live-probed and measured allocation-neutral; see §8 and §9.
- **Date:** 2026-07-26
- **Requirements:** FR-DCPS-2 (listeners/conditions), FR-DCPS-3 (status change/reset semantics), FR-QOS-4 (vendor-extension QoS namespace, kept separate from the standard policies), NFR-MEM / NFR-PERF-8 (0 bytes/sample), NFR-IP (clean-room)
- **Relates to:** ADR 0080 (`UNADDRESSABLE_PEER` — two shipped defects fixed here, §3); ADR 0088 (the closure-allocation defect, which recurred here twice, §7); ADR 0042 (the writer-loan that blocks a genuine `on_sample_removed`, §5); ADR 0064 / the no-conditions rule (a status is how this stack reports, never a printed line)
- **Contract touched:** `DDS.RTPS.HISTORY` — `hc-add-change` gains a **second return value** (§6). `DDS.QOS` gains two vendor slots. `DDS.DISC` replaces one node hook with two. All consumers enumerated in §6.

---

## 1. What this is, and what it is not

The owner asked for parity with the RTI Connext **DataWriterListener extension callbacks**, so an
application ported from Connext does not lose notifications it was written against. DDS 1.4 defines none
of them — there is no OMG clause to implement from, so the only citable source is RTI's **public
documentation**, read and recorded in `docs/provenance.md` (2026-07-26). No RTI header, source or
generated output was read or copied (NFR-IP).

That reading is what makes this ADR mostly a record of things **not** shipped. Of the six extension
callbacks Connext 7.3 actually has, this slice ships **two**, withdraws **two** that a first cut had
already written, and documents **two** as out of reach with the reason:

| Connext 7.3 DataWriterListener callback | here |
|---|---|
| `on_reliable_writer_cache_changed` | **shipped**, watermark-driven (§4) |
| `on_reliable_reader_activity_changed` | **shipped** |
| `on_sample_removed` | **withdrawn** — a different event under a familiar name (§5) |
| `on_instance_replaced` | **not possible yet** — needs a QoS and an eviction path we do not have (§5) |
| `on_application_acknowledgment` | out of scope here; APP-ACK is its own slice, and RTPS 2.5 defines no application acknowledgment at all |
| `on_service_request_accepted` | out of scope (RPC) |

`on_destination_unreachable`, which the first cut also shipped, **does not exist in Connext 7.3 at all**
(§5).

**The governing rule for the whole slice: a familiar name with different firing rules is worse than an
absent one.** An application ported from Connext reads the name, assumes the semantics, and is wrong in a
way nothing will tell it about. That is the single reason this work sat on a branch instead of landing.

---

## 2. ⭐ The reusable lesson: a status needs THREE registrations, and each omission fails silently

This is worth more than the statuses. Adding a `defconstant` and a status struct is **not** enough. A
communication status must be registered in three places:

| registration | file | what breaks if it is missing |
|---|---|---|
| `*status-kind->bit*` | `src/dds-dcps/statuses.lisp` | `%status-active-p` ends in `(and bit (logtest …))`, so the bit is `NIL` and **its StatusCondition never triggers**. The bitmask and the `get_*_status` snapshot still work, so only a WaitSet reveals it. |
| `*status-listener-invokers*` | `src/dds-dcps/entities.lisp` | `%notify-status` does `(funcall (cdr (assoc kw *status-listener-invokers*)) …)` and therefore **funcalls `NIL`** — on a receiver or discovery thread, **where the error is swallowed**. Every other path keeps working; the callback simply never arrives. |
| the `defgeneric on-<name>` | `src/dds-dcps/listeners.lisp` | nothing for the invoker to call |

The first cut of this slice registered only the constant and the struct. It compiled, it passed the
suite, and on a live reliable exchange **all three of its callbacks fired zero times**. Nothing detected
it but a live probe, because *nothing a status should have done was ever asserted*.

**So the registration itself is now asserted.** `run-status-registration-completeness-test` walks both
maps and requires every status to carry all three — with exactly two exemptions, `DATA_AVAILABLE` and
`DATA_ON_READERS`, which are **level-based**: they never travel through `%notify-status` at all
(`%fire-data-available` / `%fire-data-on-readers` walk the containment chain and call the generic function
directly, and set no bitmask bit), so an invoker entry would be dead code. That test found the gap that
§3 records, on its first run.

---

## 3. Two defects in `UNADDRESSABLE_PEER`, shipped and invisible since ADR 0080

ADR 0080's docstring has promised **"bitmask + StatusCondition + listener + `get_*_status`"** since it
landed. Only the bitmask and the snapshot ever worked:

1. **Absent from `*status-kind->bit*`** ⇒ its StatusCondition never triggered.
2. **`on-unaddressable-peer` never existed** as a generic function and had no invoker entry ⇒ enabling
   `:unaddressable-peer` in a listener mask would **funcall `NIL` on the discovery thread**.

Both are fixed here. They are independent of the new work and are the reason §2 is written as a rule
rather than an anecdote: the same omission happened twice, eight ADRs apart, and neither instance was
visible to any test.

---

## 4. The design: an episode, not a level

`RELIABLE_WRITER_CACHE_CHANGED` reports the **send window** — changes written but not yet acknowledged by
every matched reliable reader. Its field set mirrors RTI's status of the same name: four event counts
(empty / full / low-watermark / high-watermark), the current unacked count and its peak, and
`replaced_unacknowledged_sample_count`.

Two things about it are load-bearing.

### 4.1 It is EDGE-triggered, and gated on an episode

A reliable exchange moves the unacked count **twice per sample** — up on the write, down on the
acknowledgement. A level-triggered version therefore fires per sample: an application callback on the data
path, running on the write and receiver threads, saying nothing actionable. The first cut did exactly
that; the owner's word for it was *"would flood a listener"*, and that is the defect this ADR exists to
fix.

Edge-triggering alone is not sufficient. Watermark **crossings** are still per-sample when the window
oscillates 0↔1, which is the ordinary case. So the low and empty transitions are gated on a
**backpressure episode**: the high watermark **opens** one, the low watermark or a drain to empty
**closes** one. An exchange that never reaches the high watermark is not in trouble, so its perfectly
ordinary drains to zero are not events. This is a Schmitt trigger, and it is the same shape as the
mechanism RTI's own watermarks primarily drive — the switch to `fast_heartbeat_period`, which is a mode
and therefore cannot be turned off without first having been turned on.

`FULL` is deliberately **not** episode-gated: the cache being at `RESOURCE_LIMITS max_samples`, so the
next write blocks or is refused, is an absolute condition that needs no episode to mean something.

### 4.2 The watermarks default to DISABLED — a deliberate divergence from Connext

RTI documents `low_watermark` 0 and `high_watermark` 1. **Adopting those numbers here was measured and
rejected.** At `{0, 1}` with one sample in flight, every write crosses high and every acknowledgement
crosses low: two listener invocations per sample. `gate-mem` scored it at **+763 bytes/sample**.

But the byte count is not the argument. Connext can afford that default because there the pair primarily
drives an *internal* mode and the status change is a by-product costing two counter increments; here the
pair drives an *application callback*. **A status whose purpose is to announce backpressure must be silent
when there is none.** Adopting the numeric default while omitting the mechanism it was chosen for would be
parity in appearance only.

So both watermarks default to `NIL`. With them unset the status still reports the FULL transition and
still keeps its **levels** — unacked count, peak, replaced-unacked — continuously readable through
`get_reliable_writer_cache_changed_status` at no cost. That is what makes a silent default honest rather
than inert, and `run-vendor-writer-status-test` asserts both halves.

### 4.3 The unacked count is the SEND WINDOW, not the cache occupancy

The first cut passed `hc-change-count` — every change the cache *stores*. For a VOLATILE writer that has
just purged, the two coincide, which is why a live probe looked correct. They diverge exactly where it
matters: a **TRANSIENT_LOCAL** writer retains its acknowledged history for late-joiners (DDS 1.4
§2.2.3.4), so its stored count is the whole history forever while its true unacked count may be zero.
Reporting the stored count would tell such an application it was under unbounded backpressure while
nothing at all was wrong.

`writer-unacked-count` is `last-SN − acked-watermark + 1`, clamped at 0 — O(1), both terms maintained
incrementally. The watermark is now recorded by `writer-purge-acked` **before** its durability gate,
precisely so it stays true for the writer that never purges.

---

## 5. Rejected, and why

**`on_sample_removed` — withdrawn.** Connext fires it **only** for samples written with a cookie or under
Zero-Copy/FlatData, and hands back a `DDS_Cookie_t` so the application can reclaim the buffer. Ours fired
on every purge with an `:acked` / `:replaced` / `:dropped` reason — a different event under the same name.
Worse, of those three reasons **only `:acked` was ever fired**; `:replaced` and `:dropped` were documented
and dead. After the fold there is nothing left to report: `:replaced` now lives where RTI puts it, in
`RELIABLE_WRITER_CACHE_CHANGED`'s `replaced-unacked-sample-count`; `:dropped` is already `write()`'s own
return code; and `:acked` is an event RTI reports under no name at all. The genuine cookie callback needs
a writer-loan **reclaim** path that ADR 0042's loan does not have — it retains its payload by design, so
"you may now reclaim this buffer" would be a lie. That is a separate slice. **StatusKind bit 27 is left
reserved**, not recycled, so no persisted or logged mask silently changes meaning.

**`on_destination_unreachable` — dropped.** It **does not exist** in the Connext 7.3 DataWriterListener.
It had been listed from recollection and built as an alias onto `UNADDRESSABLE_PEER`. Connext's actual
answer to an unreachable destination is the internal **locator reachability ping** (5.3.0+), which stops
using the locator rather than notifying anyone. Our `UNADDRESSABLE_PEER` stands on its own merit — refuse
the match, report the locator kinds the peer did offer — but it is **not parity**, and it is not dressed
in a Connext name.

**`on_instance_replaced` — not possible yet.** It fires when a writer exceeds
`ResourceLimits::max_instances` and *reclaims* an instance, with eligibility chosen by
`DataWriterResourceLimits::instance_replacement` and the precondition that an instance's samples be fully
acknowledged before it is replaceable. **We reject instead of evicting** (`:rejected-by-instances-limit`),
and our instance limit is reader-side — the writer's instance table is unbounded. So this is a missing QoS
policy plus an eviction path, not a missing callback, and pretending otherwise by wiring a callback that
can never fire is the inert-status trap again.

---

## 6. Contract changes, with every consumer

**`DDS.RTPS.HISTORY` — `hc-add-change` now returns `(values symbol (or null integer))`**, the second value
being the SN this add evicted (KEEP_LAST only), or `NIL`. Whether an eviction destroyed *unacknowledged*
data is a **writer** question — it depends on the acked watermark across matched readers, which a
HistoryCache has no view of. Returning the SN rather than counting it here keeps `history.lisp` — a
designated hot-path file — free of the cross-layer coupling and the allocation a callback would need. An
extra value costs nothing, and **every existing caller reads a single value and is unaffected**: callers
are `%writer-add-bounded` (updated, consumes it), plus `src/dds-bench/keeplast-bench.lisp` and four sites
in `src/dds-tests/` — all single-value contexts.

**`DDS.QOS`** gains `writer-cache-low-watermark` / `writer-cache-high-watermark` (FR-QOS-4: vendor
namespace, DataWriter-scoped, **no** RxO semantics, never in SEDP, no OMG `QosPolicyId_t` — an
inconsistency reports `+qos-policy-id-invalid+` rather than an invented id, exactly as DISCOVERY_CONFIG
does). When both are set, low must be strictly below high; equal thresholds leave no hysteresis band.

**`DDS.DISC`** replaces the single `on-writer-reliability` hook with **two**: `on-writer-cache` (fired from
the write path *and* the ACKNACK purge) and `on-reader-activity` (fired from the ACKNACK path, which *is*
the evidence a reader is acknowledging). Firing the cache hook only from the ACKNACK path would report the
window falling and never rising — so a writer whose reader has stopped acknowledging, *precisely the case
the high watermark exists for*, would never be seen to cross it.

---

## 7. ⭐ The allocation defect that recurred twice in one slice

The write path is per-sample, so `gate-mem` governs. It caught **+763 B/sample**, and same-image A/B
attribution (never a profile — `sb-sprof :alloc` ranks *events*, not bytes) found **three** independent
causes, only one of which was the obvious one:

| cause | cost | why |
|---|---|---|
| RTI's `{0, 1}` watermark defaults | ~530 B/sample | 2 real events per sample (§4.2) — a semantic defect that merely *presented* as bytes |
| four edge flags `setq`'d under the lock, then read by the notification closure | **123.5 B/sample** | to SBCL those are four **mutable closed-over variables**, and it heap-allocates a **value cell for each**, on every call, whether or not any edge was crossed. Fixed by returning them as bits of **one immutably-bound fixnum** |
| `%notify-reader-activity` building its `apply-fn` closure unconditionally | **76.4 B/sample** | `%notify-status` takes a closure, and it was constructed on every inbound ACKNACK before anything had been tested. Fixed with an allocation-free membership guard |
| `%participant-writer-by-entity-id` → `%participant-writers` | **43.7 B/sample** | it `append`s a fresh list of every writer in the participant, per call. Fine for its match-time callers; not fine once the vendor statuses resolve a writer per write and per ACKNACK. Rewritten to walk the containment tree directly — allocation-free, and every other caller benefits |

**The second and third are ADR 0088's defect again**, in two new disguises: *a closure allocates on every
call, including the calls where nothing happens*. ADR 0088 lost its entire first-cut win to it. The
generalisable rule is now stated where it can be found: **on a per-sample path, the guard goes outside the
notification, never inside it** — because the argument to the notification is itself the allocation.

A fourth hypothesis, that `bordeaux-threads:with-lock-held` conses per acquisition, was **measured and
disproved** (0.00 bytes over 2 000 000 acquisitions) before any design was built on it.

---

## 8. Falsification

Every assertion here was seen to go **red** before being believed:

| break introduced | test that caught it |
|---|---|
| edges reported level-triggered instead of edge-triggered | `:vwc-edge-high-once` |
| the episode gate removed from `%writer-cache-edges` | `:vwc-quiet-by-default` |
| `hc-change-count` substituted for `writer-unacked-count` | `:wuc-transient-local` |
| a status's `*status-listener-invokers*` entry removed | `:status-reg-invoker` |
| a status's `on-<name>` generic function removed | `:status-reg-generic` |

---

## 9. As built — measured

**Allocation: the slice costs 0.0 bytes/sample.** Same-image A/B on arm64 against the live `gate-mem`
workload, whole slice on vs. neutralised: **1738.6 / 1738.6**. `gate-mem` on the final tree reads
**1740.4** against a ceiling of 1775 (`main` was 1742.1, so the slice is neutral; an intermediate reading
of 1738.2 and this one differ by 2.2 B, inside the ~3 B session spread `bench/mem-ceiling.txt` documents
at 60 000 samples — which is exactly why the A/B, not the absolute reading, is the claim). The ceiling is
**not** lowered — no win is claimed.

**Live probe** (two participants, 40 reliable samples, a distinct domain per arm):

| arm | `on_reliable_writer_cache_changed` | `on_reliable_reader_activity_changed` | snapshot |
|---|---|---|---|
| watermarks `{2, 10}` configured | **2** — one high crossing, one low | 1, `active_count=1` | `low=1 high=1 peak=28` |
| **default QoS** | **0 — silent** | 1, `active_count=1` | `peak=40` tracked |

Two events for a 40-sample burst where the first cut produced twelve, and the default configuration is
silent while still tracking every level. That is the whole design, observed on the wire rather than
argued.
