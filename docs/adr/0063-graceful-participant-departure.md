# ADR 0063 — Graceful participant departure: announce it, and honour it

- **Status:** **ACCEPTED — IMPLEMENTED AND CLOSED (2026-07-14).** The stall is fixed; all four items landed.
- **Date:** 2026-07-13
- **Requirements:** FR-DISC (SPDP), NFR-SEC-POSTURE (resource exhaustion), NFR-INTEROP
- **Related:** ADR 0062 (allocation), the `%lease-sweep` path, task #15 (**which is a misdiagnosis — see below**)

## The defect

A RELIABLE + KEEP_ALL DataWriter **permanently stops serving after two clients**. Reproduced
deterministically with the parity harness (one responder, successive pinger participants, identical
256 B payload):

| client | KEEP_ALL responder | KEEP_LAST responder |
|---|---|---|
| #1 | ok | ok |
| #2 | ok | ok |
| **#3** | **FAILS — "no echo within 5 s"** | ok |
| **#4** | **FAILS — stays broken** | ok |

The responder process is alive and un-crashed; it simply never echoes again.

**This is NOT the "4 KB large-payload stall" recorded as task #15. That defect does not exist**: a single
fresh pinger at 4096 B runs at **p50 9.9 µs, max 34.6 µs**. The ladder only *looked* payload-dependent
because each `run-echo-pinger` builds a NEW participant and the **3rd** one failed in both runs. The
variable was the re-match, not the payload. Task #15 should be closed and replaced by this ADR.

## Root cause — two defects, and the second is the load-bearing one

**(A) An RTPS writer never unmatches a reader** — `rtps-writer-proxies` has no removal path anywhere, so a
departed reader's ReaderProxy survives forever and pins `writer-purge-acked`'s watermark, wedging a
KEEP_ALL HistoryCache (detail in Decision §3).

**(B) We never announce our own departure, and we never honour anyone else's** — so the ghost that
triggers (A) also takes 100 s to even be *recognised* as gone.

- **TX:** `stop-node` (`disc.lisp:2573`) joins the receiver threads and frees the announce scratch
  buffers. It writes nothing. A participant that is deleted cleanly simply goes silent.
- **RX:** the SPDP branch of `%handle-datagram` (`disc.lisp:2361`) parses the payload and records the
  participant. The DATA's `kind` and `status-flags` **are already decoded** one screen earlier
  (`disc.lisp:2340`, via `parse-data-body`) — but the **builtin** branches ignore them. Only the
  user-data path consumes them (`disc-node-on-lifecycle`).

⇒ The **only** removal path is `%lease-sweep`, at the **100 s default lease**. A cleanly-exited peer
therefore lingers as a ghost, and a RELIABLE KEEP_ALL writer is held hostage by ghost ReaderProxies that
will never ACK. `resource-max-samples` defaults to **-1 (LENGTH_UNLIMITED)** (`qos.lisp:177`), so the
HistoryCache grows with no backstop.

This is also an **interop** defect and a **resource-exhaustion** surface (NFR-SEC-POSTURE): Connext *does*
announce departure (below), and we ignore it — so we hold a ghost of every departed Connext peer for
100 s, and any peer that disappears drives unbounded writer memory.

## The wire evidence — captured, not reconstructed

Sniffed on the domain-0 SPDP multicast group (239.255.0.1:7400) with our own PAL + RTPS parser, while an
**RTI Connext 7.3.1** `shapes_sub` ran and then **exited normally** (a real `delete_participant`):

```
[SPDP] src=010149DBBD4912B45C8601BA sn= 1 dataflag=Y plen=668 keyflag=N KIND=DATA       STATUSINFO=#x00 [--] keyhash=-
   ... periodic announce, repeated ...
[SPDP] src=010149DBBD4912B45C8601BA sn= 2 dataflag=N plen=0   keyflag=N KIND=UNREGISTER STATUSINFO=#x03 [DU] keyhash=010149DBBD4912B45C8601BA000001C1
```

On delete, Connext writes **one further change on the SPDPbuiltinParticipantWriter** (SN advances 1 → 2):

- **No serialized payload** — DataFlag=0, KeyFlag=0, `plen=0`. The instance is identified **solely by
  inline QoS**.
- **`PID_STATUS_INFO` = `0x03`** = `DisposedFlag(0x01) | UnregisteredFlag(0x02)`, both set.
- **`PID_KEY_HASH` = the participant GUID** = the 12-octet source prefix + `000001C1`, i.e.
  `ENTITYID_PARTICIPANT`.

Cross-checked against the spec (the constants are pinned from the clause, never from memory):
- RTPS 2.5 **§9.6.4.9** StatusInfo_t is a 4-octet flag field laid out `|…|F|U|D|` ⇒ D = `0x01`, U = `0x02`.
  Our `+statusinfo-disposed+` / `+statusinfo-unregistered+` (`message.lisp:560-563`) already match.
- Both flags together are exactly what the spec prescribes: *"If autodispose_unregistered_instances is
  enabled, Data Messages that unregister an instance must also dispose it."*
- `+entityid-participant+` = `#x000001c1` (`message.lisp:71`) — matches the captured keyhash tail.

**Our receive path ALREADY decodes this correctly.** The sniffer used the production parser and it
reported `KIND=UNREGISTER`, `STATUSINFO=0x03`, and the extracted keyhash. We decode the goodbye and then
throw it away.

### What the spec does and does not require

RTPS 2.5 **§8.5.3.3.2** names lease expiry as the only removal trigger it defines: *"If a Participant
fails to send another announcement within this time period, the Participant can be considered gone. In
that case, any resources associated to the Participant and its Endpoints can be freed."* It does **not**
mandate a goodbye message.

And **§8.5.3** states the SPDPbuiltinParticipantWriter is a **Best-Effort StatelessWriter** — so the
departure announcement **can be lost**. It is therefore a **prompt-cleanup optimization, never a
guarantee.** The lease sweep MUST remain as the backstop; this ADR adds a fast path, it does not replace
one.

## Decision

1. **Honour an inbound participant dispose (RX) — the higher-value half, and the one with no new wire
   surface.** In the SPDP branch of `%handle-datagram`, when `parse-data-body` reports a dispose/unregister
   for `+entityid-spdp-writer+`, prune that participant **immediately**, keyed by the GUID prefix taken
   from `PID_KEY_HASH` (validating it against the datagram's source prefix — never trust wire data;
   a dispose naming *another* participant's GUID is a trivially forgeable eviction and MUST be rejected).
   **Reuse the existing `%lease-sweep` prune wholesale** (DRY): same `on-unmatch` hooks, same purge of
   `discovered` / `discovered-writers` / `discovered-readers` / match-pairs / incompat-pairs / the SHMEM
   dest cache / the ZC attach cache. This alone fixes the stall against Connext peers and, once (2) lands,
   against ourselves.

2. **Announce our own departure (TX).** In `stop-node`, before tearing down the sockets, write the
   departure change on the SPDP writer exactly as captured: next SN, no payload, inline QoS
   `PID_STATUS_INFO = D|U` and `PID_KEY_HASH` = our participant GUID (prefix + `ENTITYID_PARTICIPANT`), to
   the same locator set the periodic announce uses. Best-effort, sent once (as Connext does) — the peer's
   lease remains the backstop if it is lost.

3. **The prune MUST drop the departed participant's ReaderProxies.** This was flagged as "verify"; it is
   now **verified, and it is a SECOND, INDEPENDENT DEFECT — arguably the primary one.**

   - **A ReaderProxy is NEVER removed from an RTPS writer. Under any circumstance.** `rtps-writer-proxies`
     is only ever created-on-first-use (`get-reader-proxy`, `reliable.lisp:151-152`) and read. **There is
     no `remhash` against it anywhere in the tree** — not on unmatch, not on lease expiry, not on
     participant delete. `%writer-unmatched` (`entities.lisp:3218`) only decrements the
     PUBLICATION_MATCHED status counters; it never reaches the engine. So the proxy table grows without
     bound across reconnects, forever.
   - **And that is what wedges the writer.** `writer-purge-acked` (`reliable.lisp:465`) drops changes
     below **the minimum acked-base over the matched readers' proxies**, and its own docstring states the
     trap: *"a proxy is created with acked-base 1 if absent, so a matched reader that has not yet ACKed
     holds the watermark at 1 and NOTHING is purged until it acks."* A ghost reader — still in the match
     set until the 100 s lease sweep — **pins that watermark at 1, so a KEEP_ALL HistoryCache purges
     nothing at all** while the writer keeps adding to it.

   ⇒ **Graceful departure alone does NOT fix the stall.** It shortens the ghost's lifetime from 100 s to
   ~0 for a *cleanly-exited* peer, but a peer that CRASHES sends no goodbye, and the proxy still leaks
   forever. The WP must therefore ALSO give the RTPS writer a real unmatch: drop the ReaderProxy (and
   re-evaluate the purge watermark) when a reader is unmatched or its participant is pruned — by either
   trigger. Fix (3) is the correctness fix; fixes (1) and (2) are what make it *prompt*.

4. **Do NOT rely on this for correctness.** The lease sweep stays. A crashed (not deleted) peer sends no
   goodbye, and the goodbye is best-effort besides.

5. **Out of scope here, tracked:** `resource-max-samples` defaulting to LENGTH_UNLIMITED means a
   RELIABLE KEEP_ALL writer has no memory backstop at all when a reader stops ACKing for *any* reason.
   That is spec-permitted but is a resource-exhaustion surface. Separate decision.

## Consequences

- **New wire surface** (the outbound dispose) ⇒ per the standing rule this needs a live interop leg
  against **BOTH** RTI Connext 7.3.1 **and** Fast DDS 3.6.1, in **both** directions:
  - *inbound:* Connext/Fast DDS deletes a participant → we prune promptly (assert the ghost is gone well
    inside the 100 s lease, and that a reliable KEEP_ALL writer keeps serving).
  - *outbound:* we delete a participant → the peer prunes us promptly (`rtiddsspy` / a Connext subscriber).
  - Remember Fast DDS is **lenient** — a green Fast DDS run must never substitute for the Connext leg.
- A regression test must reproduce the original defect: **N successive participants against one RELIABLE
  KEEP_ALL responder**, asserting client #3+ still echo. The bug survived every existing test because the
  suite never re-matched a third participant against a live writer.
- Task **#15 ("4 KB large-payload stall") is closed as a misdiagnosis** and superseded by this ADR.

## ★ THE PROXIMATE MECHANISM — NOW PROVEN (instrumented 2026-07-14). It is a PHANTOM GAP.

Instrumented the responder (rx / echo-rc / hc-change-count / proxy-count / matched) across the 3-client
repro. At the moment client #3 joins:

```
[resp t=20s] rx=1801 echo-ok=1801 echo-FAIL=0 | hc-changes=901 proxies=3 matched=6
[resp t=22s] rx=1809 echo-ok=1809 echo-FAIL=0 | hc-changes=909 proxies=3 matched=6
[resp t=24s] rx=1809 echo-ok=1809 echo-FAIL=0 | hc-changes=909 proxies=3 matched=6   <- frozen
```

Client #3 completes **8 round-trips**, then everything freezes. Decisive facts:

- **`echo-FAIL=0`: `write-sample` NEVER returns `:timeout`.** The writer is NOT blocked and NOT
  backpressured. Every earlier hypothesis about a wedged/blocking writer is **refuted**.
- The responder **receives and successfully echoes** #3's first 8 pings. The break is that the echoes
  stop *reaching* #3 — i.e. it is the **READER** side of client #3 that stalls, right after its first
  HEARTBEAT.

**The chain.** Ghost readers (#1, #2) are still in the matched set ⇒ `writer-purge-acked` — which purges
below `min(acked-base)` over **`%matched-reader-keys`** (`dataplane.lisp:3329`), i.e. the DISC match set —
purges NOTHING ⇒ the KEEP_ALL cache retains 901 changes ⇒ `writer-heartbeat` advertises **`firstSN=1`**
(`hc-min-seq`, `reliable.lisp:259`) ⇒ client #3's fresh VOLATILE reader believes it is missing SNs 1..901
and NACKs for history it must never receive. The echo (SN 910) never gets through.

**The false premise, written down in the code.** `%reader-durability-init` (`dataplane.lisp:1943-44`)
gates the pre-match-history skip on the WRITER'S DURABILITY:

> "…AND, crucially, VOLATILE-reader<->VOLATILE-writer — SKIP-HISTORY is NIL … (**a VOLATILE writer retains
> no history to wrongly pull**; gating the skip on a RETAINING writer is what keeps reliable drop-recovery
> intact)."

**A VOLATILE writer with KEEP_ALL retains everything not yet ACKed by every matched reader.** With a ghost
that never ACKs and is never unmatched, it retains forever. The premise is false, and DDS 1.4 §2.2.3.4 is
unconditional: a VOLATILE reader receives samples published AFTER it matched — *regardless of the writer's
DURABILITY*. The skip is gated on the wrong thing.

**⇒ THE WRITER-UNMATCH FIX ALONE DOES NOT FIX THIS.** The purge is gated on the DISC match set, not on the
writer's proxy table, so dropping the ReaderProxy does not advance the purge (it fixes the unbounded proxy
leak, which is a real and separate defect). And a CRASHED peer sends no goodbye, so even with §1+§2 the
ghost — and the phantom gap — persist for the full 100 s lease. The reader-side gate must be fixed.

### The fix, and the trap in it

The writer knows the match-time `lastSN`; the reader does not. So the boundary must be communicated, and
RTPS has exactly the mechanism: **GAP** — *"Gap: Describes the information that is no longer relevant to
Readers"* (RTPS 2.5 §8.3.7.4). `%writer-durability-init` (`dataplane.lisp:1918`) already sets the non-TL
reader's `unsent-base = lastSN+1` — it just never TELLS the reader that `[firstSN, lastSN]` is irrelevant.
A single GAP with `gapStart=first, gapList.base=last+1, numbits=0` declares an arbitrarily long contiguous
range irrelevant (`write-gap`, `message.lisp:436`, takes gapStart and base separately; `reader-on-gap`,
`reliable.lisp:712`, already honours `[gapStart, base-1]`).

**⚠️ THE TRAP — do not just send the GAP.** `reader-on-gap` counts every never-seen → `:gap` transition as
**SAMPLE_LOST** (DDS 1.4 §2.2.4.1). A match-time GAP over [1..901] would fire **901 bogus SAMPLE_LOST** on
the new reader — those samples were never *intended* for it, so that is a FALSE status, not a loss. The
existing discriminator is the lower-clamp to `writer-proxy-first-sn`, whose docstring already says it
"keeps a durability-skipped pre-match range (which is intentionally not-wanted, not lost) out of the
tally". So the GAP must be paired with advancing the reader's `first-sn` past the skipped range — i.e.
reuse the EXISTING skip-history latch (`init-writer-proxy-durability` / `writer-proxy-skip-history`), not
bypass it.

**Do NOT "fix" this by making a VOLATILE reader blanket-skip to `lastSN+1` on its first HEARTBEAT.** That
is the tempting one-liner and it REGRESSES reliable drop-recovery: a LIVE sample pushed after match but
dropped in transit before the first HEARTBEAT would be silently skipped instead of NACKed. That is
precisely the regression the (otherwise wrong) durability gate was protecting. The boundary must be the
writer's MATCH-TIME lastSN, which only the writer knows — hence the GAP.

## Implementation order (revised by the instrumented evidence)

1. **The reader-side pre-match-history gate** (`%reader-durability-init` + a match-time GAP from
   `%writer-durability-init`) — **THE STALL FIX.** Robust even against a CRASHED peer inside the lease
   window, because it never depends on the ghost being removed. Mind the SAMPLE_LOST trap above.
2. **Honour an inbound participant dispose** (no new wire surface; our parser already decodes it) — makes
   ghost removal prompt, lets the KEEP_ALL history purge, bounds memory.
3. **Send our own goodbye** — new wire surface ⇒ interop vs BOTH vendors.
4. **Writer unmatch / drop the ReaderProxy** — fixes the unbounded proxy leak across reconnects. Necessary,
   but on its own it fixes NEITHER the stall NOR the purge (see above).

Regression test (write it FIRST, it must go red): N successive participants against ONE
RELIABLE + KEEP_ALL responder; assert client #3+ still echo. The existing suite never re-matched a third
participant against a live writer, which is why this survived 563 green tests.

## ✅ OUTCOME — CLOSED. What actually landed, and what it cost to get there.

The stall is fixed. **`#1 ok #2 ok #3 FAIL #4 FAIL` → `4/4`**, stable across repeated runs.

| # | item | commit | effect |
|---|---|---|---|
| 1 | **Honour an inbound participant dispose** — prune AT ONCE, reusing the lease sweep's own prune (`%prune-participant-locked`) so the two paths cannot drift. Forged-eviction guard: a dispose whose keyhash prefix ≠ the datagram's SOURCE prefix is DROPPED, and we prune by the source prefix, never the wire-named one. | `7c7ea7f` | **THE FIX** |
| 2 | **Send our own goodbye** in `stop-node`, byte-shape-identical to Connext's captured `delete_participant`. | `7c7ea7f` | **THE FIX** |
| 3 | **Writer unmatch** — drop the departed reader's ReaderProxy on every local user writer, from the ONE choke point (`%fire-unmatch`) every departure trigger funnels through. | this | closes an **unbounded leak** |
| 4 | **GAP readerId** — a GAP addressed to reader A was applied to reader B (`(declare (ignore rid))`). | `5a737ee` | independent defect |

**Validated:** live repro 4/4 (3 runs) · **LIVE CONNEXT BOTH WAYS** (outbound: our goodbye matches Connext's
wire shape; inbound: a real Connext `delete_participant` prunes us at once, peers 1→0, not after 100 s) ·
interop Connext→us + Fast DDS→us + tshark · 565/565 Clasp AND SBCL · every new test **falsified** (each goes
red on the defect it guards) · all gates.

### ★ THE LESSON: THIS ADR'S ORIGINAL ORDER WAS RIGHT, AND REORDERING IT COST TWO REVERTED ATTEMPTS.

I moved the reader-side gate to the front because it looked like "the correctness fix". It is not
implementable: see ATTEMPT 2 below — discovery is asymmetric, so a writer can already have produced samples
FOR a reader before it has processed that reader's match, and a match-time irrelevance GAP therefore cannot
distinguish a late-matched LIVE sample from a genuinely pre-match one. **Two attempts, both reverted.**

The fix that worked is the one this ADR specified first, and it is also the *simpler* one: **stop retaining
what nobody wants.** It has no race precisely because it never has to make that distinction. When a design
needs to tell two things apart and the information to do so does not exist at that point in the protocol,
that is not an implementation problem — it is the design telling you it is wrong.

## ★★ ATTEMPT 2 — THE MATCH-TIME GAP DESIGN IS DEAD. Do not try it again.

Attempt 2 found Defect 2, and it is **fatal to the design**, not a coding slip. Traced on client #1 against
a **fresh** responder (empty cache, so no GAP should exist at all):

```
<GAP> gapStart=1 base=2 nb=0 armed=T first-sn=1 -> PREMATCH-BRANCH=T
PINGER-FAILED: no echo within 5 s
```

**The GAP declared the reader's OWN first echo irrelevant.** The race:

1. The pinger sees `matched-count = 2` (its OWN endpoints matched) and writes ping 1.
2. The responder receives it and echoes it — that echo is SN 1 in the writer's cache.
3. **Only then** does the responder's writer process the SEDP match for the pinger's reader and run
   `%writer-durability-init`, which now sees a NON-empty history and GAPs `[1,1]`.

Discovery is asymmetric: **the writer can already have produced samples FOR a reader before it has
processed that reader's match.** Those samples are LIVE, not pre-match, and the writer cannot tell them
apart from genuinely pre-match ones.

**And the two are the SAME MECHANISM.** `init-reader-proxy-base` sets `unsent-base = lastSN+1`, so the
writer never PUSHES SN 1 either. The baseline works **only because the reader NACKs for it and the writer
retransmits**. The "pre-match history" a late-joining reader phantom-NACKs and the "late-matched live
sample" it legitimately NACKs arrive by the identical path. **You cannot GAP the one without killing the
other.** Any writer-side irrelevance declaration at match time has this hole.

⇒ **The reader-side gate is NOT the fix, and the implementation order in ATTEMPT 1 was wrong.** Revert to
this ADR's ORIGINAL order: bound the retained history at the source by removing ghosts promptly (honour +
send the participant dispose, and give the writer a real unmatch). Then `hc-min-seq` advances, the
advertised `firstSN` is recent, the new reader's NACK range is small or empty, and the phantom gap cannot
form. That fix has no race because it never has to distinguish live from pre-match — it simply stops
retaining what nobody wants.

**KEPT from attempt 2** (landed separately, proven neutral on the repro and green on both impls): the
`%on-user-gap` **readerId** fix — see below.

## ATTEMPT 1 — IMPLEMENTED, THEN REVERTED. Read this before attempting it again.

The design above (arm the proxy at match + one contiguous match-time GAP) was implemented and **reverted
un-landed**: it did not pass, and it introduced a REGRESSION. The mechanism is right; the implementation
has at least one more defect. Patch preserved out-of-tree; do not resurrect it without fixing the below.

**What DID work** (traced live): the GAP is emitted, delivered, and consumed —
`GAP gapStart=41 base=81 numbits=0 pre-armed=T` — and `stale=0` throughout: with the fix, a newly matched
reader received **no pre-match data at all**. The phantom-NACK is genuinely closed.

**Defect 1 (found and fixed in-attempt, but RECORD IT — it is a trap).** The armed proxy **HIJACKED the
first REPAIR GAP** it saw. An ACKNACK repair GAP (`%send-user-gap`) carries its SNs in the BITMAP and sets
`gapStart = base` — an EMPTY contiguous range. The pre-match branch keyed only on `base > first-sn`, so it
fired on a repair GAP, advanced `first-sn` past legitimately-missing samples and DISCARDED the bitmap —
silently losing data on a reader with no pre-match history at all. The guard is `gap-start < base` (a real
contiguous range). **Any future pre-match/irrelevance handling MUST distinguish the two GAP shapes.**

**Defect 2 (NOT found — this is where to start).** Even with that guard, the LIVE cross-process repro
**broke client #1**, which cannot have a phantom gap (the writer's cache is empty at its match, so no GAP
is even sent to it — `(>= last first)` is false). Something in the change perturbs a reader that receives
no match-time GAP at all. Two concrete suspects, neither ruled out:
  - **The GAP fan-out.** `%writer-durability-init` falls back to `%match-destinations-prefixed` when the new
    reader's unicast destination does not resolve, which sends the GAP — addressed to the NEW reader's
    EntityId — to **every matched reader's destination**. If the receive path does not discriminate GAP by
    readerId, an OLDER reader will consume a GAP meant for someone else and skip its own live samples.
  - **`numbits = 0`.** `%send-user-gap-range` writes a SequenceNumberSet with an EMPTY bitmap. Confirm
    against RTPS 2.5 §9.4.2.6 that numBits=0 is legal on the wire and that our own reader/parser round-trips
    it; a malformed submessage here would corrupt the rest of the datagram's dispatch.

**And the in-process test was NOT a valid oracle.** `dcps-keepall-reconnect` (spin-driven, in-process) loses
samples for unrelated reasons — **client 0 itself got 28/40**, and runs swung 40/41/28 → 28/40/22. It cannot
certify this fix. **Use the cross-process live repro** (`scratchpad/responder.lisp` + `rematch.lisp`), which
isolates the defect deterministically (#1 ok, #2 ok, #3 FAIL, #4 FAIL), or rebuild the in-process test on
AUTONOMOUS participants + listeners (the `dds.bench:mem-per-sample` pattern), never on `spin`.

## Method note

The proximate mechanism above was NOT guessed — it was instrumented, and the instrumentation **refuted**
the hypothesis this ADR was originally written around (a blocked/backpressured writer: `echo-FAIL=0`,
`write-sample` never times out). That is the third time this session a plausible mechanism died on contact
with measurement (`sb-sprof`'s byte attribution; the "4 KB payload stall" that does not exist). **Instrument
before fixing. Every time.**
