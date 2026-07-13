# ADR 0063 — Graceful participant departure: announce it, and honour it

- **Status:** Proposed (design + captured wire evidence). Implementation is a follow-on WP.
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

## What is NOT yet proven (do not skip this)

The **causal chain is established** — ghost reader ⇒ purge watermark pinned at 1 ⇒ a KEEP_ALL history that
never purges — and the mitigation confirms it (KEEP_LAST responder: all clients fine). But the **proximate**
failure mechanism at client #3 is **not** proven: whether the write path stalls on the unbounded history,
on the push/heartbeat loop against two ghost readers, or on the late-joiner replay to the new reader.
**Instrument it before fixing it.** This repo has been burned twice this session by a plausible mechanism
that measurement refuted (`sb-sprof`'s byte attribution; the "4 KB payload" stall itself). Reproduce with
the harness, confirm the mechanism, *then* write the fix.
