# ADR 0097 — A writer's reliability control traffic takes the same transport as the DATA it refers to

- **Status:** **Accepted — UNBLOCKED and shipped.** It was blocked (§6) by a regression that has since been
  root-caused to a defect **this ADR did not introduce**: SHMEM segment names ignored the DDS domain
  (**ADR 0099**). This change was simply the first traffic to depend on SHMEM honouring the domain boundary.
  With ADR 0099 in place the previously-failing test passes **5/5 with this change applied and the test
  unmodified**. Owner directive 2026-07-30: *"'put control traffic on the same lane as the DATA' — that is
  non-negotiable."*
- **Date:** 2026-07-29 (unblocked 2026-07-30)
- **Requirements at stake:** **FR-XPORT-2** (SHMEM intra-host transport, same-host auto-select + UDP
  fallback); **FR-RTPS-3/4** (the reliable writer/reader engine); NFR-DET.
- **Relates to:** ADR 0096 §5 (which found this and deliberately did not ship it — see §5 there),
  ADR 0013 (the Clasp/macOS SHMEM gap), ADR 0042/0047 (why the repair stays a full payload).
- **Supersedes:** ADR 0096 §5's "OPEN" status. Nothing else changes in ADR 0096.

---

## 1. The defect

`%send-msg-buf` hard-passed `NIL` for `shmem-dest`. So when a writer's DATA to a same-host peer went over
**SHARED MEMORY** (`%send-changes-packed` has carried `shmem-dest` since FR-XPORT-2 landed), the
reliability control traffic *about that DATA* went over **UDP**:

- the periodic HEARTBEAT (`%push-heartbeat`),
- the late-joiner prompt HEARTBEAT (`%writer-durability-init`),
- the ACKNACK repair and its GAP (`%on-user-acknack`).

`%shmem-dest` resolves for those destinations — it was simply never asked. The coalesced push path had the
argument; these senders never had the parameter.

**The hazard is ordering.** The SHMEM ring and the UDP socket are drained by **two different receiver
threads** (`start-node` spawns unicast-UDP, multicast-UDP and SHMEM receivers). A HEARTBEAT on UDP
announces `lastSN` to a reader whose ring still holds those samples unread, so the reader NACKs samples it
already has in hand and the writer retransmits them. The reliable protocol is being told a lie about what
the reader could have seen.

## 2. The measurement

`bench/report/2026-07-29-adr-0097-control-lane.md`. One writer, one reliable reader, same host, SHMEM on;
publish **400** samples as a burst, then drive 400 heartbeats; count every datagram the writer emits from
every thread. Floor = 2N.

| tree | writer datagrams | floor | excess |
|---|---|---|---|
| before | **2249** | 800 | **+1449 (+181 %)** |
| after | **800** | 800 | **0** |

**2.81× the necessary traffic on the user-data path to a same-host SHMEM peer, entirely invisible**: all
400 samples arrived in both arms and no counter moved, because a retransmit of a sample the reader is
about to read is deduped on arrival. Delivery was always correct; the bandwidth was not.

⚠️ **The first two runs of that harness reported excess 0 in BOTH arms** — a clean-looking negative that
would have justified dropping this change. The counter was blind: `*datagram-sink*` was `let`-bound and
**the repair runs on the writer's receiver thread**, which cannot see a thread-local dynamic binding, so it
counted only the main thread's sends — exactly the floor, in every configuration. A measurement that cannot
see the thing it measures reports a clean result, not an error.

## 3. The decision

**Reliability control traffic to a destination takes the same transport as that destination's DATA.**

A NIL-safe `%prefix-shmem-dest` resolves the verdict (a discovery-less PEERS-fallback destination carries
no remote participant prefix, and `%shmem-dest` takes a 12-octet prefix, never NIL); `shmem-dest` is
threaded through `%send-msg-buf` → `%send-raw-buf` (which already took it), `%send-user-heartbeat` and
`%send-user-gap`; the three call sites above pass it.

Three constraints the implementation respects:

1. **Builtin/discovery/bootstrap senders keep NIL.** Their messages describe no user DATA and their
   destination may not be a SHMEM peer at all. Every one of those call sites is byte-identical.
2. **The repair resolves the lane ONLY when there is something to repair.** The steady-state ACKNACK acks
   everything and repairs nothing, and that arm runs once per sample; `%shmem-dest` takes the node lock, so
   an unconditional lookup there would add a lock hold per sample for nothing.
3. **The repair stays a FULL payload** (`zc-readers` 0). Making it a Zero-Copy reference would consume a
   second pool slot per repair and re-open the refcount question ADR 0042 closed; the transport was the
   defect, not the representation.

The UDP fallback is unchanged: a full SHMEM lane still falls back to UDP (`%send-raw-buf`), so this can
delay a datagram but never drop one.

## 4. The gate

`run-shmem-control-lane-test` — deterministic, single-process, two bare `disc-node`s, no DCPS and no
`spin`, so **nothing else emits inside a measurement window**. The lane is directly observable:
`%send-raw-buf` bumps `disc-node-shmem-sends` only on a *successful SHMEM send*, so a UDP-routed control
message contributes nothing to it.

Both windows run over a **live gap** (SN 2 dropped on every send, including the resend), and that is
load-bearing twice:

- the change stays **unacked**, so the writer's HistoryCache keeps it. A fully-acked HistoryCache is
  **purged** (RTPS 2.5 §8.4.1) and `%push-heartbeat` is then a silent no-op — which is exactly what the
  first cut of this test measured, and why it read `sent 0` against a correct implementation;
- while the drop is armed a repair plans **no submessage at all**, so the retransmit provably cannot
  contaminate the HEARTBEAT window.

| arm | assertion | with the call sites reverted |
|---|---|---|
| (0) preconditions | the peer resolves as same-host SHMEM; the DATA path already used the lane; the writer is announcing an unacked change | green (they use the resolver, not the call sites) |
| (1) the periodic HEARTBEAT | one `%push-heartbeat` adds ≥ 1 SHMEM datagram | **RED** — `CTL-LANE-HEARTBEAT … (sent 0)` |
| (2) the ACKNACK repair | its window costs **strictly more** SHMEM datagrams than a bare HEARTBEAT window | RED |

Arm (2) compares against arm (1)'s measured cost rather than a hard number, so it stays correct whatever
the destination count is. **A fix that moved only the HEARTBEAT fails (2); one that moved only the repair
fails (1).** Falsified on Linux x86_64 with the call sites reverted and the resolver left in place.

The **late-joiner prompt HEARTBEAT** takes the identical two-line change and is **not** separately gated —
stated here rather than implied, because an ungated call site is an ungated call site.

## 6. ✅ RESOLVED — why this once broke a DDS-Security test, and what the real defect was

**Root-caused 2026-07-30 to ADR 0099, a defect this change did not introduce.** SHMEM receive-segment names
were derived from the GUID prefix **without the DDS domain**, and a POSIX shm name is a process-global OS
object. The failing test runs two participants per side on **two different domains** whose identity GUIDs
differ only in the EntityId octet — so they shared a GuidPrefix, and therefore shared one segment. UDP had
always hidden this, because a domain's port range is computed from `domain_id` (RTPS 2.5 §9.6.1.1): **the
port was the isolation**, and SHMEM inherited no equivalent. Moving reliability control traffic onto the
SHMEM lane made this ADR the first traffic to depend on that boundary, so it surfaced here first.

With ADR 0099 in place: **5/5 PASS with this change applied and the test unmodified**, and the full suite is
625/625. The historical record of the block follows.

---

`run-access-control-allow-deny-test` failed **5/5** on macOS/SBCL with this change and passed **3/3**
without it. `ACAD-SQ-RECEIVED` — *"ALLOW: sq-b did not receive a Square sample from sq-a"*: the two secured
participants reach `:keyed`, the Square endpoints MATCH (`:acad-sq-matched` passes), and then the published
sample never arrives.

**Bisected to the call site.** Each site enabled alone:

| live site | result |
|---|---|
| `%push-heartbeat` only | **FAIL** |
| `%writer-durability-init` only | pass (it never fires here — the HistoryCache is empty at match time) |
| `%on-user-acknack` repair only | **FAIL** |

So it is not one site's bug: **routing a user reliability-control submessage to a `:keyed` destination over
SHMEM breaks delivery for that pairing.** A lane probe shows the HEARTBEAT going out as a *plain* 52-octet
datagram (`shmem=T keyed-prefix=T`, no SRTPS wrap — this governance sets `rtps_protection` NONE, and receive
enforcement correspondingly reads `enforce=NIL`) and being received. So the wrap is not the mechanism, and
the message is not being dropped on arrival. Root cause **not yet identified**.

**Why no other Linux run caught it:** the DDS-Security suite requires OpenSSL ≥ 3.5 and Ubuntu 24.04 ships
3.0.x, so every one of those tests SKIPPED on Linux — `625 passed, 0 FAILED` there was not covering them.
That gap is now closed (OpenSSL 3.5 is built into the repro image), and the security-inclusive Linux
baseline is **620 passed, 4 FAILED** — four *pre-existing* zero-alloc failures, all ~16.38 B/sample, all
x86_64-only. Those are separate from this ADR and are their own work.

**Do not land §3 until §6 is explained.** The traffic win is real and worth having; a DDS-Security
regression is a binary gate.

## 5. Consequences

- A same-host reliable pairing stops paying ~2.8× its necessary datagrams, and stops burning writer CPU
  re-serialising samples the reader already holds.
- The reliable state machine is no longer told a lie about what the reader could have seen, so `NACK` now
  means "genuinely missing" on this path. That makes any *future* NACK-rate signal meaningful.
- One more rule for the next transport that lands beside UDP and SHMEM: **traffic that refers to other
  traffic must share its lane, or the reliability protocol is racing itself.**
- Not covered: cross-host destinations (UDP for both, nothing to split) and the builtin discovery
  endpoints (their own SNs, their own lane, no user DATA to overtake).
