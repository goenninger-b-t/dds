# ADR 0099 — A shared-memory segment belongs to a **domain**, not just to a participant

- **Status:** **Proposed**
- **Date:** 2026-07-30
- **Requirements at stake:** **FR-XPORT-2** (SHMEM transport), **NFR-SEC-POSTURE** (a domain is an isolation
  boundary; crossing it is an isolation failure, not a performance quirk), **NFR-DET**.
- **Relates to:** ADR 0014 (the Zero-Copy pool, whose segment name derives from the same function), ADR 0097
  (blocked by this defect — see §5), DDS 1.4 §2.2.1.2.2 (the domain as an isolation boundary),
  RTPS 2.5 §9.4.4 (GuidPrefix).
- **Owner directive, 2026-07-30:** *"SHMEM resolution MUST also be domain-dependent."*

---

## 1. The defect

`%seg-name` derived a participant's shared-memory receive-segment name from its **GUID prefix alone**:

```lisp
(format nil "/dds~(~10,'0x~)" (%guid-token guid))   ; before
```

A POSIX shm name is a **process-global, host-global OS object**. A DDS domain is an **isolation boundary**
(DDS 1.4 §2.2.1.2.2). Deriving the name without the domain means two participants that share a GuidPrefix in
**different domains resolve to the same segment** — they attach to each other's rings and exchange datagrams
across a boundary the specification says must isolate them.

Nothing else was keeping them apart. The reason this had never been seen is narrow and worth stating
precisely: **UDP is domain-scoped by construction** — each domain computes its own port range from
`domain_id` (RTPS 2.5 §9.6.1.1), so two domains cannot reach each other over UDP no matter what their GUIDs
are. The port *was* the isolation. SHMEM has no port and inherited no equivalent.

## 2. The fix

The domain becomes part of the segment identity:

```lisp
(format nil "/dds~(~10,'0x~)d~(~x~)" (%guid-token guid) domain)   ; after
```

`seg-name-for-guid` takes the domain, and every derivation site passes it: the receive segment
(`make-shmem-transport`), the sender's resolve (`%resolve-shmem-dest`), and the Zero-Copy pool segment
(`%zc-pool-name`, ADR 0014). Sender and receiver compute the same name from the same two inputs, and a
sample only ever reaches a reader in the writer's own domain, so the two sides always agree.

Name budget is unchanged in practice: `/dds` + 10 hex + `d` + up to 4 hex = 19 characters, plus the ZC pool's
`z` suffix = 20, still under the macOS ~31-character shm-name cap.

## 3. What this does NOT fix — stated so it is not over-credited

`%guid-token` folds **only GUID-prefix octets 0..7** into the token. Two participants in the *same* domain
whose prefixes differ only in octets 8..11 still collide on one segment name. That is a separate,
pre-existing narrowing of a 12-octet identifier to 8 octets; it is documented at `seg-name-for-guid` and left
open, because bundling it would have made the measurement below unattributable.

## 4. How it was found, and the measurement

It was found while root-causing ADR 0097, and the route to it is the reusable part.

`run-access-control-allow-deny-test` failed **deterministically** with ADR 0097 applied and passed without
it. A single-variable A/B (one runtime switch, one binary, the same probe in both arms) confirmed the
control-lane routing was the trigger. Three hypotheses were then killed by measurement rather than argument:
the node lock is non-recursive but `%push-heartbeat` is not called under it; raising the RX pool capacity 8 →
256 changed nothing; and the 354-vs-2 heartbeat ratio turned out to be a *consequence* (an unacked
HistoryCache never purges, so the periodic HEARTBEAT keeps firing), not a cause.

The finding came from printing the participants' **full 12-octet prefixes**:

```
sq-a = D1437B8E7A950708090A0B0C     ci-a = D1437B8E7A950708090A0B0C   <- identical
sq-b = B9A1E95FB45E0708090A0B0C     ci-b = B9A1E95FB45E0708090A0B0C   <- identical
```

Two participants per side, on **two different domains**, sharing one GuidPrefix — and therefore, before this
ADR, one shared-memory segment.

**Verified**, ADR 0097 enabled, against the **unmodified** test: **5/5 PASS** (it was 5/5 FAIL, and 3/3 PASS
with ADR 0097 reverted). Full suites and gates in §6.

⚠️ **A tagging mistake worth recording, because it produced a wrong published conclusion.** The first probe
tagged participants by prefix octets 2..3, then 8..11 — *both* uniform across all four participants in this
test. On that basis a lane-divergence diagnosis was reported and had to be retracted. **A probe that cannot
distinguish the entities it labels does not report "unknown", it reports a confident wrong answer.** Print
the whole identifier, or verify the short form is injective, before trusting a single line of output.

## 5. Consequence for ADR 0097

ADR 0097 was **correct and is unblocked by this ADR.** It did not introduce a defect; it moved reliability
control traffic onto the SHMEM lane and thereby became the first traffic to depend on SHMEM honouring the
domain boundary. Its measured benefit (2249 → 800 writer datagrams for 400 samples, **+181 % traffic saved**)
stands. Landing it is a separate slice on top of this one, with its own re-verification.

## 6. Consequences

- **Domain isolation is now real on SHMEM**, not merely inherited from UDP's port arithmetic. Two domains in
  one process, or on one host, can no longer share a segment.
- **This is an ABI break for the segment name.** Two peers must agree on the name to meet at all; a
  domain-scoped sender and an unscoped receiver simply never find each other and fall back to UDP (correct
  delivery, lost optimisation, no corruption). Mixed-version same-host peers are the only affected case.
- The Zero-Copy pool segment (ADR 0014) inherits the scoping through `%zc-pool-name`, so a ZC slot cannot be
  read across a domain boundary either.
- **The general lesson: a transport that names a global OS object must put every isolation dimension in the
  name.** The domain was the missing one here; the truncation in §3 is the same class of bug one level down.
