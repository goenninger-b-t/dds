# ADR 0060 — A disabled endpoint does not communicate; a suppressed sample is SAMPLE_LOST

Status: Accepted
Date: 2026-07-11
Work package: post-WP tracked-residual close-out (owner-directed item 8)
Relates to: ADR 0052 §3 (the "deferred engine registration" deferral — **its safety argument is retracted here**); ADR 0056 (the S7 autonomous announcer, which invalidated that argument); ADR 0054 (SAMPLE_LOST v1, which left `reader-suppress-sn` uncounted); ADR 0031 lim.1 (the suppression mechanism itself)

## 1. A disabled endpoint was announced and matched — a spec violation

DDS 1.4 §2.2.2.1.1.7 is unambiguous: **a disabled entity does not communicate.** A `DataWriter`/`DataReader`
created under a factory whose `ENTITY_FACTORY.autoenable_created_entities` is FALSE is created *disabled*
and must stay off the wire until `enable()`.

Ours did not. Measured, before this ADR — two autonomous participants, each holding one **disabled**
endpoint, with no `spin` anywhere:

```
[probe] writer enabled? NIL ; reader enabled? NIL
[probe] after 5s: p1 matched=1  p2 matched=1        <-- disabled endpoints, SEDP-announced and MATCHED
```

**Why it was there, and why the argument no longer holds.** ADR 0052 §3 kept *eager* engine registration
(an endpoint registers with the engine at create, and the disabled state is enforced at the DCPS data ops)
and deferred true deferred-registration on this reasoning:

> *"Since discovery is `spin`-driven, a disabled endpoint that is never spun never announces."*

That argument was already thin — an application that calls `spin` for its *other* endpoints announces the
disabled one too — and **WP-DCPS-API-COMPLETION S7 killed it outright**: an autonomous participant now spins
*itself*, on a background thread, whether or not the application ever asks. The deferral's safety property
was a property of the *application's* behaviour, not of the middleware, and a later feature took that
behaviour away. That is the general lesson here: **a deferral justified by "nothing currently exercises this
path" is only as durable as the reason nothing exercises it.** S7 made the path unconditional.

## 2. Decision — withhold, don't strand

Registration stays eager (ADR 0052's reasoning for that is intact: the engine EntityId is assigned at create
and DCPS threads it everywhere). What changes is **visibility**:

- The disc node keeps a set of **registered-but-not-yet-enabled** endpoint EntityIds
  (`disc-node-unenabled-endpoints`).
- `announce-endpoints` **does not SEDP-announce** them (plain *and* secure SEDP — the filter runs before the
  discovery-protection split, so it covers both).
- `%match-remote-endpoint` **does not match** them, so a disabled endpoint cannot be matched by an inbound
  remote either — otherwise a peer's SEDP would still bind to it and fire statuses on a disabled entity.
- `enable()` calls `enable-local-endpoint`, which **releases** the endpoint onto the wire: the next announce
  advertises it and it matches normally.

The default (autoenable on) path leaves the table **empty**, so the announce and match sets are the
add-order lists exactly as before — byte-identical.

**Withhold, not strand.** The regression test asserts both halves: while disabled, neither side matches; after
`enable()`, the *same* endpoints match and data flows. A fix that silenced an endpoint permanently would be a
worse bug than the one it fixed.

## 3. A suppressed sample is a LOST sample (ADR 0054's v1 gap)

ADR 0031 lim.1 lets the reader **suppress** an SN that has failed to decode with its KM present
*`*decode-fail-suppress-threshold*`* times: `reader-suppress-sn` marks it GAP-irrelevant so the reliable
writer stops retransmitting a sample that can never decode. That is correct — but it means the sample is
**permanently gone**: the reader will never NACK it again, so no retransmit can recover it.

ADR 0054 shipped SAMPLE_LOST counting the irrecoverable-GAP path and explicitly left this one out
("reader-suppress-sn (secure) not counted as SAMPLE_LOST v1"). The consequence is that a real, permanent data
loss reached the application **with no status at all** — the sample simply never arrived, and
`SAMPLE_LOST.total_count` stayed 0. DDS 1.4 §2.2.4.1 defines SAMPLE_LOST as exactly this: a sample was lost
and never received.

**Suppression now raises SAMPLE_LOST** on the DataReader(s) routed from that writer, using the same hook and
the same route fan-out as the GAP path, fired **outside** the node lock (the hook re-enters DCPS, which takes
its own locks — the established `%fire-unmatch` discipline).

## 4. Closed without code (honest, not lazy)

- **Node-scoped pools freed at `stop-node`, not per-endpoint delete** (ADR 0052 §3). This is **by design**,
  not a defect: the ZC pool, the secured payload/decode pools and the per-node arenas are *shared* across a
  participant's N endpoints (ADR 0048), so deleting one of N must not tear down a pool a sibling is still
  using. The consequence — an early per-endpoint delete does not early-reclaim node-scoped pools — is bounded
  by the participant's lifetime and is not a leak and not a UAF. No change. Revisit only if early reclaim is
  ever actually needed.
- **The file backend's `topics.map`-loss cross-restart non-reclaim.** Benign (bounded, non-corrupting), and
  SQLite is immune. Left documented; no change.

## 5. Verification

- `dcps-disabled-endpoint-silent` (new; RED before): two autonomous participants each holding a *disabled*
  endpoint do **not** match after 2.5 s of announcing (RED: `matched=1` both sides); `enable()` then releases
  them — they match and a sample flows end-to-end.
- `decode-fail-suppress` (extended): the arm that trips suppression now also asserts `SAMPLE_LOST` fires on
  the matched DataReader (RED before: the loss was silent).
- 562/562 on **both** Clasp and SBCL; `gate-hotpath` + `gate-types` green. No wire-format change; no hot-path
  change (the announce/match filters are control-plane, and the SAMPLE_LOST fire only runs on a decode that
  has already failed to the suppression threshold).
