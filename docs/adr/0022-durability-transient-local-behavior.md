# ADR 0022 — TRANSIENT_LOCAL durability + late-joiner: the as-built behavior

- **Status:** Accepted (M6/P5; WP-DURABILITY-TRANSIENT-LOCAL, 2026-06-18)
- **Relates to:** ADR 0021 (the durability/persistence SERVICE scope/roadmap — the in-scope follow-on);
  `docs/superpowers/specs/2026-06-18-wp-durability-transient-local-design.md`; DDS 1.4 §2.2.3.4 (DURABILITY);
  RTPS 2.5 §8.4.1 (writer HistoryCache) / §8.4.2.2 (StatefulWriter push/HEARTBEAT/ACKNACK).
- **Scope:** TRANSIENT_LOCAL only, both sides. TRANSIENT + PERSISTENT require the durability service (ADR 0021).

## Context

DURABILITY QoS was already advertised (`PID_DURABILITY` 0x001d), parsed, and RxO-matched (offered-rank ≥
requested-rank) before this WP; only the late-joiner BEHAVIOR was missing. DDS 1.4 §2.2.3.4: a TRANSIENT_LOCAL
DataWriter RETAINS its samples and REPLAYS them to a late-joining TRANSIENT_LOCAL DataReader. The standard TL
retains for the writer's lifetime, bounded only by HISTORY + RESOURCE_LIMITS (per-writer TRANSIENT/PERSISTENT
lifetime is the durability service's job). The reliable HEARTBEAT/ACKNACK/retransmit machinery already existed
and does the actual replay; this WP supplied the durability-aware RETENTION + the durability-aware
SEQUENCE-NUMBER INITIALIZATION on both sides that makes the existing machinery replay (or not) correctly.

## Decision — the as-built behavior

### 1. Durability-aware retention (writer)

`writer-purge-acked` (`src/dds-rtps/reliable.lisp`) is gated on the writer's DURABILITY:

- **VOLATILE writer:** full-ACK purge as before (history bounded by the slowest matched reader's ACK) —
  byte-identical to pre-WP.
- **TRANSIENT_LOCAL writer:** does NOT full-ACK-purge (a no-op return of 0). Its HistoryCache is
  **HISTORY-bounded, not ACK-bounded**: KEEP_LAST per-instance eviction (`hc-add-change`) still drops the
  oldest beyond `depth`; KEEP_ALL is bounded by RESOURCE_LIMITS (the existing reject/block on full). Retained
  for the writer's lifetime (the conformant default).
- **TRANSIENT / PERSISTENT writer:** treated like TRANSIENT_LOCAL (retain) — never silently purging more than
  the conformant default; full TRANSIENT/PERSISTENT is the service (ADR 0021).

### 2. SEQUENCE-INIT both sides (the firstSN / lastSN+1 decision at match time)

Threaded through the DCPS on-match hook (`%on-disc-match`, `src/dds-dcps/entities.lisp`), where the peer's
advertised durability is in scope:

- **Writer side — `%writer-durability-init` (`src/dds-disc/dataplane.lisp`):** when BOTH the writer AND the
  matched reader are TRANSIENT_LOCAL, init that reader's ReaderProxy `UNSENT-BASE = firstSN` (`hc-min-seq`,
  from a single locked `writer-heartbeat` snapshot — no torn read vs a concurrent write/purge) so the existing
  push (`writer-unsent-list`) REPLAYS the whole retained history, then send a prompt HEARTBEAT `[firstSN,lastSN]`
  so the reader ACKNACKs and the existing retransmit path delivers it (to that reader's participant alone when
  its unicast destination resolves, else fanned out — each reader NACKs only its own gaps). Otherwise (a
  VOLATILE writer **or** a VOLATILE reader) init `UNSENT-BASE = lastSN+1` (future-only). Sets only the push
  watermark; the ACKNACK repair watermark (`acked-base`) is left at its default (independent, §8.4.2.2).
- **Reader side — `%reader-durability-init` (`src/dds-disc/dataplane.lisp`) + the one-shot skip-history latch:**
  marks the matched writer's WriterProxy SKIP-HISTORY (`init-writer-proxy-durability`). On the FIRST HEARTBEAT
  (`reader-on-heartbeat`, `src/dds-rtps/reliable.lisp`), a SKIP-HISTORY proxy advances `firstSN` to `lastSN+1`
  so the reader SKIPS the writer's advertised pre-match history (NACKing only future gaps). The skip is
  **LATCHED** (`durability-applied-p`) so it applies exactly ONCE — a later HEARTBEAT (the writer published new
  samples) never re-skips them. A TRANSIENT_LOCAL reader matched a retaining writer leaves SKIP-HISTORY NIL →
  NACKs the full advertised range → receives the retransmitted history.

### 3. Reuse of the reliable machinery

No new transport path. The replay rides the existing StatefulWriter push / HEARTBEAT / ACKNACK / retransmit
(RTPS 2.5 §8.4.2.2). This WP only changes WHERE the sequence-number watermarks start (firstSN vs lastSN+1) and
WHETHER the writer purges; everything downstream is the already-shipped reliable engine.

### 4. `durability-finalize` (the OPT-IN extension, on top of the conformant default)

`durability-finalize (dw)` (DCPS, `src/dds-dcps/entities.lisp`) → the disc bridge
`finalize-writer-durability` → `writer-finalize-durability` sets a per-writer FINALIZED flag; a FINALIZED
non-VOLATILE writer reverts to the VOLATILE-style full-ACK purge (the retained late-joiner history is RELEASED
once all current readers ACK; samples published afterward behave VOLATILE). MONOTONIC (no un-finalize in v1),
idempotent, a no-op for a VOLATILE writer and when there is no engine writer yet (the bridge guards `(when w …)`,
so the no-op is the absence of an engine writer, not an explicit enabled check). This is a NON-STANDARD
extension ADDED ON TOP of the conformant default (DDS leaves per-writer TL lifetime to the durability service),
never replacing it. The tunable retention-DURATION timer + LIFESPAN QoS remain separate follow-ups.

### 5. The spec-§3 divergence — skip iff VOLATILE-reader AND retaining-writer

The design spec §3 originally framed the reader-side skip as "a VOLATILE reader **(or matched a VOLATILE
writer)** → skip." **That is WRONG and is NOT the as-built behavior.** A VOLATILE writer RETAINS NOTHING, so
everything it HEARTBEATs is LIVE; skipping to `lastSN+1` against a VOLATILE writer would discard live, never-yet-
delivered samples (T2 found this breaks reliable / reliable-zc retransmit with **silent loss**). The as-built
skip condition (`%reader-durability-init`) is therefore precisely:

```
skip = (VOLATILE local reader) AND (matched writer is a RETAINING durability — TRANSIENT_LOCAL/TRANSIENT/PERSISTENT)
```

In EVERY other admitted combination — a TRANSIENT_LOCAL reader matched a retaining writer (REQUEST the history),
AND crucially **VOLATILE-reader ↔ VOLATILE-writer** — SKIP-HISTORY is NIL, i.e. byte-identical to before this
WP, so a VOLATILE reader against a VOLATILE writer still NACKs a dropped LIVE sample. Gating the skip on a
RETAINING writer is what keeps reliable drop-recovery intact. The spec §3 wording has been corrected to match
the as-built; this divergence (skip conditioned on a retaining writer, not on the reader/writer being VOLATILE
in isolation) is the recorded as-built behavior.

## Known edges

### Residual race (DEFERRED, item carried from T2) — VOLATILE-reader ↔ TL-writer match-window

For a VOLATILE reader matched to a TRANSIENT_LOCAL writer, the skip floor (`lastSN+1`) is applied on the FIRST
HEARTBEAT. There is a narrow window between match and that first HEARTBEAT in which, **if a newly-written LIVE
sample's HEARTBEAT beats its own DATA to the reader**, the reader could compute the skip floor over a range that
already includes that just-published LIVE sample and thus skip it. This is **narrow** in practice — the engine
COALESCES DATA + HEARTBEAT into one datagram (the same coalescing the interop READMEs note), so the DATA almost
always accompanies the HEARTBEAT that establishes the floor — and it only affects the VOLATILE-reader↔TL-writer
combination (a VOLATILE reader's deliberate skip), never the TL↔TL replay path or the VOLATILE↔VOLATILE path.
It is **DEFERRED and documented as a known edge**; the race-free fix is a per-reader JOIN-FLOOR captured at
match time (snapshot `lastSN` at match, skip strictly below that floor regardless of HEARTBEAT timing) rather
than recomputing the floor from the first HEARTBEAT — a follow-up.

## Cross-DDS interop result (the per-feature DoD — both directions, both peers, LIVE)

Verified in-session 2026-06-18 vs RTI Connext 7.3.1 and eProsima Fast DDS 3.6.1 on `lo0`
(`interop/durability-transient-local/`, captures committed):

- **Forward (our TL writer → late foreign TL reader), both peers — fully wire-captured:** our HEARTBEAT holds
  `firstAvailableSeqNumber = 1` on EVERY HEARTBEAT (the TL KEEP_ALL retention on the wire), the late reader
  NACKs, and we RETRANSMIT the retained range (Leg 1 Connext ≈95, Leg 2 Fast DDS ≈89 retransmits — raw tshark
  submessage tallies, see the README footnote); both foreign peers reported receiving the pre-join history
  starting at sample #1 (`x=53 y=52`, our first sample).
- **Reverse (foreign TL writer → our late TL reader), both peers:** our late reader decoded the foreign
  writer's FIRST pre-join sample (`x=53 y=52` from Connext; `x=50 y=50` from Fast DDS) + our outbound ACKNACKs
  are on the wire. The foreign-peer→us user-DATA direction is UNDER-CAPTURED on macOS `lo0` BPF (the documented
  reverse-direction quirk, same as `interop/shmem-send-self-guard`); the reverse proof rests on the decoded
  application receipt + the ACKNACK SN progression, stated plainly.
- **The VOLATILE contrast (both foreign TL writers):** a VOLATILE late reader does NOT receive the retained
  pre-join history (first decoded sample is mid-animation) — isolating genuine late-joiner history delivery from
  merely receiving future samples, and confirming the §5 skip branch on the wire.

## Consequences

- **Conformance:** TRANSIENT_LOCAL retention + late-joiner replay is DDS 1.4 §2.2.3.4 conformant; the
  `durability-finalize` control is a documented extension on top (never replacing conforming behavior). The
  §5 divergence is a CORRECTION of an erroneous spec sentence to the conformant/safe as-built (skip a retaining
  writer only) — it removes a silent-loss bug, it does not deviate from the standard.
- **Hot path:** retention/replay is off the measured CDR hot path (it changes watermarks + the purge branch,
  not the per-sample codec). `make mem` is unaffected (0.0000 bytes/sample); no bench warranted (FR-LANG-7 —
  no hot-path change).
- **Default unchanged:** DURABILITY defaults to VOLATILE → byte-identical to the prior wire; the whole feature
  is inert unless TRANSIENT_LOCAL is requested.
- **Follow-on:** the durability SERVICE (TRANSIENT, then PERSISTENT) per ADR 0021 reuses this writer-side
  retention as its foundation; the residual race fix (per-reader join-floor), the retention-DURATION timer, and
  LIFESPAN QoS are separate follow-ups.

## M6 exit gate

TRANSIENT_LOCAL durability + late-joiner, interop-verified both directions (both peers) — MET (the four
directional legs + both VOLATILE contrasts, `interop/durability-transient-local/README.md`).
