# ADR 0023 — TRANSIENT durability service: Phase-1 as-built architecture

- **Status:** Accepted (M6/P5; WP-DURABILITY-SERVICE-TRANSIENT, 2026-06-18)
- **Relates to:** ADR 0021 (the durability/persistence SERVICE scope decision);
  ADR 0022 (TRANSIENT_LOCAL writer-side retention + late-joiner replay — the foundation this service
  reuses); `docs/superpowers/specs/2026-06-18-durability-service-transient-design.md`;
  `docs/superpowers/spikes/2026-06-18-durability-virtual-guid-findings.md` (PID_ORIGINAL_WRITER_INFO
  finding, the Phase-2 dedup mechanism).
- **Scope:** TRANSIENT durability service, Phase 1 (in-memory store, writer-is-gone scenario,
  thread-or-process, OTP supervisor, CLI/env entrypoint). PERSISTENT (disk-backed + DARE) is Phase 3.

## Context

ADR 0022 landed TRANSIENT_LOCAL: a TL writer retains its HistoryCache for the duration of its own
lifetime and replays to late-joiner TL readers via the existing reliable HEARTBEAT/ACKNACK machinery.
That covers only the writer's lifetime. DDS 1.4 §2.2.3.4 defines TRANSIENT as "samples outlive
the writer" — requiring a third party to collect and re-publish after the original writer exits.
ADR 0021 scoped that third party IN, with six owner-specified capabilities (embedded library entity,
multi-service runner, thread-or-process, OTP supervisor, CLI entrypoint, pluggable persistence).

This ADR records the as-built Phase-1 service architecture, its Phase-1 limitations, and the
Phase-2 boundary established by the Task-1 spike.

## Decision — the as-built Phase-1 architecture

### 1. Pluggable durable store (ADR 0021 cap. 6 — in-memory first)

`durable-store` (`src/dds-durability/store.lisp`) is a vtable-pattern struct: seven function
slots (`put`, `get-range`, `topics`, `purge`, `open`, `close`, `count-fn`) decouple the caller
from the backing implementation, mirroring the transport vtable pattern (FR-XPORT-5 analogue).
No CLOS dispatch — a single slot-read + funcall per operation.

Public dispatch: `store-put`, `store-get-range`, `store-topics`, `store-purge`, `store-open`,
`store-close`, `store-count`.

The sole Phase-1 implementation is `make-memory-store` (`:max-samples` 0 = unbounded; a positive
value caps the total record count across all topics — `store-put` returns `:rejected` when full,
never silently overwriting). Records are keyed by `(topic, writer-guid-as-list, sn)`; `store-put`
is idempotent on the same key (a re-put is a no-op returning T). `store-get-range` returns records
sorted by `(writer-guid ascending, sn ascending)`. All operations are lock-guarded; no GC-heap
allocation occurs on the critical path after table growth.

`durable-record` carries `(topic, writer-guid, sn, key-hash, kind, payload)`. The `kind` field
is `:data`/`:dispose`/`:unregister`; the store can hold all three. (Phase-1 collection is
DATA-only — see §6.)

### 2. Service specification (ADR 0021 cap. 2)

`service-spec` (`src/dds-durability/spec.lisp`) is the discrimination unit for a single service
node: `(domain, topics, store-factory, mode, qos-overrides, name)`. `topics` is either an explicit
list of `(topic-string . type-string)` conses, a `(lambda (topic type) …)` predicate, or NIL
(matches nothing). `service-spec-matches-p` dispatches on the filter type without CLOS.

### 3. Collect + replay (ADR 0021 cap. 1; publish-on-collect model)

`durability-service` (`src/dds-durability/service.lisp`) is a `disc-node` with:

- A reliable TRANSIENT_LOCAL KEEP_ALL **collecting reader** that receives every DATA sample
  published on the service's topic (from any matching writer, including foreign ones via
  the SPDP/SEDP peer-announce and unicast discovery wired in `service-start`).
- A reliable TRANSIENT_LOCAL KEEP_ALL **replay writer** on the same topic. Its HistoryCache
  mirrors the store via the **publish-on-collect** model: each sample the collect loop stores
  is immediately re-published through this writer. The writer's HistoryCache grows to hold the
  full retained history; the shipped TL late-joiner machinery (ADR 0022 `%writer-durability-init`,
  HEARTBEAT/ACKNACK/retransmit) delivers it to any subsequently-discovered TL reader — including
  after the original writer is gone.

The collect loop (`%collect-loop`) runs on a dedicated thread, polling `disc-node` sample keys
every ~5 ms. Each new `(writer-guid, sn)` pair drives a `store-put` + `publish-sample` to the
replay writer. A seen-key hash provides belt-and-suspenders dedup on top of `store-put`'s own
idempotence. Per-iteration errors are caught, counted, and routed to `*durability-error-hook*`
(default: a clockless power-of-ten rate-limited WARN); a `SERIOUS-CONDITION` is not caught
(process/image-fatal errors propagate as designed). `service-stop` is idempotent.

The collect loop re-announces SPDP + SEDP every ~1.5 s (`announce-participant` + `announce-endpoints`)
so foreign participants (Connext, Fast DDS) can discover the service on its unicast address without
requiring multicast (RTPS 2.5 §8.5.3.3).

`service-start` honors `qos-overrides`:
- `:data-representation <list>` — governs the replay writer's SEDP advertisement; payload bytes
  forwarded opaque; default `(:xcdr2)`. For foreign-peer interop the interop test uses `:xcdr1`.
- `:peers <list-of-(host . port)>` — initial SPDP unicast peer list; default none.
- `:multicast <boolean>` — when T, enables multicast SPDP on the service node; default NIL.

### 4. Multi-service runner (ADR 0021 cap. 1–2)

`service-runner` (`src/dds-durability/runner.lisp`) is a registry of N `service-spec`s. Each
is instantiated as a `durability-service` and started on `runner-start`. `:thread` mode (default)
runs the service collect loop in the host image. `:process` mode launches a child Lisp (SBCL)
invoking `durability-service-main` with `%spec->argv`-serialized CLI args, monitored via a
lightweight thread polling `uiop:process-alive-p`; a non-SBCL impl falls back to in-thread with
a notice. A double `runner-start` is a no-op (concurrent-start guard). `runner-stop` nulls the
services list and resets the started flag (the runner may be restarted after a stop). `runner-status`
returns `(name . alive-p)` pairs.

### 5. OTP-style supervisor (ADR 0021 cap. 4)

`supervisor` (`src/dds-durability/supervisor.lisp`) implements one-for-one restart with
restart-intensity capping: at most MAX-RESTARTS restarts in a sliding WINDOW-SECONDS window per
service. A watcher thread polls `service-alive-p` every POLL-MS milliseconds (default 50). On a
dead service not yet shed, `%supervisor-restart-service` records the timestamp BEFORE attempting
`service-start` (so a fault-induced immediate death still counts), then either installs the fresh
service in the runner (via `%supervisor-replace-service`, under both locks), or sheds it and fires
`*durability-error-hook*` with context `:supervisor-shed`. Restart semantics are OTP permanent:
any termination (crash OR deliberate `service-stop`) triggers a restart — to stop a supervised
service permanently, stop the supervisor or the runner.

An **orphan guard** rechecks `supervisor-running` after the potentially-slow `service-start`
completes: if `supervisor-stop` flipped the flag during that window, the just-started service is
immediately stopped and NOT installed in the runner (no orphan leak).

The `%restart-allowed-p` predicate is pure (no side effects, no threads) and unit-testable in
isolation.

### 6. CLI/env entrypoint (ADR 0021 cap. 3, 5)

`parse-durability-config` + `durability-service-main` (`src/dds-durability/main.lisp`).
`parse-durability-config` is PURE (no I/O): it walks the CLI `argv` list and an `env` alist (or
1-arg function), returning `(values specs max-restarts window-seconds)`. Config precedence:
CLI > env > defaults. Supported CLI flags: `--domain`, `--topic NAME:TYPE`, `--mode thread|process`,
`--max-restarts N`, `--window-seconds N`, `--name S`; env vars `DDS_DURABILITY_DOMAIN`,
`DDS_DURABILITY_TOPICS` (comma-separated `NAME:TYPE` pairs), `DDS_DURABILITY_MODE`,
`DDS_DURABILITY_NAME`.

All parse checks are explicit manual bounds-checks (never a safety-level-dependent type dispatch),
so `durability-config-error` is signalled under any optimization policy, including `(safety 0)`.
`durability-service-main` wraps `parse-durability-config` → `make-service-runner` → `make-supervisor`
→ `runner-start` → `supervisor-start`, then loops (subprocess body) or returns `(cons runner sup)`
(embedded use, `:block nil`).

`%spec->argv` serializes a `service-spec` back to CLI token strings for the subprocess launcher;
predicate-only specs cannot be serialized (`:process` mode requires explicit cons-list topics).

## Phase-1 conformance result — cross-DDS interop

**Writer-is-gone scenario, LIVE in-session 2026-06-18** (`interop/durability-transient/`):

- A Connext 7.3.1 publisher (TRANSIENT, RELIABLE, KEEP_ALL) writes samples, then exits.
  Our durability service collected 409 and re-published them via its TL+KEEP_ALL replay writer.
  A late-joining Connext 7.3.1 subscriber received the pre-exit history (409/409, from sample #1),
  `firstAvailableSeqNumber=1` confirmed on the wire (the service writer's TL retention; the replay
  writer is the source of this HEARTBEAT, not the original writer). NACK→retransmit sequence
  confirmed by tshark. **PASS.** (Exact per-leg figures are the authoritative record in
  `interop/durability-transient/README.md`.)
- Same scenario against eProsima Fast DDS 3.6.1 publisher (200 samples) + late-joining Fast DDS
  3.6.1 subscriber. The late-joining reader received the collected pre-exit history starting at
  sample #1. **PASS** (Fast DDS ~3s discovery delay caused the service to miss the first ~28
  samples in the initial collection — a Fast DDS discovery-timing gap, not a service defect; the
  late-joiner proof rests on the samples the service actually collected and replayed).
- **VOLATILE late-joiner contrast**: a VOLATILE subscriber receives 0 pre-join history from the
  service writer (the ADR 0022 §5 skip branch — a VOLATILE reader matched against the service's TL
  replay writer skips to `lastSN+1`). Confirmed both peers.

Honest caveats: macOS `lo0` BPF reverse-direction under-capture quirk (the same documented quirk
from ADR 0022 and the SHMEM/data-representation interop tests); the service's replay writer
publishes under its OWN GUID/SN — this is conformant for the writer-is-gone scenario and is the
one the Phase-1 DoD covers (see Phase-1 limitations, §8).

## Phase-1 system conformance (VOLATILE default)

The DURABILITY default is VOLATILE. When no durability service is configured, all behavior is
byte-identical to the pre-Phase-1 stack: no collect loop, no replay writer, the service is not
instantiated. The `dds-durability` ASDF system is loaded only when the host application calls
`make-service-runner` / `runner-start`; it does not alter any default behavior of the rest of
the stack.

## Phase-1 limitations (documented honestly)

### 8.1 Replay under own GUID/SN — no double-delivery guard (the primary Phase-1 limit)

The replay writer publishes under its own GUID and its own ascending sequence numbers. This is
correct when the **original writer is gone** (the sole Phase-1 DoD scenario): only the service
writer is alive on the topic, so no reader can receive the same sample from two sources
simultaneously.

**The no-double-delivery case (original writer alive at the same time as the service) is NOT
handled in Phase 1.** If both the original writer and the service replay writer are matched to the
same reader simultaneously, the reader receives the same logical sample twice (once from each
source). The Phase-2 wire mechanism for dedup is `PID_ORIGINAL_WRITER_INFO (0x0061)` — a
**standard OMG RTPS 2.5 PID** (§8.3.5.4, Table 9.12) — confirmed by the Task-1 spike (see §9).

**Foreign-service coexistence** (two independent TRANSIENT services on the same domain, each
relaying the same topic) is similarly deferred: the receiver-side dedup using
`PID_ORIGINAL_WRITER_INFO` is the mechanism for that case too (any two relays carrying the same
`originalGUID + originalSN` are deduplicated at the receiver; no inter-service coordination
protocol is required or observed — see the spike §4). Phase-2 adds the dedup carrier.

### 8.2 One topic per service node (MVP)

`%service-primary-topic` extracts the first explicit `(topic . type)` cons from the spec.
A service node listens and replays on exactly one topic. A predicate-only spec signals at
`service-start`. Multi-topic-per-service (a single node serving multiple topics) is a Phase-2
follow-up.

### 8.3 DATA-kind capture only

The collect-loop poll API (`disc-node-sample-sns` / `node-sample`) exposes payloads but not
change-kind. The `durable-record` struct has a `:kind` field supporting `:dispose` and
`:unregister`, but the collect loop always stores `:data`. Replay of dispose/unregister lifecycle
transitions (so a late-joiner sees the correct NOT_ALIVE_DISPOSED / NO_WRITERS state at join time)
is a Phase-2 follow-up.

### 8.4 In-memory state lost on process restart

The in-memory store (`make-memory-store`) holds no persistent state. A `:process`-mode service
that is killed and restarted (e.g. by the supervisor) begins with an empty store. PERSISTENT
durability (disk-backed + CNSA-2.0 DARE) is Phase 3, per ADR 0021 sequencing.

### 8.5 Supervisor restart of a :process service falls back to in-thread

The OTP supervisor calls `make-durability-service` / `service-start` on restart, which always
creates a new `:thread`-mode service regardless of the spec's `:mode` setting (the supervisor
knows specs, not the process handle). A `:process`-mode service that is shed-and-restarted by the
supervisor runs in-thread. This is a documented sequencing simplification; correcting it requires
the supervisor to invoke `%start-process-service` on restart.

### 8.6 `:process` mode is SBCL-only

`%start-process-service` dispatches on `pal-impl-name` at runtime (no reader conditionals per
the operating contract §10). Non-SBCL impls fall back to in-thread with a printed notice.
`durability-service-main` is fully portable Lisp; the subprocess launcher simply invokes this
Lisp.

## Phase-2 boundary — the PID_ORIGINAL_WRITER_INFO mechanism (Task-1 spike)

The Task-1 spike (`docs/superpowers/spikes/2026-06-18-durability-virtual-guid-findings.md`)
captured a live RTI Persistence Service v7.3.1 TRANSIENT relay and independently confirmed the
mechanism against eProsima Fast DDS 3.6.1 source (Apache-2.0, read for understanding, no code
copied; recorded in `docs/provenance.md`).

**Finding:** the standard OMG RTPS 2.5 PID is **`PID_ORIGINAL_WRITER_INFO (0x0061)`**
(§8.3.5.4, `OriginalWriterInfo`). Layout in inline QoS (LE):

```
paramId(2B=0x0061) + paramLen(2B=0x0018=24) +
guidPrefix(12B=original-writer-prefix) + entityId(4B=original-writer-entityId) +
SN.high(4B=0) + SN.low(4B=original-SN, LE)
```

Dedup rule at the receiver: for each incoming DATA carrying `PID_ORIGINAL_WRITER_INFO`, track
`max_received_SN[originalGUID]`; discard if `originalSN <= max`. This is entirely receiver-side;
no inter-relay coordination is required.

**Phase-2 action:** the replay writer MUST emit `PID_ORIGINAL_WRITER_INFO` in the inline QoS of
every relayed DATA submessage, carrying the `(writer-guid, sn)` stored in the `durable-record`.
The `durable-record` already captures both fields. The DATA submessage emitter in
`src/dds-rtps/message.lisp` needs an optional `inline-qos-pids` argument; the collect loop
passes the original `(writer-guid, sn)` at relay time.

Additionally observed but DEFERRED: `PID_ENTITY_VIRTUAL_GUID (0x8002)` in the SEDP PUBLICATION
announcement (RTI vendor PID; Fast DDS names it `PID_PERSISTENCE_GUID`; same layout — 16-byte GUID
value). Not required for per-sample dedup; deferred per spike §5.3.

## Consequences

- **Conformance:** the Phase-1 service delivers the TRANSIENT writer-is-gone scenario conformantly
  via the standard DDS collect+relay model. VOLATILE default is byte-identical to before. The
  publish-on-collect model reuses the shipped TL late-joiner machinery (no new wire format).
- **No-double-delivery** and **foreign-service coexistence** are Phase-2 features gated behind the
  `PID_ORIGINAL_WRITER_INFO` inline QoS carrier (a standard PID, clean-room implementation from
  RTPS 2.5 §8.3.5.4 — no vendor behavior copied).
- **Hot path:** the service is control-plane. No hot-path files are touched; `make mem` stays
  0.0000 bytes/sample; no bench warranted (FR-LANG-7).
- **Conformance gate:** `make test` (SBCL + Clasp), `gate-hotpath`, `gate-types`, `mem`, `fuzz`
  (including the config-parser fuzz arm added in this task), `wire` — all PASS.
- **Follow-ons:** multi-topic-per-service; dispose/unregister replay; per-reader join-floor race
  fix (carried from ADR 0022); retention-DURATION timer; LIFESPAN QoS; and Phase 3 PERSISTENT
  (pluggable file/db store + CNSA-2.0 DARE per ADR 0021 cap. 7).

## M6 exit gate (durability service component)

Phase-1 TRANSIENT durability service — embedded library entity, multi-service runner, thread-or-process,
OTP supervisor, CLI/env entrypoint, in-memory pluggable store, cross-DDS interop writer-is-gone
scenario both peers — MET.
