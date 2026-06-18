# Design — TRANSIENT durability service (M6/P5, slice 2)

- **Date:** 2026-06-18
- **Status:** Design approved (brainstorm); spec under owner review before the implementation plan.
- **Scope:** the embedded TRANSIENT durability/persistence service (ADR 0021 slice 2). In-memory persistence
  first; disk-backed persistence + the always-on CNSA-2.0 Data-At-Rest Encryption (capability 7) are the
  PERSISTENT slice (slice 3), out of scope here.
- **Relates to:** ADR 0021 (the durability service is IN scope; the 7 owner-specified capabilities + the
  vertical-slice sequencing); ADR 0022 + `2026-06-18-wp-durability-transient-local-design.md` (TRANSIENT_LOCAL
  durability + late-joiner — the writer-side retention + reliable replay this service reuses); DDS 1.4
  §2.2.3.4 (DURABILITY) + §2.2.3.5 (DURABILITY_SERVICE QoS); RTPS 2.5 §8.4.1/§8.4.2.2 (reliable
  writer/reader, HEARTBEAT/ACKNACK/retransmit).

## 1. Goal

DURABILITY QoS **TRANSIENT** (DDS 1.4 §2.2.3.4) requires durable samples to outlive the original DataWriter:
a late-joining reader that discovers the topic AFTER the original writer is gone must still receive the
retained history. TRANSIENT_LOCAL (shipped, ADR 0022) covers only the writer's own lifetime. TRANSIENT
therefore requires a durability ENTITY — a participant that collects durable samples, stores them, and
replays them to late-joiners independent of the original writer. This slice delivers that entity as an
embedded service with all six non-crypto capabilities of ADR 0021.

## 2. Owner decisions (brainstorm, 2026-06-18)

1. **MVP boundary:** full slice-2 — all six capabilities (embedded entity, multi-service runner,
   thread-or-process, OTP-style supervisor, `durability-service-main` CLI, pluggable persistence), with
   in-memory persistence first. DARE (capability 7) deferred to the PERSISTENT slice.
2. **Relay/wire model:** standard relay **plus** interop with foreign durability services — the relay
   preserves the ORIGINAL writer's identity (a virtual/persistence GUID) so a TRANSIENT late-joiner does NOT
   receive samples twice when the original writer and/or a foreign durability service is also present.
3. **Process mode:** `:thread` = a `dds.pal` thread in-image; `:process` = a child OS process running the
   `durability-service-main` entrypoint via `uiop:launch-program` (portable across SBCL/Allegro/Clasp, no
   fork dependence; the CLI entrypoint is reused as the process body).
4. **Service discrimination unit:** per-`(domain + topic-filter)`, where the filter is an explicit
   `(topic . type)` list OR a predicate over discovered-endpoint metadata.
5. **De-risking:** the FIRST task is an investigation spike — determine whether RTI Persistence Service
   (`rtipersistenceservice`, Connext Pro) and the Fast DDS persistence plugin run here, capture their
   durable-replay + late-joiner exchange with tshark, and identify the virtual-GUID dedup PID(s). The spike's
   findings refine the vendor-interop scope before that wire format is committed.

## 3. Architecture & module layout

A new ASDF system **`dds-durability`** layered on `dds-dcps` (entities) + `dds-disc` (embedded participant) +
`dds-pal` (threading/process). Six units, each one clear purpose behind a defined interface:

| Unit | File | Responsibility |
|---|---|---|
| **`durable-store` protocol** | `store.lisp` | Pluggable persistence vtable (`defstruct` of closures, matching the hot-path idiom): `store-put`, `store-get-range`, `store-topics`, `store-purge`, `store-open`/`store-close`. Ships one impl: **in-memory** (`make-memory-store`). File/db/microservice are later plugs against the same protocol. The DARE wrapper (slice 3) sits ABOVE this protocol. |
| **`durability-service`** | `service.lisp` | One embedded participant (a `disc-node`) for a `(domain, topic-filter)` spec: a TRANSIENT_LOCAL/TRANSIENT RELIABLE KEEP_ALL **reader** per matched durable topic feeding the store, and a **writer** replaying the store to late-joiners under preserved original identity (the dedup core). |
| **`service-spec` + matching** | `spec.lisp` | The discrimination unit: `domain` + a topic/type selector (explicit `(topic . type)` list OR a predicate over discovered endpoint metadata) + store factory + mode + QoS overrides. |
| **`service-runner`** | `runner.lisp` | Holds N service specs; starts each in **thread** (`dds.pal` thread) or **process** (`uiop:launch-program` of `durability-service-main`) mode per a keyword. Owns the registry (start/stop/list/status); the single object the host app embeds (capability 1). |
| **`supervisor`** | `supervisor.lisp` | OTP-style: one watcher per running service; liveness = thread-alive / process-exit-code; restart per a **one-for-one** strategy with a **restart-intensity** window (max R in T seconds → shed + escalate via a hook). |
| **`durability-service-main`** | `main.lisp` | CLI/env entrypoint (capability 5): parse config (precedence CLI > env > defaults) → build specs → run the runner+supervisor. Also the body the subprocess process-mode launches — one code path, reused. |

Tests in `dds-tests` (`durability-test.lisp`); interop harness in `interop/durability-transient/`.

## 4. Data flow & the dedup / original-identity mechanism (the conformance core)

**Collect path:** for each matched durable topic the service's reader (TRANSIENT_LOCAL/TRANSIENT, RELIABLE,
KEEP_ALL) receives the original writer's samples and calls `store-put`, recording per sample the **original
writer's identity** + original sequence number + source timestamp + key + change-kind (write/dispose/
unregister) + the original writer's advertised HISTORY — not just the payload. That identity is what makes
dedup work downstream.

**Replay path:** when a late-joiner reader is discovered (the same match hook the TL WP shipped —
`%writer-durability-init`), the service's writer replays `store-get-range` for that topic over the existing
reliable HEARTBEAT/ACKNACK/retransmit engine. Replay honors the original writer's HISTORY (per-key
KEEP_LAST/KEEP_ALL), is source-timestamp ordered, and includes dispose/unregister so a late-joiner sees an
instance was disposed. The original writer dying does NOT purge the store.

**The dedup problem (why a naive relay is non-conformant against foreign services):** DDS readers reject
duplicates by `(writerGUID, SN)`. A relay re-publishing under its OWN GUID with its OWN SNs is, to the
late-joiner, a distinct source — so a TRANSIENT late-joiner that also hears the original writer (or another
durability service) receives every sample TWICE. The fix is to carry the original writer's identity across
the relay so all copies collapse to one logical source:

- **Conformant substrate (we own):** the relay preserves + re-emits the original `(writerGUID, SN)`
  association via the DDS-standard sample-identity / source-identity concept (an inline QoS / parameter on
  the relayed DATA).
- **Vendor interop (added ON TOP, clean-room):** RTI uses a `PID_PERSISTENCE_GUID`/virtual-GUID; Fast DDS has
  its own. Task 1 (the spike) captures both services replaying to a late-joiner, identifies the exact PID(s)
  + dedup rule byte-for-byte (the legacy-TypeObject reverse-engineering method), and pins the wire format. We
  implement the conformant identity-preservation PLUS the vendor PID as an interop behavior layered on top —
  never replacing conforming behavior, never a false-reject if the PID is absent.

**Honest risk (stated plainly):** if the spike finds RTI's inter-service coordination (which service "wins"
when several hold the same data) is proprietary beyond the GUID dedup, full coexistence may reduce to "no
double-delivery via the shared virtual-GUID" with deeper coordination documented as a gap. The virtual-GUID
dedup is the load-bearing, achievable part.

## 5. Runner, supervisor, CLI/config & persistence interface

**`service-spec`** (discrimination unit): `(:domain N :topics <list-or-predicate> :store <store-factory>
:mode :thread|:process :qos-overrides ...)`. `:topics` is either an explicit `(topic . type)` list or a
predicate `(lambda (topic type qos) ...)` over discovered-endpoint metadata — "definable criteria" without
over-engineering.

**`service-runner`**: takes a list of specs, instantiates each `durability-service`, starts it in its mode.
`:thread` → a `dds.pal` thread running the service loop in-image. `:process` → `uiop:launch-program` of
`durability-service-main` with the spec serialized to CLI/env. Owns start/stop/list/status; the embedded
library entity the host app holds (capability 1).

**`supervisor`** (OTP-style, capability 4): one watcher per running service. Liveness = thread-alive (thread
mode) / process exit code (process mode). On death → restart per a **one-for-one** strategy with a
**restart-intensity window** (max R restarts in T seconds → give up + escalate via a hook) so a poison-pill
service is shed, not infinitely respun. Restart re-runs the relay from the store (thread mode: store survives
in-image; process mode: store is re-opened — in-memory loses state on process restart, a documented MVP
limitation that PERSISTENT/disk fixes). Strategies beyond one-for-one (one-for-all, rest-for-one) are
follow-on.

**`durability-service-main`** (capability 5): config from CLI args + env vars (precedence CLI > env >
defaults) → a list of `service-spec`s. Both the standalone entrypoint and the body process-mode launches —
one code path.

**`durable-store` protocol** (capability 6): the vtable interface is the contract; the **in-memory** impl
ships now (a per-topic, per-key ordered structure holding `(original-identity, SN, source-ts, key, kind,
payload)` records). File/db/microservice are later plugs against the same protocol; the always-on CNSA-2.0
**DARE** (capability 7) is a wrapper ABOVE the store protocol, added in the PERSISTENT slice, so no plaintext
is ever written to a durable plug.

## 6. Error handling

Every service loop runs under a per-iteration guard (the shipped RX/sender pattern, `with-sender-emit-guard`):
a transient error is caught, counted, observed via a bindable hook, and the loop continues; the supervisor
handles only thread/process DEATH, not in-loop hiccups. Store ops are fallible — `store-put` on a full
in-memory store → a RESOURCE_LIMITS-style reject + hook, never silent loss, never unbounded heap growth
(NFR-MEM). Subprocess launch failure → the supervisor restart-intensity applies. Every parsed config value
and every wire-sourced identity field is bounds-checked (NFR-SEC-POSTURE) — a forged/oversized virtual-GUID
must never OOB or be trusted blindly.

## 7. Testing strategy

- **Unit:** store-protocol conformance (in-memory), spec-matching predicate, restart-intensity math, CLI/env
  parsing.
- **Integration (headline, our-stack):** an original writer publishes N TRANSIENT samples then TERMINATES; a
  durability service has collected them; a reader joining AFTER the writer is gone receives all N from the
  service — VOLATILE contrast gets none; a **no-double-delivery** assertion when both the still-alive original
  writer and the service are present.
- **Supervisor:** kill a service thread/process → assert restart + resumed replay; crash-loop → shed.
- **Cross-DDS interop (per-feature DoD, both peers):** a foreign Connext/Fast DDS late-joiner receives our
  service's retained history; and — gated on the spike — coexistence with a running foreign durability service
  shows no double-delivery via the shared virtual-GUID.
- **Gates:** 256+ green SBCL+Clasp; gate-hotpath / gate-types / mem / fuzz (the config parser + the wire
  identity field) / wire all green.

## 8. Vertical-slice implementation ordering

Each is a thin, demonstrable increment; the plan details them.

1. **Spike** — foreign persistence tooling availability + capture/RE the virtual-GUID dedup PID(s). Findings
   refine slices 5–6.
2. **`durable-store` + in-memory impl** — protocol, vtable, store conformance tests. No DDS yet.
3. **Single in-thread service, our-stack relay** — collect → store → replay to a late-joiner after the writer
   dies (the core value, end-to-end, our→our), with identity-preservation dedup (conformant substrate).
4. **Runner + spec matching + supervisor** — multi-service, thread mode, restart; then process mode via
   `durability-service-main` + CLI/env config.
5. **Vendor virtual-GUID interop** — emit/parse the spiked PID; cross-DDS DoD vs foreign late-joiners.
6. **Foreign-service coexistence** — no-double-delivery vs a running foreign durability service (scope per the
   spike).

Each slice: implement → 2 reviews/task → gates → cross-DDS where applicable → autonomous commits on the
branch → final whole-branch review → squash-merge presented for approval, **push held**.

## 9. Out of scope (this slice)

- PERSISTENT durability (disk-backed store surviving restart) + the always-on CNSA-2.0 DARE (capability 7) —
  the next slice (slice 3).
- The tunable retention-DURATION timer + LIFESPAN QoS (carried from ADR 0022 follow-ups).
- Supervisor strategies beyond one-for-one; the file/db/microservice store plugs (the protocol is delivered,
  the extra impls are follow-on).
- The rest of the Connext Professional service suite (Routing/Recording/Cloud-Discovery/Admin-Console/Monitor)
  remains out of scope (ADR 0021).
