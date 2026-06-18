# ADR 0021 — The durability/persistence service is in scope (TRANSIENT + PERSISTENT enabled)

- **Status:** Accepted (owner directive, 2026-06-18)
- **Supersedes (in part):** the service-suite-out-of-scope boundary in `CLAUDE.md` §1/§10 and `REQUIREMENTS.md`
  §1.2, **for the durability/persistence service only**.
- **Relates to:** the M6/P5 durability work; `docs/superpowers/specs/2026-06-18-wp-durability-transient-local-design.md`.

## Context

The operating contract scoped the Connext *Professional* service suite — Routing, Recording/Replay,
**Persistence**, Cloud Discovery, Admin Console / Monitor — OUT of scope (`CLAUDE.md` §1: "do not start
building services"; §10: "Never start a Connext Professional service (… Persistence/etc.)"; `REQUIREMENTS.md`
§1.2: "Persistence Service (as a *separate* service process)"; §13 open-decision #2 left the "Professional"
scope undecided).

But DURABILITY QoS **TRANSIENT** and **PERSISTENT** (DDS 1.4 §2.2.3.4) are NOT functional without a durability
entity: their samples must outlive the original DataWriter (TRANSIENT) and survive a process/system restart
(PERSISTENT). TRANSIENT_LOCAL (the writer's own retention) covers only the writer's lifetime. Delivering
TRANSIENT/PERSISTENT therefore REQUIRES a durability service.

## Decision

**The durability/persistence service is IN scope.** This reverses the service-suite exclusion **for this one
service**; the other Professional services (Routing/Recording/Cloud-Discovery/Admin-Console/Monitor) REMAIN out
of scope. The service is built clean-room from the DDS durability concept (a DDS participant that subscribes to
durable topics, stores their samples, and re-publishes them to late-joiners), with these owner-specified
capabilities:

1. **Embedded library entity** (a participant created in-process), not primarily a standalone binary.
2. **Multi-service runner** — run multiple durability services discriminated by definable criteria.
3. **Thread-or-process** execution per service, selectable by a keyword argument.
4. **Erlang/OTP-style supervisor** monitoring all services, with restart.
5. **`durability-service-main`** — a separate entrypoint reading config from CLI + env args.
6. **Pluggable persistence** — file-based, database-backed, microservice-backed implementations.
7. **Always-on Data-At-Rest Encryption** — tamper-proof, **CNSA 2.0** (AES-256-GCM AEAD + post-quantum key
   establishment ML-KEM/FIPS-203 + SHA-384), via a vetted crypto library (libsodium/OpenSSL, §9), never
   hand-rolled — a layer ABOVE the pluggable persistence. Integral (always maintained), not optional.

## Sequencing (vertical-slice, owner-chosen)

1. **TRANSIENT_LOCAL** (the current WP) — writer-side retention + late-joiner replay; the foundation the
   service reuses. No service required.
2. **Durability service / TRANSIENT** — the embedded service (capabilities 1-6 above, in-memory persistence
   first) relaying durable samples beyond the writer's lifetime.
3. **PERSISTENT** — disk-backed persistence + the CNSA-2.0 DARE (capability 7), surviving restart.

Each slice is independently demonstrable + testable, with the established process (brainstorm→spec→plan→
subagent-driven→squash-merge) and the cross-DDS-interop-per-feature DoD.

## Consequences

- **Scope/effort:** a multi-milestone subsystem (OTP-style supervision + a pluggable storage/crypto stack +
  the DDS relay). The DARE pulls in P6/security (M7), built integral to the service.
- **Conformance:** the DDS durability semantics are conformant; the service is the standard delivery mechanism.
  The multi-service/supervisor/thread-or-process/CLI/pluggable-persistence/CNSA-2.0-DARE are value-adds ON TOP
  of the conforming behavior (operating-contract extension rule).
- **Contract:** `REQUIREMENTS.md` §1.2/§13 and `CLAUDE.md` §1/§10 are amended to reflect this (the durability
  service moves in-scope; the rest of the suite stays out). Crypto remains vetted-library-only (§9).
- **Security posture:** the always-on DARE means the persistence layer never writes plaintext; key management
  (CNSA-2.0 ML-KEM-wrapped keys) and a pluggable KMS hook are part of the service spec.
