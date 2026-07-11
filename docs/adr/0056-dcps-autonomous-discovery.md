# ADR 0056 — Autonomous background discovery: the per-participant announcer thread

Status: Accepted
Date: 2026-07-11
Work package: WP-DCPS-API-COMPLETION Slice S7, task S7.T1 (the autonomous-discovery announcer; T2 SEDP-on-create/delete + T3 thread-lifecycle are substantively exercised by the same path, explicit tests + live interop to follow)
Relates to: the manual `spin` discovery drive (this ADR makes it optional); the S4 deadline monitor (ADR 0054 — this reuses its exact per-participant background-thread lifecycle: `dds.pal:spawn` + lock/cv/running + stop-and-JOIN on delete); the disc-node receiver thread (inbound discovery, already autonomous)

## 1. Context

Discovery was **caller-driven**: the application had to call `dds.dcps:spin` in a loop to drive each
SPDP + SEDP announce + the lease/liveliness/autopurge sweeps (`announce-participant` +
`announce-endpoints` + `%writer-liveliness-sweep` + `%autopurge-sweep`). Inbound discovery (SPDP/SEDP
receive + matching) already ran autonomously on the disc-node's receiver thread; only the periodic
**announce + aging drive** was manual. `spin`'s own docstring named the blocker: "an automatic
background announcer with isolated send buffers is a follow-up (the engine's announce buffers are not
yet thread-isolated)." In fact the send buffers were already **role-separated** — `tx-msg`/`tx-payload`
(announce), `rx-tx-msg` (receiver), `async-tx-msg` (async sender) — so the only requirement is that a
single driver own the announce buffers at a time.

## 2. Decision

Add an opt-in **autonomous discovery mode** (`create-participant :autonomous t`; a `dp-autonomous-p`
participant slot). When set, a per-participant **auto-announcer** background thread
(`src/dds-dcps/autodiscovery.lisp`) periodically drives `%spin-once` (the extracted spin body), so the
participant discovers, matches, ages, and exchanges data with **no** app-driven `spin`.

- **Lifecycle = the S4 deadline-monitor pattern, verbatim.** `auto-announcer` = lock + cv + `running`
  flag + `period-seconds`. Spawned by `%start-auto-announcer` (idempotent; only when autonomous +
  enabled + not already running) from both `create-participant` (post-`start-node`) and `enable` (so a
  participant enabled later starts then). Stopped by `%stop-auto-announcer` in `delete-participant`
  **before** `stop-node` / node teardown: sets `running` NIL + signals the cv **under the lock** (no
  lost wakeup), then **joins** — the in-flight `%spin-once` completes before the node/buffers it uses are
  freed (no strand, no use-after-free). The announcer shares the participant's one lazy-thread-creation
  lock (`dp-deadline-lock`) — it and the deadline monitor never contend (both one-shot creations).
- **The loop** announces first (a fresh autonomous participant advertises promptly), then waits on the cv
  for `period-seconds` (default 1 s ≈ the SPDP cadence), re-checking `running` on each wake. Each
  `%spin-once` is guarded (`handler-case`) so a transient send error (a wedged socket) does not kill
  autonomous discovery — the next cycle retries.
- **`spin` is a NO-OP in autonomous mode.** The announcer owns `tx-msg`/`tx-payload`, so a concurrent
  `spin` would race them; an autonomous participant needs no `spin`. `spin` stays the deterministic
  manual/test path for non-autonomous participants (byte-identical — it just calls `%spin-once`).

## 3. Consequences

- **Additive + opt-in.** `:autonomous` defaults NIL → byte-identical, spin-driven behaviour; no thread is
  spawned for a non-autonomous participant. The wire (SPDP/SEDP content) is unchanged — only the *cadence
  driver* moves from the app thread to a background thread (the same announce calls, on a timer).
- **Concurrency.** The announcer runs the same announce/sweep logic `spin` did, now concurrently with the
  receiver thread (already the case for `spin` vs receiver) and the app thread. Announce buffers are
  single-driver (spin no-ops when autonomous). The DCPS sweeps + `announce-endpoints` reads of the local
  endpoint set run under the same node/participant locks the receiver path uses; the deadline monitor
  already established that a per-participant background thread touching entity state under locks is safe.
- **Verified.** `run-dcps-autonomous-discovery-test`: two `:autonomous` participants MATCH and exchange
  data with **no** `spin`, and the announcer threads stop + join cleanly on delete (554/554 both impls;
  gate-hotpath + gate-types green). This also exercises T2 (autonomous end-to-end pub/sub, zero spin) and
  T3 (clean create→delete thread teardown — the full suite passing proves no strand/leak).
- **Cost.** One `dds.pal:spawn`'d thread per autonomous participant, waking once per `period-seconds` to
  run the same announce/sweep work `spin` did — control plane, not the measured hot path.

## 4. Remaining (S7 exit gate, checkpointed)

- An explicit T3 thread-lifecycle test (create/enable/delete cycles leave no live threads — a stronger
  assertion than the implicit teardown above).
- A killed-participant-ages-out test (a short announced lease so the peer's `%lease-sweep`, now
  announcer-driven, prunes it observably).
- Live interop vs Connext 7.3.1 + Fast DDS (the SPDP/SEDP announce cadence on the wire — the one wire
  surface, though the announce content is unchanged from the spin path).
- Configurable `period-seconds` / lease via QoS (default 1 s today).

## 5. Alternatives considered

- **Lock the announce buffers so spin and the announcer can coexist.** Rejected as unnecessary
  complexity: autonomous mode replaces spin by design; a lock per announce cycle buys nothing and adds
  contention. `spin` no-op is simpler and clearer.
- **One shared announcer thread for all participants.** Rejected: a per-participant thread mirrors the
  deadline monitor, keeps teardown a clean per-participant join, and avoids a global structure keyed by
  participant — consistent with the rest of the stack's per-node/per-participant threading.
