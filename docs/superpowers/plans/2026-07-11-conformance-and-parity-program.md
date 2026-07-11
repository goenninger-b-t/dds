# WP-CONFORMANCE-AND-PARITY — the program that closes every open item

Owner-directed, 2026-07-11. Base: `main = 3940f50` (562/562 both impls, gates green).
Goal: implement every still-missing feature and clean up every open item, in the order that reaches
completion **fastest at the highest quality and performance**, with **live QA against RTI Connext 7.3.1
AND eProsima Fast DDS** on every item that has a wire surface.

This plan is the output of an audit against `REQUIREMENTS.md` + `docs/verification.csv`, not against memory.

---

## 0. The three constraints that fix the ordering

1. **One open item can invalidate the project's headline goal, so it is measured before anything is
   optimized.** Every `NFR-PERF-1…9` target is a *ratio* against RTI Connext on identical hardware. That
   side-by-side run was never done — M5's "bench parity" exit gate is marked ✅ on absolute in-process
   loopback numbers only (`bench/report/2026-06-13-perftest-baseline.md` says so in its own limitations
   section). Until the ratio exists we do not know whether the performance track is *empty* or *enormous*.
   **Measuring it first is worth more than any feature.**
2. **Live interop runs are the scarce resource; batch them by WIRE SURFACE.** Bringing up both vendor
   peers, both directions, with the documented gotchas, costs far more than the code for a single QoS
   policy. Features sharing a wire surface are therefore built together and validated in ONE campaign.
3. **Some "gaps" are bookkeeping, not engineering.** 42 `verification.csv` rows still read `partial` and the
   roadmap says M7 "IN PROGRESS" while the shipped log says the P6 exit gate is met. The matrix is supposed
   to *be* the truth. Fix it early, cheaply, so nothing downstream is re-litigated.

**Critical path: WP-1 → WP-8.** Everything else schedules around it.

---

## Phase 0 — Measure, and make the record honest

### WP-1 · Connext performance parity (THE critical path) 🔴

The headline claim ("approaches Connext-class median performance") is **unverified**. Close that.

**RTI Perftest is NOT bundled with the Connext 7.3.1 install on this machine** (`$NDDSHOME/bin` has
rtiddsgen / rtiddsspy / rtiddsping, no perftest). Rather than adopt a foreign harness whose methodology
differs from ours, build ONE symmetric **echo ping-pong** protocol and implement it identically on both
stacks — that is what makes the ratio apples-to-apples:

- **pinger**: publish a sample stamped with `t0`, wait for the echo, record RTT; one-way := RTT/2.
- **responder**: on receipt, immediately republish the sample verbatim.
- Identical topic/type/QoS (RELIABLE, KEEP_LAST 1, VOLATILE), identical payload ladder, identical warmup,
  identical percentile computation, identical clock source (`dds.pal:monotonic-ns` ↔ `clock_gettime`).

**Tasks**
- **T1** Our side: cross-process echo pinger/responder (`dds.bench`), on the real wire — the existing
  `run-latency` is an *in-process* pair and cannot be compared to a foreign stack.
- **T2** Connext side: C++ pinger/responder (`interop/perftest/connext/`), same protocol, same QoS.
  Clean-room: written from the Connext public API against our own protocol — no RTI source copied.
- **T3** Fast DDS side: same, `interop/perftest/fastdds/` (a second reference point; the *target* is
  Connext, per REQUIREMENTS §7).
- **T4** Run the matrix: **ours↔ours**, **Connext↔Connext** (the reference), **ours↔Connext** (cross —
  also proves interop *under load*). Payloads 32 B / 256 B / 1 KB / 4 KB / 16 KB / 64 KB; UDPv4 loopback +
  LAN; SHMEM where both stacks support it. Latency p50/p99/p99.99/max + throughput (samples/s, Mb/s).
- **T5** The **NFR-PERF ratio table**: one row per NFR-PERF-1…9, target band, measured ratio, PASS/FAIL.
  Plus allocation counters (NFR-PERF-8: 0 bytes/sample) and static-arena high-water (NFR-MEM).

**Exit gate:** every NFR-PERF row carries a **measured ratio against Connext**, PASS or FAIL, published in
`bench/report/`. A FAIL is an acceptable outcome of this WP — an *unmeasured* row is not.
`REQUIREMENTS.md` itself predicts NFR-PERF-3 (p99.99 jitter) is the likeliest failure, on GC-tail risk. If
so, that is a **finding**, not a defeat: it scopes WP-8.

### WP-2 · Verification-matrix + roadmap truth-up 🟢
Cheap, no code, runs while WP-1's binaries build. Walk all 42 `partial` rows: flip what is done, keep what
is not, and say *why* for each. Reconcile the roadmap's M7 status with the shipped log. **The matrix must
stop lying**, or every future audit re-derives it from scratch (as this one had to).

---

## Phase 1 — The wire-surface QoS gaps, in ONE interop campaign

Four policies, one shared wire surface (SEDP/SPDP parameters + builtin-topic data) ⇒ built together,
validated once. **Every PID pinned from the spec clause, never from memory** (the most expensive bug class
in this repo).

### WP-3 · USER_DATA / TOPIC_DATA / GROUP_DATA 🟡
Three octet-blob policies, propagated in builtin-topic data. Absent entirely today (they exist only as
access-control strings and policy-id constants). QoS slots → SEDP/SPDP parameters → surfaced by the
builtin-topic readers.

### WP-4 · DURABILITY_SERVICE QoS 🟡
The durability *service* is built (ADR 0021); the QoS policy that *configures* it (history kind/depth,
resource limits) is not. Propagated in `PublicationBuiltinTopicData`.

### WP-5 · TIME_BASED_FILTER 🟡
Not modeled at all today — only a policy-id constant exists. Reader-local `minimum_separation` enforcement,
**plus** the §2.2.3 consistency rule against DEADLINE that S1 honestly recorded as omitted ("policy not
modeled"). Closes that recorded gap.

**Interop campaign A** (one sitting, both vendors, both directions): our policies appear in *their* builtin
topics; *their* policies appear in ours; TIME_BASED_FILTER visibly thins a fast foreign writer's stream.
Recipes + the three known gotchas (Connext on the LAN iface; Fast DDS loopback-only ⇒ `PEERS=127.0.0.1:7410`;
`REP=xcdr1` on outbound legs, because a stock vendor reader advertises XCDR1-only and DATA_REPRESENTATION is
RxO) are already documented in `interop/autodiscovery/README.md`.

---

## Phase 2 — PRESENTATION: the one with real semantics

### WP-6 · coherent_access + ordered_access 🔴
Today the flags are carried, RxO-checked and immutability-checked, but **never enforced** — plumbing without
semantics. This is the largest genuine feature left:
`begin_coherent_changes`/`end_coherent_changes` (Publisher), `begin_access`/`end_access` (Subscriber), the
coherent-set wire representation, and GROUP-scoped ordering.

It touches the reliable engine and the durability replay path, so it gets its own slice, its own adversarial
review, and its own interop campaign (**B**) — deliberately *not* sharing a blast radius with Phase 1.

---

## Phase 3 — Build the gate that does not exist

### WP-7 · `make corpus` (FR-CDR-8) + a real `make interop` 🟡
`make corpus` is an **`echo` stub** — and it is the **P0** gate in the operating contract §6. `FR-CDR-8`
reads `not-started`. **`rtiddsgen` IS available on this machine**, so the blocker is gone: generate the RTI
reference vectors for the corpus types, commit them as locked byte-exact vectors, and make `make corpus`
actually gate XCDR1/XCDR2 byte-exactness in both endiannesses across every extensibility kind.
`make interop` is likewise an `echo` deferring to `wire`; wire it to the real cross-vendor harness.

---

## Phase 4 — Performance work, scoped BY WP-1's numbers

### WP-8 · Close whatever the parity table says is off-target 🔴
**Deliberately unspecified until measured.** Writing it more precisely now would be guessing, and guessing is
how a performance track becomes infinite. Likely candidates in REQUIREMENTS' own order of risk: p99.99 jitter
(GC tail → arena/pre-alloc audit on the measured path), then throughput levers (batching + async flow control
already exist and would need *tuning*, not building). Re-run WP-1's matrix as the exit gate.

---

## Phase 5 — Portability (owner-gated) 🟢

### WP-9 · AllegroCL, the third PAL
The Definition of Done requires SBCL **and** AllegroCL; everything to date has landed against 2 of 3
(Clasp + SBCL). **Blocked on the licensed build being installed** — cannot start without the owner.

---

## Parallel track (no dependencies; fills the gaps while interop/bench runs execute)

### WP-10 · XTypes serializer edges 🟡
Unions, MUTABLE structs, `TK_NONE` base, sequence edges are all still **provisional** in the XCDR2 TypeObject
serializer (the README says so). Validate against live vendor TypeObjects (both stacks emit them).

---

## Sequencing

| Phase | Work packages | Depends on | Live QA |
|---|---|---|---|
| **0** | **WP-1 parity run** · WP-2 matrix truth-up | — | Connext (echo harness) |
| **1** | WP-3 + WP-4 + WP-5 (batched) | WP-2 | **Campaign A** — both vendors |
| **2** | WP-6 PRESENTATION | Phase 1 | **Campaign B** — both vendors |
| **3** | WP-7 corpus + interop gates | — (rtiddsgen present) | byte-exact vs RTI vectors |
| **4** | **WP-8 perf** | **WP-1** | Connext (re-run the matrix) |
| **5** | WP-9 AllegroCL | owner: licensed build | full suite × 3 impls |
| **∥** | WP-10 XTypes edges | — | both vendors |

**Critical path: WP-1 → WP-8.** WP-1 goes first *even though it produces no feature*, because it is the only
item that can invalidate a headline requirement, and because its result determines whether Phase 4 is empty
or dominant.

---

## Scope decisions recorded

- **MultiTopic (DCPS §2.2.2.3.4) — OUT.** RTI does not implement it either, so there is no peer to
  interoperate with and no way to QA it live against either vendor. Recording the decision rather than
  silently omitting it. Reopen on owner request.
- **DLRL, Connext Professional services (Routing/Recording/Cloud-Discovery/Admin-Console/Monitor) — OUT** by
  the operating contract (the durability service remains the sole in-scope service, ADR 0021).
- **Owner-only, unscheduled here:** patent B1 (ZC/FlatData counsel — the LAST activity per standing
  directive) and the two eProsima upstream reports (outward-facing, drafts filing-ready).

## Definition of done, program-wide

Every WP: green on **Clasp AND SBCL** (Clasp first); `gate-hotpath` + `gate-types` green; **live interop
against BOTH vendors** for anything with a wire surface; a before/after **bench number** for anything on the
hot path; ADR for any contract change; docs (docstrings + `docs/wiki/` + README) and `verification.csv` in
lockstep; commit message presented for approval before landing.
