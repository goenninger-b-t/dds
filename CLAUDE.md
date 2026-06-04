# CLAUDE.md — Common Lisp DDS/RTPS Stack (XCDR-based, Connext-class core)

This file is the operating contract for every Claude Code session on this repository. Read it fully, then read the two authoritative specs before doing anything else.

---

## 1. Project goal

Build, in Common Lisp, a **data-centric publish/subscribe middleware** implementing **OMG DDS 1.4** on the **OMG DDSI-RTPS 2.5** wire protocol with **OMG XCDR (1 + 2)** as the foundational serialization, that **interoperates on the wire with RTI Connext 7.x** and approaches **Connext-class median performance**. CLOS is preferred wherever it costs nothing; the **measured hot path** is `defstruct` + monomorphized code generation + manual vtables, with all hot-path memory drawn from a **static, startup-allocated, non-GC'd arena** sized by `*static-arena-bytes*`. Targets: **SBCL, AllegroCL, Clasp** (Linux-first).

**Scope is the core libraries + high-value differentiators** (FlatData-equivalent, Zero-Copy/SHMEM, batching, async+flow-control, content-filtered topics, durability, security). The Connext *Professional* **service suite** (Routing/Recording/Persistence/Cloud-Discovery/Admin-Console/Monitor) is **out of scope** here — do not start building services; do not let the architecture preclude them.

---

## 2. Authoritative specifications — READ BEFORE ACTING

Two files in this repo are the single source of truth. **At the start of every session, read both in full** (they are large; that is intentional — do not skim, do not work from this summary alone):

- **`REQUIREMENTS.md`** — *what* and *how well*. Functional + non-functional requirements, conformance profiles P0–P7, the QoS/RTPS/XTypes/CDR detail, the performance targets, the CLOS policy, the static-memory rules, acceptance criteria, the verification matrix, and the open decisions.
- **`IMPLEMENTATION-PLAN.md`** — *how* and *in what order*. Layered architecture (L0–L9), ASDF module layout, the **subagent orchestration model (§3)**, the **contract sketches (§7)**, the phased roadmap M0–M8 with exit gates, the work-package breakdown, the testing/perf/IP strategy, and the risk register.

**Precedence:** if the two ever conflict, `REQUIREMENTS.md` wins; flag the conflict and open an ADR. If reality contradicts a spec, **do not silently diverge** — record it and propose the change. (If you prefer guaranteed inclusion over leanness, these may be `@`-imported here; default is on-demand read to keep base context small.)

---

## 3. Operating mode — `ultracode` (xhigh effort + auto-orchestrated workflows)

This session pins **xhigh effort** and **auto-fans work out to parallel subagents**. That power is the main risk, not the main benefit. Govern it as follows:

1. **Contract-first, always. Freeze before you fan out.** The single highest-leverage rule: **do not spawn parallel implementation work until the M0 interface contracts are frozen** (`IMPLEMENTATION-PLAN.md` §3.2, §7: `DDS.PAL`, `DDS.CORE.BUFFER`, `DDS.CDR`, the `type-support` shape, the transport record, the `DDS.RTPS.HISTORY` protocol, `DDS.CORE.ARENA`). Auto-orchestration that fans out against unfrozen interfaces parallelizes *churn* and you pay for the rework twice. Hold the fan-out until M0 is green.
2. **Objective ranking is fixed.** Correctness, security, and stability are **binary gates** — they pass or the work is not done. Performance is the **measured optimization target**. "Shortest time" is a *consequence* of eliminating rework (contracts + gates), **never** a license to skip a gate or guess. Optimize the schedule by not redoing work, not by typing faster.
3. **Plan, then build.** For any non-trivial task, produce a short plan first (mirror the three-phase explore→plan→implement pipeline). Map auto-spawned subagents onto the **work packages and agent roles in `IMPLEMENTATION-PLAN.md` §3**, not an ad-hoc decomposition.
4. **One milestone at a time.** Follow the M0→M8 sequence. Do not begin a milestone until the prior milestone's exit gate passes. Do not pull P4 performance work forward over P0–P2 correctness.
5. **Spend deep reasoning where it pays.** Use `ultrathink` on the genuinely hard sub-problems: the RTPS reliable writer/reader state machines and HEARTBEAT/ACKNACK/GAP timing; XCDR1↔XCDR2 alignment and extensibility (the 8-byte-alignment divergence); SequenceNumberSet bitmap edge cases; lock-free queue memory ordering and fences; the static-arena exhaustion/backpressure paths; type assignability. Do not burn it on boilerplate.

---

## 4. Non-negotiable constraints (distilled — full text in the specs)

- **CLOS policy / hot-path purity** (`REQUIREMENTS` FR-LANG-0, NFR-CLOS). CLOS is the preferred default everywhere it shows no measured cost. The **hot path is CLOS-free**: no `defgeneric`/`defmethod` dispatch and **no per-sample object instantiation** in the CDR primitives, generated codecs, buffer/cursor, `CacheChange`/`SampleInfo`, or the engine's per-sample type dispatch. Those use `defstruct` + monomorphic functions + manual vtables (`defstruct` of closures). The CI `hotpath-purity-gate` enforces this.
- **Static, non-GC'd memory on hot paths** (`REQUIREMENTS` NFR-MEM). All hot-path buffers/pools come from an **off-heap/foreign arena allocated once at startup**, sized by the special variable **`*static-arena-bytes*`** (read once at init; rebinding later is a no-op until teardown). **Anything addressed by a raw pointer/SAP is foreign/static, never a plain heap array** (SBCL & Allegro GCs move objects; this is the only cross-impl-stable representation). **Arena exhaustion → RESOURCE_LIMITS (reject/backpressure), never a silent GC-heap fallback.** Steady state allocates **zero** bytes/sample.
- **Never hardcode wire constants from memory.** RTPS PIDs, encapsulation-representation identifiers, builtin EntityIds, the keyhash rule, XCDR alignment rules — **read them from the spec clause and verify against byte-exact vectors / live Connext captures.** A wrong constant from memory is the most common and most expensive bug class here. Cite the clause in a comment.
- **Bounds-check every network-facing parser, even in `(safety 0)`** (`REQUIREMENTS` NFR-SEC-POSTURE). Validate lengths/offsets against buffer extents before trusting wire data. A malformed RTPS submessage must never cause OOB access. Resource-exhaustion guards (max fragments, max reassembly bytes, max instances) are mandatory. The fuzz gate proves it.
- **Clean-room IP** (`REQUIREMENTS` NFR-IP). Implement from the OMG specs. **Never copy, decompile, or paste RTI Connext source, headers, or `rtiddsgen` output.** Reading Apache-2.0 (Fast DDS) / EPL-EDL (Cyclone) / OpenDDS for understanding is allowed, but copying imports their license — record provenance in `docs/provenance.md`. FlatData/Zero-Copy mechanisms need **legal review before P4 ships** (patent risk).
- **The wire is the oracle.** Correctness is established by **XCDR byte-exactness** against reference vectors and by **Connext interop** validated with the Wireshark/tshark RTPS dissector — not by "it looks right." Build the byte-exact CDR corpus and the interop harness *first*.

---

## 5. Definition of Done

A unit of work is **done** only when **all** hold:
- Code compiles and unit tests pass on **SBCL and AllegroCL** (Clasp too, or a documented gap per NFR-PORT — Clasp may trail one profile).
- All applicable **quality gates green** (§6).
- The interface contract is **unchanged**, or the change is captured in an **ADR** (`docs/adr/NNNN-*.md`) listing every consumer + migration.
- **Docs updated**: the verification matrix (`docs/verification.csv`), provenance log if external sources were consulted, and any affected spec cross-reference.
- For any **hot-path** change: a **before/after bench number** in `bench/report/` (no perf change lands on intuition — `REQUIREMENTS` FR-LANG-7).
- No new reader conditionals (`#+sbcl`/`#+allegro`/`#+clasp`) outside `dds-pal/` (CI lint enforces this).

A **milestone** is done only when its exit gate in `IMPLEMENTATION-PLAN.md` §4 passes (e.g., M2 = Connext Shapes interop both directions, reliable + best-effort, tshark-validated).

---

## 6. Quality gates (must be green before "done"; wire these in M0)

Create these as `make` targets (or scripts) in M0 and keep them green thereafter. Underlying mechanism is ASDF test ops run per implementation.

```
make build        # load all systems on SBCL, AllegroCL, Clasp; fail on any warning promoted to error
make test         # asdf:test-system across all landed systems, each impl
make corpus       # XCDR byte-exact conformance vectors (gates P0) — both endiannesses, all extensibility kinds
make gate-hotpath # hotpath-purity-gate: fail if CLOS dispatch / per-sample alloc in hot-path packages
make fuzz         # fuzz the CDR decoder + RTPS submessage parser (+ replay real Connext captures)
make interop      # Connext 7.x + one of {Fast DDS, Cyclone, OpenDDS}; validate wire with tshark
make bench        # perftest-equivalent: latency p50/p99/p99.99/max, throughput, alloc counters, per-pool high-water
make mem          # assert hot-path workload runs entirely from the static arena, no heap fallback, high-water < budget
```

Per-impl invocation pattern (adapt exact flags in M0):
- SBCL: `sbcl --non-interactive --eval '(asdf:test-system :dds-cdr)'`
- AllegroCL: `mlisp -batch -e '(asdf:test-system :dds-cdr)' -kill`  *(confirm exact batch flags for the installed Allegro)*
- Clasp: `clasp --non-interactive --eval '(asdf:test-system :dds-cdr)'`

---

## 7. Per-task workflow loop

For each task an agent picks up:
1. **Read** the relevant spec sections (don't reconstruct from memory).
2. **Plan** (explore→plan→implement); if it touches a frozen contract, write the **ADR first** and get it accepted.
3. **Implement** against the frozen contracts and the mocked dependencies (mocks exist from M0 so you never block on a missing dependency).
4. **Test** on all three impls (or document the Clasp gap).
5. **Run the gates** in §6 that apply.
6. **Bench** if the change is on the hot path; paste the before/after into `bench/report/`.
7. **Update** the verification matrix / docs / provenance.
8. **Commit** with a message referencing the WP id and the requirement id(s).

---

## 8. Subagent orchestration (see `IMPLEMENTATION-PLAN.md` §3 for the authority)

Roles: **A0 Architect/Integrator** (owns contracts, ADRs, gates — the only role that edits interface packages), A1–A3 **PAL/{SBCL,Allegro,Clasp}**, A4 **CDR**, A5 **type compiler/gen**, A6 **RTPS engine**, A7 **discovery**, A8 **DCPS**, A9 **transports**, A10 **perf/features+bench**, A11 **interop/QA+fuzz**, A12 **security (late)**, A13 **docs**.

Rules: **no agent edits another agent's package** (file an issue or open a contract ADR via A0). After the M0 freeze, A1–A5 and A11 run in parallel; A6/A8 start against mocks. Keep `main` green for all *landed* profiles on every merge. Subagents inherit these constraints — restate the hot-path-purity, static-arena, no-hardcoded-constants, and bounds-check rules in any subagent prompt.

---

## 9. Build / dev environment

- **Lisps:** SBCL (latest + one prior), AllegroCL (the licensed build), Clasp (recent). 64-bit, Linux-first.
- **Load-bearing dependencies** (pin versions; vendor anything on the hot path): `static-vectors` (foreign-backed octet buffers), `bordeaux-threads` + a portable `atomics` CAS layer (with per-impl native fast paths in the PAL), `cffi` (sockets `recvmmsg`/`sendmmsg`/iovec, SHMEM, crypto FFI), `usocket` or `sb-bsd-sockets` for the baseline, an LZ4 binding (P4), `ironclad`/libsodium/OpenSSL (P6 security only). Justify every new dependency.
- **Dependency manager:** ASDF + a lockfile (qlot or vendored). Reproducible builds.

---

## 10. Never do

- Never spawn parallel implementation fan-out before the M0 contracts are frozen.
- Never put CLOS dispatch or per-sample object allocation on the hot path.
- Never allocate hot-path buffers on the GC heap, and never silently fall back to the heap on arena exhaustion.
- Never hardcode an RTPS/XCDR wire constant from memory — read the clause, verify against vectors.
- Never trust wire data without bounds-checking, even in `(safety 0)`.
- Never copy RTI Connext source/headers/generated code.
- Never start a Connext *Professional* service (Routing/Recording/Persistence/etc.).
- Never land a performance change without a before/after measurement.
- Never mark work done with a red gate or a skipped interop/byte-exact check.
- Never put reader conditionals outside `dds-pal/`.

---

## 11. Milestone sequence (exit gates in `IMPLEMENTATION-PLAN.md` §4)

`M0` contracts+skeleton+CI · `M1` P0 XCDR byte-exact + real PALs · `M2` P1 minimal RTPS + **Connext Shapes interop** · `M3` P2 DCPS+QoS+conditions+content-filter · `M4` P3 XTypes+TypeLookup+assignability · `M5` P4 batching/async/SHMEM/Zero-Copy/FlatData/LZ4 + bench parity · `M6` P5 durability/late-joiner · `M7` P6 security (gated) · `M8` P7 tooling/services (gated, mostly out of scope).

Start at M0. Do not jump ahead.
