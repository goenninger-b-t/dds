# IMPLEMENTATION PLAN — NeoDDS (Common Lisp DDS/RTPS Stack, XCDR-based)

**Companion to:** `REQUIREMENTS.md` (read first). **Tone:** normative, sequencing-focused.
**Method:** subagent-driven, contract-first. **Targets:** SBCL, AllegroCL, Clasp.

> This plan is written so that autonomous coding subagents can each own a work package with minimal coupling. The governing rule is **contract-first**: inter-layer interfaces are frozen by the Integrator before parallel work begins; changes flow through ADRs.

---

## 1. Architectural overview

Strict bottom-up layering. Each layer depends **only** on the contract of the layer below. Nothing above L0 contains implementation-conditional code.

```
L9  API & Tooling        Lisp API, Modern-C++-shaped API, gen, spy, monitoring hooks   [Request/Reply+RPC: OUT OF SCOPE this release, ADR 0094]
L8  Advanced features    Batching, async+flow-control, Zero-Copy/SHMEM, FlatData-equiv, compression, durability, security
L7  Transports           UDPv4/v6, SHMEM, TCP — all via the pluggable transport record
L6  DCPS                 Entities, QoS+RxO, conditions/WaitSets, instances, read/take, content filters
L5  Discovery            SPDP, SEDP, participant liveliness, builtin endpoints
L4  RTPS engine          Stateful/stateless writer+reader, reliability (HB/ACKNACK/GAP), fragmentation, HistoryCache, submessage codec
L3  Type system + gen    XTypes model, TypeObject/TypeIdentifier, type compiler → defstruct + monomorphic codecs + type-support
L2  CDR codec            XCDR1 + XCDR2 (PLAIN/DELIMITED/MUTABLE), encapsulation, alignment, endianness
L1  Core runtime         Static arena + octet buffers + cursors, object pools, time/clock, scheduler/timers, lock-free queues, byte-order ops
L0  PAL (per-impl)       Raw memory/SAP, atomics/CAS/fences, native threads, sockets (incl. recvmmsg/sendmmsg), GC control, opt hints
```

**Data-plane principle (governs every layer):** the steady-state path from `write()` to wire and from wire to `read()` does **no heap allocation** (no consing, no per-sample CLOS instantiation) — all hot-path memory is drawn from a static, startup-allocated, non-GC'd arena sized by the special variable `*static-arena-bytes*` (REQUIREMENTS NFR-MEM); performs the **minimum copies** (ideally zero for SHMEM/FlatData), and on the per-sample path dispatches via **slot-read + funcall** (manual vtable), not generic functions. **Off the hot path, CLOS is permitted and preferred** (entity model, QoS, listeners, conditions, discovery, tooling) wherever it shows no performance degradation. Everything in the design exists to protect that path; the CLOS/defstruct boundary is set by measurement (REQUIREMENTS FR-LANG-0 / FR-LANG-7).

---

## 2. Repository & module layout (ASDF)

```
dds/                      (umbrella)
  dds-pal/                L0 — files guarded by #+sbcl / #+allegro / #+clasp; ONE shared contract package
    src/pal-contract.lisp     (the frozen API: package DDS.PAL, all functions declared here)
    src/pal-sbcl.lisp
    src/pal-allegro.lisp
    src/pal-clasp.lisp
  dds-core/               L1
  dds-cdr/                L2   (depends: dds-core)
  dds-types/              L3   (depends: dds-cdr)         — runtime type machinery
  dds-gen/                L3   (depends: dds-types)       — the IDL/s-expr compiler (build-time tool)
  dds-rtps/               L4   (depends: dds-cdr, dds-core)
  dds-disc/               L5   (depends: dds-rtps, dds-types)
  dds-dcps/               L6   (depends: dds-rtps, dds-disc, dds-types)
  dds-xport-udp/          L7   (depends: dds-rtps via transport record)
  dds-xport-shmem/        L7
  dds-xport-tcp/          L7
  dds-feat-batching/      L8
  dds-feat-async/         L8
  dds-feat-zerocopy/      L8   (depends: dds-xport-shmem)
  dds-feat-flatdata/      L8   (depends: dds-gen, dds-cdr)
  dds-feat-compress/      L8
  dds-feat-durability/    L8
  dds-security/           L8   (gated; depends: dds-pal FFI to libsodium/openssl)
  dds-api/                L9
  dds-rpc/                L9   -- NOT BUILT THIS RELEASE (FR-API-3 deferred, ADR 0094)
  dds-tools-spy/          L9
  dds-tests/  dds-bench/  dds-interop/   (cross-cutting test/bench/interop systems)
```

**Conditional-compilation rule (MUST):** `#+sbcl|#+allegro|#+clasp` reader conditionals appear **only** inside `dds-pal/` and (rarely, with an ADR) inside `dds-bench/`. A CI lint fails the build on any reader conditional elsewhere.

---

## 3. Subagent orchestration model

The work is decomposed so that, after an initial contract-freeze phase, **6–10 agents work in parallel** with weekly integration. Coupling is pushed into frozen interface packages; agents touch only their package + the contracts they consume.

### 3.1 Agent roles

| Agent | Owns | Primary outputs |
|-------|------|-----------------|
| **A0 — Architect/Integrator** (lead) | All contracts, ADRs, integration, the verification matrix, release gates | Frozen interface packages; merges; gate sign-off |
| **A1 — PAL/SBCL** | `pal-sbcl.lisp` | SAP buffers, atomics, sockets, GC hooks, vops for endian/memcpy |
| **A2 — PAL/Allegro** | `pal-allegro.lisp` | `sys:memref` buffers, native atomics+`mp:`, sockets, `gsgc` hooks |
| **A3 — PAL/Clasp** | `pal-clasp.lisp` | CFFI/clbind buffers, `mp:`/std::atomic, sockets, Boehm/MPS tuning; optional C++ hot-codec |
| **A4 — CDR codec** | `dds-cdr/` | XCDR1/2 encode/decode, encapsulation, conformance corpus |
| **A5 — Type compiler** | `dds-types/`, `dds-gen/` | IDL/s-expr → defstruct+codecs+TypeObject+keyhash+type-support |
| **A6 — RTPS engine** | `dds-rtps/` | submessage codec, writer/reader state machines, reliability, fragmentation, HistoryCache |
| **A7 — Discovery** | `dds-disc/` | SPDP/SEDP, liveliness, builtin endpoints |
| **A8 — DCPS** | `dds-dcps/` | entities, QoS+RxO, conditions/WaitSets, read/take, content filters |
| **A9 — Transports** | `dds-xport-*` | UDP/SHMEM/TCP behind the transport record |
| **A10 — Perf/Features** | `dds-feat-*`, `dds-bench/` | batching, async/flow, zero-copy, flatdata, compression, the perftest harness |
| **A11 — Interop/QA** | `dds-interop/`, `dds-tests/fuzz` | Connext+open-peer interop matrix, Wireshark CI, fuzzing |
| **A12 — Security** (late) | `dds-security/` | the five SEC plugins |
| **A13 — Docs** | `/docs`, API ref | glossary, ADR log, user guide |

A single human (or a single orchestrating agent) MAY hold several roles in early phases; the **contracts** are what enable later fan-out, not the headcount.

### 3.2 Contract-first protocol (the thing that makes parallelism safe)

1. **A0 freezes the L0–L4 interface packages in M0** (signatures + docstrings + invariants + a stub/mocked impl). These are: `DDS.PAL`, `DDS.CORE.BUFFER`, `DDS.CDR` (the codec protocol), the **`type-support` struct shape**, the **transport record shape**, and the **HistoryCache protocol**. See §7.
2. Each agent codes against frozen contracts + the mocked deps, with its own unit tests, **before** the real dependency exists.
3. Interface changes require an **ADR** (`/docs/adr/NNNN-*.md`) approved by A0; the ADR enumerates every consumer and the migration.
4. **Definition of Done (per WP):** code + unit tests green on all three impls (or documented Clasp gap) + contract unchanged-or-ADR'd + docs updated + entry in verification matrix.
5. **Integration cadence:** weekly merge to `main`; a green `main` requires the full conformance suite for all *landed* profiles to pass.
6. **No agent edits another agent's package** without a cross-cutting ADR; bugs in a dependency are filed, not patched in place.

### 3.3 Parallelism map (what can run concurrently)

- After M0 freeze: **A1/A2/A3 (PALs), A4 (CDR), A5 (types/gen)** run fully in parallel against contracts.
- A6 (RTPS) starts against the **mock transport + mock type-support**, so it does not wait for A9 or A5.
- A8 (DCPS) starts against a **mock RTPS engine** exposing the writer/reader/HistoryCache protocol.
- A11 (interop/QA) builds the harness against mocks and the Shapes type early, so interop tests exist *before* the engine is real.
- A10 features and A12 security are the natural tail; they consume stable lower layers.

---

## 4. Phased roadmap (milestones & exit criteria)

Effort is expressed in **sequence and dependency**, not calendar dates (calendar depends on agent throughput, which is yours to set). Each milestone has a hard, demonstrable exit gate.

### M0 — Contracts, skeleton, CI (foundation)
- A0 freezes interface packages (§7); CI matrix (SBCL/Allegro/Clasp) green on the skeleton; `noclos-gate` lint live; ADR process live.
- PAL **contract** defined; each PAL has a *compiling stub* (real impls follow in M1).
- **Exit:** every ASDF system loads on all three impls; mocks let every upper layer compile; one trivial end-to-end "echo over a mock transport" test passes.

### M1 — P0 CDR + real PALs (the bedrock)
- A4 delivers XCDR1+XCDR2 byte-exact against the conformance corpus (both endiannesses, all extensibility kinds, optionals, DHEADER/EMHEADER).
- A1/A2/A3 deliver real buffers, atomics, sockets, GC hooks. PAL conformance tests pass on all three.
- A5 delivers the **s-expr type DSL → defstruct + monomorphic codec + key-hash + type-support**; round-trips through A4's codec.
- A11 stands up the fuzzer against the CDR parser and the (stub) submessage parser.
- **Exit (P0):** XCDR byte-exact vs. RTI-generated vectors; CDR fuzzer runs clean for N hours; generated `defstruct` types serialize/deserialize losslessly on all three impls.

### M2 — P1 Minimal RTPS interop (the credibility milestone)
- A6 delivers submessage codec + stateful reliable writer/reader + best-effort path + HistoryCache (KEEP_LAST/KEEP_ALL) + HEARTBEAT/ACKNACK/GAP + SequenceNumberSet.
- A7 delivers SPDP + SEDP + liveliness + builtin endpoints.
- A9 delivers UDPv4 unicast+multicast behind the transport record.
- A11: **first Connext interop** — exchange the Shapes type both directions, best-effort and reliable; validate every packet with the Wireshark RTPS dissector in CI.
- **Exit (P1):** publish from this stack → subscribe in Connext (and vice versa) for ShapeType, reliable and best-effort; tshark shows spec-conformant submessages; no parser crashes under the fuzzer with real Connext traffic replayed.

### M3 — P2 DCPS
- A8 delivers full entities, the QoS set + **RxO matching truth tables**, conditions/WaitSets, instance lifecycle, `read`/`take` with all selectors + SampleInfo, content-filtered topics + query conditions, builtin-topic readers.
- A0 wires DCPS onto the RTPS engine through the frozen protocols.
- **Exit (P2):** DCPS conformance suite green; content-filter interop with Connext (writer- and reader-side); RxO incompatibilities correctly block matches and raise statuses; WaitSet/condition semantics verified.

### M4 — P3 XTypes
- A5 delivers TypeObject/TypeIdentifier (Minimal+Complete), TypeLookup builtin endpoints, assignability + TYPE_CONSISTENCY_ENFORCEMENT, full annotation set, DynamicType/DynamicData (reflective, off hot path).
- **Exit (P3):** assignability matrix passes; remote type discovery via TypeLookup interoperates with a compliant peer (offline conformance now; Fast DDS under FR-IO-2) and type-compatibility assessment interoperates with Connext via its legacy TypeObject announcement (ADR 0010 — Connext does not implement the standard TypeLookup service); appendable/mutable evolution scenarios pass both directions.

### M5 — P4 Performance differentiators (the "Professional delta")
- A10 delivers, in this order: **batching** → **async + flow controllers** → **DATA_FRAG fragmentation pacing** (coordinated with A6) → **SHMEM transport** (A9) → **Zero-Copy-over-SHMEM** → **FlatData-equivalent binding** (A5 emits Offset/Builder) → **LZ4 compression**.
- A10 delivers the **perftest-equivalent harness** and the first parity report vs. Connext.
- **Exit (P4):** NFR-PERF-1,4,5,6,7,8 met on SBCL+Allegro; Zero-Copy and FlatData interop-validated with Connext where wire-compatible; pre-allocation mode shows **0 bytes/sample** steady-state (allocation counters) on SBCL+Allegro.

### M6 — P5 Durability/Reliability hardening
- A8/A6 deliver TRANSIENT_LOCAL durability + durable writer history + late-joiner correctness + large-data robustness + multi-channel writers.
- **Exit (P5):** late-joiner gets historical data per durability QoS, interop-validated; large-data + lossy-network soak passes; **program-level acceptance (REQUIREMENTS §9) achievable.**

### M7 — P6 Security (gated)
- A12 delivers the five SEC plugins atop PAL crypto FFI; secure discovery; AES-GCM protection.
- **Exit (P6):** secure interop with a Connext Security-enabled participant on a shared governance/permissions set. `(High-risk, high-effort; schedule only if required.)`

### M8 — P7 Tooling / optional services
- spy, gen polish (IDL parser), monitoring export. Services (Routing/Recording/Persistence) only if separately scoped (REQUIREMENTS §13).

---

## 5. Detailed work packages

Each WP: **Owner · Inputs · Outputs · Depends · Acceptance.** (IDs map to milestones.)

- **WP-PAL (A1/A2/A3, M0–M1).** In: PAL contract. Out: per-impl buffers/atomics/sockets/GC/opt-hints. Dep: contract. Acc: PAL conformance suite green per impl; microbench of buffer R/W and CAS within target of native C.
- **WP-CDR (A4, M1).** In: type-support shape, buffer API. Out: XCDR1/2 codec + corpus. Dep: WP-PAL buffers. Acc: FR-CDR-8 byte-exact; fuzz-clean.
- **WP-GEN (A5, M1→).** In: IDL/s-expr grammar, codec protocol, type-support shape. Out: compiler emitting defstruct+codecs+TypeObject+keyhash+FlatData accessors. Dep: WP-CDR. Acc: round-trip + assignability + (later) FlatData layout == wire.
- **WP-RTPS-MSG (A6, M2).** In: buffer API, codec. Out: submessage encode/decode + message framing. Dep: WP-CDR. Acc: tshark-validated; fuzz-clean against replayed Connext captures.
- **WP-RTPS-REL (A6, M2).** In: HistoryCache protocol, submessage codec. Out: stateful reliable writer/reader, HB/ACKNACK/GAP, SN sets, fragmentation. Dep: WP-RTPS-MSG. Acc: reliability correctness suite (loss/reorder/dup injected); Connext reliable interop.
- **WP-DISC (A7, M2).** In: RTPS writer/reader, type-support. Out: SPDP/SEDP/liveliness/builtins. Dep: WP-RTPS-REL. Acc: Connext discovers this stack and vice versa within NFR-PERF-9.
- **WP-XPORT-UDP (A9, M2).** In: transport record. Out: UDPv4 uni+multicast. Dep: WP-PAL sockets. Acc: interop; multicast control verified.
- **WP-DCPS (A8, M3).** In: RTPS+disc protocols, QoS structs. Out: entities/QoS/RxO/conditions/read-take/CFT. Dep: WP-RTPS-REL, WP-DISC. Acc: P2 suite + content-filter interop.
- **WP-XTYPES (A5, M4).** In: TypeObject machinery. Out: TypeLookup, assignability, DynamicData. Dep: WP-GEN. Acc: P3 suite + TypeLookup interop.
- **WP-BATCH / WP-ASYNC / WP-FRAGPACE / WP-SHMEM / WP-ZEROCOPY / WP-FLATDATA / WP-LZ4 (A10/A9/A5, M5).** Out: the §5.9 features. Dep: stable L4–L7. Acc: NFR-PERF gates + interop where applicable + 0-alloc steady state.
- **WP-DURABILITY (A8/A6, M6).** Out: TRANSIENT_LOCAL + durable history + late-joiner. Acc: P5 suite.
- **WP-PERFTEST (A10, M5).** Out: latency/throughput harness mirroring RTI Perftest scenarios. Acc: produces parity report vs. Connext on identical HW.
- **WP-INTEROP (A11, M2→).** Out: interop matrix automation + Wireshark CI + fuzz infra. Acc: matrix green per landed profile.
- **WP-SEC (A12, M7).** Out: SEC plugins. Acc: secure interop.
- **WP-API/SPY/DOCS (A9-A13, ongoing).** Acc: API stable; spy prints discovered traffic; docs current. **RPC interop is NOT an acceptance criterion this release** — FR-API-3 is out of scope (ADR 0094).

---

## 6. Per-implementation engineering notes (the L0 substance)

The PAL contract is impl-agnostic; the implementations differ sharply. `(C: high on SBCL specifics; moderate on Allegro/Clasp exact symbol names — verify against current vendor docs; treat symbol names below as the capability required, not a guaranteed spelling.)`

### 6.1 SBCL (pacesetter)
- **Buffers:** `static-vectors` (foreign-backed `(simple-array (unsigned-byte 8) (*))` with a stable SAP) for all wire I/O; `sb-sys:sap-ref-{8,16,32,64}` with explicit endianness; `sb-sys:with-pinned-objects` only where a Lisp object must survive a syscall. Avoid GC-moving buffers in I/O.
- **Atomics/concurrency:** `sb-ext:cas`, `sb-ext:atomic-incf`, `sb-thread:barrier`; `sb-concurrency` queues/mailboxes for SPSC/MPSC.
- **Sockets:** `sb-bsd-sockets` for the baseline; a thin CFFI shim for `recvmmsg`/`sendmmsg`/`sendmsg`-iovec and multicast socket options.
- **Codegen:** scoped `(declare (optimize (speed 3) (safety 0) (debug 0)))` on hot functions only; pervasive type declarations; `(declaim (inline …))`; `sb-ext:defglobal`/`define-load-time-global` for fast globals; `truly-the`; hand-written `define-vop` for byte-swap and small memcpy if profiling demands.
- **GC/determinism:** raise `(setf (sb-ext:bytes-consed-between-gcs) …)`, generational tuning, `dynamic-extent`; `sb-sys:without-gcing` only in a bounded, audited critical section behind the unsafe flag.

### 6.2 AllegroCL (co-pacesetter; owner's production Lisp)
- **Buffers:** foreign memory via `ff:` (e.g., `ff:allocate-fobject` / `ff:with-stack-fobject`) + `sys:memref`/`sys:memref-int` typed raw access; simple-streams for buffered I/O. `(C: moderate on exact `ff:`/`sys:` spellings.)`
- **Atomics/concurrency:** native CAS/atomic primitives in `excl`/`sys` + `mp:` processes/locks/gates; verify exact atomic API in the installed Allegro version. Portable fallback: the `atomics` library.
- **Sockets:** Allegro `socket:` API; CFFI shim for `recvmmsg`/`sendmmsg` if the native API lacks batching.
- **Codegen:** `(declaim (optimize (speed 3)(safety 0)))` scoped; use `(declare (:explain :boxing :calls))` to drive boxing out of hot loops; immediate-type-aware coding.
- **GC/determinism:** Allegro's GC is highly tunable — `sys:gsgc-parameter` / `sys:gsgc-switch` to control tenuring and newspace; `excl:without-interrupts`/scheduling for short critical sections.

### 6.3 Clasp (trailing target)
- **Buffers:** CFFI (`cffi:foreign-alloc`, `cffi:mem-ref`) and/or `clbind` to C++; a `static-vectors` backend if available, else CFFI buffers. The hot CDR codec MAY be implemented in C++ and exposed via `clbind` — a legitimate, Clasp-specific optimization that sidesteps GC entirely for serialization. `(C: moderate.)`
- **Atomics/concurrency:** `mp:` package; `std::atomic` via interop where needed; `atomics` library fallback.
- **Sockets:** CFFI to POSIX directly (Clasp's strength is C interop).
- **Codegen:** LLVM backend does the heavy lifting; `(declaim (optimize speed))`; push truly-hot kernels to C++.
- **GC/determinism:** **the risk.** Boehm is conservative (imprecise, less predictable pauses); MPS-precise mode is preferable for determinism — evaluate. Document the NFR-PERF-3/8 gap rather than pretend parity. Clasp is allowed to trail one profile (NFR-PORT).

---

## 7. Interface contracts (frozen in M0) — sketches

These are the load-bearing contracts. Exact final signatures live in the interface packages; the **shapes** are what every agent codes against.

### 7.1 Buffer/cursor (`DDS.CORE.BUFFER`)
A buffer is an off-heap octet region + length; a cursor is an index + endianness + the buffer. Required ops (all bounds-checked at the boundary, even in `safety 0`):
```
make-octet-buffer (n) -> buffer            ; PAL-backed, stable address
buffer-sap (buffer) -> address             ; for syscalls / SHMEM
cursor (buffer &key endianness) -> cursor
align (cursor n)                           ; advance to n-byte boundary (n in {1,2,4,8})
put-u8/u16/u32/u64/i.../f32/f64 (cursor v) ; endianness-aware, alignment-respecting
get-u8/... (cursor) -> v
put-octets (cursor src off len) / get-octets
cursor-position (cursor) -> index
```
**Invariant:** alignment is computed from the buffer origin used by the codec (for SerializedPayload, the byte after the 4-byte encapsulation header).

### 7.2 CDR codec protocol (`DDS.CDR`)
The codec is **not** generic-function-based. Generated code calls concrete `put-*`/`get-*`. The *protocol* the generator targets:
```
;; emitted per type T:
serialize-T   (sample cursor)            ; writes XCDR(rep) per T's extensibility
deserialize-T (cursor) -> sample         ; allocates from T's pool or fills caller buffer
serialized-size-T (sample &key rep) -> n ; exact, no trial encoding
key-hash-T    (sample) -> (octets 16)    ; MD5-or-shortcut per [XTYPES]
```
Representation (XCDR1 plain/PL, XCDR2 plain/delimited/PL) selected by a compile-time arg to the generator and/or a runtime rep flag carried in the encapsulation header.

### 7.3 type-support record (`DDS.TYPES`)
The manual vtable consumed by the engine:
```
(defstruct (type-support (:type … ) )   ; plain struct, slots hold function objects
  name type-name extensibility
  serialize deserialize serialized-size key-hash
  typeobject typeidentifier
  sample-pool-alloc sample-pool-free
  flatdata-offset flatdata-builder       ; nil unless FlatData binding
  data-representation-mask)
```
Engine hot-path code never sees type T; it sees a `type-support` and `funcall`s its slots (zero type-cache probes). The *registry* mapping types→`type-support`, the entity objects that hold a `type-support`, and listeners/conditions MAY be CLOS — only this per-sample dispatch bundle is required to be a `defstruct` of functions.

### 7.4 HistoryCache protocol (`DDS.RTPS.HISTORY`)
```
make-history-cache (kind depth resource-limits type-support) -> hc
hc-add-change (hc change) -> {ok | rejected reason}   ; enforces HISTORY+RESOURCE_LIMITS+LIFESPAN
hc-remove-change (hc seqnum)
hc-get-change (hc seqnum) -> change-or-nil
hc-min-seq / hc-max-seq (hc)
hc-changes-for-reader (hc reader-proxy) -> iterator    ; writer side
```
`change` (CacheChange) is a pooled struct: kind (DATA/DISPOSE/UNREGISTER), writer-GUID, SN, instance-key-hash, serialized-payload (off-heap), source-timestamp, inline-QoS.

### 7.5 transport record (`DDS.XPORT`)
```
(defstruct transport
  kind                                   ; UDPv4 | SHMEM | TCP | …
  send                                   ; (locator buffer off len) -> sent?
  receive-loop                           ; spawns/feeds the receiver, hands buffers up
  open-receive-resource                  ; bind/join-multicast etc.
  close
  max-message-size locator-kind)
```
Adding a transport = constructing one record; the RTPS engine is untouched. The transport *object* MAY be a CLOS instance for configuration/lifecycle; the per-packet `send` slot is a stored function so the latency path stays dispatch-free. The receiver hands **off-heap buffers from a pool** up to the engine; the engine returns them when done (no per-packet consing).

### 7.6 PAL contract (`DDS.PAL`) — capability list
Memory (alloc/free off-heap **static regions** the GC neither scans, moves, nor reclaims; typed raw R/W; bounded pin), atomics (`cas`, `atomic-incf`, `fence`), threads (`spawn`, join, locks, condition vars, optional affinity/priority), sockets (UDP uni/multicast with options; SHMEM segment create/attach; batched send/recv; iovec), clock (monotonic ns), GC control (suggest/inhibit-window/tuning), and optimization hints (a macro that expands to the impl's best "fast" declarations). Each is a small, testable surface with a conformance test.

### 7.7 Static arena & pools (`DDS.CORE.ARENA`)
The home of the `*static-arena-bytes*` knob; everything on the hot path allocates from here, once, at startup.
```
init-arena (&key (bytes *static-arena-bytes*)) -> arena   ; one-shot, from PAL off-heap static memory; idempotent until teardown
teardown-arena (arena)
make-pool (arena element-bytes capacity) -> pool          ; carved from the arena; fixed capacity, no growth
pool-acquire (pool) -> object-or-nil                      ; nil => exhausted; caller applies RESOURCE_LIMITS, never heap-falls-back
pool-release (pool object)
pool-high-water (pool) -> n                               ; metric (NFR-OBS)
arena-report (arena) -> plist                             ; reserved sizes per pool, for startup logging
```
**Invariants:** `*static-arena-bytes*` and any per-pool special variables are read **once** at `init-arena`; later rebinding has no effect until teardown/reinit. `pool-acquire` returning `nil` is the exhaustion signal — the engine maps it to `SAMPLE_REJECTED`/backpressure, **never** to a GC-heap allocation on the hot path (unless the off-by-default elastic mode is enabled). Buffers handed to syscalls/SHMEM come from arena (foreign/static) memory, so their addresses are stable across GC on all three impls. Pool capacities SHOULD be derived from the relevant `RESOURCE_LIMITS` QoS so the memory-level and DDS-level limits agree.

---

## 8. Testing & verification strategy

- **Unit:** per module, per impl. CI matrix = {SBCL, Allegro, Clasp} × {systems landed}.
- **CDR conformance corpus (gating P0):** golden byte vectors for every primitive, struct, union, sequence, array, optional, and extensibility kind, both endiannesses — generated from (a) RTI `rtiddsgen` reference programs and (b) [XTYPES] worked examples. Assert byte-exact. This is the single highest-leverage test asset; build it first.
- **Property/fuzz (gating P1+):** the CDR decoder and RTPS submessage parser are fuzzed (AFL/libFuzzer-style via CFFI harness, plus replay of captured Connext traffic). A malformed packet MUST never corrupt memory (NFR-SEC-POSTURE) — fuzz proves it.
- **RTPS reliability correctness:** a lossy/reordering/duplicating mock transport injects faults; assert eventual reliable delivery, correct NACK/GAP, no infinite retransmit, resource limits honored.
- **Interop matrix (gating, FR-IO):** {SBCL, Allegro, Clasp} × {Connext 7.x, one of Fast DDS/Cyclone/OpenDDS} × {best-effort, reliable, content-filter, durability, XTypes-evolution, large-data/frag}. Wireshark/tshark validates wire conformance in CI. The **Shapes** demo is the smoke test; the matrix is the gate.
- **Performance harness (`dds-bench`, gating NFR-PERF):** mirror RTI Perftest scenarios (latency PING/PONG halved for one-way; max-throughput with batching; latency-vs-throughput) on **identical hardware** running both this stack and Connext; report p50/p99/p99.99/max + samples/s + Mbps + allocation counters + GC events. Parity is judged from this report.
- **Determinism/soak:** 24h+ runs reporting latency-distribution drift, GC frequency/pause, and queue-depth stability; verify **0 bytes/sample** in pre-alloc mode via allocation counters.
- **`hotpath-purity-gate` (gating, all):** static analysis fails the build if `defmethod`/`defgeneric`/`defclass` — or per-sample CLOS instantiation — appears in the designated hot-path packages (`dds.cdr`, generated-codec output, `dds.core.buffer`, the engine's per-sample dispatch module, `dds.rtps.history` change ops). CLOS is unrestricted everywhere else and is the preferred default there.

---

## 9. Performance engineering plan (where the battles are actually won)

Priority order — fix these and dispatch overhead is noise; ignore them and zero-CLOS is cosmetic:

1. **Allocation/GC (highest leverage).** A static, startup-allocated, **non-GC'd arena** (sized by the special variable `*static-arena-bytes*`, read once at factory init) backs all hot-path buffers and pools (`CacheChange`/`SampleInfo`/fragments/scratch/per-endpoint state); steady-state acquire/release is pointer/index work with **0 allocation**. Raw-pointer/SAP buffers are always foreign/static (stable across SBCL's and Allegro's *moving* GCs; out of Clasp/Boehm's conservative scan). Arena exhaustion → RESOURCE_LIMITS (reject/backpressure), **never** a silent GC-heap fallback on the hot path. `dynamic-extent` for transients; per-impl GC tuning for the cold path. Verified by allocation counters **and per-pool high-water-mark**, not by eye.
2. **Copies.** Target counts: UDP plain = 2 (ser into pooled buffer → socket; socket → pooled buffer + deser); FlatData = ser/deser elided (in-memory == wire); Zero-Copy/SHMEM = 0 intra-host (transmit 16-byte references). Every copy on the path is justified in code review or removed.
3. **Syscalls.** `sendmmsg`/`recvmmsg` to batch; `sendmsg` iovec for scatter/gather (header + payload without a join copy); large socket buffers; multicast to fan out once.
4. **Locks.** Lock-free SPSC (writer→sender) and MPSC (receiver→readers); per-endpoint state partitioned to avoid global locks; reader/writer matching done off the hot path.
5. **Dispatch (lowest leverage, but free to get right).** On the per-sample path: monomorphic generated codecs; manual-vtable `funcall`; no GF type-cache probes; typed slot access with declarations. Off the per-sample path, generic functions are fine and preferred — a once-per-`write` GF on a monomorphic call site is single-digit-to-low-tens-of-ns on SBCL and is dominated by the serialization work it guards; verify with the bench harness rather than assuming.
6. **Wire efficiency.** XCDR2 by default (more compact, 4-byte max alignment); batching for small samples; optional LZ4 at serialization.

**Instrument first, optimize second.** Each impl gets a profiling recipe (SBCL `sb-sprof` + `statistical`/`:alloc`; Allegro profiler + `:explain` boxing notes; Clasp LLVM/perf). No optimization lands without a before/after number in the bench report.

---

## 10. Risk register

| # | Risk | Likelihood | Impact | Mitigation |
|---|------|-----------|--------|------------|
| R1 | Hard-RT tail-latency parity (NFR-PERF-3) unattainable on GC'd runtime | **High** | High (if RT is a real requirement) | Static non-GC'd arena (`*static-arena-bytes*`) backing all hot-path memory; per-impl GC tuning; bounded GC-inhibit windows; **renegotiate the requirement / delegate RT nodes to Connext Micro/Cert**; report the gap honestly |
| R2 | Scope creep toward full "Professional" service suite | High | Very High | Hard scope line (REQUIREMENTS §1.2/§13); services only as separately-funded programs |
| R3 | XCDR1↔XCDR2 alignment/extensibility interop bugs | High | High | Byte-exact corpus from RTI vectors *first*; tshark CI; fuzz; test 8-byte-member FINAL types specifically |
| R4 | SequenceNumberSet / NACK bitmap off-by-one | Medium-High | High | Exhaustive bitmap tests; cross-check against Connext captures |
| R5 | Clasp determinism/perf below target | Medium-High | Medium | NFR-PORT one-profile trailing allowance; MPS-precise GC eval; C++ hot-codec via clbind |
| R6 | FlatData/Zero-Copy **patent** exposure | Medium | **High (legal)** | Legal review before P4 ship; design around encumbered claims; document provenance (NFR-IP) |
| R7 | Allegro/Clasp PAL primitive availability (exact atomic/socket APIs) differ from assumption | Medium | Medium | `atomics`+`bordeaux-threads`+`usocket` portable fallback; native fast paths as enhancement, not dependency |
| R8 | Type compiler complexity (IDL 4.2 full grammar) underestimated | Medium | Medium | s-expr DSL first (unblocks everyone); IDL parser as a second, parallel track |
| R9 | Subagent integration drift / contract churn | Medium | High | Contract-first freeze; ADR gate; weekly green-`main` discipline; mocks for every dependency |
| R10 | Discovery scalability / no-multicast deployment | Medium | Medium | Initial-peers + unicast-only mode in P1; defer Cloud-Discovery equivalent |
| R11 | DoS via malformed packets in `safety 0` code | Medium | High | NFR-SEC-POSTURE bounds checks at the boundary; fuzz gate; resource-exhaustion guards |
| R12 | VendorId / OMG coordination delay | Low | Low | Use documented dev VendorId until assigned |

---

## 11. IP / clean-room discipline (operational)

- **Source rule:** specs (OMG) + this team's reasoning only. RTI artifacts are **behavioral references via interop**, never source/headers/`rtiddsgen` output.
- **Open-source reading:** Fast DDS (Apache-2.0), Cyclone (EPL/EDL), OpenDDS may be read for understanding; **copying imports their license** — if any snippet is adapted, record provenance and comply. Prefer independent implementation.
- **Provenance log:** `/docs/provenance.md` lists every external source consulted and its influence.
- **Patent review (gating P4):** counsel reviews FlatData/Zero-Copy-equivalent mechanisms against RTI's patent portfolio before shipping P4. This is R6; do not treat it as a formality.

---

## 12. CI / tooling

- ASDF + a lockfile (qlot or vendored) pinning every dependency.
- GitHub-Actions-equivalent matrix: SBCL (latest + one prior), AllegroCL (the licensed version), Clasp (recent). Jobs: build, unit, CDR-corpus, fuzz (time-boxed), `hotpath-purity-gate`, tshark wire-conformance, interop (nightly, needs Connext + a peer in the runner), bench (nightly, dedicated HW), soak (weekly).
- ADR log, verification matrix CSV, and the interop matrix are CI-published artifacts.

---

## 13. Realism statement (read before committing resources)

- **Core (P0–P5) is large but tractable** for a focused, well-orchestrated effort: a from-scratch, interoperable, performant DDS/RTPS core is comparable to what small teams (and the OpenDDS / Cyclone / Fast DDS projects) have built — the difference here is the Lisp substrate and the hot-path defstruct/codegen discipline (CLOS permitted and preferred elsewhere), both of which are engineering constraints, not blockers. **Confidence: moderate-high that P0–P5 is achievable** with the plan above.
- **Median performance parity is reachable; tail/hard-RT parity is the open risk** (R1). Do not promise NFR-PERF-3.
- **Full "Professional" parity (all services) is a multi-program endeavour** and is explicitly *not* what this plan commits to. **Confidence: high.**
- **The two highest-value early investments** are (1) the **byte-exact CDR conformance corpus** and (2) the **Connext interop harness with Wireshark validation**. Build both before the RTPS engine is "done" — they convert "we think it's right" into "the wire proves it." Everything else is downstream of getting the bytes exactly right.

---

*End IMPLEMENTATION-PLAN.md*
