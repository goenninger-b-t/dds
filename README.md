# Common Lisp DDS

A from-scratch, **data-centric publish/subscribe** middleware in Common Lisp implementing
the **OMG DDS 1.4** application model over the **OMG DDSI-RTPS 2.5** wire protocol, with
**OMG XCDR (1 + 2)** as the foundational serialization. The design goal is to **interoperate
on the wire with RTI Connext 7.x** and approach **Connext-class median performance** on the
supported Lisp implementations.

> **Status: pre-release, under active development.** The DCPS application layer (P2) is
> complete; the XTypes layer (P3) is well advanced. See [Status](#status) for the precise,
> honest per-profile picture. This is research/engineering code, not a shipping product.

The two authoritative specs for this repository are [`REQUIREMENTS.md`](REQUIREMENTS.md)
(*what* and *how well*) and [`IMPLEMENTATION-PLAN.md`](IMPLEMENTATION-PLAN.md) (*how* and
*in what order*). They win over this README on any conflict.

---

## What it is

DDS is a peer-to-peer, brokerless pub/sub standard: applications declare **Topics** (a name + a strongly-typed schema) and exchange **samples** through **DataWriters** and **DataReaders** whose **QoS** policies must be compatible for them to match. Underneath, **RTPS** is the interoperable wire protocol (discovery, reliability, fragmentation) and **XCDR** is the binary serialization. **Common Lisp DDS** implements that stack natively:

- **CLOS where it's free, `defstruct` where it counts.** The control plane (entities, QoS,
  listeners, conditions, discovery, the type compiler, tooling) is idiomatic CLOS. The
  **measured hot path** (CDR primitives, generated per-type codecs, buffer/cursor,
  `CacheChange`/`SampleInfo`, the engine's per-sample dispatch) is `defstruct` +
  monomorphized code generation + manual vtables — **no generic-function dispatch and no
  per-sample allocation**. A CI gate enforces the boundary.
- **Static, non-GC'd memory on the hot path.** All hot-path buffers/pools are carved once at
  startup from an off-heap arena sized by `*static-arena-bytes*`; steady state allocates
  **zero** bytes per sample, and arena exhaustion maps to DDS `RESOURCE_LIMITS`, never a
  silent GC-heap fallback.
- **The wire is the oracle.** Correctness is established by **XCDR byte-exactness** against
  reference vectors and by **interop validated with the Wireshark/tshark RTPS dissector** —
  not by "it looks right." Wire constants are pinned from the in-repo OMG specs and verified,
  never hardcoded from memory.
- **A type compiler** (`define-dds-type`, the `rtiddsgen` analogue) turns a type definition
  into a `defstruct` + monomorphic XCDR codecs + key-hash + the XTypes TypeObject + a
  `type-support` registration — the linchpin of the no-CLOS-on-the-hot-path strategy.

**Targets:** SBCL, AllegroCL, Clasp (64-bit, Linux-first). Landed and CI-exercised today:
**SBCL + Clasp** (AllegroCL is a first-class target, not yet wired in — ADR 0004).

---

## Scope

### In scope

Core DDS/DCPS + RTPS + discovery + XTypes/XCDR, plus the high-value performance
differentiators that distinguish Connext *Professional*: batching, asynchronous publication
with flow control, shared-memory transport, Zero-Copy-over-SHMEM, a FlatData-equivalent
binding, serialization-time compression, and durable history. DDS Security is a gated late
profile. Conformance is decomposed into profiles **P0–P7** (see below).

### Explicitly out of scope

The Connext *Professional* **service suite** — Routing Service, Recording/Replay Service,
Persistence Service (as a separate process), Cloud Discovery Service, Admin Console /
Monitor GUIs, and similar. Each is its own program; they are **deferred, not designed out** —
the architecture must not preclude them. See `REQUIREMENTS.md` §13.

---

## Status

Conformance profiles and where they stand (the canonical, per-requirement matrix is
[`docs/verification.csv`](docs/verification.csv)):

| Profile | What | State |
|---|---|---|
| **P0** CDR core | XCDR1 + XCDR2 codec, encapsulation, alignment | **partial** — primitives/strings/sequences/structs + DHEADER/EMHEADER pinned & spec-seed byte-exact; the XCDR2 encapsulation options pad bits are emitted + interpreted per DDS-XTypes 1.3 §7.6.3.1.2; full RTI reference-vector corpus pending |
| **P1** Minimal RTPS | submessages, reliable + best-effort writer/reader, SPDP+SEDP, UDPv4 uni/multicast | **partial** — engine + discovery + data plane run over real UDP, tshark-validated; **bidirectional Connext Shapes interop achieved 2026-06-09** (live RTI Connext 7.3.1, reliable, both directions); **fragmented large-sample interop (DATA_FRAG + HEARTBEAT_FRAG + NACK_FRAG) achieved 2026-06-10** — 8000-octet LargeData byte-exact both ways, incl. forced-fragment-loss recovery where Connext's NACK_FRAG is answered with exactly the missing fragments; **Writer Liveliness Protocol landed 2026-06-12** (RTPS 2.5 §8.4.13) — the `ParticipantMessageData` codec plus the `BuiltinParticipantMessage` writer/reader endpoints wired on the discovery node: `assert-participant-liveliness` writes one `ParticipantMessageData` per liveliness kind (AUTOMATIC / MANUAL_BY_PARTICIPANT, distinct DDS-key instances `participantGuidPrefix + kind`, §8.4.13.5) to each discovered peer on the announce cadence, the PM reader records a per-remote liveliness stamp, the writer is RELIABLE (DATA + HEARTBEAT, §8.4.13.3), and the builtin-endpoint-set bits 10/11 are advertised; **reader-side `LIVELINESS_CHANGED` timing landed 2026-06-12** — the announce-cadence `%liveliness-sweep` judges each matched remote writer alive/not-alive against its offered `LIVELINESS` lease and fires `on_liveliness_changed` + bumps the `DataReader`'s `LIVELINESS_CHANGED` status on each alive↔not-alive transition (DDS 1.4 §2.2.4.1); **writer-side `LIVELINESS_LOST` + `DataWriter::assert_liveliness` landed 2026-06-12** — the DCPS-cadence (`spin`) `%writer-liveliness-sweep` fires `on_liveliness_lost` + bumps the `DataWriter`'s monotonic `LIVELINESS_LOST` `total_count` once per going-lost transition when a local writer fails to assert its own liveliness within its offered lease (DDS 1.4 §2.2.3.11), with kind-aware assertion (AUTOMATIC via the cadence, MANUAL_BY_PARTICIPANT via a write/assert on any of the participant's such writers, MANUAL_BY_TOPIC only via that writer); **participant-lease expiry confirmed live vs Connext 2026-06-12** — a killed Connext participant is pruned within its announced `leaseDuration`, decrementing `SUBSCRIPTION_MATCHED` 1→0; **standard `ParticipantMessageData` byte-validated vs the conformant peer Fast DDS 3.6.1 2026-06-12** — a live Fast DDS BuiltinParticipantMessageWriter (`0x000200c2`) AUTOMATIC-liveliness assertion is decoded and reproduced byte-exact by our codec (default RTI participant-liveliness rides RTI's proprietary `NDDSPING`, so the conformant peer was the right oracle); **reverse direction proven 2026-06-12** — we now advertise `PID_LIVELINESS` (0x001b) in SEDP, and a live Fast DDS reader RxO-matched our MANUAL_BY_PARTICIPANT writer and reported `on_liveliness_changed` ALIVE while we assert → NOT_ALIVE when we stop (MANUAL liveliness isn't kept alive by SPDP, so this proves Fast DDS semantically consumes our `ParticipantMessageData`) |
| **P2** DCPS | entities, full QoS + RxO matching, conditions/WaitSets, instances, read/take, content-filtered topics, builtin topics | **complete** (offline conformance) — **HISTORY `KEEP_LAST` is now per-instance on both sides** (DDS 1.4 §2.2.3.18, WP-KEEPLAST 2026-06-16): the writer HistoryCache and the reader cache keep the last `depth` changes/samples *per key* (a keyhash→SN index evicting an instance's own oldest, not the global oldest), the engine honors the configured HISTORY QoS via `enable-publisher` (the default is now the spec generic KEEP_LAST-1; retention-dependent tests/harnesses migrated to explicit KEEP_ALL), and the interior-SN holes per-instance eviction creates are closed by a reactive GAP wired in both directions with a hard-capped irrelevant-range guard (RTPS 2.5 §8.3.7.4, NFR-SEC-POSTURE); honest write-path bench `bench/report/2026-06-16-wp-keeplast.md` (`make bench-keeplast`, FR-LANG-7) — a keyed KEEP_LAST writer adds a ~16-octet keyhash/sample + the per-instance index cons (freed on evict, ~0 steady-state bytes), KEEP_ALL + unkeyed unchanged (NO 0-cost claim; the bench also surfaced + fixed an O(N²) regression the WP had introduced on the KEEP_ALL add path — the index is now KEEP_LAST-only so KEEP_ALL stays O(1)) |
| **P3** XTypes | TypeObject/TypeIdentifier, assignability + `TYPE_CONSISTENCY_ENFORCEMENT`, XCDR2 TypeObject serializer + EquivalenceHash, `TypeInformation` over SEDP, inbound Connext `PID_TYPE_OBJECT_LB` reader + advisory type-compat | **in progress** — all of the above landed; the serializer's canonical bytes + EquivalenceHash are **externally confirmed vs live Fast DDS 3.6.1** for the exercised path (FINAL struct + `i32` + unbounded `string8`; its 92-octet SEDP `PID_TYPE_INFORMATION` is locked as a regression vector, test `fastdds-type-information-vector`, and our ShapeType hash + serialized size 87 match byte-for-byte — the parser also now consumes the foreign `LC=5` framing; provisional only for the unexercised serialization-VM edges: unions, MUTABLE structs, `TK_NONE` base, sequence-member TIs, nested-dependency hashes); the inbound `PID_TYPE_OBJECT_LB` path is ZLIB-inflate + a name fingerprint feeding an **advisory** match-time verdict (never a gate — ADR 0009); the built-in TypeLookup service is **complete offline** — the `TypeLookup_Request` and `TypeLookup_Reply` XCDR2 codecs (framing aligned to the Fast DDS `@final` convention: `CDR2_LE` encapsulation, union DHEADERs, `LC=5` mutable members), the MinimalTypeObject deserializer (`parse-minimal-type-object`, the byte-exact inverse of the serializer, so a received TypeObject feeds assignability), the transport-free server core (`find-type-support-by-hash` hash index + `type-lookup-respond`), and the four built-in service endpoints (XTypes 1.3 Table 61) wired into the discovery node — a reliable request reader/reply writer serving the registry plus a `type-lookup-query` getTypes client with timeout sweep and an in-flight cap — are in; **no Connext oracle exists** (RTI doesn't implement the protocol — ADR 0010), so the emitted bytes are frozen as **self-pinned regression vectors** (test `typelookup-vectors`) and independently cross-checked by the tshark RTPS dissector, which decodes both payloads **field-by-field with zero disagreements** (`make wire` gates two TL frames; live Fast DDS frames re-pinned the framing 2026-06-12 — see the CONFIRM-VS-PEER walk below); **FR-TYPE-4 gated matching is wired end-to-end (offline)**: every `DomainParticipant` installs an assignability gate on the engine's SEDP `type-gate` hook — equal EquivalenceHashes match with zero wire traffic; differing hashes fetch the remote Minimal TypeObject via TypeLookup (nested member hashes resolved with bounded follow-up queries) and decide via is-assignable-from under the **reader's** `TYPE_CONSISTENCY_ENFORCEMENT`, an `:incompatible` verdict raising INCONSISTENT_TOPIC; every unassessable case (no/malformed TypeInformation, unknown hash, timeout, depth bound) falls back to name-based matching, never a rejection; **legacy-TypeObject degrading tier complete (2026-06-11)**: `parse-legacy-type-object` recognizes union (member-kind `0x15`) and array (member-kind `0x11`) members, both then confirmed to degrade the whole parse to `:unsupported` (fail-open) via live Connext 7.3.1 captures (`C_Union`, `C_Array`); bitmask not capturable (`rtiddsgen 4.3.1` rejects the keyword — documented gap); **90 tests green SBCL**; **legacy enum members now gate STRUCTURALLY (2026-06-12, Task S0.3)**: enum (member-kind `0x0E`) is flipped OUT of the degrade tier — the enum-definition node (CODE 5) is resolved by the shared 8-octet type-hash mechanism, its bit-bound + literals (each carrying a literal name, so NameHashes match a local model) folded into an `EK_MINIMAL` enumerated `type-identifier`; the live `C_Enum` (`@key long id; SomeEnum{RED=0,GREEN=1,BLUE=2} e`) parses to a `minimal-struct-type` whose `e` member drives `struct-assignable-from` through `enum-assignable-from` (XTypes Table 18) — a matching local is assignable both ways, a BLUE-value-changed local is rejected, no false-reject on re-run (**96 tests green SBCL**); **legacy single-dimension array members now gate STRUCTURALLY (2026-06-12, Task 1.3)**: array (member-kind `0x11`) is flipped OUT of the degrade tier — the array-definition node (CODE 3) is resolved by the shared 8-octet type-hash mechanism, its element type-kind (CODE 100 child, long 5→`i32`) and single fixed dimension (CODE 200 child: `count:u32`=1 then the bound `4`) folded into a plain-array `type-identifier`; the live `C_Array` (`@key long id; long arr[4]`) parses to a `minimal-struct-type` whose `arr` member drives `struct-assignable-from` (XTypes Table 17, arrays not resizable → identical dimensions) — a matching local (`i32`×4) is assignable both ways, an `arr[5]` (size) or short `arr[4]` (element-kind) local is rejected, no false-reject on re-run; multi-dimensional arrays (`count≠1`) and non-primitive elements remain a documented fail-open gap (**99 tests green SBCL + Clasp**); **legacy union members now gate STRUCTURALLY (2026-06-12, Task 2.3)**: union (member-kind `0x15`) is flipped OUT of the degrade tier — the union-definition node (CODE 10) is resolved by the shared 8-octet type-hash mechanism, its cases container (CODE 100: `count:u32` then per entry a named CODE-0 node + a CODE-100 label-list child) folded into an `EK_MINIMAL` union `type-identifier` (the first entry the discriminator, each later entry a member with its case label + member name, so NameHashes match a local model); the live `C_Union` (`@key long id; SomeUnion switch(long){case 0: long a; case 1: double b} u`) parses to a `minimal-struct-type` whose `u` member (disc `i32`; `{0}`→`a` `i32`; `{1}`→`b` `f64`) drives `struct-assignable-from` through `union-assignable-from` (XTypes Table 19 UNION_TYPE row, by shared case label) — a matching local is assignable both ways, a local where case 0's member type changes `long`→`double` is rejected, no false-reject on re-run; a default member, a non-primitive discriminator/member, or a multi-label case remains a documented fail-open gap (`ti-delimited-p` was extended so a union of delimited members self-delimits, removing a false-reject for a FINAL-struct union member) (**102 tests green SBCL + Clasp**); **LIVE Connext legacy-TypeObject type-gating ACHIEVED 2026-06-11 (ADR 0011, completes ADR 0010)** — wired into the DCPS gate, `parse-legacy-type-object` now decides matching against a **live RTI Connext 7.3.1** writer: a DCPS-level gated subscriber (`dds.shapes:run-gated-subscriber` / `make gated-sub`) faces Connext's real `PID_TYPE_OBJECT_LB`, gating a structurally-compatible local `C_Shape` `:compatible` (matched, 25 samples delivered) and a structurally-incompatible local (`shapesize` long→`i64`) `:incompatible` (INCONSISTENT_TOPIC, 0 samples), and never false-rejecting the compatible peer on a re-run (**91 tests green SBCL**); **EquivalenceHash externally confirmed 2026-06-12 (FR-IO-2 S3)** — the live Fast DDS 3.6.1 `PID_TYPE_INFORMATION` locked as a vector closes the ADR 0009 unconfirmed thread for the exercised path (**92 tests green SBCL + Clasp**, the latter after root-causing a Clasp unmanaged-free heap corruption to the runtime, not the test — NFR-PORT row in `docs/verification.csv`); **TypeLookup getTypes client live vs Fast DDS 3.6.1 (FR-IO-2 S4 leg A, 2026-06-12)** — `dds.shapes:run-typelookup-probe` (`make fastdds-tl-probe`) queried their TypeLookup server for the SEDP-announced EK_MINIMAL hash and consumed the reply live (request/reply frames 85/86-87 in `interop/fastdds/captures/s4-ourclient-lo0.pcap`), surfacing + fixing failing-locked-vector-test-first the conformant answer shape our client lacked: a MINIMAL query may be answered with the COMPLETE TypeObject plus the `complete_to_minimal` mapping (XTypes 1.3 §7.6.3.3.4.2), now reconstructed to MINIMAL via the new `dds.types:complete-to-minimal-type-object` (the locked Fast DDS reply reconstructs **byte-identical** to our own ShapeType MinimalTypeObject, test `fastdds-typelookup-reply-vector`; **93 tests green SBCL**); **TypeLookup CONFIRM-VS-PEER walk closed (FR-IO-2 S4 leg B-patched, 2026-06-12)** — under a controller-approved NON-STOCK diagnostic (Fast DDS's SEDP vendor gate neutralized locally, then restored + re-proven stock) their stock TypeLookup client queried our server and **built its DynamicType from our reply** (600/600 RELIABLE samples; their JSON-dump failures root-caused to a Fast DDS defect — raw MINIMAL `NameHash` bytes as member names — not our framing), peer-confirming the codec framing in both directions: instanceName forms, ReplyHeader remoteEx placement, EMHEADER1 LC=5 rule-22 reuse, top-level `@final`/`CDR2_LE`, and the Call/Return/Result union DHEADERs; still self-pinned: the non-OK Return-arm omission + non-CDR2_LE encapsulations (walk table in `interop/fastdds/README.md`); DynamicData deferred |
| **P4** Performance differentiators | batching, async/flow-control, SHMEM, Zero-Copy, FlatData, LZ4 | **in progress** — large-sample fragmentation (DATA_FRAG) pulled forward and Connext-validated under P1; **write-side batching** (size/time-triggered, ~95x small-sample throughput) and **asynchronous publication** via a decoupled sender thread landed (both default-off); **flow control landed 2026-06-15** (FR-PF-2, ADR 0016, standard DDS — not patent-gated) — a shareable **`flow-controller`** with its own scheduler thread paces the aggregate user-data byte rate of its associated writers via a **bytes/period token bucket** with fragment-level granularity, round-robining one datagram per writer per turn (so multiple writers interleave at the shaped rate) behind a **pluggable scheduling-policy hook** (round-robin in v1; the EDF/`TRANSPORT_PRIORITY` anchors drop in without rework); the controller lock is **never held across the build/send/deficit-sleep** (the two locks never held simultaneously), the built datagram is **held, never rebuilt** across a token deficit, and a writer with no controller is **byte-identical** to before; honest rate-shaping bench (`bench/report/2026-06-15-wp-async-flow.md`, `make bench-async-flow`): the achieved drain rate tracks the configured ceiling within the startup-full-bucket + per-datagram-granularity overshoot (e.g. configured 125 KB/s → achieved ~132 KB/s; a smaller `max-burst` tracks ~1.0x), the AGGREGATE rate of two writers on one controller is shaped to ~R (not 2R), and a large sample is paced at DATA_FRAG-fragment granularity (fragments spread across periods — the FR-PF-2 headline), with the same workload **tens of times slower paced than the unpaced `enable-async` baseline — flow control is rate *control*, it ADDS latency by design (NO "0-cost" claim)**; because the controller is **shared** across writers, `stop-node` tears one writer down via a **per-node emit barrier** (`flow-controller-unregister` removes the node from the scheduler's writer set, then blocks until the scheduler is provably not, and never again will be, mid-emit on it) rather than a whole-scheduler join — so freeing the node's socket/SHMEM/buffers cannot race a live scheduler send (no use-after-free), proven by a concurrency stress test that deterministically parks the scheduler mid-emit and asserts `stop-node` blocks until release (and which fails against the pre-barrier code); default-off. **Block-up-to-`max_blocking_time` backpressure landed 2026-06-15** (the Phase-D half; FR-PF-2/FR-QOS, ADR 0016 §Backpressure, standard DDS): a reliable `writer-write`/`writer-lifecycle-change` on a **HISTORY KEEP_ALL** cache with a finite **RESOURCE_LIMITS `max_samples`** that is **full** **blocks** on a space-available condvar (releasing the writer lock) for up to **RELIABILITY `max_blocking_time`**, then returns **`RETCODE_TIMEOUT`** (`:timeout`) with the cache intact and **no SN consumed** (`max_blocking_time = 0` ⇒ immediate `:timeout`); space is signalled (a `condvar-broadcast`) whenever the cache shrinks — a KEEP_ALL cache shrinks only on the ACKNACK purge (the slowest reader having ACKed), plus controller teardown — so a blocked write wakes and either succeeds or hits its deadline. The bound is **per-writer**; paired with the `flow-controller` (aggregate-rate drain) it keeps the backlog bounded (NFR-MEM). Wired via `enable-publisher`'s `:max-samples`/`:max-blocking-ns` (both `nil` default ⇒ unlimited + no blocking — **byte-identical** to a writer with no bound); the DCPS `write-sample`/`dispose`/`unregister` surface `+retcode-timeout+`. The only lock held across the wait is the writer lock (released by `condvar-wait`); the freeing thread (ACKNACK purge on the receiver thread / paced scheduler on its own thread — never the app thread) re-takes it to purge+signal, so there is no lock cycle and a blocked publish cannot wedge the send-only scheduler; **shared-memory intra-host transport landed 2026-06-14** (FR-XPORT-2) — same-host user DATA auto-routes through a per-receiver `mmap` ring (header + a `PTHREAD_PROCESS_SHARED` mutex/condvar notify block + K per-sender SPSC lanes, mutex-guarded lane claim so no foreign CAS → SBCL+Clasp parity) when both peers share a host-uuid and advertise a SHMEM locator, with **UDP the fallback for all discovery/HEARTBEAT/ACKNACK and every non-SHMEM case**; the engine is untouched (it plugs into the frozen `dds.xport:transport` record); **1.35x–1.94x lower one-way median latency** vs UDP loopback and 0 per-sample heap allocation on the send path (end-to-end reliable throughput is HEARTBEAT/ACKNACK-handshake-bound, not SHMEM-bound — `bench/report/2026-06-14-wp-shmem.md`); SBCL has full SHMEM on every platform, Clasp/macOS-arm64 falls back to UDP (a documented NFR-PORT gap: Clasp's CFFI mispasses `shm_open`'s variadic `mode_t`), Clasp/Linux expected pending verification; **Zero-Copy-over-SHMEM landed 2026-06-14 as a best-effort v1 (FR-PF-3, ADR 0014) — DEFAULT OFF and *NOT cleared for ship pending counsel (R6, patent-gated)***: with `dds.disc:*zerocopy-enabled*` `t`, a LARGE same-host sample (above `*zerocopy-min-payload-bytes*`, default 1024) is placed once into a per-writer `mmap` sample-pool and only a 16-byte **reference** crosses the transport instead of the fragmented payload, which a same-host ZC-capable reader (SEDP `PID_ZEROCOPY_CAPABLE`) resolves from the writer's pool; generation+bounds-checked (an invalid/forged ref is dropped, NFR-SEC-POSTURE), with every fallback (off / no ZC reader / pool saturated / stale ref) going to normal DATA so there is no loss or double-delivery, and *byte-identical behaviour to today when off* (the default); a real 2-OS-process round-trip (`make zc-xproc`, `scripts/zerocopy-roundtrip.sh`) proves the reference resolves cross-process, and the large-sample bench shows the ref-passing win — up to ~15.8x lower one-way median vs the fragmented SHMEM path and up to ~9.9x higher throughput at 64 KiB, with the honest caveat that the v1 resolver over-allocates a slot-sized sink so the per-sample *allocation* win only appears near the slot size (`bench/report/2026-06-14-wp-zerocopy.md`); reliable Zero-Copy is a follow-up; SBCL only — Clasp/macOS inherits the SHMEM by-name-attach gap (the ZC tests pass-skip there); **FlatData-equivalent landed 2026-06-14 (FR-PF-4, NFR-PERF-7, ADR 0015) — *NOT cleared for ship pending counsel (R6, patent-gated)***: for a FINAL fixed-size `:flatdata t` type the in-memory layout *equals* the XCDR2 wire layout, so the type compiler emits compile-time **Offset** accessors (read/modify in place, 0-alloc for fixnum-range fields), a constructor that writes the encap header byte-identically to the engine, `serialize-<name>-fd` = **identity** (block-copy, 0 per-field encode — a genuine **0-alloc TX**, byte-exact vs the classic serializer), and `deserialize-into-<name>-fd` (0-alloc copy into a loaned buffer) under the vtable; honest measurement (`bench/report/2026-06-14-wp-flatdata.md`, `make bench-flatdata`): TX serialize 0 GC-bytes/sample, engine-visible non-ZC RX vtable ~80 vs ~128 classic (a modest GC-heap win + 0 per-field decode, **not** zero), and **FlatData-over-ZC RX a SAFE SINGLE COPY out of SHMEM — ~830x less GC than the WP-ZEROCOPY-v1 sink+re-copy, but NOT literal-0-copy** (a Lisp octet-buffer cannot wrap a raw foreign SAP and the async off-thread read has no slot-aware release hook, so a literal-0-copy view would be a cross-process use-after-free — deferred); **keyed FlatData landed 2026-06-17** (WP-KEYED-FLATDATA, FR-PF-4/FR-TYPE-5, ADR 0015): a `:flatdata t` type now carries **fixed-size scalar `@key`** members via a **buffer-reading keyhash** `key-hash-<name>-fd` (byte-identical to the spec/struct keyhash, RTPS 2.5 §9.6.4.8) wired into `type-support`, lighting up real per-key loan handles, NEW/NOT_NEW view-state, dispose/unregister, and the per-instance KEEP_LAST drop on the loan path — **variable-size/string `@key` members are still deferred** (a compile-time error, FlatData v1 fixed-size); the cross-DDS interop keyhash/instance-identity (the F1 gate, `interop/keyed-flatdata`) is **confirmed LIVE on the wire vs RTI Connext 7.3.1** (our keyed FlatData samples group into the correct per-key instances on Connext with a byte-identical keyhash, and dispose-by-key resolves to the right instance) with the **Fast DDS leg handed to the owner** (apps + run targets + expected result); the untrusted FlatData wrap/read paths are fuzzed (`make fuzz`: malformed payloads reject-or-read-in-bounds incl. a `(safety 0)` variant proving the length/encap guard is an explicit manual check, hence safety-independent, and forged cross-process ZC recorded-len/generation clamp to the slot — never an OOB, NFR-SEC-POSTURE); **literal-0-copy RX landed 2026-06-16 (WP-FLATDATA-ZC-LOAN, FR-PF-3/4, NFR-PERF-7, ADR 0017) — *still NOT cleared for ship pending counsel (R6)***: a `:flatdata t` reader created while `dds.disc:*zerocopy-enabled*` is on is **loan-capable** — the disc receiver thread stores the **unresolved** ZC reference (no copy; the slot stays loaned via the writer's `refcount = matched-readers`) and the DCPS **loan API** (`dds.dcps:take-loaned`/`read-loaned`) hands the app a `dds.types:flatdata-view` whose `<name>-<field>-fd` accessors read **directly off the writer's SHMEM slot — literal 0 intra-host copies**; `dds.dcps:return-loan` releases the slot (idempotent / double-return-safe), reader-close returns any outstanding loan (no leaked refcount), and **force-reclaim skips `refcount>0` slots** so a held loan can never be overwritten under the app's read (no UAF) — proven by a concurrency lifetime stress test (a held loan stays byte-correct while a writer churns the pool; pool-full ⇒ non-ZC fallback, no wedge; no refcount leak) and an untrusted loan-acquire fuzz (forged slot/generation/len ⇒ NIL or a slot-clamped view, never an OOB even at `(safety 0)`); the headline RX bench (`bench/report/2026-06-16-wp-flatdata-zc-loan.md`, `make bench-flatdata-zc-loan`) shows the per-sample RX allocation drop to the **bare pool-mutex acquire (~32 GC bytes/sample, payload-independent — no owned delivery vector)** vs the FlatData+ZC v1 single-copy ~79 (mutex + the ~47-octet owned vector) and the WP-ZEROCOPY-v1 sink+re-copy ~65551 — the progression **65551 → 79 → 32**, **honest (FR-LANG-7, NO `0-cost` claim):** the eliminated per-sample owned vector is the *allocation* win, but the loan API ADDS the explicit `%zc-acquire-for-read` + `%zc-release` calls + the app's `return-loan` obligation; SBCL only (ZC, ADR 0013; Clasp pass-skips); the loan path is now keyed-FlatData-capable (the per-key loan handle + the per-instance KEEP_LAST drop ride `key-hash-<name>-fd`, WP-KEYED-FLATDATA below); **follow-ups (not done): the Builder + variable-size/string/sequence/nested FlatData (incl. variable-size/string `@key`), the app-facing ZC loan-write API** (to remove the remaining TX app→slot copy), and a documented **one-loan-capable-reader-per-`disc-node` invariant** (the slot refcount + `zc-loan-marker` are per source-GUID→SN on a node holding a single `user-reader`; a second loan-capable reader on one node would let the first `return-loan` free a slot the second still views — unreachable as-built, but a precondition the reliable / multi-reader follow-up must lift via refcount-per-reader or per-reader markers); **lock-free 0-alloc loaned RX landed 2026-06-16 (WP-ZC-LOAN-LOCKFREE, FR-PF-3/4, NFR-PERF-7, ADR 0018) — *still NOT cleared for ship pending counsel (R6)***: the loaned RX is now **literal 0-alloc and 0-copy** — `%zc-acquire-for-read` dropped the pool mutex for a **generation acquire-load + `dds.pal:fence :acquire`** (the generation is the release/acquire synchronization variable, doubling as the stale-ref validate), and `%zc-release` dropped it for a direct **`cas-sap-u32` refcount decrement** (the writer's `%zc-loan` reorders to **payload → `fence :release` → generation-store-LAST**, so the generation is the single publication point), so the per-sample loaned RX (acquire + read + return) allocates **literal 0 GC-heap bytes** — the progression closes **65552 → 79 → 31 → 0** (`bench/report/2026-06-16-wp-zc-loan-lockfree.md`, `make bench-zc-loan-lockfree`); the generation release/acquire handshake is **verified real on arm64** (`DMB SY` from `fence`, `CASAL` from the CAS — disassembled from SBCL's own VOPs) and **byte-exact cross-process** by `make zc-xproc`; the **honest tradeoff (FR-LANG-7, NO `0-cost` claim):** the writer's loan lost its O(1) freelist-pop (the freelist was dropped — a lock-free `cas`-decrement release cannot maintain one without a second CAS) for an **O(slots) `refcount==0` scan** (benched: ~106 ns/loan at 2 slots → ~1801 ns at 128, the O(slots) sensitivity — writer-side, amortized, a writer typically has few slots), and the loan/return *calls* + the app's `return-loan` *obligation* are still real; a **Phase-B amendment** found+fixed a latent NFR-MEM defect — the first `cas-sap-u64` release over the combined `(gen<<32)|refcount` word **boxed a bignum** once a slot's generation reached ~`2^30` (regressing to ~32 B/sample), so the release CASes the **u32 refcount sub-field directly** (0-alloc at *any* generation); SBCL only (ZC + foreign-SAP atomics, ADR 0013; Clasp pass-skips); **follow-up (not done): a lock-free freelist (a CAS stack) to restore the writer's O(1) loan while keeping the lock-free release** — revisit only if the O(slots) scan benches as a real cost in a real workload; **reliable Zero-Copy loan delivery verified + hardened 2026-06-16 (WP-RELIABLE-ZC scope A, FR-PF-3/4, R6, ADR 0017) — *still NOT cleared for ship pending counsel (R6)***: a ZC loan sample on a **RELIABLE** writer rides the existing reliable path with **no separate reliability gate** — it has a SequenceNumber, is NACKable and retransmittable; the **reader-RX 0-copy/0-alloc + the 16-byte wire reference are the ZC win** under reliability, and the **loan composes with reliability via the refcount** (the reader ACKs on receive; the writer's full-ACK HistoryCache purge, RTPS 2.5 §8.4.1, frees the HC copy, but the loaned **slot outlives the purge** — force-reclaim skips `refcount>0` — until `return-loan`, no use-after-free). HONEST (FR-LANG-7): the **retransmit is reliable via COPY-FALLBACK, not re-loan** — the ACKNACK repair leg re-emits the **full retained HistoryCache payload** (byte-exact, no loss; `%on-user-acknack` omits `zc-readers`), which a loan-capable reader delivers as an owned **copy**, not a ZC view; and the **writer keeps the HistoryCache full-payload copy** (needed for retransmit + non-ZC/remote readers), so the writer-side is **double-storage, NOT zero-copy** under reliability (the v1 cost) — no writer-side-zero-copy claim for reliable; a saturated pool falls back to the full payload (copy-delivered, never a silent drop), and a single `take-loaned` returns interleaved views + fallback copies byte-exact. Proven by five SBCL scenarios (`run-reliable-zc-{retransmit,poolfull-fallback,mixed,slot-outlives-purge,qos}-test`; Clasp pass-skip — ZC is an NFR-PORT gap), **211 green** both impls; the run also **found + fixed a latent reliability/memory bug** — `make-reader-qos`/`make-writer-qos` silently dropped a caller's `:reliability` override (the injected default was leftmost-winning, HyperSpec 3.4.1.4), so a RELIABLE-requesting reader advertised BEST_EFFORT, was excluded from the writer's matched-reader purge set, and the writer never purged its HistoryCache on full-ACK for it → unbounded HC growth; FIXED (the caller's keyword now wins, commit `0a03bf5`). **Scope-B follow-ups (not done): re-loan-on-retransmit** (the ACKNACK path re-sends a ZC ref instead of the full copy — needs per-peer `%zc-readers` on the retransmit so the slot refcount stays 1 per resolving destination, avoiding a double-free when the resend fans to multiple peers) and **true writer-side reliable ZC** (the HistoryCache change references the slot, no full-payload copy, when all readers are same-host ZC); **keyed FlatData landed 2026-06-17 (WP-KEYED-FLATDATA, FR-PF-4/FR-TYPE-5, ADR 0015) — *still NOT cleared for ship pending counsel (R6)***: the FlatData v1 **NO_KEY deviation is closed for fixed-size scalar `@key` members**. The linchpin is a buffer-reading keyhash `key-hash-<name>-fd` (the FlatData sample is the octet-buffer / a `flatdata-view`, not a struct, so the spec `key-hash-<name>` struct keyhash cannot read it) — it reuses the struct keyhash's **big-endian XCDR2 serialization + the ≤16-direct-zero-padded / >16-MD5 rule (RTPS 2.5 §9.6.4.8)**, sourcing each `@key` value from the existing `<name>-<field>-fd` accessor instead of the struct slot, so it is **byte-identical to the struct keyhash** for the same key values (a keyed FlatData instance's identity equals what a non-FlatData peer computes — the conformance crux; pinned BE vector + struct cross-check, both the ≤16 and >16-MD5 paths, test `keyed-flatdata-keyhash`). Wired into `type-support` (`:keyed-p t` + `:key-hash #'key-hash-<name>-fd`), the existing keyed machinery lights up: a **real per-key loan handle** (`%loan-instance-handle` returns the loaned view's keyhash for a keyed type, replacing the synthetic SN+GUID fold — `keyed-flatdata-loan-handle`), the **per-instance KEEP_LAST drop on the ZC loan path** (`%drain-one-loan`, closing the WP-KEEPLAST loan-path follow-up — `keyed-flatdata-loan-keeplast`), **copy-path keyed behavior** (real per-key instance-handle + NEW/NOT_NEW view-state + per-instance KEEP_LAST, ≈free — `keyed-flatdata-copy-behavior`), and **dispose/unregister by sample** (the buffer → `key-hash-<name>-fd` → NOT_ALIVE_DISPOSED — `keyed-flatdata-dispose`); **variable-size/string `@key` members are still deferred** (a compile-time error — FlatData v1 fixed-size scalar; they ride the Builder follow-up). The `-fd` keyhash is **off the measured CDR hot path** (computed only for keyed FlatData) — `make mem` stays **0.0000** serialize/deserialize/round-trip, no hot-path number changed, **no new bench warranted** (FR-LANG-7). 232 green SBCL+Clasp (the SBCL-only ZC loan tests pass-skip on Clasp); gate-types(1285)+gate-hotpath+mem(0-alloc CDR)+fuzz+wire PASS. **Cross-DDS interop F1 (per-feature DoD 2026-06-17, `interop/keyed-flatdata`): CONNEXT 7.3.1 LIVE PASS, FAST DDS OWNER-PENDING.** An offline cross-impl test (`keyed-flat-interop-keyhash`) asserts our `key-hash-keyed-flat-fd` equals an **independently-derived** standards-conformant peer keyhash (RTPS 2.5 §9.6.4.8) for the shared `KeyedFlat {@key long id; long x; long y}` type (green both impls). **Live in-session:** our keyed FlatData publisher → a Connext subscriber that grouped 30/30 samples into exactly 3 per-key instances with the keyhash `00000000…`/`00000001…`/`00000002…` **byte-identical to ours** (the conformance crux proven on the wire), and our **dispose-by-key** resolved to the correct instance on Connext (the dispose DATA's `PID_KEY_HASH` dissects under tshark, `interop/keyed-flatdata/captures/`). **FlatData reader transcodes a foreign representation landed 2026-06-17** (WP-FLATDATA-XCDR-TRANSCODE, FR-PF-4, DDS-XTypes 1.3 §7.6.3.1.2, ADR 0015) — *still NOT cleared for ship pending counsel (R6)*: a `:flatdata t` reader now reads **any standard representation** (PLAIN_CDR_BE/LE `0x0000`/`0x0001` = XCDR1, PLAIN_CDR2_BE `0x0006` = XCDR2-BE) by **transcoding** it into its canonical XCDR2-LE buffer — decode the body via the type's sibling struct codec (the mode `:xcdr1`/`:xcdr2` + the cursor endianness from the rep-id) then re-serialize XCDR2-LE — instead of **rejecting** a non-`0x0007` payload as before; the native `0x0007` (PLAIN_CDR2_LE) path stays **read-in-place (0-copy)** and PL_CDR/DELIMITED/XML stay a clean false-REJECT. Because XCDR1 caps alignment at 8 and XCDR2 at 4 (DDS-XTypes 1.3 §7.4) the transcode is a **re-align + byte-swap** (handled naturally by decode-then-reserialize, not a pure byte-swap). This **closes the forward-leg false-REJECT** WP-KEYED-FLATDATA flagged — a conformant Connext/Fast DDS peer defaults to XCDR1 — so the keyed-FlatData cross-DDS interop is now **LIVE in BOTH directions vs RTI Connext 7.3.1 + Fast DDS 3.6.1** (forward + reverse: per-key keyhash byte-identical, dispose-by-key resolved; `interop/keyed-flatdata/`). It benefits **all** FlatData types (keyed and unkeyed) — a reader *representation* fix. The transcode is the foreign-rep **fallback off the measured CDR hot path** (`make mem` stays **0.0000** serialize/deserialize/round-trip, no hot-path number changed → no bench), and the untrusted decode is **bounds-checked + fuzzed** (`make fuzz`, the foreign-rep transcode arm incl. a `(safety 0)` variant — no OOB even on a malformed/short payload, NFR-SEC-POSTURE). The separate `PID_DATA_REPRESENTATION` (0x0073) SEDP advertisement (so a peer can PREFER XCDR2 and skip the transcode) is a follow-up, **not** a transcode or keyhash defect; **sender-thread emit resilience landed 2026-06-17** (WP-SENDER-ERROR-RESILIENCE, FR-PF-2, RTPS 2.5 §8.4, ADR 0016 — the WP-ASYNC-FLOW deferred Should-fix; standard DDS, NOT R6): **both** background sender threads — the async sender (`%async-sender-loop`) and the flow scheduler (`%flow-scheduler-loop`) — are now **fault-resilient**, mirroring the RX receiver thread's existing per-iteration guard, so a transient error signalled out of one emit (a hard SHMEM send fault, datagram-build/destination-resolution, arena exhaustion, a future transport) is **caught, counted, observed, and the loop continues** instead of the thread dying and silently stalling every writer it serves; one DRY macro `with-sender-emit-guard` wraps the single emit in each loop (catches `error`, **not** `serious-condition` — a fatal VM state still terminates), the flow path **drops + advances the plan cursor unconditionally** (Option 1: a dropped reliable DATA stays in the HistoryCache and is recovered by the writer's proactive re-push, pushMode=true §8.4.2.2 / the HEARTBEAT-ACKNACK fallback §8.4 — and there is **no hot-spin** because the unsent watermark already advanced at snapshot time, so a drained faulted plan is never re-snapshotted); observability is the bindable **`*sender-emit-error-hook*`** `(condition context count)` (default a clockless rate-limited WARN — log at count 1 / powers of ten) plus per-thread error counters; the guard is **off the measured CDR hot path** (`make mem` stays **0.0000**, no hot-path number changed → no bench warranted, FR-LANG-7) and inert in production (the `*debug-emit-fault*` injector defaults NIL ⇒ byte-identical wire); proven by **6 unit tests** (async-survives, inert/byte-identical, no-spin single + multi-entry-DATA_FRAG, reliable-repair-after-drop, hook-self-error — all green SBCL, the flow/timing ones pass-skip on Clasp) **+ live cross-DDS interop** (the async sender caught 3/3 injected faults and stayed alive while interoperating with a live RTI Connext 7.3.1 + Fast DDS 3.6.1 reliable subscriber, delivery preserved — `interop/sender-resilience/`, tshark-validated); **LZ4 not started** |
| **P5** Durability/late-joiner | TRANSIENT_LOCAL, durable writer history, large-data | **not started** |
| **P6** Security (gated) | the five DDS-Security plugins | **not started** |
| **P7** Tooling/services (gated) | spy, IDL parser, monitoring | partial (a Shapes harness + tshark wire gate exist) |

**Verification right now:** unit/integration suite **green on SBCL and Clasp** (latest run:
all tests passing); quality gates green — `gate-types` (every function is `ftype`-declared),
`gate-hotpath` (no CLOS/alloc in hot-path packages), `mem` (0 bytes/sample), `wire` (tshark
RTPS dissector). **Live Connext interop has run** against RTI Connext 7.3.1 (the harness +
oracle apps are in [`interop/connext/`](interop/connext/)): bidirectional reliable ShapeType
exchange and bidirectional fragmented LargeData exchange (`make large-pub` / `make large-sub`;
`DROP=3` injects fragment loss to exercise NACK_FRAG recovery), tshark-validated on `lo0`
captures. **Live Fast DDS interop has run** against eProsima Fast DDS 3.6.1 (the peer harness
is in [`interop/fastdds/`](interop/fastdds/); `make fastdds-pub` / `make fastdds-sub`):
mutual SPDP/SEDP discovery plus bidirectional **reliable** ShapeType exchange (forward 95/100
with head-of-stream sns 1-5 declared unavailable pre-match (HB first=5 + GAP of sn 5); reverse 250/250 with full pre-match
recovery), HEARTBEAT/ACKNACK verified on the user endpoints both directions and the payloads
tshark-validated — the FR-IO-2 data-plane DoD; the **EquivalenceHash byte-level lock landed**
(S3: Fast DDS's `PID_TYPE_INFORMATION` locked as a regression vector, test
`fastdds-type-information-vector`, matching our hash + serialized size byte-for-byte); and the
**TypeLookup getTypes client leg ran live** (S4 leg A: `make fastdds-tl-probe` queries their
TypeLookup server and consumes the reply — see the P3 row above); S4 leg B (their client
against our TypeLookup server) closed with a documented **finding**: Fast DDS 3.6.1 discards
`PID_TYPE_INFORMATION` from non-eProsima vendors, so no foreign announcement can trigger its
TypeLookup client — the type-blind leg-B harness (`make fastdds-type-probe`) is proven
end-to-end against an eProsima peer and ready unchanged for any peer without that gate (see
the S4 leg B section of [`interop/fastdds/README.md`](interop/fastdds/README.md)). The one
direction that gate blocks — **our `TypeLookup_Reply` consumed by their client** — was then
verified under a controller-approved **NON-STOCK diagnostic** (the vendor gate neutralized in
a local Fast DDS build, afterwards restored and re-proven stock): their stock TypeLookup
engine queried our server (getTypeDependencies + getTypes), **built its DynamicType from our
MINIMAL TypeObject**, and took **600/600** RELIABLE samples — closing the TypeLookup
**CONFIRM-VS-PEER walk** in both directions (the walk table, the exact patch, and the
explicitly-not-stock caveat live in
[`interop/fastdds/README.md`](interop/fastdds/README.md)). With that,
**FR-IO-2 is met and closed** ([ADR 0012](docs/adr/0012-fastdds-peer-fr-io-2.md),
2026-06-12): every stock-citable element — discovery, the bidirectional reliable data
plane, the type-identity oracle, and the TypeLookup client leg — ran against an
**unmodified** Fast DDS 3.6.1 peer; only the leg-B reply direction carries the non-stock
label, and it travels with that result wherever it is cited.

---

## Architecture

Strict bottom-up layering; each layer depends only on the contract of the one below, and
nothing above L0 contains implementation-conditional code.

```
L9  API & tooling     Lisp API, Request/Reply (planned), gen, spy, Shapes harness
L8  Advanced features  batching, async+flow (landed, default-off), Zero-Copy, FlatData, compression, durability, security   (P4+)
L7  Transports         UDPv4 + SHMEM (same-host, auto-select, UDP fallback); TCP planned — behind a pluggable transport record
L6  DCPS               entities, QoS+RxO, conditions/WaitSets, instances, read/take, content filters
L5  Discovery          SPDP, SEDP, builtin endpoints, PID_TYPE_INFORMATION
L4  RTPS engine        submessage codec, reliable/best-effort writer+reader, HistoryCache, HEARTBEAT/ACKNACK/GAP
L3  Type system + gen  XTypes model, TypeObject/TypeIdentifier + EquivalenceHash, the type compiler
L2  CDR codec          XCDR1 + XCDR2 (PLAIN/DELIMITED/MUTABLE), encapsulation, alignment, endianness
L1  Core runtime       static arena, off-heap octet buffers + cursors, pools, MD5, byte-order ops
L0  PAL (per-impl)     raw memory/SAP, threads, sockets, GC control — the ONLY place with #+sbcl/#+clasp
```

### ASDF systems

| System | Layer | Package | Responsibility |
|---|---|---|---|
| `dds-pal`   | L0 | `dds.pal` | platform abstraction (memory, threads, sockets, clock) |
| `dds-core`  | L1 | `dds.core.arena`, `dds.core.buffer`, `dds.core.md5` | arena, buffers/cursors, vendored MD5 |
| `dds-cdr`   | L2 | `dds.cdr` | XCDR1/2 primitive + composite codec, encapsulation |
| `dds-types` | L3 | `dds.types` | `type-support` vtable + registry, XTypes model, assignability, TypeObject serializer |
| `dds-gen`   | L3 | `dds.gen` | `define-dds-type` — the type/IDL compiler |
| `dds-qos`   | L3 | `dds.qos` | DDS 1.4 QoS policies + Requested/Offered matching |
| `dds-rtps`  | L4 | `dds.rtps.*` | submessage codec, reliable engine, HistoryCache, discovery wire |
| `dds-disc`  | L5 | `dds.disc` | SPDP/SEDP discovery + reliable data plane over UDP |
| `dds-dcps`  | L6 | `dds.dcps` | the DDS entity model, conditions, statuses, content filters, builtin topics |
| `dds-xport` | L7 | `dds.xport`, `dds.xport.udp`, `dds.xport.shmem` | the transport record + UDPv4 + shared-memory intra-host transport |
| `dds-shapes`| L9 | `dds.shapes` | standalone Square/ShapeType interop harness |
| `dds-tests` | —  | `dds.tests` | the cross-cutting unit/integration suite |
| `dds`       | —  | umbrella | loads the landed stack |

---

## Build & test

Requires a Lisp (SBCL and/or Clasp) with Quicklisp. The `Makefile` wraps per-implementation
invocation (`scripts/with-sbcl.sh`, `scripts/with-clasp.sh`).

```sh
make build         # load all systems (LISP=./scripts/with-clasp.sh by default; or with-sbcl.sh)
make test          # run the unit/integration suite
make build-all     # build on both landed impls (Clasp + SBCL)
make test-all      # test on both
make gate-types    # every defun has a single-line ftype declaim (FR-LANG-8)
make gate-hotpath  # no CLOS dispatch / per-sample alloc in hot-path files (NFR-CLOS)
make mem           # measured 0 bytes/sample serialize/deserialize (NFR-PERF-8)
make wire          # validate emitted RTPS against the tshark RTPS dissector (FR-TOOL-3)
make all           # build-all + test-all + gates + mem
```

Standalone Shapes interop participants (multicast discovery on domain `DOMAIN`):

```sh
make square-pub COLOR=BLUE       # publish an animated Square (ShapeType)
make square-sub                  # subscribe and print received shapes
make square-spy                  # discovery diagnostic: print discovered participants/locators
```

---

## Quickstart

```lisp
(ql:quickload :dds)

;; 1. Define a topic type. The compiler emits a defstruct + monomorphic XCDR codecs +
;;    key-hash + XTypes TypeObject + a registered type-support.
(dds.gen:define-dds-type sensor (:extensibility :final)
  (id    :i32 :key t)        ; @key -> drives the instance key-hash
  (temp  :i32)
  (label :string))

;; 2. Two participants, a writer, and a reader on the same Topic/type.
(let* ((ts  (dds.types:find-type-support "sensor"))
       (p1  (dds.dcps:create-participant :domain 0))
       (p2  (dds.dcps:create-participant :domain 0))
       (tw  (dds.dcps:create-topic p1 "Sensors" "sensor" ts))
       (tr  (dds.dcps:create-topic p2 "Sensors" "sensor" ts))
       (dw  (dds.dcps:create-datawriter (dds.dcps:create-publisher  p1) tw))
       (dr  (dds.dcps:create-datareader (dds.dcps:create-subscriber p2) tr)))
  ;; 3. Let discovery match the endpoints (caller-driven spin in v1).
  (loop repeat 100 until (plusp (dds.dcps:matched-count p1))
        do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
  ;; 4. Write a sample; take it on the reader.
  (dds.dcps:write-sample dw (make-sensor :id 1 :temp 21 :label "rack-A"))
  (loop repeat 100 for s = (dds.dcps:take-samples dr) until s
        do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02)
        finally (format t "~&got ~s~%"
                        (and s (dds.dcps:cached-sample-data (first s)))))
  (dds.dcps:delete-participant p1)
  (dds.dcps:delete-participant p2))
```

More worked examples — per feature, with API references — are in the
**[wiki](docs/wiki/README.md)**.

---

## Interop with RTI Connext

[`interop/connext/`](interop/connext/) is a Connext-side test harness (built against the
Connext **public API** + your own IDL — clean-room; no Connext source is copied) that serves
as the gold interop/oracle reference: a TypeObject/EquivalenceHash probe, bidirectional
Shapes pub/sub, and a byte-exact XCDR payload capture. It requires a Connext install and is
**not** part of this repo's CI. See [`interop/connext/README.md`](interop/connext/README.md).

[`interop/fastdds/`](interop/fastdds/) is the equivalent **eProsima Fast DDS 3.6.1** peer
harness (FR-IO-2): a standards-conformant peer that — unlike Connext (ADR 0010) — speaks the
builtin TypeLookup service, making it the oracle for our TypeLookup CONFIRM-VS-PEER path. It
runs through the pinned toolchain in `scripts/with-fastdds.sh` and is **not** part of CI.
See [`interop/fastdds/README.md`](interop/fastdds/README.md).

---

## Repository layout

```
src/            the Lisp stack (one directory per ASDF system; see the table above)
docs/
  wiki/         per-system/feature API + use-case guide (start at docs/wiki/README.md)
  specs/        the in-repo OMG specs (DDS 1.4, RTPS 2.5, XTypes 1.3, IDL) — the clean-room source
  adr/          architecture decision records
  verification.csv   the requirement -> evidence -> gate matrix
  provenance.md      clean-room provenance log (NFR-IP)
interop/connext/  the RTI Connext live-test / oracle harness (C++; needs Connext)
interop/fastdds/  the Fast DDS peer harness (C++; pinned toolchain via scripts/with-fastdds.sh)
scripts/        per-impl launchers + the quality-gate scripts
tools/          rtps-pcap (wire-conformance pcap builder)
bench/          performance reports (P4)
REQUIREMENTS.md, IMPLEMENTATION-PLAN.md   the operating contract
sbom.spdx.json    SPDX 3.0.1 JSON-LD SBOM (EU CRA / BSI TR-03183-2; auto-generated)
```

---

## Software Bill of Materials (SBOM)

[`sbom.spdx.json`](sbom.spdx.json) is an **SPDX 3.0.1 JSON-LD** Software Bill of Materials,
structured to the EU **Cyber Resilience Act** (Reg. (EU) 2024/2847, Annex I) and **BSI
TR-03183-2** data-field requirements (SBOM author + timestamp; per component: supplier, name,
version, dependency relationships, licence where determinable, a unique identifier). It covers
the top-level dependencies (`static-vectors`, `cffi`, `bordeaux-threads`) and the Common Lisp
runtime. It is produced by `scripts/generate-sbom.py` from the live `*.asd` top-level
`:depends-on` set, and **kept current automatically**: the `scripts/git-hooks/pre-commit` hook
regenerates + stages it before every commit (activate once per clone with `make hooks`).
Regenerate manually with `make sbom`. Do not hand-edit it.

---

## License

The Common Lisp DDS code and documentation are © 2026 **Gönninger B&T GmbH, Deutschland**
(author: Frank Gönninger), licensed under **Creative Commons Attribution-NoDerivatives 4.0
International (CC BY-ND 4.0)** — share verbatim with attribution; no derivatives. See
[`LICENSE.md`](LICENSE.md) and [`COPYRIGHT.md`](COPYRIGHT.md). Third-party dependencies keep
their own licenses (enumerated in [`sbom.spdx.json`](sbom.spdx.json)).

---

## Intellectual-property posture (clean-room)

Implemented **clean-room from the OMG specifications** (in `docs/specs/`). RTI Connext is a
**behavioral reference via interop only** — its source, headers, and `rtiddsgen` output are
never copied.

---

## Contributing / working in this repo

Read `REQUIREMENTS.md` and `IMPLEMENTATION-PLAN.md`. Non-negotiables: hot-path purity (CLOS-free + zero per-sample
alloc), static-arena memory, no hardcoded wire constants, bounds-checked network parsers,
and **every API symbol carries a docstring and the `docs/wiki/` +
this README are kept in lockstep with the source on every change.**
