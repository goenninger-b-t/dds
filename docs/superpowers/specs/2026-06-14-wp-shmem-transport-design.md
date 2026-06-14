# WP-SHMEM — shared-memory intra-host transport — design

**Goal (FR-XPORT-2).** A same-host transport that delivers the *identical* serialized RTPS datagrams
through a shared-memory ring instead of a UDP socket, selected automatically when both peers run on one
host. It is the patent-clean foundation WP-ZEROCOPY (FR-PF-3) builds on: Zero-Copy later replaces "copy
datagram into the ring" with "write a ~16-byte reference into the ring", reusing this segment +
notification machinery verbatim.

**Scope (v1):** ours-to-ours intra-host delivery with **UDP as the fallback** for every non-SHMEM case.
SHMEM segment layouts are vendor-proprietary (RTI and Fast DDS use different segments and different
vendor locator kinds; there is no standard RTPS SHMEM locator), so cross-vendor SHMEM interop is **out
of scope** — "interop where wire-compatible" (M5 exit gate) excludes SHMEM by construction, and same-host
cross-vendor already falls back to UDP loopback in the field. **Out of v1:** Zero-Copy reference passing
(WP-ZEROCOPY), a Linux `futex` notification fast-path (a measured follow-up; a pthread PROCESS_SHARED condvar is
the portable v1), Windows.

## Contract impact
- The `transport` record (`dds.xport`, IMPLEMENTATION-PLAN §7.5 / FR-XPORT-5) is **unchanged** — a SHMEM
  transport is "construct one record", so the RTPS engine and `%handle-datagram` are untouched.
- **ADR required:** WP-SHMEM **extends the M0-frozen `dds.pal` contract** three ways: (a) SHMEM segment
  primitives, (b) cross-process `PTHREAD_PROCESS_SHARED` mutex+condvar primitives, and (c) the **M1 atomics fast path** — the
  current `cas`/`atomic-incf`/`fence` are M0 stubs (`cas`/`atomic-incf` signal `pal-unimplemented`; `fence`
  is a no-op ignoring `:kind`), verified at `pal-sbcl.lisp:81-96` / `pal-clasp.lisp:102-117`. This WP
  implements them for real. Because an atomic CAS cannot go through the stub's runtime `place-fn`
  indirection, the real atomics are **foreign-SAP-specific primitives** (`cas-sap-u64`,
  `atomic-incf-sap-u64`, plus a real `fence`), which is exactly what the cross-process ring needs. PAL
  edits are the A0 role; the ADR lists the added symbols + the (sole) consumer `dds.xport.shmem`. No
  reader-conditional (`#+sbcl`/`#+clasp`) leaves `dds-pal/`.

## Module layout
New `src/dds-xport/shmem.lisp`, package `dds.xport.shmem`, in the **existing `dds-xport` system** (mirrors
`udp.lisp`; both only construct a `transport` record — the milestone layout's separate `dds-xport-shmem`
system is not warranted for one file). `make-shmem-transport` returns `(values transport handle)`, exactly
like `make-udp-transport`.

## New PAL surface (ADR-gated; CFFI `foreign-funcall`, mirroring `pal-net.lisp`)
- Segment: `shm-create(name size)` = `shm_open(O_CREAT|O_EXCL|O_RDWR,0600)` + `ftruncate` + `mmap(MAP_SHARED)`
  — the create's `mode` is a **variadic arg, so it MUST be passed via `cffi:foreign-funcall-varargs`** on
  arm64 (a plain `foreign-funcall` passes a garbage mode → EACCES on later attach; verified 2026-06-14);
  `shm-attach(name size)` = `shm_open(O_RDWR)` (2-arg, non-variadic) + `mmap`; `shm-detach(h)` = `munmap`+`close`;
  `shm-destroy(name)` = `shm_unlink`; `shm-sap(h)` → the `mmap` base SAP (typed R/W on the foreign region
  via the PAL SAP accessors — the same `sap-ref-*` / `cffi:mem-ref` family the buffer layer uses; the shm
  region is a raw `mmap` pointer, not a `static-vectors` octet-buffer).
- Notification: a **`PTHREAD_PROCESS_SHARED` mutex + condition variable living IN the segment** — NOT named
  semaphores (`sem_open` cannot be driven from the Lisp runtime on macOS arm64: its `mode`/`value` are
  variadic and CFFI/sb-alien mispass them → EINVAL, verified 2026-06-14 via CFFI plain+varargs+sb-alien vs
  working C). PAL primitives (all NON-variadic `pthread_*`, so they work from Lisp on macOS + Linux;
  libpthread already linked → no new dependency): `pshared-mutex-init`/`pshared-cond-init` (creator only,
  set the `PTHREAD_PROCESS_SHARED` attrs), `pshared-lock`/`pshared-unlock`, `pshared-cond-wait`,
  `pshared-cond-signal`/`pshared-cond-broadcast`, `pshared-destroy`. The receiver waits on the cond with the
  predicate **"any lane has data"** (re-checked under the mutex; the SPSC release-store + the mutex acq/rel
  give correct ordering, no lost wakeup). The sender enqueues, then locks + signals. **Clean shutdown:** set
  the in-segment `stop` flag, lock + broadcast, join the receive thread before teardown. No polling.
- Naming: macOS caps shm/sem names at ~31 chars, so names are `"/dds" + 10 hex of a host+GUID hash`, not
  the full GUID. The exact length cap + the leading-slash requirement are pinned from the platform at
  design/impl time, not from memory.
- Atomics (real M1 fast path, replacing the M0 stubs): `fence(kind)` with `:acquire`/`:release`/`:full`
  (SBCL `sb-thread:barrier (:read)/(:write)/(:memory)` — verified; Clasp `mp:fence`), and foreign-SAP
  64-bit atomics `cas-sap-u64(sap off old new)` + `atomic-incf-sap-u64(sap off delta)` (SBCL `sb-ext:cas`
  / `sb-ext:atomic-incf` on `sb-sys:sap-ref-64` — **verified to compile + run**; Clasp `mp:cas` /
  `mp:atomic-incf` — foreign-place support confirmed by a probe-first task, else NFR-PORT Clasp gap).

## Segment & ring layout
One **receive segment per participant** (the receiver creates it; senders attach). Layout:
`[ Header (64B) | Notify block (mutex + cond + stop, cache-aligned) | K SPSC lanes ]`. Header: `magic:u32`,
`version:u32`, `lane_count:u32`, `capacity:u32`, `max_record:u32`. Notify block: a `pthread_mutex_t` + a
`pthread_cond_t` + a `stop:u64`, each at a fixed cache-aligned offset, the block sized to the per-platform
max pthread struct sizes (macOS arm64 mutex 64B/cond 48B; Linux mutex 40B/cond 48B) so one layout serves
both. Per-lane descriptor `{owner_token:u64, write_cursor:u64, read_cursor:u64}` cache-aligned (no false
sharing). All fixed-offset, fixed-width, little-endian; `magic`+`version` are an ABI guard checked on attach.

Each lane is a byte-ring of length-prefixed records `[len:u32][payload:len]`. A record that would straddle
the wrap boundary is preceded by a skip-to-start sentinel (`len = 0xFFFFFFFF`) rather than split. Lane
capacity is derived from the writer's `RESOURCE_LIMITS` QoS so the memory-level and DDS-level limits agree
(IMPLEMENTATION-PLAN arena/pool invariant: pool capacities derived from the relevant `RESOURCE_LIMITS`).
Total segment bytes are drawn so the region is `mmap`-backed
foreign/static memory — the GC neither scans nor moves it (NFR-MEM).

## Concurrency & memory ordering — per-sender SPSC lanes
The path is multi-producer (several same-host participants may target one receiver) / single-consumer
(one receive-loop drains). v1 avoids MPSC by giving **each sending participant its own SPSC lane**:

- **Lane claim (once, at attach):** under the segment's pshared mutex, the sender scans lanes for its
  `owner_token` (already-claimed → reuse) else a free slot (`owner_token`==0), claims it via `store-sap-u64`,
  and unlocks. One mutex-guarded claim per (sender,receiver) pair for the life of the connection — off the
  hot path, so **no foreign-SAP CAS is needed** (this gives Clasp full parity; SBCL could use `cas-sap-u64`
  but the uniform mutex path is simpler).
- **Enqueue (SPSC, no CAS):** copy `[len][payload]` at `write_cursor mod capacity`, then a
  **store-release** publishes the advanced `write_cursor` (`dds.pal:fence :release` — now a real CPU
  barrier — before the aligned 64-bit cursor store). Single producer per lane ⇒ no contended index, no
  compare-and-swap on the hot path.
- **Drain (SPSC, no CAS):** the receiver does a **load-acquire** on each lane's `write_cursor` (aligned
  64-bit load then `dds.pal:fence :acquire`) before reading records up to it, then advances `read_cursor`.
- The receive-loop round-robins the K lanes on each condvar wake.

Steady-state enqueue/drain are lock-free — aligned 64-bit `store`/`load` + the real `fence`, no per-message
CAS; the only lock is the pshared mutex for the one-time lane claim. So the ring needs **no foreign-SAP CAS
at all**, and **SBCL and Clasp are at full parity** (the A4 Clasp foreign-CAS gap is irrelevant here).
`cas-sap-u64`/`atomic-incf-sap-u64` (A3) remain valid PAL primitives kept for a future lock-free-MPSC
optimization, unused by this ring. Cost: a fixed cap of **K** concurrent same-host senders per receiver (K
configurable, default 32); the K+1-th sender falls back to UDP. The single lock-free CAS-MPSC byte-ring
alternative is deferred unless the bench shows the lane model is the bottleneck (FR-LANG-7 — no perf change
on intuition). bordeaux-threads v2 atomics are **not** used (heap `atomic-integer` objects cannot live in
shared memory or be CAS'd cross-process).

## Send / receive (engine untouched)
- `make-shmem-transport(&key participant-guid host-uuid capacity lane-count)`: `shm-create` this
  participant's receive segment, then `pshared-mutex-init`/`pshared-cond-init` its in-segment notify block;
  build a `transport` with `:kind :shmem`, `:locator-kind :shmem`, `:max-message-size` = `max_record`, and
  the closures below.
- `send(locator buffer off len)`: resolve `locator` → segment name; `shm-attach` (cached per-transport by
  name in a hash table populated off the hot path); **bounds-check `len ≤ max_record`** before any write;
  enqueue into this sender's lane; then `pshared-lock` + `pshared-cond-signal` + `pshared-unlock` the
  destination's notify block. Lane full ⇒ return a reject sentinel.
- `receive-loop`: under `pshared-lock`, `pshared-cond-wait` until a lane has data or `stop` is set, then
  drain all committed records across all lanes → hand each record to the **existing `%handle-datagram`**
  callback → every current RTPS/reliability/discovery/lifecycle behaviour runs over SHMEM with zero engine
  changes.
- `open-receive-resource` → this segment's SHMEM locator (for SPDP/SEDP advertisement). `close` → set
  `stop`, broadcast, join the receive thread, `pshared-destroy`, detach all attached segments, `shm-destroy`
  the own segment.
- `stop-node` **joins the receive-loop thread before** detach/destroy (the same ordering rule the existing
  receiver-thread teardown uses — avoids the use-after-free a prior session hit by freeing buffers before
  joining).

## Discovery / locator
Advertise a **vendor-specific SHMEM `Locator_t`** beside the UDP locator in SPDP (metatraffic) and SEDP
(user) endpoints: a `kind` we own + document (there is **no** standard RTPS SHMEM kind; the value is
pinned in the ADR, not from memory; cross-vendor peers see an unknown kind and ignore it — fail-open), the
16-byte `address` carrying the segment-name hash, `port` a discriminator. A peer selects SHMEM iff (a) it
understands our `kind` **and** (b) it shares our **host-uuid** (a boot/host hash advertised in SPDP);
otherwise UDP. Purely additive — no existing discovery behaviour changes; a peer that ignores the SHMEM
locator still matches and talks over UDP.

## Safety / backpressure / lifecycle
- **A segment written by another process is an untrusted parser surface — treat the ring exactly like the
  wire.** Bounds-check every `len`/offset against lane extents before reading, even at `(safety 0)`
  (NFR-SEC-POSTURE); a buggy or malicious peer process must never cause an OOB read or crash the receiver.
  The ring record parser is added to `make fuzz`.
- Lane/ring full ⇒ reject ⇒ **RESOURCE_LIMITS / UDP fallback for that datagram**; reliable samples remain
  in the HistoryCache and repair via HEARTBEAT/ACKNACK (RTPS 2.5 §8.4.2.2). **Never a GC-heap fallback**
  (NFR-MEM).
- Stale segments (carrying their in-segment pthread mutex/cond) left by a crashed peer are reclaimed on the next `shm-create`: `O_EXCL` fails
  ⇒ `shm_unlink` + recreate.

## Hot-path purity & memory (gate-hotpath, mem)
`send` stays slot-read + `funcall` via the `transport` record (FR-XPORT-5) — no `defgeneric` dispatch.
The enqueue is raw SAP writes; the drain hands existing buffers to `%handle-datagram`. **No consing, no
per-sample CLOS, 0 bytes/sample steady-state** (the ring is preallocated foreign/static). The
`hotpath-purity-gate` and `make mem` (0-alloc) cover the SHMEM `send`/drain path.

## Testing / bench (acceptance)
- **Functional:** the existing UDP-loopback integration tests re-run over SHMEM (reliable + best-effort
  round-trip, multi-sample, large-sample via DATA_FRAG-over-SHMEM) — same `%handle-datagram`, so a pass
  proves engine-transparency.
- **Cross-process:** two separate Lisp processes attach to one segment and exchange samples (the real
  proof; loopback within one image does not exercise cross-process mmap/condvar).
- **Concurrency stress:** N sender processes → 1 receiver; assert no loss, no corruption, no deadlock (the
  SPSC-lane correctness gate).
- **Security:** fuzz the ring record parser (malformed `len`, wrap-sentinel edge, oversized record) under
  `make fuzz`.
- **Bench (FR-LANG-7, NFR-PERF-6):** SHMEM vs UDP-loopback latency p50/p99/p99.99 + throughput +
  bytes/sample → `bench/report/2026-06-14-wp-shmem.md`; target NFR-PERF-6 (large-sample latency within
  **1.5×** of the SHMEM+mmap floor) + the 0-alloc steady-state assertion.
- **Gates:** build / test / gate-hotpath / mem / fuzz green on **SBCL + Clasp**; Allegro is a documented
  NFR-PORT gap (the licensed build is absent in this environment), mirroring the existing Clasp latitude.

## Open / deferred (explicit, not silent)
- Linux `futex` notification fast-path — deferred, measured follow-up; a pthread PROCESS_SHARED condvar is v1.
- K-sender cap overflow → UDP fallback is logged, not silent (no hidden capacity ceiling).
- AllegroCL perf-gate parity — blocked on the licensed build; gap documented per NFR-PORT.
