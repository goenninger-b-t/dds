# Transports & the Platform Abstraction Layer

The transport layer (L7, `dds-xport`) decouples the RTPS engine from the wire: every transport is a single
`transport` record — a `defstruct` whose per-packet `send` (and lifecycle) operations are *stored functions*,
so the latency path is one slot read plus a `funcall`, never a CLOS dispatch. Adding a transport means
constructing one record; the engine above is untouched (FR-XPORT-5). The Platform Abstraction Layer (L0,
`dds-pal`) is the single frozen contract every layer depends on for off-heap static memory, atomics,
threads/locks/condvars, UDPv4 sockets, the monotonic clock, GC control, and optimization hints — and it is the
**only** place in the tree where `#+sbcl`/`#+clasp` reader conditionals are permitted (NFR-PORT). Landed today:
UDPv4 unicast/multicast over each implementation's native `sb-bsd-sockets`, plus a synchronous loopback mock
for tests.

Package nicknames used below: `dds.xport`, `dds.xport.udp`, `dds.pal` (and `dds.core.buffer`,
`dds.core.arena` in the examples).

## API reference

### The transport record — `dds.xport`

The pluggable transport record (IMPLEMENTATION-PLAN §7.5). Construct it with `make-transport` /
`make-mock-transport`, never the internal `%make-transport`.

| Symbol | Kind | Description |
|---|---|---|
| `dds.xport:transport` | struct type | Pluggable transport record; per-packet `send` + lifecycle ops are stored function slots so the latency path stays dispatch-free. |
| `dds.xport:transport-p` | predicate | True if its argument is a `transport`. |
| `dds.xport:transport-kind` | accessor | Transport kind keyword (e.g. `:mock`, `:udpv4`). |
| `dds.xport:transport-send` | accessor | The stored per-packet send function (called by `send`). |
| `dds.xport:transport-receive-loop` | accessor | The stored receive-loop function slot. |
| `dds.xport:transport-open-receive-resource` | accessor | The stored open-receive-resource function slot. |
| `dds.xport:transport-close` | accessor | The stored lifecycle close function slot. |
| `dds.xport:transport-max-message-size` | accessor | Maximum message size for this transport (`fixnum`; default 65507). |
| `dds.xport:transport-locator-kind` | accessor | Locator kind keyword this transport understands. |
| `dds.xport:send` | function | `(transport locator buffer off len)` — dispatch-free per-packet send: one slot read + `funcall` (FR-XPORT-5). Declared `inline`. |
| `dds.xport:make-transport` | function | Public constructor; `&key kind send receive-loop open-receive-resource close max-message-size locator-kind`. Adding a transport = constructing one of these; the RTPS engine is untouched. |
| `dds.xport:make-mock-transport` | function | `&key on-receive max-message-size` — synchronous loopback: `send` hands the octets straight to `on-receive`, called as `(buffer off len)`. Deterministic; used by the M0 echo test. |

### UDPv4 transport — `dds.xport.udp`

Wraps the frozen `dds.xport` transport record around the native `dds.pal` UDP socket layer (ADR 0006).
The raw PAL socket has no slot in the frozen record, so `make-udp-transport` returns it as a **second value**
and the `send`/`close` closures capture it.

| Symbol | Kind | Description |
|---|---|---|
| `dds.xport.udp:make-udp-transport` | function | `&key host port` — open a UDPv4 socket bound to `host:port` (defaults `"0.0.0.0"`/`0`) and wrap it in a transport record. `send` assumes `off` is 0 for v1 (whole-buffer datagram from index 0). Returns `(values transport socket)`. |
| `dds.xport.udp:udp-transport-local-port` | function | `(socket)` — the bound local port of the UDP socket. |
| `dds.xport.udp:udp-transport-recv` | function | `(socket buffer)` — block until a datagram arrives; read it into `buffer` up to its capacity. Returns `(values size sender-address sender-port)`. |
| `dds.xport.udp:start-udp-receiver` | function | `(socket on-datagram)` — spawn a thread that blocks on `socket`, receiving each datagram into a 64 KiB octet-buffer and calling `(on-datagram buffer size)`. The thread exits when the socket is closed; one malformed datagram does not kill it. Returns the thread. |
| `dds.xport.udp:udp-locator` | struct type | Destination address for a UDPv4 send: dotted-quad `host` + `port`. |
| `dds.xport.udp:make-udp-locator` | function | `&key host port` — construct a `udp-locator` (defaults `"127.0.0.1"`/`0`). |
| `dds.xport.udp:udp-locator-host` | accessor | The locator's dotted-quad host string. |
| `dds.xport.udp:udp-locator-port` | accessor | The locator's UDP port (`(unsigned-byte 16)`). |
| `dds.xport.udp:run-udp-transport-test` | function | Transport-level UDP loopback self-test (sender `send` -> receiver recv on 127.0.0.1); returns `T`. |
| `dds.xport.udp:run-udp-receiver-test` | function | Receiver-thread loopback self-test; a background thread receives a datagram and records it; returns `T`. |

### Shared-memory transport — `dds.xport.shmem`

The same-host intra-host transport (FR-XPORT-2). It delivers the **identical** serialized RTPS datagrams
through a POSIX shared-memory ring instead of a UDP socket, and like every transport it constructs one
frozen `dds.xport:transport` record — the RTPS engine and `%handle-datagram` are untouched. It is the
patent-clean foundation a future Zero-Copy path (FR-PF-3) builds on, reusing this segment + notification
machinery. See [When SHMEM engages](#when-shmem-engages-and-what-stays-on-udp) and
[SHMEM architecture](#shmem-architecture) below for the selection rule and the segment layout.

| Symbol | Kind | Description |
|---|---|---|
| `dds.xport.shmem:make-shmem-transport` | function | `&key participant-guid host-uuid lane-count capacity` — create this participant's SHMEM **receive** segment (header + pshared notify block + `lane-count` per-sender SPSC lanes) and wrap it in a `transport` record whose `send` attaches to the destination segment and enqueues. `capacity` is the per-lane ring size in bytes (multiple of 8; default 65536); `lane-count` defaults 8. Returns a `shmem-transport`. |
| `dds.xport.shmem:shmem-transport` | struct type | Owns a participant's receive segment + the frozen `transport` record + a per-sender attach cache + this sender's lane token + the drain sink + the receiver thread (the bits that have no slot in the frozen record). |
| `dds.xport.shmem:shmem-transport-transport` | accessor | The frozen `dds.xport:transport` record to plug into the engine. |
| `dds.xport.shmem:shmem-transport-locator` | function | `(st)` — the `shmem-locator` a peer uses to send to `st` (segment name + host-uuid + ring geometry). |
| `dds.xport.shmem:shmem-locator` | struct type | A SHMEM send destination: receiver segment `name` + same-host `host-uuid` + ring `lane-count`/`capacity`. |
| `dds.xport.shmem:make-shmem-locator` | function | `&key name host-uuid lane-count capacity` — construct a `shmem-locator`. |
| `dds.xport.shmem:shmem-locator-name` / `-host-uuid` / `-lane-count` / `-capacity` | accessors | The locator's fields. |
| `dds.xport.shmem:seg-name-for-guid` | function | `(guid)` — the deterministic receive-segment name a peer's 12-octet GUID prefix maps to. A sender derives the destination segment name from the remote participant's prefix, so the discovery layer addresses a same-host peer with `make-shmem-locator :name (seg-name-for-guid remote-prefix)`. |
| `dds.xport.shmem:start-shmem-receiver` | function | `(st on-datagram)` — spawn the receive thread: it blocks on the segment's pshared cond until a lane has data (or stop), then drains **all** lanes and calls `(on-datagram sink size)` per record. Uses the conditional-wakeup parked flag so a busy sender skips the futex wake while the thread is draining. |
| `dds.xport.shmem:stop-shmem-receiver` | function | `(st)` — signal the receive thread to exit (set stop + broadcast) and **join it before** any segment teardown (no use-after-free). |
| `dds.xport.shmem:shmem-receive-drain` | function | `(st on-datagram)` — drain all lanes of `st`'s own receive segment once, calling `on-datagram` per record (the single-shot drain the threaded receiver wraps). |
| `dds.xport.shmem:shmem-transport-close` | function | `(st)` — stop the receiver, destroy the pshared objects, detach all attached + own segments, and unlink the own segment. |
| `dds.xport.shmem:shm-attach-by-name-reliable-p` | function | `()` — `T` except on Clasp/macOS-arm64, whose plain `cffi:foreign-funcall` mispasses `shm_open`'s variadic `mode_t` so a created segment is unre-openable by name (NFR-PORT gap, ADR 0013). The transport requires by-name attach, so its loopback tests pass-skip where this is `NIL`. A runtime check, not a reader conditional. |
| `dds.xport.shmem:run-shmem-transport-test` | function | Transport-level SHMEM loopback in one image (tx `send` -> rx own-segment drain); returns `T`. Pass-skips on the Clasp/macOS by-name-attach gap. |
| `dds.xport.shmem:run-shmem-receiver-test` | function | Receiver-thread loopback self-test; returns `T`. Pass-skips on the same gap. |
| `dds.xport.shmem:run-shmem-stress-test` | function | Contention self-test: N sender lanes -> one receiver, asserting no loss/corruption/deadlock; returns `T`. |

The transport selection is a discovery-layer policy, controlled by one special variable:

| Symbol | Kind | Description |
|---|---|---|
| `dds.disc:*shmem-enabled*` | special var | Master switch (read once per node at `make-disc-node`) for routing same-host user DATA over SHMEM instead of UDP (FR-XPORT-2). Default `T` on SBCL everywhere and Clasp/Linux (where the SHMEM package is present and by-name attach works); `NIL` on Clasp/macOS (the `shm_open` variadic-mode ABI gap, ADR 0013). Rebind to `NIL` before `make-disc-node` to force the all-UDP path. Not a wire constant — a local transport-selection policy. |

### The PAL contract — `dds.pal`

The single frozen L0 surface (IMPLEMENTATION-PLAN §7.6). Everything above L0 depends only on these symbols;
per-impl bodies live in `pal-<impl>.lisp`.

**Failures are returned, never signalled (ADR 0064).** Every fallible PAL call returns
**`(values result status)`**: `status` is `nil` on success, otherwise a keyword naming the failure
(`:setsockopt-failed`, `:eof`, `:timeout`, `:shm-open-failed`, `:ftruncate-failed`, `:mmap-failed`,
`:mutex-init-failed`, `:cond-init-failed`, `:send-failed`). Nothing in this layer signals a Lisp condition
— a failure is a value the caller tests and propagates, and the toplevel DDS API turns it into a
`ReturnCode_t`. Inside a `defun*` body, propagate with **`(try form)`** (return `(values nil status)` from
the enclosing function if `form` failed, else yield its primary value) and fail with **`(bail :status)`**.
Conditions raised by *dependencies* (e.g. `sb-bsd-sockets:socket-error`) are caught at the PAL call that
makes them and converted to a status there.

**Conditions & introspection**

| Symbol | Kind | Description |
|---|---|---|
| `dds.pal:pal-error` | condition | Base class for all PAL-level failures (control plane only). |
| `dds.pal:pal-unimplemented` | condition | Signalled by a capability stub not yet provided for this build. |
| `dds.pal:pal-op` | reader | The operation symbol carried by a `pal-unimplemented`. |
| `dds.pal:+pal-capabilities+` | constant | The capability groups every PAL must eventually satisfy: `(:memory :atomics :threads :sockets :clock :gc-control :opt-hints)`. |
| `dds.pal:pal-impl-name` | function | `()` — keyword naming the running implementation (e.g. `:sbcl`). |

**Memory (off-heap, non-GC'd, raw-pointer-addressable)**

| Symbol | Kind | Description |
|---|---|---|
| `dds.pal:alloc-static` | function | `(n-bytes)` — allocate `n-bytes` of off-heap octet memory the GC neither scans, moves, nor reclaims; returns a foreign-backed `(unsigned-byte 8)` vector with a GC-stable address; contents unspecified. On Clasp, satisfied from a length-keyed recycle pool when possible. |
| `dds.pal:free-static` | function | `(vec)` — release memory from `alloc-static`. Idempotency is the caller's job. On Clasp this recycles `vec` into the pool instead of deallocating: the runtime's `gctools:deallocate-unmanaged-instance` GC_frees an interior pointer and corrupts the Boehm heap (documented NFR-PORT gap until fixed upstream). |
| `dds.pal:static-pointer` | function | `(vec)` — the raw foreign pointer (a system-area-pointer on SBCL) to `vec`, for syscalls. |
| `dds.pal:static-length` | function | `(vec)` — octet length of a static region. |
| `dds.pal:mem-ref-u8` | function | `(vec index)` — typed raw read of one octet (declared `inline`). |
| `dds.pal:mem-set-u8` | function | `(vec index value)` — typed raw write of one octet (declared `inline`). |

**Atomics**

| Symbol | Kind | Description |
|---|---|---|
| `dds.pal:atomic-cell` | struct/type | A PAL atomic counter cell: a single `(unsigned-byte 64)` `value` slot that `cas`/`atomic-incf` operate on atomically. The **concrete place** the generic atomics needed (ADR 0041): the native RMW primitives are place-form macros that must see a compile-time-known place, so the old runtime `place-fn` indirection could not be lowered to a hardware atomic; a first-class cell whose fixed slot they target exposes them as ordinary functions. A single `(unsigned-byte 64)` slot is the one representation both impls accept for BOTH ops (probed). |
| `dds.pal:make-atomic-cell` | function | `(&key value)` — construct an `atomic-cell` (`value` defaults 0). |
| `dds.pal:atomic-cell-value` | function | `(cell)` — read the live value; a **plain (relaxed) load** (use `cas`/`atomic-incf` for an atomic RMW, `fence` for standalone ordering). |
| `dds.pal:cas` | function | `(cell old new)` — **generic compare-and-swap** (M0 stub CLOSED, ADR 0041): if `cell`'s value = `old` store `new`; returns the PREVIOUS value either way (succeeded iff the return is = `old`). Full-barrier (sequentially-consistent) RMW: SBCL `sb-ext:cas`, Clasp `mp:cas` over the `(unsigned-byte 64)` slot. Returns the previous value, matching `cas-sap-u64`. Runs on **both impls** (unlike the SAP forms). |
| `dds.pal:atomic-incf` | function | `(cell &optional delta)` — **generic fetch-add** (M0 stub CLOSED, ADR 0041): atomically add signed `delta` (default 1) modulo 2^64; returns the NEW value (a negative `delta` decrements). SBCL `sb-ext:atomic-incf` (returns old, normalized to new here), Clasp `mp:atomic-incf` (returns new). Matches `atomic-incf-sap-u64`. Runs on **both impls**. |
| `dds.pal:fence` | function | `(&optional kind)` — **real memory barrier (M1):** `:acquire` = load barrier, `:release` = store barrier, `:full` = full barrier. SBCL maps to `sb-thread:barrier`; the SHMEM ring uses it for the release/acquire publish/consume of lane cursors and the full StoreLoad fence of the conditional-wakeup handshake. |

**SAP-targeted 64-bit atomics (M1 fast path, ADR 0013)** — the SHMEM ring needs true hardware atomics on a
raw foreign 64-bit cell addressed by `(sap, byte-offset)`, which the generic `atomic-cell` ops (a Lisp
struct slot, not a foreign cell) do not cover.

| Symbol | Kind | Description |
|---|---|---|
| `dds.pal:load-sap-u64` | function | `(sap offset)` — aligned 64-bit read of the foreign location at `sap+offset` (bytes). |
| `dds.pal:store-sap-u64` | function | `(sap offset value)` — aligned 64-bit write of `value` at `sap+offset`. |
| `dds.pal:cas-sap-u64` | function | `(sap offset old new)` — atomic compare-and-swap of the u64 at `sap+offset`; returns the PREVIOUS value (= `old` on success). **SBCL only** (`sb-ext:cas` over `sb-sys:sap-ref-64`, a full barrier); **Clasp signals `pal-unimplemented`** — Clasp has no usable hardware atomic over a raw foreign cell (NFR-PORT gap, ADR 0013). Unused by the v1 SHMEM ring (the lane claim is mutex-guarded) and no longer by the Zero-Copy loan release (which now uses `cas-sap-u32` directly on the refcount sub-field — see below). |
| `dds.pal:cas-sap-u32` | function | `(sap offset old new)` — atomic compare-and-swap of the u32 at `sap+offset`; returns the PREVIOUS value (= `old` on success). **SBCL only** (`sb-ext:cas` over `sb-sys:sap-ref-32`, disassembled to arm64 `CASAL` — a 32-bit full barrier, the same acquire+release ordering as the u64 CAS); **Clasp signals `pal-unimplemented`** (same NFR-PORT gap, ADR 0013). Backs the lock-free `%zc-release`: it CASes ONLY the u32 refcount cell directly, so the combined `(generation<<32)|refcount` word is never materialised — **0-alloc at any generation** (a `cas-sap-u64` overlay of that word boxed a bignum once the generation reached ~2^30; NFR-MEM); the full barrier orders the reader's payload reads before `refcount→0` (WP-ZC-LOAN-LOCKFREE, R6, ADR 0018; NOT cleared for ship — pending counsel). |
| `dds.pal:atomic-incf-sap-u64` | function | `(sap offset delta)` — atomically add `delta` to the u64 at `sap+offset`; returns the NEW value. SBCL only (CAS-retry fetch-add); Clasp signals `pal-unimplemented` (same gap). Unused by the v1 ring. |

**POSIX shared memory + cross-process notification (ADR 0013)** — the SHMEM transport's segment and its
in-segment `PTHREAD_PROCESS_SHARED` mutex/condvar. All thin CFFI wrappers; no external library dependency.

| Symbol | Kind | Description |
|---|---|---|
| `dds.pal:shm-create` | function | `(name size)` — `shm_open(O_CREAT\|O_EXCL\|O_RDWR,0600)` + `ftruncate` + `mmap(MAP_SHARED)`. The creator. Returns `(values segment nil)`, or `(values nil status)` — `:shm-open-failed` / `:ftruncate-failed` / `:mmap-failed`, each closing the fd it opened. A stale segment from a crashed peer is reclaimed (`O_EXCL` fails -> `shm_unlink` + recreate). |
| `dds.pal:shm-attach` | function | `(name size)` — `shm_open(O_RDWR)` + `mmap`; a sender attaches to a receiver's existing segment by name. Returns `(values segment nil)`, or `(values nil :shm-open-failed)` when no such segment exists — the **ordinary** outcome for a stale/forged peer name, which the zero-copy reader caches as "no pool". |
| `dds.pal:shm-detach` | function | `(handle)` — `munmap` + `close`. |
| `dds.pal:shm-destroy` | function | `(name)` — `shm_unlink`. |
| `dds.pal:shm-sap` | function | `(handle)` — the `mmap` base SAP, for the typed `sap-ref-*`/`cffi:mem-ref` reads/writes the ring uses. |
| `dds.pal:shm-segment-size` | function | `(handle)` — the segment's byte length. |
| `dds.pal:pshared-mutex-init` / `pshared-cond-init` | functions | `(sap offset)` — creator-only init of a `PTHREAD_PROCESS_SHARED` mutex / condvar living **in** the segment. Return `(values t nil)` or `(values nil :mutex-init-failed / :cond-init-failed)`. |
| `dds.pal:pshared-lock` / `pshared-unlock` | functions | `(sap offset)` — lock / unlock the in-segment mutex. |
| `dds.pal:pshared-cond-wait` | function | `(sap cond-offset mutex-offset)` — wait on the in-segment cond, releasing the mutex. |
| `dds.pal:pshared-cond-signal` / `pshared-cond-broadcast` | functions | `(sap offset)` — wake one / all waiters on the in-segment cond. |
| `dds.pal:pshared-destroy` | function | `(sap mutex-offset cond-offset)` — destroy the in-segment mutex + cond. |

**Threads, locks, condition variables**

| Symbol | Kind | Description |
|---|---|---|
| `dds.pal:spawn` | function | `(fn &key name)` — spawn a thread running `fn` (default name `"dds"`); returns the thread. |
| `dds.pal:join` | function | `(thread)` — block until `thread` finishes; return its result. |
| `dds.pal:make-lock` | function | `(&optional name)` — create a mutex (default name `"dds-lock"`). |
| `dds.pal:with-lock` | macro | `((lock) &body body)` — evaluate `body` with `lock` held. |
| `dds.pal:make-condvar` | function | `()` — create a condition variable for use with `condvar-wait` / `condvar-signal`. |
| `dds.pal:condvar-wait` | function | `(cv lock &optional timeout-seconds)` — wait on `cv` releasing `lock`. `nil` timeout waits forever, else a bounded wait; re-check the predicate on wake (ADR 0007). |
| `dds.pal:condvar-signal` | function | `(cv)` — wake one thread waiting on `cv`. |

**UDPv4 sockets (native, FR-XPORT-1)**

| Symbol | Kind | Description |
|---|---|---|
| `dds.pal:udp-open` | function | `(&key host port reuse-port)` — open a UDPv4 socket bound to `host:port` (port 0 = ephemeral); `reuse-port` enables `SO_REUSEPORT` before bind. Returns `(values socket nil)`, or `(values nil :setsockopt-failed)` — the half-open socket is closed first, so a failed open leaks no fd. |
| `dds.pal:udp-local-port` | function | `(socket)` — the bound local port of `socket`. |
| `dds.pal:udp-send-to` | function | `(socket buffer length host port)` — send `length` octets of `buffer` from `socket` to `host:port`, via raw `sendto(2)` with **zero allocation per datagram** (ADR 0065). Returns `sendto`'s value: the octet count sent, or **negative** on failure — UDP is best-effort, so the caller drops the datagram and the reliable layer recovers via HEARTBEAT/ACKNACK. **`buffer` MUST be PAL-static (`dds.pal:alloc-static`)**: it is handed to the kernel by raw pointer, and NFR-MEM requires anything addressed by a pointer/SAP to be foreign/static, never a plain heap array (SBCL's and AllegroCL's GCs move objects, so a heap vector's address can be invalidated underneath a blocking syscall). |
| `dds.pal:*udp-raw-sendto*` | special variable | Default `T`: `udp-send-to` fills a pre-allocated per-thread foreign `struct sockaddr_in` and calls `sendto(2)` directly. `NIL`: the original `sb-bsd-sockets:socket-send` path, which allocates ~360 B per datagram — about 262 B of it re-parsing the dotted-quad destination **string** on every send. **The datagram bytes on the wire are identical either way**; only the syscall wrapper differs. Kept as the A/B lever ADR 0062 requires for sizing an allocation change against `make gate-mem`, and as an escape hatch should a platform's `sockaddr_in` layout differ from the Darwin and Linux ones documented in ADR 0065. `run-udp-loopback-test` asserts byte-exact delivery under **both** arms, which is what makes a wrong layout fail loudly rather than silently drop every datagram. |
| `dds.pal:udp-recv` | function | `(socket buffer length)` — block until a datagram arrives; return `(values size sender-address sender-port)`, with **zero allocation per datagram** (ADR 0066). Used from a dedicated receiver thread. On the raw path the sender address is **not reported** (`NIL`) — nothing in the stack uses it, since RTPS identifies a source by GuidPrefix, never by IP. **A NEGATIVE size means the socket was closed**: `recvfrom(2)` reports that by returning −1 where `socket-receive` signalled, so **a receiver loop must check for it and exit**, or the thread spins and `stop-node`'s join never returns. Zero is *not* an exit condition — a zero-length datagram is legal, and treating it as end-of-stream would let any peer kill a receiver thread. **`buffer` MUST be PAL-static**, as for `udp-send-to`. |
| `dds.pal:*udp-raw-recvfrom*` | special variable | Default `T`: `udp-recv` calls `recvfrom(2)` directly with `src_addr = NULL`. `NIL`: the original `sb-bsd-sockets:socket-receive` path, which allocates ~305 B per datagram — most of it building a sender sockaddr and converting it to a Lisp address that no caller reads. A/B lever and escape hatch, as `*udp-raw-sendto*` is; `run-udp-loopback-test` asserts byte-exact delivery under both arms. |
| `dds.pal:udp-close` | function | `(socket)` — close `socket`. |
| `dds.pal:udp-set-reuse-port` | function | `(socket)` — enable `SO_REUSEPORT` so multiple participants on one host can share the SPDP multicast port. Must be called before bind. Returns `(values t nil)` or `(values nil :setsockopt-failed)`. |
| `dds.pal:udp-join-multicast` | function | `(socket group)` — join the IPv4 multicast `group` (dotted-quad) on the default interface and enable loopback (RTPS 2.5 §9.6.1.1). The socket must already be bound to the multicast port. Returns `(values t nil)` or `(values nil :setsockopt-failed)` — a node that cannot join the SPDP group discovers nobody, so the caller must surface it rather than proceed deaf. |

**Clock**

| Symbol | Kind | Description |
|---|---|---|
| `dds.xport.shmem:*shmem-rx-spin-iterations*` | special | **Latency vs CPU.** How many times the SHMEM receiver re-checks its lanes *before* it takes the mutex and parks on the pshared condvar. **Default 0** (park immediately). Parking costs a cross-process futex round trip — the sender's `pthread_cond_signal` plus the receiver having to be *scheduled* onto a core — measured at **~6–7 µs of the ~19 µs 256 B one-way**. A receiver still spinning when the datagram lands skips both halves, and costs the sender nothing (`%shmem-send` only signals when `parked=1`). Measured: **spin 0 → 19 125 ns; 500 → 12 270 ns; 5 000 → 11 791 ns; 50 000 → 11 750 ns** — it saturates by ~500. CPU cost is modest and bounded (responder CPU 0.76 s → 0.98 s over the same run), because the spin exits the instant data lands and a genuinely idle receiver still parks and *stays* parked. Set it (≈500–2 000) on a latency-critical node. **The spin runs OUTSIDE the pshared mutex** — putting it inside (where `%rx-wait-for-work` runs) starves `stop-shmem-receiver`, which needs that mutex to broadcast: latency went 7× *worse* and long spins hung on teardown. |
| `dds.pal:monotonic-ns` | function | `()` — monotonic time in nanoseconds, via `clock_gettime` (CFFI, one shared implementation on both impls). The timebase for every latency measurement and RTPS timer deadline. **Resolution 41 ns**; cost 16 ns/call on SBCL, 633 ns/call on Clasp (see below). Superseded the M0 `get-internal-real-time` clock, which had **1 µs** resolution on SBCL — every latency figure published before this landed was quantised to 1 µs per timestamp. |
| `dds.pal:*clock-monotonic-id*` | special | The `clock_gettime` clk_id, chosen by **measured resolution**, not by name: `4` = `CLOCK_MONOTONIC_RAW` on macOS (id `6`, `CLOCK_MONOTONIC`, is deliberately coarsened to a 1 µs tick there), `1` = `CLOCK_MONOTONIC` on Linux (ns, vDSO). Picking by name is silently wrong both ways — id `6` on Linux is `CLOCK_MONOTONIC_COARSE` (~ms) and the call still *succeeds*. |
| `dds.pal:*clock-gettime-fp*` | special | The `clock_gettime` pointer, resolved **once** at load. Calling a foreign function *by name* on Clasp re-resolves the symbol on **every call** — measured 4230 ns/call (even bare `getpid()` costs 4824 ns) vs 379 ns through a cached pointer. Every hot foreign call must go through a cached pointer. |
| `dds.pal:*thread-timespec*` | special | Per-thread pre-allocated foreign `struct timespec` for `monotonic-ns`, bound by `spawn`. `with-foreign-object` is a real `malloc` on Clasp (~3.3 µs/call); it must be reused — but per-thread, never global, because the receiver and user threads read the clock concurrently and would tear each other's timestamp. |
| `dds.pal:call-with-thread-clock` | function | `(fn)` — run FN with this thread's `monotonic-ns` scratch bound. `spawn` wraps every PAL thread in it; a thread the PAL did not create (e.g. a bench harness) may wrap itself to get the fast path instead of the `with-foreign-object` fallback. |

> **Clasp clock cost — a known, root-caused platform limit.** Clasp is **633 ns/call** vs SBCL's **16 ns**, with the *same* clock and the *same* 41 ns resolution. The two avoidable costs are fixed above (per-call `dlsym`, per-call foreign `malloc`); the ~600 ns residual is Clasp's **libffi dynamic dispatch** — CFFI exposes no direct-call compiler macro on Clasp (`compiler-macro-function` is `NIL` for `foreign-funcall` and `foreign-funcall-pointer`), whereas SBCL emits a direct inline call. Closing it requires an upstream CFFI/Clasp contribution, not a change here. It is affordable because `monotonic-ns` is **not on the per-sample path** (it serves blocking-wait deadlines, the flow-controller token bucket on opt-in async writers, and shmem stress loops). **Consequence:** sub-µs *profiling* is done on SBCL; both impls remain fully validated for correctness.

**GC control / measurement**

| Symbol | Kind | Description |
|---|---|---|
| `dds.pal:gc-suggest` | function | `()` — suggest a GC to the implementation. M0 no-op. |
| `dds.pal:with-gc-inhibited` | macro | `(&body body)` — M0 no-op wrapper; an unsafe `without-gcing` path lands behind an explicit flag in a later ADR. |
| `dds.pal:bytes-consed` | function | `()` — total bytes consed so far (the NFR-PERF-8 zero-alloc oracle). |

**Optimization hints**

| Symbol | Kind | Description |
|---|---|---|
| `dds.pal:with-hot-optimizations` | macro | `(&body body)` — expand to this build's strongest safe-enough hot-path optimize declarations (M0 baseline keeps `safety` at 1 while manual bounds-checks are established). |

## Examples

Each block below is adapted from a passing test in `src/dds-tests/`.

### Mock transport — synchronous loopback (`on-receive`)

The mock transport's `send` hands its octets straight to your `on-receive` callback `(buffer off len)`.
Deterministic and dependency-free, which is why the M0 echo test uses it. Adapted from `run-echo-test`
(`src/dds-tests/echo-test.lisp`).

```lisp
(let ((received nil))
  (let ((tr (dds.xport:make-mock-transport
             :on-receive
             (lambda (buffer off len)
               (declare (ignore off))
               (let ((rc  (dds.core.buffer:cursor buffer :endianness :little))
                     (dst (make-array len :element-type '(unsigned-byte 8))))
                 (dds.core.buffer:get-octets rc dst 0 len)
                 (setf received dst))))))
    ;; send 8 octets; the mock delivers them inline to on-receive
    (let* ((payload (make-array 8 :element-type '(unsigned-byte 8)
                                  :initial-contents '(68 68 83 45 69 67 72 79)))  ; "DDS-ECHO"
           (sbuf    (dds.core.buffer:make-octet-buffer 16))
           (wc      (dds.core.buffer:cursor sbuf :endianness :little)))
      (dds.core.buffer:put-octets wc payload 0 (length payload))
      (dds.xport:send tr nil sbuf 0 (length payload)))   ; locator ignored by the mock
    received))   ; => #(68 68 83 45 69 67 72 79)
```

### UDPv4 loopback — transport `send` to a blocking recv

Open two UDPv4 transports on `127.0.0.1` (ephemeral ports), send through the transport record, and read the
datagram back with `udp-transport-recv`. Adapted from `dds.xport.udp:run-udp-transport-test`
(`src/dds-tests/udp-test.lisp`).

```lisp
(multiple-value-bind (rx-transport rx-socket)
    (dds.xport.udp:make-udp-transport :host "127.0.0.1" :port 0)
  (declare (ignore rx-transport))
  (multiple-value-bind (tx-transport tx-socket)
      (dds.xport.udp:make-udp-transport :host "127.0.0.1" :port 0)
    (unwind-protect
         (let* ((rx-port    (dds.xport.udp:udp-transport-local-port rx-socket))
                (out-buffer (dds.core.buffer:make-octet-buffer 64))
                (in-buffer  (dds.core.buffer:make-octet-buffer 64))
                (c          (dds.core.buffer:cursor out-buffer)))
           (dds.core.buffer:put-u8 c #xDE)
           (dds.core.buffer:put-u8 c #xAD)
           (dds.core.buffer:put-u8 c #xBE)
           (dds.core.buffer:put-u8 c #xEF)
           ;; dispatch-free send to the receiver's locator
           (dds.xport:send tx-transport
                           (dds.xport.udp:make-udp-locator :host "127.0.0.1" :port rx-port)
                           out-buffer 0 4)
           (sleep 0.2)
           (multiple-value-bind (size addr sport)
               (dds.xport.udp:udp-transport-recv rx-socket in-buffer)
             (declare (ignore addr sport))
             (values size (dds.core.buffer:octet-buffer-vec in-buffer))))   ; => 4, #(#xDE #xAD #xBE #xEF ...)
      (dds.pal:udp-close rx-socket)
      (dds.pal:udp-close tx-socket))))
```

### UDPv4 with a background receiver thread

`start-udp-receiver` spawns a thread that blocks on the socket and calls `(on-datagram buffer size)` for each
datagram; it exits cleanly when the socket is closed. Adapted from `dds.xport.udp:run-udp-receiver-test`
(`src/dds-tests/udp-test.lisp`).

```lisp
(multiple-value-bind (rx-tr rx-sock)
    (dds.xport.udp:make-udp-transport :host "127.0.0.1" :port 0)
  (declare (ignore rx-tr))
  (multiple-value-bind (tx-tr tx-sock)
      (dds.xport.udp:make-udp-transport :host "127.0.0.1" :port 0)
    (let ((received nil))
      (unwind-protect
           (progn
             (dds.xport.udp:start-udp-receiver
              rx-sock
              (lambda (buf size)
                (setf received
                      (cons size (aref (dds.core.buffer:octet-buffer-vec buf) 0)))))
             (let ((ob   (dds.core.buffer:make-octet-buffer 16))
                   (port (dds.xport.udp:udp-transport-local-port rx-sock)))
               (let ((c (dds.core.buffer:cursor ob)))
                 (dds.core.buffer:put-u8 c #x55)
                 (dds.core.buffer:put-u8 c #x66))
               (dds.xport:send tx-tr
                               (dds.xport.udp:make-udp-locator :host "127.0.0.1" :port port)
                               ob 0 2))
             (loop repeat 100 until received do (sleep 0.02))
             received)   ; => (2 . #x55)
        (dds.pal:udp-close tx-sock)
        (dds.pal:udp-close rx-sock)))))
```

### Raw PAL sockets (without the transport wrapper)

The transport record wraps these, but the PAL UDP layer is usable directly — this is what
`run-udp-loopback-test` (`src/dds-tests/udp-test.lisp`) exercises.

Both buffers must be **PAL-static** (`dds.pal:alloc-static`) — the kernel reads the send buffer and writes
the receive buffer through raw pointers (ADR 0065/0066, NFR-MEM).

```lisp
(let ((rx (dds.pal:udp-open :host "127.0.0.1" :port 0)))
  (unwind-protect
      (let ((tx  (dds.pal:udp-open :host "127.0.0.1" :port 0))
            (out (dds.pal:alloc-static 4))                       ; static: addressed by raw pointer
            (in  (dds.pal:alloc-static 16)))                     ; static: the kernel writes into it
        (replace out #(#xde #xad #xbe #xef))
        (unwind-protect
            (let ((port (dds.pal:udp-local-port rx)))
              (dds.pal:udp-send-to tx out 4 "127.0.0.1" port)    ; => 4 (negative = dropped)
              (sleep 0.2)
              (multiple-value-bind (n addr sport) (dds.pal:udp-recv rx in 4)
                (declare (ignore addr sport))   ; sender NIL on the raw path; n < 0 = socket closed
                (values n in)))   ; => 4, #(#xde #xad #xbe #xef ...)
          (dds.pal:free-static out)
          (dds.pal:free-static in)
          (dds.pal:udp-close tx)))
    (dds.pal:udp-close rx)))
```

### SHMEM transport — same-host send through the ring

Two participants on one host: the receiver creates its segment, a background receive thread cond-waits and
drains, and the sender attaches by the receiver's locator and enqueues. The engine never sees the difference —
the sender calls the same `dds.xport:send`. Adapted from `dds.xport.shmem:run-shmem-receiver-test`
(`src/dds-tests/echo-test.lisp`); it pass-skips on the Clasp/macOS by-name-attach gap (ADR 0013).

```lisp
(when (dds.xport.shmem:shm-attach-by-name-reliable-p)        ; skip on the Clasp/macOS NFR-PORT gap
  (let ((rx (dds.xport.shmem:make-shmem-transport
             :participant-guid (make-array 12 :element-type '(unsigned-byte 8) :initial-element 1)
             :host-uuid 7))
        (tx (dds.xport.shmem:make-shmem-transport
             :participant-guid (make-array 12 :element-type '(unsigned-byte 8) :initial-element 2)
             :host-uuid 7))
        (received nil))
    (unwind-protect
         (progn
           ;; the receiver's background thread blocks on the pshared cond, then drains all lanes
           (dds.xport.shmem:start-shmem-receiver
            rx (lambda (sink size)
                 (setf received (cons size (aref (dds.core.buffer:octet-buffer-vec sink) 0)))))
           (let ((buf (dds.core.buffer:make-octet-buffer 64)))
             (let ((c (dds.core.buffer:cursor buf)))
               (dds.core.buffer:put-u8 c #xDE) (dds.core.buffer:put-u8 c #xAD))
             ;; dispatch-free send to the receiver's SHMEM locator — same call as UDP
             (dds.xport:send (dds.xport.shmem:shmem-transport-transport tx)
                             (dds.xport.shmem:shmem-transport-locator rx)
                             buf 0 2))
           (loop repeat 100 until received do (sleep 0.02))
           received)   ; => (2 . #xDE)
      (dds.xport.shmem:shmem-transport-close tx)
      (dds.xport.shmem:shmem-transport-close rx))))
```

In a live deployment you never construct the locator by hand: discovery does it. With `dds.disc:*shmem-enabled*`
`T`, two participants that share a host-uuid and have each advertised a SHMEM locator in SPDP/SEDP auto-route
their bulk user DATA through the ring; everything else stays on UDP. The real **two-process** round-trip
(separate Lisp images attaching to one segment — the proof loopback within one image cannot give) is the
`make shmem-xproc` harness (`scripts/shmem-roundtrip.sh`); the latency/throughput numbers are `make bench-shmem`.

## Publication send modes: sync, async-unpaced, async-paced (flow control)

Independently of *which* transport carries a datagram, a writer is in exactly one of **three send modes** —
they govern *which thread sends* and *when* (WP-ASYNC / WP-ASYNC-FLOW, FR-PF-2,
[ADR 0016](../adr/0016-async-flow-control.md)). All three are **wire-invisible**: they change only *when* a
datagram leaves, never its bytes (the operating-contract "extend, never replace conforming RTPS" pattern), so
none is patent-gated and none is R6.

| Mode | How to opt in | Who sends | When |
|---|---|---|---|
| **sync** (default) | nothing | the **calling** (`publish-sample`) thread | inline, immediately on write |
| **async-unpaced** | `dds.disc:enable-async` | a **per-node** background sender thread | on signal it flushes **all** unsent (the reliable unsent-list *is* the queue), **unpaced** — drains as fast as the link allows |
| **async-paced** (flow control) | associate with a `dds.disc:flow-controller` | the **controller's** scheduler thread | rate-shaped: one datagram per associated writer per turn (selection policy `:round-robin` / `:edf` / `:priority`), gated by a bytes/period token bucket |

A writer is associated with **at most one** controller; association **supersedes** the per-node unpaced sender
for that writer (`enable-async` remains for the async-*without*-rate-control case). Flow control is **off by
default** — a writer with no controller is **byte-identical** to a sync (or `enable-async`) writer.

### Worked example — a shared flow-controller pacing a writer

`make-flow-controller` builds a token bucket (`tokens-per-period` bytes every `period` ns, capacity
`max-burst`) plus its own scheduler thread; `flow-controller-associate` registers a writer node, making its
publication async-and-paced; the writer is configured **HISTORY KEEP_ALL** with a finite `max_samples` and a
`max_blocking_time` so a too-fast producer **blocks up to `max_blocking_time`** then gets `RETCODE_TIMEOUT`
rather than growing the cache without bound (the backpressure half — see the [QoS wiki](qos.md#backpressure-block-up-to-max_blocking_time-reliability--resource_limits)).
Adapted from `dds.tests::run-flow-pacing-test` (`src/dds-tests/integration-test.lisp`); SBCL (real threads +
timing — the flow tests pass-skip on Clasp, NFR-PORT).

```lisp
(let* ((payload (make-array 1400 :element-type '(unsigned-byte 8) :initial-element #x5a))
       (w (dds.disc:make-disc-node
           :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element #x93)
           :host "127.0.0.1" :port 0))
       (controller nil))
  (unwind-protect
       (progn
         ;; bound the writer's cache so a too-fast producer is back-pressured, not unbounded:
         ;; KEEP_ALL + max_samples=64 + max_blocking_time=200 ms (RETCODE_TIMEOUT when full past the deadline)
         (dds.disc:add-local-writer w :topic "Paced" :type "X"
                                    :reliability dds.rtps.discovery:+reliability-reliable+)
         (dds.disc:enable-publisher w :max-samples 64 :max-blocking-ns 200000000)
         ;; 100 KB/s = 10000 bytes every 100 ms, bucket capacity 10000 bytes
         (setf controller (dds.disc:make-flow-controller
                           :tokens-per-period 10000 :period 100000000 :max-burst 10000))
         (dds.disc:flow-controller-associate controller w)   ; now publication is async + rate-shaped
         ;; publish-sample returns immediately (the controller's thread sends, paced); RETCODE_TIMEOUT
         ;; (:timeout) if the bounded cache is full past max_blocking_time
         (dotimes (i 100)
           (let ((rc (dds.disc:publish-sample w payload)))
             (when (eq rc :timeout) (format t "~&back-pressured at sample ~d~%" i)))))
    (when controller (dds.disc:destroy-flow-controller controller))   ; join the scheduler; flush remaining ignoring the bucket
    (dds.disc:stop-node w)))   ; unregisters w from the controller via the per-node emit barrier BEFORE freeing
```

For **two or more** writers, call `flow-controller-associate` once per writer participant on the **same**
controller — and, since **Slice S1b** (WP-N-ENDPOINT-S1B-FLOW, ADR 0048), a **single participant with N
DataWriters** also works: one associate registers a **per-writer selection entry** (`flow-writer-state`) for
each of the participant's writers, so the scheduler drives ALL of them (not just the primary). Either way the
scheduler round-robins (or EDF/priority-selects) one datagram per **writer** per turn, so their datagrams
interleave and the **aggregate** byte rate is shaped to the configured rate (not N × it) — the token bucket is
one-per-controller, shared across every writer; EDF/priority order the samples **across** the participant's
writers (a tight-`LATENCY_BUDGET` writer ahead of a loose one on the same participant). `stop-node` tears one
writer participant down via a **per-node emit barrier** (`flow-controller-unregister`) — it removes all the
participant's per-writer entries from the scheduler's writer set
then blocks until the shared scheduler is provably not, and never again will be, mid-emit on it, so freeing the
node's socket/buffers cannot race a live send; the controller keeps serving its other writers. A large sample
is paced at **DATA_FRAG fragment** granularity — its fragments spread across periods (the FR-PF-2 headline use
case).

### Honest cost (FR-LANG-7) — rate control trades latency

Flow control is rate **control**: it bounds the byte rate by **delaying** datagrams, so it **adds latency by
design** — there is **no "0-cost"/"free" claim**. The honest bench (`bench/report/2026-06-15-wp-async-flow.md`,
`make bench-async-flow`): the achieved drain rate tracks the configured ceiling within a small startup-burst +
per-datagram-granularity overshoot (e.g. configured 125 KB/s → achieved ~132 KB/s; a smaller `max-burst`
tracks ~1.0×); the **same** workload runs **tens of times slower paced than unpaced** — which is the *point*,
not overhead to remove. Use `enable-async` (unpaced) when you want async without a rate bound; use a
`flow-controller` when a downstream link or reader must not be overrun.

### Sender-thread fault resilience — `*sender-emit-error-hook*`

Both background sender threads — the **async sender** (`%async-sender-loop`, one per `enable-async` node) and
the **flow scheduler** (`%flow-scheduler-loop`, one per `flow-controller`) — are **fault-resilient**
(WP-SENDER-ERROR-RESILIENCE, FR-PF-2; standard DDS, NOT R6). They mirror the RX receiver thread's existing
per-iteration guard: a transient `error` signalled out of one emit (a hard SHMEM-send segment/bounds error,
datagram-build / destination-resolution, static-arena exhaustion, a future transport) is **caught, counted,
observed via a hook, and the loop continues** — instead of the thread dying and silently stalling every writer
it serves. The guard catches `error` **only, not `serious-condition`**: a fatal VM state (`storage-condition`
/ control-stack-exhausted) still terminates the thread, because masking it would hide an unrecoverable
condition. It is inert in production — the bytes on the wire are **byte-identical** to before — and **off the
measured CDR hot path** (`make mem` stays 0.0000).

**Drop-and-recover (Option 1, RTPS 2.5 §8.4).** When the flow scheduler's emit faults, it **drops the
datagram and advances its plan cursor unconditionally**, so the scheduler always makes progress and **never
hot-spins** — the writer's unsent watermark is advanced at *snapshot* time, so a drained faulted plan is never
re-snapshotted (bounded work). A dropped **reliable** DATA stays in the writer's HistoryCache and is recovered
by the writer's **proactive re-push of unacked samples** (pushMode=true, §8.4.2.2) on the next flush — the
periodic HEARTBEAT keeps advertising `[firstSN,lastSN]` and an ACKNACK-driven repair is the fallback (§8.4.1);
a best-effort drop is conformant (loss tolerated). Local send-error handling is implementation-defined (the
standard is silent — this resilience does not change the wire), and the alternatives were rejected:
retry-the-same risks **wedging** a writer (no SN advances), clear-pending defers proactive push.

**Observability.** `dds.disc:*sender-emit-error-hook*` is a bindable funcallable `(condition context count)`
invoked on each caught emit error (the default is a clockless rate-limited `WARN` — it logs only when `count`
is 1 or a power of ten, so a persistent failure logs O(log n) lines, never a flood). `context` is
`:async-sender`, `:flow-scheduler`, or `:shmem-send-fault`; `count` is that thread's running error count (also
readable as the `disc-node` `async-emit-errors` / `flow-controller` `emit-errors` slots, and for the SHMEM
fault the `disc-node-shmem-send-faults` counter). **The hook runs on the sender thread** — so it must not
block, it does **not** inherit the binding thread's dynamic environment (bind the **global** value, not a
thread-local `let`), and a hook that itself signals is swallowed (it can never re-kill the thread).

**SHMEM-send self-guard (WP-SHMEM-SEND-SELF-GUARD, FR-XPORT-2).** The same hook also fires — with context
`:shmem-send-fault` — when a **signalled** `%shmem-send` hard fault (segment detached / pshared error /
bounds) is caught in `%send-raw-buf` and the datagram is degraded to the UDP fallback. This widens the hook's
use beyond the two sender-thread emit sites to this transport-fault site (the catch lives in `dds.disc`'s
production send path, not the lower `dds.xport` SHMEM `:send` lambda, so the counter + hook stay in scope
without an upward `dds.xport → dds.disc` dependency). It is distinct from a **benign lane-full**, where the
SHMEM send *returns* 0 (not a signal): that takes the **silent** UDP fallback with **no** counter bump and
**no** hook fire (the fault-vs-lane-full distinction). Either way the datagram still delivers over UDP, and a
genuinely lost reliable sample is backstopped by HEARTBEAT/ACKNACK repair (§8.4.1). The fault never propagates
out of the user-data send. The `disc-node-shmem-send-faults` counter is the proof/diagnostic; the
`dds.xport.shmem:*debug-shmem-send-fault*` test affordance injects the synthetic fault (inert NIL =
byte-identical production).

| Symbol | Kind | Contract |
|---|---|---|
| `dds.disc:*sender-emit-error-hook*` | special variable | funcallable `(condition context count) → t`; called for each caught emit `error`. On a sender thread for `context` ∈ {`:async-sender`, `:flow-scheduler`}; on the calling (or sender) thread for `:shmem-send-fault` (a `%shmem-send` hard fault caught in `%send-raw-buf` → UDP fallback). `count` is the matching running error count. Must not block; a signalling hook is itself guarded. Default rate-limited WARN. |
| `dds.disc:disc-node-shmem-send-faults` | accessor | Count of **signalled** `%shmem-send` faults caught in `%send-raw-buf` and degraded to the UDP fallback (proof/diagnostic; FR-XPORT-2). A benign lane-full return-0 does **not** advance it. |
| `dds.disc:*debug-emit-fault*` | special variable | **test affordance, default `NIL` = inert** (byte-identical wire). A positive integer N faults the next N `%send-raw-buf` calls (decrementing); `:persistent` faults every call. Mirrors `*debug-drop-sample-numbers*`. |
| `dds.xport.shmem:*debug-shmem-send-fault*` | special variable | **test affordance, default `NIL` = inert** (byte-identical production). When non-`NIL`, `%shmem-send` signals `shmem-send-test-fault` before doing any work — exercises the `%send-raw-buf` self-guard (catch → `disc-node-shmem-send-faults` + hook `:shmem-send-fault` → UDP fallback). Never set in production. |

```lisp
;; Observe sender-thread emit faults: set the GLOBAL hook (it fires on the sender thread).
(let ((errors '()))
  (setf dds.disc:*sender-emit-error-hook*
        (lambda (condition context count)
          (push (list context count (type-of condition)) errors)))   ; record; do not block
  ;; ... an async / flow-paced writer runs; on each caught emit error the hook fires ...
  ;; errors now holds e.g. ((:async-sender 1 sender-emit-test-fault) ...), newest first;
  ;; the thread stayed alive and kept sending — a dropped reliable DATA repairs via re-push.
  errors)
```

### Scheduling policies (`:round-robin` | `:edf` | `:priority`)

The next-writer selector is a **pluggable policy hook** chosen by `make-flow-controller`'s `:scheduling`
keyword; all three shape to the same aggregate rate (selection is orthogonal to the token-bucket pacing —
it changes only *which* writer drains next, never *when* or the wire bytes):

- **`:round-robin`** (default) — fair cursor rotation, one datagram per writer per turn.
- **`:edf`** (WP-FLOW-EDF-PRIORITY, ADR 0016) — earliest-deadline-first, keyed on **`LATENCY_BUDGET`**:
  the pending writer whose head-unsent sample has the smallest deadline (write-time + latency-budget) drains
  first. Keyed on `LATENCY_BUDGET`, **not** QoS `DEADLINE` (which here is the periodicity/liveliness contract).
  A budget-0 writer (the default) has deadline = write-time, so it sorts **earliest (most urgent)**.
  `LATENCY_BUDGET` is a max-delay *hint* that informs *ordering* — a saturated bucket may still miss it.
- **`:priority`** (WP-FLOW-EDF-PRIORITY, ADR 0016) — highest **`TRANSPORT_PRIORITY`** first, **with
  starvation-avoidance aging**: effective priority = base + `floor((now − last-served)/`
  `*flow-priority-aging-quantum-ns*)` (default quantum 10 ms), so a low-priority writer starved behind a
  saturating high-priority one still wins within ≈ `(P_high − P_low)` quanta — bounded, not the unbounded
  starvation a pure highest-first policy would inflict.

The writer's `LATENCY_BUDGET` + `TRANSPORT_PRIORITY` are cached onto the node at
`flow-controller-associate` time (read once from the writer QoS; no per-datagram QoS read on the selection
path), and the EDF head write-time is stamped both on the idle→pending transition **and** at each plan
re-snapshot as the writer's head-of-line batch drains (so under sustained backlog the key tracks the writer's
current head, not its first-ever-pending time — otherwise a continuously-backlogged writer would monopolize);
these stamps are gated by policy, so the `:round-robin`/off path is untouched. All under the controller lock,
so the policy never touches the writer lock. Bench: `make bench-flow-edf-priority`
(`bench/report/2026-07-04-wp-flow-edf-priority.md`) — EDF deadline-miss reduction + priority service-share +
the aging starvation bound, all vs round-robin.

### Deferred (v1 → follow-ups)

Still deferred: SEDP propagation of `TRANSPORT_PRIORITY`/`LATENCY_BUDGET` (sender-local scheduling needs only
the writer-local value), per-sample priority/deadline, **runtime rate
re-configuration** (rate is set at `make-flow-controller`), pacing of discovery/HEARTBEAT/ACKNACK (only user
DATA is paced), and cross-process flow control (a controller is an in-process, sender-side object). The
`FlowController`, asynchronous `PublishMode`, and the policy *names* are RTI Connext vendor-extension names —
**none is normative** in OMG DDS 1.4 or DDSI-RTPS 2.5 (the standard QoS set has no `PUBLISH_MODE` or
`FLOW_CONTROLLER`; asynchronous publication is an implementation freedom), and the implementation is clean-room
from FR-PF-2 + first principles.

## SHMEM architecture

`make-shmem-transport` creates **one receive segment per participant** (the receiver creates it, senders
attach). The segment is laid out as a fixed-offset, little-endian region:

```
[ Header (magic/version/lane_count/capacity/max_record) | Notify block | K SPSC lanes ]
```

- **Notify block** — a `PTHREAD_PROCESS_SHARED` mutex + condition variable + a `stop` flag + a `parked` flag,
  each at a fixed cache-aligned offset, the block sized to the per-platform max pthread struct sizes so one
  layout serves macOS and Linux. (Named POSIX semaphores were rejected: `sem_open` cannot be driven from the
  Lisp runtime on macOS arm64 — its variadic args are mispassed. The non-variadic `pthread_*` calls work from
  both SBCL and Clasp on macOS + Linux; libpthread is already linked.)
- **K per-sender SPSC lanes** — the path is multi-producer (several same-host participants may target one
  receiver) / single-consumer (one receive loop drains). v1 sidesteps a lock-free MPSC ring by giving **each
  sending participant its own SPSC lane**. A lane is a byte-ring of length-prefixed records `[len][payload]`; a
  record that would straddle the wrap boundary is preceded by a skip-to-start sentinel rather than split. Lane
  capacity derives from the writer's `RESOURCE_LIMITS` QoS, so the memory-level and DDS-level limits agree. The
  whole segment is `mmap`-backed foreign/static memory — the GC neither scans nor moves it (NFR-MEM).

**Lane claim is mutex-guarded** — at attach, a sender takes the segment's pshared mutex once, finds its
existing lane (reuse) or the first free one, and claims it. One claim per (sender, receiver) pair for the life
of the connection, off the hot path — so **no foreign-SAP compare-and-swap is needed**, which gives SBCL and
Clasp full parity at that layer.

**Steady-state enqueue/drain are lock-free** — the producer copies the record then publishes the advanced
write-cursor with a *release* fence; the consumer does an *acquire* load of the write-cursor before reading up
to it. Aligned 64-bit `load`/`store` + the real `dds.pal:fence`, no per-message CAS.

**Conditional (parked-flag) wakeup** — naively the sender would lock + signal the condvar (a futex syscall) on
every send, even into a busy receiver. Instead the receiver publishes `parked = 1` strictly under the mutex
before it actually `cond-wait`s, full-fences, and **re-checks** the data predicate; the sender enqueues,
full-fences, reads `parked`, and signals **only** when `parked = 1`. This Dekker StoreLoad handshake makes a
skipped signal provably never a lost wakeup (at least one side observes the other), so a tight blast into a
draining receiver does **no** per-message futex wake — the WP-SHMEM raw-send throughput fix.

**The ring is an untrusted parser surface** — a segment written by another process is treated exactly like the
wire: every `len`/offset is bounds-checked against the lane extents before it is read, even at `(safety 0)`
(NFR-SEC-POSTURE). A lane/ring-full enqueue returns a reject sentinel, which the discovery layer maps to a UDP
fallback for that datagram (the reliable sample stays in the HistoryCache and repairs via HEARTBEAT/ACKNACK) —
**never** a GC-heap fallback.

**A signalled SHMEM-send hard fault also degrades to UDP** (WP-SHMEM-SEND-SELF-GUARD, FR-XPORT-2). The lane-full
reject above is a benign *return-0*; a **signalled** `%shmem-send` error (segment detached / pshared error /
bounds) is a different outcome, and it too must not propagate out of the user-data send. `%send-raw-buf`
(`dds.disc`) wraps the SHMEM send in a `handler-case`: a signal is caught, bumps `disc-node-shmem-send-faults`,
fires `*sender-emit-error-hook*` with context `:shmem-send-fault` (see
[Sender-thread fault resilience](#sender-thread-fault-resilience--sender-emit-error-hook)), and falls back to
UDP exactly like a return-0 — so the datagram still delivers. The catch lives here in the production send path
(which already holds the transport + node + UDP-fallback dest + the hook), **not** the lower `dds.xport` SHMEM
`:send` lambda, so the counter + hook stay in scope without an upward `dds.xport → dds.disc` dependency. The
fault-vs-lane-full distinction matters: only the **signal** path bumps the counter and fires the hook; the
benign lane-full takes the silent UDP fallback. The `dds.xport.shmem:*debug-shmem-send-fault*` test affordance
injects the synthetic fault (inert NIL = byte-identical production).

### When SHMEM engages, and what stays on UDP

SHMEM is the same-host data path; **UDP is the fallback and carries everything else**. A peer is sent bulk user
DATA over SHMEM iff both of the following hold (`dds.disc` resolves this per remote, then caches the verdict):

1. it shares this node's **host-uuid** — a u64 from the MD5 of the hostname (`dds.disc::%host-uuid`),
   advertised in SPDP, so two participants on one host agree without an out-of-band exchange; and
2. it advertised a **SHMEM locator** (a vendor `Locator_t`) beside its UDP locator in discovery.

Discovery, the metatraffic (SPDP/SEDP) channel, and the reliable HEARTBEAT/ACKNACK handshake **always** ride
UDP in v1 — only bulk user DATA takes SHMEM. The SHMEM locator is purely additive: a cross-vendor peer (or any
peer that does not share the host-uuid) sees an unknown locator kind, ignores it, and matches + talks over UDP.
Cross-vendor SHMEM is out of scope by construction (RTI and Fast DDS use different, proprietary segments and
locator kinds; there is no standard RTPS SHMEM wire format).

The selection vendor constants are **ours**, pinned in ADR 0013 (not OMG spec clauses): the SHMEM `Locator_t`
kind `0x47420001` (`dds.rtps.discovery:+locator-kind-shmem+`) and `PID_SHMEM_HOST_UUID` `0x8040`
(`dds.rtps.message:+pid-shmem-host-uuid+`, in the `0x8000` vendor PID range).

### Performance characteristics

Measured SBCL/macOS (Apple M5), `bench/report/2026-06-14-wp-shmem.md`:

- **Latency: a clear win.** SHMEM cuts the one-way median (p50) latency to **1.35x–1.94x** lower than UDP
  loopback (largest for the smallest payloads), with a p99 comparable-to-better and a *lower* worst-case max
  tail. For one outstanding message the pshared mutex is uncontended and a userspace condvar wake beats two
  trips through the kernel networking stack.
- **Throughput: end-to-end reliable samples/s is UDP-handshake-bound, not SHMEM-bound.** The
  `delivered-samples/s` over the reliable data plane is dominated by the HEARTBEAT/ACKNACK round-trip and the
  receiver poll granularity — both transports gate on the same handshake, so the coarse harness metric does not
  surface the transport difference (the UDP baseline itself swung ~10x run-to-run with no code change). A direct
  send-path micro-bench (no reliable handshake) isolates the conditional-wakeup optimization at **~1.4x–1.8x**
  raw SHMEM send throughput with no record loss. The remaining transport follow-up is a lock-free-MPSC ring; the
  reliable-handshake/poll-granularity cost is a separate engine/DCPS follow-up.
- **Allocation: 0 bytes/sample on the SHMEM send path.** The ring is preallocated foreign/static, the enqueue is
  raw SAP writes, and the destination is resolved once and cached per remote — steady-state SHMEM `send` does no
  per-datagram heap allocation (it now allocates at the UDP baseline per sample). The residual ~9–11 KB/sample
  seen end-to-end is the v1 disc-layer data-plane copy, identical on both transports and explicitly *not* the
  gated hot path; the gated XCDR codec is already 0-alloc (`make mem`).

## Zero-Copy over SHMEM (WP-ZEROCOPY) — default-OFF, R6 patent-gated

> **NOT cleared for ship — pending counsel (R6).** Zero-Copy mirrors RTI's patented mechanism (the operating
> contract §NFR-IP; ADR 0014). It is implemented clean-room from FR-PF-3 + the OMG spec, ships **off by
> default**, and must clear legal review before any `*zerocopy-enabled*`-on deployment. Every Zero-Copy file
> carries this marker.

On top of SHMEM, a writer can place a large serialized sample in a per-writer SHMEM **sample-pool** it owns and
transmit a **16-byte reference** (a vendor SerializedPayload encapsulation, `dds.cdr:+zc-encapsulation-id+` =
`0x4B43`) instead of the payload; a same-host, ZC-capable reader maps the pool, resolves the reference, and
delivers the real bytes. v1 is **best-effort**; the win is **large samples** crossing as a tiny reference (no
payload copy into the transport). The reference rides the **existing DATA path** (UDP or the SHMEM ring) through
the full RTPS machinery unchanged.

**Selection (all must hold, else normal serialized DATA — exactly one of {reference, payload} per reader, no
double-delivery):** `*zerocopy-enabled*` was `T` at `make-disc-node` (so the node built a pool — the pool slot,
not the special, is the runtime gate, mirroring `disc-node-shmem`; this matters because the receiver/async
threads cannot see a later dynamic binding); the matched reader is **same-host** (`host-uuid` match) and
advertised **`PID_ZEROCOPY_CAPABLE`** (`0x8041`) in SEDP; and the serialized payload is **larger than
`*zerocopy-min-payload-bytes*`** (default 1024 — small samples are not worth a slot + a reference). A pool
saturated with in-read slots, or a payload larger than a slot, falls back to normal serialized DATA. The
reference is **untrusted cross-process input**: the resolver bounds-checks the slot index and validates the slot
**generation** (the single guard against stale, force-reclaimed, and forged references) before any slot access,
even at `(safety 0)` (NFR-SEC-POSTURE); an invalid reference is dropped (best-effort). With `*zerocopy-enabled*`
`nil` (the default) the data path is **byte-identical** to the non-ZC path.

**Security gate — no cleartext payload in SHMEM for a secured writer (DDS-Security 1.1 §8.5; ADR 0036 Carry 10).**
The raw Zero-Copy path puts the serialized payload in the shared pool **out-of-band** from the datagram, and the
datagram-tier transforms — `rtps_protection` (whole-RTPS, §8.5.1.10-.12) and `metadata_protection`
(user-submessage, §8.5.1.7-.9) — are applied to the *datagram* at send time, which under Zero-Copy carries only the
16-byte reference. So those transforms would encrypt the reference while the actual payload sat in shared memory **in
the clear**. Therefore the selection has one more, **fail-closed** requirement: the writer's governance must **not**
mandate datagram-tier protection — `%zc-payload-wire-protected-p` is T (and the raw Zero-Copy path is disabled) when
`disc-node-rtps-protection-kind` **or** `disc-node-user-submessage-protection-kind` ≠ `:none`. A secured writer's
large sample instead takes the normal serialized-DATA path, whose datagram `%send-raw-buf` protects (submessage +
SRTPS wrap) over UDP **or the SHMEM ring** — the ring wraps the whole datagram in place before transmission, so it
never leaks; only the out-of-band Zero-Copy pool did. `data_protection` (payload tier) is applied at serialize time,
so a `data_protection`-only writer keeps Zero-Copy (the pool holds the already-encrypted SecuredPayload). A
non-secured writer (both kinds `:none`, the default) is untouched — full Zero-Copy performance, byte-identical and
zero-alloc. Proof: `dds.disc:run-zc-shmem-secured-cleartext-test` (Part B inspects the live pool segment and asserts
the secured payload is provably absent while a non-secured control's marker is present).

**Confidential Zero-Copy for an ENCRYPT-tier writer — the in-slot SecuredPayload overlay (ADR 0051).** Gating off
means a wire-protected writer forfeits Zero-Copy on every large sample. WP-SECURITY-ZC-SHMEM-OVERLAY closes that for
the **ENCRYPT** case: an ENCRYPT-tier writer with `data_protection` = NONE now **keeps Zero-Copy** by sealing the
serialized payload **into the pool slot as a `data_protection` `SecuredPayload`** under its per-writer EntityCrypto
key (`%zc-overlay-eligible-p` T ⇒ `%zc-change-item` takes the overlay arm instead of returning NIL). The slot holds
ciphertext, and the 20-octet reference carries an integrity-protected **overlay sentinel**
(`dds.cdr:+zc-ref-overlay-secured+`, in the `reserved` field inside the rtps/metadata wrap) so the reader decodes
the slot copy-on-read — regardless of its own governance — and drops fail-closed on a missing key or a tampered
slot. `SIGN`-only and loan-write writers stay gated (a SIGN payload is visible on the wire; a raw-ZC-for-SIGN
relaxation is deferred), so the leak stays closed for all tiers. Non-overlay references stay `reserved = 0` — wire
byte-identical. See [security.md §3.8](security.md) and ADR 0051. Proof:
`dds.disc:run-zc-shmem-secured-overlay-test`.

| Symbol | Kind | Meaning |
|---|---|---|
| `dds.disc:*zerocopy-enabled*` | special var | **Default `NIL`.** Read once per node at `make-disc-node`; when `T` (and SHMEM is available) the node builds a Zero-Copy writer pool and advertises `PID_ZEROCOPY_CAPABLE`. NOT cleared for ship — pending counsel (R6). |
| `dds.disc:*zerocopy-min-payload-bytes*` | special var | Size threshold (default 1024): only a serialized payload **strictly larger** is sent as a reference. A local policy, not a wire constant. |
| `dds.disc:+zerocopy-pool-slots+` / `+zerocopy-pool-slot-bytes+` | constants | Shared pool geometry (32 slots x 65536 octets), used by **both** pool creation and the reader's attach sizing (one definition). |
| `dds.disc:disc-node-zc-sends` | accessor | Count of samples this node published as a 16-byte reference (proof/diagnostic). |
| `dds.rtps.discovery:endpoint-data-zerocopy-capable` | accessor | T iff the endpoint advertised `PID_ZEROCOPY_CAPABLE` (fail-open: absent → NIL). |
| `dds.cdr:+zc-encapsulation-id+` / `encode-zc-reference` / `parse-zc-reference` | constant / functions | The 20-octet reference codec (4-octet encapsulation header + `{slot-index, generation, slot-bytes, reserved}` LE). `parse-zc-reference` returns the `reserved` field as a 4th value. |
| `dds.cdr:+zc-ref-overlay-secured+` | constant | The overlay sentinel (value 1) placed in the reference's `reserved` u32 when the slot holds a `data_protection` `SecuredPayload` overlay (ENCRYPT-tier ZC, ADR 0051); 0 = raw (byte-identical to a non-overlay reference). A LOCAL transport discriminator in our own ZC reference format, not an OMG wire constant; it rides inside the rtps/metadata wrap so a SHMEM attacker cannot flip it. |
| `dds.xport.zerocopy` | package | The SHMEM sample-pool. The mutex'd copy-resolve (`%zc-resolve`/`%zc-resolve-fresh`) keeps full Clasp parity; the **loaned-RX path is lock-free** (WP-ZC-LOAN-LOCKFREE, ADR 0018, R6): `%zc-loan` writes payload → `fence :release` → generation-store-LAST (the generation is the release/acquire sync variable), `%zc-acquire-for-read` is a generation acquire-load + `fence :acquire` + clamped read (0-copy/0-alloc), and `%zc-release` is a direct `cas-sap-u32` refcount decrement (0-alloc at any generation; the freelist was dropped, so the writer's loan scans the lowest-pubseq `refcount==0` slot, O(slots)). The lock-free path is SBCL-only (foreign-SAP atomics, ADR 0013); Clasp pass-skips. |

The pool segment name derives deterministically from the writer GUID (`seg-name-for-guid` + `"z"`), so the
reader maps it with no extra advertisement. The cross-vendor case is out of scope (the segment + encapsulation
are ours — there is no standard RTPS zero-copy wire format). On the Clasp/macOS NFR-PORT gap (no by-name attach)
Zero-Copy is unavailable for the same reason as SHMEM; its end-to-end test pass-skips.

### Measured (Phase E) — bench + a real 2-process round-trip

`make bench-zerocopy` (`dds.bench:run-bench-zerocopy`) compares Zero-Copy vs serialized-SHMEM vs UDP at
4/16/64 KiB and writes `bench/report/2026-06-14-wp-zerocopy.md`. For LARGE same-host samples Zero-Copy is a
clear **latency** win (≈2.5x–3.9x lower one-way median vs UDP loopback; up to **15.8x** vs the fragmented SHMEM
path — only a 16-byte reference crosses, so there is no fragmentation/reassembly round-trip) and a **throughput**
win that grows with payload size (up to **9.9x** vs SHMEM at 64 KiB). The 512 B control row (below the threshold)
shows `zc-sends = 0` — the writer correctly falls back to normal DATA — and every above-threshold row asserts
`disc-node-zc-sends` advanced, so the Zero-Copy figures are proven to have crossed as a reference. **Honest
caveat (FR-LANG-7):** the v1 reader resolve over-allocates a slot-sized scratch sink per sample, so the
per-sample *allocation* win only materializes once the sample approaches the slot size (64 KiB); at 4/16 KiB
Zero-Copy conses more than SHMEM. The follow-up landed: for a FlatData type the RX resolves the slot into a
single exact-length owned vector (`%zc-resolve-fresh`, no slot-sized sink, no re-copy) — **~830x less RX GC
than the v1 sink+re-copy** (`bench/report/2026-06-14-wp-flatdata.md`, `make bench-flatdata`). It is a SAFE
SINGLE COPY out of SHMEM, **not** literal-0-copy (a Lisp octet-buffer cannot wrap a raw foreign SAP and the
async off-thread read has no slot-aware release hook, so a literal-0-copy view would be a cross-process
use-after-free; deferred — ADR 0015). The untrusted resolve clamp is fuzzed with forged recorded-len /
generation / slot-index (`make fuzz`): the result is always NIL or clamped to slot-bytes, never an OOB.

`make zc-xproc` (`scripts/zerocopy-roundtrip.sh`, `dds.shapes:run-zc-xproc-pub`/`run-zc-xproc-sub`) launches two
**separate SBCL OS processes** that discover over loopback UDP and exchange large `LargeData` samples; the
publisher stores each in its pool and sends only a reference, and the subscriber resolves it from the writer's
pool **cross-process** and verifies the payload byte-exact (PASS = sub received ≥ threshold byte-exact AND the
pub's `zc-sends > 0`). This is the proof a within-image test cannot give: the reference resolves across the OS
boundary. SBCL only (Clasp/macOS inherits the SHMEM by-name-attach gap). **FlatData-over-Zero-Copy literal-0-copy
RX landed (WP-FLATDATA-ZC-LOAN, FR-PF-3/4, ADR 0017): a loan-capable `:flatdata` reader's disc receiver thread
stores the unresolved reference (no copy; slot held via the writer's refcount) and the DCPS `take-loaned` /
`return-loan` loan API hands the app a `flatdata-view` it reads in place off the writer's slot — see the type
system wiki. The loaned RX is now also literal 0-alloc (WP-ZC-LOAN-LOCKFREE, ADR 0018): `%zc-acquire-for-read`
+ `%zc-release` are lock-free (a generation acquire-load + `fence :acquire`, and a `cas-sap-u32` refcount
decrement) so the per-sample loaned RX consumes literal 0 GC-heap bytes (the progression `65552 → 79 → 31 → 0`,
`make bench-zc-loan-lockfree`) — honest tradeoff: the writer's loan is now O(slots) (the freelist was dropped),
benched at Phase C. **Reliable ZC loan delivery verified + hardened (WP-RELIABLE-ZC scope A, FR-PF-3/4, ADR
0017): a ZC loan sample on a RELIABLE writer rides the existing reliable path with NO separate reliability
gate (it has a SequenceNumber, is NACKable and retransmittable); the reader-RX 0-copy/0-alloc + the 16-byte
wire reference are the ZC win, and the loan composes with reliability via the refcount — the reader ACKs on
receive, and the writer's full-ACK HistoryCache purge (RTPS 2.5 §8.4.1) frees the HC copy while the loaned
SLOT outlives the purge (force-reclaim skips `refcount>0`) until `return-loan` (no UAF). Honest (FR-LANG-7):
the retransmit is reliable via COPY-FALLBACK, not re-loan — the ACKNACK repair leg re-emits the FULL retained
HistoryCache payload (byte-exact; `%on-user-acknack` omits `zc-readers`), delivered as an owned copy not a ZC
view; and the WRITER KEEPS the HistoryCache full-payload copy (needed for retransmit + non-ZC/remote readers),
so the writer-side is DOUBLE-STORAGE, NOT zero-copy, under reliability (the v1 cost — no writer-side-zero-copy
claim for reliable). A saturated pool falls back to the full payload (copy-delivered, never a silent drop).
Five SBCL scenarios green (`run-reliable-zc-{retransmit,poolfull-fallback,mixed,slot-outlives-purge,qos}-test`;
Clasp pass-skip), 211 green both impls; the run also found + fixed a latent reliability/memory bug
(`make-reader-qos`/`make-writer-qos` silently dropped a caller's `:reliability` override → a RELIABLE reader
advertised BEST_EFFORT → was excluded from the writer's purge set → unbounded HC growth; fixed, commit
`0a03bf5`). Scope-B follow-ups (not done): re-loan-on-retransmit (re-send a ZC ref on the ACKNACK path —
needs per-peer `%zc-readers` so the slot refcount stays 1 per resolving destination, avoiding a double-free
when a resend fans to multiple peers) and true writer-side reliable ZC (the HistoryCache change references
the slot, no full-payload copy, when all readers are same-host ZC). The loan-WRITE API remains a follow-up.**

#### Writer-side Zero-Copy TX: loan-write, acked-slot pinning, multi-destination sharing (ADR 0042 / 0044 / 0047)

The Scope-B follow-ups above landed as three layered work packages (all R6, patent-gated, default-off):

- **loan-write (ADR 0042)** — the app-facing zero-copy TX loan: `loan-sample` hands the app a `flatdata-view` over a pre-acquired pool slot, the app writes fields straight into the slot through the SAP-mode Offset setters, and `write-loaned` publishes it — the send site emits the **pre-committed slot's** ref with no app→slot copy (the change is born `:armed` with the slot identity; `%zc-armed-item` claims it one-shot at the first ZC destination). Secured / oversize / undersize / no-pool / saturated writes degrade gracefully to a heap FlatData sample.
- **acked-slot pinning (ADR 0044)** — an eligible reliable writer (VOLATILE or finalized, ≥1 matched reliable reader) **pins** the committed slot with a second, distinct refcount hold (`%zc-pin`) until the full-ACK purge, so retransmit / non-ZC / extra-ZC sends read the still-live slot on demand instead of materialising a retained payload on every write. Bounded by `dds.disc:*zc-pin-budget*` (default 16); ineligible writers / exhausted budget keep the always-correct retained-payload fallback.
- **multi-destination sharing (ADR 0047)** — when a sample fans out to **≥2 co-resident ZC-capable participants**, all N share **ONE** pool slot (refcount = N) instead of taking N separate slots + N app→slot copies. **N is the ZC-eligible destination-GROUP count, not the reader-endpoint count** — a participant resolves a `readerId`-UNKNOWN DATA once regardless of how many co-located ZC readers it has, so counting endpoints would leak the slot. The send site is hoisted above the per-group loop (`%capture-push-groups` freezes every destination's unsent set once, `%shared-zc-refs` loans one slot per shareable change reaching ≥2 ZC groups); a pre-committed armed slot is bumped 1→N with `%zc-bump` (the generation-guarded dual of `%zc-release`, of which `%zc-pin` is the `delta=1` case), and the ADR 0044 pin composes additively. **Honest scope (FR-LANG-7):** this is a pool-economy *optimization* — even before it, all N destinations already received the sample over Zero-Copy; the payoff is N−1 slots + N−1 copies saved and materialises **only** with ≥2 co-resident ZC participants, not the primary 1:1 same-host case. A single ZC destination, a lost armed claim, or pool saturation falls back to the per-destination fresh loan (byte-identical, always correct). Slots + copies drop N→1 at fan-out (`bench/report/2026-07-05-wp-zc-multi-dest.md`, N ∈ {2,4,8}).

### NFR-PORT gap — Clasp/macOS-arm64

**SBCL has full SHMEM on every platform.** On **Clasp/macOS-arm64** the transport is unavailable: Clasp's CFFI
cannot reliably pass `shm_open`'s variadic `mode_t` argument on arm64 (verified ~40% flaky), so a created
segment is unre-openable by name — the cross-process attach the transport depends on. There, `*shmem-enabled*`
defaults `NIL` and **UDP carries everything** (`shm-attach-by-name-reliable-p` returns `NIL`; the SHMEM tests
pass-skip cleanly). **Clasp/Linux** is expected to work via the register varargs ABI but is **pending
verification on a Linux host**. (A separate, deeper Clasp gap — no usable hardware atomic over a raw foreign
cell — keeps the SAP-CAS primitives SBCL-only, but the v1 ring's mutex-guarded claim means that gap does not
affect SHMEM on Clasp/Linux.) This mirrors the existing Clasp threading and foreign-atomics latitude (NFR-PORT).

## Notes / status

- **Landed:** UDPv4 unicast and multicast over each implementation's native `sb-bsd-sockets` (SBCL contrib;
  Clasp bundled), the pluggable `transport` record, the synchronous mock transport, and the **shared-memory
  intra-host transport** (FR-XPORT-2; auto-selected for same-host user DATA, UDP fallback; SBCL full, Clasp/macOS
  NFR-PORT gap — see [SHMEM architecture](#shmem-architecture) above). The SHMEM send now **degrades a signalled
  hard fault to the UDP fallback** (WP-SHMEM-SEND-SELF-GUARD, FR-XPORT-2): caught in `%send-raw-buf`, counted in
  `disc-node-shmem-send-faults`, observed via `*sender-emit-error-hook*` (context `:shmem-send-fault`), distinct
  from a benign lane-full return-0 — see
  [When SHMEM engages](#when-shmem-engages-and-what-stays-on-udp) above. Multicast (`SO_REUSEPORT` +
  `IP_ADD_MEMBERSHIP` + loopback) is wired in the PAL for SPDP discovery; the OS-specific socket-option constants
  are gated by **OS** reader conditionals (`#+darwin`/`#-darwin`) in `pal-net.lisp`, not impl ones.
- **Landed (gated, default-OFF):** Zero-Copy-over-SHMEM (WP-ZEROCOPY, FR-PF-3) — a per-writer SHMEM
  sample-pool + 16-byte-reference passing for large same-host samples, behind `dds.disc:*zerocopy-enabled*`
  (default `NIL`) and **NOT cleared for ship pending counsel (R6, ADR 0014)**. See
  [Zero-Copy over SHMEM](#zero-copy-over-shmem-wp-zerocopy--default-off-r6-patent-gated) above.
- **Landed (gated, default-OFF):** FlatData-equivalent for FINAL fixed-size scalar types (WP-FLATDATA,
  FR-PF-4, ADR 0015; keyed FlatData for fixed-size scalar `@key` is supported — WP-KEYED-FLATDATA; a variable-size/string `@key` is still a compile-time error in v1) — in-memory == XCDR2 wire, Offset accessors,
  identity serialize (0-alloc TX), a SAFE SINGLE-COPY RX over Zero-Copy for non-loan readers (~830x less RX GC
  than the v1 sink+re-copy), and — for a loan-capable `:flatdata` reader — **literal-0-copy RX via the DCPS
  loan/return_loan API** (WP-FLATDATA-ZC-LOAN, ADR 0017: `take-loaned`/`read-loaned` hand a `flatdata-view` read
  in place off the writer's SHMEM slot, `return-loan` releases it; force-reclaim skips held slots, so no UAF),
  now also **lock-free 0-alloc** (WP-ZC-LOAN-LOCKFREE, ADR 0018: the loaned RX `%zc-acquire-for-read` +
  `%zc-release` dropped the pool mutex for a generation acquire-load + `fence :acquire` and a `cas-sap-u32`
  refcount decrement, so the per-sample loaned RX is **literal 0 GC bytes** — the progression `65552 → 79 → 31
  → 0`, `make bench-zc-loan-lockfree`; honest tradeoff: the writer's loan lost its O(1) freelist-pop for an
  O(slots) `refcount==0` scan, ~106 ns/loan at 2 slots → ~1801 ns at 128, benched at Phase C — the reader RX is
  the win, the writer pays a small bounded scan; a lock-free freelist to restore O(1) is a noted follow-up).
  **NOT cleared for ship pending counsel (R6).** See the [type system wiki](type-system.md#8-flatdata--flatdata-t-offset-accessors-final-fixed-size-r6-not-cleared-for-ship). The untrusted wrap/read + ZC resolve clamp
  are fuzzed (`make fuzz`). **Reliable ZC loan delivery is verified + hardened (WP-RELIABLE-ZC scope A, ADR
  0017):** a ZC loan sample on a RELIABLE writer rides the existing reliable path with no separate reliability
  gate; the **reader-RX 0-copy/0-alloc + the 16-byte wire reference are the ZC win**, and the **loan composes
  with reliability via the refcount** (the reader ACKs on receive; the writer's full-ACK HistoryCache purge
  frees the HC copy, but the loaned slot outlives the purge — force-reclaim skips `refcount>0` — until
  `return-loan`). Honest (FR-LANG-7): the **retransmit is reliable via copy-fallback, not re-loan** (the
  ACKNACK leg re-sends the full retained payload, delivered as a copy, not a ZC view) and the **writer keeps
  the HistoryCache full-payload copy** (double-storage, **not** zero-copy on the writer side under reliability
  — the v1 cost). Five SBCL scenarios green, 211 both impls; the run also fixed a latent QoS bug
  (`make-reader-qos`/`make-writer-qos` dropped a caller's `:reliability` override → unbounded HC growth;
  commit `0a03bf5`). **Scope-B follow-ups (not done):** re-loan-on-retransmit and true writer-side reliable ZC.
- **Planned:** the app-facing ZC loan-**write** API (the remaining TX app→slot copy), the WP-RELIABLE-ZC
  scope-B follow-ups (re-loan-on-retransmit; true writer-side reliable ZC — no HistoryCache full-payload copy
  when all readers are same-host ZC), a TCP transport, a Linux
  `futex` notification fast-path for SHMEM, a lock-free-MPSC ring, and a raw `recvmmsg`/`sendmmsg`/iovec batched
  send/recv fast path. The UDP send is one datagram per `socket-send` (small samples are coalesced first).
- **Per-impl rule:** `#+sbcl`/`#+clasp` reader conditionals live **only** under `dds-pal/` (`pal-sbcl.lisp` and
  the per-impl PALs). The shared `pal-net.lisp` and everything in `dds-xport` carry none. CI lint enforces this
  (NFR-PORT, the operating contract §10).
- **PAL maturity:** the **SBCL** PAL is the reference; Clasp shares the native socket layer. The **AllegroCL**
  PAL is a planned target and **not yet present**. The **M1 atomics fast path landed** with WP-SHMEM (ADR 0013):
  `fence` is now a real `:acquire`/`:release`/`:full` barrier, and the SAP-targeted 64-bit atomics + POSIX
  shm/pshared primitives are implemented (SBCL full; Clasp has the SAP-CAS + `shm-create`/macOS gaps noted above).
  The generic `cas`/`atomic-incf` place stubs remain (no callers; the SAP forms supersede them). `gc-suggest` and
  `with-gc-inhibited` are still no-ops. (`monotonic-ns` NO LONGER uses the portable scaled clock — the
  promised `clock_gettime` fast path has landed; see the clock entry above.)
- **UDP is best-effort by design:** the UDPv4 transport's `send` swallows a `sendto` failure to one destination
  (an unreachable/stale/placeholder locator, e.g. a peer advertising `0.0.0.0`) and returns 0 rather than
  signalling — the reliable RTPS layer recovers via HEARTBEAT/ACKNACK. See the [RTPS engine](rtps-engine.md).

## See also

- [RTPS engine](rtps-engine.md) — the reliable/best-effort writer/reader that drives these transports.
- [Discovery](discovery.md) — SPDP/SEDP over UDP unicast + multicast.
- [CDR codec, buffers & the arena](cdr-and-memory.md) — the `octet-buffer`/cursor and static arena the examples
  serialize into.
