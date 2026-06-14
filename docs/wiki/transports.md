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
| `dds.pal:cas` | function | `(place-fn old new)` — generic place-based atomic compare-and-swap. Still a stub (signals `pal-unimplemented`); it has no callers — the SHMEM ring uses the SAP-targeted forms below. The generic stub is kept (removing it would break the frozen contract, ADR 0002). |
| `dds.pal:atomic-incf` | function | `(place-fn &optional delta)` — generic place-based atomic increment. Still a stub (signals `pal-unimplemented`), no callers; superseded by the SAP-targeted form below. |
| `dds.pal:fence` | function | `(&optional kind)` — **real memory barrier (M1):** `:acquire` = load barrier, `:release` = store barrier, `:full` = full barrier. SBCL maps to `sb-thread:barrier`; the SHMEM ring uses it for the release/acquire publish/consume of lane cursors and the full StoreLoad fence of the conditional-wakeup handshake. |

**SAP-targeted 64-bit atomics (M1 fast path, ADR 0013)** — the SHMEM ring needs true hardware atomics on a
raw foreign 64-bit cell addressed by `(sap, byte-offset)`, which the generic `place-fn` stubs cannot lower.

| Symbol | Kind | Description |
|---|---|---|
| `dds.pal:load-sap-u64` | function | `(sap offset)` — aligned 64-bit read of the foreign location at `sap+offset` (bytes). |
| `dds.pal:store-sap-u64` | function | `(sap offset value)` — aligned 64-bit write of `value` at `sap+offset`. |
| `dds.pal:cas-sap-u64` | function | `(sap offset old new)` — atomic compare-and-swap of the u64 at `sap+offset`; returns the PREVIOUS value (= `old` on success). **SBCL only** (`sb-ext:cas` over `sb-sys:sap-ref-64`); **Clasp signals `pal-unimplemented`** — Clasp has no usable hardware atomic over a raw foreign cell (NFR-PORT gap, ADR 0013). Unused by the v1 ring (the lane claim is mutex-guarded), kept for a future lock-free-MPSC optimization. |
| `dds.pal:atomic-incf-sap-u64` | function | `(sap offset delta)` — atomically add `delta` to the u64 at `sap+offset`; returns the NEW value. SBCL only (CAS-retry fetch-add); Clasp signals `pal-unimplemented` (same gap). Unused by the v1 ring. |

**POSIX shared memory + cross-process notification (ADR 0013)** — the SHMEM transport's segment and its
in-segment `PTHREAD_PROCESS_SHARED` mutex/condvar. All thin CFFI wrappers; no external library dependency.

| Symbol | Kind | Description |
|---|---|---|
| `dds.pal:shm-create` | function | `(name size)` — `shm_open(O_CREAT\|O_EXCL\|O_RDWR,0600)` + `ftruncate` + `mmap(MAP_SHARED)`; returns a segment handle. The creator. A stale segment from a crashed peer is reclaimed (`O_EXCL` fails -> `shm_unlink` + recreate). |
| `dds.pal:shm-attach` | function | `(name size)` — `shm_open(O_RDWR)` + `mmap`; a sender attaches to a receiver's existing segment by name. |
| `dds.pal:shm-detach` | function | `(handle)` — `munmap` + `close`. |
| `dds.pal:shm-destroy` | function | `(name)` — `shm_unlink`. |
| `dds.pal:shm-sap` | function | `(handle)` — the `mmap` base SAP, for the typed `sap-ref-*`/`cffi:mem-ref` reads/writes the ring uses. |
| `dds.pal:shm-segment-size` | function | `(handle)` — the segment's byte length. |
| `dds.pal:pshared-mutex-init` / `pshared-cond-init` | functions | `(sap offset)` — creator-only init of a `PTHREAD_PROCESS_SHARED` mutex / condvar living **in** the segment. |
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
| `dds.pal:udp-open` | function | `(&key host port reuse-port)` — open a UDPv4 socket bound to `host:port` (port 0 = ephemeral); `reuse-port` enables `SO_REUSEPORT` before bind. Returns the socket. |
| `dds.pal:udp-local-port` | function | `(socket)` — the bound local port of `socket`. |
| `dds.pal:udp-send-to` | function | `(socket buffer length host port)` — send `length` octets of `buffer` from `socket` to `host:port`. |
| `dds.pal:udp-recv` | function | `(socket buffer length)` — block until a datagram arrives; return `(values size sender-address sender-port)`. Used from a dedicated receiver thread. |
| `dds.pal:udp-close` | function | `(socket)` — close `socket`. |
| `dds.pal:udp-set-reuse-port` | function | `(socket)` — enable `SO_REUSEPORT` so multiple participants on one host can share the SPDP multicast port. Must be called before bind. |
| `dds.pal:udp-join-multicast` | function | `(socket group)` — join the IPv4 multicast `group` (dotted-quad) on the default interface and enable loopback (RTPS 2.5 §9.6.1.1). The socket must already be bound to the multicast port. |

**Clock**

| Symbol | Kind | Description |
|---|---|---|
| `dds.pal:monotonic-ns` | function | `()` — monotonic time in nanoseconds. |

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

```lisp
(let ((rx (dds.pal:udp-open :host "127.0.0.1" :port 0)))
  (unwind-protect
      (let ((tx  (dds.pal:udp-open :host "127.0.0.1" :port 0))
            (out (make-array 4 :element-type '(unsigned-byte 8)
                               :initial-contents '(#xde #xad #xbe #xef)))
            (in  (make-array 16 :element-type '(unsigned-byte 8))))
        (unwind-protect
            (let ((port (dds.pal:udp-local-port rx)))
              (dds.pal:udp-send-to tx out 4 "127.0.0.1" port)
              (sleep 0.2)
              (multiple-value-bind (n addr sport) (dds.pal:udp-recv rx in 4)
                (declare (ignore addr sport))
                (values n in)))   ; => 4, #(#xde #xad #xbe #xef ...)
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

| Symbol | Kind | Meaning |
|---|---|---|
| `dds.disc:*zerocopy-enabled*` | special var | **Default `NIL`.** Read once per node at `make-disc-node`; when `T` (and SHMEM is available) the node builds a Zero-Copy writer pool and advertises `PID_ZEROCOPY_CAPABLE`. NOT cleared for ship — pending counsel (R6). |
| `dds.disc:*zerocopy-min-payload-bytes*` | special var | Size threshold (default 1024): only a serialized payload **strictly larger** is sent as a reference. A local policy, not a wire constant. |
| `dds.disc:+zerocopy-pool-slots+` / `+zerocopy-pool-slot-bytes+` | constants | Shared pool geometry (32 slots x 65536 octets), used by **both** pool creation and the reader's attach sizing (one definition). |
| `dds.disc:disc-node-zc-sends` | accessor | Count of samples this node published as a 16-byte reference (proof/diagnostic). |
| `dds.rtps.discovery:endpoint-data-zerocopy-capable` | accessor | T iff the endpoint advertised `PID_ZEROCOPY_CAPABLE` (fail-open: absent → NIL). |
| `dds.cdr:+zc-encapsulation-id+` / `encode-zc-reference` / `parse-zc-reference` | constant / functions | The 20-octet reference codec (4-octet encapsulation header + `{slot-index, generation, slot-bytes, reserved}` LE). |
| `dds.xport.zerocopy` | package | The SHMEM sample-pool (`%zc-loan`/`%zc-resolve`/`%zc-release`, pshared-mutex-guarded — full Clasp parity, no foreign-SAP CAS). |

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
Zero-Copy conses more than SHMEM. Sizing the sink to the parsed length (cheap) and ultimately read-in-place
(FlatData) turn the allocation win on at all sizes.

`make zc-xproc` (`scripts/zerocopy-roundtrip.sh`, `dds.shapes:run-zc-xproc-pub`/`run-zc-xproc-sub`) launches two
**separate SBCL OS processes** that discover over loopback UDP and exchange large `LargeData` samples; the
publisher stores each in its pool and sends only a reference, and the subscriber resolves it from the writer's
pool **cross-process** and verifies the payload byte-exact (PASS = sub received ≥ threshold byte-exact AND the
pub's `zc-sends > 0`). This is the proof a within-image test cannot give: the reference resolves across the OS
boundary. SBCL only (Clasp/macOS inherits the SHMEM by-name-attach gap). **Reliable Zero-Copy and literal
read-in-place / FlatData are follow-ups (out of scope v1).**

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
  NFR-PORT gap — see [SHMEM architecture](#shmem-architecture) above). Multicast (`SO_REUSEPORT` +
  `IP_ADD_MEMBERSHIP` + loopback) is wired in the PAL for SPDP discovery; the OS-specific socket-option constants
  are gated by **OS** reader conditionals (`#+darwin`/`#-darwin`) in `pal-net.lisp`, not impl ones.
- **Landed (gated, default-OFF):** Zero-Copy-over-SHMEM (WP-ZEROCOPY, FR-PF-3) — a per-writer SHMEM
  sample-pool + 16-byte-reference passing for large same-host samples, behind `dds.disc:*zerocopy-enabled*`
  (default `NIL`) and **NOT cleared for ship pending counsel (R6, ADR 0014)**. See
  [Zero-Copy over SHMEM](#zero-copy-over-shmem-wp-zerocopy--default-off-r6-patent-gated) above.
- **Planned:** literal 0-copy read-in-place (WP-FLATDATA), reliable Zero-Copy, a TCP transport, a Linux
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
  `with-gc-inhibited` are still no-ops; `monotonic-ns` uses the portable real-time clock scaled to ns (a
  `clock_gettime(CLOCK_MONOTONIC)` fast path is a later replacement).
- **UDP is best-effort by design:** the UDPv4 transport's `send` swallows a `sendto` failure to one destination
  (an unreachable/stale/placeholder locator, e.g. a peer advertising `0.0.0.0`) and returns 0 rather than
  signalling — the reliable RTPS layer recovers via HEARTBEAT/ACKNACK. See the [RTPS engine](rtps-engine.md).

## See also

- [RTPS engine](rtps-engine.md) — the reliable/best-effort writer/reader that drives these transports.
- [Discovery](discovery.md) — SPDP/SEDP over UDP unicast + multicast.
- [CDR codec, buffers & the arena](cdr-and-memory.md) — the `octet-buffer`/cursor and static arena the examples
  serialize into.
