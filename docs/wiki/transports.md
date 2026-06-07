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
| `dds.pal:alloc-static` | function | `(n-bytes)` — allocate `n-bytes` of off-heap octet memory the GC neither scans, moves, nor reclaims; returns a foreign-backed `(unsigned-byte 8)` vector with a GC-stable address. |
| `dds.pal:free-static` | function | `(vec)` — release memory from `alloc-static`. Idempotency is the caller's job. |
| `dds.pal:static-pointer` | function | `(vec)` — the raw foreign pointer (a system-area-pointer on SBCL) to `vec`, for syscalls. |
| `dds.pal:static-length` | function | `(vec)` — octet length of a static region. |
| `dds.pal:mem-ref-u8` | function | `(vec index)` — typed raw read of one octet (declared `inline`). |
| `dds.pal:mem-set-u8` | function | `(vec index value)` — typed raw write of one octet (declared `inline`). |

**Atomics**

| Symbol | Kind | Description |
|---|---|---|
| `dds.pal:cas` | function | `(place-fn old new)` — atomic compare-and-swap. **M0 stub: signals `pal-unimplemented`** (native fast path lands in M1). |
| `dds.pal:atomic-incf` | function | `(place-fn &optional delta)` — atomic increment. **M0 stub: signals `pal-unimplemented`** (native fast path lands in M1). |
| `dds.pal:fence` | function | `(&optional kind)` — memory fence of the given `kind`. M0 no-op; a native barrier fast path lands in M1. |

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

## Notes / status

- **Landed:** UDPv4 unicast and multicast over each implementation's native `sb-bsd-sockets` (SBCL contrib;
  Clasp bundled), the pluggable `transport` record, and the synchronous mock transport. Multicast (`SO_REUSEPORT`
  + `IP_ADD_MEMBERSHIP` + loopback) is wired in the PAL for SPDP discovery; the OS-specific socket-option
  constants are gated by **OS** reader conditionals (`#+darwin`/`#-darwin`) in `pal-net.lisp`, not impl ones.
- **Planned:** SHMEM/zero-copy and TCP transports, and a raw `recvmmsg`/`sendmmsg`/iovec batched send/recv fast
  path. None are present yet — today's UDP send is one datagram per `socket-send`.
- **Per-impl rule:** `#+sbcl`/`#+clasp` reader conditionals live **only** under `dds-pal/` (`pal-sbcl.lisp` and
  the per-impl PALs). The shared `pal-net.lisp` and everything in `dds-xport` carry none. CI lint enforces this
  (NFR-PORT, the operating contract §10).
- **PAL maturity:** the **SBCL** PAL is the reference; Clasp shares the native socket layer. The **AllegroCL**
  PAL is a planned target and **not yet present**. Several capabilities are explicit M0 stubs pending M1 native
  fast paths: `cas` and `atomic-incf` signal `pal-unimplemented`; `fence`, `gc-suggest`, and `with-gc-inhibited`
  are no-ops; `monotonic-ns` uses the portable real-time clock scaled to ns (a `clock_gettime(CLOCK_MONOTONIC)`
  fast path is the M1 replacement).
- **UDP is best-effort by design:** the UDPv4 transport's `send` swallows a `sendto` failure to one destination
  (an unreachable/stale/placeholder locator, e.g. a peer advertising `0.0.0.0`) and returns 0 rather than
  signalling — the reliable RTPS layer recovers via HEARTBEAT/ACKNACK. See the [RTPS engine](rtps-engine.md).

## See also

- [RTPS engine](rtps-engine.md) — the reliable/best-effort writer/reader that drives these transports.
- [Discovery](discovery.md) — SPDP/SEDP over UDP unicast + multicast.
- [CDR codec, buffers & the arena](cdr-and-memory.md) — the `octet-buffer`/cursor and static arena the examples
  serialize into.
