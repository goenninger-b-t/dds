# ADR 0114 — The AllegroCL socket layer: one portability seam, not a rewrite

- **Status:** Accepted
- **Date:** 2026-08-07
- **Requirement:** FR-XPORT-1, NFR-PORT, NFR-MEM
- **Completes:** ADR 0113 §5 — `:dds-pal` now **loads and functions** on AllegroCL

---

## 1. The problem

`pal-net.lisp` is written against `SB-BSD-SOCKETS`, which **SBCL and Clasp both bundle and AllegroCL does
not**. `:dds-pal` therefore failed to load on Allegro with `Package "SB-BSD-SOCKETS" not found`, and that
was the whole of what ADR 0113 left open.

## 2. What measurement changed about the scope

The raw count — 45 references — badly overstated it. Of 68 functions in the file:

- **32 are pure CFFI** (`mmap`, POSIX and SysV shared memory, semaphores, the pshared mutex/condvar) and
  needed nothing;
- **20 need neither** (plain Lisp, `bordeaux-threads`);
- **16** touch `sb-bsd-sockets`, across only **12 distinct symbols**.

⭐ **And the hot paths already bypass it entirely.** `udp-send-to` and `udp-recv` call `sendto`/`recvfrom`
through CFFI and touch `sb-bsd-sockets` only to obtain the **integer file descriptor**. A socket in this PAL
is *already* an fd wrapper.

## 3. The decision — use AllegroCL's own socket interface, and add ONE seam

AllegroCL ships a mature `socket:` interface (93 exported symbols). Reimplementing `socket(2)`/`bind(2)`
through CFFI — which was the first plan — would have been reinventing a maintained, tested library for no
gain. The mapping is essentially 1:1:

| `sb-bsd-sockets` | `socket:` |
|---|---|
| `make-instance 'inet-socket` + `socket-bind` | `make-socket :type :datagram :local-host/:local-port` |
| `sockopt-reuse-address` | `:reuse-address t` |
| `socket-file-descriptor` | `socket-os-fd` |
| `socket-name` (port) | `local-port` |
| `socket-send` / `socket-receive` | `send-to` / `receive-from` |
| `socket-connect` / `socket-listen` / `socket-accept` | `make-socket :remote-*` / `:connect :passive` / `accept-connection` |
| `socket-close` | `close` — an Allegro socket **is a stream** |

Two one-line shims carry the whole divergence: **`%socket-fd`** and **`%socket-close`**. Everything else is
a `#+allegro` arm inside `pal-net.lisp`, where reader conditionals are permitted.

### ⭐ The property that had to survive: zero-allocation datagram I/O

`socket-os-fd` answers the same integer, so the raw CFFI `sendto`/`recvfrom` path — the reason NFR-MEM's
per-datagram allocation is zero — works **unchanged** on Allegro sockets. Verified directly before any PAL
code was written: a datagram round-tripped on loopback through `socket:make-socket` + raw CFFI, payload
intact. The port therefore costs nothing on the hot path rather than trading it away.

## 4. Where the semantics genuinely differ, and it is NOT hidden

- **Bind/listen happen at creation.** `make-socket` takes `:local-host`/`:local-port`/`:backlog`, so there
  is no separate bind or listen step — which also means **SO_REUSEPORT is applied after the bind** on
  Allegro, unlike the sb-bsd-sockets path. The SPDP shared multicast port is the only consumer, and a
  platform refusing it still surfaces the status rather than leaving a silently unshared port.
- ⚠️ **`tcp-recv` loses the `:timeout` / `:eof` distinction.** The sb-bsd-sockets path reads `n=NIL` for an
  `SO_RCVTIMEO` timeout and `n=0` for a clean close. Allegro's stream `read-sequence` signals on timeout,
  which this arm folds into `:eof`. The consumer (the durability microservice) retries either way, so the
  behaviour is safe — but it is **coarser**, and that is a documented NFR-PORT gap, not an equivalence.
- **`(require :sock)` is mandatory.** The socket interface is a loadable module, not part of the base
  image; without it every `socket:` reference is a read-time failure.

## 5. ⛔ A bug this introduced, caught before it reached SBCL

Routing every `socket-file-descriptor` call through `%socket-fd` was done with a global replace — which also
rewrote **`%socket-fd`'s own body**, turning its `#-allegro` arm into `(%socket-fd socket)`: unbounded
recursion on **SBCL and Clasp**, the two implementations that were previously green.

It was found by inspection, not by the Allegro test — the Allegro arm takes the `#+allegro` branch and could
never have exercised it. ⭐ **A port verified only on the new platform can break the old ones in exactly the
code the port shares**, which is why the regression run on SBCL and Clasp is part of this ADR's verification
and not an afterthought.

## 6. Verification

Through the PAL's own API on AllegroCL, not the raw syscalls:

- **UDP** — `udp-open`, `udp-local-port`, `udp-send-to` and `udp-recv` on **both** the raw static-buffer
  fast path *and* the non-static fallback, payload compared octet-for-octet, `udp-close`
- **TCP** — `tcp-listen`, `tcp-local-port`, `tcp-accept` **in a real second thread**, `tcp-connect`,
  `tcp-send`, `tcp-recv`, `tcp-close`

Result: **GREEN, 0 failures**, and `:dds-pal` loads.

Plus the full suites on SBCL and Clasp, and `gate-build`, to prove the shared arms are unchanged.

## 7. What is still not parity

`:dds-pal` is one system. The layers above it — `dds-core`, `dds-cdr`, `dds-types`, `dds-rtps`, `dds-disc`,
`dds-dcps`, the tests — have not been loaded on AllegroCL yet, and each may surface its own portability
work. **The Definition of Done's "SBCL and AllegroCL" is not yet met**; what is now true is that the
platform layer beneath everything else is ported and verified.
