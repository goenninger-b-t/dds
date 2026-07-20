# ADR 0066 — `udp-recv` receives via raw `recvfrom(2)` and stops reporting the sender address

- **Status:** Accepted
- **Date:** 2026-07-20
- **Requirements:** NFR-MEM, NFR-PERF-8, FR-XPORT-1, NFR-SEC-POSTURE, NFR-PORT
- **Relates to:** ADR 0065 (the symmetric send-side change), ADR 0062 (the allocation budget)
- **Contract touched:** `DDS.PAL` — `udp-recv` (now `(values size status)`: sender address no longer
  reported, `:closed` status, buffer must be PAL-static), `*udp-raw-recvfrom*` (added);
  `DDS.XPORT.UDP` — `udp-transport-recv` return type

## Context

ADR 0065 removed the allocation from the datagram **send** path. Re-splitting the budget afterwards left
the receiver threads still the largest phase (1092 B of 2708, 40 %), and a higher-resolution allocation
profile (25 k cycles → ~1100 samples; the earlier 4 k-cycle run produced 188 and was useless) still showed
`make-sockaddr-for` at 1.7 % and `call-with-socket-addr` at 1.7 % — on the **receive** side this time.

`udp-recv` was:

```lisp
(multiple-value-bind (buf size addr port) (sb-bsd-sockets:socket-receive socket buffer length)
  (declare (ignore buf))
  (values size addr port))
```

`socket-receive` builds a sockaddr for the sender and converts it into a Lisp address on every datagram.
Measured in isolation: **304.6 B/call**, against **0.0 B/call** for `recvfrom(2)` with `src_addr = NULL`.

**Nothing in the stack uses the sender address.** RTPS identifies a source by the GuidPrefix in the message
header (RTPS 2.5 §8.3.3), never by IP. `start-udp-receiver` — the only production consumer — takes
`(nth-value 0 …)`; the two remaining callers, both tests, `(declare (ignore addr senderport))`. We were
paying a sockaddr, an address conversion and a generic-function dispatch per received datagram to produce
a value no one reads.

## Decision

1. **`udp-recv` calls `recvfrom(2)` directly with `src_addr = NULL`** (equivalent to `recv(2)`), through a
   pre-resolved `*recvfrom-fp*`, and returns **`(values SIZE STATUS)`**. The sender address is no longer
   reported at all. If a future caller needs it, add a separate `udp-recv-from` rather than taxing every
   datagram.

2. **`BUFFER` must be PAL-static**, as for `udp-send-to` (ADR 0065): the kernel writes into it through a
   raw pointer, and NFR-MEM forbids SAP-addressing a heap array.

3. **`*udp-raw-recvfrom*` (default T) keeps the `socket-receive` path** as the A/B lever and escape hatch.

### The part that is not a syscall swap: how the receiver thread exits

This is the load-bearing half, and it was investigated before any code was written.

`start-udp-receiver`'s loop exits **because `socket-receive` SIGNALS** on a closed socket
(`handler-case (error () (return))`). `recvfrom(2)` reports the same condition by **returning −1**. A naive
port therefore spins forever, `stop-node`'s join never returns, and the stack cannot shut down — *exactly*
the Linux defect `udp-close` exists to document and fix. Two facts were established empirically rather than
assumed:

- **A thread parked in raw `recvfrom` on a UDP socket is NOT woken by `dds.pal:tcp-shutdown` on Darwin.**
  `udp-close` calls `(ignore-errors (tcp-shutdown socket))`, and `shutdown(2)` on an *unconnected* UDP
  socket returns `ENOTCONN`. A probe that shut down such a socket and then joined the parked thread **hung**
  and had to be killed. On Darwin the real wake is `close(2)`; on Linux the shutdown does wake it (which is
  why the ADR-0063-era fix worked there).
- **`socket-close` resets the descriptor slot to −1 on BOTH SBCL and Clasp** (measured). So a `recvfrom`
  that reads the fd fresh each iteration gets −1 → `EBADF` → an immediate negative return, and there is **no
  fd-reuse exposure** — the socket object never hands back a recycled descriptor belonging to another socket.

### ⚠️ AND THE FIRST CUT OF THIS GOT IT WRONG — CI CAUGHT IT, macOS COULD NOT

The first version exited the loop on **any negative return**. That is wrong by construction, and it was
green on macOS and **red on Linux** (`d1cae6f`: receiver threads died mid-run, surfacing as an
unrelated-looking ZC refcount failure, `PIN2-FREED-REVERSE`).

`-1` does not mean "closed". It also means, at least:

- **EINTR** — SBCL stops threads for GC with a signal on Linux, so a blocked `recvfrom` is interrupted
  routinely under load. `socket-receive` hid this by retrying internally.
- **ECONNREFUSED** — Linux queues an ICMP port-unreachable from an earlier `sendto` and reports it on the
  *next* `recvfrom` of the same unconnected UDP socket. We send to peers that may have gone away, so that
  is ordinary traffic, not an error. Darwin does not do this for unconnected sockets.

Either one alone kills a receiver thread silently. **The precise test is the SOCKET, not the return
value:** `socket-close` resets the fd slot to −1 on both implementations, so `fd < 0` means closed and
nothing else. `udp-recv` therefore returns `(values SIZE STATUS)`, with `STATUS = :CLOSED` only when the fd
is gone; a negative size with a NIL status is transient and the loop simply receives again.

**Zero is deliberately NOT an exit condition either.** A zero-length UDP datagram is legal, so treating it
as end-of-stream would let any peer kill a receiver thread by sending one (NFR-SEC-POSTURE). On Linux a
`shutdown`-woken `recvfrom` also returns 0, indistinguishable from that; `udp-close` closes immediately
after shutting down, so the fd goes to −1 and the next call reports `:CLOSED`. Shutdown timing is
unchanged — only how the loop learns about it.

**The lesson is a standing one, paid again:** a syscall's error return is a *set* of conditions, and
collapsing it to a single meaning is the same class of mistake as reading a wire constant from memory.
macOS cannot see it; CI/Linux is the oracle.

### A type declaration that would have silently eaten the check

`udp-transport-recv` declared `(values (integer 0) t t)`. With a negative size now possible that is not
merely stale, it is dangerous: at `(safety 0)` a caller's own `(minusp size)` check is foldable to `NIL`
against a declared non-negative type. Now `(values integer t)`.

## Consequences

- **`gate-mem` 2730.2 → 2642.9** by A/B with the flag set globally (a `let` binding never reaches the
  receiver threads). Noise band 2621–2643 over four runs; arm64 ceiling 2800 → **2710**.
- Cumulative under ADR 0062: **3560 → ~2630, −917 B/sample (−26 %)**, of which the two datagram-syscall
  slices are −262.
- The isolated 304.6 B/call over-predicted the −87 B end-to-end delta by ~3.5× — the **fourth** per-site
  over-report. The ADR 0062 rule is unchanged: per-site numbers RANK, `gate-mem` SIZES.
- **Migration.** `start-udp-receiver` exits on `:CLOSED` and ignores transient negatives;
  `udp-transport-recv` returns `(values integer t)` (was `(values (integer 0) t t)`); `run-udp-loopback-test` moved its receive buffer to `alloc-static` and now drives **both** arms
  of the raw/`sb-bsd-sockets` flags, asserting byte-exact delivery in each.
- **x86_64 ceiling is NOT lowered in this commit** — it cannot be measured on the arm64 dev box. Per the
  process note now in `bench/mem-ceiling.txt`, the CI number is read and that row lowered in an immediate
  follow-up. (ADR 0065 was worth 4× more on x86_64 than on arm64, so the divergence is expected to be real.)

## What this ADR does NOT do

- It does not change when or how sockets are woken or closed; `udp-close` is untouched.
- It does not batch syscalls (`recvmmsg`, FR-XPORT-6) — still a later step.
- It does not touch the SHMEM receive path, which is where the remaining receiver-thread allocation now
  concentrates (`shmem-receive-drain` / `%lane-drain` / `%rx-wait-for-work`, plus `dispatch-message` and
  `%handle-datagram`).
