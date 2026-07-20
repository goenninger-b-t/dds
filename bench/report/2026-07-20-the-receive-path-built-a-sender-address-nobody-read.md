# The receive path built a sender address nobody read

**Date:** 2026-07-20 · **Requirement:** NFR-MEM (0 B/sample), NFR-PERF-8 · **ADR:** 0066 (decision), 0062 (budget)
**Machine:** arm64 Darwin, SBCL · **Harness:** `dds.bench:mem-per-sample` (`make gate-mem`), payload 0, n = 3000.

## Headline

| | B/sample |
|---|---|
| before (`*udp-raw-recvfrom*` NIL) | **2730.2** |
| after (`*udp-raw-recvfrom*` T) | **2642.9** |
| `make gate-mem`, three further runs | 2621.0 / 2642.8 / 2621.0 |

**−87 B/sample (−3.2 %).** arm64 ceiling **2800 → 2710**. Cumulative under ADR 0062:
**3560 → ~2630, −917 B/sample (−26 %)**.

## How it was found

After ADR 0065 the phase split was re-measured rather than inherited (total 2708.4, matching `gate-mem`
2708.3 — and the −175 from ADR 0065 landed exactly on the receiver thread, confirming the model):

| phase | B/sample | share |
|---|---|---|
| **RECEIVER THREADS** | **1092.4** | **40 %** |
| WRITE — TX, user thread | 851.4 | 31 % |
| HIT — the take that returns the sample | 633.4 | 23 % |
| MISS — an empty `take-samples` | 131.1 | 5 % |

A re-profile at usable resolution (25 000 cycles → ~1100 samples; the earlier 4 000-cycle run yielded 188
and ranked nothing) still showed `make-sockaddr-for` 1.7 % and `call-with-socket-addr` 1.7 % — the send path
was gone, so this was the **receive** side.

| variant | B/call |
|---|---|
| `udp-recv` as shipped | **304.6** |
| raw `recvfrom(2)`, `src_addr = NULL` | **0.0** (byte-exact) |

`sb-bsd-sockets:socket-receive` builds a sockaddr for the sender and converts it to a Lisp address on every
datagram. **Nothing reads it**: RTPS identifies a source by GuidPrefix, never by IP; `start-udp-receiver`
takes `(nth-value 0 …)` and both other callers `(declare (ignore addr senderport))`.

## The half that wasn't a syscall swap

The receiver thread exits today *because `socket-receive` signals* on a closed socket. `recvfrom` returns
−1 instead, so a naive port spins forever and `stop-node`'s join hangs — the "stack could not shut down on
Linux" defect. Two facts were probed, not assumed:

- A thread parked in raw `recvfrom` is **not** woken by `tcp-shutdown` on Darwin (`shutdown(2)` on an
  unconnected UDP socket returns `ENOTCONN`). The probe **hung** and had to be killed — which is how this
  was learned rather than shipped.
- **`socket-close` resets the fd slot to −1 on both SBCL and Clasp**, so a fresh-read fd yields `EBADF`
  immediately and there is no fd-reuse exposure.

Hence: exit on **negative**, never on zero (a zero-length datagram is legal — treating it as EOF would let
any peer kill a receiver thread, NFR-SEC-POSTURE). Full argument in ADR 0066.

`udp-transport-recv`'s declared return type `(values (integer 0) t t)` was widened to `(values integer t t)`:
at `(safety 0)` a non-negative declaration lets the compiler fold a caller's `(minusp size)` check away.

## Honesty note

304.6 B/call isolated → −87 B end-to-end, a ~3.5× over-report and the **fourth** in this campaign. The rule
holds and was followed: per-site numbers RANK, `gate-mem` SIZES, and nothing is claimed until it does.

## Validation

`gate-build` PASS both impls (clean cache, self-falsified) · **570/570 Clasp and SBCL — no hang, so the
receiver-thread shutdown path is intact** · `gate-hotpath` · `gate-types` · `gate-nocond` (ceiling 0) ·
`gate-pal` · `corpus` · `mem` · `fuzz` — all green. `run-udp-loopback-test` drives both arms and asserts
byte-exact delivery in each; `run-udp-receiver-test` exercises spawn → recv → close → thread exit.
