# The ACKNACK re-parsed its destination IP string on every datagram

**Date:** 2026-07-20 · **Requirement:** NFR-MEM (0 B/sample), NFR-PERF-8 · **ADR:** 0065 (decision), 0062 (budget)
**Machine:** arm64 Darwin, SBCL · **Harness:** `dds.bench:mem-per-sample` (`make gate-mem`) — two co-located
participants, default SHMEM transport, payload 0, n = 3000.

## Headline

| | B/sample |
|---|---|
| before (`*udp-raw-sendto*` NIL) | **2883.0** |
| after (`*udp-raw-sendto*` T) | **2708.2** |
| `make gate-mem`, twice, after | **2730.2 / 2730.2** |

**−153 to −175 B/sample (−5.3 % to −6.1 %).** arm64 ceiling ratcheted **2950 → 2800**. Cumulative from the
ADR 0062 baseline: **3560 → 2730, −830 B/sample (−23 %)**.

The A/B flag was set with a global `setf`, not a `let`. A `let` binds only the measuring thread and the
sends happen on the receiver threads, which reads as a false "no difference" — the trap that misled
slices 1 and 3.

## How the target was found

ADR 0062's budget was re-split by probing each phase of the measurement cycle
(`write-sample` ; `take` (miss) ; `sleep` ; `take` (hit)):

| phase | B/sample | share |
|---|---|---|
| WRITE — TX, user thread | 873.2 | 30 % |
| MISS — an empty `take-samples` | 152.9 | 5 % |
| **SLEEP window — RECEIVER THREADS** | **1267.1** | **44 %** |
| HIT — the take that returns the sample | 589.8 | 20 % |
| total | 2883.0 | (matches `gate-mem` exactly) |

The sleep window is a clean receiver-thread probe: `(sleep 0.0002)` allocates **0 B** on the calling
thread (measured in isolation), so everything accrued across it came from another thread.

Two things this settled before any code was written:

- **A control arm** — the same cycle tempo with the writer idle — costs **196.6 B**, which is exactly the
  two empty `take-samples` calls at 98.3 B each. Background DDS chatter is ~0 B/cycle at this tempo, so
  **93 % of `gate-mem` is genuinely marginal per-sample cost**, not amortized background.
- **Counter deltas** (not inference) show exactly **1 SHMEM DATA send and 1 ACKNACK per sample**. Every
  per-datagram cost on the ACKNACK path is therefore paid once per sample, undivided.

Then the primitives on that path were measured in isolation — a tight loop of N identical calls with one
`bytes-consed` delta around the whole loop, the same shape that produced the 98.3 B empty-take figure that
the phase split independently confirmed:

| variant | B/call |
|---|---|
| `udp-send-to` as shipped | **360.3** |
| `socket-send` with the address list hoisted | 98.3 |
| raw `sendto(2)` + pre-built sockaddr | **0.0** (and delivers byte-exact) |

## The defect

```lisp
(sb-bsd-sockets:socket-send socket buffer length :address (list (%parse-ipv4 host) port))
```

`%parse-ipv4` parses the **dotted-quad destination STRING** into four octets on every datagram, via four
`parse-integer` calls — ~262 B of the 360. The remaining ~98 B is `socket-send`'s keyword parsing,
generic-function dispatch and per-call alien sockaddr.

This is the mirror image of `89bf344`, which deleted a `format nil` that rendered an IP string per locator
per send. That fixed octets→string. **string→octets was still there, on every datagram we send.**

## The fix

Fill a pre-allocated per-thread foreign `struct sockaddr_in` (carved from the same per-thread allocation
that already backs `*thread-timespec*` / `*thread-atomic-cell*`) with a fixnum-accumulating, bounds-capped
parse, and call `sendto(2)` through a pre-resolved function pointer. Wire bytes unchanged. Full rationale,
the two platform layouts and the falsification argument are in ADR 0065.

## Honesty note — the per-site number over-predicted, again

The isolated measurement said 360 B/call at 1 call/sample; `gate-mem` moved ~153–175. That is the **third**
time a per-site figure has over-reported (after `%reader-routes-for`'s 328 → 88 and two `sb-sprof :alloc`
shares). The ADR 0062 rule stands unchanged and was followed here: **per-site numbers RANK candidates;
`gate-mem` SIZES them, and nothing is claimed until it does.**

## Validation

`gate-build` PASS both impls (clean cache, self-falsified) · **570/570 tests on Clasp and SBCL** ·
`gate-hotpath` · `gate-types` (2893 defuns) · `gate-nocond` (ceiling 0) · `gate-pal` · `corpus` (11
vectors, 0 mismatches) · `mem` · `fuzz` — all green. `run-udp-loopback-test` now asserts byte-exact
delivery under **both** arms of `*udp-raw-sendto*`, which is what makes the platform-specific `sockaddr_in`
layout falsifiable; CI/Linux is the oracle for the non-Darwin branch.
