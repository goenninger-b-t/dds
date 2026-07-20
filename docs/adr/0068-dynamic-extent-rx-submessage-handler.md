# ADR 0068 — the RX submessage handler is a stack-allocated (`dynamic-extent`) closure

- **Status:** Accepted
- **Date:** 2026-07-20
- **Requirements:** NFR-MEM, NFR-PERF-8, NFR-SEC-POSTURE
- **Relates to:** ADR 0062 (the allocation budget)
- **Contract touched:** none. `%handle-datagram` internals only; no signature, no wire, no API.

## Context

After the SHMEM slice (ADR 0067) the receiver thread was still the largest allocation phase, and its two
biggest frames in the allocation profile were `dispatch-message` (7.3 %) and `%handle-datagram` (7.0 %).
Reading `%handle-datagram` rather than trusting the profile: it dispatches a datagram's submessages by
building a **fresh lambda per datagram** and handing it to `dispatch-message`:

```lisp
(dds.rtps.message:dispatch-message
 cursor
 (lambda (id flags c body-len) …)   ; closes over node, enforce-rtps, src-prefix, buf
 size)
```

That closure captures four values from the enclosing frame, so SBCL cannot prove it does not escape across
the (non-inlined) call to `dispatch-message` and **heap-allocates it on every received datagram** — measured
at ~110–130 B/sample (roughly two received datagrams per round trip: the DATA on the reader side, the
ACKNACK on the writer side).

## Decision

**Name the handler with `flet` and declare it `dynamic-extent`, so SBCL stack-allocates it.**

```lisp
(flet ((%rx-dispatch-submsg (id flags c body-len) …))
  (declare (dynamic-extent #'%rx-dispatch-submsg))
  (dds.rtps.message:dispatch-message cursor #'%rx-dispatch-submsg size))
```

This is sound because **`dispatch-message` is a downward funarg**: it `funcall`s the handler in a loop and
never stores it (verified by reading it — no slot assignment, no return, no push). A handler that does not
outlive the call frame that created it is the textbook case `dynamic-extent` exists for. The wire bytes, the
dispatch order, and every submessage handler are untouched; only where the closure's environment lives
changes — heap → stack.

## Why this is safe in *this* function specifically

`%handle-datagram` is the RTPS parser entry point — the single most-fuzzed, most security-sensitive
function in the stack, run at `(safety 0)`. A `dynamic-extent` closure that *did* escape would be a
use-after-return reading a reclaimed stack frame: silent corruption, not a clean error. So the claim "it
does not escape" is not taken on inspection alone:

- **The RTPS message fuzzer drives adversarial submessage streams straight through this closure** —
  mutation, truncation, random, all-zero, corrupt prefixes, hostile counts — in both production and
  `safety-0` builds, and is clean. If any path retained the handler, the fuzzer's reuse of freed stack
  would surface it.
- **Both SBCL and Clasp build and pass 571/571.** Clasp may not stack-allocate at all (its GC differs);
  `dynamic-extent` is a permission, not a command, so a conforming implementation that ignores it stays
  correct — the win is SBCL's, the correctness is both.

## Consequences

- **`gate-mem` 2533.6 → ~2413** (measured 2402.6 / 2424.6 / 2402.6). arm64 ceiling 2600 → **2470**.
- Cumulative under ADR 0062: **3560 → ~2413, −1147 B/sample (−32 %)**.
- Unlike the transport slices, this fires on **every received datagram of every kind** — discovery,
  metatraffic, user data, control — not only the measured topology, so the real-world effect is broader
  than the bench number.
- No x86_64 CI wrinkle expected beyond the usual ceiling follow-up: `dynamic-extent` help varies by
  implementation, and the x86_64 row is lowered from the CI number as before.

## What this does NOT do

- It does not touch `dispatch-message` or the frozen `type-support` / submessage contracts.
- It does not address the remaining receiver allocation (`%source-prefix`'s 12-octet copy stays declined
  per ADR 0062 §6; the SHMEM receive-side SAP boxing; `parse-data-body`'s multiple-value returns).
- It changes no security decision — the same submessages are enforced, dropped, and delivered as before.
