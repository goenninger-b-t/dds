# ADR 0007 — PAL condvar-wait gains an optional timeout (DDS.PAL)

- **Status:** Accepted (2026-06-06)
- **Deciders:** A0 (integrator)
- **Amends:** ADR 0002 (the frozen L0 `DDS.PAL` contract, §7.6)

## Context

`DDS.PAL` froze the thread primitives `make-condvar` / `condvar-wait (cv lock)` /
`condvar-signal (cv)` at M0. The two-argument `condvar-wait` blocks until signalled,
with **no bounded wait**. The M3 #3 follow-up replaces the DCPS WaitSet's ~10 ms busy
poll with a condition-variable wake driven by the receiver thread; that requires a
**timed** wait so `WaitSet::wait(timeout)` can honour its DDS Duration_t deadline and
so a missed/spurious wake cannot block a waiter forever. No other timed-blocking
primitive exists in the contract.

## Decision

Extend `condvar-wait` with an optional timeout (seconds):

```
condvar-wait (cv lock &optional timeout-seconds) -> woke-p
```

- `timeout-seconds` `nil` (the default) ⇒ wait indefinitely, exactly as before.
- A non-nil real ⇒ wait at most that many seconds.
- Returns a generalized boolean: true if the wait returned due to a signal (or a
  spurious wake), `nil` on timeout. Callers MUST re-check their predicate on wake
  (condition variables admit spurious wakeups); the return value is a hint, not a
  guarantee that the predicate holds.

Both PAL implementations delegate to `bordeaux-threads:condition-wait`, which already
accepts a `:timeout` keyword; the wrapper simply forwards it. The exported symbol set
of `DDS.PAL` is unchanged — only `condvar-wait`'s arity grows by one optional argument.

## Compatibility

**Backward-compatible.** Every existing call site uses the two-argument form, which is
unaffected (`timeout-seconds` defaults to `nil` ⇒ the prior indefinite-wait semantics).
This is an additive extension of the §7.6 contract, not a breaking change. As of this
ADR `condvar-wait` had **no in-tree callers** (the WaitSet polled); the first caller is
`dds.dcps:wait-set-wait`, introduced in the same change.

## Consumers

- `dds.pal` (pal-contract docstring; pal-sbcl.lisp; pal-clasp.lisp). No pal-allegro
  exists yet; when it lands it MUST implement the three-argument form.
- `dds.dcps` (conditions.lisp `wait-set-wait` — the sole initial caller).

## Verification

`wait-set-wait` is exercised by `dcps-conditions-waitset` (GuardCondition on-demand
wake, ReadCondition wake on real UDP data, empty-WaitSet timeout) and the new
`dcps-condvar-wake` test (a written sample wakes a blocked WaitSet and fires
on_data_available). The timeout path is asserted by the empty-WaitSet case returning
nil within its deadline. Green on Clasp + SBCL.
