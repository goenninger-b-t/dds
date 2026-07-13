# The send path formatted an IP string per locator, per send — and re-resolved the destination every time

**Date:** 2026-07-13 · **WP-8 perf (NFR-MEM, NFR-PERF-8)** · SBCL 2.6.5, arm64 Darwin, cross-process,
256 B, one-way, `dds.bench:run-echo-pinger` vs `run-echo-responder`, domain 6, SHMEM+spin default.

## Result

Steady-state allocation **5603 → 3966 bytes/sample (−29.2 %)**. Three interleaved `git stash` A/B reps
in ONE session (this box swings 16–32 µs on identical code, so a cross-session comparison is worthless):

| arm | bytes/sample | p50 (µs) | p99 (µs) | max (µs) |
|---|---|---|---|---|
| before | 5596 / 5607 / 5606 → **5603** | 10.1 / 11.1 / 12.2 | 46 / 54 / 70 | 12.6 / 12.4 / 0.7 ms |
| after  | 3968 / 3970 / 3960 → **3966** | 9.2 / 9.4 / 9.2 | 37 / 43 / 43 | 10.0 / 11.1 / 12.6 ms |

The bytes number is the reliable signal — it is reproducible to ±0.2 %. p50 moved ~17 % and the AFTER arm
is visibly tighter (9.2–9.4 vs 10.1–12.2), but that sits close to the box's noise band; do not bank it.

## ⚠️ The tail is NOT fixed. This does not close task #29.

`max` is still ~10–12 ms in BOTH arms. The ~10 ms tail is a **GC pause in the peer**
(`2026-07-13-the-tail-is-the-peers-gc.md`), and 3966 B/sample still feeds it. Cutting allocation by 29 %
does not stop a GC; only **zero** does. The goal remains 0 B/sample — this is one step, not the answer.

## What was actually allocating

Re-profiled with `sb-sprof :mode :alloc :threads :all` (a user-thread-only profile misses the drain, which
runs on the receiver thread). **The prior session's profile was stale** — its #1 suspect,
`%writer-add-bounded` at 21 %, now measures 1.6 %; `312db1b` had changed the picture. Re-profile, never
inherit a profile.

The new #1 was `SB-KERNEL:%FIND-POSITION-IF` at **18.2 %**, which no previous note mentions:

1. **`locator-usable-udpv4-p` rendered a dotted-quad STRING to ask a yes/no question about four octets.**

   ```lisp
   (and (= (locator-kind loc) +locator-kind-udpv4+)
        (not (string= (locator-ipv4-string loc) "0.0.0.0")))   ; <- locator-ipv4-string is a FORMAT NIL
   ```

   `locator-ipv4-string` is `(format nil "~d.~d.~d.~d" ...)` — a string-output-stream, control-string
   interpretation, and a result string. `usable-udpv4-locator` `find-if`s this predicate over the peer's
   locator list, and the data plane calls that on **every send** to resolve a destination. So each send
   formatted one IP string per advertised locator purely to compare it against `"0.0.0.0"`. That is the
   `%FIND-POSITION-IF` frame: the predicate's allocation, attributed to the walker calling it.

   A Locator_t's address is 16 octets with the IPv4 in octets 12..15 (RTPS 2.5 §9.3.2.4). "Is it
   0.0.0.0" is four `aref`s and zero allocation. New `locator-unspecified-ipv4-p` tests the octets. The
   dotted-quad is a *rendering* of the address, never its identity.

2. **`%usable-destination` re-resolved and re-consed the destination on every send.** Even with the
   predicate fixed it still built one more `format nil` (the chosen locator's host string) plus a fresh
   `(host . port)` cons per send — and it is a **pure function of the SPDP record's locator lists**.

   Memoized on a new `spdp-data-user-dest` slot. The memo cannot go stale: `%record-discovered`
   **replaces** the struct in `disc-node-discovered` on every re-announce, so a fresh record carries a
   fresh `:unresolved` memo and the cache's lifetime is exactly the record's — no invalidation hook to
   forget. (Contrast the SHMEM dest, cached on the *node*, which needs an explicit
   `%invalidate-shmem-dest`.) A race between receiver threads recomputes the same value. Every consumer
   dedups with `:test #'equal` and none mutates the cons, so sharing it is behaviour-preserving.

## Traps this cost me (write them down, they recur)

- **THREE responders were alive on domain 6 at once.** My bench spawned a new 120 s responder per run
  without reaping the last. The pinger then got double echoes and the profile went pathological:
  `MAKE-CONDITION` at 14.7 %, p50 268 µs, 59 KB/sample — a completely fictitious picture I nearly chased.
  `scratchpad/bench.sh` now kills every responder first and **aborts unless exactly one is alive**.
  A bench harness that does not assert its own topology will lie to you.
- **`sb-sprof`'s own compilation shows up in the profile** (`SB-C::%COMPILE-COMPONENT`, `SB-WALKER::*`).
  Ignore those frames.

## Remaining allocation (post-fix profile, flat — no single dominant site left)

`%handle-datagram` 5.6 % · `%instance-handle` 4.5 % (the 16-octet keyhash, **retained** — needs an ADR,
it touches the frozen type-support contract) · `%push-one-writer-changes` 3.2 % · `%deserialize-sample`
3.1 % · `%drain` 3.0 % · `make-sockaddr-for` 2.6 % (sb-bsd-sockets rebuilds a sockaddr per send from the
host STRING — the string round-trip the memo above now only defers) · `%reader-push-targets` 2.5 % ·
`dispatch-message` 2.2 % · `call-with-mutex` 1.8 % · `%writer-add-bounded` 1.6 %.

No single fix gets to zero from here; it is a long tail of ~2–5 % sites. The keyhash and the RX
deserialization products (loan semantics — a sample handed to the user must not be recycled underneath
them, and `read` and `take` differ) are the two that need design work rather than a local edit.
