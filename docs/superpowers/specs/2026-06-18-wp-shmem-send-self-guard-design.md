# WP-SHMEM-SEND-SELF-GUARD — a hard %shmem-send fault degrades to the UDP fallback (FR-XPORT-2) — design

**Goal.** Make a SIGNALED `%shmem-send` hard error (segment detached, pshared error, bounds) degrade GRACEFULLY:
catch it on the production send path, observe it (a counter + the sender-error hook), and fall through to the
EXISTING UDP fallback — so the datagram still delivers over UDP, instead of propagating (today the
WP-SENDER-ERROR-RESILIENCE thread-guard catches it but drops the datagram + relies on reliability repair).
Non-R6 (SHMEM is standard, FR-XPORT-2). The deferred follow-up flagged in WP-SENDER-ERROR-RESILIENCE / ADR 0016.

## Owner-confirmed decisions (brainstorm 2026-06-18)
1. Observability = **a counter + fire the sender-error hook** (the most observable option; the owner accepts
   widening `*sender-emit-error-hook*`'s use beyond sender-thread emit errors to this transport-fault site).
2. **Layering:** the hook (`*sender-emit-error-hook*`) lives in `dds.disc`; the SHMEM `:send` lambda lives in
   `dds.xport` (a lower layer `dds.disc` depends on). To avoid an upward `dds.xport → dds.disc` dependency,
   the guard goes in **`%send-raw-buf` (dds.disc)** — the production send path that already has the SHMEM
   transport + the node + the UDP-fallback dest + the hook in scope.

## Grounded current state (file:line — verified)
- `src/dds-disc/dataplane.lisp:81` `%send-raw-buf` — the shared one-datagram send. Its SHMEM block:
  ```lisp
  (when (and shmem-dest (disc-node-shmem node))
    (when (plusp (dds.xport:send (dds.xport.shmem:shmem-transport-transport (disc-node-shmem node))
                                 shmem-dest buf 0 len))
      (incf (disc-node-shmem-sends node))
      (return-from %send-raw-buf t)))   ; delivered over SHMEM
  (dds.xport:send (disc-node-transport node) (dds.xport.udp:make-udp-locator …) buf 0 len))  ; UDP fallback
  ```
  Today a SIGNALED `%shmem-send` error propagates out of the `(dds.xport:send shmem …)` call (the `plusp`
  never completes). A return-0 (lane-full / claim-fail) already falls through to the UDP send.
- `src/dds-xport/shmem.lisp:192` — the SHMEM `:send` lambda calls `%shmem-send` with NO handler (unlike UDP
  `:send` at `udp.lisp:31-39` which wraps in `(handler-case … (error () 0))`). `%shmem-send` at shmem.lisp:212.
- `src/dds-disc/disc.lisp:134` — `disc-node` slot `(shmem-sends 0 :type (integer 0))` (the SHMEM diagnostic
  counter to mirror); `disc.lisp:67` the defstruct.
- `*sender-emit-error-hook*` + the `%note`-style fire pattern in `dataplane.lisp` (WP-SENDER-ERROR-RESILIENCE).

## Design

### 1. The guard (in `%send-raw-buf`, dds.disc)
Wrap the SHMEM send in a `handler-case`; on a SIGNALED error, observe + return 0 → the existing UDP fallback:
```lisp
(when (and shmem-dest (disc-node-shmem node))
  (when (plusp (handler-case
                   (dds.xport:send (dds.xport.shmem:shmem-transport-transport (disc-node-shmem node))
                                   shmem-dest buf 0 len)
                 (error (c) (%note-shmem-send-fault node c) 0)))   ; hard SHMEM fault → counter+hook, fall to UDP
    (incf (disc-node-shmem-sends node))
    (return-from %send-raw-buf t)))
(dds.xport:send (disc-node-transport node) (dds.xport.udp:make-udp-locator …) buf 0 len))
```
The `handler-case` fires ONLY on a signal (a hard fault) → `%note-shmem-send-fault` + return 0 → `(plusp 0)`
nil → UDP fallback delivers. A benign lane-full (the SHMEM send RETURNS 0) does NOT enter the handler → UDP
fallback with NO counter/hook (the fault-vs-lane-full distinction). The SHMEM `:send` lambda (dds.xport) stays
unguarded so it can signal up to `%send-raw-buf`; non-production callers (the SHMEM unit tests) are
test-scoped with controlled input.

### 2. The observability — `%note-shmem-send-fault` + a counter
- A `disc-node` slot `(shmem-send-faults 0 :type fixnum)` (beside `shmem-sends`, disc.lisp:134).
- `%note-shmem-send-fault (node condition)` (dds.disc, beside the WP-SENDER-ERROR-RESILIENCE hook machinery):
  `(incf (disc-node-shmem-send-faults node))` then `(ignore-errors (funcall *sender-emit-error-hook*
  condition :shmem-send-fault (disc-node-shmem-send-faults node)))` — the `ignore-errors` guarantees a
  signaling hook cannot break the send. Reuses the existing `(condition context count)` hook contract; the
  context keyword `:shmem-send-fault` distinguishes it from `:async-sender` / `:flow-scheduler`.

### 3. Fault injection (test affordance, inert in production)
`*debug-shmem-send-fault*` (special in `dds.xport.shmem`, default NIL, exported; mirrors `*debug-emit-fault*`):
when non-NIL, `%shmem-send` (or the `:send` lambda) signals a `shmem-send-test-fault` (a
`define-condition … (error)`). Injected at the TOP of `%shmem-send` (shmem.lisp:212). NIL → zero production
effect, byte-identical. The test sets it → `%send-raw-buf`'s `handler-case` catches → counter+hook+UDP-fallback.

## Test scenarios (oracle = the UDP-fallback delivery + the counter + the hook record; both impls)
1. **Hard fault → UDP fallback + counter + hook (our-to-our, both impls):** a same-host SHMEM peer pair;
   bind `*sender-emit-error-hook*` to a recorder (GLOBAL setf if the send is on another thread, else a let is
   fine — the send here is on the caller thread); set `*debug-shmem-send-fault*`; send a user DATA; assert the
   datagram ARRIVES at the peer via the UDP fallback (received), `(disc-node-shmem-send-faults node)` = 1, the
   hook fired with context `:shmem-send-fault`, and `shmem-sends` did NOT increment (it went UDP, not SHMEM).
2. **Lane-full → UDP fallback, NO counter/hook (both impls):** simulate the SHMEM send RETURNING 0 (not
   signaling) → the datagram falls back to UDP, but `shmem-send-faults` stays 0 and the hook does NOT fire
   (the fault-vs-lane-full distinction). (If a return-0 simulation is awkward, assert this via the handler-case
   structure + that the no-fault path leaves the counter 0.)
3. **No-regression (both impls):** `*debug-shmem-send-fault*` NIL → a normal SHMEM send still delivers over
   SHMEM (`shmem-sends` increments, counter 0); AND a non-SHMEM (UDP / foreign) dest send (`shmem-dest` NIL)
   is byte-identical (the guard is inert — `make mem` / the existing send tests unaffected).
4. **Cross-DDS interop (the per-feature DoD — minimal wire surface; both peers):** SHMEM is ours-to-ours, so
   the cross-DDS surface is NO-REGRESSION: confirm a live Connext + Fast DDS peer (to which we ALWAYS UDP-send,
   never SHMEM — `shmem-dest` is NIL for a foreign peer) still receives our data byte-identically (the guard
   never triggers for them). Plus the our-to-our fault→UDP-fallback (scenario 1) as the feature proof.

## Out of scope (follow-ups)
- A silent transport-level catch in the SHMEM `:send` lambda (dds.xport) mirroring UDP — it would catch the
  signal → 0 BEFORE `%send-raw-buf`, defeating the counter+hook (you can't have both catch). The production
  path is `%send-raw-buf`; the owner chose counter+hook, so the catch is there.
- The `%shmem-send` internal robustness (its own bounds are already checked; this WP handles the OUTCOME).

## Conformance citations
- FR-XPORT-2 (SHMEM transport). Local send-error handling is implementation-defined (no RTPS clause governs
  it — same as WP-SENDER-ERROR-RESILIENCE); the UDP-fallback delivery is more conformant than a drop (the
  datagram is delivered, not lost). RTPS 2.5 §8.4 (reliability) still backstops any genuinely lost datagram.
- NFR-SEC-POSTURE: the fault injector is a test affordance, inert in production, never wire-triggered.
- ADR 0013 (PAL SHMEM + the SHMEM transport) — extend with the self-guard as-built note. The
  cross-DDS-interop-per-feature DoD (minimal here — SHMEM is ours-to-ours; no-regression vs Connext+Fast DDS).
