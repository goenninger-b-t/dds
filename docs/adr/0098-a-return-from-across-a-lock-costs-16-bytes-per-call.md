# ADR 0098 — A `RETURN-FROM` out of a `HANDLER-CASE` inside a lock costs 16 bytes on **every** call

- **Status:** **Proposed**
- **Date:** 2026-07-29
- **Requirements at stake:** **NFR-MEM** (zero bytes/sample in steady state; hot-path allocation is a gate,
  not a preference), **NFR-PERF-8**, **NFR-PORT** (a property that holds on one platform and not another is
  not a property).
- **Relates to:** ADR 0064 (an exhausted arena is a *status*, not a condition — the decision that introduced
  this shape), ADR 0095 (the shared process arena — the decision that last edited it), ADR 0088 / ADR 0089
  (the same defect *class*: an allocation forced by a construct that looks free), ADR 0078 / ADR 0085.
- **Provoked by:** four DDS-Security zero-alloc tests, red on Linux x86_64 and green on macOS/arm64, which
  became visible only when OpenSSL 3.5 entered the repro image (`bcfab9f`).

---

## 1. What was red, and why nobody had seen it

`dds.dare` (CNSA-2.0 DARE) requires **OpenSSL >= 3.5**. Ubuntu 24.04 ships 3.0.x, so `dare-available-p`
returned NIL and **the entire DDS-Security suite skipped on Linux**. Every `N passed, 0 FAILED` Linux run
before 2026-07-29 was not covering it. Once the repro image built OpenSSL 3.5 from source, the
security-inclusive Linux baseline at `main` (`bcfab9f`) was **620 passed, 4 FAILED, 624 total**:

| test | assertion | measured |
|---|---|---|
| `secured-live-zeroalloc` | `LIVE-RX-LOAN-ZERO-DELTA-256` | +16.2472 B/sample |
| `rtps-protection-zeroalloc` | the pooled SRTPS wrap must cons ~0 | 16.38 B/datagram |
| `user-submessage-protection-zeroalloc` | the pooled metadata_protection send wrap must cons ~0 | 16.38 B/datagram |
| `secured-dataplane-mem` | enabling the tier adds ~0 over plain | delta 16.3840 |

The tests are not wrong. They are the ZA-2 gates that made the secured path allocation-free, they still pass
on macOS/arm64, so the property is real and this platform had regressed against it — or never met it.

## 2. Ruling out the two explanations that would have ended the hunt early

**It is not a TLAB artifact.** 16.384 = 65536/4000 exactly — one 64 KiB TLAB refill over the gate's 4000
iterations — so the gate's own number cannot distinguish "16 B per call" from "one one-off refill". Sweeping
the iteration count settles it: a per-call cost stays flat, a one-off decays as 1/N.

```
iters=  1000  total=      0  per-call= 0.0000
iters=  4000  total=  65536  per-call=16.3840
iters= 16000  total= 262144  per-call=16.3840
iters= 64000  total=1048576  per-call=16.3840
iters=256000  total=4096000  per-call=16.0000   <- converges to the TRUE per-call cost
```

**It is not the crypto.** Measured piece-by-piece inside `%maybe-wrap-srtps` at 200 000 iterations each, the
AEAD is free and the whole cost sits in one accessor:

```
FULL %maybe-wrap-srtps        16.0563
encode-rtps-message-into       0.0000   <- the AEAD itself
pool acquire+release           0.0000
%with-send-scratch             0.0000
%ensure-send-scratch-pool     15.8925   <- the whole cost
```

Whose steady-state path is `(or (slot node) <carve>)` with the carve **not taken** — a struct-slot read and a
return. That cannot cons 16 bytes. So the cost was being forced by a construct in the *untaken* branch, paid
on every call.

## 3. The measurement that named the construct

Five variants, each `(or (disc-node-send-scratch-pool node) <one construct>)`, compiled **in the same file,
same package and same compiler policy** as the real function (a probe in another file is not comparable), all
measured in one process at 200 000 iterations with the real function as an in-process control:

| variant | B/call |
|---|---|
| v1 slot read only | 0.0000 |
| v2 + untaken `WITH-LOCK` | 0.0000 |
| v3 + untaken `HANDLER-CASE` | 0.0000 |
| v4 + untaken `HANDLER-CASE` containing a `RETURN-FROM` | 0.0000 |
| **v5 the real shape — all three nested** | **16.0563** |
| **v6 the same nesting, `RETURN-FROM` removed** | **0.0000** |
| **v7 the candidate fix (`WHEN`-guarded `SETF`)** | **0.0000** |
| REAL `%ensure-send-scratch-pool` (control) | 16.0563 |

**No single construct costs anything. Only the nesting does.** v5 and v6 differ in exactly one token.

## 4. Why

`dds.pal:with-lock` expands to an `UNWIND-PROTECT`. `HANDLER-CASE` expands to a `HANDLER-BIND` whose handler
is a closure, plus a `BLOCK`/`RETURN-FROM` pair. On its own that handler closure is stack-allocatable and
costs nothing. Put a `RETURN-FROM` in the body that targets a block **outside** the intervening
`UNWIND-PROTECT`, and the non-local exit has to be able to run through the unwind — the handler closure can
no longer be given dynamic extent and is heap-allocated instead. On SBCL x86_64 a closure with no captured
values is 2 words = **16 bytes**, and it is built at function entry, so it is paid on **every** call —
including every steady-state call that never enters the branch and never signals anything.

This is the third time this class has been paid for in this stack: an allocation forced by a construct that
allocates nothing on its face, invisible to correctness tests, invisible to a form-grepping hot-path scanner,
and findable only by a byte-level A/B. See ADR 0088 (a closure built as an *argument* before the callee can
decide anything) and ADR 0089 (a heap value cell per closed-over mutable variable, paid even when the closure
is never built).

## 5. The fix

Replace the early exit with a guard. In every one of these functions the `RETURN-FROM` was **gratuitous**:
the value `NIL` propagates out through the enclosing `OR` / `WITH-LOCK` / `OR` chain to exactly the same
result, so a `WHEN`-guarded `SETF` is semantically identical and carries no non-local exit.

```lisp
;; before — 16 B on every call
(when (null pool) (return-from %ensure-send-scratch-pool nil))
(setf (disc-node-send-scratch-arena node) arena
      (disc-node-send-scratch-pool  node) pool)

;; after — 0 B
(when pool
  (setf (disc-node-send-scratch-arena node) arena
        (disc-node-send-scratch-pool  node) pool))
```

The ADR 0064 obligation the `RETURN-FROM` existed to discharge is unchanged and still explicit: a NIL pool
**must** be tested, because an unchecked NIL would still run the `SETF` and store an arena whose own contract
says "only after the carve succeeds". The guard tests it; it simply does not unwind to do so.

At `%ensure-secured-payload-pool` the change is also a *correctness* improvement, not only an allocation one.
Its `RETURN-FROM` unwound out of a callback, through `writer-ensure-payload-pool`'s writer lock, and out of
that function entirely — whereas returning NIL is that function's **documented** `provision-fn` contract
("…or NIL when no pool could be carved"), which its body already handles with `(when pool (setf …)) pool`.

## 6. The nine sites

The shape had been copied nine times, every one of them on a per-datagram or per-sample path — which is why
four independent gates failed at the same 16 bytes:

| file | function |
|---|---|
| `src/dds-disc/dataplane.lisp` | `%ensure-send-scratch-pool`, `%ensure-submsg-scratch-pool`, `%ensure-zc-overlay-scratch`, `%ensure-secured-payload-pool`, `%ensure-secured-decode-pool`, `%ensure-rx-store-pool` |
| `src/dds-disc/disc.lisp` | `%ensure-secure-rx-pool`, `%ensure-bracket-rx-pool`, `%ensure-key-id-rx-pool` |

`%ensure-logmac` (`src/dds-durability/store-encrypted.lisp`) also carries a `RETURN-FROM`, but it is a
`LABELS`-local function with no intervening `HANDLER-CASE`/`UNWIND-PROTECT`, and v4 shows a bare `RETURN-FROM`
is free. It is deliberately left alone.

**The duplication was the real exposure, and it is now closed — as a second, behaviour-free slice.** Nine
copies of one double-checked lazy carve is *why* one construct became four red gates, and nothing stopped a
tenth copy reintroducing it. The borrow half of this pair was already factored (`%with-scratch`, with thin
per-pool wrappers); the carve half now is too.

`%lazy-carve-pool` (`src/dds-disc/disc.lisp`, beside `%with-scratch` and `%node-arena`) holds the whole
invariant in one place: *carve exactly once, off the steady state, under the pool's own lock; on failure leave
the slot NIL and change nothing; never unwind.* It takes the pool/lock/arena accessor names, the sizing, an
optional `:conditions` (sites whose allocation can exhaust real off-heap memory pass
`(or error storage-condition)`), an optional `:on-failure` (for the one site that latches instead of retrying
per sample), and an optional install body for extra state a site publishes alongside its pool. It sets the
arena slot and then the pool slot, pool **last**, because that slot *is* the double-checked-carve flag.

**Eight of the nine now go through it.** `%ensure-secured-payload-pool` deliberately does not: its pool lives
on the writer's HistoryCache rather than a node slot, its double-check and lock belong to
`writer-ensure-payload-pool`, and its arena is pushed onto a *list* under a different lock — it shares the
guarded carve but not the structure. Covering it would mean making the pool slot, the lock and the arena slot
all optional, which buys one call site and costs every reader of the macro. The macro's docstring names that
exception explicitly, so it stays a decision rather than decaying into an oversight.

The macro protects the sites that use it, not the language — so the construct-level protection is now a
**gate**: `make gate-nlx` (`scripts/gate-nlx.sh` + `scripts/nlx-scan.py`). It is a **form walker, not a grep**,
because that is forced by §3: no single construct is the defect, only the nesting, and a regex cannot see
nesting. It parses the forms, walks a frame stack, and flags an exit whose target block lies outside an
intervening unwind when the exit is raised from inside a handler. It **learns this repo's own lock/borrow
macros** by finding every `defmacro` whose expansion reaches `UNWIND-PROTECT`, to a fixpoint, seeded with the
external ones (`with-lock-held`, `with-mutex`) whose bodies are not in `src/`.

Two tiers, the shape `gate-nocond` established because a permanently-red gate is an ignored gate: the
per-sample engine is **strict (zero)**, and the rest — TypeObject/TypeLookup parsing and DARE crypto
primitives, where 16 B *once* is not a per-sample cost — is **ratcheted** at 26 in `bench/nlx-ceiling.txt`
and may only go down.

**It found a tenth site on its first run**, which is the argument for building it: `publish-sample`'s secured
T5a branch raised `(return-from publish-sample :timeout)` from inside a `HANDLER-CASE` nested in the
`UNWIND-PROTECT` that releases the pooled buffer — on the per-sample write path. There the exit is *not*
gratuitous (it must abort), so the fix is the other shape: the handler sets a flag and the exit is raised
**outside** the unwind. ⚠️ **No allocation win is claimed for it** — the secured-publish arm measures
+0.0046 → −0.1621 B/sample, i.e. noise. The pattern is corrected because it is the documented defect; the
measurement says this particular workload was not paying for it.

## 7. What this ADR does **not** claim

It does not claim the defect is x86_64-specific, and the data in hand cannot support that. The macOS dev box
runs **SBCL 2.6.5** on arm64; the repro image runs **SBCL 2.2.9.debian** on x86_64, deliberately the distro
build so it matches CI. **Both the architecture and the compiler version differ** — four minor releases apart
— so the observed split is not attributable to either one from these measurements, and calling it
"x86_64-only" would be a guess wearing a measurement's clothes. It does not matter for the fix: the construct is removed outright, so the cost
is zero on every implementation, and the property no longer depends on which compiler notices it.

## 8. Consequences

- Four DDS-Security zero-alloc gates that had never been green on the CI platform are green, at their real
  measured value rather than a relaxed ceiling.
- One rule to carry forward, and it is the generalisable part: **a non-local exit that crosses a lock is not
  free, and its cost is charged to the path that never takes it.** Prefer a guard to a `RETURN-FROM` inside
  any `HANDLER-CASE` nested in an `UNWIND-PROTECT` on a per-sample path.
- The corollary that cost the most to learn here: **no single construct in this shape allocates.** Testing
  them one at a time — the obvious experiment — returns 0.0000 four times and exonerates the real cause.
  Only the composition allocates, so the ladder has to include the composed shape or it proves nothing.
- A green suite is only as wide as the image's capabilities. Four real failures hid for weeks behind a
  pass-skip caused by a missing library, on a suite that reported `0 FAILED`.
