# The RX submessage handler was a fresh heap closure on every datagram

**Date:** 2026-07-20 · **Requirement:** NFR-MEM (0 B/sample), NFR-PERF-8 · **ADR:** 0068 (decision), 0062 (budget)
**Machine:** arm64 Darwin, SBCL · **Harness:** `dds.bench:mem-per-sample` (`make gate-mem`), payload 0, n = 3000.

## Headline

| | B/sample |
|---|---|
| before (heap closure) | **2533.6** |
| after (`dynamic-extent`) | **~2413** (2402.6 / 2424.6 / 2402.6) |

**−110 to −130 B/sample (−4.5 %).** arm64 ceiling **2600 → 2470**. Cumulative under ADR 0062:
**3560 → ~2413, −1147 B/sample (−32 %)**.

## The defect

With the transport slices done, the receiver thread's two biggest allocation frames were `dispatch-message`
(7.3 %) and `%handle-datagram` (7.0 %). Reading `%handle-datagram` rather than the profiler found why: it
dispatches a datagram's submessages through a **lambda built fresh per datagram**, closing over four values
(`node`, `enforce-rtps`, `src-prefix`, `buf`). SBCL cannot prove that closure does not escape across the
non-inlined `dispatch-message` call, so it heap-allocates it — every received datagram, ~2 per round trip.

## The fix

`dispatch-message` `funcall`s the handler in a loop and never stores it — a downward funarg. Naming the
handler with `flet` and declaring it `dynamic-extent` lets SBCL stack-allocate it instead:

```lisp
(flet ((%rx-dispatch-submsg (id flags c body-len) …))
  (declare (dynamic-extent #'%rx-dispatch-submsg))
  (dds.rtps.message:dispatch-message cursor #'%rx-dispatch-submsg size))
```

Wire bytes, dispatch order and every submessage handler unchanged; only where the closure lives moves,
heap → stack.

## Why this one needed the fuzzer, not just gate-mem

`%handle-datagram` is the RTPS parser entry — the most-fuzzed, most security-critical function in the
stack, run at `(safety 0)`. A `dynamic-extent` closure that escaped would read a reclaimed stack frame:
silent corruption. So "it does not escape" was verified, not assumed —

- `make fuzz` drives adversarial submessage streams (mutation / truncation / random / all-zero / corrupt
  prefixes / hostile counts) straight through this closure in production **and** `safety-0`, and is clean;
- both SBCL and Clasp build and pass **571/571** (`dynamic-extent` is a permission — a GC that ignores it
  stays correct; the win is SBCL's, the correctness is both).

The paren restructuring (lambda → `flet`, +2 closes, a `declare`, the call moved down) was checked with the
string/comment-aware paren checker scoped to the function before building — net depth 0 — because a
mis-balanced edit in this function is exactly the recurring hazard the campaign notes warn about.

## Validation

`gate-build` PASS both impls (clean cache, self-falsified) · **571/571 Clasp and SBCL** · `make fuzz`
clean (RTPS message + submessage-protection + origin-auth, prod + safety-0) · `gate-hotpath` ·
`gate-types` · `gate-nocond` (ceiling 0) · `gate-pal` · `corpus` · `mem` — all green.
