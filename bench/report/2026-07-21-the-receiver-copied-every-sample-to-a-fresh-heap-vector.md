# The receiver copied every sample into a fresh heap vector — it now draws that copy from an arena pool

**Date:** 2026-07-21 · **Requirement:** NFR-MEM (0 B/sample), NFR-PERF-3, NFR-PERF-8, NFR-SEC-POSTURE · **ADR:** 0078, 0062
**Machine:** arm64 Darwin, SBCL · **Harnesses:** `dds.bench:mem-per-sample` A/B in one session + `make gate-mem`
+ the full suite (the correctness oracle).

## How it was found

Not by the profiler. `sb-sprof :mode :alloc` ranks allocation **events**, not bytes, and after ADR 0073–0077
its top-N is a decoy of small frequent allocations — the previous attempt at its #1 entry (the serialize
cursor, 17.8 % of events) measured **48 B/call locally and 0 B end-to-end**, because SBCL already
stack-allocates it, and was reverted. This site was found by asking a different question: *which allocation
scales with payload size?*

Exactly one did. Every received copy-path sample is copied out of the reusable receive datagram buffer into a
fresh GC-heap vector (`%on-user-data`, the `:not-a-ref` arm). The copy is necessary — the receive buffer is
reused by the next datagram while the sample must survive until the user thread drains it — but its memory
being per-sample and on the GC heap is not. At 4 KB samples that is 4 KB of garbage per receive.

## The fix

Draw the copy from a per-node arena-backed pool. The obstacle is that a pool hands out **fixed-size** buffers
while the store previously held a vector whose length *was* the payload extent — and that extent is
load-bearing twice over: `%deserialize-payload` bounds-checks against it (a longer buffer would let a
truncated payload over-read into the *previous* sample's bytes), and the durability relay persists and
republishes it.

So the pooled buffer **carries its own extent**: the pool's element is an `octet-buffer` whose `capacity` is
set to the exact `plen` at acquire. The decoder then bounds-checks against exactly `plen` — byte-identical to
the vector it replaces — and needs no scratch wrapper at all, because the stored buffer *is* the bounds. A
pooled entry is also a **distinct type**, so an extent-unaware consumer cannot silently read the wrong length;
`node-sample` keeps its exact-length contract by copying such an entry out, and only the hot drain uses the
new verbatim accessor `node-sample-raw`.

Release rides the **single store-drop choke** (`%purge-secured-sample`), so every present and future drop path
returns the buffer through one site. Secured nodes are excluded (their ciphertext needs an exact extent and
they already pool their decode output); should a live handshake install a transform mid-flight,
`%deliver-user-sample` returns the buffer and takes the pre-pool path.

## Result

- **≈ −35 B/sample at zero payload, and linear in payload size thereafter.** A/B in one session at
  `:samples 30000` (which amortises the per-run fixed cost; each arm reproducible to ±0.07 B):

  | arm | B/sample |
  |---|---|
  | baseline | 1887.15 1887.16 1887.17 1887.21 1887.22 |
  | pooled | 1852.32 1854.27 1854.38 1854.39 1854.42 |

- `gate-mem` (3000 samples) floor **1791.1**; **arm64 ceiling 1900 → 1890**, x86_64 2090 → 2040 (est ~1917,
  robustly-safe pending CI).

## A finding about the gate itself

`gate-mem`'s default 3000-sample workload carries a fixed ~65 KB of per-run allocation, which amortises to a
**~22 B/sample quantum that appears or does not**: one unchanged arm measures 1791 / 1813 / 1835 / 1857 across
runs. Its run-to-run spread (~65 B) now **exceeds a typical slice's win** (~35 B), so no single gate run can
resolve one — which is why the number above comes from a 30 000-sample A/B and not from the gate. Recorded in
`bench/mem-ceiling.txt`. Raising the gate's own sample count is the fix; it re-baselines both architecture
rows, so it needs its own commit and a CI round-trip for x86_64.

## Validation

`gate-build` PASS both impls (self-falsified). **575/575 Clasp and SBCL.** `gate-hotpath` / `gate-types` /
`gate-nocond` / `gate-pal` / `corpus` (both impls) / `mem` / `fuzz` all green.

New regression `run-rx-store-pool-test`, **falsified three ways, each seen red**:

- delete the pool-release from the store-drop choke → `:rxp-returned` fails with *in-use 64, high-water 64*
  (the pool never recovers a buffer);
- set the acquired buffer's capacity to the carve size instead of the payload length → `:rxp-normalized` fails;
- present the full extent instead of a truncated one → `:rxp-truncation-bounded` fails, which is what proves
  that assertion is not vacuous.

That middle probe also **corrected a claim I had written into the test**: the field-value check does *not*
catch a wrong extent, because a well-formed payload deserializes correctly even with an over-long one (the
decoder simply stops reading). The security property needed its own assertion — a complete payload written
into a pooled buffer and then presented with a **truncated** extent must be refused at the bounds rather than
completed from the recycled bytes beyond it.
