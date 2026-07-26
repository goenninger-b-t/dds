# NFR-PERF-8 status: where the remaining bytes are, and what stands between them and zero

**Date:** 2026-07-26 · **Requirement:** NFR-MEM (0 B/sample), NFR-PERF-3, NFR-PERF-8 · **ADR:** 0062, 0087, 0088

**The target remains ZERO** (owner directive, 2026-07-26). This report is the honest position statement
that goes with it: what the number is, where it sits, what is mechanically removable, and the one place
where zero is blocked by a *contract* rather than by effort.

## Where the number is

| arch | B/sample | ceiling |
|---|---|---|
| arm64 (Apple silicon, SBCL) | **1742.1** | 1775 |
| x86_64 (Ubuntu 24.04, SBCL) | **1704.5** | 1740 |

From **3560** at the campaign's start: **−51 %** on arm64 over ~14 slices. `gate-mem` (60 000 samples,
the live two-participant DCPS path over SHMEM) is the only oracle; per-site harnesses over-report and are
used for ranking only.

## The phase split (arm64, payload 0)

| phase | ~B/sample | share |
|---|---|---|
| **receiver threads** | **~790** | ~45 % |
| TX (user thread) | ~668 | ~38 % |
| take-hit (the take that returns a sample) | ~291 | ~17 % |
| empty take | 0.0 | 0 % |

## The receiver, decomposed

⚠️ The raw attribution table is **INCLUSIVE of callees** — parents contain children and must not be
summed. `%lane-drain` measures 393.6 B/sample but *calls* `on-datagram`, i.e. the whole receive pipeline,
so it is not an independent target; reading it as one is a mistake this report exists partly to prevent.
Children subtracted, the receiver is **the submessage handlers**:

| handler | own cost |
|---|---|
| `%on-user-acknack` | ~212 (was ~240 before ADR 0088) |
| `%handle-datagram` own | ~153 |
| `%on-user-heartbeat` | ~109 |
| `%on-user-data` own | ~66 |
| `dispatch-message` own | ~22 — nearly pure routing |

**~256 B of the receiver phase is still unattributed.** Measure it before assuming what is in it.

## What stands between the take path and zero — a contract, not effort

The copy path's drain calls `type-support-deserialize`, which allocates a **fresh user struct per sample**
and hands it to the application. With it, `sample-info` (13 slots), the `cached-sample` wrapper and a cons
enter the reader cache. **All four are retained**, because DDS `read` is non-destructive: the application
may hold delivered samples indefinitely (DDS 1.4 §2.2.2.5.3).

**An object whose lifetime the application controls cannot be pooled.** That places a floor of roughly
**200–290 B/sample** — approximately the whole take-hit phase — on the copy path specifically.

This is not a missing optimisation. A `deserialize-into-<name>` variant already exists in the generator
and is deliberately unused here: it needs a pooled target, and a pooled target needs the application to
hand the sample back.

**The stack already reaches literal zero on RX where the contract allows it** — the FlatData/Zero-Copy
loan path measures 0 GC bytes/sample (`65552 → 79 → 31 → 0`, see the DCPS wiki), because there the
application explicitly `return-loan`s. So "zero" is demonstrated; what is open is whether the *copy* path
adopts the same bargain.

**Reaching zero on the measured path therefore requires extending the loan contract to it** — every
`take` returning a pooled sample the app must return. That is an API change, and it activates the five
hazards catalogued in the RX-pooling plan (read/take aliasing; the WaitSet's cross-thread drain; the
instance-rec key sample retained for `get_key_value`; the N≥2-reader shared-store refcount; the KEEP_LAST
loan use-after-free guard). It is a design decision, not a slice.

## Realistic expectation for the grind

Without that contract change, mechanical work (closures, boxing, per-call conses and scratch) plausibly
reaches **~300–400 B/sample**. Basis: fourteen slices took 3560 → 1742 and the wins are shrinking — the
last two were −82 and −28 — because what remains is spread thin across many small sites.

## Two known-unknowns, recorded rather than smoothed over

- **A ~65 KB per-run allocation** inside the measured window, occurring 0–3 times per run, **still
  unexplained**. At 60 000 samples it amortises to ~1 B/sample so it no longer perturbs the gate, but it
  is a real and possibly leaking steady-state allocation that nobody has chased. `65507` is exactly
  `*max-datagram-bytes*`, which is the lead worth following.
- **SBCL boxing is the likeliest hidden constant** across the handler sites — closures, `&rest`, and u64s
  crossing the fixnum boundary. ADR 0088's first cut was exactly this class: a builder closure allocating
  on every call including cache hits, which moved `gate-mem` by +1.6 B — **invisible to every correctness
  test**, because the code was right, the cache hit, and every assertion passed. The optimisation was
  simply absent. That is the standing argument for `gate-mem` being the oracle and a design argument
  never being one.
