# A `RETURN-FROM` across a lock cost 16 bytes on every call

**NFR-MEM / NFR-PERF-8 · Linux x86_64 (Docker repro image, distro SBCL) · the four DDS-Security zero-alloc
gates, and an in-process variant ladder at 200 000 iterations**

This slice is measured on **Linux x86_64**, not arm64, because the defect does not reproduce on the dev box.
See "why arm64 shows nothing" below — a flat `gate-mem` here is the expected result, not a null result.

## End to end — the four gates that were red

| gate | assertion | before (`main` = `bcfab9f`) | after |
|---|---|---|---|
| `secured-live-zeroalloc` | `LIVE-RX-LOAN-ZERO-DELTA-256` | **+16.2472 B/sample** | **+0.1579** |
| `rtps-protection-zeroalloc` | pooled SRTPS wrap ≈ 0 | **16.38 B/datagram** | **0.00** |
| `user-submessage-protection-zeroalloc` | pooled metadata_protection send wrap ≈ 0 | **16.38 B/datagram** | **pass** |
| `secured-dataplane-mem` | T5 meta-send adds ≈ 0 over plain | **delta 16.3840** | **delta 0.0000** |

Full Linux x86_64 suite: **620 passed / 4 FAILED / 624** → **624 passed / 0 FAILED / 624**.

The `secured-dataplane-mem` per-tier lines are now flat across the board:

```
mem[meta-send ]: plain=0.0000 secured=0.0000 -> delta=0.0000 B/sample
mem[rtps-send ]: plain=0.0000 secured=0.0000 -> delta=0.0000 B/sample
mem[rtps-recv ]: plain=0.0000 secured=0.0000 -> delta=0.0000 B/sample
mem[oauth-send]: plain=0.0000 secured=0.0000 -> delta=0.0000 B/sample
```

## The isolated measurement — a variant ladder, one construct at a time

Seven variants of `(or (disc-node-send-scratch-pool node) <construct>)`, compiled **in the same file, same
package, same compiler policy** as the real function, all in one process at 200 000 iterations, with the real
function as an in-process control:

| variant | B/call |
|---|---|
| v1 slot read only | 0.0000 |
| v2 + untaken `WITH-LOCK` | 0.0000 |
| v3 + untaken `HANDLER-CASE` | 0.0000 |
| v4 + untaken `HANDLER-CASE` containing a `RETURN-FROM` | 0.0000 |
| **v5 the real shape — all three nested** | **16.0563** |
| **v6 the same nesting, `RETURN-FROM` removed** | **0.0000** |
| **v7 the candidate fix (`WHEN`-guarded `SETF`)** | **0.0000** |
| REAL `%ensure-send-scratch-pool` (control, same process) | **16.0563** |

v5 and v6 differ by exactly one token. **No single construct allocates; only the composition does** — which
is why the obvious experiment (test each construct on its own) returns 0.0000 four times and exonerates the
real cause.

## Ruling out the TLAB

16.384 = 65536/4000 exactly — one 64 KiB TLAB refill over the gate's 4000 iterations — so the gate's own
number cannot tell "16 B per call" from "one one-off refill". Sweeping the iteration count separates them: a
per-call cost stays flat, a one-off decays as 1/N.

```
iters=  1000  total=      0  per-call= 0.0000
iters=  4000  total=  65536  per-call=16.3840
iters= 16000  total= 262144  per-call=16.3840
iters= 64000  total=1048576  per-call=16.3840
iters=256000  total=4096000  per-call=16.0000   <- the TRUE per-call cost
```

## And ruling out the crypto

Piece-by-piece inside `%maybe-wrap-srtps`, 200 000 iterations each. The AEAD is free; the whole cost is one
accessor whose steady-state path is a struct-slot read:

```
FULL %maybe-wrap-srtps        16.0563
encode-rtps-message-into       0.0000   <- the AEAD itself
pool acquire+release           0.0000
%with-send-scratch             0.0000
%ensure-send-scratch-pool     15.8925   <- the whole cost
```

## The defect

`dds.pal:with-lock` expands to an `UNWIND-PROTECT`; `HANDLER-CASE` installs a handler closure. On its own
that closure gets dynamic extent and costs nothing. Put a `RETURN-FROM` in the body targeting a block
**outside** the intervening `UNWIND-PROTECT` and the non-local exit has to run through the unwind — the
closure can no longer be stack-allocated. A no-capture SBCL closure on x86_64 is 2 words = **16 bytes**,
built at function entry, so it is charged to **every** call, including every steady-state call that never
enters the branch and never signals.

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

The `RETURN-FROM` was gratuitous: `NIL` propagates out through the enclosing `OR`/`WITH-LOCK`/`OR` chain to
the identical result. The ADR 0064 obligation it discharged (a NIL pool **must** be tested, or the `SETF`
stores an arena the contract says to store only after a successful carve) is unchanged — the guard tests it
without unwinding.

Nine sites, every one on a per-datagram or per-sample path, which is why one construct produced four
independent red gates.

## Why arm64 shows nothing, and why that is not a reason to doubt the fix

macOS/arm64 runs **SBCL 2.6.5**; the repro image runs **SBCL 2.2.9.debian** on x86_64, deliberately the
distro build so it matches CI. **Both architecture and compiler version differ** — four minor releases apart
— so these measurements cannot attribute the split to either. `make gate-mem` on arm64 is therefore expected
to be **unchanged**, and both arm64 ceiling columns in `bench/mem-ceiling.txt` are deliberately **left
alone** — this is not an arm64 allocation slice.

Measured, 3 runs, nothing else on the machine: COPY **559.1 / 560.2 / 560.2** (ceiling 590), RETURN
**352.8 / 351.7 / 350.6** (ceiling 385) — inside the recorded baseline band of 558.0–561.3 and 350.6–352.8.
No arm64 movement, as predicted.

It does not matter for the fix. The construct is removed outright, so the cost is zero on every
implementation and the property stops depending on which compiler happens to notice it.

## Verification

Linux x86_64 **624/624, 0 FAILED** (from 620/4/624). No new compiler warnings: the 4 `undefined variable`
forward references are byte-identical to a stashed-baseline compile of the same two files.
