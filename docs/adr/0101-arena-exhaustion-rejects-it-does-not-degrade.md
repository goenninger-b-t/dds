# ADR 0101 — Arena exhaustion REJECTS; it does not degrade to an allocating fallback

- **Status:** **Accepted (owner ruling) — IMPLEMENTED, all four slices**
- **Date:** 2026-07-31
- **Requirements at stake:** **NFR-MEM** (the operating contract §4: *"Arena exhaustion → RESOURCE_LIMITS
  (reject/backpressure), never a silent GC-heap fallback"*), **FR-PF-7** (all hot-path memory from the
  arena), **NFR-DET**.
- **Relates to:** ADR 0095 slice 4 (which this closes), ADR 0064 (exhaustion is a status, not a condition),
  ADR 0078 / ADR 0085 (the RX store pool and its kill-switch), ADR 0031, ADR 0051.
- **Supersedes:** the per-pool "allocating fallback" policy documented in ten `%ensure-*-pool` docstrings.

> **Owner ruling, 2026-07-31:** *"We do as the contract says — that is why it is a contract after all!"*

---

## 1. The divergence

ADR 0095 slice 4 said `*static-arena-bytes*` becomes a real ceiling and *"the engine maps it to
RESOURCE_LIMITS"*. The code does something else: **every pool that fails to carve degrades to an allocating
fallback**, each defended in its own docstring as *"correct, byte-identical wire, never a per-datagram GC on
the pooled path"*.

The contract is not ambiguous, and the ruling settles the reading: **exhaustion is a reject, not a
downgrade.** A guarantee that silently stops holding under pressure is not a guarantee — it is a default.

## 2. What "fallback" actually means here — two different violations

The word covered two different things, and separating them is what makes the work tractable:

| fallback | backing | violates |
|---|---|---|
| `make-octet-buffer` | `dds.pal:alloc-static` — **off-heap** | FR-PF-7's budget (it is outside `*static-arena-bytes*`), **not** the GC-heap clause |
| `make-array` / `subseq` / `encode-serialized-payload` | **GC heap** | the contract's explicit prohibition, *and* the 0-B property |

The GC-heap set is the flagrant one: under exhaustion the steady state starts consing per sample, which is
precisely the property the whole 16-slice allocation campaign exists to hold. The off-heap set is subtler —
it keeps 0 B/sample but silently spends memory the budget was supposed to bound, so a process configured with
a 64 MiB ceiling can quietly exceed it.

**Both are rejects under the ruling.** The strict reading of the contract sentence is that *arena exhaustion*
maps to RESOURCE_LIMITS; "never a silent GC-heap fallback" is the emphasis, not the whole rule.

## 3. What "reject" means per path — this is the part that needs stating

"Reject" is not one behaviour, and getting it wrong per direction would be worse than the fallback:

- **Publish / TX.** Return **RESOURCE_LIMITS** to the caller. `publish-sample` already does exactly this for
  the secured payload pool (`:timeout`), so the shape is established and the rest follow it. The application
  learns immediately and can back off — which is the whole point of backpressure.
- **Receive / RX.** There is no caller to reject, so the sample is **dropped and counted**. For RELIABLE that
  *is* backpressure: the sample is not acknowledged, the writer retransmits, and the reader recovers once
  memory frees. For BEST_EFFORT a drop is conformant. Silently heap-allocating instead is the one option
  that hides the condition from both ends.
- **Node creation.** A refused carve for the slice-3 TX scratch must fail participant creation with a status
  rather than quietly reverting to `alloc-static` outside the budget. A process that cannot fit its
  configured budget should learn at init, not at the first sample.

## 4. What this costs, stated plainly

Under memory pressure this stack will now **drop user data where it previously delivered it more slowly**.
That is a real, deliberate product change and the argument against it is not frivolous: a middleware that
keeps working degraded is, for some deployments, better than one that refuses.

The ruling resolves it in favour of the guarantee: the static-memory property is load-bearing for the
determinism this stack sells, and an operator is better served by an immediate, visible RESOURCE_LIMITS than
by a stack that silently changes its performance characteristics under load. **The kill-switches stay** —
`*rx-store-pool-enabled*` and the like — so an operator who wants the old behaviour can still choose it
explicitly, which is the difference between a policy and an accident.

## 5. Staging

Vertical slices, each independently demonstrable, per the operating contract:

1. **The GC-heap set. SHIPPED.** `disc-node-arena-rejects` counts every reject, so "never a *silent*
   fallback" has an observable. Converted: **key-id-RX** (was a heap 4-array), **bracket-RX** (was
   `make-array blen`), **RX-store** (was `make-array plen`).

   **Two distinctions had to be preserved, and both would have caused false-REJECTs if collapsed:**
   - *bracket-RX* — a failed carve and an **oversized bracket** shared one `else` branch. Oversize is a
     legitimate too-big datagram, not a memory condition; it keeps the allocating path. Only pool-NIL rejects.
   - *RX-store* — "wanted but exhausted" versus "never wanted". The ADR 0085 kill-switch being off, or the
     crypto/loan path not using this pool, is an **operator choice**; only `rx-store-carve-failed` rejects.

   The secured decode path already self-caps at the working-set budget and rejects there (SAMPLE_REJECTED),
   so it was left as is.
2. **The off-budget `alloc-static` set. SHIPPED.** `%maybe-wrap-srtps` and `%maybe-wrap-user-submessages`
   returned an off-budget `alloc-static` buffer on a failed carve; both now reject. NIL is already
   `%send-raw-buf`'s fail-closed drop for a *required* wrap, so the reject reuses the established path
   rather than inventing one — and a reliable writer retransmits, making it backpressure rather than loss.

3. **Node creation. SHIPPED.** A refused slice-3 carve now returns `(values NIL :arena-exhausted)` from
   `make-disc-node` instead of reverting to `alloc-static` outside the budget. A process that cannot fit its
   configured arena learns at **init**, not at the first sample. The socket is closed on that path, so a
   refusal leaks no fd.

4. **The end-to-end proof. SHIPPED.** `run-arena-exhaustion-test` now asserts creation is *refused* with
   `:ARENA-EXHAUSTED` under a ceiling that admits no carve, and that the refusal is **repeatable** rather
   than a first-call artefact of a fresh process arena.

Slice 4 of ADR 0095 is closed by this ADR: its test half shipped in `ded9e2d`, and its RESOURCE_LIMITS half
is this document.
