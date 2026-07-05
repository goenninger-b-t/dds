# ADR 0047 — Multi-ZC-destination refcounting: one shared pool slot across N co-resident ZC destinations

- **Status:** Accepted (WP-ZC-MULTI-DEST-REFCOUNT, 2026-07-05) — **NOT cleared for ship, pending counsel (R6)** (layered on the patent-gated Zero-Copy/FlatData path; ADR 0014/0015/0017/0042/0044).
- **Deciders:** A0 (integrator), A10 (perf/features)
- **WP:** WP-ZC-MULTI-DEST-REFCOUNT (ADR 0042 §Follow-ups, "Multi-ZC-destination refcounting").
- **Requires:** REQUIREMENTS FR-PF-3 (Zero-Copy/SHMEM), FR-PF-4 (FlatData/loan-write), FR-LANG-7 (no perf change without a before/after number), NFR-MEM (static / zero steady-state alloc), NFR-CLOS (hot-path purity), NFR-SEC-POSTURE; the operating contract §4 (correctness/stability binary gates), §6 (bench every hot-path change).
- **Amends / builds on:** ADR 0014 (WP-ZEROCOPY pool), ADR 0018 (lock-free loan), ADR 0042 (FlatData loan-write / the pre-committed armed slot + the send-site lifecycle), ADR 0044 (acked-slot pinning / the TX pin as a second refcount hold). Additive: it adds one pool primitive (`%zc-bump`, of which `%zc-pin` becomes the `delta=1` case) and hoists the send-site loan above the per-group loop — no consumer of an existing symbol changes its contract; a single-ZC-destination or non-ZC write is byte- and refcount-identical to ADR 0042/0044.
- **Resolves:** ADR 0042 §Follow-up "Multi-ZC-destination refcounting".

---

## 1. Context — what this is, and what it is NOT (the honest framing, FR-LANG-7)

This is a **pool-economy OPTIMIZATION, not a Zero-Copy capability gap.** Today, when a writer's sample goes to **≥2 co-resident ZC-capable destinations** (each a separate participant/process on the same host — v1 is one user-reader per participant), it **already** reaches all of them over Zero-Copy — but by taking **N separate pool slots + N app→slot copies**: the first ZC destination claims the pre-committed/armed slot (or takes a fresh loan), and every *other* ZC destination takes its own fresh `%zc-loan` into a separate slot (`dataplane.lisp` `%zc-change-item`, `resolves=1` each). This WP makes all N share **ONE** slot with **refcount = N**, saving **N−1 slots + N−1 copies** and relieving the per-writer 32-slot pool at fan-out.

The payoff materialises **ONLY with ≥2 co-resident ZC participants** — **not** the primary 1:1 same-host case, which is untouched (byte- and refcount-identical). We do not overclaim: the 1:1 path, every non-ZC destination, every retransmit, and every fallback are exactly as before.

## 2. The governing principle — bounded best-effort over an always-correct fallback

Multi-dest sharing is a **BEST-EFFORT optimization layered on top of the always-correct per-destination fresh-loan path** (today's behaviour: each ZC destination its own slot, refcount 1). The per-destination path is **not** removed — it stays the mandatory fallback, taken whenever the shared loan cannot be established safely (see §5). Correctness — **no slot leak, no use-after-free, no double-free** — is a **binary gate**; the slot-economy win is never traded against it. When in doubt, fall back.

## 3. The crux — what N is, and why (leak/UAF exactness)

**N is the count of ZC-ELIGIBLE DESTINATION GROUPS (participant-receivers) that will EMIT a ref for the change — NOT the `%zc-readers` endpoint count.**

A push destination (`%reader-push-targets` group) is one remote participant's unicast `(host . port)`. A DATA submessage with `readerId = ENTITYID_UNKNOWN` sent there is **resolved ONCE** by that participant's single receiver (`%on-user-data` → one `%zc-release`), **regardless of how many co-located ZC reader endpoints** the participant has (the `%zc-ref-builder` docstring warns this explicitly: refcount = the matched-reader *count* would leak the slot when a destination has >1 ZC reader endpoint). Therefore:

- **refcount too HIGH** (e.g. counting endpoints) → the slot never reaches 0 → **LEAK** (never reclaimed until teardown).
- **refcount too LOW** → freed while a receiver still holds a ref → **UAF** (a later loan reuses the slot; the generation guard catches a *reused* slot, but not an in-flight *double-hold underflow*).

So the refcount must be **EXACTLY the number of receivers that each release once**: the number of ZC-eligible groups whose captured unsent set contains the change. A change is **ZC-shareable** iff (the change-level half of the existing `%zc-change-item` gate) it is `:data`, **not** wire-protected (`%zc-payload-wire-protected-p` — the ADR 0036 Carry-10 security gate, unchanged and authoritative), and `payload-len > *zerocopy-min-payload-bytes*`. N counts only the groups that (a) are ZC-eligible (`%zc-readers > 0`) **and** (b) have that change in their captured unsent set — so **divergent late-joiner watermarks are handled exactly** (a change present in only a subset of ZC groups shares with refcount = that subset; a change reaching only one ZC group is N=1 and rides the unchanged per-group path).

## 4. The send-path hoist (the mechanism)

The two push entry points — `%push-data-buf` (sync/async) and `%node-datagram-plan` (flow-paced) — previously looped `(dolist (group (%reader-push-targets node)) …)` capturing each group's unsent set and building its datagram plan **in the same step**, so the ZC loan decision (`%zc-change-item`) was taken **per group**. This WP restructures both to a **capture-all-first** shape:

1. **`%capture-push-groups`** captures **every** group's unsent set ONCE (`writer-capture-unsent` — advancing each reader's unsent-base and acquiring a send-ref, exactly the old per-group semantics, just hoisted ahead of any emit) into a frozen list of `%zc-push-group` bundles (dest, dest-prefix, shmem-dest, `zc-count`, changes).
2. **`%shared-zc-refs`** counts, per ZC-shareable change, the ZC-eligible **emitter groups** over the frozen bundles; for each change reaching **≥2** such groups it establishes ONE shared slot and records `change → (slot . gen)`:
   - **Non-armed (classic ZC) change** — ONE `%zc-loan` with `readers = N` from the change payload (`%ensure-change-payload`; a pinned change resolves on demand, `len = cache-change-payload-len`, T5a-safe).
   - **Armed (loan-write) change** — win the one-shot `writer-zc-claim` (`:armed → :consumed`), then **`%zc-bump` the pre-committed slot's delivery hold from 1 to N** (`delta = N−1`, generation-guarded CAS, the dual of `%zc-release`).
3. Per group, the plan build consults the table via **`%zc-emit-item`**: a ZC-eligible group (`zc-readers > 0`) with a shared entry emits that **same `(slot, gen)`** ref (`%zc-ref-item`); everything else takes the unchanged per-destination `%zc-change-item`. **The ref bytes are byte-identical** to a fresh `%zc-ref-builder` / `%zc-armed-item` emission (`%encode-zc-ref-vec` + `write-data`, the same emitters — only the slot is shared), and `zc-sends` still bumps once per emitted datagram (N ZC groups → N ref datagrams on the wire, unchanged).

**Why the count is exact without a global lock (the stability argument).** The count in step 2 and the emit in step 3 read the **SAME frozen captured sets** produced by step 1 — not a separate re-scan. So `refcount = N` is the exact number of ref-emissions, and each emission is resolved+released once by a distinct participant-receiver, **by construction**. A group appearing/disappearing in the matches table after the capture cannot change the count (the group list was frozen once). No lock beyond the per-capture writer lock is needed; the `writer-zc-claim` one-shot (under the writer lock) serializes the armed claim against any concurrent emit, and `%zc-bump` is an atomic CAS on a slot held at refcount ≥ 1. *(This is a stronger guarantee than the brief's "hold one node-lock across the whole send" sketch — the code takes several short critical sections, not one long hold; capturing-once makes the exactness independent of that.)*

## 5. Refcount accounting and the pin composition

Let N = the ZC-eligible emitter-group count for a change.

| case | raw refcount before | after claim + bump / loan | releases to 0 |
|------|---------------------|---------------------------|---------------|
| non-armed, N≥2 | 0 (fresh) | `%zc-loan readers=N` → **N** | N receiver `%zc-release` |
| armed (unpinned), N≥2 | 1 (delivery) | claim, `%zc-bump +（N−1)` → **N** | N receiver `%zc-release` |
| armed **+ pinned** (ADR 0044), N≥2 | 2 (delivery 1 + pin 1) | claim, `%zc-bump +(N−1)` → **N+1** | N receiver + 1 pin `%zc-release` |
| N=1 (any) | — | unchanged per-group path | as ADR 0042/0044 |

The **TX pin composes additively**: `%zc-bump` raises only the delivery holds (by N−1); the pin remains a distinct +1 hold released at the full-ACK purge (`hc-try-release-pinned`). Whichever of the N+1 releases lands last frees the slot — **either order** (proven by the pin-composition test, both orders). No pin accounting is perturbed.

**Fallback triggers (each yields today's per-destination fresh loan, byte-identical, always correct):**
- **N = 1** — single ZC destination: not shared at all (the per-group path claims/loans exactly as ADR 0042).
- **Lost armed claim** — a concurrent emit already won the one-shot claim → no shared entry; the per-group path serves it.
- **Pool saturation** — `%zc-loan` returns NIL (no free slot) → no entry; each ZC group falls back to its own fresh loan / full payload. Note the shared loan needs only **ONE** free slot (not N), so sharing strictly *relieves* pool pressure — the brief's "N > free slots" worry is inverted by this design; only a fully-saturated pool falls back.
- **Failed bump** — unreachable for a slot held at refcount ≥ 1 (generation-stable); defensively, the claimed hold is `%zc-release`d and the change (now `:consumed`) is served by per-group fresh loans.
- **Wire-protected / non-`:data` / undersized** — never ZC-shareable (`%zc-shareable-change-p`), unchanged.

## 6. The leak/UAF safety argument

- **No leak:** refcount = N = the exact number of ref datagrams emitted for the change; each is resolved+released exactly once by a distinct participant-receiver (readerId-UNKNOWN → one resolve per participant). The N-count and the N emissions are read from the same frozen captured sets, so they cannot disagree.
- **No UAF / no early free:** the slot is held at refcount ≥ 1 until the last of the N (+ pin) releases; `%zc-take-free-or-reclaim` only reclaims refcount==0, so the slot is never reused while a receiver holds it; `%zc-release` is floored (a double-return is a validated no-op) and generation-guarded (a stale/reclaimed ref never decrements a live slot).
- **The armed one-shot** (`writer-zc-claim`, under the writer lock) guarantees the pre-committed slot's ref is emitted for exactly one shared loan; a retransmit of a consumed change never re-emits the slot (falls back to the retained/resolved payload), exactly as ADR 0042.

**Bounded degradation (documented, not a bug — same class as today).** A datagram lost to one of the N groups leaves that group's delivery hold unreleased → the shared slot strands at refcount ≥ 1 (a reliable reader still receives the sample via its NACK'd payload retransmit, but never resolves the shared slot for that SN). This is the **same leak class** as today's single-destination lost-ref (a lost ZC ref strands its one slot until `%zc-take-free-or-reclaim` can reclaim it, i.e. never for that generation — bounded by pool size / node lifetime). Multi-dest does **not worsen** it: today N destinations = N slots (one lost strands one slot); multi-dest = 1 slot (one lost strands one slot). In aggregate multi-dest uses *fewer* slots, so a loss leaves the pool under *less* pressure.

## 7. Consequences

- **Positive:** at fan-out to N co-resident ZC destinations, slots consumed and app→slot copies drop **from N to 1** (measured: `bench/report/2026-07-05-wp-zc-multi-dest.md`, N ∈ {2,4,8} — N−1 slots + N−1 copies saved; the 8 KiB copy-time drops ~N×). The pool primitive is reused (DRY): `%zc-pin` becomes the `delta=1` case of `%zc-bump`; the shared refs reuse `%zc-ref-item` / `%zc-loan readers=N` / `writer-zc-claim`; no parallel refcount path invented.
- **Cost / honest framing:** the pre-scan adds a bounded walk of the already-captured push groups (no per-sample alloc; the shared-ref table is one control-plane hash-table per push pass, off the measured hot-path files) — `make mem` / `gate-hotpath` stay green. The win requires ≥2 co-resident ZC participants; the 1:1 case is unchanged.
- **Wire:** byte-identical on every path — a shared ZC leg emits exactly the `%encode-zc-ref-vec` ref bytes to each destination (the same `(slot, gen)`, just shared), non-ZC groups and the fallback path are untouched, corpora/KATs unchanged.
- **Security:** the `%zc-payload-wire-protected-p` gate (secured/wire-protected writers never ZC) is unchanged and folded into `%zc-shareable-change-p` — multi-dest never shares a slot for a secured writer.
- **Consumers touched:** `dds.xport.zerocopy` (`%zc-bump`, `%zc-pin` delegates); `dds.disc` (`%zc-shareable-change-p`, `%zc-emit-item`, `%zc-push-group`, `%capture-push-groups`, `%shared-loan-for`, `%shared-zc-refs`, the `shared` optional threaded through `%changes-datagram-plan` / `%send-changes-packed`, and the restructured `%push-data-buf` / `%node-datagram-plan`). All additive and behind the ≥2-ZC-group gate — a single-ZC-destination or non-ZC write is byte- and refcount-identical to ADR 0042/0044.

## 8. Follow-ups

- **Pin-release-on-unmatch / lost-datagram slot recovery:** the §6 stranded-hold class (bounded, same as today) is reclaimed only at pool pressure / teardown; a targeted release-on-unmatch (also an ADR 0044 §8 follow-on) would tighten it.
- **Slot-ref-on-retransmit:** re-emitting the slot REF on a retransmit (instead of reading bytes) remains the outstanding ADR 0042/0044 follow-on; multi-dest does not change that path (retransmits pass `zc-readers=0` → payload).
