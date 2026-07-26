# ADR 0088 — the control-path `%source-guid` is lookup-only, and should stop allocating

- **Status:** **Accepted — Option B, owner decision 2026-07-26.** The owner first authorised a PAL contract ADR (Option A); after reading §4/§5 they chose **Option B explicitly on principle — *"I want this fixed by construction"* — independent of the size of the byte win.** That framing is the reason the design below leans on invariants (write-once entries, verified hits) rather than on an audit obligation. Implemented and measured; see §9.
- **Date:** 2026-07-26
- **Requirements:** NFR-MEM (0 bytes/sample), NFR-PERF-3 (the peer GC-tail), NFR-PERF-8
- **Relates to:** ADR 0062 (the allocation campaign — and §6, whose reasoning applies directly here); ADR 0076 (the RX stable-handle precedent); ADR 0087 (the TX twin, landed); ADR 0078 (why a receive-path change is handled carefully); ADR 0041 (PAL atomics)
- **Contract touched:** **Option A widens the `DDS.PAL` contract** (a new *exported* special variable). **Option B touches no contract** — it is internal to `DDS.RTPS.RELIABLE` + `DDS.DISC`. Both require the same prerequisite in `DDS.RTPS.RELIABLE` (§3).

## 1. The measurement

Fresh, arm64, against the live `gate-mem` workload. **A per-call byte cost is meaningless without the
call count** — that is precisely what made the old `:alloc` profile mis-rank this area, so both were
measured.

| | value | method |
|---|---|---|
| `%source-guid` per call | **32.1 B** | isolated, n = 200 000 |
| `%source-guid` calls per sample | **4.40** | `fdefinition`-wrapped counter over a live run (counts the receiver threads) |
| **total** | **≈ 141 B/sample** | ≈ **8 %** of the post-ADR-0087 budget of 1769.8 |

## 2. The finding — ADR 0062's blanket claim is too strong

ADR 0062's table records `%source-guid` as *"**CAUTION: its result IS RETAINED** … so it cannot become a
shared scratch."* That is **true for the data path and false for the control path.**

`get-reader-proxy` (`src/dds-rtps/reliable.lisp:184`) and `%get-writer-proxy` (`:696`) are both

```lisp
(or (gethash k tbl) (setf (gethash k tbl) (make-...)))
```

— they retain the key **only on creation**. Measured over 3000 samples:

| | count | per sample |
|---|---|---|
| `get-reader-proxy` **hits** (pure lookup, GUID is garbage) | **9901** | 3.300 |
| `get-reader-proxy` **creates** (GUID retained as an `equalp` key) | **1** | 0.00033 |

**One retention for the process's lifetime; ~3.3 pure-garbage lookups per sample.** That is the ADR 0076
stable-handle shape exactly.

⚠️ **`dataplane.lisp:3283` is NOT in scope** — its own comment reads *"ONE source GUID: km-resolve +
reliable proxy + the three inner tables + the loan handle"*. It is already single-computed **and**
genuinely retained. The in-scope sites are the control paths: `:3595` (ACKNACK, ~1/sample — the prize),
`:3548` / `:3561` (GAP, rare).

## 3. The prerequisite, common to both options

The retention contract is currently **implicit and undocumented**: the tables silently keep whatever
array the caller passed. Before *any* caller may pass a non-fresh array, creation must store a private
copy:

```lisp
(defun* %retained-proxy-key (key) (function (t) t)
  "KEY, copied if it is a sequence — the private key a proxy table RETAINS. Integers (the value-level
   tests) have nothing to alias and pass through."
  (if (typep key 'sequence) (copy-seq key) key))
```

applied at **both** `get-reader-proxy:191` and `%get-writer-proxy:703`.

**Why it is load-bearing:** without the copy, a reused caller buffer would *be* the live hash key, and the
next datagram would mutate it in place. The proxy then becomes unfindable, a fresh one is created, and the
writer's acked-base silently stops advancing — **no crash, no error, just a reliability protocol that
quietly stops working.** Cost: one `copy-seq` per process lifetime (measured: 1 per 3000 samples).

## 4. The two options

### Option A — a per-thread GUID scratch in the PAL *(what the owner authorised)*

`dds.pal:spawn` already wraps every PAL thread in `call-with-thread-clock`, which carves one 40-octet
foreign block into `*thread-timespec*` / `*thread-atomic-cell*` / `*thread-sockaddr*`. Add a fourth
per-thread scratch for the GUID and **export it**, so `DDS.DISC` can reach it.

It cannot ride the existing block: those are foreign **SAPs**, and an `equalp` hash key must be a **Lisp**
`(simple-array (unsigned-byte 8) (16))`. (No conflict with the static-arena rule — that rule governs
memory addressed by a raw pointer; this array is never SAP-addressed.) So it is a new Lisp binding, a new
exported symbol, and a widening of the PAL contract, which today exports no per-thread scratch at all.

- ✅ Kills the allocation at **every** site, not just memoizable ones. Reuses proven machinery.
- ❌ **Safe only for as long as every consumer copies before retaining.** This is exactly the objection
  ADR 0062 §6 used to *decline* the `%source-prefix` scratch: *"a deferral justified by 'nothing currently
  exercises this path' is only as durable as the reason nothing exercises it."* A future consumer that
  retains the scratch reintroduces the silent-corruption bug, and nothing structural stops it.
- ❌ Non-PAL threads get `NIL` and must fall back — a second path to keep correct.

### Option B — memoise the GUID per endpoint *(recommended)*

The GUID for a given `(src-prefix, entity-id)` pair is **invariant**. Rather than a scratch that is
rewritten per datagram, keep a small per-writer/per-reader memo from a cheap allocation-free **fixnum
fingerprint** of those 16 octets to the **canonical retained GUID** — the very array already stored as the
proxy table's key. On a hit, the caller gets back an array that is *already* the retained key.

⚠️ A fingerprint collision would return the **wrong** GUID → the wrong proxy → silent mis-attribution, the
worst failure class here. So a hit **must be verified** by comparing the 16 octets (allocation-free)
before use; a mismatch falls through to the allocating path. With verification a collision is merely slow,
never wrong.

- ✅ **Retention becomes safe by construction, not by audit.** The value handed out *is* the canonical
  key; a consumer that retains it is correct by definition. This structurally eliminates the hazard class
  Option A only manages — the decisive argument.
- ✅ No contract change; no PAL edit; no per-thread state; no non-PAL-thread fallback path.
- ✅ Benign under concurrency: the mapping is deterministic, so a race between receiver threads at worst
  recomputes and stores an `equalp`-identical array.
- ❌ Reaches only sites that can see the endpoint. Verified: `w` (the local writer) **is** in scope at the
  ACKNACK site `:3595`, which is the ~1/sample prize. The rare GAP sites hold only `node`.
- ❌ Needs a bounded memo (a writer may match many readers) — a small ring or an eviction cap, not an
  unbounded table, or it becomes a remote-drivable growth path.

## 5. Recommendation

**Option B**, with §3 landed first as its own reviewed change. Option A buys the remaining rare sites at
the cost of a permanent, audit-maintained aliasing hazard in the PAL's exported surface; Option B removes
the hazard instead of managing it, and covers the one site that is actually per-sample.

If the owner prefers Option A regardless — it is the authorised route and it does cover more sites — then
§3 is mandatory, not optional, and the ADR 0062 §6 durability objection must be recorded against it
explicitly rather than left implicit.

## 6. Realistic prize, stated honestly

~32 B × the lookup-only calls per sample. Of the 4.40 calls, only the control-path ones qualify, so
**≈ 32–64 B/sample — roughly 2–4 %** of the current 1769.8. Worth doing; **not** worth rushing onto the
receive path, which is where ADR 0078's heap corruption lived. Whichever option is chosen, this lands as
its own slice with its own `gate-mem` before/after, validated on both impls and both platforms, plus
`make interop`.

## 7. Falsification (required before either is believed)

- A test that **holds a proxy across a mutation of the caller's buffer** and asserts the proxy is still
  found — this fails today (pre-§3) and passes after, which is the falsification of §3 itself.
- Option B additionally: a test that **forces a fingerprint collision** and asserts the verification step
  rejects it and still yields the correct proxy.
- `gate-mem` before/after on **both** architectures — arm64 and x86_64 moved by materially different
  amounts on ADR 0087 (−82.4 vs −125.4), so neither may be predicted from the other.

## 9. As built (Option B) — and two things the measurement corrected

**Shipped shape.** `%retained-endpoint-key` (the §3 prerequisite) at both proxy-creation sites;
`writer-lookup-key` + `%guid-names-endpoint-p` + `%build-endpoint-guid` + a `key-cache` slot on
`rtps-writer`; the ACKNACK site in `dataplane.lisp` calls the lookup instead of building a GUID.

**Measured on BOTH architectures** (per §7 — neither may be predicted from the other):

| arch | before | after | delta |
|---|---|---|---|
| arm64 | 1769.8 | **1742.1** | **−27.7** |
| x86_64 | 1777.4 | **1704.5** | **−72.9** |

x86_64 gained ~2.6× more, the same arch divergence as ADR 0065 (−175 vs −708) and ADR 0087 (−82.4 vs
−125.4). Suite **607 passed** (606 + the new test) on SBCL-macOS and SBCL-Linux.

### ⚠️ 9.1 The first cut won NOTHING, and only the byte measurement said so

The miss-path builder was first passed as a **closure**, `(lambda () (%source-guid src-prefix rid))`.
A closure over the prefix and id **allocates on EVERY call — cache hits included** — so the change merely
swapped a 32-octet GUID for a closure of similar size: `gate-mem` moved **+1.6 B, i.e. not at all.**
Passing the *components* and letting the miss path call `%build-endpoint-guid` produced the −27.7.

**No correctness test could have caught this** — the code was right, the cache hit, every assertion
passed, and the optimisation was simply absent. It is the sharpest illustration in this campaign of why
`gate-mem` is the oracle and a design argument is not: the reasoning for the slice was sound and the
first implementation of it still won zero. `%build-endpoint-guid`'s docstring records this so the
callback shape is not reintroduced.

### 9.2 §1's per-call number was inflated — the in-situ cost is lower

§1 reports `%source-guid` at **32.1 B/call** from an isolated harness; measured **in situ** in the live
workload it is **87.5 B/sample across 4.40 calls ≈ 19.9 B/call**. The isolated figure over-reports by
**~1.6×** — the same class of error ADR 0062's own "⚠️ CORRECTION" section records (there, ~3.5×). The
realistic prize in §6 should therefore be read as the lower half of its range, which is what landed.
**Rule reaffirmed: size a candidate in situ, and treat any per-site harness number as an upper bound.**

### 9.3 The receiver-phase ranking, corrected

The attribution table is **INCLUSIVE of callees**, and `%lane-drain` calls `on-datagram` — i.e. the whole
receive pipeline — so its 393.6 B/sample largely *is* `%handle-datagram`, overlapping rather than adding.
Reading it as an independent target is wrong. Subtracting children from parents gives the real ranking of
the 817.8 B/sample receiver phase, which is **the submessage handlers**, led by ACKNACK:

| handler | own cost (excl. children) |
|---|---|
| `%on-user-acknack` | ~240 → **~212** after this ADR |
| `%handle-datagram` own | ~153 |
| `%on-user-heartbeat` | ~109 |
| `%on-user-data` own | ~66 (of 174.8; `%deliver-data-on-readers` is 109.2) |
| `dispatch-message` own | ~22 (nearly pure routing) |

## 8. Also measured while scoping (corrects a stale note)

**The SHMEM premium is now only 66.4 B/sample** (SHMEM 1774.3 vs pure UDP 1708.0 — a free A/B via
`(setf dds.disc:*shmem-enabled* nil)`, set **globally**, never a thread-local `let`). The standing note
recording ~131 B is stale: the `%claim-lane` memoisation already took most of it. **SHMEM is no longer a
top allocation target.**
