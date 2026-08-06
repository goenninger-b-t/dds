# ADR 0106 — The writer's instance handle is INTERNED per instance, not reallocated per write

- **Status:** Accepted (as-built, §7)
- **Date:** 2026-08-06
- **Requirement:** NFR-MEM (0 bytes/sample steady state), FR-PF-7
- **Contract touched:** `dw-instances`' VALUE shape — internal to `DDS.DCPS`, four call sites
- **Supersedes nothing.** It closes the residue `%write-key-hash`'s own docstring names.

---

## 1. The decision

`%write-key-hash` returns a **stable, per-instance** 16-octet handle instead of a freshly allocated one per
write. The handle is computed into a reusable transient scratch (`dw-keyhash-out`, the writer twin of
`dr-keyhash-out`), used to look up the writer's instance table, and the **stored** handle is returned. A new
instance allocates exactly one handle, once, forever.

This is the TX twin of the indirection the RX drain has used since **ADR 0076**, and it is the fix
`%write-key-hash`'s docstring already names: *"Only the SCRATCH is reusable; closing the remaining 32 B
needs the ADR 0076 stable-handle indirection on the writer side."*

**Measured target: ~32 B/sample** of the ~43 B/sample the keyed write path costs
(`bench/report/2026-08-06-where-the-remaining-224-bytes-live.md`: keyed+reliable 122.3, unkeyed+reliable
79.7, on a no-peer writer).

## 2. Why the handle could not simply be recycled

It is **RETAINED**, on three paths, which is why the current code allocates deliberately rather than
carelessly:

| # | path | retains the handle as |
|---|---|---|
| a | `publish-sample-into` → `writer-write` | the CacheChange's instance handle, for KEEP_LAST per-instance eviction |
| b | `%write-sample-1` | a key in `dw-instances` (EQUALP) |
| c | `%deadline-touch-writer` → `%deadline-arm-or-rearm` | a key in the writer's deadline table |

The campaign's standing rule decides it: **retained ⇒ a write-once CACHE, never a scratch**
([[dds-allocation-campaign-lessons]]). Interning satisfies every retainer because the object handed out is
*immutable and permanent*, not reused. This is ADR 0088's distinction exactly — a memoised invariant is
safe where a shared mutable scratch is a silent mis-attribution.

⚠️ **Today the three retainers each hold a DIFFERENT array with equal contents**, and it works only because
all three lookups are `equalp`. After this change they share one array, which is strictly stronger.

## 3. The mechanism

- `dw-keyhash-out` — a reusable 16-octet result array per writer, guarded by the **existing**
  `dw-keyhash-busy` CAS try-lock that already guards `dw-keyhash-scratch`. A writer that loses the CAS takes
  the allocating path, exactly as today.
- `dw-instances` value becomes a `writer-instance` record with two slots: **`handle`** (the stable array,
  which is also the table's key) and **`key-sample`** (the `get_key_value` key holder, unchanged in meaning).
  CL offers no way to read a hash entry's stored *key* back, which is the whole reason the handle has to
  live in the value.
- `%writer-intern-handle` is the single intern point: `gethash` the transient; on a hit return
  `writer-instance-handle`; on a miss `copy-seq` once, create the record under `dw-status-lock`, return the
  copy.

**Four call sites** move from "the value IS the key sample" to "the value HAS the key sample":
`%write-sample-1`'s first-write record, `register-instance`, `lookup-instance` (presence only — unchanged),
and `get-key-value`.

## 4. The hazard that decides the test

⛔ **THE DEADLINE RETENTION PATH IS CONDITIONAL, AND THAT MAKES IT THE DANGEROUS ONE.**
`%deadline-touch-writer` runs its period check **first** and is a complete no-op under the default
`DURATION_INFINITE` — so path (c) does not retain anything at all in any default configuration. A handle
that was wrongly recycled or wrongly shared would therefore look perfectly correct in every test the suite
has, and would only misbehave once an application configured a finite offered DEADLINE.

**The arm for this ADR must configure a finite DEADLINE and write several instances**, or it is testing two
of the three retainers and claiming three. `%write-key-hash`'s docstring already says this in its own words
(*"the deadline path is the nastiest because it is CONDITIONAL"*); this ADR turns that sentence into a test.

## 5. Scope, and one thing deliberately left

**KEEP_ALL keyed writers are NOT covered and are worse than KEEP_LAST.** `%write-key-hash` is gated on
`%writer-keeplast-p`, so a KEEP_ALL writer gets `NIL` and `%write-sample-1` then computes a handle at the
`dw-instances` site with **no serialization scratch at all** — the full pre-ADR-0087 cost (~112 B/call
measured there). That is a separate, larger finding; it is recorded here rather than fixed, because the fix
is a different change (move the intern to where both paths converge) and it wants its own measurement.

## 6. Verification

- The ~32 B/sample win, measured on the **no-peer writer probe** (seconds per iteration, no discovery, no
  timing): keyed+reliable before vs after.
- `gate-mem` all three columns, unchanged or improved, ratchets re-banked.
- A new arm that (1) configures a **finite offered DEADLINE**, (2) writes several instances repeatedly,
  (3) asserts `get_key_value` still returns the right key holder per instance, `lookup_instance` still
  reports the right presence, and the handles are **`eq` across writes of the same instance** — the property
  that makes the intern observable at all, and the one a "still allocates a fresh one" regression breaks.

---

## 7. As built

**Measured, on the no-peer bisect that located it** (`bench/report/2026-08-06-where-the-remaining-224-bytes-live.md`):

| arm | before | after |
|---|---|---|
| keyed + reliable | 122.3 / 123.4 | **95.0 / 91.7** |
| unkeyed + reliable | 79.7 / 79.7 | 80.8 / 79.7 (unchanged, as predicted — no handle) |
| keyed + best-effort | 111.4 / 112.5 | **79.7 / 80.8** |

**Confirmed end-to-end by `gate-mem`, −32 B/sample on ALL THREE arms** — the same handle, seen three ways:

| arm | arm64 before → after | x86_64 before → after |
|---|---|---|
| COPY | 464 → **431.4** | 496 → **465.1** |
| RETURN | 256 → **221.7** | 307 → **277.0** |
| INTO | 225 → **192.2** | 276 → **244.0** |

Ceilings: arm64 `453 236 203`, x86_64 `490 - 258`.

### ⚠️ A REGRESSION THE EXISTING SUITE CAUGHT, on both SBCL and Linux

`run-keeplast-keyhash-threaded-test` / `KL-UNKEYED-SHARED-NIL` went red immediately: **an unkeyed type's
handle is the SHARED `+instance-handle-nil+` constant**, which `%instance-handle` returns *itself* rather
than building — so the intern's `copy-seq` handed the CacheChange a private all-zero array instead of the
shared one. The intern now `eq`-tests that constant and stores it as-is; everything else arrives in a
transient scratch and must still be copied. Worth recording as a positive: this is one of the few defects
today that the suite *could* already reach, and it reached it on the first run.

### `lookup_instance` now returns the canonical handle

It previously computed a fresh handle and returned that. With a canonical one available it returns the
stored object, so every holder of an instance's handle points at one array (§2.2.2.4.2.5 lets the
application retain what it hands back). That is also what makes the intern observable through the public
API at all.

### The falsification

`run-writer-handle-intern-test` — with `%write-key-hash` handing out `(copy-seq stable)` instead of
`stable`, i.e. exactly the pre-ADR cost, `:whi-interned` goes RED while every value assertion stays green.
That is the whole reason the arm asserts **EQ** and not `equalp`. It configures a **finite offered
DEADLINE**, per §4, so all three retainers are exercised rather than two.
