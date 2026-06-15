# WP-FLATDATA — FlatData-equivalent binding (FINAL fixed-size v1) — design

> **AFK NOTE (2026-06-14):** Written autonomously while the owner was AFK. Every clarifying decision the
> brainstorming process would normally surface is made here with a defensible default and flagged in
> **§AFK autonomous decisions (review these)**. Per the brainstorming HARD-GATE, **no feature code is written
> until the owner reviews + approves this spec** (and the plan). The plan
> (`docs/superpowers/plans/2026-06-14-wp-flatdata.md`) is provisional, for review alongside this spec.

> **SUPERSEDED IN PART — see ADR 0015 "Phase D outcome".** This spec was written pre-implementation. Phase D
> found that the **literal-0-copy RX** goal below is **NOT safely achievable in this architecture's best-effort
> v1** (a Lisp octet-buffer cannot wrap a raw foreign SAP; the async off-thread read has no slot-aware release
> hook; writer force-reclaim would overwrite a held view — a literal-0-copy SHMEM-slot view would be a
> cross-process use-after-free). The **delivered, as-built** RX is a **SAFE SINGLE COPY out of SHMEM (~830×**
> less RX allocation than the WP-ZEROCOPY-v1 sink+re-copy, measured), **NOT** literal-0-copy; literal-0-copy RX
> is **deferred** (needs an engine-contract change: SAP-backed accessors + a refcount-spanning ZC-aware read
> path). Every "literal 0-copy" / "0 copies" / "≈0 deser" claim below is the original design intent and is
> superseded by the as-built single-copy result — read it as the deferred goal, not a shipped property. The TX
> serialize-is-identity (0 GC-heap, 0 per-field encode) result DID ship as described. v1 is **NO_KEY** only.

**Goal (FR-PF-4, NFR-PERF-7).** For an annotated **FINAL fixed-size** type, the in-memory representation
**equals** the XCDR2 wire bytes, so serialize cost is **zero** (identity TX, as-built): the type compiler emits
**Offset accessors** that read/modify each field in place in a foreign buffer, and the buffer *is* the
SerializedPayload. Composed with WP-ZEROCOPY the original goal was literal **0 intra-host copies** (the reader
reading fields directly from the writer's SHMEM slot) — **SUPERSEDED**: the as-built RX is a safe **single** copy
out of SHMEM (~830× less than the WP-ZEROCOPY-v1 sink+re-copy), removing the WP-ZEROCOPY-v1 slot-sized sink +
re-copy but **not** the one copy; literal-0-copy RX is deferred (see the banner above / ADR 0015 Phase-D outcome).

## R6 — PATENT GATE (same as WP-ZEROCOPY)
FlatData mirrors RTI's patented mechanism (REQUIREMENTS §NFR-IP; R6). **Build-now / gate-the-ship,
engineering-first:** FlatData is **opt-in per type** (the `:flatdata t` annotation — a type is never FlatData
unless annotated, so the default codegen path is unchanged); the FlatData codegen + the ZC read-in-place
path carry the **`NOT cleared for ship — pending counsel (R6); see ADR 0015`** marker; clean-room from
FR-PF-4 + the OMG XCDR spec, no RTI source; counsel does the authoritative claim clearance before ship.

## Scope
- **v1 = FINAL, all-fixed-size-scalar types** (members ∈ bool/u8/i8/octet/u16/i16/u32/i32/u64/i64; NO
  strings, NO sequences, NO variable or nested-variable members). This is exactly FR-PF-4's "FINAL FlatData
  types are restricted to fixed-size members" + NFR-PERF-7's "fixed-size sample". The existing DSL is already
  FINAL-only; FlatData adds the all-fixed-size check.
- **OUT of v1 (follow-ups):** the **Builder** for variable-size/mutable types; strings/sequences/nested-
  variable in FlatData; an app-facing WP-ZEROCOPY loan API that writes a FlatData buffer directly into a pool
  slot (the natural pairing — noted in WP-ZEROCOPY out-of-scope too).

## Architecture
A FlatData type's **sample is a foreign octet buffer** holding the complete SerializedPayload:
`[XCDR2 encapsulation header : 4 octets][fixed-size XCDR2 body]`. Because the body is a FINAL all-fixed-size
struct in PLAIN_CDR2, every field sits at a **compile-time-constant offset** (the same alignment/size rules
the existing `%ssize`/`cdr-size-align` already implement, evaluated at macro-expansion time since all sizes
are constant). The type compiler emits, per field, **Offset accessors** that read/write the field at
`4 + <field-xcdr2-offset>` in the buffer's SAP, plus a constructor that allocates the buffer (from a
foreign pool/arena) and writes the encapsulation header once. `serialize` is **identity** (the buffer already
IS the SerializedPayload — as-built: 0 GC-heap, 0 per-field encode); `deserialize` validates then reads-in-place
into a FlatData sample. *(SUPERSEDED — see ADR 0015 "Phase D outcome": the as-built `deserialize` COPIES the body
into a fresh/loaned buffer, since the engine frees the received RX buffer right after delivery, so a literal
no-copy view of the received buffer would be use-after-free; it is 0-per-field-decode, not 0-copy.)* The engine
hot path is unchanged (it still sees the `type-support` vtable; FlatData just makes `serialize` trivial,
`deserialize` a validate+block-copy, and adds the `flatdata-offset` accessors).

## Components
1. **DSL extension** (`src/dds-gen/dsl.lisp`): `define-dds-type` accepts `:flatdata t` in OPTIONS. For a
   `:flatdata t` type, after the existing checks, assert FINAL + every member fixed-size scalar (else a clear
   compile error: "FlatData v1 requires FINAL + fixed-size scalar members; got <m>"). Compute each member's
   compile-time XCDR2 body offset (fold `cdr-size-align` + size over the members, all constant). Emit:
   - `+<name>-flatdata-size+` — the total SerializedPayload size (4 + aligned body).
   - per field: `(<name>-<field>-fd sap)` getter + `(setf (<name>-<field>-fd sap) v)` setter, reading/writing
     at `4 + offset` via the existing `dds.cdr` fixed-offset primitives / `dds.pal` SAP refs (XCDR2-LE).
   - `(make-<name>-flatdata &optional buffer)` — allocate (or wrap) a `+<name>-flatdata-size+` foreign buffer
     and write the XCDR2-LE encapsulation header; returns the buffer (the sample).
   - a `flatdata-layout` struct `{size, encap-offset=4, (field . (offset getter setter))}` stored in the
     `type-support` `flatdata-offset` hook (FR-LANG-3, already a slot).
2. **type-support wiring**: for a FlatData type, `serialize` = "the buffer is the payload" (identity /
   `serialized-size` = `+<name>-flatdata-size+`); `deserialize` = wrap the received payload as the sample
   (read-in-place). `keyed-p`/key-hash unchanged (keys read via the same fixed offsets).
3. **WP-ZEROCOPY read-in-place integration** (`dds-disc/dataplane.lisp`): when the matched type is FlatData,
   the ZC writer stores the FlatData buffer (already the payload) in the pool slot with **no per-field
   re-serialize** (the identity serializer ran once; the loan is the one app-buffer→slot copy — the documented
   v1 TX cost). *(SUPERSEDED — see ADR 0015 "Phase D outcome": the original goal here — "the ZC reader hands the
   slot SAP directly to the app via the Offset accessors with no copy = literal 0-copy" — is NOT safely
   achievable in v1.)* **As-built:** the ZC reader removes the WP-ZEROCOPY-v1 slot-sized **sink + re-copy** and
   instead reads the slot in place into **one** exact-length owned vector (`%zc-resolve-fresh`, a single
   under-mutex copy), releasing the slot immediately — a **safe single copy out of SHMEM (~830×** less RX
   allocation than the v1 sink+re-copy, measured), **NOT literal-0-copy**. Literal-0-copy RX is deferred (needs
   SAP-backed accessors + a DCPS-level refcount-spanning ZC-aware read path — an engine-contract change).

## Memory / hot-path
FlatData buffers are foreign/static (a pool/arena, NFR-MEM); the Offset accessors are raw SAP read/write +
the fixed-offset cdr primitives — no per-sample CLOS, no consing, **0 per-field serialize/deserialize work**
(NFR-PERF-7). *(As-built note: TX serialize is 0-alloc identity; the engine-visible non-ZC `deserialize` and
the ZC RX each do ONE buffer copy — 0 per-field decode, not 0-alloc — see ADR 0015 Phase-D outcome.)*
gate-hotpath covers the accessor + the ZC read-in-place path.

## Safety
A received FlatData payload is untrusted: before wrapping/reading, validate `len >= +<name>-flatdata-size+`
(>=, not ==: a conforming trailing-padded peer payload may be longer; reject only if too short to contain all
fields — never false-REJECT a valid sample) and the encapsulation id; a mismatch → reject (RxO /
SAMPLE_REJECTED), never an OOB accessor read (NFR-SEC-POSTURE). Offset accessors are bounds-bound by the
fixed size. Fuzz the wrap/accessor path.

## Testing / acceptance
- DSL: a `:flatdata t` FINAL fixed-size type emits accessors + the layout; field offsets match the XCDR2
  wire offsets (byte-exact vs the existing `serialize` of the same type — the FlatData buffer must equal the
  serialized struct, proving in-memory==wire). A `:flatdata t` type with a string/sequence → compile error.
- Round-trip: build via Offset setters → the buffer bytes == the classic `serialize` of an equal struct;
  read via Offset getters == the classic deserialize. **NFR-PERF-7: serialize alloc ≈ 0 (as-built: 0-alloc
  identity TX) + the loaned-target inner RX path 0-alloc; the engine-visible non-ZC `deserialize` allocates one
  buffer/sample (0 per-field decode, NOT 0-alloc)** (alloc-counter + `make bench-flatdata`). *(SUPERSEDED — the
  original blanket "deserialize alloc ≈ 0" is corrected to the per-path as-built; see ADR 0015 Phase-D outcome.)*
- ZC + FlatData end-to-end: a FlatData type over WP-ZEROCOPY → the reader reads the slot in place into one
  owned vector. *(SUPERSEDED — the original "0 copies / bytes drop to ~0" is a **safe single copy**, ~830× less
  RX allocation than the WP-ZEROCOPY-v1 sink+re-copy, **not** literal-0-copy; see ADR 0015 Phase-D outcome.)*
- Fuzz the untrusted-payload wrap (wrong length / bad encap → reject, no OOB). Engine-untouched: non-FlatData
  types are byte-identical (the DSL change is additive, gated on `:flatdata t`).
- Gates green SBCL+Clasp; behind the per-type opt-in; R6 marker throughout.

## AFK autonomous decisions (REVIEW THESE — each is a fork I'd normally ask)
1. **Opt-in via `:flatdata t` in `define-dds-type` OPTIONS** (not a separate macro / not a global flag). A
   type is FlatData only if annotated → the default path is untouched, and R6 "off by default" = "no type is
   FlatData unless you ask". *Alt: a separate `define-flatdata-type` macro.* Chose the option for minimal DSL
   surface + reuse.
2. **The FlatData buffer includes the 4-byte encapsulation header** (the buffer == the full SerializedPayload,
   transmittable/poolable as-is, accessors offset by 4). *Alt: body-only buffer + prepend the header on send.*
   Chose buffer==payload for true zero-copy (no prepend copy).
3. **v1 = FINAL fixed-size scalar only** (no strings/sequences/nested-variable; no Builder). Matches FR-PF-4
   exactly. The Builder + variable-size is the single biggest deferred piece.
4. **Offset accessors as generated functions** `<name>-<field>-fd` (get) / `(setf …)` (set) over a SAP,
   stored in `flatdata-offset`. *Alt: a generic offset-table + a runtime accessor.* Chose generated monomorphic
   fns (FR-LANG-0 no-CLOS hot path).
5. **App API**: the sample is the foreign buffer + the accessors (NOT a Lisp struct). `make-<name>-flatdata`
   allocates from a foreign pool/arena. *Open: the exact pool/arena ownership + free discipline — I'll spec a
   simple arena-backed buffer in the plan; the WP-ZEROCOPY loan-API pairing (write directly into a pool slot)
   is deferred.*
6. **R6 = per-type opt-in annotation** (vs WP-ZEROCOPY's runtime `*zerocopy-enabled*` flag) — FlatData has no
   runtime path to gate (it's compile-time codegen), so the annotation IS the gate; the NOT-cleared-for-ship
   marker rides the codegen + the ZC read-in-place path.

## Out of scope (explicit)
The Builder; variable-size/mutable/string/sequence/nested-variable FlatData; the app-facing ZC loan-write
API; cross-vendor FlatData interop beyond XCDR2 byte-equivalence (the layout IS XCDR2, so a conforming peer
that speaks XCDR2 interops — but the zero-copy *transport* is ours/SHMEM, per WP-ZEROCOPY).
