# ADR 0015 — WP-FLATDATA: FlatData-equivalent binding (FINAL fixed-size v1)

- **Status:** Accepted (2026-06-15); NO_KEY deviation **closed for fixed-size scalar keys** (2026-06-17, WP-KEYED-FLATDATA — see *Keyed FlatData* below)
- **Deciders:** A0 (integrator)
- **Amends:** nothing frozen — purely additive; no existing interface symbol changed
- **Feature:** FR-PF-4 (FlatData publication), FR-TYPE-5 (keyhash), NFR-PERF-7 (fixed-size sample serialize/deserialize ≈ 0)

## R6 — PATENT GATE (defining constraint)

WP-FLATDATA mirrors RTI's patented FlatData mechanism (REQUIREMENTS §NFR-IP, R6).

**Owner ruling: build-now / gate-the-ship, engineering-first.**

- **Per-type opt-in.** A type is FlatData only if annotated `:flatdata t` in `define-dds-type`.
  The default codegen path is untouched; no type is FlatData unless explicitly annotated — this
  IS the "off by default" gate (FlatData is compile-time codegen, not a runtime switch).
- Every WP-FLATDATA file carries the header: `;;;; NOT cleared for ship — pending counsel (R6); see ADR 0015.`
- **Clean-room** from FR-PF-4 + the OMG XCDR spec only — **no RTI source/headers/rtiddsgen output consulted**.
- Engineering-first + provenance: counsel does the authoritative claim clearance before any
  FlatData type ships. This ADR records provenance + design-around notes for counsel.

## Context

WP-ZEROCOPY (ADR 0014) achieves 0-copy transport for large samples: the writer places the
serialized payload in a SHMEM pool slot and sends a 16-byte reference; the reader resolves the
reference and copies the payload into a fresh sink buffer. The bench (Phase E1, ADR 0014) showed
that **the resolve-side sink copy is the remaining allocation hot-spot**: the reader allocates a
slot-sized sink per sample regardless of the actual payload length.

WP-FLATDATA removes that copy. For a FINAL all-fixed-size type the in-memory representation
**equals** the XCDR2 wire bytes (buffer IS SerializedPayload). The type compiler emits **Offset
accessors** — monomorphic functions that read/write each field at a compile-time-constant offset.
The original Phase-D goal was "literal 0 intra-host copies" — the reader reading fields directly
from the writer's SHMEM slot. **Phase D found that a literal-0-copy RX view is NOT safely
achievable in this architecture's best-effort v1** (see *Phase D outcome* below); the delivered,
safe result is the removal of the WP-ZEROCOPY v1 slot-sized **sink + re-copy**, leaving a **single
copy** out of SHMEM into an exact-length owned vector (RX 0-extra-alloc beyond the one payload
vector). The literal-0-copy view is flagged as requiring an engine-contract change.

The authoritative design spec is `docs/superpowers/specs/2026-06-14-wp-flatdata-design.md`.

## Design (v1 — FINAL, all-fixed-size-scalar only)

### Scope

v1 covers **FINAL types whose every member is a fixed-size scalar** (bool, u8/i8/octet,
u16/i16, u32/i32, u64/i64 — no strings, no sequences, no nested/variable members). This is
exactly FR-PF-4 "FINAL FlatData types are restricted to fixed-size members" + NFR-PERF-7
"fixed-size sample". The existing DSL is already FINAL-only; FlatData adds the all-fixed-size
compile-time check.

### Buffer == SerializedPayload

A FlatData type's **sample is a foreign octet buffer** whose layout is:
```
[XCDR2 encapsulation header : 4 octets][PLAIN_CDR2-LE FINAL body]
```
Because the body is a FINAL all-fixed-size struct in PLAIN_CDR2, every field sits at a
**compile-time-constant offset** computed at macroexpansion time from the same
alignment/size rules (`cdr-size-align` + per-member size) the existing `%ssize` uses — but
with all sizes constant the fold is entirely static. The type compiler emits, per field:
- `(<name>-<field>-fd sap)` — getter: read the field at `4 + <body-offset>` via the
  existing `dds.cdr` fixed-offset primitives over a SAP (XCDR2-LE).
- `(setf (<name>-<field>-fd sap) v)` — setter: write the field at the same offset.
- `(make-<name>-flatdata &optional buffer)` — allocate (or wrap) a `+<name>-flatdata-size+`
  foreign buffer, write the XCDR2-LE encapsulation header once with the OPTIONS trailing-pad
  bits set identically to the engine (`finalize-encapsulation-options`), return the buffer.
- `+<name>-flatdata-size+` — the total SerializedPayload size: `4 + <unpadded-body-size>`,
  byte-identical to the engine's `%serialize-sample` output. A FINAL body is **not**
  tail-padded; the trailing pad to the next 4-byte boundary is recorded in the encapsulation
  OPTIONS field (XTypes 1.3 §7.6.3.1.2), not as body octets — so the one valid wire length is
  the last member's end + 4, e.g. `{u32,u8}` -> 9 (not 12), confirmed by the byte-exact oracle.
- A `flatdata-layout` struct `{size, (field . (offset getter setter))}` stored in the
  `type-support` `:flatdata-offset` hook (FR-LANG-3).

`serialize` = identity (the buffer already IS the SerializedPayload; serialized-size =
`+<name>-flatdata-size+`). `deserialize` = wrap the received payload as the sample
(read-in-place, after validating `len >= +<name>-flatdata-size+` and the encap id — `>=`,
not `==`: a conforming trailing-padded peer payload may be longer; reject only if too short to
contain all fields, never false-REJECT a valid sample; see §Safety).
`keyed-p`/key-hash unchanged (keys read via the same fixed offsets).

### DSL extension — compile-time gate (Task A1, this ADR)

`define-dds-type` accepts `:flatdata t` in OPTIONS. After the existing FINAL check, assert
every member is a fixed-size scalar:
```
(when (getf options :flatdata)
  (when (some (lambda (m) (or (getf m :var) (not (eq (getf m :kind) :scalar)))) parsed)
    (error "define-dds-type: :flatdata v1 requires FINAL + fixed-size scalar members ...")))
```
A `:flatdata t` type with a `:string`, `:sequence`, or nested member → compile-time error at
macroexpansion. A `:flatdata t` type with all-fixed-size-scalar members expands as a normal
type in Task A1 (accessors/codegen are Task A2+). The gate is additive; non-FlatData types
are untouched.

### WP-ZEROCOPY read-in-place integration (Task A3 / Phase D)

When a matched type is FlatData, the ZC **writer** stores the FlatData buffer (already the full
SerializedPayload) directly in the pool slot with **no per-field serialize** (the identity
serializer ran once in `%serialize-sample`; the loan is the single app-buffer→slot copy — the
documented v1 TX cost). The ZC **reader** removes the WP-ZEROCOPY v1 **slot-sized sink + re-copy**
and instead reads the slot in place straight into one exact-payload-length owned vector
(`%zc-resolve-fresh` — a single under-mutex copy), then releases the slot immediately — RX
0-extra-alloc, no use-after-free. See *Phase D outcome* for why the slot SAP is **not** handed to
the app directly.

## Phase D outcome (2026-06-15) — literal-0-copy RX deferred; safe single-copy shipped

The Phase-D headline ("the reader reads fields directly from the writer's SHMEM slot, literal 0
intra-host copies") is **not safely achievable in this architecture's best-effort v1.** Four
independent, individually-fatal blockers (each established by reading the source, not assumed):

1. **No SAP→Lisp-array view primitive.** The FlatData Offset accessors read
   `(octet-buffer-vec buf)`, a Lisp `(simple-array (unsigned-byte 8) (*))`. A pool slot is a raw
   `mmap` foreign SAP. There is no PAL primitive to wrap an externally-owned SAP as a Lisp
   `simple-array` (`dds.pal:alloc-static` allocates its *own* static-vector; `static-pointer` is
   array→SAP). So an `octet-buffer` cannot view the slot, and the accessors cannot read it without
   the bytes first living in a Lisp array (a copy).
2. **Async store-then-read with no slot-aware release hook.** `%on-user-data` (receiver thread)
   stores an opaque payload vector and only *wakes* the app; the app reads later on the user thread
   via `%drain`→`%deserialize-sample`, an unbounded time later, through a path that knows nothing of
   slots/refcounts. A stored non-owning view cannot have its lifetime bounded across that read.
3. **Writer force-reclaim overwrites the slot under the reader.** `%zc-take-free-or-reclaim`
   evicts+regenerates the oldest slot on pool pressure; a held non-owning view would read torn /
   foreign bytes (the generation guard *detects* but cannot *prevent* the overwrite of a held view).
4. **The dataplane is type-opaque.** `dds.disc` never sees `type-support-flatdata-offset` (it lives
   in `dds.dcps`, reached only at `%drain`). Even a reduced-copy "resolve directly into the FlatData
   buffer" inside the dataplane store would require threading the DCPS type handle down — an
   engine-contract change, not a dataplane tweak.

Per the operating contract (correctness + stability are **binary gates** overriding the perf goal),
the safe path shipped: **writer** = no double-serialize (already true by construction; asserted in
the test via byte-equality of slot vs published payload); **reader** = `%zc-resolve-fresh` removes
the 65536-byte sink + the second copy, leaving one under-mutex copy into an exact-length owned
vector, slot released immediately (lifetime ends before the app read — no cross-process UAF; copy
clamped to the fixed slot-bytes — no OOB into SHMEM). Measured (`run-flatdata-zerocopy-test` /
`make bench-flatdata`, SBCL): RX **79 bytes/sample** (the one payload vector) vs the WP-ZEROCOPY v1
**65551 bytes/sample** (sink + re-copy) — **~830× less RX allocation**. TX still has the one app→slot copy (the loan-write API
is the follow-up). The literal-0-copy view remains a **follow-up requiring an engine-contract
change**: a ZC-aware, type-aware, refcount-spanning read path (slot delivered as a refcounted loan
held until the app's read completes) **and** a SAP→Lisp-array (or SAP-backed accessor) primitive.

## Final design (as implemented) — the honest as-built (v1, R6 NOT-cleared-for-ship)

> **As-built update (2026-06-17, WP-KEYED-FLATDATA):** the v1 NO_KEY restriction below is **lifted for
> fixed-size scalar `@key` members** — see *Keyed FlatData* near the end of this ADR. The text in this
> section is the original NO_KEY v1 as-built; read it together with that closing section. Variable-size /
> string `@key` members remain a compile-time error (FlatData v1 fixed-size).

WP-FLATDATA v1 ships exactly the following for a `:flatdata t` **FINAL all-fixed-size-scalar** type
(opt-in per type; default codegen untouched). Stated against measurement (FR-LANG-7) — no path is claimed
≈0 unless `dds.pal:bytes-consed` reads ≈0 (`make bench-flatdata`, SBCL, type `fd-abc` = `u8`/`u32`/`u64`,
20-octet payload):

- **Buffer == SerializedPayload, proven byte-exact.** The sample is a foreign octet buffer
  `[4-octet XCDR2-LE encap header][PLAIN_CDR2-LE FINAL body]`; in-memory **is** the wire, byte-identical to
  the engine's `%serialize-sample` (incl. the non-4-aligned tail — a FINAL body is not tail-padded, the pad
  rides the encap OPTIONS field, e.g. `{u32,u8}` → 9 not 12).
- **Compile-time Offset accessors** `<name>-<field>-fd` get/`setf` — raw vec read/write at `4 + offset`,
  **0-alloc** for fixnum-range fields (a `> most-positive-fixnum` u64 boxes a bignum on read — a Lisp cost,
  not a FlatData cost; the read itself is 0-copy).
- **`serialize` = identity** (block-copy the body into the engine's reused TX cursor): **0 GC-heap, 0
  per-field encode** — the genuine TX win (measured 0.0 vs classic 32.1 bytes/op).
- **`deserialize` (engine-visible non-ZC vtable)** = validate (`len >= +size+`, encap id 0x0007) + read-in-place
  into a freshly allocated FlatData buffer: **0 per-field decode but allocates ONE buffer/sample** (~80
  bytes/op, modestly below classic ~128) — **NOT 0-alloc**. The loaned-target inner path
  `deserialize-into-<name>-fd` (the path ZC uses) is **0-alloc** (copy into a caller-owned buffer).
- **FlatData over Zero-Copy (RX)** = a **SAFE SINGLE COPY out of SHMEM**: `%zc-resolve-fresh` reads the slot
  in place into one exact-length owned vector under a single mutex hold (no slot-sized sink, no re-copy),
  releasing the slot before the app's later off-thread read — **~830× less RX allocation** (measured 79
  bytes/sample vs WP-ZEROCOPY-v1's 65551). **This is NOT literal-0-copy.** TX on the ZC path still has the one
  app→slot copy (the loan-write API is the follow-up).
- **NO_KEY in the original v1; keyed (fixed-size scalar `@key`) lifted 2026-06-17** — see *Keyed FlatData*
  below. A variable-size / string `@key` member remains a **compile-time error** (FlatData v1 fixed-size scalar).

**Deferred (follow-ups — stated as not-done at Phase D; item 1 SUBSEQUENTLY DELIVERED, see note):**
1. **Literal-0-copy RX — DELIVERED (WP-FLATDATA-ZC-LOAN, ADR 0017; 0-alloc finish WP-ZC-LOAN-LOCKFREE, ADR
   0018).** The engine-contract change was made exactly as specified: the SAP-backed `-fd` accessor primitive
   + the DCPS-level refcount-spanning, ZC-aware, type-aware read path (the received slot is stored as a
   `zc-loan-marker` ref — not a heap copy — and delivered as a refcounted loan held across the app's read via
   `take-loaned`/`return-loan`). The four Phase-D cross-process-UAF blockers are all resolved (generation-
   guarded slot lifetime; refcount held until `return-loan`; force-reclaim skips refcount>0). The loaned
   FlatData RX path is now 0 intra-host copies AND 0 GC-bytes/sample (measured 65552→79→31→0). The one
   remaining constraint — one loan-capable reader per `disc-node` (ADR 0017 §) — is lifted by the
   N-user-endpoint refactor, not a literal-0-copy gap. Non-FlatData types are inherently bounded out (their
   typed read API returns a deserialized struct = a copy).
2. **The Builder + variable-size FlatData** — strings, sequences, nested/variable members, `@mutable`
   (variable-size / string `@key` members ride this — still deferred).
3. ~~Keyed FlatData (v1 is NO_KEY).~~ **Done for fixed-size scalar keys** (WP-KEYED-FLATDATA, 2026-06-17) —
   see *Keyed FlatData* below.
4. **The app-facing ZC loan-write API** — write directly into a pool slot, removing the TX app→slot copy.

## Memory / hot-path

FlatData buffers are foreign/static (a pool/arena, NFR-MEM). Offset accessors are raw SAP
read/write at fixed offsets — no per-sample CLOS dispatch, no consing, **0 per-field**
serialize/deserialize work (NFR-PERF-7). As-built (see *Final design* above): TX serialize is 0-alloc
identity; the engine-visible non-ZC `deserialize` and the ZC RX each do ONE buffer copy (0 per-field
decode, not 0-alloc). `gate-hotpath` covers the accessor + ZC read-in-place path.

## Safety

A received FlatData payload is untrusted: before wrapping it, validate the available payload
length is `>= +<name>-flatdata-size+` — **NOT `==`** — and the encapsulation id is the expected
XCDR2-LE (`PLAIN_CDR2_LE`, 0x0007). The length check is `>=`, not `==`, to be false-REJECT-safe
(the no-false-REJECT rule, owner directive): a conforming or trailing-padded peer payload may be
LONGER than this type's minimal serialized size, and rejecting it would be a false REJECT (the
worst class); reject only if the payload is too SHORT to contain every field, which is the case
that would risk an OOB accessor read. A violation → reject (signal, surfaced as SAMPLE_REJECTED /
drop by the engine), never an OOB access (NFR-SEC-POSTURE); bounds-checked even at `(safety 0)`.
Offset accessors are bounds-safe by the fixed size. The wrap/accessor path is fuzzed.

**ZC-clamp trust boundary (trusted-header-geometry assumption).** On the FlatData-over-ZC RX path the resolve
copy is clamped to the slot's recorded length and to the per-slot capacity (`min(recorded-len, slot-bytes)`,
`%zc-slot-payload-len`). That `slot-bytes` bound is read from the **pool-header** `slot-bytes` field
(`%zc-slot-bytes`), which lives in the **cross-process-writable** SHMEM segment — so a co-located *malicious*
process could inflate the header `slot-bytes` past the locally-mapped segment and turn the clamp into an
**over-READ** of adjacent mapped memory. The owned-destination sizing prevents the over-**WRITE** (the copy is
additionally clamped to room in the reader's own vector). This is the **pre-existing WP-ZEROCOPY v1 trust model
— not a Phase-D regression**: the pool geometry (slot count / slot-bytes) is *trusted header state*, exactly as
WP-ZEROCOPY already sizes the reader's attach from the **shared constants, not the wire value** (ADR 0014). It
is acceptable for v1 because the feature is `*zerocopy-enabled*`-OFF by default **and NOT cleared for ship
(R6)**; hardening the header geometry against a hostile co-located writer (or sizing every clamp from
process-local constants) is part of the security pass that must precede any ZC-on ship.

## Consumers (as built / planned)

- `src/dds-gen/dsl.lisp` — `define-dds-type` `:flatdata` option + compile-time gate (Task A1)
- `src/dds-gen/dsl.lisp` — FlatData Offset accessor + layout codegen (Task A2)
- `src/dds-gen/dsl.lisp` — type-support vtable swap: serialize=identity (block-copy the FlatData body, no
  per-field encode) / deserialize=read-in-place (validate + body copy into a fresh-or-loaned FlatData buffer,
  no per-field decode) / constant serialized-size; the engine hot path is unchanged (it funcalls the vtable —
  FlatData only swaps the pointers); keyed via `key-hash-<name>-fd` (the buffer-reading keyhash, *Keyed
  FlatData* below; original v1 was NO_KEY because the struct keyhash cannot read the buffer);
  0 GC-alloc/sample proven via `dds.pal:bytes-consed` (Task C1, NFR-PERF-7)
- `src/dds-xport/zerocopy-pool.lisp` — `%zc-resolve-fresh` / `%zc-resolve-into` / `%zc-slot-payload-len`:
  the single-copy ZC RX resolve (reads the slot in place into one exact-length owned vector; no slot-sized
  sink + re-copy) (Task A3 / Phase D)
- `src/dds-disc/dataplane.lisp` — `%zc-try-resolve` read-then-release (single copy, slot released before the
  app read) + the FlatData-over-ZC no-double-serialize writer contract on `%zc-ref-builder` (Phase D)
- `src/dds-tests/integration-test.lisp` — `run-flatdata-zerocopy-test` (round-trip via Offset accessors +
  honest RX bytes/sample measurement) (Phase D)
- The **literal 0-copy SAP view with refcount lifetime is deferred** (engine-contract change — see
  *Phase D outcome*) — **SUBSEQUENTLY DELIVERED: WP-FLATDATA-ZC-LOAN (ADR 0017) + WP-ZC-LOAN-LOCKFREE (ADR
  0018), 0 GC-bytes/sample on the loaned FlatData RX path;** the non-ZC RX path still copies once because the
  engine frees the RX buffer after delivery (inherent to the non-loan / non-FlatData read)

## Provenance

Implemented clean-room from FR-PF-4 + OMG XCDR 1.3 spec; no RTI source, headers, or
`rtiddsgen` output consulted. The buffer-equals-payload identity, compile-time offset
computation, and Offset accessor pattern are this project's own design derived from first
principles and the OMG XCDR fixed-size layout rules. Provenance logged in `docs/provenance.md`.

**NOT cleared for ship — pending counsel (R6).**

## Out of scope (v1)

The Builder for variable-size/mutable types; strings/sequences/nested-variable FlatData; the
app-facing WP-ZEROCOPY loan-write API (write directly into a pool slot — the natural WP-FLATDATA
+ WP-ZEROCOPY pairing); cross-vendor FlatData interop beyond XCDR2 byte-equivalence.

## Consequences

- `define-dds-type` gains the `:flatdata` option; a `:flatdata t` type with a variable or
  non-scalar member is a macroexpansion-time error (additive, non-breaking).
- No existing behaviour changed; non-FlatData types are byte-identical.
- `docs/verification.csv` FR-PF-4 row: open until Task A2 byte-exact + Task A3 ZC integration pass.
- No migration burden: purely additive.

## Keyed FlatData — closing the NO_KEY deviation (2026-06-17, WP-KEYED-FLATDATA, FR-PF-4 + FR-TYPE-5)

The v1 NO_KEY restriction (above) was a **documented deviation**: a `:flatdata t` type could not carry
`@key` members because the spec keyhash `key-hash-<name>` reads a *struct* sample via slot accessors, and a
FlatData sample has **no struct** — it is the octet buffer. WP-KEYED-FLATDATA removes that deviation for
**fixed-size scalar `@key` members** (the second half of queue #3; the same R6 gate as the rest of the
FlatData/Zero-Copy line — `:flatdata t` opt-in + `dds.disc:*zerocopy-enabled*` for the loan path;
**NOT cleared for ship — pending counsel (R6)**).

**The linchpin — `key-hash-<name>-fd`, a buffer-reading keyhash.** For a keyed FlatData type the type
compiler now emits `key-hash-<name>-fd (sample)` where `sample` is the FlatData octet-buffer **or** a
`flatdata-view`. It reuses the struct keyhash's exact serialization (the per-member `:put` codecs to a
**big-endian** XCDR2 cursor, the ≤16-direct-zero-padded / >16-MD5 rule per **RTPS 2.5 §9.6.4.8**), sourcing
each `@key` value from the existing `<name>-<field>-fd` accessor (LE, in place, dual-dispatching
owned-buffer vs view) instead of the struct slot accessor. Result: **byte-identical** to the struct keyhash
for the same key values — so a keyed FlatData instance's identity equals what a non-FlatData peer computes
(the conformance crux; oracle = a pinned BE vector + the struct cross-check, both the ≤16 and >16-MD5 paths;
test `keyed-flatdata-keyhash`). One function serves the write/wire path (owned buffer) **and** the loan path
(view); there is no struct case.

**What follows once the keyhash is wired into `type-support`** (`:keyed-p t` + `:key-hash #'key-hash-<name>-fd`):
- **Real per-key loan handle.** `%loan-instance-handle` returns the keyhash of the loaned view for a keyed
  type (replacing the synthetic SN+GUID fold used for NO_KEY) — two samples of different keys get distinct
  handles, two of the same key get the same handle (test `keyed-flatdata-loan-handle`).
- **Loan-path per-instance KEEP_LAST drop.** `%drain-one-loan` now applies `%reader-keeplast-drop-oldest`
  per instance, closing the WP-KEEPLAST loan-path follow-up gap (DDS 1.4 §2.2.3.18; test
  `keyed-flatdata-loan-keeplast`). For NO_KEY FlatData the per-(GUID,SN)-unique handle means the cap never
  fires — behaviour unchanged.
- **Copy-path keyed behavior (≈free).** A keyed FlatData reader without ZC gets a real per-key
  `instance-handle`, NEW/NOT_NEW view-state, instance-recs, and per-instance KEEP_LAST — the existing keyed
  machinery lit by the keyhash wiring, no new code (test `keyed-flatdata-copy-behavior`).
- **Dispose/unregister by sample.** A keyed FlatData app passes the FlatData buffer to dispose/unregister;
  `%resolve-handle` → `%instance-handle` → `key-hash-<name>-fd` reads the buffer; a matched reader sees
  NOT_ALIVE_DISPOSED for that instance (DDS 1.4 §2.2.2.5; test `keyed-flatdata-dispose`).

**Residual limitation (still deferred — FlatData fixed-size).** A variable-size / string `@key` member is
**still a compile-time error** (the FlatData v1 FINAL fixed-size-scalar restriction is intact; variable-size
keys ride the Builder follow-up). The keyhash, the loan path, the copy path, and dispose/unregister are
validated by internal tests (231 green SBCL+Clasp; the SBCL-only ZC loan tests pass-skip on Clasp).

**Pending final gate — cross-DDS interop (F1, owner directive 2026-06-17).** Per the new per-feature DoD,
the keyhash byte-exactness and keyed instance identity must be **confirmed on the wire against RTI Connext +
Fast DDS** (a keyed FlatData instance matching/disposing against a foreign keyed peer). That cross-DDS interop
verification is tracked as the **F1 final gate and is PENDING** — internal byte-exactness vs the spec rule and
vs our own struct keyhash is proven; live-peer confirmation is the remaining step before this row is fully closed.

**NOT cleared for ship — pending counsel (R6); see the R6 — PATENT GATE section above.**

## FlatData reader transcodes a foreign representation — closing the forward-leg false-REJECT (2026-06-17, WP-FLATDATA-XCDR-TRANSCODE, FR-PF-4 + DDS-XTypes 1.3 §7.6.3.1.2)

The original v1 (and WP-KEYED-FLATDATA) FlatData reader read **only** `PLAIN_CDR2_LE` (0x0007), its
canonical buffer representation, and **rejected** any other RTPS encapsulation id (false-REJECT-safe —
it dropped, never mis-read). WP-KEYED-FLATDATA's cross-DDS interop surfaced that this was a real
forward-leg gap: a conformant RTI Connext / Fast DDS peer defaults to **XCDR1** (the wire showed
`PLAIN_CDR_LE` 0x0001), so a foreign publisher → our `:flatdata t` subscriber matched but every sample
was rejected. WP-FLATDATA-XCDR-TRANSCODE **closes that false-REJECT** — the forward-leg limitation
this ADR's *Keyed FlatData* / *Out of scope* lines flagged is now resolved.

**As-built — decode-then-reserialize via the sibling struct codec (no new codec; DRY).** In
`deserialize-into-<name>-fd` the SerializedPayload rep-id (`+representation-ids+`, DDS-XTypes 1.3
§7.6.3.1.2 — read from the table, never hardcoded) selects the path:
- `0x0007` PLAIN_CDR2_LE → **native read-in-place** (0-copy/0-alloc) — UNCHANGED, the canonical path.
- `0x0000` PLAIN_CDR_BE / `0x0001` PLAIN_CDR_LE / `0x0006` PLAIN_CDR2_BE → **transcode**: decode the body
  via the type's sibling `deserialize-<name>` struct codec (mode `:xcdr1`/`:xcdr2` + the cursor endianness
  from the rep-id — both already implemented), then **re-serialize that struct XCDR2-LE** into the
  reader's canonical FlatData buffer via the existing serializer. The result is the canonical XCDR2-LE
  buffer the `<name>-<field>-fd` accessors + `key-hash-<name>-fd` read — so keyhash / per-key instance /
  view-state / KEEP_LAST compose identically to a native sample (the transcode runs BEFORE the keyhash
  derivation).
- PL_CDR(2) / DELIMITED_CDR / XML → the existing clean **reject** (false-REJECT-safe; a FINAL fixed-size
  FlatData type is PLAIN-encapsulated, so these are not expected for it — rejecting is correct).

**Why decode-then-reserialize, not a byte-swap.** XCDR1 caps alignment at 8 and XCDR2 at 4 (DDS-XTypes
1.3 §7.4), so an 8-byte scalar sits at a different offset under the two — the transcode is a **re-align +
byte-swap**, handled naturally by routing through the struct decode + the XCDR2-LE re-serialize. The
foreign payload is **untrusted**: the struct decode bounds-checks every field against the body extent
(even at `(safety 0)` — NFR-SEC-POSTURE), and the re-serialize writes exactly the `+size+` FlatData
layout into the fixed buffer (no overflow); a malformed/short foreign payload → a clean reject, never an
OOB (fuzzed — `make fuzz`, the transcode foreign-rep decode arm).

**Cost / hot-path.** The transcode is the **foreign-representation FALLBACK** (it allocs the decode +
the re-serialize) — **off the measured CDR hot path**; the native 0x0007 path is unchanged, so
`make mem` stays **0.0000** serialize/deserialize/round-trip and **no hot-path number changed → no bench
warranted** (FR-LANG-7). It benefits ALL FlatData types (keyed and unkeyed) — it is a reader
*representation* fix, not keyed-specific.

**Interop result.** The keyed-FlatData cross-DDS interop is now LIVE in **both directions** vs RTI
Connext 7.3.1 + Fast DDS 3.6.1 (the forward leg via the transcode) — see `interop/keyed-flatdata/README.md`
and `docs/verification.csv` (FR-PF-4 row). **Separate follow-up (NOT this WP):** advertising the reader's
accepted reps via `PID_DATA_REPRESENTATION` (0x0073) in SEDP + RxO matching — a general
DATA_REPRESENTATION QoS feature for ALL types that would let a peer PREFER XCDR2 and skip the transcode;
with the transcode the reader reads any standard rep regardless of what is advertised, so the
false-REJECT is closed without it (the advertisement is a perf/signaling optimization).

Clean-room from FR-PF-4 + DDS-XTypes 1.3 §7.6.3.1.2/§7.4 + first principles; no new external source
consulted (provenance: `docs/provenance.md`). **NOT cleared for ship — pending counsel (R6).**
