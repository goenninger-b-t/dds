# WP-KEYED-FLATDATA — keyed FlatData (lift the NO_KEY restriction) — design

**Goal (FR-PF-4, FR-TYPE-5).** Lift FlatData v1's NO_KEY restriction so a `:flatdata t` type may carry
`@key` members. The linchpin is a **buffer-reading keyhash** (`key-hash-<name>-fd`) that derives the
16-octet instance key hash directly from the FlatData buffer (no struct), byte-identical to the spec
keyhash. Once that keyhash is wired into `type-support`, the rest of keyed behavior follows from the
existing keyed machinery: a **real per-key loan handle** for loaned keyed-FlatData samples (replacing the
synthetic SN+GUID fold), NEW/NOT_NEW view-state + instance-recs, dispose/unregister, and the per-instance
KEEP_LAST drop on the loan path (closing the WP-KEEPLAST follow-up gap). This is queue #3b — the second
half of #3 (per-key / keyed-FlatData); it closes the documented FlatData v1 NO_KEY deviation (ADR 0015).

## R6 — PATENT GATE (same as the FlatData / Zero-Copy line)
Keyed FlatData rides the R6-gated FlatData + Zero-Copy paths: built behind `:flatdata t` + (for the loan
path) `dds.disc:*zerocopy-enabled*` (default OFF) + the `NOT cleared for ship — pending counsel (R6); see
ADR 0015/0017` marker on the new codegen. The copy/wire path (the `-fd` keyhash on an owned buffer) is
both-impl; the loan path is SBCL-only (ZC is an NFR-PORT gap on Clasp). Clean-room from FR-PF-4 + the OMG
keyhash rule (RTPS 2.5 §9.6.4.8) — no RTI source/headers/`rtiddsgen` output.

## Grounded current state (file:line — verified, not from memory)
- `dsl.lisp:~185` — the FlatData branch already enforces FINAL + fixed-size scalar members. `dsl.lisp:189-191`
  — a SEPARATE `keys → error` check rejects ANY `@key` member on a `:flatdata t` type ("NO_KEY only"). This
  is the check to lift; the fixed-size-scalar check already constrains keys.
- `dsl.lisp:257-277` — `key-hash-<name>` (struct keyhash): serializes the `@key` members in member order to
  a **big-endian** XCDR2 cursor (RTPS 2.5 §9.6.4.8), ≤16 → zero-padded direct / >16 → MD5; reads a
  deserialized **struct sample** via the slot accessors. NOT reusable for FlatData (no struct; the values
  live in the LE buffer).
- `dsl.lisp:294-312` — `<name>-<field>-fd` accessors read the buffer **XCDR2-LE in place**, dual-dispatching
  an owned octet-buffer vs a `flatdata-view` over a live slot SAP (single predicted branch, 0-alloc). These
  are the value source for `key-hash-<name>-fd`. `%flatdata-offsets` (`dsl.lisp:87-101`) gives the
  compile-time per-member body offsets; the filtered `keys` are available at `define-dds-type` expansion.
- `type-support.lisp:19-46` — `type-support` has `keyed-p` (TopicKind) + `key-hash` (a function slot).
  `dsl.lisp:417-428` sets them: `:keyed-p (and keys t)`, `:key-hash (when keys #'key-hash-<name>)`.
  `entities.lisp:470-475` `%instance-handle (ts sample)` = `(if kh (funcall kh sample) +instance-handle-nil+)`.
- `entities.lisp:936-954` `%loan-instance-handle (ts view sn sguid)` — ignores ts/view, returns the SN
  (low 8) + FNV-1a GUID fold (high 8) synthetic handle; its docstring flags the real per-key keyhash as the
  follow-up. `entities.lisp:976` is the call site in `%drain-one-loan`.
- `entities.lisp:~980` `%drain-one-loan` — a comment notes the per-instance KEEP_LAST drop is SKIPPED on the
  loan path ("revisit for keyed FlatData WP-3b"). The copy path (`%drain-one-sample:~1126`) does
  `(when depth (%reader-keeplast-drop-oldest dr handle depth))` before the cache append.
- `entities.lisp:489-547` — dispose/unregister: `%resolve-handle` passes a pre-computed handle straight
  through (`%handle-p`), else `%instance-handle` computes it from a sample via the type-support keyhash;
  the engine path (`dataplane.lisp:843-866`) takes the 16-octet handle.

## Decisions baked in (brainstorming 2026-06-17 — owner-chosen, confirm at spec review)
1. **Full keyed behavior** (owner-chosen): the keyhash + lift NO_KEY + real per-key loan handle + the
   loan-path per-instance KEEP_LAST drop + dispose/unregister (validated) + view-state/instance-recs
   (≈free via the existing machinery). Not "core only".
2. **Fixed-size scalar `@key` members only** in v1 (variable-size/string keys stay a compile error —
   consistent with FlatData v1's existing fixed-size restriction). Deferred.
3. The `key-hash-<name>-fd` takes the FlatData sample (owned octet-buffer OR `flatdata-view`); the `-fd`
   accessors dual-dispatch, so ONE function serves the write/wire path (owned buffer) AND the loan path
   (view). No struct case (FlatData has no struct representation).
4. R6; loan path SBCL-only; copy/wire path both impls.

## Design

### 1. `key-hash-<name>-fd` — the buffer-reading BE keyhash (the linchpin)
Codegen, for a keyed FlatData type, a `key-hash-<name>-fd (sample)` where `sample` is the FlatData sample
(octet-buffer or `flatdata-view`). It reads each `@key` member's value via the existing `<name>-<field>-fd`
accessor (LE, in place, dual-dispatching buffer/view), serializes the keys **in member order to a
big-endian XCDR2 cursor**, and applies the existing ≤16-direct / >16-MD5 rule — REUSING the
`key-hash-<name>` serialization logic (the `:put` codecs + the buffer + the BE cursor + the MD5 branch),
only changing the value source from struct accessors to the `-fd` accessors. Result: byte-identical to the
struct keyhash for the same key values (the conformance crux). `defun*` + full ftype
`((or octet-buffer flatdata-view) → (simple-array (unsigned-byte 8) (16)))`.

### 2. Lift the NO_KEY restriction + wire type-support
Remove the `keys → error` check (`dsl.lisp:189-191`) for FlatData. The FINAL + fixed-size-scalar check
stays (so a `@key` member that is variable-size / a string / non-scalar still errors — FlatData v1). For a
keyed FlatData type, `define-dds-type` emits `key-hash-<name>-fd` and binds `type-support` `:keyed-p t` +
`:key-hash #'key-hash-<name>-fd`.

### 3. Real per-key loan handle
`%loan-instance-handle (ts view sn sguid)`: when the type is keyed (`(type-support-key-hash ts)` non-NIL),
return `(funcall (type-support-key-hash ts) view)` — the real per-key 16-octet handle read from the loaned
view. When NO_KEY, keep the SN+GUID fold (unchanged). Same 16-octet handle allocation either way — **no
0-alloc regression**: the fold already allocated a 16-octet handle, and `make mem` measures the CDR hot
path, not this DCPS loan-handle. (The keyhash does more compute than the fold — reading the key fields +
BE-serializing — but it is the necessary instance identity for keyed semantics.)

### 4. Close the loan-path per-instance KEEP_LAST drop (the WP-KEEPLAST gap)
In `%drain-one-loan`, after `%loan-instance-handle` returns the now-real per-key handle and before the cache
append, add `(let ((depth (%reader-keeplast-depth dr))) (when depth (%reader-keeplast-drop-oldest dr handle
depth)))` — mirroring the copy path. Remove the "skipped for NO_KEY v1" comment (replace with the as-built
note). For NO_KEY FlatData the handle is still per-(GUID,SN)-unique, so the cap effectively never fires
(one sample per synthetic instance) — unchanged behavior; for keyed FlatData the per-instance drop now
applies correctly.

### 5. Keyed behavior on the copy path (≈free)
No new code: with `:keyed-p t` + the keyhash wired, the reader's existing `%instance-handle ts data` (copy
path, `%drain-one-sample`) returns the real per-key handle for a keyed FlatData sample → NEW/NOT_NEW
view-state, instance-recs, and the WP-KEEPLAST per-instance KEEP_LAST all operate on the correct instance.
Confirmed by a test.

### 6. Dispose/unregister of a keyed FlatData instance
Works via the existing `dispose-instance`/`unregister-instance` → `%resolve-handle` → `%instance-handle` →
`key-hash-<name>-fd` path: a keyed FlatData app passes the FlatData sample (octet-buffer) to dispose; the
keyhash reads the buffer; the engine emits the no-payload dispose/unregister DATA with PID_KEY_HASH. A
pre-computed handle still passes straight through (`%handle-p`). Validated by a test (no new wiring expected;
the test confirms the path).

## The conformance crux (the wire is the oracle)
The `-fd` keyhash MUST be byte-identical to the spec keyhash for the same key values — a keyed FlatData
instance's identity must equal what a non-FlatData peer computes (so dispose/keyed-matching interop). The
mechanism guarantees it: the `-fd` accessor reads the LE buffer into the host value; the BE serialize writes
that host value — the same bytes the struct keyhash produces. Oracle: a byte-exact test asserting
`key-hash-<name>-fd`(buffer) equals (a) a pinned keyhash vector for known key values AND (b) the struct
`key-hash-<name>` for the same values if the FlatData type also generates a struct keyhash (else just the
pinned vector). Both the ≤16-direct and >16-MD5 paths exercised.

## Test scenarios (oracle = byte-exact keyhash + the instance behavior; both impls except the SBCL-only loan path)
1. **Keyed FlatData compiles + keyhash byte-exact.** A `:flatdata t` type with a fixed-size scalar `@key`
   member compiles (NO_KEY error lifted); `key-hash-<name>-fd` over an owned buffer equals the pinned BE
   keyhash vector for known key values (and the struct keyhash if generated). The ≤16 direct path AND a
   >16 (multi-field / wider) key forcing the MD5 path both byte-exact. A variable-size/string `@key` still
   raises the compile error.
2. **Per-key loan handle.** A loan-capable reader of a keyed FlatData type loans two samples of DIFFERENT
   key values → two DISTINCT handles (= their keyhashes); two samples of the SAME key → the SAME handle
   (no SN-fold aliasing). Byte-exact field reads via `-fd` still correct.
3. **Loan-path per-instance KEEP_LAST drop.** A KEEP_LAST depth-2 loan-capable reader of a keyed FlatData
   type; loan 3 samples of instance A + 3 of B → `dr-cache` holds the last 2 of EACH (the loan path now
   applies the drop). NO_KEY FlatData loan path unchanged (regression).
4. **Copy-path keyed behavior.** A keyed FlatData reader (no ZC) gets real per-key instance handles in
   SampleInfo; NEW for a first-seen key, NOT_NEW for a repeat; per-instance KEEP_LAST holds on the copy
   path. (≈free — proves the keyhash wiring lit the existing machinery.)
5. **Dispose/unregister.** A keyed FlatData writer disposes an instance by sample (the buffer) → the
   matched reader sees NOT_ALIVE_DISPOSED for that instance; unregister likewise. The keyhash-from-buffer
   path resolves the handle.
6. **Regression.** NO_KEY FlatData (the shipped v1) byte/behaviour-identical; non-FlatData keyed types
   unchanged; `make mem` 0.0000 unaffected (the `-fd` keyhash is computed only for keyed FlatData, off the
   measured CDR path); `gate-types`/`gate-hotpath`/`fuzz` PASS.

## Out of scope (follow-ups)
- Variable-size / string / sequence `@key` members (FlatData v1 is fixed-size scalar) — needs variable-size
  FlatData first.
- The FlatData Builder; nested / sequence FlatData.
- #4 sender-thread transient-send-error resilience (the other queued M5/P4 WP).

## Conformance citations
- RTPS 2.5 §9.6.4.8 — KeyHash (the 16-octet instance key hash; the keyhash serialization + ≤16/MD5 rule).
- DDS 1.4 §2.2.2.5 — instance lifecycle (NEW/NOT_NEW view-state; NOT_ALIVE_DISPOSED).
- DDS-XTypes 1.3 §7.6.3 — XCDR2 / FlatData FINAL fixed-size layout (the buffer the `-fd` keyhash reads).
- FR-PF-4 (FlatData) + FR-TYPE-5 (keyhash); ADR 0015 (FlatData v1 NO_KEY deviation, now closed).
