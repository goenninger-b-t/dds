# WP-FLATDATA-XCDR-TRANSCODE — FlatData reader transcodes a foreign representation → XCDR2-LE — design

**Goal (FR-PF-4, DDS-XTypes 1.3 §7.6.3.1.2).** Make a `:flatdata t` reader read a SerializedPayload in ANY
standard representation (XCDR1 BE/LE, XCDR2 BE) by **transcoding** it into the reader's canonical XCDR2-LE
buffer — instead of rejecting a non-`PLAIN_CDR2_LE` (0x0007) payload as it does today. This closes the
forward-leg false-REJECT WP-KEYED-FLATDATA's interop surfaced (a conformant RTI Connext peer defaults to
XCDR1-BE; our FlatData reader rejected it) and completes keyed-FlatData's bidirectional cross-DDS interop.
It is a FlatData-reader **representation** fix — it benefits ALL FlatData types (keyed and unkeyed). The
native XCDR2-LE / our-to-our path stays read-in-place (0-copy/0-alloc); the transcode is the
foreign-representation fallback only.

## R6
FlatData is R6 patent-gated (`:flatdata t`). The transcode is on the FlatData **copy/wire** path (UDP; NOT
the same-host ZC loan path), so it needs no `*zerocopy-enabled*`; both impls (SBCL + Clasp). The new codegen
carries the `NOT cleared for ship — pending counsel (R6); see ADR 0015` marker. Clean-room.

## Grounded current state (file:line — verified)
- `dsl.lisp:413-419` — `deserialize-into-<name>-fd`: a length guard (`avail < +size+` → reject, false-REJECT-safe)
  then an encap guard `(unless (and (= (aref src 0) #x00) (= (aref src 1) #x07)) (error 'cdr-not-implemented …))`
  — rejects any rep-id ≠ `0x0007`. THIS reject is what the transcode replaces (for the transcodable reps).
- `cdr.lisp:10-21` — `+representation-ids+`: `:plain-cdr-be 0x0000` / `:plain-cdr-le 0x0001` (XCDR1),
  `:plain-cdr2-be 0x0006` / `:plain-cdr2-le 0x0007` (XCDR2), plus PL/XML/DELIMITED variants. Our FlatData
  buffer is `:plain-cdr2-le` (0x0007, `dsl.lisp:360`); a Connext XCDR1 peer sends `0x0000`/`0x0001`.
- `dsl.lisp:209-220` — the generated struct codec `deserialize-<name> (cursor &optional (mode :xcdr2))` —
  ALREADY decodes XCDR1 (`mode :xcdr1`) and XCDR2 (`mode :xcdr2`); `primitives.lisp:19-48` `cdr-align` caps
  to `%max-align` (8 for `:xcdr1`, 4 for `:xcdr2`); the cursor is endianness-aware (`message.lisp` sets it
  from the submessage E-flag, and `cursor :endianness` is settable). So an existing path can decode a
  foreign XCDR1-BE / XCDR2-BE payload into the struct. The FlatData type ALSO generates this struct codec
  (the "classic ser/des stay emitted for interop/non-FlatData use").
- `dsl.lisp:87-101` `%flatdata-offsets` caps alignment to 4 (XCDR2); XCDR1 uses uncapped 8 — so XCDR1 and
  XCDR2 byte layouts DIFFER for 8-byte scalars (e.g. `[i8,i64]` = 12 octets XCDR2 vs 16 XCDR1). The transcode
  is therefore a re-align + byte-swap, NOT a pure byte-swap — handled naturally by decode-then-reserialize.
- `PID_DATA_REPRESENTATION` (0x0073) does NOT exist on the wire: the QoS field + RxO check exist
  (`qos.lisp:120-122,187-188`, `statuses.lisp:48`) but nothing is emitted/parsed in SEDP
  (`discovery.lisp:485-553`). (The noted follow-up — see Out of scope.)

## Decisions baked in (brainstorming 2026-06-17 — owner-chosen, confirm at spec review)
1. **Transcode-only, reusing the existing struct codec** (owner chose the transcode over advertising
   XCDR2). Mechanism: decode the foreign body via `deserialize-<name>` (mode + endianness from the rep-id)
   → re-serialize XCDR2-LE into the FlatData buffer via the existing serializer. No new codec; DRY.
2. The native `PLAIN_CDR2_LE` (0x0007) path stays read-in-place (0-copy/0-alloc) — unchanged. The transcode
   is the foreign-representation FALLBACK (it allocs the decode+reserialize — acceptable for interop, off
   the measured hot path).
3. **`PID_DATA_REPRESENTATION` on the wire is a SEPARATE follow-up WP** (a general DATA_REPRESENTATION QoS
   feature for ALL types) — NOT in this WP. With the transcode, the reader reads any rep regardless of what
   is advertised, so the false-REJECT is closed without it; the advertisement is a perf/signaling optimization.
4. R6; both impls (copy/wire path, not ZC).

## Design

### 1. The transcode (RX, in the FlatData deserialize)
In `deserialize-into-<name>-fd` (and/or `fd-des`), when the SerializedPayload rep-id is a TRANSCODABLE
non-canonical representation, decode + re-serialize instead of rejecting:
- `0x0000` PLAIN_CDR_BE  → `deserialize-<name>` with `mode :xcdr1`, cursor endianness `:big`
- `0x0001` PLAIN_CDR_LE  → `deserialize-<name>` with `mode :xcdr1`, cursor endianness `:little`
- `0x0006` PLAIN_CDR2_BE → `deserialize-<name>` with `mode :xcdr2`, cursor endianness `:big`
- `0x0007` PLAIN_CDR2_LE → **native read-in-place** (unchanged, 0-copy)

Decode the body (after the 4-octet encap header) into a `<name>` struct via the sibling struct codec, then
**re-serialize that struct XCDR2-LE** (`mode :xcdr2`, LE) into the target FlatData octet-buffer (the same
`serialize-<name>` / the FlatData identity path the writer uses). The result is the canonical XCDR2-LE
buffer the `<name>-<field>-fd` accessors (and `key-hash-<name>-fd`) read. Map the rep-id via
`+representation-ids+` (cite §7.6.3.1.2; do not hardcode from memory).

### 2. Non-transcodable reps stay rejected (documented)
PL_CDR(2) (`0x0002/0x0003/0x000a/0x000b`), DELIMITED_CDR (`0x0008/0x0009`), XML (`0x0004`) → the existing
reject (false-REJECT-safe). A FINAL fixed-size FlatData type is emitted/received as PLAIN encapsulation (no
DHEADER, no member headers), so these are unexpected for it; rejecting them is correct (not a regression).
Document this scope.

### 3. 0-copy preserved + bounds
The native 0x0007 path is unchanged (read-in-place). The transcode allocs (the struct + the re-serialize)
— the foreign-representation fallback, NOT the measured CDR hot path (`make mem` stays 0.0000). The foreign
payload is UNTRUSTED: the struct decode bounds-checks every field against the body extent (the cursor
already does; verify even at `(safety 0)` — NFR-SEC-POSTURE); the re-serialize writes exactly the `+size+`
FlatData layout into the fixed buffer (no overflow). A malformed/short foreign payload → a clean
reject/error, never OOB.

### 4. Keyhash + keyed behavior compose
After the transcode the buffer is canonical XCDR2-LE, so `key-hash-<name>-fd` + the per-key instance +
view-state + KEEP_LAST all work identically to a native sample (the keyed-FlatData machinery reads the
post-transcode buffer). The transcode runs BEFORE the keyhash/instance derivation in the drain.

## Test scenarios (oracle = the field values + the keyhash + the wire; both impls except the live-peer legs)
1. **Offline transcode unit test** (both impls): hand-build a `KeyedFlat`/fixed-size-scalar payload as
   PLAIN_CDR_BE (0x0000, XCDR1 big-endian, with the XCDR1 8-byte alignment for any i64) → run it through the
   FlatData deserialize → assert the `-fd` accessors read the correct field values AND `key-hash-<name>-fd`
   equals the native keyhash. Repeat for PLAIN_CDR_LE (0x0001) and PLAIN_CDR2_BE (0x0006). Include a type
   with an i64 `@key`/member so the XCDR1↔XCDR2 alignment divergence is exercised (the transcode must
   re-align, not just byte-swap).
2. **Native path unchanged** (regression, both impls): a PLAIN_CDR2_LE (0x0007) payload still reads
   in-place (0-copy); `make mem` 0.0000 unaffected; off/non-FlatData byte-identical.
3. **Non-transcodable rejected** (both impls): a PL_CDR2 / DELIMITED / XML rep-id on a FlatData type → the
   clean reject (unchanged), false-REJECT-safe.
4. **Untrusted foreign payload** (fuzz/bounds, both impls): a short/forged XCDR1-BE payload → a clean
   reject/error, no OOB even at `(safety 0)`; add to the FlatData fuzz arm.
5. **Cross-DDS interop — the FORWARD leg (the per-feature DoD).** Re-run the keyed-FlatData forward leg from
   WP-KEYED-FLATDATA's harness (`interop/keyed-flatdata/`): a Connext publisher (defaulting to XCDR1-BE) →
   our FlatData subscriber now READS the samples via the transcode — matched, correct field values, correct
   per-key instance. Live vs RTI Connext 7.3.1 (attempted in-session). The Fast DDS forward leg handed to
   the owner (their env) with the expected result. Document the result (interop/ + verification.csv).

## Out of scope (follow-ups)
- **`PID_DATA_REPRESENTATION` on the wire** (advertise the reader's accepted reps in SEDP + RxO matching) —
  a general DATA_REPRESENTATION QoS feature for ALL types; makes peers PREFER XCDR2 (skipping the transcode)
  + conformant signaling. Its own WP.
- TX in a non-XCDR2-LE representation (we always send XCDR2-LE; only RX transcodes).
- Variable-size / string / sequence / nested FlatData (still fixed-size scalar v1).
- The Connext forward-leg dispose-by-key over the transcode (verify if cheap; else note).

## Conformance citations
- DDS-XTypes 1.3 §7.6.3.1.2 — RTPS encapsulation identifiers (the rep-id table; PLAIN_CDR(2)_BE/LE).
- DDS-XTypes 1.3 §7.4 — XCDR1 vs XCDR2 alignment (the 8-byte vs 4-byte-cap divergence).
- RTPS 2.5 §9.6.4.8 — KeyHash (the post-transcode keyhash equals the native keyhash).
- FR-PF-4 (FlatData); ADR 0015 (FlatData; the NO_KEY deviation already closed by WP-KEYED-FLATDATA).
