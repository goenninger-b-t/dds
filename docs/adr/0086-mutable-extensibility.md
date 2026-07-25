# ADR 0086 — MUTABLE extensibility: EMHEADER framing in the generator

- **Status:** PROPOSED (design; implementation is the follow-on work package)
- **Date:** 2026-07-25
- **Requirements:** **FR-TYPE-1 (MUST)** — "Support FINAL / APPENDABLE / MUTABLE extensibility"; **FR-CDR-8 (MUST)** — byte-exact conformance "both endiannesses, all extensibility kinds"
- **Spec:** DDS-XTypes 1.3 §7.4.1.2.1 (parameter ID bitmask), §7.4.3.4.2 (EMHEADER / LC / NEXTINT), §7.4.3.5 rules (21)–(25), Table 34 (reserved PIDs), Table 46 (encapsulation ids) — read from `docs/specs/xtypes-1_3.pdf`
- **Contract touched:** `dds.gen:define-dds-type` accepts `:mutable`; generated codecs gain a member-header framed path. No wire change for existing `:final` / `:appendable` types.

## Context — this is unimplemented, not untested

`src/dds-gen/dsl.lisp:365` rejects it at macroexpansion:

```lisp
(unless (member ext '(:final :appendable))
  (error "define-dds-type: extensibility must be :final or :appendable (got ~s);
          :mutable needs EMHEADER framing and is a later increment" ext))
```

FR-TYPE-1 is a MUST and names all three kinds, so this is an outstanding conformance gap, not a deferred
nicety. It also blocks FR-CDR-8: the byte-exact corpus covers FINAL (`perf-data`, 11 vectors) and
APPENDABLE (`log-event`, 1 vector) and **cannot** cover MUTABLE, so the most intricate encoding in XCDR —
the one with per-member headers, length codes and unknown-member skipping — has never been checked against
an external encoder. `corpus-verify`'s own docstring makes the point: *"an EXTERNAL encoder is the only
thing that can falsify us."*

**The foundation already exists**, which is what makes this bounded:

- `dds.cdr:emheader1-encode` / `emheader1-decode` (`src/dds-cdr/primitives.lisp:371`), already pinned to §7.4.3.4.2.
- Encapsulation ids `PL_CDR_BE/LE` = `0x0002/0x0003` and `PL_CDR2_BE/LE` = `0x000a/0x000b` (`src/dds-cdr/cdr.lisp:13,20`), matching Table 46.

What is missing is the **generator**: emitting the framing, choosing length codes, and skipping unknown
members on decode.

## The encoding, quoted from the spec

**EMHEADER1 (§7.4.3.4.2).** Four bytes, stream endianness:

```
EMHEADER1 = (M_FLAG << 31) + (LC << 28) + (MemberId & 0x0fffffff)
```

`M_FLAG` is 1 iff the member is `must_understand`. `LC` is the 3-bit length code:

| LC | header | serialized member length |
|---|---|---|
| 0 | 4 bytes | 1 byte |
| 1 | 4 bytes | 2 bytes |
| 2 | 4 bytes | 4 bytes |
| 3 | 4 bytes | 8 bytes |
| 4 | 8 bytes (NEXTINT) | NEXTINT |
| 5 | 8 bytes (NEXTINT) | NEXTINT, **and NEXTINT is reused as part of the member** |
| 6 | 8 bytes (NEXTINT) | 4 × NEXTINT, NEXTINT reused |
| 7 | 8 bytes (NEXTINT) | 8 × NEXTINT, NEXTINT reused |

LC 5–7 "cause NEXTINT to be reused also as part of the serialized member… because the serialization of
certain members also starts with an integer length, which would take exactly the same value as NEXTINT."
That is the `XCDR.offset = XCDR.offset-4` in rule (22) — the writer rewinds so the member's own length
prefix *is* the NEXTINT.

**Rules (21)–(22), XCDR2 (`PL_CDR2`):**

```
(21) XCDR[2] << {O : MSTRUCT_TYPE} = XCDR << { DHEADER(O) : UInt32 } << { O.member[i] : MMEMBER }*
(22) XCDR[2] << {M : MMEMBER}      = XCDR << { EMHEADER1(M) : UInt32 }
                                          << IF (LC(M)>=4) { NEXTINT(M) : UInt32 }
                                          << IF (LC(M)>=5) XCDR.offset = XCDR.offset-4
                                          << { M.value : M.value.type }
```

**Rules (23)–(25), XCDR1 (`PL_CDR`)** — a parameter list, terminated by a sentinel, with a per-member
alignment origin reset:

```
(23) XCDR[1] << {O : MSTRUCT_TYPE} = XCDR << { O.member[i] : MMEMBER }*
                                          << { PID_SENTINEL : UInt16 } << { length = 0 : UInt16 }
(24) short form (M.id <= 2^14 and ssize <= 2^16):
     XCDR << ALIGN(4) << { FLAG_I + FLAG_M + M.id : UInt16 } << { M.value.ssize : UInt16 }
          << PUSH( ORIGIN=0 ) << { M.value : M.value.type }
(25) long form:
     XCDR << ALIGN(4) << { FLAG_I + FLAG_M + PID_EXTENDED : UInt16 } << { slength=8 : UInt16 }
          << { M.id : UInt32 } << { M.value.ssize : UInt32 }
          << PUSH( ORIGIN=0 ) << { M.value : M.value.type }
```

`FLAG_IMPL_EXTENSION` is the MSB of the 16-bit PID and **shall be zero** for user-defined types (§7.4.1.2.1:
"implementations of user-defined data types will never set the FLAG_IMPL_EXTENSION bit"). `FLAG_MUST_UNDERSTAND`
is the next bit, set "if and only if the must_understand property of the member… is set to true".
`PID_EXTENDED` = `0x3F01`, and `0x7F01` with must-understand set (§7.4.1.2.1). `PUSH(ORIGIN=0)` is the
XCDR1 per-member alignment reset — the classic PL_CDR behaviour our RTPS ParameterList codec already implements.

## Decisions

1. **Both encodings, both endiannesses.** XCDR2 `PL_CDR2` and XCDR1 `PL_CDR`. A stock foreign reader may
   request either (the DATA_REPRESENTATION RxO lesson of `e3f1803`), so emitting only XCDR2 would silently
   fail to match exactly the peers this exists to interoperate with.
2. **Member ids come from the DSL**, defaulting to declaration order starting at 0, overridable per member
   — the `@id` of FR-TYPE-1. Ids are what MUTABLE means; they must not be positional-by-accident.
3. **Unknown members are SKIPPED on decode, not fatal** — that is the whole point of MUTABLE — *unless*
   `M_FLAG` is set, where an unrecognised member must cause the sample to be discarded (§7.4.1.2.1: the bit
   "indicates whether the parameter, if its ID is not recognized… may be simply ignored or whether it causes
   the entire data sample to be discarded"). Skipping uses the header's own length, so it never needs the
   member's type. A discard is a **status**, never a condition (ADR 0064).
4. **LC selection is a writer choice the spec does not fix, and byte-exactness against Connext therefore
   pins it empirically.** Any LC that encodes the correct length is conformant, so two conformant writers can
   emit different bytes for the same sample. The rule adopted: smallest correct LC — 0–3 for 1/2/4/8-byte
   members, and 5–7 for members whose own serialization begins with a UInt32 length (strings, sequences),
   taking the 4-byte saving the spec describes. **This must be confirmed against a captured Connext payload
   before it is called byte-exact**; if Connext differs, the vector wins and this rule changes, not the vector.
5. **`:mutable` is refused for `:flatdata`**, alongside the existing `:appendable` refusal — FlatData's
   in-memory layout *is* the wire (ADR 0015), and per-member headers destroy the identity block-copy.
6. **Hot-path purity is preserved.** The framing is emitted as monomorphic generated code like the existing
   kinds, no CLOS dispatch and no per-sample allocation (operating contract §4, `gate-hotpath`).

## Validation — the exit gate

- Round-trip and **byte-exact unit vectors** for each LC class, both endiannesses, both encodings.
- **Skip-unknown**: a payload carrying an id we do not know decodes, dropping that member; with `M_FLAG`
  set, the sample is discarded and reported.
- **The exit gate is a live RTI Connext MUTABLE capture** committed to `corpus/xcdr2/`, verified by
  `make corpus`. That gate now *forces* the vector to be wired in: since `d24c318`, an unrecognised vector
  in the corpus directory fails rather than being silently skipped.
- Peer built per the established clean-room pattern (`interop/connext/cdr-capture`): commit the IDL, the
  hand-written driver and the Makefile; `rtiddsgen` output is produced at build time and gitignored
  (`docs/provenance.md` §M4).

## Consequences

- Closes the FR-TYPE-1 MUST and the last dimension of FR-CDR-8.
- Existing `:final` / `:appendable` types are untouched — no wire change, no regeneration.
- MUTABLE is larger on the wire (a header per member) and slower to decode (id dispatch). That is inherent
  to the kind and is the user's choice per type, not a default.

## Alternatives rejected

- **XCDR2 only.** Half the RxO surface; a stock `@final`-era reader requesting XCDR1 would not match.
- **Positional ids.** Would make MUTABLE structurally identical to APPENDABLE and defeat its purpose.
- **Treating an unknown must_understand member as skippable.** Directly contradicts §7.4.1.2.1 and would
  silently deliver a sample the writer said must not be misread.
