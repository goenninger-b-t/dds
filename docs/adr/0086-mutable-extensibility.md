# ADR 0086 — MUTABLE extensibility: EMHEADER framing in the generator

- **Status:** ACCEPTED — implemented, and the exit gate is met: a live RTI Connext 7.3.1 MUTABLE payload
  is committed at `corpus/xcdr2/mutabledata-connext.bin` and our encoder reproduces it **byte for byte**
  (`make corpus`; falsifiable — one flipped sentinel bit turns it red). Both encodings, both
  endiannesses; unit coverage in `make test` gate `gen-mutable`.
- **Date:** 2026-07-25 (design), amended on implementation — see *Amendments* at the end, which correct
  the LC 5–7 reading in the table below, reverse Decision 4, and record the four defects the design
  missed, three of them found only by the captured vector.
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
  in the corpus directory fails rather than being silently skipped. **MET** — `mutabledata-connext.bin`,
  72 octets, PL_CDR/XCDR1, byte-exact; peer in `interop/connext/mutable/`. It corrected three details of
  the encoder that unit tests could not (A5).
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

---

## Amendments (on implementation)

Four things changed once this met the wire. Three are corrections to this ADR; two are defects the
design did not anticipate, recorded here because both were latent traps rather than typos.

### A1. The LC 5–7 table above is ambiguous, and the obvious reading of it is wrong

The table reproduces the spec faithfully — "LC = 5 … serialized member length is **also NEXTINT**" —
and that sentence, taken at face value together with rule (22)'s rewind, is self-contradictory. If the
member both *starts at* the NEXTINT word and *is* NEXTINT octets long, then for a string of L octets
the member occupies 4+L octets while its own leading word holds L. The writer's NEXTINT is overwritten
by a different value and no reader can recover the length.

The consistent reading, and the one implemented in `dds.cdr:lc-member-extent`, is that for LC ≥ 5
**NEXTINT is the member's own leading COUNT and LC gives the element width**. The multipliers are the
tell: "4\*NEXTINT" (LC 6) and "8\*NEXTINT" (LC 7) are only meaningful if NEXTINT counts elements. So
the extent measured from the rewind point is:

| LC | extent from the rewind point |
|---|---|
| 5 | 4 + 1×NEXTINT (octet/char elements — a string, a sequence of octets) |
| 6 | 4 + 4×NEXTINT (4-byte elements) |
| 7 | 4 + 8×NEXTINT (8-byte elements) |

The naive reading is exactly **4 octets short per member**, which does not fail loudly: it
desynchronises the walk so the *next* EMHEADER1 is read out of the middle of the previous member.
These are precisely the codes a foreign writer is most likely to use, since they exist to save 4
octets on length-prefixed members. Pinned by `mutable-lc-extent-table` and `mutable-decodes-lc5`.

### A2. Decision 4 is REVERSED for the encoder: we emit LC 0–4, not 5–7 — and the question turned out
### not to arise against Connext at all

Decision 4 adopted "smallest correct LC", i.e. 5–7 for length-prefixed members, while noting the rule
was unpinned until a Connext capture existed. The encoder instead takes the unambiguous option: LC 0–3
for a fixed-width member, LC 4 for everything else. LC 4 is fully conformant for any member — the spec
frames 5–7 as a saving ("the use of length codes 5 to 7 saves 4 bytes"), never a requirement — and it
keeps our bytes a function of the declared member widths alone. The decoder handles all eight codes
regardless, which is the half interoperability actually depends on.

**The capture now exists** (`corpus/xcdr2/mutabledata-connext.bin`, gated by `make corpus`) and it did
not settle this, because **RTI Connext 7.3.1 does not send `@mutable` as PL_CDR2 at all** — see A5.
There are no length codes in PL_CDR. So the LC choice remains unpinned against Connext, and
`dds.gen::%mutable-lc` remains the single function to change should a PL_CDR2 vector ever say otherwise.

### A5. Connext sends `@mutable` as PL_CDR (XCDR1), and the vector corrected three things

The exit gate was expected to arbitrate a length code. It arbitrated something more basic: for an
`@mutable` type, Connext 7.3.1 stamps the payload **`0x0003` = PL_CDR_LE, encoding version 1** — not the
`0x000b` (PL_CDR2_LE) this stack sends. So the **XCDR1 parameter-list framing of rules (23)–(25) is the
encoding that actually carries MUTABLE to Connext**, and Decision 1's insistence on implementing both
encodings — which could easily have been dropped as gold-plating, since XCDR2 is the default for new
types (FR-CDR-4) — is the only reason this interoperates at all. Had the "or make the type refuse
XCDR1" shortcut been taken, MUTABLE would have shipped unable to talk to the one peer it exists to talk
to, and every local test would still have passed.

The 72-octet vector then falsified three details of the XCDR1 encoder, each hand-derived from the clause
and each looking right:

1. **The declared parameter length is rounded UP to a multiple of 4**, with the pad octets emitted.
   Rules (24)/(25) say `M.value.ssize`, which reads as the exact size; Connext declares 4 for a 2-octet
   `short` and 12 for a 10-octet string. A PL_CDR list *is* the RTPS ParameterList structure (RTPS 2.5
   §9.4.2.11), where lengths are 4-multiples — and this repo's own `dds.rtps.message:write-parameter`
   had always done exactly that for discovery. The generator had reinvented the encoding beside a
   correct implementation of it.
2. **The terminator is `0x7F02`**, PID_LIST_END with FLAG_MUST_UNDERSTAND, not the bare `0x3F02`.
   Table 34 marks PID_LIST_END must-understand and the clause requires writers to set the bit as the
   table says; rule (23) names only "PID_SENTINEL" and mentions no flag. A decoder masks the flags off
   before comparing, so this is invisible to any round-trip test — only an external encoder shows it.
3. Our XCDR1 output is now **byte-identical to Connext's 72 octets**, and the check is falsifiable:
   reverting the sentinel to `0x3F02` alone turns `make corpus` red.

### A6. The live outbound leg found a false-REJECT the vector could not: the member WIRE NAME

A captured vector proves our *encoder* reproduces Connext's octets. It cannot prove Connext's own
DataReader accepts what we write, and those are different claims. Wiring a live `us -> Connext MUTABLE`
leg (`interop/connext/mutable/mutable_sub`) immediately showed the difference: **Connext received zero
samples**, while Connext's own log showed it had matched *us*. A **one-sided match** — our type gate
refusing a conformant peer, visible only as `matched=0` and one line of `INCOMPATIBLE —
legacy-TypeObject assignability`.

Both models turned out identical on extensibility, member ids and member kinds. The difference was a
single character in a **member name**: our TypeObject announced `"t-ns"`, derived from the Lisp slot
`t-ns`, where `MutableData.idl` declares `t_ns`. Assignability matches members by NameHash
(§7.2.4.4.4), the hashes differ, `member-names-ids-consistent-p` fails, and an identical type is
judged inconsistent.

The underlying gap was not MUTABLE-specific and is the more important finding: **`define-dds-type` had
no way to give a member a wire name that differs from its Lisp slot.** IDL uses `_`, Lisp uses `-`, so
*no* type with an underscore in a member name could interoperate with a foreign peer — silently, as a
non-match with no error anywhere. Fixed by a `:name` member option (defaulting to the downcased slot,
duplicates rejected at macroexpansion), which now feeds the TypeObject NameHash and the content-filter
field accessors alike. Regression: `mutable-wire-name-*` in `run-gen-mutable-test`.

Two process points. This is the ADR 0057 shape recurring — a defect that *only* an outbound live leg
can see, because inbound testing exercises the peer's gate rather than ours. And the gate's diagnostic
was too thin to act on: `INCOMPATIBLE` named no failing condition, so it now dumps both models
(extensibility, ids, kinds) when `*type-compat-log*` is set.

The capture tooling had its own defect, worth recording because it would have silently poisoned any
future vector: `corpus-capture` reads the buffer handed to `%deliver-user-sample`, which since the RX
store-copy pool landed is a pooled **slot** rather than the payload — a 72-octet sample was captured as
16 396 octets of payload-plus-slack, and nothing about the file looked wrong. Both capture functions now
disable the pool, by **`setf` rather than `let`**: the receive path runs on the receiver thread, and a
dynamic binding is thread-local, so the obvious `let` leaves the pool on and the capture silently long.

### A3. Parameter id 1 is a MEMBER of a user-defined type, not a list terminator

Rule (23) terminates the XCDR1 parameter list with "PID_SENTINEL", which is not a name Table 34
defines. Table 34 has **PID_LIST_END = 0x3F02**, "indicates the end of the parameter list data
structure", and separately notes that Simple Discovery types "shall be subject to a special
limitation: member ID 1 shall not be used and parameter ID 1 shall terminate the parameter list to
provide backwards compatibility."

Reading that as "accept id 1 as a terminator too, for robustness" is a trap, and the first
implementation fell into it. Member ids default to declaration order, so **id 1 is the second member
of a typical struct**: treating parameter id 1 as end-of-list truncates the parameter walk there and
delivers defaults for every later member — a wrong sample reported as a good one, which is worse than
any reject. The discovery limitation buys the id-1 terminator *by giving up id 1 as a member*, and it
is scoped to the built-in topic types. A user type writes and recognises PID_LIST_END only
(`dds.cdr:pl-end-of-list-p`), and `mutable-xcdr1-id1-is-a-member` is the regression guard.

### A4. The RX path had no PL_CDR arm at all

`%encap->codec` mapped PLAIN_CDR, PLAIN_CDR2 and DELIMITED_CDR and let PL_CDR/PL_CDR2 fall through its
`ecase` — its docstring called that "the correct conservative reject", which it was for exactly as
long as no mutable type could exist. Shipping MUTABLE without this arm would have made the stack
refuse **its own writer's samples**, since `encapsulation-id-for` stamps a mutable payload with
precisely the id that was being refused. A conformance gap in one layer had become a false-REJECT in
another, and nothing connected them: this ADR's own "the foundation already exists" survey listed the
encapsulation ids as present and did not check that anything consumed them on receive.

Two more of the same shape were fixed with it: `serialized-size-<name>` had no mutable arm, so the
payload buffer was sized without the DHEADER or any member header (a buffer overflow on every mutable
write), and `deserialize-into-<name>` fell through to a positional read (garbage on the pooled RX
path). The lesson for the next extensibility-shaped change is that the generator emits **five**
coordinated functions plus an encapsulation id, and a design that verifies one of them verifies
nothing.
