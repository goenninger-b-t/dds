# ADR 0111 — Complete the type system first, then put an IDL front-end on it

- **Status:** Proposed
- **Date:** 2026-08-07
- **Requirement:** FR-CDR-1/2 (MUST), FR-TYPE-1/2, FR-TOOL-1, FR-LANG-3; XTypes 1.3 §7.3.1, §7.4.1
- **Supersedes nothing.** Opens the feature-completeness work stream that follows the closed allocation
  campaign (owner directive, 2026-08-07).

---

## 1. Context — the finding that reorders this work

The stated goal was "IDL parser + the missing constructor types", ranked as the largest gap between a
conformant stack and one usable by an existing Connext shop. Auditing the type system to scope that turned
up something more basic:

⛔ **There is no IEEE 754 floating-point support anywhere in the stack.** `dds-cdr` exports
`cdr-put/get-{bool,u8,u16,u32,u64,i8,i16,i32,i64,octet,string,enum,sequence,dheader}` and **no float codec
at all**; a search for `single-float`/`double-float` across `src/` outside the tests finds 22 hits, all of
them QoS durations, content-filter literals, discovery timing and bench arithmetic. `*dds-type-map*` in
`dds-gen/dsl.lisp` has no float entry, so `define-dds-type` cannot even *declare* a float member.

**NeoDDS cannot serialize a `float` or a `double`.** XTypes 1.3 Table 25 lists `float`/`double` as core IDL
primitives; FR-CDR-1 makes the XCDR primitives a MUST. Connext interop was demonstrated on Shapes, whose
members are `string` + three `long` — which is exactly why this never surfaced.

The full inventory of what the type system cannot express:

| missing | XTypes clause |
|---|---|
| **Float32, Float64** | Table 25, Table 31 |
| Float128 (`long double`) | Table 25, Table 31 |
| **Char8 (`char`), Char16 (`wchar`), `wstring`** | Table 25, §7.4.1.1.2 |
| **Arrays** (incl. multi-dimensional) | §7.3.1.6 |
| **Unions** | §7.3.1.11 |
| **Maps** | §7.3.1.9 |
| **Bitmask / bitset** | §7.3.1.8 |
| `typedef` / alias, modules | §7.3.1.5 |

An IDL front-end built on top of this could parse a real `.idl` file and then fail to represent most of it.
**So the type system is completed first, and the front-end lands on a type system that can carry a real
data model.** That is a re-ordering of the approved stream, not a change of destination.

## 2. Decision

### 2.1 The IDL front-end EMITS `define-dds-type`, it does not re-implement code generation

The front-end is a **lexer + parser + a lowering pass that produces `define-dds-enum` /
`define-dds-type` forms**. There is exactly one code generator in this project and it stays that way: every
codec, `serialized-size` path, key-hash and `type-support` continues to come from `dds-gen/dsl.lisp`.

This is the DRY rule applied at subsystem scale, and it has a second payoff: **every type-system slice below
is independently demonstrable through the existing DSL before any IDL syntax exists**, which is what makes
them vertical slices rather than horizontal layers.

### 2.2 Slice order

Each slice is end-to-end: CDR codec → DSL member type → `type-support` → wire → byte-exact corpus vector →
round-trip test, and each is independently demonstrable.

1. **Float32 + Float64.** The P0 hole. Includes the PAL bit-conversion primitives (§2.3).
2. **Char8, Char16, `wstring`.** §7.4.1.1.2: Char8 serializes as-is like Byte; `String<Char8>` is UTF-8
   including the terminating NUL; `String<Char16>` is UTF-16.
3. **Arrays**, fixed-size then multi-dimensional.
4. **Unions** — discriminator + cases; the largest single-slice jump in the DSL's shape.
5. **Maps.**
6. **Bitmask / bitset.**
7. **`typedef`/alias and modules** — naming and scoping, no new wire form.
8. **The IDL front-end**: lexer, parser, lowering. ⚠️ Gated on §4.

### 2.3 Float bit conversion lives in the PAL

Converting a `single-float`/`double-float` to and from its IEEE 754 bit pattern has no portable ANSI CL
spelling that is both correct for denormals/NaN/Inf and fast. Per the operating contract, **no reader
conditional may appear outside `dds-pal/`**, so this becomes four PAL entry points —
`f32-bits` / `f32-from-bits` / `f64-bits` / `f64-from-bits` — with per-implementation native fast paths and
a portable fallback. **No new dependency** (an `ieee-floats` library would otherwise be the obvious reach,
and it is not justified for four functions the PAL already exists to hold).

## 3. ⛔ The constants this slice must not invent

Pinned from **XTypes 1.3 Table 31** (§7.4.1.1.1, version-1 encoding):

| primitive | encoded size | alignment (v1) |
|---|---|---|
| Float32 | 4 | 4 |
| Float64 | 8 | 8 |
| **Float128** | **16** | **8** |
| Char8 | 1 | 1 |
| Char16 | 2 | 2 |

⚠️ **Float128's size and alignment differ** (16 vs 8). That is precisely the class of constant the operating
contract forbids reconstructing from memory.

And the XCDR1/XCDR2 divergence, from §7.4.2:

```
MALIGN(O)            = MIN(O.type.alignment, XCDR.maxalign)
MAXALIGN(VERSION1)   = 8
MAXALIGN(VERSION2)   = 4
```

So **Float64 aligns to 8 under XCDR1 and to 4 under XCDR2** — the same rule Int64/UInt64 already obey.
`cdr-align` already implements this cap, so the float codecs are `(cdr-align c 4|8 mode)` followed by the
byte write; they inherit the divergence rather than restating it.

**Float128 is DEFERRED, with a reason:** Common Lisp has no portable 128-bit float, and both target
implementations map `long-float` to `double-float`. Carrying it would mean an opaque 16-octet value that
cannot be arithmetically used, which is a different feature from "support `long double`". Recorded here so
the omission is a decision rather than an oversight.

## 4. The IDL specification — ACQUIRED 2026-08-07, slice 8 unblocked

XTypes §7.3.1.1.1 does not restate the grammar; it pins the DDS subset **by reference**:

> *"it uses the Extensible DDS Profile (Sub Clause 9.3.2 [IDL]), which is composed of … Core Data Types (7.4.1
> [IDL]), Extended Data Types (7.4.13 [IDL]), Anonymous Types (7.4.14 [IDL]), Annotations (7.4.15 [IDL])"*

**`docs/specs/idl-4.2.pdf` — OMG IDL v4.2, formal/18-01-05 — is now in the repository** (owner, 2026-08-07),
and every clause XTypes references resolves in it with matching titles: 7.4.1 Core Data Types, 7.4.13
Extended Data-Types, 7.4.14 Anonymous Types, 7.4.15 Annotations, 8.3.1/8.3.2/8.3.4/8.3.5 the four annotation
groups, and 9.3.2 Extensible DDS Profile.

The grammar is stated as **679 numbered EBNF productions** (e.g. `(1) <specification> ::= <definition>+`),
so every production the parser implements **cites its number**, exactly as wire constants cite their clause.
A production written from memory is the same defect class as a PID from memory.

⚠️ `docs/specs/idl-4.1.pdf` is **byte-identical to `idl-4.2.pdf`** (same MD5) and its title page reads
*Version 4.2, formal/18-01-05*. It is a **misnamed duplicate, not a second version** — there is no IDL 4.1
in the repo. It should be deleted rather than left to imply a 4.1/4.2 comparison that cannot be made.

The four real `.idl` files in `docs/specs/` remain the **corpus** oracle — `dds_rtf2_dcps.idl` exercises
modules, structs, enums, sequences, typedefs, unions and annotations, so "the parser accepts the OMG's own
IDL" is a checkable acceptance criterion. It is a corpus, not a grammar: it constrains coverage, and the
numbered productions constrain correctness. Both are required.

## 5. Verification

- Per slice: byte-exact corpus vectors in **both endiannesses** and **both encoding versions** (the
  Float64 XCDR1-vs-XCDR2 alignment difference is itself a required vector), round-trip PBT, and the full
  suite on SBCL + Clasp.
- **`gate-mem` on every slice.** Floats are the live NFR-MEM risk: a `double-float` is boxed unless it lives
  in a declared `defstruct` slot and stays in declared-type code. The generated codecs must keep it unboxed,
  and the gate is what proves it.
- `gate-hotpath` (the codecs are hot-path; no CLOS, no per-sample allocation).
- Interop: a float-bearing type exchanged with Connext and Fast DDS, tshark-validated — the wire is the
  oracle, and a float is exactly where an endianness or alignment error hides.
