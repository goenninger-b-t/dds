# Legacy RTI TypeObject (PID_TYPE_OBJECT_LB / 0x8021) structural parse + fail-open assignability gating

- **Date:** 2026-06-11
- **Status:** Design — approved for planning
- **Area:** L3 type system (a TLV tokenizer + semantic interpreter for RTI's legacy TypeObject), the clean-room capture corpus + diff tool, L6 DCPS (the fail-open legacy-parse gate branch), interop harness
- **Requirements:** FR-TYPE-2/4 (TypeObject parse → assignability), FR-IO-1 (Connext interop), NFR-SEC-POSTURE (bounds + resource guards on a network-derived parser), NFR-IP (clean-room), the operating contract §4 (the wire is the oracle). **Completes ADR 0010** (the "Connext type-gating via the legacy 0x8021 TypeObject" follow-on).

## 1. Goal & scope

RTI Connext 7.3.1 advertises a type on the wire via the vendor parameter `PID_TYPE_OBJECT_LB` (0x8021) — a ZLIB-compressed, RTI-proprietary "legacy TypeObject" — and (for the small types we interop on) emits no OMG `PID_TYPE_INFORMATION` (0x0075) and no standard TypeLookup service (ADR 0009, ADR 0010). To gate endpoint matching on real type compatibility against Connext, we must **structurally parse that legacy TypeObject** into our model and drive assignability with it.

We already ZLIB-inflate it (`inflate-type-object-lb`) and apply a coarse name *fingerprint* (`assess-type-object-lb`, advisory). This feature adds the structural parse the fingerprint stands in for.

In scope:
- A two-layer parser: a generic, bounds-checked **TLV tokenizer** + a tier-by-tier **semantic interpreter** producing a `minimal-struct-type`.
- Full aggregate construct coverage **pursued incrementally**: primitives, strings, `@key`, member names/ids, extensibility, then sequences + nested structs, then enums/unions/arrays/bitmask — each tier driven by differential captures; anything undecoded errors cleanly to `:unsupported`.
- A clean-room **capture corpus** (the oracle) + a **differential-diff tool** (the RE accelerator).
- A **fail-open** DCPS gate: a high-confidence parse gates (real assignability + TYPE_CONSISTENCY_ENFORCEMENT); any uncertainty falls back to today's name-match, never rejects.
- Live bidirectional gating against Connext 7.3.1.

Out of scope (recorded, not designed-out): re-serializing RTI's format (no clean-room emitter exists, so no parse∘serialize round-trip); DynamicData; SCC/cyclic types (the DSL is acyclic); constructs that resist black-box decoding (left `:unsupported` + recorded as known gaps).

## 2. Decisions (locked during brainstorming)

1. **Gate, fail-open.** A confident parse → real assignability gating (reject truly-incompatible types). ANY parse uncertainty — unknown tag, unmodeled kind, malformed bytes — → name-match fallback, **never a reject**. A misparse degrades to the status quo, never to a false-reject of a live Connext peer.
2. **Full aggregate scope, incremental + degrading.** Pursue primitives→strings→keys→nested→sequences→enums/unions/arrays/bitmask; each tier ships independently; an undecoded construct is `:unsupported`, not a blocker.
3. **DoD = offline byte-exact corpus + live both-ways gating.** The captured-variant corpus parses byte-exact (regression-locked); live Connext shows a compatible type matching AND an incompatible type rejected, both directions.
4. **Approach C** — the two-layer tokenizer/interpreter PLUS the offline differential-diff tool, given the large full-scope campaign.

## 3. What we already observe (clean-room, from our own capture)

Inflating the locked ShapeType capture (`%connext-shape-type-lb`, 232→540 octets) shows a **self-describing nested TLV**, little-endian:
- A recurring 4-byte tag family — `01 7f 08 00` (a container/typed node) and a short `02 7f 00 00` (a primitive/reference) — introduces each element; nodes nest.
- 4-byte length fields; length-prefixed names: `0a 00 00 00 "ShapeType"`, `"color"`, `"y"`, `"shapesize"`, `"string_255_character"`.
- Repeated 8-byte IDs that read as type hashes (`5e ba de cf 42 18 4b f2` at the struct head and tail); small integer fields (`64`=100, `65`=101, `c8`=200, `05 00 05 00`) that read as kind/flag enums.

These observations bound the tokenizer's shape. **The *meaning* of each tag/field is NOT assumed from this single sample** — it is established by differential capture (§6) and documented as observed behavior. Even where the format is recognizable, semantics are recorded from experiments, never from RTI internals.

## 4. Architecture & components

**`src/dds-types/legacy-type-object.lisp`** (package `dds.types`), two strictly separated layers:

**Layer 1 — TLV tokenizer (the security boundary).** `%lto-read-node` walks the nested `tag(4)/len(4)/value` tree over a bounds-checked cursor with no semantic knowledge. Every tag/len/string read is validated against the inflated-buffer extent before use; guards `*lto-max-depth*`, `*lto-max-elements*`, `*lto-max-string-bytes*` reject before allocating. Returns a token tree (each node: tag, value-region, children, any decoded length-prefixed name) or `NIL` on any structural violation. Fully testable and fuzzable without decoding tag meanings.

**Layer 2 — semantic interpreter.** `parse-legacy-type-object (octets) → (or minimal-struct-type (member :unsupported) null)` folds the token tree into a `minimal-struct-type` carrying **real member names** (NameHash computed from the actual name, so assignability's NameHash path and name-fallback both work). Per-member TypeIdentifiers: primitives → `primitive-type-identifier`; strings → string TI + bound; sequences → `sequence-type-identifier`; nested struct → `hash-type-identifier` with the recursively-parsed nested model attached as `referenced` (the mechanism the TypeLookup gate already uses). Unknown tag / unmodeled-or-ungateable kind → `:unsupported`; structurally broken → `NIL`. Grown tier by tier; models only what `struct-assignable-from` can meaningfully gate.

**`tools/legacy-typeobject-diff.lisp`** (offline, not in the runtime path). Takes two inflated TypeObjects, aligns them through the tokenizer, prints the changed byte ranges and the structural node each falls in. The RE accelerator and a provenance artifact.

**`interop/connext/typeobject-corpus/`** (clean-room oracle). A family of IDL variants (one per construct/feature), a Connext publisher app (rtiddsgen, mirroring the existing shapes/large-data harness), and a capture script; each variant's `PID_TYPE_OBJECT_LB` is captured from live Connext and its inflated bytes locked as a regression vector.

**DCPS wiring** (`src/dds-dcps/type-gate.lisp`). One new branch: a remote with 0x8021 and no 0x0075 → `inflate-type-object-lb` → `parse-legacy-type-object`; a `minimal-struct-type` → `struct-assignable-from` + reader-side TCE → gate; `:unsupported`/`NIL` → fail-open name-match + log. The advisory `assess-type-object-lb` fingerprint stays as a logged diagnostic. The gate's existing per-GUID FIFO cache holds the parsed model (no re-parse on re-announce).

## 5. Data flow

SEDP match (dds-disc) → DCPS type-gate → remote 0x8021 present, 0x0075 absent → inflate (capped by `*max-type-object-bytes*`) → `%lto-read-node` tree → interpreter → `minimal-struct-type` (real names/ids/keys/extensibility/TIs; nested resolved+attached) → `struct-assignable-from` local vs parsed-remote under reader-side TCE → `:compatible`/`:incompatible`; any non-model result → `:compatible` (name fallback) + log. Verdict cached per remote GUID.

## 6. The reverse-engineering method (NFR-IP, the load-bearing discipline)

Each tag/field's meaning is established by a **differential-capture experiment**: take a base IDL, change exactly one feature (rename a member, retype a field, add a member, move `@key`, flip extensibility, change a string bound, add a sequence/enum/union/array/bitmask), capture both inflated TypeObjects from live Connext, diff via the tool, and attribute the changed bytes to that feature. The experiment (variant pair + changed ranges + conclusion) is recorded in `docs/provenance.md` and a one-line code comment at the decode site. **No RTI source/headers/`rtiddsgen` output and no GPL Wireshark RTPS dissector are consulted** — observed bytes only. Reading is allowed of OMG specs and Apache/EPL open peers for *understanding the type model*, not this format.

## 7. Error handling & security (NFR-SEC-POSTURE)

- The tokenizer bounds-checks every tag/len/string against the inflated extent before trusting it (the data is post-inflate control-plane, but a malformed TypeObject must never OOB or stack-overflow the discovery thread).
- `*lto-max-depth*`, `*lto-max-elements*`, `*lto-max-string-bytes*` reject before allocation; total inflated size already capped by `*max-type-object-bytes*`.
- Interpreter unknown/broken → `:unsupported`/`NIL`; the gate is fail-open on every non-model result — a parse defect can never reject a peer.
- The tokenizer is added to `make fuzz` (random/truncated/mutated inflated buffers → no condition, NIL-or-tree).

## 8. Testing & Definition of Done

- **Byte-exact corpus:** every captured variant (ShapeType + the §9 construct variants) parses to its expected `minimal-struct-type`, regression-locked; the inflated bytes are the embedded oracle.
- **Tokenizer fuzz** green.
- **Assignability:** parsed-model compatible/incompatible pairs decided correctly (incl. the NameHash path, the ignore-* options, extensibility rules).
- **Live Connext 7.3.1, both directions (the acceptance gate):** a compatible type matches; a deliberately-incompatible type (same topic+type-name, a member retyped) is rejected by our gate — observed on the wire + `CONNEXT_VERBOSE` logs.
- **Gates:** full suite SBCL (+ Clasp at stage boundaries per the documented NFR-PORT Clasp gap), `gate-types`, `gate-hotpath` (control-plane; hot path untouched), `fuzz`, `make wire` where relevant.
- Provenance, `docs/verification.csv` (FR-TYPE-2/4, FR-IO), `docs/MILESTONES.md`, and `docs/wiki/` updated per stage.

## 9. Staged implementation (commit per stage; main green throughout; each stage degrades cleanly)

0. **Oracle + tooling.** `typeobject-corpus/` rtiddsgen harness + capture script + the diff tool; lock the ShapeType inflated 540-octet vector. No parser.
1. **TLV tokenizer.** Byte-exact structural tree of the ShapeType capture; bounds + guards; fuzzed.
2. **Interpreter tier 1 — flat structs.** Primitives, bounded/unbounded strings, `@key`, member names+ids, `@final/@appendable/@mutable`. Byte-exact ShapeType → model; assignability runs. Each feature's encoding pinned by a differential capture, provenance-logged.
3. **Tier 2 — sequences + nested structs.** Capture variants; recursion + attachment; byte-exact; LargeData-class types gate.
4. **Tier 3 — enums, unions, arrays, bitmask.** One capture campaign per construct; an undecodable construct stays `:unsupported` (fail-open) and is recorded as a known gap.
5. **DCPS wiring.** The fail-open legacy-parse branch in the type-gate; offline tests with synthesized 0x8021 endpoint-data.
6. **Live bidirectional Connext gating** (DoD acceptance): compatible matches, incompatible rejected, both directions, observed on the wire.

## 10. Risks & open questions

- **Black-box decoding may stall on a construct** (unions/bitmask especially). Mitigation: the fail-open architecture makes every undecoded construct `:unsupported` → name-match; partial coverage always ships; the construct is a recorded gap, not a failure.
- **Single-vendor, single-version format.** The decoding is specific to Connext 7.3.1's emitter; a future RTI version could change bytes. Mitigation: the corpus is versioned; unknown tags fail open; this is interop-robustness, not correctness-critical.
- **False-reject risk is the cardinal hazard.** Bounded by decision 1 (fail-open) + requiring a high-confidence parse before gating + the live both-ways acceptance test (which must show NO false-reject of a compatible Connext peer).
- **rtiddsgen may bound/transform types** (ADR 0009: it bounded an "unbounded" string at 255; the corpus IDL must record each generated type's actual shape, as the DATA_FRAG/`-unboundedSupport` work did).
- **The legacy TypeObject carries COMPLETE info (real names)** while our minimal-hash path is name-erased — assignability already compares NameHash and now has real names to hash; no model change needed, but the parsed model's `extensibility`/key/optional flags must be mapped from RTI's flag encoding (a differential-capture item).
