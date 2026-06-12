# Legacy-TypeObject aggregate-member gaps: enum + array + union structural gating

- **Date:** 2026-06-12
- **Status:** Design — approved for planning.
- **Area:** L3 type system — `src/dds-types/{legacy-type-object,xtypes,assignability}.lisp`; `dds-tests`; the live Connext corpus `interop/connext/typeobject-corpus/`
- **Requirements:** FR-TYPE-4 (assignability + TYPE_CONSISTENCY_ENFORCEMENT — moves enum/array/union from a fail-open gap toward structural gating); NFR-SEC-POSTURE (bounds-check every legacy-wire read); NFR-IP (clean-room reverse-engineering of RTI's proprietary legacy TypeObject — no RTI source, no GPL dissector); the operating contract §4 (the wire is the oracle).

## 1. Goal & scope

Today `parse-legacy-type-object` (the clean-room parser for RTI's inflated `PID_TYPE_OBJECT_LB`, 0x8021) degrades the **whole parse** to `:unsupported` — a safe fail-open to name-match at the DCPS gate — whenever any member is an enum (member-kind 0x0E), union (0x15), or array (0x11), because the XTypes assignability model has no TypeIdentifier for those constructs. This feature closes those three gaps: each gains a real TypeIdentifier, a spec-grounded assignability rule, and parser wiring, so a struct carrying such a member **gates structurally** against a live Connext peer instead of always name-matching.

In scope: enum, array, union — all three captured in the corpus (`C_Enum`, `C_Array`, `C_Union`).

Out of scope (documented gaps, not designed out):
- **Bitmask** — `rtiddsgen` 4.3.1 rejects the `bitmask` keyword, so there is no wire capture and therefore no oracle (the operating contract §4 forbids gating on an unverified encoding). Stays a documented gap until a newer `rtiddsgen` can emit it.
- **map / alias** — not in the corpus; no driver; remain fail-open.
- Standard (non-legacy) EK_MINIMAL enum/array/union TypeObjects on the OMG wire — out of band here; this feature is about the **legacy** 0x8021 blob. (The new model TypeIdentifiers are reusable by a future standard-TypeObject path, but that path is not built here.)

## 2. Decisions (locked during brainstorming, owner-approved)

1. **All three capturable aggregates** (enum + array + union), not a smaller cut.
2. **Approach A — vertical slices**, staged enum → array → union: each aggregate is a full end-to-end slice (RE → model → assignability → wire → corpus test) verified against its live capture before the next begins. Union last (riskiest). Rejected: horizontal layers (no end-to-end verification until late; model-before-RE rework) and model-light ad-hoc gating (divergent type vocabulary, harder to verify).
3. **Actual XTypes 1.3 spec assignability rules**, each clause-pinned. Enum modeled as a real enum TypeIdentifier — assignable only to an enum, **never widened to `long`** (resolving the hazard the earlier degrading-tier note flagged).
4. **Fail-open is the cardinal invariant, unchanged.** Any member whose legacy node cannot be fully and safely decoded, and any assignability sub-case that cannot be confidently modeled, leaves the parse `:unsupported` (name-match) — **never a false reject**. Union gates only where the legacy wire is safely modelable; ambiguous cases stay fail-open with the residue documented.

## 3. Normative anchors (pin from `docs/specs/xtypes-1_3.pdf` via pdftotext at implementation time; cite the clause in code)

- **Enum assignability** — §7.2.4.4.2 / Table 12: T1, T2 both enumerated; literals matched **by name** that exist in both must have the same value; the `@try_construct` / must-understand handling for literals present in only one. (Minimal carries `MinimalEnumeratedType` = bit-bound + literals each with `MinimalMemberDetail.name_hash` + value — so matching is by the 4-octet NameHash, consistent with the existing `member-names-agree-p` discipline for structs.)
- **Array assignability** — plain-collection rule: element types **strongly** assignable (the delimited-type concept already in `assignability.lisp`) **and identical dimensions** (arrays are not resizable — bounds must be equal, unlike sequence/string where `ignore_*_bounds` options apply).
- **Union assignability** — §7.2.4.5: discriminator types assignable; key/must-understand correspondence on the discriminator; for members selected by the same label, the member types are assignable; default-member correspondence; `@try_construct` handling for labels present in only one union.
- **Legacy node encodings** — reverse-engineered clean-room per aggregate via `tools/legacy-typeobject-diff.lisp` (`lto-diff`) against the corpus capture, in the exact manner the struct/string/sequence/primitive encodings were established (recorded in `docs/provenance.md` with the differential that pins each field). The aggregate member-kind words are already pinned (enum 0x0E, array 0x11, union 0x15 at member-node VALUE-START+8); the **def-node internals** (enum literals+values; array element-kind + dimensions; union discriminator + cases + labels + member types) are the new RE.

## 4. Architecture & components (per aggregate; stage = commit boundary)

Each aggregate is one vertical slice across the same four units:

1. **Legacy RE + decode** (`legacy-type-object.lisp`): new `+lto-code-*+` constant(s) for the def-node, a bounds-checked decoder that walks the node into the fields the model needs, established clean-room from the corpus differential. Every read bounds-checked first (NFR-SEC-POSTURE); over-depth / missing-referenced-node / unknown-sub-encoding → the member is unmodelable → whole parse `:unsupported` (the existing degrade path).
2. **Model** (`xtypes.lisp`): a new TypeIdentifier kind + in-memory referenced descriptor, mirroring the nested-struct `referenced` pattern (so assignability recurses without needing the real EK_MINIMAL hash):
   - **Enum:** `enumerated-type-identifier` → referenced enum descriptor `{bit-bound; literals: list of (name-hash . value)}`.
   - **Array:** plain-array TypeIdentifier (small/large by dimension size, per the existing string8 small/large precedent) → element TypeIdentifier + dimension bound(s).
   - **Union:** `union-type-identifier` → referenced union descriptor `{discriminator TI + flags; members: each (labels, member-TI, default-p, name-hash)}`.
3. **Assignability** (`assignability.lisp`): the §3 rule, CLOS-free, clause-cited, recursing via the referenced descriptor; strong-assignability reused for element/member types.
4. **Wire flip** (`legacy-type-object.lisp` / `%lto-member-type-identifier`): the aggregate member-kind now builds its TI instead of leaving `type-identifier` NIL / forcing `:unsupported`. The degrade tier still catches anything not safely decodable.

## 5. Data flow

`inflate-type-object-lb` (0x8021 → octets) → `tokenize-legacy-type-object` (lto-tree) → `parse-legacy-type-object` folds members into a `minimal-struct-type`; an enum/array/union member now carries a real TypeIdentifier (with its referenced descriptor) rather than degrading. The DCPS gate (`src/dds-dcps/type-gate.lisp` `%gate-legacy-type-object`) is **unchanged** — its `struct-assignable-from` now recurses into the new TIs. A structurally-incompatible peer → `:incompatible` → INCONSISTENT_TOPIC; everything else stays the fail-open `:compatible`.

## 6. Error handling & fail-open (the cardinal invariant)

- **Decode side:** unknown sub-encoding, over-`*lto-max-type-depth*`, missing referenced def-node, or any bounds-check failure → the member is unmodelable → **whole parse `:unsupported`** → name-match. No partial model with a NIL-TI member ever reaches the gate (the existing degrading-tier guarantee, extended to the new decoders).
- **Assignability side:** a decoded aggregate whose spec rule has a sub-case we cannot confidently evaluate (e.g., a union default-member shape the legacy wire doesn't disambiguate) returns **not-assignable conservatively only when the spec is unambiguous**; where the spec outcome is uncertain from the available wire info, the *parse* should have already degraded that member to `:unsupported` rather than the assignability function guessing — i.e., uncertainty is resolved at decode time (fail-open), not at gate time (which could false-reject). Union is the case most likely to exercise this; its residue is documented per stage.
- **No false reject** is verified per aggregate by the re-run pattern from the live legacy gating (a compatible local stays `:compatible` across re-runs even after an incompatible local was rejected).

## 7. Testing

Per aggregate, the already-locked corpus capture drives one test (mirroring `lto-assignability` / `lto-parse-enum`):
- **Parse:** the captured blob yields the expected TypeIdentifier structure (byte-grounded against the RE).
- **Gate compatible:** `struct-assignable-from` of a locally-built model with a matching aggregate member → assignable **both directions** (`:compatible`).
- **Gate incompatible:** a local model differing in the aggregate (enum: a literal value changed / a literal renamed; array: a different bound or element type; union: a changed case type or label) → **not** assignable (`:incompatible`).
- **Fail-open:** a still-unmodelable variant stays `:compatible` (name-match).

Plus: the full suite stays green (currently 93) on SBCL per task and Clasp at each stage boundary (`GC_DONT_GC=1`); `make gate-types` + `make gate-hotpath` green (these files are control-plane, not hot-path). `docs/provenance.md` records each aggregate's differential; `docs/verification.csv` FR-TYPE-4, `docs/wiki/type-system.md`, and `README.md` updated in lockstep.

## 8. Stages (commit boundaries)

- **S0 — Enum.** RE the legacy enum def-node (literals + values via the C_Enum differential) → `enumerated-type-identifier` + descriptor → Table-12 assignability → wire flip → `lto-enum-assignability` corpus test. Exit: a struct with an enum member gates structurally vs C_Enum; enum-vs-non-enum is not assignable; fail-open residue (if any) documented.
- **S1 — Array.** RE the array def-node (element-kind + dimensions via C_Array) → plain-array TI → element-assignable + identical-dims assignability → wire flip → `lto-array-assignability` test. Exit: array member gates structurally vs C_Array; differing element/bound rejected.
- **S2 — Union + closeout.** RE the union def-node (discriminator + cases + labels + member types via C_Union — the largest RE) → `union-type-identifier` + descriptor → §7.2.4.5 assignability (degrade-safe) → wire flip → `lto-union-assignability` test. Then closeout: `provenance.md` (all three differentials), `verification.csv` FR-TYPE-4 (enum/array/union now structural; bitmask/map/alias residual gaps reaffirmed), wiki + README, memory. Exit: union gates where safely modelable, else fail-open documented; suite green SBCL+Clasp; no false-reject re-run passes.

## 9. Definition of Done

Enum and array members gate structurally and are corpus-verified both directions. Union gates structurally for the shapes safely modelable from the legacy wire, with any residue fail-open and documented. The fail-open-never-false-reject invariant holds (verified by re-run). Suite green on SBCL and Clasp; gate-types + gate-hotpath green. Bitmask remains a documented no-oracle gap. Docs (provenance, verification.csv, wiki, README) in lockstep.
