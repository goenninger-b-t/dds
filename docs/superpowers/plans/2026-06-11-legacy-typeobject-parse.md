# Legacy RTI TypeObject (0x8021) Structural Parse — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Structurally parse RTI Connext's proprietary legacy TypeObject (the inflated `PID_TYPE_OBJECT_LB`/0x8021 payload) into our `minimal-struct-type` model so endpoint matching can gate on real assignability against live Connext 7.3.1 — fail-open (a parse defect degrades to name-matching, never a false-reject).

**Architecture:** A two-layer parser — a generic bounds-checked TLV tokenizer (the security boundary) plus a tier-by-tier semantic interpreter that maps tokens to the model and returns `:unsupported` on anything undecoded. A clean-room **capture corpus** (Connext-generated, byte-locked) is the oracle; a **differential-diff tool** reverse-engineers each tag's meaning by varying one IDL feature and diffing the inflated bytes. The DCPS type-gate gets one fail-open branch for stock Connext peers (0x8021 present, 0x0075 absent).

**Tech Stack:** Common Lisp (SBCL + Clasp), the in-repo XCDR2/RTPS/discovery/assignability stack, `chipz` (already a dep, pure-Lisp inflate), RTI Connext 7.3.1 + rtiddsgen, tcpdump/our own pcap reader for capture.

**Spec:** `docs/superpowers/specs/2026-06-11-legacy-typeobject-parse-design.md`.

## How the reverse-engineering works (READ THIS FIRST — it governs every parser task)

This is a black-box reverse-engineering effort. The byte-exact test literals in Stages 1–4 are **produced by the Stage-0 capture pipeline during execution**, not invented. The plan specifies the *procedure* completely; the executor runs it and embeds the real bytes. For each construct/feature, the method is invariant:

1. Add/already-have a base IDL and a one-feature-changed variant IDL in the corpus.
2. Capture both inflated TypeObjects from live Connext (Stage 0 pipeline).
3. Run `tools/legacy-typeobject-diff.lisp` on the pair → the changed byte ranges + their structural node.
4. From the diff, attribute the changed bytes to that feature; write the decode; **record the experiment** (variant pair, changed ranges, conclusion) in `docs/provenance.md` + a one-line code comment at the decode site.
5. Lock the captured vector + assert the parsed model is byte-exact-derived.

**Clean-room (NFR-IP, absolute):** the meaning of every tag/field comes from these experiments only. NEVER read RTI source/headers/`rtiddsgen`-generated `.cxx`, and NEVER use the GPL Wireshark RTPS dissector to decode the TypeObject. Reading OMG specs / Apache-EPL peers for the *type model* is fine; decoding *this format* is observation-only. The corpus capture uses OUR OWN parser (`parse-endpoint-data`), not tshark's dissector.

## Non-negotiable rules for every task (the operating contract)

- **`defun*`/`defstruct*` for everything** (`dds.lang`), every parameter typed, full ftype.
- **Bounds-check every tokenizer read** against the inflated-buffer extent before trusting any tag/len/offset, even at `(safety 0)`; resource guards (`*lto-max-depth*`, `*lto-max-elements*`, `*lto-max-string-bytes*`) reject before allocation. The data is post-inflate control-plane but a malformed TypeObject must never OOB or stack-overflow the discovery thread.
- **Fail-open is sacred:** no parse result other than a confident `minimal-struct-type` may ever cause a match rejection. `:unsupported`/`NIL` → name-match. The live acceptance test must show ZERO false-rejects of a compatible Connext peer.
- **Comments one line max**; rationale → commit message + `provenance.md`. No AI attribution anywhere.
- **After each task:** `make gate-types && make gate-hotpath` + the task's tests green on **SBCL** (`./scripts/with-sbcl.sh --eval '(ql:quickload :dds-tests :silent t)' --eval '(dds.tests:run-all-tests)' --eval '(uiop:quit 0)'`); run **Clasp at stage boundaries** with `GC_DONT_GC=1 ./scripts/with-clasp.sh ...` (the documented NFR-PORT Boehm-GC gap; one retry allowed). Present each commit message for owner approval before committing (no Co-Authored-By).
- **Suite baseline at plan start: 79 green SBCL.** Each task states its expected new count.
- **Connext env (three separate exports):** `export NDDSHOME=/Applications/rti_connext_dds-7.3.1` then `export CONNEXTDDS_ARCH=arm64Darwin20clang12.0` then `export DYLD_LIBRARY_PATH=$NDDSHOME/lib/$CONNEXTDDS_ARCH`. lo0 capture needs no sudo (user ∈ access_bpf).

## File structure

| File | Responsibility | Stage |
|---|---|---|
| `interop/connext/typeobject-corpus/` (create) | IDL variants + a Connext publisher app + USER_QOS_PROFILES.xml; one type per construct/feature | 0,2,3,4 |
| `interop/connext/typeobject-corpus/capture.sh` (create) | drive a Connext corpus-pub + our capture-sub; emit each variant's LB as a Lisp byte-vector literal | 0 |
| `src/dds-shapes/shapes.lisp` (modify) | a `corpus-capture-subscriber` that prints a matched remote's raw `endpoint-data-type-object-lb` as a Lisp literal | 0 |
| `tools/legacy-typeobject-diff.lisp` (create) | offline: inflate two LBs, tokenize, align, print changed byte ranges + structural node | 0 |
| `src/dds-types/legacy-type-object.lisp` (create) | the TLV tokenizer (`%lto-read-node`) + the semantic interpreter (`parse-legacy-type-object`) | 1,2,3,4 |
| `src/dds-types/packages.lisp` (modify) | exports per stage | 1,2 |
| `dds-types.asd` (modify) | add the new component after `type-object-lb` | 1 |
| `src/dds-dcps/type-gate.lisp` (modify) | the fail-open legacy-parse branch (0x8021 present, 0x0075 absent) | 5 |
| `src/dds-tests/legacy-typeobject-test.lisp` (create) | tokenizer + interpreter byte-exact corpus tests | 1,2,3,4 |
| `src/dds-tests/pbt-test.lisp` (modify) | fuzz the tokenizer | 1 |
| `src/dds-tests/{integration,echo}-test.lisp` (modify) | DCPS gate test + registrations | 5 |
| `docs/provenance.md` (modify) | every differential-capture experiment | 0–4 |
| `docs/verification.csv`, `docs/MILESTONES.md`, `README.md`, `docs/wiki/{type-system,discovery,dcps}.md` (modify) | doc lockstep | each |

---

## STAGE 0 — Capture oracle + diff tooling (no parser)

> The corpus is the clean-room oracle. We capture LB bytes by having OUR stack subscribe to a Connext corpus-publisher and dump the raw `endpoint-data-type-object-lb` it discovers — no pcap dissector. The diff tool is the RE accelerator.

### Task 0.1: Corpus capture subscriber

**Files:** Modify `src/dds-shapes/shapes.lisp`, `src/dds-shapes/packages.lisp`, `Makefile`.

**Context:** `src/dds-shapes/shapes.lisp` has `run-subscriber`/`run-large-subscriber` over a disc-node. The disc-node's matched remote endpoints carry `dds.rtps.discovery:endpoint-data-type-object-lb` (opaque LB octets) — this is already captured at SEDP time (see `run-sedp-type-object-lb-test`). We add a subscriber variant that, on discovering a remote writer with a non-NIL LB, prints that LB as a ready-to-paste Lisp byte vector and exits.

- [ ] **Step 1:** Read `run-large-subscriber` in `shapes.lisp` and the disc-node `on-match`/discovered-writers accessors in `src/dds-disc/disc.lisp` (how to enumerate matched remote writers + reach their `endpoint-data`). Identify the accessor returning the remote publication endpoint-data list.

- [ ] **Step 2:** Add:

```lisp
(defun* run-corpus-capture-subscriber (&key (domain 0) (topic "Square") (type "ShapeType")
                                            (seconds 20))
    (function (&key (:domain (integer 0)) (:topic string) (:type string) (:seconds (integer 0)))
              (or null (simple-array (unsigned-byte 8) (*))))
  "Subscribe on TOPIC/TYPE, spin up to SECONDS, and on the first matched remote writer that
   announced a PID_TYPE_OBJECT_LB print it as a Lisp byte vector (for the corpus) and return
   it; NIL if none seen. Clean-room capture: reuses our own SEDP parser, no external dissector."
  ...)
```

Implementation: build a disc-node + reader for TOPIC/TYPE (mirror `run-large-subscriber`'s node/reader setup), spin the node, poll the discovered-writers for a non-NIL `endpoint-data-type-object-lb`; on first hit `(format t "~&;; ~a / ~a~%(~{~a~^ ~})~%" topic type (coerce lb 'list))` and return it. One-line comments only.

- [ ] **Step 3:** Export `run-corpus-capture-subscriber`; add a `Makefile` target `corpus-capture` (mirror `large-sub`, pass TOPIC/TYPE/DOMAIN). Load `:dds-shapes` on SBCL clean; `make gate-types`.
- [ ] **Step 4:** Commit — `feat(shapes): corpus-capture subscriber dumps a remote PID_TYPE_OBJECT_LB as a Lisp vector`.

### Task 0.2: Connext corpus publisher + base IDL

**Files:** Create `interop/connext/typeobject-corpus/{Corpus.idl,corpus_pub.cxx,USER_QOS_PROFILES.xml,Makefile,README.md}`; modify `interop/connext/Makefile`, `interop/connext/.gitignore`.

**Context:** Mirror `interop/connext/large-data/` (its `common.mk` reuse, the `-unboundedSupport`/QoS lessons, the build pattern). The base IDL reproduces ShapeType so its capture matches the already-locked `%connext-shape-type-lb` (a cross-check that the pipeline is faithful).

- [ ] **Step 1:** `Corpus.idl` with the base type first:
```idl
@final struct C_Shape { @key string color; long x; long y; long shapesize; };
```
(matches RTI's ShapeType shape; confirm rtiddsgen's treatment of `string` bound as in the large-data README, record it).
- [ ] **Step 2:** `corpus_pub.cxx` — a single-process matched writer+reader per the `typeobject_probe.cxx` pattern (so SEDP definitely fires), topic/type chosen by argv so one binary serves every corpus type. QoS UDPv4-only + single-interface pin (mirror large-data), reliable.
- [ ] **Step 3:** Build (`make -C interop/connext/typeobject-corpus`); wire into `interop/connext/Makefile` APPS; `.gitignore` the rtiddsgen output + binaries + any pcap.
- [ ] **Step 4: Capture cross-check.** Run the Connext `corpus_pub` for `C_Shape` on topic "Square" type "C_Shape" and our `make corpus-capture TOPIC=Square TYPE=C_Shape`; confirm the dumped LB inflates (via a quick `inflate-type-object-lb` call) and `type-object-strings` shows `C_Shape`/`color`/`shapesize`. Save the dumped vector. Commit — `test(interop): Connext TypeObject corpus harness + base C_Shape capture`.

### Task 0.3: Differential-diff tool

**Files:** Create `tools/legacy-typeobject-diff.lisp`. (Standalone; loads `:dds-types` for `inflate-type-object-lb`; the tokenizer doesn't exist yet, so v1 diffs at the raw-byte level and is upgraded to structural alignment in Task 1.5.)

- [ ] **Step 1:** `(defun lto-diff (lb-a lb-b) ...)`: inflate both; if lengths equal, print every differing offset run `(start..end)` with both byte slices + the surrounding ASCII; if lengths differ, print the longest common prefix/suffix and the differing middle. Pure reporting to stdout.
- [ ] **Step 2:** Smoke-test it on `C_Shape` vs a hand-edited copy (flip one byte) — confirm it reports exactly that offset. (No suite test; it's a tool.)
- [ ] **Step 3:** Commit — `tools: legacy-TypeObject differential-diff (raw-byte)`.

---

## STAGE 1 — TLV tokenizer (the security boundary)

### Task 1.1: Tokenizer struct + guards + the node reader

**Files:** Create `src/dds-types/legacy-type-object.lisp` (package `dds.types`; add to `dds-types.asd` after `type-object-lb`); modify `src/dds-types/packages.lisp`; test `src/dds-tests/legacy-typeobject-test.lisp` (new; register in `echo-test.lisp`).

**What we observed (from §3 of the spec; the tokenizer must walk this, NOT interpret it):** little-endian; a 4-byte tag (`01 7f 08 00` container, `02 7f 00 00` short/primitive seen); 4-byte length fields; length-prefixed strings. The tokenizer's job is only to produce the tree; the EXACT framing (where a length is, whether children are counted or length-delimited) is determined in Step 2 from the `C_Shape` capture via the diff tool + manual walk — DO NOT assume; derive it and cite the offsets in a comment.

- [ ] **Step 1: Specials + node struct:**
```lisp
(defparameter *lto-max-depth* 32
  "Max nesting depth for the legacy-TypeObject tokenizer (NFR-SEC-POSTURE).")
(defparameter *lto-max-elements* 4096
  "Max total nodes the legacy-TypeObject tokenizer will produce (NFR-SEC-POSTURE).")
(defparameter *lto-max-string-bytes* 8192
  "Max length-prefixed string the tokenizer will accept (NFR-SEC-POSTURE).")

(defstruct* (lto-node (:constructor %make-lto-node))
  "One node of the parsed legacy-TypeObject TLV tree: its 4-octet TAG, the absolute
   byte range [VALUE-START, VALUE-END) of its value, child nodes, and the decoded
   length-prefixed NAME when the node carries one (else NIL). Structure only, no semantics."
  (tag 0 :type (unsigned-byte 32))
  (value-start 0 :type (integer 0))
  (value-end 0 :type (integer 0))
  (children '() :type list)
  (name nil :type (or null string)))
```

- [ ] **Step 2: Derive the framing.** Using the `C_Shape` inflated capture + `lto-diff` against a renamed variant (capture `C_Shape` with `color`→`colour` — add the variant to `Corpus.idl`, rebuild, capture), determine: tag width/position, length field position/width, how children are delimited, where strings sit. Write the finding into `docs/provenance.md` (experiment: base vs colour) and a header comment in `legacy-type-object.lisp` with the byte offsets.

- [ ] **Step 3: Failing test** `run-lto-tokenize-test` (register `("lto-tokenize" . run-lto-tokenize-test)`): inflate the locked `%connext-shape-type-lb` (move/duplicate that helper into the new test file or call it from integration-test — reuse, don't re-embed), tokenize, and assert the tree's shape against what the manual walk established: the root node, a child whose `name` = "ShapeType", member child nodes whose `name`s include "color"/"shapesize"/"string_255_character", and that `%lto-read-node` consumed exactly to the buffer end. Provide the assertions from the real capture (filled at execution from Step 2's walk).

- [ ] **Step 4: Run — FAIL** (`%lto-read-node` undefined).

- [ ] **Step 5: Implement `%lto-read-node`:**
```lisp
(defun* %lto-read-node (octets pos end depth count)
    (function ((simple-array (unsigned-byte 8) (*)) (integer 0) (integer 0)
               (integer 0) (cons (integer 0) null))
              (or null lto-node))
  "Read one TLV node from OCTETS[POS,END), recursively. DEPTH guards nesting
   (*lto-max-depth*); COUNT is a mutable cell guarding total nodes (*lto-max-elements*).
   Returns the node or NIL on any bounds/guard violation. Every tag/len/string read is
   bounds-checked against END first. Structure only; tags are not interpreted."
  ...)
```
plus the public `(defun* tokenize-legacy-type-object (octets) ... )` that calls it from 0 with a fresh count cell and returns the root or NIL (also NIL if it didn't consume to the end — a trailing-garbage guard). Bounds-check discipline mirrors `parse-minimal-type-object`.

- [ ] **Step 6: Run SBCL — PASS.** Export `tokenize-legacy-type-object`, `lto-node` + accessors, the three specials. `make gate-types && make gate-hotpath`.
- [ ] **Step 7: Commit** — `feat(types): legacy-TypeObject TLV tokenizer with bounds + resource guards`.

### Task 1.2: Fuzz the tokenizer

**Files:** Modify `src/dds-tests/pbt-test.lisp`.

- [ ] **Step 1:** Add `tokenize-legacy-type-object` to the never-signal fuzz property (seed = the inflated `C_Shape` bytes; the three families random/truncated/mutated; first value ∈ `{NIL, lto-node}`; never signals).
- [ ] **Step 2:** `make fuzz LISP=./scripts/with-sbcl.sh` green.
- [ ] **Step 3: Stage-boundary Clasp run** (`GC_DONT_GC=1 ./scripts/with-clasp.sh ...`) — record pass/count. Commit — `test(types): fuzz the legacy-TypeObject tokenizer`.

### Task 1.5: Upgrade the diff tool to structural alignment

**Files:** Modify `tools/legacy-typeobject-diff.lisp`.

- [ ] **Step 1:** Now that the tokenizer exists, make `lto-diff` tokenize both inputs and report each changed byte range with the `lto-node` (tag + name path) it falls in — so an experiment says "the bytes at the `colour` member node changed", not just an offset. Keep the raw fallback for unparseable inputs.
- [ ] **Step 2:** Re-run on base-vs-colour; confirm it localizes the change to the member node. Commit — `tools: structural alignment in the legacy-TypeObject diff`.

---

## STAGE 2 — Interpreter tier 1: flat structs (primitives, strings, keys, names, ids, extensibility)

> Each feature below is ONE differential experiment (base vs one-change variant) → decode → byte-exact corpus test. Add each variant to `Corpus.idl`, rebuild, capture via `make corpus-capture`, embed the locked vector. The interpreter target is `parse-legacy-type-object (octets) -> (or minimal-struct-type (member :unsupported) null)`.

### Task 2.1: Struct skeleton + member names + ids → model

**Files:** Modify `src/dds-types/legacy-type-object.lisp`, `packages.lisp`; test `legacy-typeobject-test.lisp`.

- [ ] **Step 1:** Experiments (capture + diff + provenance each): (a) base `C_Shape`; (b) `color`→`colour` (member-name encoding — already done in 1.2); (c) add a 5th member `long w` (how members are counted/listed + the id encoding); (d) reorder two members (is the id positional or explicit?). Record each in `provenance.md`.
- [ ] **Step 2: Failing test** `run-lto-parse-shape-test`: `(parse-legacy-type-object (inflate ...C_Shape...))` returns a `minimal-struct-type` whose `name`="C_Shape" (or "ShapeType" for the real capture — use whichever vector the test embeds), `extensibility`=`:final`, and 4 members named color/x/y/shapesize with the ids derived from the capture; assert via a `%lto-model-equal-p` helper (mirror `%struct-model-equal-p` from `xtypes-test.lisp` — reuse if exported, else a local). Members' TIs unchecked in this task (Task 2.2/2.3).
- [ ] **Step 3: FAIL.** Implement `parse-legacy-type-object` calling `tokenize-legacy-type-object` then folding the struct node + member nodes into `make-minimal-struct-type` + `make-struct-member` (real names → NameHash computed; ids from the capture). Unknown struct-level tag → `:unsupported`; bad tree → `NIL`.
- [ ] **Step 4: PASS SBCL.** Export `parse-legacy-type-object`. Gates. Commit — `feat(types): parse legacy TypeObject struct skeleton (names + ids + extensibility)`.

### Task 2.2: Primitive member types

- [ ] **Step 1:** Experiments: variants of `C_Shape` retyping `x` to each primitive — `short`, `unsigned long`, `long long`, `octet`, `float`, `double`, `boolean`, `char`, `int8`/`uint8` (note rtiddsgen's int8/uint8→octet mapping per the Extensible Types Guide; record). Diff each against base; map RTI's type-kind encoding → our `primitive-type-identifier` kinds (`+ti-*+`). Provenance per primitive.
- [ ] **Step 2: Failing test** `run-lto-parse-primitives-test`: for each captured variant, parse and assert the retyped member's TI kind equals the expected `+ti-*+`. Embed each locked vector.
- [ ] **Step 3: FAIL → implement** the primitive type-kind decode in the member-TI path. An unknown type-kind → the whole parse `:unsupported` (fail-open).
- [ ] **Step 4: PASS. Gates. Commit** — `feat(types): decode legacy-TypeObject primitive member kinds`.

### Task 2.3: Strings (bounded + unbounded) + the @key flag

- [ ] **Step 1:** Experiments: `color` as `string` (unbounded) vs `string<32>` vs `string<255>` (bound encoding); a variant moving `@key` from `color` to `x` (key-flag encoding); a no-key variant. Diff + provenance.
- [ ] **Step 2: Failing test** `run-lto-parse-strings-keys-test`: parse the captured variants; assert the string member's TI is a string TI with the right bound, and `minimal-struct-member-key-p` matches the captured `@key`.
- [ ] **Step 3: FAIL → implement** string-TI (+bound) decode and the key-flag decode. Unknown → `:unsupported`.
- [ ] **Step 4: PASS. Gates. Commit** — `feat(types): decode legacy-TypeObject string bounds + @key flag`.

### Task 2.4: Extensibility (@final/@appendable/@mutable) + assignability over a parsed model

- [ ] **Step 1:** Experiments: `C_Shape` as `@appendable` and `@mutable` (the extensibility-flag encoding — we observed `@final`=flags `0x0001`; confirm appendable/mutable). Provenance.
- [ ] **Step 2: Failing test** `run-lto-assignability-test`: parse a captured `C_Shape`, build a LOCAL `minimal-struct-type` for the same shape (via `make-minimal-struct-type`/`make-struct-member`, mirror how `xtypes-test` builds models), and assert `dds.types:struct-assignable-from` returns T for the compatible pair and NIL for an incompatible one (e.g. retype a member) — proving the parsed model feeds the real gate. Also assert the parsed extensibility matches per variant.
- [ ] **Step 3: FAIL → implement** the extensibility decode; verify assignability consumes the parsed model unchanged (it should — same struct type).
- [ ] **Step 4: PASS SBCL + stage-boundary Clasp. Gates.** Update `docs/verification.csv` (FR-TYPE-2/4: tier-1 legacy parse + assignability landed), `docs/wiki/type-system.md` (the parser + its `:unsupported` contract). Commit — `feat(types): legacy-TypeObject extensibility + assignability over the parsed model`.

---

## STAGE 3 — Interpreter tier 2: sequences + nested structs

### Task 3.1: Sequence members

- [ ] **Step 1:** Experiments: a `C_Seq` type `{ @key long id; sequence<octet> payload; }` (matches LargeData) and `sequence<long, 10>` (bounded) — the sequence encoding + element-type reference + bound. Capture + diff + provenance.
- [ ] **Step 2: Failing test** `run-lto-parse-sequence-test`: parse; assert the payload member's TI is a `sequence-type-identifier` with the right element kind + bound.
- [ ] **Step 3: FAIL → implement** sequence-TI decode (recursing the tokenizer subtree for the element type). Unknown element → `:unsupported`.
- [ ] **Step 4: PASS. Gates. Commit** — `feat(types): decode legacy-TypeObject sequence members`.

### Task 3.2: Nested struct members + recursion/attachment

- [ ] **Step 1:** Experiments: `C_Nested { @key long id; C_Inner inner; }` with `C_Inner { long a; long b; }` — how the legacy format references/inlines a nested struct (inline subtree? a hash reference to a sibling element? the `01 7f 08 00` containers + the 8-byte hashes we observed suggest a TypeLibrary of elements referenced by hash). Diff + provenance (this is the most format-revealing experiment — the 8-byte IDs at offsets 0x38/0x208 in the ShapeType dump are the lead).
- [ ] **Step 2: Failing test** `run-lto-parse-nested-test`: parse `C_Nested`; assert the `inner` member's TI is a `hash-type-identifier` whose `referenced` is the parsed `C_Inner` model (so `struct-assignable-from` recurses), and that `struct-assignable-from` gates a nested-compatible vs nested-incompatible pair correctly.
- [ ] **Step 3: FAIL → implement** the nested-struct decode: resolve the referenced element (by hash within the TypeLibrary, or inline subtree — per the experiment), parse it, attach as `referenced`. Guard recursion by `*lto-max-depth*` + a visited-hash set (cycle guard, fail-open). Unknown → `:unsupported`.
- [ ] **Step 4: PASS SBCL + Clasp. Gates.** Verification.csv tier-2 note. Commit — `feat(types): decode legacy-TypeObject nested structs (recursion + attachment)`.

---

## STAGE 4 — Interpreter tier 3: enums, unions, arrays, bitmask (degrading)

> Each is one capture campaign. ANY construct that resists black-box decoding stays `:unsupported` (fail-open) and is logged as a known gap in `provenance.md` + verification.csv — pursued, never blocking.

### Task 4.1: Enums

- [ ] **Step 1:** Experiments: an `enum Color { RED, GREEN, BLUE }` member, and a member with explicit enum values. Diff + provenance.
- [ ] **Step 2: Failing test** `run-lto-parse-enum-test`: parse; assert the enum member maps to whatever TI our model+assignability supports for enums (check `assignability.lisp` for enum handling first — if it treats enums as their underlying integer, model that; if unmodeled, the decode returns `:unsupported` and the test asserts THAT + fail-open, recording the gap).
- [ ] **Step 3: FAIL → implement** what assignability can use; `:unsupported` otherwise. **Decision rule:** model only what `struct-assignable-from` can gate; never emit a TI assignability will mis-handle.
- [ ] **Step 4: PASS. Gates. Commit** — `feat(types): decode legacy-TypeObject enums (or :unsupported gap)`.

### Task 4.2: Unions, arrays, bitmask

- [ ] **Step 1:** One experiment + provenance entry per construct (a `union` over a discriminator; a `long[4]` array member; a `bitmask`). For each, check `assignability.lisp` support FIRST.
- [ ] **Step 2: Failing tests** `run-lto-parse-union-test` / `-array-test` / `-bitmask-test`: each asserts either a correct TI (if modeled+gateable) or a clean `:unsupported` + the recorded gap. No construct may produce a TI that assignability mis-gates.
- [ ] **Step 3: FAIL → implement** the gateable subset; `:unsupported` + logged gap otherwise.
- [ ] **Step 4: PASS SBCL + Clasp. Gates.** verification.csv tier-3 + the known-gap list. Commit — `feat(types): decode legacy-TypeObject arrays/unions/bitmask (gateable subset; gaps recorded)`.

---

## STAGE 5 — DCPS fail-open gate wiring

### Task 5.1: Legacy-parse branch in the type-gate

**Files:** Modify `src/dds-dcps/type-gate.lisp`; test `src/dds-tests/integration-test.lisp` (mirror `run-dcps-type-gate-test`); register in `echo-test.lisp`.

**Context:** Read `src/dds-dcps/type-gate.lisp` in full — the verdict ladder, the per-GUID cache, `%remote-writer-p`, the TypeInformation path, and where `endpoint-data-type-object-lb` is reachable from the remote endpoint-data. The new branch sits AFTER the no-TypeInformation check: TypeInformation absent BUT 0x8021 present → legacy path.

- [ ] **Step 1: Failing test** `run-dcps-legacy-gate-test` (two-node-style, mirror `run-dcps-type-gate-test`): synthesize a remote writer endpoint-data with NO `type-information` and a `type-object-lb` = a captured `C_Shape` LB; local type = a compatible shape → match completes (gate `:compatible` via the legacy parse, no TypeLookup query); local type = a structurally-incompatible shape under the same topic+type-name → INCONSISTENT_TOPIC, no match; a remote whose LB is `:unsupported` (feed garbage-but-inflatable bytes, or an unmodeled construct's LB) → match completes (fail-open name-match). Assert the parsed-vs-name path via the gate's verdict/log observable.
- [ ] **Step 2: FAIL → implement** the branch: `inflate-type-object-lb` → `parse-legacy-type-object`; `minimal-struct-type` → cache + `struct-assignable-from` + reader-side TCE → `:compatible`/`:incompatible`; `:unsupported`/`NIL` → `:compatible` (fail-open) + `%tg-log`. Reuse the existing cache + verdict-table machinery. The advisory `assess-type-object-lb` stays as an additional logged diagnostic.
- [ ] **Step 3: PASS SBCL + Clasp. Gates** (`gate-hotpath` must stay green — control-plane only). Update `docs/wiki/dcps.md` (the legacy-gate rung + fail-open) + verification.csv. Commit — `feat(dcps): fail-open legacy-TypeObject assignability gate for Connext peers (FR-TYPE-4)`.

---

## STAGE 6 — Live bidirectional Connext gating (DoD acceptance)

### Task 6.1: Live compatible match + incompatible reject

> Mirrors the M2/DATA_FRAG live method. `NDDSHOME`/`CONNEXTDDS_ARCH`/`DYLD_LIBRARY_PATH` exports; lo0 capture no-sudo; `CONNEXT_VERBOSE=1` for STATUS_ALL.

- [ ] **Step 1: Compatible, both directions.** Connext `corpus_pub` (C_Shape) ↔ our subscriber whose local type is the matching shape: confirm our gate parses Connext's 0x8021, runs assignability, returns `:compatible`, and the match completes + samples flow (capture lo0; `CONNEXT_VERBOSE`). Then our publisher ↔ Connext subscriber for the same type (Connext gates on its own side; we just must interoperate). Record evidence.
- [ ] **Step 2: Incompatible reject (the key proof).** A Connext type and a LOCAL type sharing topic+type-name but structurally incompatible (a member retyped long→double): confirm our gate parses Connext's TypeObject, `struct-assignable-from` returns NIL, our side raises INCONSISTENT_TOPIC and does NOT match — observed via our status + the absence of data. Confirm NO false-reject of the compatible case from Step 1 (the cardinal hazard).
- [ ] **Step 3: Lock evidence + close out.** Record the fix chain (if any) + the live results in `docs/verification.csv` (FR-IO/FR-TYPE-4) and `docs/MILESTONES.md` (M4: Connext legacy-TypeObject gating achieved — completes ADR 0010). Update `README.md` + `docs/wiki/{type-system,dcps,discovery}.md`. Provenance final pass (all experiments recorded). Commit — `docs: legacy-TypeObject Connext gating achieved — compatible matches, incompatible rejected (completes ADR 0010)`.

---

## Self-review notes

- **Spec coverage:** §4 components → tokenizer (Task 1.1), interpreter (Stages 2–4), diff tool (0.3/1.5), corpus harness (0.1/0.2), DCPS wiring (5.1). §6 RE method → the per-task experiment+provenance discipline, stated in the header and every Stage 2–4 task. §7 guards → Task 1.1 specials + bounds + Task 1.2 fuzz. §8 DoD → byte-exact corpus (Stages 1–4 tests), fuzz (1.2), assignability (2.4/3.2), live both-ways (6.1). §9 stages → Stages 0–6 one-to-one. §2 decisions: fail-open enforced in 5.1 + 6.1; full-scope-degrading in Stage 4's `:unsupported` rule; offline+live DoD in Stages 1–4 + 6.
- **Capture-driven literals (the one honest exception to "no placeholders"):** the byte vectors in Stages 1–4 tests are produced by Task 0.1's pipeline during execution and embedded then — the *procedure* is fully specified; the bytes are outputs, not undecided design. Flagged in the header so the executor and the subagent-driven controller embed real captures rather than inventing values.
- **Type consistency:** `tokenize-legacy-type-object`/`%lto-read-node`/`lto-node`, `parse-legacy-type-object` (→ `minimal-struct-type`|`:unsupported`|`NIL`), the three `*lto-*` specials, `run-corpus-capture-subscriber`, `lto-diff` used consistently across tasks. The interpreter reuses `make-minimal-struct-type`/`make-struct-member`/`primitive-/sequence-/hash-type-identifier`/`struct-assignable-from` (existing) — no new model.
- **Open dependency to verify at execution:** the exact legacy framing (Task 1.1 Step 2) and the nested-struct reference mechanism (Task 3.2 Step 1) are the two highest-uncertainty decodes — both are explicit capture experiments with the observed leads (the `01 7f 08 00` containers, the 8-byte hashes) noted, and both fail open if they resist.
- **Scope guard:** Stage 4 constructs degrade to `:unsupported` rather than block; the gate never rejects on a non-model result; the live test must show zero false-rejects.
