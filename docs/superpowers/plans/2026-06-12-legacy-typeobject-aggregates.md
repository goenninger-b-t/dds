# Legacy-TypeObject Aggregate Gating (enum + array + union) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make a struct carrying an enum, array, or union member gate **structurally** against a live Connext peer (FR-TYPE-4) instead of always fail-open name-matching, by giving each aggregate a real XTypes TypeIdentifier, a sound spec-grounded assignability rule, and clean-room legacy-0x8021 decode — verified against the live Connext corpus.

**Architecture:** Three vertical slices (enum → array → union). Each adds: (1) a TypeIdentifier kind / in-memory referenced descriptor in `xtypes.lisp`; (2) a **sound** assignability rule in `assignability.lisp` (rejects only on *provable* incompatibility, else assignable — preserving fail-open); (3) clean-room legacy decode in `legacy-type-object.lisp` reverse-engineered via `lto-diff` against the corpus capture; (4) a corpus-locked test. The DCPS gate is unchanged — its `struct-assignable-from` recurses into the new TIs.

**Tech Stack:** Common Lisp (`defun*`/`defstruct*` per the operating contract; full ftype declarations), the existing `dds.types` model, `tools/legacy-typeobject-diff.lisp` (`lto-diff`), the live captures in `src/dds-tests/legacy-typeobject-test.lisp`. Spec: `docs/superpowers/specs/2026-06-12-legacy-typeobject-aggregates-design.md`.

---

## Standing rules (restate to every subagent)

1. **Clean-room.** RTI's legacy TypeObject is reverse-engineered ONLY from the inflated wire bytes of our own captures via `lto-diff`. Never read RTI source, `rtiddsgen` output, or the GPL Wireshark dissector. Record every newly-pinned offset/constant in `docs/provenance.md` with the differential that established it.
2. **The wire is the oracle.** Never invent a legacy-encoding offset or constant from memory. Each decode field is pinned by diffing the aggregate's capture against the base `C_Shape` (or a sibling) and cross-checking the IDL ground truth (the literal values, the array size, the union cases are known from `interop/connext/typeobject-corpus/Corpus.idl`).
3. **Fail-open is the cardinal invariant.** Any member whose legacy node cannot be fully + safely decoded → the member is unmodelable → the WHOLE parse degrades to `:unsupported` (the existing degrade tier). Each assignability rule rejects ONLY on a provable spec incompatibility; when uncertain it returns assignable. A wrong reject (breaking a working Connext match) is the worst outcome — worse than a missed gate.
4. **Bounds-check every legacy-wire read FIRST** (NFR-SEC-POSTURE), before any arithmetic on the value, exactly as the existing `%lto-*` helpers do (check against the node's VALUE-END / the buffer length).
5. Lisp: `defun*`/`defstruct*` with full `(function (...) ...)` ftype declarations; docstrings on every exported symbol; one-line comments only, each wire decision citing the provenance differential or the spec clause; no reader conditionals outside `dds-pal/`.
6. Suite green per task on SBCL (`make test-sbcl`, currently **93**); Clasp at each stage boundary (`GC_DONT_GC=1 make test-clasp`, one retry on the known flake — see clasp-developers/clasp#1793). `make gate-types` + `make gate-hotpath` green (these files are control-plane).
7. **Every commit message is PRESENTED TO THE OWNER FOR APPROVAL before `git commit`.** No AI attribution anywhere; no AI-assistant attribution in any repo file; cite "the operating contract", never a config filename.
8. Docs in lockstep (operating contract §5.1): a changed/added exported symbol updates its docstring + `docs/wiki/type-system.md` + `README.md` if status shifts; `docs/verification.csv` FR-TYPE-4 updated per stage; `docs/provenance.md` gets each differential.

## Reference: the code you are extending

- **Member-TI dispatch** — `%lto-member-type-identifier` (`src/dds-types/legacy-type-object.lisp`): a `cond` on the member-kind u16 at member-node `VALUE-START+8`. Today: string `+lto-member-kind-string+` 0x13, sequence 0x12, struct 0x16, else primitive via `*lto-primitive-kind-keyword*`, else NIL. You add enum/array/union arms here.
- **Degrade tier** — a member with a present kind word (`%lto-member-has-kind-p`) but a NIL TI is unmodelable → whole parse `:unsupported`. Flipping an aggregate out of the gap = making its arm return a real TI for the modelable case (and NIL for the not-safely-decodable case, which keeps it in the degrade tier).
- **Def-node resolution** — `%lto-find-def-node octets root member-node def-code` resolves a member's 8-octet type-hash@`VALUE-START+16` to the sibling definition node with that code; `%lto-def-child-u16/u32 octets def-node child-code` reads a u16/u32 from a named child. Strings use `+lto-code-string-def+` 8 / `+lto-code-string-bound+` 200; sequences `+lto-code-sequence-def+` 7 / `+lto-code-sequence-element+` 100; structs `+lto-code-struct+` 9. Enum/array/union def-codes are NEW (RE-discovered).
- **Model** — `src/dds-types/xtypes.lisp`: `type-identifier` defstruct (slots `kind`/`bound`/`element`/`hash`/`referenced`); `primitive-type-identifier`, `string8-type-identifier`, `sequence-type-identifier`, `hash-type-identifier ek :referenced ...`. Kind octets: `+ek-minimal+` 0xf1, `+ti-string8-small/large+` 0x70/0x71, `+ti-plain-sequence-small/large+` 0x80/0x81. `minimal-struct-type`/`-member` are the referenced descriptors for structs.
- **Assignability** — `src/dds-types/assignability.lisp`: `ti-assignable-from t1 t2 opts` (the `cond` you extend), `strongly-assignable-from`, `struct-assignable-from`, `ti-aggregated-p` (true for EK_* kinds). The EK_* branch currently calls `struct-assignable-from` on `(type-identifier-referenced ...)` unconditionally — you make it **dispatch by referenced descriptor type**.
- **Tests** — `src/dds-tests/legacy-typeobject-test.lisp` holds the captures (`%lto-connext-c-enum-lb` 208 B, `%lto-connext-c-array-lb` 200 B, `%lto-connext-c-union-lb` 232 B) and `run-lto-*-test` functions; register new tests in the alist in `src/dds-tests/echo-test.lisp`. Run one test directly:
  `./scripts/with-sbcl.sh --eval '(asdf:load-system :dds-tests)' --eval '(print (dds.tests::run-lto-parse-enum-test))' --eval '(uiop:quit 0)'`

---

## Stage S0 — Enum

### Task 0.1: Enum model — `minimal-enumerated-type` + `enumerated-type-identifier`

**Files:**
- Modify: `src/dds-types/xtypes.lisp`
- Modify: `src/dds-types/packages.lisp` (export the new symbols)
- Test: `src/dds-tests/xtypes-test.lisp` (or the file holding the existing `xtypes-assignability` model unit test — grep `run-xtypes-assignability-test` to confirm the file, then co-locate)

- [ ] **Step 1: Write the failing test.** Add to the model test file a check that the constructor builds the expected structure:

```lisp
(defun* run-enum-model-test ()
    (function () t)
  "minimal-enumerated-type + enumerated-type-identifier build an EK_MINIMAL TI whose
   referenced descriptor carries the literals (NameHash . value) and bit-bound."
  (let* ((lits (list (dds.types:make-enum-literal "RED" 0)
                     (dds.types:make-enum-literal "GREEN" 1)
                     (dds.types:make-enum-literal "BLUE" 2)))
         (e (dds.types:make-minimal-enumerated-type :bit-bound 32 :literals lits))
         (ti (dds.types:enumerated-type-identifier e)))
    (assert (= (dds.types:type-identifier-kind ti) dds.types:+ek-minimal+))
    (assert (dds.types:minimal-enumerated-type-p (dds.types:type-identifier-referenced ti)))
    (assert (= 3 (length (dds.types:minimal-enumerated-type-literals
                          (dds.types:type-identifier-referenced ti)))))
    (assert (= 1 (dds.types:enum-literal-value
                  (second (dds.types:minimal-enumerated-type-literals
                           (dds.types:type-identifier-referenced ti))))))
    t))
```

Register it in `src/dds-tests/echo-test.lisp` (alist, e.g. `("enum-model" . run-enum-model-test)`).

- [ ] **Step 2: Run it, expect failure** (`make test-sbcl`): undefined `make-minimal-enumerated-type` etc.

- [ ] **Step 3: Implement the model** in `xtypes.lisp` (place near `minimal-struct-member`/`minimal-struct-type`):

```lisp
;;; ---- Enumerated type (idl §XX MinimalEnumeratedType; in-memory descriptor) ----

(defstruct* (enum-literal (:constructor %make-enum-literal) (:copier nil))
  "One enumerated literal: NAME-HASH is the 4-octet NameHash (MD5(name)[0:4]) matched
   across types (the Minimal form carries only the hash); VALUE is the i32 constant."
  (name-hash (make-array 4 :element-type '(unsigned-byte 8)) :type (array (unsigned-byte 8) (4)))
  (value 0 :type (signed-byte 32)))

(defun* make-enum-literal (name value)
    (function (string (signed-byte 32)) enum-literal)
  "An enum-literal for NAME (its NameHash computed via member-name-hash) and VALUE."
  (%make-enum-literal :name-hash (member-name-hash name) :value value))

(defstruct* (minimal-enumerated-type (:constructor make-minimal-enumerated-type) (:copier nil))
  "In-memory MinimalEnumeratedType: BIT-BOUND (the storage bit width, default 32) and
   LITERALS (a list of enum-literal). The referenced descriptor of an EK_MINIMAL enum TI."
  (bit-bound 32 :type (integer 1 64))
  (literals nil :type list))

(defun* enumerated-type-identifier (enum)
    (function (minimal-enumerated-type) type-identifier)
  "An EK_MINIMAL TypeIdentifier whose REFERENCED descriptor is ENUM, so assignability
   (FR-TYPE-4) recurses into it ahead of the deferred EquivalenceHash — the same in-memory
   referenced pattern nested structs use (hash-type-identifier)."
  (hash-type-identifier +ek-minimal+ :referenced enum))
```

Confirm `member-name-hash` is exported/visible in `xtypes.lisp` (it is used for struct members). Export `enum-literal`, `make-enum-literal`, `enum-literal-value`, `enum-literal-name-hash`, `minimal-enumerated-type`, `minimal-enumerated-type-p`, `make-minimal-enumerated-type`, `minimal-enumerated-type-literals`, `minimal-enumerated-type-bit-bound`, `enumerated-type-identifier` from `packages.lisp` (`dds.types`).

- [ ] **Step 4: Run it, expect pass** (`make test-sbcl` → 94).

- [ ] **Step 5: Commit** (present message; suggested):
```
feat(types): in-memory MinimalEnumeratedType + enumerated-type-identifier (FR-TYPE-4 S0)

Enum descriptor (bit-bound + literals as NameHash/value) wrapped in an
EK_MINIMAL TypeIdentifier via the referenced-descriptor pattern, so
assignability can recurse into enums. Model only; assignability + legacy
decode follow.
```

### Task 0.2: Enum assignability — sound rule + EK dispatch

**Files:**
- Modify: `src/dds-types/assignability.lisp`
- Modify: `src/dds-types/packages.lisp` (export `enum-assignable-from` if cross-package tests need it)
- Test: the model test file (add `run-enum-assignability-test`)

- [ ] **Step 1: Pin the clause.** `pdftotext docs/specs/xtypes-1_3.pdf - | less` — find the enumerated-type assignability rule (§7.2.4.4, the Enumeration row/Table). Confirm the **provable-incompatibility** core: two literals with the **same name** must have the **same value**; record the exact clause number in a code comment.

- [ ] **Step 2: Write the failing test:**

```lisp
(defun* run-enum-assignability-test ()
    (function () t)
  "enum-assignable-from rejects ONLY a provable incompatibility (same literal name,
   different value); identical enums are assignable both ways; a differing-value enum
   is not; an enum vs a non-enum aggregated type is not."
  (flet ((enum (&rest pairs)
           (make-minimal-enumerated-type
            :bit-bound 32
            :literals (loop for (n v) on pairs by #'cddr
                            collect (make-enum-literal n v)))))
    (let ((a (enum "RED" 0 "GREEN" 1 "BLUE" 2))
          (same (enum "RED" 0 "GREEN" 1 "BLUE" 2))
          (badval (enum "RED" 0 "GREEN" 1 "BLUE" 3))
          (opts (default-assignability-options)))
      (assert (enum-assignable-from a same opts))
      (assert (enum-assignable-from same a opts))
      (assert (not (enum-assignable-from a badval opts)))
      (assert (not (enum-assignable-from badval a opts)))
      ;; extra-literal-on-one-side is UNCERTAIN -> assignable (fail-open, no false reject)
      (assert (enum-assignable-from a (enum "RED" 0 "GREEN" 1) opts))
      t)))
```

Register `("enum-assignability" . run-enum-assignability-test)`.

- [ ] **Step 3: Run it, expect failure** (undefined `enum-assignable-from`).

- [ ] **Step 4: Implement** in `assignability.lisp`:

```lisp
;;; ---- Enumerated assignability (XTypes §7.2.4.4 enumerated row) ----

(defun* enum-assignable-from (t1 t2 opts)
    (function (minimal-enumerated-type minimal-enumerated-type assignability-options) t)
  "Sound under-approximation of enumerated is-assignable-from (§7.2.4.4): returns NIL only
   on a PROVABLE incompatibility — two literals sharing a NameHash but carrying different
   values (the spec forbids same-name/different-value). Literals present on only one side are
   uncertain (try_construct/must_understand are not on the legacy wire) and DO NOT cause a
   reject (fail-open: never false-reject a possibly-assignable pair). OPTS is accepted for
   signature uniformity."
  (declare (ignore opts))
  (loop for l1 in (minimal-enumerated-type-literals t1)
        always (let ((l2 (find (enum-literal-name-hash l1)
                               (minimal-enumerated-type-literals t2)
                               :key #'enum-literal-name-hash :test #'equalp)))
                 (or (null l2)
                     (= (enum-literal-value l1) (enum-literal-value l2))))))
```

Then make `ti-assignable-from`'s EK_* branch **dispatch by referenced type**. Replace:

```lisp
    ((and (ti-aggregated-p t1) (ti-aggregated-p t2))
     (struct-assignable-from (type-identifier-referenced t1)
                             (type-identifier-referenced t2) opts))
```

with:

```lisp
    ((and (ti-aggregated-p t1) (ti-aggregated-p t2))
     (let ((r1 (type-identifier-referenced t1))
           (r2 (type-identifier-referenced t2)))
       (cond
         ((and (minimal-struct-type-p r1) (minimal-struct-type-p r2))
          (struct-assignable-from r1 r2 opts))
         ((and (minimal-enumerated-type-p r1) (minimal-enumerated-type-p r2))
          (enum-assignable-from r1 r2 opts))
         (t nil))))                      ; mismatched referenced kinds (enum vs struct) not assignable
```

(Array and union add their predicates to this `cond` in S1/S2.)

- [ ] **Step 5: Run it, expect pass** (`make test-sbcl` → 95). Confirm the pre-existing `xtypes-assignability` + `lto-assignability` tests still pass (the dispatch refactor must not change struct behavior).

- [ ] **Step 6: Commit** (present message):
```
feat(types): sound enumerated assignability + EK-referenced dispatch (FR-TYPE-4 S0)

enum-assignable-from rejects only a provable same-name/different-value
contradiction (§7.2.4.4); uncertain cases stay assignable (fail-open).
ti-assignable-from's EK_* branch now dispatches by referenced descriptor
(struct vs enum; array/union later); mismatched kinds not assignable.
Struct path unchanged (xtypes-assignability/lto-assignability green).
```

### Task 0.3: Legacy enum decode — RE the def-node + wire flip + corpus test

**Files:**
- Modify: `src/dds-types/legacy-type-object.lisp`
- Modify: `docs/provenance.md` (the C_Enum differential)
- Test: `src/dds-tests/legacy-typeobject-test.lisp` (+ register in `echo-test.lisp`)

- [ ] **Step 1: Reverse-engineer the enum def-node (RE-discovery; the wire is the oracle).** Run `lto-diff` on the C_Enum capture vs base, and inspect the inflated tree, to pin: (a) the enum member-kind word at `VALUE-START+8` (the corpus README says enum = `+lto-member-kind-enum+` 0x0E — confirm); (b) the def-node CODE the enum member's hash@+16 references (call it `+lto-code-enum-def+`); (c) within that def-node, how literals are listed (the child CODE that holds each literal's name + value, and the offsets of the value and the name). The IDL ground truth: `SomeEnum { RED=0, GREEN=1, BLUE=2 }` — the decoded literals MUST come out RED/0, GREEN/1, BLUE/2. Use the lto tool:

```bash
./scripts/with-sbcl.sh --eval '(asdf:load-system :dds-tests)' \
  --eval '(load "tools/legacy-typeobject-diff.lisp")' \
  --eval '(lto-diff (dds.tests::%lto-connext-c-shape-lb) (dds.tests::%lto-connext-c-enum-lb))' \
  --eval '(uiop:quit 0)'
```

(Confirm the base accessor name with `grep "%lto-connext-c-shape-lb\|%lto-connext-shape" src/dds-tests/legacy-typeobject-test.lisp`; if absent, diff C_Enum against C_Nested or read the inflated C_Enum tree directly via the tokenizer.) **Record every pinned offset/CODE in `docs/provenance.md`** under a dated "C_Enum legacy enum def-node" entry, with the differential bytes that establish each.

- [ ] **Step 2: Write the failing corpus test** in `legacy-typeobject-test.lisp`:

```lisp
(defun* run-lto-enum-assignability-test ()
    (function () t)
  "The live C_Enum legacy TypeObject parses to a minimal-struct-type whose `e` member is a
   real EK_MINIMAL enum TI (SomeEnum RED=0/GREEN=1/BLUE=2), and struct-assignable-from gates:
   a matching local model is assignable both ways; a local whose enum changes BLUE's value is
   not; the no-false-reject re-run holds."
  (let* ((lb (%lto-connext-c-enum-lb))
         (inflated (dds.types:inflate-type-object-lb lb))
         (parsed (dds.types:parse-legacy-type-object inflated)))
    (assert (dds.types:minimal-struct-type-p parsed))     ; NOT :unsupported anymore
    (let* ((opts (dds.types:default-assignability-options))
           (good (%build-c-enum-local :blue 2))           ; helper: builds @key long id; SomeEnum e
           (bad  (%build-c-enum-local :blue 3)))
      (assert (dds.types:struct-assignable-from parsed good opts))
      (assert (dds.types:struct-assignable-from good parsed opts))
      (assert (not (dds.types:struct-assignable-from parsed bad opts)))
      (assert (not (dds.types:struct-assignable-from bad parsed opts)))
      t)))
```

Write `%build-c-enum-local` next to it: build a `minimal-struct-type` named "C_Enum" with members `id` (i32, @key) and `e` (an `enumerated-type-identifier` over `SomeEnum`), member ids per the corpus (0,1). The enum literal NameHashes come from `make-enum-literal "RED" 0` etc. — the SAME hashes the parsed wire model carries (name-erased models match by NameHash). Register `("lto-enum-assignability" . run-lto-enum-assignability-test)`.

- [ ] **Step 3: Run it, expect failure** — `parsed` is currently `:unsupported`, so `minimal-struct-type-p` fails.

- [ ] **Step 4: Implement the decode** in `legacy-type-object.lisp`. Add the RE-pinned constants:

```lisp
(defconstant +lto-member-kind-enum+ #x0E
  "RTI legacy member-kind word (member node VALUE-START+8) for an ENUM member.
   Pinned clean-room from the C_Enum differential (docs/provenance.md).")
(defconstant +lto-code-enum-def+ <RE-DISCOVERED>
  "RTI legacy TypeLibrary CODE for an enum definition node. Pinned from the C_Enum
   differential (docs/provenance.md).")
;; + any literal-list child CODE / offset constants the RE established.
```

Add an `%lto-enum-type-identifier octets root member-node` that resolves the enum def-node (`%lto-find-def-node ... +lto-code-enum-def+`), walks its literal children into `enum-literal`s (each bounds-checked FIRST), builds `make-minimal-enumerated-type` + `enumerated-type-identifier`, and returns NIL (→ degrade) if the def-node, any literal field, or the value/name is missing or OOB. Then add the arm to `%lto-member-type-identifier`'s `cond`:

```lisp
      ((= kind +lto-member-kind-enum+)
       (%lto-enum-type-identifier octets root node))
```

- [ ] **Step 5: Run it, expect pass.** Also confirm `run-lto-unmodelable-unsupported-test` / `run-lto-parse-aggregates-unsupported-test` still pass for the cases they cover, and UPDATE them: the C_Enum case there asserted `:unsupported`; it must now assert the parsed struct (or be moved to the new test). Edit those assertions so the suite reflects that enum is no longer unmodelable. `make test-sbcl` → green.

- [ ] **Step 6: Update docs** — `docs/verification.csv` FR-TYPE-4 (enum now structural, cite the test + the C_Enum capture), `docs/wiki/type-system.md` (enum decode + assignability), `README.md` if the P3 status line enumerates the gaps.

- [ ] **Step 7: Clasp at the S0 boundary** — `GC_DONT_GC=1 make test-clasp` (one retry on the flake). `make gate-types gate-hotpath`.

- [ ] **Step 8: Commit** (present message):
```
feat(types): legacy-TypeObject enum members gate structurally (FR-TYPE-4 S0)

Clean-room-decoded the RTI legacy enum def-node (literals + values,
C_Enum differential in provenance) into a real EK_MINIMAL enum TI;
%lto-member-type-identifier flips enum (0x0E) out of the degrade tier.
Live C_Enum now gates: compatible local -> assignable both ways, a
changed enumerator value -> not assignable, no false-reject on re-run
(test lto-enum-assignability). Unmodelable-aggregate tests updated.
verification.csv/wiki/README lockstep. NN green SBCL+Clasp.
```

---

## Stage S1 — Array

### Task 1.1: Array model — plain-array TypeIdentifier

**Files:** Modify `src/dds-types/xtypes.lisp`, `src/dds-types/packages.lisp`; Test: the model test file.

- [ ] **Step 1: Failing test:**

```lisp
(defun* run-array-model-test ()
    (function () t)
  "array-type-identifier builds a plain-array TI carrying the element TI and the fixed size."
  (let ((ti (dds.types:array-type-identifier (dds.types:primitive-type-identifier :i32) 4)))
    (assert (dds.types:ti-array-p ti))
    (assert (= 4 (dds.types:type-identifier-bound ti)))
    (assert (= dds.types:+tk-int32+ (dds.types:type-identifier-kind
                                     (dds.types:type-identifier-element ti))))
    t))
```

Register `("array-model" . run-array-model-test)`.

- [ ] **Step 2: Run, expect failure** (undefined `array-type-identifier`/`ti-array-p`).

- [ ] **Step 3: Implement** in `xtypes.lisp` (near the sequence constructor):

```lisp
(defconstant +ti-plain-array-small+ #x90
  "XTypes TypeIdentifierKind octet TI_PLAIN_ARRAY_SMALL (idl §56-70): fixed array, SBound dims.")
(defconstant +ti-plain-array-large+ #x91)

(defun* array-type-identifier (element size)
    (function (type-identifier (integer 1)) type-identifier)
  "A plain ARRAY TypeIdentifier with ELEMENT element TI and a single fixed dimension SIZE
   (the corpus oracle covers 1-D arrays; multi-dim is a documented decode gap that fails open).
   SMALL when SIZE <= 255, else LARGE (the 255 threshold of idl §56-70, as for strings)."
  (%make-type-identifier :kind (if (> size 255) +ti-plain-array-large+ +ti-plain-array-small+)
                         :bound size :element element))
```

Add to `assignability.lisp` (it needs the predicate) or `xtypes.lisp` an exported `ti-array-p`:

```lisp
(defun* ti-array-p (ti)
    (function (type-identifier) t)
  "True if TI is a plain array (TI_PLAIN_ARRAY_SMALL/LARGE)."
  (let ((k (type-identifier-kind ti)))
    (or (= k +ti-plain-array-small+) (= k +ti-plain-array-large+))))
```

(Place `ti-array-p` beside `ti-sequence-p` in `assignability.lisp` for cohesion; export from `dds.types`.) Export `+ti-plain-array-small+`, `+ti-plain-array-large+`, `array-type-identifier`, `ti-array-p`.

- [ ] **Step 4: Run, expect pass.** **Step 5: Commit** (present message: "feat(types): plain-array TypeIdentifier (FR-TYPE-4 S1) — model only").

### Task 1.2: Array assignability — element strongly-assignable + identical size

**Files:** Modify `src/dds-types/assignability.lisp`; Test: model test file.

- [ ] **Step 1: Failing test:**

```lisp
(defun* run-array-assignability-test ()
    (function () t)
  "Arrays are assignable iff element strongly-assignable AND identical fixed size (arrays are
   not resizable). A different size or element kind is a provable incompatibility."
  (let ((opts (default-assignability-options))
        (a (array-type-identifier (primitive-type-identifier :i32) 4)))
    (assert (ti-assignable-from a (array-type-identifier (primitive-type-identifier :i32) 4) opts))
    (assert (not (ti-assignable-from a (array-type-identifier (primitive-type-identifier :i32) 5) opts)))
    (assert (not (ti-assignable-from a (array-type-identifier (primitive-type-identifier :i64) 4) opts)))
    t))
```

Register `("array-assignability" . run-array-assignability-test)`.

- [ ] **Step 2: Run, expect failure** (the array branch doesn't exist; `ti-assignable-from` falls to `(t nil)` — the SAME-SIZE case fails).

- [ ] **Step 3: Implement** — add a branch to `ti-assignable-from`'s `cond`, **before** the `(t nil)`:

```lisp
    ((and (ti-array-p t1) (ti-array-p t2))
     (let ((e1 (type-identifier-element t1)) (e2 (type-identifier-element t2)))
       (and e1 e2
            (= (type-identifier-bound t1) (type-identifier-bound t2))   ; identical dims; no ignore_bounds
            (strongly-assignable-from e1 e2 opts)
            t)))
```

Also extend `ti-delimited-p` if arrays can be collection elements/keys (an array is delimited iff its element is — mirror the sequence clause); add `((ti-array-p ti) (ti-delimited-p (type-identifier-element ti)))` to `ti-delimited-p`.

- [ ] **Step 4: Run, expect pass.** **Step 5: Commit** (present message: "feat(types): array assignability — element strongly-assignable + identical size (FR-TYPE-4 S1)").

### Task 1.3: Legacy array decode — RE + wire flip + corpus test

**Files:** Modify `src/dds-types/legacy-type-object.lisp`, `docs/provenance.md`; Test: `legacy-typeobject-test.lisp` (+ `echo-test.lisp`); docs lockstep.

- [ ] **Step 1: RE the array def-node** (wire is the oracle). `lto-diff` C_Array vs base; pin: array member-kind 0x11 at `VALUE-START+8` (confirm `+lto-member-kind-array+`); the def-node CODE (`+lto-code-array-def+`); within it, the element type-kind (a u16, mapped via `*lto-primitive-kind-keyword*` — C_Array's element is `long`) and the dimension(s) (`long arr[4]` → a single bound 4; pin where the bound u32 lives and how a dims-count is encoded). IDL ground truth: element i32, size 4, 1 dimension. **Record in `docs/provenance.md`.** A capture showing >1 dimension, or a non-primitive element, → return NIL (decode gap, fail-open).

- [ ] **Step 2: Failing corpus test** (`run-lto-array-assignability-test`): parse `%lto-connext-c-array-lb` → a `minimal-struct-type` whose `arr` member is `array-type-identifier(i32, 4)`; a matching local model assignable both ways; a local with `arr[5]` or `short arr[4]` not; no false-reject re-run. Build the local with a `%build-c-array-local` helper. Register the test.

- [ ] **Step 3: Run, expect failure** (`parsed` is `:unsupported`).

- [ ] **Step 4: Implement** — add `+lto-member-kind-array+` 0x11, `+lto-code-array-def+` `<RE>`, an `%lto-array-type-identifier octets root member-node` (resolve def-node; read element-kind via `*lto-primitive-kind-keyword*`; read the single dimension u32; build `array-type-identifier`; NIL on OOB / multi-dim / non-primitive element / missing fields — all bounds-checked first), and the arm:

```lisp
      ((= kind +lto-member-kind-array+)
       (%lto-array-type-identifier octets root node))
```

- [ ] **Step 5: Run, expect pass;** update `run-lto-parse-aggregates-unsupported-test` (the C_Array case no longer `:unsupported`). `make test-sbcl` green.

- [ ] **Step 6: Docs lockstep** (verification.csv FR-TYPE-4, wiki, README). **Step 7: Clasp boundary** (`GC_DONT_GC=1 make test-clasp`; gate-types/gate-hotpath). **Step 8: Commit** (present message, mirroring S0's enum commit for array).

---

## Stage S2 — Union + closeout

### Task 2.1: Union model — `minimal-union-type` + `union-type-identifier`

**Files:** Modify `src/dds-types/xtypes.lisp`, `src/dds-types/packages.lisp`; Test: model test file.

- [ ] **Step 1: Failing test:**

```lisp
(defun* run-union-model-test ()
    (function () t)
  "union-type-identifier builds an EK_MINIMAL TI whose referenced descriptor carries the
   discriminator TI and members (each with labels, member TI, default-p, NameHash)."
  (let* ((m0 (dds.types:make-union-member "a" '(0) (dds.types:primitive-type-identifier :i32) nil))
         (m1 (dds.types:make-union-member "b" '(1) (dds.types:primitive-type-identifier :f64) nil))
         (u (dds.types:make-minimal-union-type
             :discriminator (dds.types:primitive-type-identifier :i32) :members (list m0 m1)))
         (ti (dds.types:union-type-identifier u)))
    (assert (= (dds.types:type-identifier-kind ti) dds.types:+ek-minimal+))
    (assert (dds.types:minimal-union-type-p (dds.types:type-identifier-referenced ti)))
    (assert (equal '(0) (dds.types:union-member-labels
                         (first (dds.types:minimal-union-type-members
                                 (dds.types:type-identifier-referenced ti))))))
    t))
```

Register `("union-model" . run-union-model-test)`.

- [ ] **Step 2: Run, expect failure.**

- [ ] **Step 3: Implement** in `xtypes.lisp`:

```lisp
;;; ---- Union type (idl §XX MinimalUnionType; in-memory descriptor) ----

(defstruct* (union-member (:constructor %make-union-member) (:copier nil))
  "One union member: NAME-HASH (4-octet NameHash), LABELS (list of i32 case labels),
   TYPE-IDENTIFIER (the member's type), DEFAULT-P (T iff the `default:` member)."
  (name-hash (make-array 4 :element-type '(unsigned-byte 8)) :type (array (unsigned-byte 8) (4)))
  (labels nil :type list)
  (type-identifier nil :type (or null type-identifier))
  (default-p nil :type boolean))

(defun* make-union-member (name labels type-identifier default-p)
    (function (string list (or null type-identifier) t) union-member)
  "A union-member for NAME (NameHash via member-name-hash), case LABELS, TYPE-IDENTIFIER,
   and DEFAULT-P."
  (%make-union-member :name-hash (member-name-hash name) :labels labels
                      :type-identifier type-identifier :default-p (and default-p t)))

(defstruct* (minimal-union-type (:constructor make-minimal-union-type) (:copier nil))
  "In-memory MinimalUnionType: DISCRIMINATOR (a TypeIdentifier) and MEMBERS (union-member list).
   The referenced descriptor of an EK_MINIMAL union TI."
  (discriminator nil :type (or null type-identifier))
  (members nil :type list))

(defun* union-type-identifier (union)
    (function (minimal-union-type) type-identifier)
  "An EK_MINIMAL TypeIdentifier whose REFERENCED descriptor is UNION (the referenced pattern)."
  (hash-type-identifier +ek-minimal+ :referenced union))
```

Export the new symbols from `packages.lisp`.

- [ ] **Step 4: Run, expect pass. Step 5: Commit** (present message: "feat(types): in-memory MinimalUnionType + union-type-identifier (FR-TYPE-4 S2) — model only").

### Task 2.2: Union assignability — sound §7.2.4.5 under-approximation

**Files:** Modify `src/dds-types/assignability.lisp`; Test: model test file.

- [ ] **Step 1: Pin §7.2.4.5** (`pdftotext`). Record the clause. The sound core: discriminator types assignable; for members selected by the **same label**, the member types must be assignable — a same-label/different-(non-assignable)-type is a **provable** incompatibility. Members/labels unique to one side and default-member subtleties are **uncertain** → do not reject (fail-open).

- [ ] **Step 2: Failing test:**

```lisp
(defun* run-union-assignability-test ()
    (function () t)
  "union-assignable-from rejects only a provable incompatibility: a label present in both whose
   member types are not assignable (or discriminators not assignable). Identical unions are
   assignable both ways; a changed case-0 member type is not; label-set differences are uncertain
   (assignable, fail-open)."
  (flet ((u (disc &rest ms)
           (make-minimal-union-type :discriminator disc :members ms)))
    (let* ((opts (default-assignability-options))
           (i32 (primitive-type-identifier :i32)) (f64 (primitive-type-identifier :f64))
           (a (u i32 (make-union-member "a" '(0) i32 nil) (make-union-member "b" '(1) f64 nil)))
           (same (u i32 (make-union-member "a" '(0) i32 nil) (make-union-member "b" '(1) f64 nil)))
           (bad  (u i32 (make-union-member "a" '(0) f64 nil) (make-union-member "b" '(1) f64 nil))))
      (assert (union-assignable-from a same opts))
      (assert (union-assignable-from same a opts))
      (assert (not (union-assignable-from a bad opts)))
      (assert (not (union-assignable-from bad a opts)))
      t)))
```

Register `("union-assignability" . run-union-assignability-test)`.

- [ ] **Step 3: Run, expect failure.**

- [ ] **Step 4: Implement** in `assignability.lisp`:

```lisp
;;; ---- Union assignability (XTypes §7.2.4.5), sound under-approximation ----

(defun* union-assignable-from (t1 t2 opts)
    (function (minimal-union-type minimal-union-type assignability-options) t)
  "Sound under-approximation of union is-assignable-from (§7.2.4.5): returns NIL only on a
   PROVABLE incompatibility — discriminators not assignable, OR two members selected by a common
   case label whose member types are not assignable. Label-set differences and default-member
   subtleties are uncertain (try_construct not on the legacy wire) and do not cause a reject
   (fail-open). Members are matched by shared case LABEL."
  (let ((d1 (minimal-union-type-discriminator t1))
        (d2 (minimal-union-type-discriminator t2)))
    (and d1 d2 (ti-assignable-from d1 d2 opts)
         (loop for m1 in (minimal-union-type-members t1)
               always (loop for m2 in (minimal-union-type-members t2)
                            always (or (null (intersection (union-member-labels m1)
                                                           (union-member-labels m2)))
                                       (let ((mt1 (union-member-type-identifier m1))
                                             (mt2 (union-member-type-identifier m2)))
                                         (and mt1 mt2 (ti-assignable-from mt1 mt2 opts) t))))))))
```

Add the union dispatch to `ti-assignable-from`'s EK_* `cond` (next to enum):

```lisp
         ((and (minimal-union-type-p r1) (minimal-union-type-p r2))
          (union-assignable-from r1 r2 opts))
```

- [ ] **Step 5: Run, expect pass.** Confirm enum/struct/array tests still green. **Step 6: Commit** (present message: "feat(types): sound union assignability §7.2.4.5 + EK dispatch (FR-TYPE-4 S2)").

### Task 2.3: Legacy union decode — RE (the largest) + wire flip + corpus test

**Files:** Modify `src/dds-types/legacy-type-object.lisp`, `docs/provenance.md`; Test: `legacy-typeobject-test.lisp` (+ `echo-test.lisp`); docs lockstep.

- [ ] **Step 1: RE the union def-node** (the largest RE — budget for it). `lto-diff` C_Union vs base + read the inflated tree. Pin: union member-kind 0x15 at `VALUE-START+8`; the union def-node CODE (`+lto-code-union-def+`); within it the discriminator type-kind and, per case, the label (i32) and the member type-kind. IDL ground truth: `union SomeUnion switch(long) { case 0: long a; case 1: double b; }` — discriminator i32; member `a` label 0 type i32; member `b` label 1 type f64. Decode ONLY what is safely pinnable; anything not (default member, nested-aggregate members, multi-label cases not present in the capture) → return NIL → fail-open. **Record the full differential in `docs/provenance.md`.**

- [ ] **Step 2: Failing corpus test** (`run-lto-union-assignability-test`): parse `%lto-connext-c-union-lb` → a `minimal-struct-type` whose `u` member is a `union-type-identifier` over SomeUnion(disc i32; {0→i32, 1→f64}); a matching local model assignable both ways; a local where case 0 is `double` not assignable; no false-reject re-run. `%build-c-union-local` helper. Register the test.

- [ ] **Step 3: Run, expect failure.**

- [ ] **Step 4: Implement** — `+lto-member-kind-union+` 0x15, `+lto-code-union-def+` `<RE>`, `%lto-union-type-identifier octets root member-node` (resolve def-node; read discriminator kind; per case read label + member-kind via `*lto-primitive-kind-keyword*`; build `make-union-member`/`make-minimal-union-type`/`union-type-identifier`; NIL — fail-open — on any OOB, a non-primitive discriminator/member, a default member, or any field the RE could not safely pin), and the arm:

```lisp
      ((= kind +lto-member-kind-union+)
       (%lto-union-type-identifier octets root node))
```

- [ ] **Step 5: Run, expect pass;** update `run-lto-parse-aggregates-unsupported-test` (the C_Union case is now modelable — move it to the new test or change the assertion). Any union shape NOT in the corpus that the decoder can't safely handle must still degrade to `:unsupported`; if you can cheaply construct such a fail-open case, assert it stays `:compatible`. `make test-sbcl` green.

- [ ] **Step 6: Clasp boundary** (`GC_DONT_GC=1 make test-clasp`; gate-types/gate-hotpath). **Step 7: Commit** (present message, mirroring S0 for union, noting the fail-open residue — default-member / nested-aggregate-member / multi-label union shapes stay `:unsupported`).

### Task 2.4: Closeout

**Files:** Modify `docs/verification.csv`, `docs/wiki/type-system.md`, `README.md`, `docs/provenance.md`; memory.

- [ ] **Step 1:** `docs/verification.csv` FR-TYPE-4 — final state: enum + array + union now gate structurally (cite the three corpus tests); the residual fail-open gaps reaffirmed (bitmask — no oracle, rtiddsgen rejects the keyword; map/alias — no corpus driver; multi-dim arrays, union default/nested members — decode gaps that fail open). Confirm wording does not overclaim (these are *sound-rejection* rules; uncertain cases still fail open).
- [ ] **Step 2:** `docs/wiki/type-system.md` — the enum/array/union model + assignability + legacy decode sections, with the fail-open principle stated. `README.md` — the P3/FR-TYPE-4 status line if it enumerates the aggregate gaps.
- [ ] **Step 3:** `docs/provenance.md` — verify all three differentials (enum/array/union def-nodes) are recorded with their pinning bytes.
- [ ] **Step 4:** Full gates: `make build-sbcl test-sbcl gate-types gate-hotpath`; `GC_DONT_GC=1 make test-clasp` once more. Paste tails. **Commit** the closeout (present message).
- [ ] **Step 5:** Update the `dds-stack-position` memory file (aggregate gaps closed; new HEAD; remaining candidates: bitmask when rtiddsgen supports it, map/alias, keyed/no-key endpoint kinds, liveliness/lease expiry, writer-repair pacing). Push held for owner approval.

---

## Self-review notes (run; fixed inline)

- **Spec coverage:** spec §4 units (RE/model/assignability/wire) ↔ each stage's 3 tasks; §3 clauses cited in the assignability tasks (0.2/1.2/2.2 Step 1) + RE tasks; §6 fail-open ↔ the "sound under-approximation" rules + the NIL-on-uncertain decode + the no-false-reject re-run assertions; §7 testing ↔ the per-aggregate corpus tests; §8 stages ↔ S0/S1/S2; bitmask/map/alias residue ↔ Task 2.4 Step 1.
- **Deliberate RE-discovery (not placeholders):** the `<RE-DISCOVERED>` def-node CODE/offset constants in Tasks 0.3/1.3/2.3 Step 1 are pinned at execution time by `lto-diff` against the named corpus capture + the IDL ground truth — each names its authoritative source and its provenance entry. This is the same pattern the prior legacy tasks used; the *structure* (which helper resolves the def-node, which `cond` arm, the test's expected semantics) is fully concrete.
- **Type consistency:** `enumerated-type-identifier`/`make-minimal-enumerated-type`/`make-enum-literal`/`enum-literal-value`/`enum-assignable-from`; `array-type-identifier`/`ti-array-p`; `union-type-identifier`/`make-minimal-union-type`/`make-union-member`/`union-member-labels`/`union-member-type-identifier`/`union-assignable-from` — used consistently across model, assignability, decode, and tests. The EK_* dispatch `cond` in `ti-assignable-from` is extended once per stage (struct→+enum→+union); array uses its own non-EK branch. All reference `default-assignability-options`/`struct-assignable-from`/`strongly-assignable-from`/`ti-delimited-p`, which exist today.
