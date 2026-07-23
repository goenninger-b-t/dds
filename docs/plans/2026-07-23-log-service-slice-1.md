# Distributed logging — slice 1 implementation plan

> **For implementers:** every task ends with an independently testable deliverable and a commit.
> Steps use checkbox (`- [ ]`) syntax. Work them in order; Phase A is a hard prerequisite for Phase B.

**Goal:** `dds.log` emits a structured log event; a collector service subscribing on a configurable
domain renders it to a five-field text file and a newline-delimited JSON file, with TRACE entry/exit
timing, an emit path that never blocks the caller, and severity-graded shedding that is counted and
reported.

**Architecture:** ADR 0082 is the authority — read it before starting. A public `@appendable`
`LogEvent` type (bounded strings, keyed on `host`+`process`) is published by a worker thread draining
a bounded ring that the emit macros fill without blocking; the service reads it and fans out to
replaceable formatter and sink closures.

**Tech stack:** Common Lisp (SBCL + Clasp), ASDF, `dds.gen` type compiler, `dds.dcps`, `dds.pal`.

## Global constraints

These apply to **every** task. They are the operating contract, not preferences.

- **`defun*` / `defstruct*` for every function and struct** (`dds.lang`), with a full `(function (arg-types) return-type)` declaration. See `src/dds-lang/lisp-lang-tools.lisp`.
- **No Lisp conditions anywhere in `src/`.** Fallible functions return `(values result status)`; propagate with `(try form)`, fail with `(bail :status)`. `make gate-nocond` has a ceiling of **0** and must stay there. The only exemptions are the nine annotated `NOCOND(...)` classes — do not invent a tenth.
- **Every exported function, special variable and constant carries a docstring** stating its contract; every wire constant cites its spec clause.
- **Never hardcode a wire constant from memory.** RFC 5424 severity values are read from the RFC and cited at the definition site.
- **Bounds-check everything parsed from the wire**, at `(safety 0)` too.
- **No reader conditionals outside `src/dds-pal/`.** `make gate-pal` enforces it.
- Tests are `run-<name>-test` functions returning `T`, registered in the alist in `run-all-tests` (`src/dds-tests/echo-test.lisp:3678`), and use the `%check` helper (`src/dds-tests/echo-test.lisp:10`).
- **Both implementations must pass**: `make test LISP=./scripts/with-sbcl.sh` and `make test-clasp`, Clasp run first.
- **Never load systems with `ql:quickload`** — it muffles warnings. Use `asdf:load-system`.
- Commit messages are presented for approval before committing; never add AI-attribution trailers.
- **No "Claude"/AI-assistant reference in any repository file.**

---

## File structure

**Phase A — extend the CDR layer and the type compiler** (`src/dds-cdr/`, `src/dds-gen/`)
- Modify `primitives.lisp`: UTF-8 string codec, replacing the Latin-1-only one.
- Modify `dsl.lisp`: bounded strings, enum members, `:appendable` extensibility.

> **Directive, 2026-07-23:** *"Do not model LogEvent around the type compiler deficiencies — extend the
> type compiler!"* Every gap Phase A closes is closed in the compiler and the codec, where every future
> type benefits. Nothing in Phase B works around a missing feature.

**Phase B — the type**
- Create `interop/log/DdsLog.idl` — the IDL foreign publishers are generated from.
- Create `src/dds-log/packages.lisp`, `src/dds-log/event.lisp` — the `LogEvent` type + construction.

**Phase C — emit** (`src/dds-log/`)
- Create `emit.lisp` — category table, level thresholds, ring, shedding, worker, drop statuses, the severity macros and `with-trace-scope`.
- Modify `src/dds-lang/lisp-lang-tools.lisp` — `defun*` gains the enclosing-name `macrolet`.
- Modify `src/dds-pal/pal-sbcl.lisp`, `pal-clasp.lisp`, `pal-contract.lisp` — best-effort `source-location`.

**Phase D — the service** (`src/dds-log/`)
- Create `formatter.lisp` — text and JSON renderers as closures.
- Create `sink.lisp` — file sinks as closures.
- Create `service.lisp`, `runner.lisp`, `supervisor.lisp`, `main.lisp` — mirroring `src/dds-durability/`.

**Build + tests**
- Create `dds-log.asd`; modify `dds-tests.asd` (`:depends-on` + a `log-test` component) and `dds.asd`.
- Create `src/dds-tests/log-test.lisp`; modify `src/dds-tests/echo-test.lisp` (test registry).

---

## Phase A — the type compiler must be able to express the type

### Prerequisite (NOT part of this plan): the UTF-8 string codec

`cdr-put-string` is Latin-1 only and signals above U+00FF, which no logging system can live with.
That fix is **its own reviewed change** — owner decision, 2026-07-23 — because it rewrites a hot-path
wire codec that every string in every type goes through, and it must be reviewed on its own merits
rather than as a subordinate step of a logging feature. See
**`docs/plans/2026-07-23-utf8-string-codec.md`**.

**It must land before Task 1 of this plan**, which needs `dds.cdr:utf8-octet-length` to measure an
IDL bound in octets.

### Task 1: bounded strings in the type DSL

`(:string N)` must be a member type distinct from `:string`. The bound is a wire contract: XTypes
carries it in the TypeObject and `rtiddsgen` will emit `string<N>`, so an unbounded string on our side
against a bounded one on theirs is a **different type** that fails to match (ADR 0009).

**Files:**
- Modify: `src/dds-gen/dsl.lisp` (`*dds-type-map*` at :6, `%parse-member` at :34)
- Test: `src/dds-tests/gen-test.lisp`

**Interfaces:**
- Consumes: nothing.
- Produces: member spec `(slot (:string N))` accepted by `dds.gen:define-dds-type`; a generated
  constant `+<type>-<slot>-bound+` = N; the emitted **TypeObject carries `string<N>`** so
  assignability sees a bounded string; the on-wire codec is byte-identical to `:string` within bound.

**The compiler enforces the bound; the caller does not.** `define-dds-type` currently emits a plain
`defstruct` (`dsl.lisp:275`) whose accessors are `<type>-<slot>` with no checked setter — so add one.
A bounded member gains a generated `set-<type>-<slot>` returning `(values t nil)` or
`(values nil :string-bound-exceeded)`, measuring the value with `dds.cdr:utf8-octet-length` from the prerequisite change
because an IDL bound counts **octets**. The plain `defstruct` accessor stays (existing types are
untouched, and the hot path keeps its direct slot access), so this is additive.

Both halves are required and they do different jobs: the **TypeObject** bound is what a foreign
`rtiddsgen`-generated peer compares against for matching — getting that wrong is ADR 0009's defect —
while the **checked setter** is what stops an over-long value reaching the wire in the first place.
Neither substitutes for the other, and neither belongs in the log layer.

- [ ] **Step 1: Write the failing test.** In `src/dds-tests/gen-test.lisp`:

```lisp
(dds.gen:define-dds-type bounded-str-t (:extensibility :final)
  (id :i32 :key t)
  (name (:string 8)))

(defun* run-bounded-string-test ()
    (function () t)
  "A bounded string declares its bound in the type (XTypes 1.3 §7.3.1.2.1 — the bound is part of the
   type, which is why a bounded and an unbounded string are NOT the same type and do not match), and
   serializes byte-identically to an unbounded string for a value within bound."
  (%check :bound-constant (= +bounded-str-t-name-bound+ 8) "the bound is exposed as a constant")
  (let* ((s (make-bounded-str-t :id 1 :name "12345678"))
         (buf (dds.core.buffer:make-octet-buffer 64))
         (c (dds.core.buffer:cursor buf :endianness :little)))
    (serialize-bounded-str-t s c :xcdr2)
    (%check :bounded-roundtrip
            (string= (bounded-str-t-name (deserialize-bounded-str-t
                                          (dds.core.buffer:cursor buf :endianness :little) :xcdr2))
                     "12345678")
            "a value at the bound round-trips")
    (%check :bounded-typeobject
            (search "string<8>" (princ-to-string (dds.gen:type-object-for 'bounded-str-t)))
            "the TypeObject declares the bound, not an unbounded string")
    (multiple-value-bind (ok status) (set-bounded-str-t-name s "123456789")
      (%check :bounded-refused (and (null ok) (eq status :string-bound-exceeded))
              "the generated setter refuses a value over the bound")
      (%check :bounded-unchanged (string= (bounded-str-t-name s) "12345678")
              "a refused set leaves the value alone"))
    ;; The bound counts OCTETS: eight 2-octet characters are 16 octets and must be refused, even
    ;; though they are only eight characters. A character count here would let a multi-byte string
    ;; overflow the peer's buffer — which is the whole reason the bound exists.
    (%check :bounded-octets-not-characters
            (null (set-bounded-str-t-name s (make-string 8 :initial-element (code-char #xE4))))
            "eight 2-octet characters exceed a bound of 8"))
  t)
```

  Adjust `serialize-`/`deserialize-`/`type-object-for` to the exact names `define-dds-type` emits —
  read `dsl.lisp:275-310` and use what is actually generated rather than what this plan guessed.

- [ ] **Step 2: Run it and watch it fail.**
  `./scripts/with-sbcl.sh --non-interactive --eval '(asdf:load-system :dds-tests)'`
  Expected: FAIL at macroexpansion — `define-dds-type: unsupported member type (:STRING 8)`.

- [ ] **Step 3: Implement.** In `%parse-member`, add a branch ahead of the `keywordp` branch for
  `(and (consp dds-type) (eq (car dds-type) :string))`: reuse the `:string` row of `*dds-type-map*`
  for codec ops and add `:bound (second dds-type)` to the plist. Reject a non-positive-integer bound
  at macroexpansion time with `; NOCOND(MACRO)`. Emit three things: the `+<type>-<slot>-bound+`
  constant, the checked `set-<type>-<slot>` function, and `:bound` threaded into the TypeObject
  emission so the member's type is a bounded string. Measure with `dds.cdr:utf8-octet-length` (the prerequisite change)
  — **the bound is octets, not characters** (IDL `string<N>` bounds octets).

- [ ] **Step 4: Run the test and watch it pass**, then falsify twice: (a) drop `:bound` from the
  TypeObject emission and confirm `bounded-typeobject` goes red — that assertion is the whole interop
  point, and an unfalsified version of it proves nothing; (b) measure the setter's length with
  `length` instead of `utf8-octet-length` and confirm `bounded-octets-not-characters` goes red.
  Restore both.

- [ ] **Step 5: Register + run both suites.** Add `("gen-bounded-string" . run-bounded-string-test)`
  to `run-all-tests`. Run `make test-clasp` then `make test LISP=./scripts/with-sbcl.sh`.

- [ ] **Step 6: Commit.** `git add src/dds-gen/dsl.lisp src/dds-tests/gen-test.lisp src/dds-tests/echo-test.lisp`

### Task 2: enum members in the type DSL

**Files:**
- Modify: `src/dds-gen/dsl.lisp`
- Test: `src/dds-tests/gen-test.lisp`

**Interfaces:**
- Produces: `(dds.gen:define-dds-enum name (kw value) ...)` and member type `(:enum name)`.
  Wire representation is `int32` (XTypes 1.3 §7.3.1.2.1 default enum bit bound 32). The generated
  accessor takes and returns the **keyword**; the codec reads and writes the **integer**.

- [ ] **Step 1: Write the failing test** asserting: a keyword round-trips through serialize/deserialize;
  an explicit value is honoured (define an enum with a gap, e.g. `(:a 0) (:c 7)`, and assert the wire
  octets carry 7 for `:c`); an unknown integer on the wire decodes to `(values nil :unknown-enum-value)`
  rather than to a wrong keyword. That last one is the one that matters: a foreign publisher of a newer
  revision will send values we do not know, and inventing a keyword for them is how a decoder lies.
- [ ] **Step 2: Run it, watch it fail** (`unsupported member type (:ENUM ...)`).
- [ ] **Step 3: Implement.** `define-dds-enum` builds a load-time bidirectional table (keyword→i32 and
  i32→keyword). `%parse-member` gains an `(:enum name)` branch reusing the `:i32` row for codec ops
  with `:enum-table` in the plist; the get path maps integer→keyword and returns the status form on an
  unknown value; the put path maps keyword→integer.
- [ ] **Step 4: Run, watch it pass; falsify** by making the unknown-value path return the raw integer
  and confirming the test goes red. Restore.
- [ ] **Step 5: Register `("gen-enum" . run-gen-enum-test)`; both suites.**
- [ ] **Step 6: Commit.**

### Task 3: `:appendable` extensibility in generated codecs

XTypes 1.3 §7.4.3.4.1: an APPENDABLE type is serialized in XCDR2 as a **DHEADER** (UInt32 serialized
size) followed by the members, and a reader that runs out of members before the DHEADER's extent stops
and skips the remainder. That is exactly what makes adding a field compatible.

**Files:**
- Modify: `src/dds-gen/dsl.lisp` (the `:final`-only rejection at :262, and the codec emitters)
- Test: `src/dds-tests/gen-test.lisp`

**Interfaces:**
- Consumes: `dds.cdr:cdr-put-dheader` / `cdr-get-dheader` (`src/dds-cdr/primitives.lisp:198`).
- Produces: `(:extensibility :appendable)` accepted; serialize emits a backpatched DHEADER; deserialize
  reads it, decodes the members it knows, and **skips to the DHEADER's end**.

- [ ] **Step 1: Read the working precedent.** `src/dds-types/typeobject-cdr.lisp:63` — `%dheader-begin`
  and its backpatch. Do not invent a second mechanism; follow that one.
- [ ] **Step 2: Write the failing test** — the compatibility property, not just the framing:
  define `appendable-v1` (two members) and `appendable-v2` (the same two plus a third), serialize a
  `v2` sample, deserialize it **as `v1`**, and assert the two shared members are correct and the
  decode consumed exactly the DHEADER extent. Then the reverse: a `v1` sample decoded as `v2` leaves
  the third member at its default. A test that only checks "a DHEADER is present" proves nothing about
  the property the extensibility exists for.
- [ ] **Step 3: Run it, watch it fail** (`only :final extensibility is supported in v1`).
- [ ] **Step 4: Implement.** Accept `:appendable`; when set, wrap the member serialization in the
  backpatched DHEADER and have the deserializer record the DHEADER end, decode known members, then
  `cursor-set-position` to that end. **Bounds-check the DHEADER against the buffer extent before
  trusting it** — it is wire data (NFR-SEC-POSTURE), and a DHEADER claiming more than the datagram
  holds must be refused, not followed.
- [ ] **Step 5: Run, watch it pass. Falsify twice:** (a) drop the skip-to-DHEADER-end and confirm the
  v2→v1 case goes red; (b) drop the DHEADER bounds check and confirm a truncated buffer reads past its
  end. Restore both.
- [ ] **Step 6: `make corpus`** — the byte-exact vectors must still pass; `:final` types must be
  **byte-identical** to before (no DHEADER). If any vector moved, the `:final` path was touched: fix it.
- [ ] **Step 7: Register `("gen-appendable" . run-gen-appendable-test)`; both suites; `make gate-hotpath`.**
- [ ] **Step 8: Commit.**

---

## Phase B — the type

### Task 4: `LogEvent`, its IDL, and byte-exact corpus vectors

**Files:**
- Create: `interop/log/DdsLog.idl`, `src/dds-log/packages.lisp`, `src/dds-log/event.lisp`, `dds-log.asd`
- Modify: `dds-tests.asd`, `dds.asd`
- Test: `src/dds-tests/log-test.lisp`

**Interfaces:**
- Consumes: Tasks 1–3.
- Produces: `dds.log:log-event` struct with accessors `log-event-{host,process,thread,sequence,
  timestamp,severity,category,function,file,line,event-kind,elapsed-ns,truncated,message}`;
  `dds.log:+severity-emerg+` … `+severity-trace+`; `dds.log:make-log-event`.

- [ ] **Step 1: Read RFC 5424 §6.2.1 Table 2** and write the severity values down from the RFC text.
  Do not type them from memory — this project's most expensive bug class is a recalled wire constant.
  Cite `RFC 5424 §6.2.1` in the docstring of each constant.
- [ ] **Step 2: Write `interop/log/DdsLog.idl`** exactly as ADR 0082 §3 specifies, with a header
  comment stating it is kept in lockstep with `event.lisp` (mirroring `interop/perftest/PerfData.idl`).
- [ ] **Step 3: Write the failing test** in `src/dds-tests/log-test.lisp`: construct a `log-event` with
  every field set, serialize, deserialize, assert every field round-trips; assert a message longer than
  1024 octets is **truncated with `truncated` set T**, not refused and not silently cut; assert the
  severity constants equal the RFC values.
- [ ] **Step 4: Run it, watch it fail** (no such package `DDS.LOG`).
- [ ] **Step 5: Implement** `packages.lisp` + `event.lisp` with the `define-dds-enum` forms and the
  `define-dds-type` from ADR 0082 §3, plus `dds-log.asd` (`:depends-on ("dds-core" "dds-pal" "dds-qos"
  "dds-types" "dds-gen" "dds-disc" "dds-dcps")`, `:serial t`). Add `"dds-log"` to `dds-tests.asd`
  `:depends-on` and a `(:file "log-test")` component.
- [ ] **Step 6: Run, watch it pass.**
- [ ] **Step 7: Capture corpus vectors.** Add `LogEvent` to the corpus (`scripts/capture-corpus.sh`,
  `make corpus`) in **both endiannesses**. These are the vectors a foreign publisher is checked against.
- [ ] **Step 8: Both suites + `make corpus` + `make gate-types`.**
- [ ] **Step 9: Commit.**

---

## Phase C — the emit path

### Task 5: categories, level thresholds, and the zero-cost disabled check

**Files:** Create `src/dds-log/emit.lisp`; Test: `src/dds-tests/log-test.lisp`

**Interfaces:**
- Produces: `dds.log:define-log-category` (name → constant small integer id, load-time),
  `dds.log:level-enabled-p` (inline, `(category-id severity) → boolean`),
  `dds.log:set-category-level` (`(category severity) → (values t nil)`),
  `dds.log:*category-levels*` — a `(simple-array (unsigned-byte 8) (*))` indexed by category id.

- [ ] **Step 1: Write the failing test** — a category defaults to INFO; `set-category-level` moves the
  threshold; `level-enabled-p` is true for severities at or above it and false below (remember: lower
  numeric value = higher severity, so "enabled" is `(<= severity threshold)`); an unregistered category
  id is refused rather than indexing out of bounds.
- [ ] **Step 2: Run it, watch it fail.**
- [ ] **Step 3: Implement.** `define-log-category` assigns ids densely at load time and grows
  `*category-levels*`. `level-enabled-p` is `(declaim (inline ...))` and does exactly one `aref` plus
  one `<=`.
- [ ] **Step 4: Run, watch it pass.**
- [ ] **Step 5: Prove the zero-allocation claim.** Write `run-log-disabled-alloc-test`: with the
  category set to a threshold that disables TRACE, run 100 000 `log-trace` calls inside
  `sb-ext:get-bytes-consed` (SBCL) / the Clasp equivalent, and assert **0 bytes**. Falsify by moving
  the format call outside the `when` and confirming it goes red. This is FR-LOG-4 and it is a
  measurement, not an adjective.
- [ ] **Step 6: Register both tests; both suites.**
- [ ] **Step 7: Commit.**

### Task 6: source-location capture — function, file, line

**Files:** Modify `src/dds-lang/lisp-lang-tools.lisp`, `src/dds-pal/pal-sbcl.lisp`,
`src/dds-pal/pal-clasp.lisp`, `src/dds-pal/pal-contract.lisp`; Test: `src/dds-tests/log-test.lisp`

**Interfaces:**
- Produces: `dds.lang:current-function-name` (a macro; the enclosing `defun*`'s name, or `NIL`);
  `dds.pal:source-location` (a macro → `(values file line)`, `(values nil 0)` where unavailable).

- [ ] **Step 1: Write the failing test** — a `defun*` body reporting its own name; a form outside any
  `defun*` reporting `NIL` rather than a wrong name; `source-location` returning a file string whose
  name matches the test file, or `(nil 0)` on an implementation without support. **Assert the honest
  fallback explicitly** — a missing line number reported as 0 must be distinguishable from line 0 of a
  real file, so the file must be `NIL` whenever the line is unknown.
- [ ] **Step 2: Run it, watch it fail.**
- [ ] **Step 3: Implement `current-function-name`.** In `defun*`'s expander, wrap the body in
  `(macrolet ((%dds-current-function-name () '(quote NAME))) ...)`; define a global
  `%dds-current-function-name` macro expanding to `nil` as the outside-a-`defun*` fallback, and
  `current-function-name` as a macro expanding to `(%dds-current-function-name)`.
  **This touches the macro every function in the system is defined with.** It is compile-time only and
  additive, but run `make gate-build` on both implementations and confirm zero new warnings before
  going further.
- [ ] **Step 4: Implement `dds.pal:source-location`** per implementation — this is the one place reader
  conditionals are permitted. Where an implementation offers no line number, return `(values nil 0)`.
  Record the gap in `docs/verification.csv` as an NFR-PORT gap.
- [ ] **Step 5: Run, watch it pass. Both suites + `make gate-pal` + `make gate-build`.**
- [ ] **Step 6: Commit.** Present this one for approval separately — it modifies a core macro.

### Task 7: the bounded ring and severity-graded shedding

**Files:** Modify `src/dds-log/emit.lisp`; Test: `src/dds-tests/log-test.lisp`

**Interfaces:**
- Produces: `dds.log:make-log-ring` (`(capacity) → (values ring status)`),
  `dds.log:ring-offer` (`(ring event) → (values accepted-p nil)` — **never blocks, never signals**),
  `dds.log:ring-take` (`(ring) → (values event nil)` or `(values nil :empty)`),
  `dds.log:ring-drop-count` (`(ring severity) → count`).
- Shed thresholds are configuration, not constants: `dds.log:*shed-thresholds*`, an alist of
  severity → minimum free fraction.

- [ ] **Step 1: Write the failing test — the property, not the plumbing.** Fill a ring to capacity with
  TRACE events, then offer a CRIT: the CRIT must be **accepted** and a TRACE must have been shed.
  Then assert the inverse: a ring full of CRIT must **refuse** a TRACE. Then assert the drop counters
  are per-severity and sum to the number refused.
- [ ] **Step 2: Run it, watch it fail.**
- [ ] **Step 3: Implement.** A `defstruct*` ring over a pre-allocated `simple-vector` of pre-allocated
  `log-event` structs (fill in place — the emit path must not allocate an event per call). `ring-offer`
  computes free capacity and compares against the offering severity's threshold.
- [ ] **Step 4: Run, watch it pass. Falsify:** remove the grading so all severities share one
  threshold, and confirm the "CRIT is accepted into a TRACE-full ring" assertion goes red. **A shedding
  policy nobody has watched fail is a shedding policy nobody has.** Restore.
- [ ] **Step 5: Register; both suites.**
- [ ] **Step 6: Commit.**

### Task 8: the worker thread, the writer, and reported drops

**Files:** Modify `src/dds-log/emit.lisp`; Test: `src/dds-tests/log-test.lisp`

**Interfaces:**
- Produces: `dds.log:start-log-publisher` (`(&key domain topic ring-capacity) → (values publisher
  status)`), `dds.log:stop-log-publisher` (`(publisher) → (values t status)`),
  `dds.log:get-log-drop-status` (`(publisher) → a status snapshot struct`).

- [ ] **Step 1: Write the failing test** — start a publisher against an in-process reader, emit N
  events, stop, and assert all N arrive in order with fields intact; assert `stop-log-publisher`
  **drains** the ring before returning rather than discarding it.
- [ ] **Step 2: Run it, watch it fail.**
- [ ] **Step 3: Implement.** A `bordeaux-threads` worker draining the ring into a RELIABLE/KEEP_ALL
  DataWriter; `stop` sets a flag, wakes the worker, drains and joins. The worker blocking on a full
  writer history is the intended backpressure — do not add a timeout that silently discards.
- [ ] **Step 4: Implement drop reporting** through the status machinery: a vendor status bit **clear of
  the OMG 0–14 range** (follow ADR 0080's `UNADDRESSABLE_PEER`, bit 24), a StatusCondition, a listener
  callback, and a `get_*_status` snapshot carrying per-severity counts. **Never print.**
- [ ] **Step 5: Write the overload test** — a deliberately tiny ring plus a stalled reader; assert the
  drop counters and the `sequence` gaps observed at the reader **agree**. Two independent accounts of
  the same loss that disagree mean one of them is wrong.
- [ ] **Step 6: Run; both suites; `make gate-nocond` (ceiling stays 0).**
- [ ] **Step 7: Commit.**

### Task 9: the severity macros and `with-trace-scope`

**Files:** Modify `src/dds-log/emit.lisp`; Test: `src/dds-tests/log-test.lisp`

**Interfaces:**
- Produces: `dds.log:log-emerg` `log-alert` `log-crit` `log-err` `log-warn` `log-notice` `log-info`
  `log-debug` `log-trace` — each `(category control-string &rest args)`; `dds.log:with-trace-scope`
  — `((category) &body body)`.

- [ ] **Step 1: Write the failing test** — each macro produces an event at its severity carrying the
  enclosing function name, file and line; `with-trace-scope` produces exactly **two** events, an
  `EV_ENTRY` and an `EV_EXIT` whose `elapsed-ns` is greater than a known sleep; with TRACE disabled it
  produces **zero** events and — assert this explicitly — **does not read the clock**, by binding a
  counting stub over the PAL time function and asserting the count is 0.
- [ ] **Step 2: Run it, watch it fail.**
- [ ] **Step 3: Implement.** Each macro expands to `(when (level-enabled-p <const-id> <const-sev>)
  (%log-emit ...))`. `with-trace-scope` puts the whole timing apparatus, clock read included, inside
  the `when`. It must emit its EXIT event on a non-local exit too — use `unwind-protect`.
- [ ] **Step 4: Run, watch it pass. Falsify:** hoist the clock read out of the `when` and confirm the
  "does not read the clock" assertion goes red. Restore.
- [ ] **Step 5: Both suites + re-run the Task 5 zero-allocation test.**
- [ ] **Step 6: Commit.**

---

## Phase D — the collector service

### Task 10: formatters — the golden vectors

**Files:** Create `src/dds-log/formatter.lisp`; Test: `src/dds-tests/log-test.lisp`

**Interfaces:**
- Produces: `dds.log:make-text-formatter`, `dds.log:make-json-formatter` — each returns a
  `log-formatter` struct of closures with slot `render` : `(event stream) → (values t status)`.

- [ ] **Step 1: Write the failing test against the two reference lines** — these are the oracle,
  reproduced byte for byte:

```
2026-07-23T11:28:53.645329Z | NOTICE | SUP | gbt_sup_log() - gbttctools/src/core/l6/sup/sup.c:93 | supervisor up with 2 children
2026-07-23T11:20:13.501947Z | CRIT   | MEM | gbt_tc_core_mem_init() - gbttctools/src/src.c:1234 | Segmentation Fault encountered.
```

  Construct the `log-event` whose fields produce each line and assert `string=` on the rendered
  result. Include a `WARN` case to pin the 6-column padding, and a `TRACE` `EV_EXIT` case to pin how
  elapsed time is rendered.
- [ ] **Step 2: Run it, watch it fail.**
- [ ] **Step 3: Implement the text formatter.** ISO 8601 UTC, exactly **six** fractional digits, `Z`
  suffix; severity left-aligned in 6 columns; `<function>() - <file>:<line>`; fields joined by ` | `.
  Convert `timestamp` nanoseconds to microseconds by truncation, not rounding — a log timestamp that
  rounds forward can order two events wrongly.
- [ ] **Step 4: Implement the JSON formatter** — newline-delimited, one object per event, with a
  hand-written escaper. Test it against the cases that break naive escapers: `"`, `\`, a literal
  newline, a tab, a control character below 0x20 (must become `\u00XX`), and a non-ASCII character.
  A JSON writer that has not been tested against these is a JSON writer that will emit invalid JSON.
- [ ] **Step 5: Run, watch it pass; both suites.**
- [ ] **Step 6: Commit.**

### Task 11: file sinks

**Files:** Create `src/dds-log/sink.lisp`; Test: `src/dds-tests/log-test.lisp`

**Interfaces:**
- Produces: `dds.log:make-file-sink` (`(&key path formatter) → (values sink status)`) returning a
  `log-sink` struct of closures with slots `write-event`, `flush`, `close`.

- [ ] **Step 1: Write the failing test** — events written to a temp path appear in order; `close`
  flushes; a path that cannot be opened returns `(values nil :sink-open-failed)` and **does not
  signal**.
- [ ] **Step 2–4:** run it red, implement, run it green.
- [ ] **Step 5: Both suites + `make gate-nocond`.**
- [ ] **Step 6: Commit.**

### Task 12: the service, runner, supervisor and entrypoint

**Files:** Create `src/dds-log/service.lisp`, `runner.lisp`, `supervisor.lisp`, `main.lisp`

**Interfaces:**
- Produces: `dds.log:make-log-service-spec` (`&key domain topic sinks queue-capacity`),
  `dds.log:log-service-start` → `(values service status)`, `dds.log:log-service-stop`,
  `dds.log:log-service-main` (`&key argv env block`).

- [ ] **Step 1: Read `src/dds-durability/{spec,service,runner,supervisor,main}.lisp`.** Mirror that
  shape; do not invent a second service idiom. In particular `log-service-main` maps a non-NIL start
  status to `uiop:quit 1` — the exit code **is** the `ReturnCode_t`.
- [ ] **Step 2: Write the failing test** — a service started on a domain with two sinks receives
  published events and writes both files; a sink that fails to open sheds that sink and starts the
  rest, reporting the status, rather than failing the whole service.
- [ ] **Step 3–4:** run it red, implement, run it green. The service's reader feeds the **same** ring
  from Task 7 (not a second queue implementation), drained by a per-sink worker.
- [ ] **Step 5: Both suites; `make gate-nocond`; `make gate-types`.**
- [ ] **Step 6: Commit.**

### Task 13: end-to-end, and the documentation that makes it done

**Files:** Test: `src/dds-tests/log-test.lisp`; Create `docs/wiki/logging.md`; Modify
`docs/verification.csv`, `README.md`, `docs/adr/0082-distributed-logging-service.md`

- [ ] **Step 1: Write the end-to-end test** — in one process: start the service with both file sinks,
  start a publisher, emit one event per severity plus one `with-trace-scope`, stop both, and assert the
  text file's lines match the golden rendering and every JSON line parses.
- [ ] **Step 2: Run it; both suites.**
- [ ] **Step 3: Write `docs/wiki/logging.md`** — API reference from the docstrings, a use case, and a
  worked example. It is generated from the docstrings and the in-repo specs, never from memory.
- [ ] **Step 4: Add `FR-LOG-1..9` rows to `docs/verification.csv`** recording what was verified, how,
  and what was **falsified** — for each falsification, what turned red.
- [ ] **Step 5: Update `README.md`** (status) and ADR 0082 (as-built notes and anything the
  implementation contradicted — if reality contradicted the ADR, record it; do not silently diverge).
- [ ] **Step 6: Full gate run:** `make build`, `make test` both implementations, `make corpus`,
  `make gate-hotpath`, `make gate-types`, `make gate-nocond`, `make gate-pal`, `make mem`.
- [ ] **Step 7: Commit** and present the message for approval.

---

## Explicitly NOT in this slice

Follow-on slices, in order: RFC 5424 UDP syslog sink · HTTP bulk sink · foreign-vendor interop legs
(Connext and Fast DDS publishers feeding our service, wired into `make interop`) · rotation and
retention · a zero-allocation **enabled** emit path.

**The interop legs are the notable omission.** ADR 0082 makes `LogEvent` a public wire contract, and
per the standing per-feature rule a wire-visible feature is not finished until it has been tested
against both Connext and Fast DDS. Slice 1 delivers the corpus vectors — which is what a foreign
publisher would be checked against — but not the live legs. That debt is real and is named here so it
cannot be mistaken for completion.
