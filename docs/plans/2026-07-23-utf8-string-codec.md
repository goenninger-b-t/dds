# UTF-8 string codec — implementation plan

> **For implementers:** every task ends with an independently testable deliverable and a commit.
> Steps use checkbox (`- [ ]`) syntax. This is a **wire-visible, hot-path** change to a foundational
> codec; it is reviewed on its own merits, not as a step of the feature that motivated it.

**Goal:** `cdr-put-string` / `cdr-get-string` encode and decode **UTF-8**, as IDL and XTypes require,
replacing a Latin-1 codec that refuses most of Unicode and misencodes the rest.

**Why this is a conformance defect, not a limitation.** `cdr-put-string`
(`src/dds-cdr/primitives.lisp:89`) writes `char-code` as one octet and *signals* `cdr-not-implemented`
above U+00FF; `cdr-get-string` reads octets straight back as character codes. So today: any string
containing a character above U+00FF is **refused outright**, and for U+0080..U+00FF we emit a single
octet that **every conformant peer misdecodes** — an RTI or Fast DDS peer reads those octets as
UTF-8 and sees a malformed sequence. Topic and type names go through this same codec in SPDP/SEDP
(`discovery.lisp:703,709,793,796`), so the defect reaches discovery, not just user payloads.

**Scope note:** this is motivated by the logging service (ADR 0082 §9.0), but it is not part of it and
does not depend on it. `docs/plans/2026-07-23-log-service-slice-1.md` Task 1 consumes
`dds.cdr:utf8-octet-length` from here.

## Global constraints

- **`defun*` / `defstruct*` with full type declarations**; **no Lisp conditions in `src/`** (`make gate-nocond` ceiling is **0**); docstrings on every exported symbol citing the spec clause for any wire constant.
- **Bounds-check everything from the wire, at `(safety 0)` too.** This task adds a new parser over hostile input — treat it as such.
- **No reader conditionals outside `src/dds-pal/`.** Implement UTF-8 by hand over the cursor: `sb-ext:string-to-octets` is implementation-specific and would force the PAL, and a dependency for this is unjustifiable (operating contract §9).
- **Both implementations must pass**, Clasp first: `make test-clasp`, then `make test LISP=./scripts/with-sbcl.sh`.
- **Hot path:** the string codec is on the measured path. `make mem` before/after numbers go in `bench/report/`; no hot-path change lands on intuition (FR-LANG-7).

---

## The three consequences that make this more than a codec swap

1. **`cdr-get-string` sizes its result by octets.** It does `(make-string (1- len))` and fills one
   character per octet. Under UTF-8 the character count is **≤** the octet count, so the allocation
   and the fill loop both change shape. This is the annotated `HOTPATH-ALLOC(TRACKED)` allocation —
   expect the `make mem` number to move and report it.
2. **The generated size estimator assumes one octet per character** — `dsl.lisp:316`:
   `(incf pos (+ 5 (length (accessor sample))))`. Under UTF-8 that **under-estimates**, and an
   under-estimated size is an under-sized buffer. This is a latent buffer overflow the moment a
   multi-byte character appears, and Task 3 fixes it. It must not be left for later.
3. **`cdr-not-implemented` can be retired.** Its only reason to exist is the Latin-1 restriction; the
   annotation at `primitives.lisp:99` even says *"Remove when UTF-8 lands."* Removing it also removes
   the `handler-case` at `entities.lisp:1409` — a small, real reduction in condition surface (ADR 0064).

---

### Task 1: `utf8-octet-length` and the encoder

**Files:**
- Modify: `src/dds-cdr/primitives.lisp` (`cdr-put-string` :89), `src/dds-cdr/packages.lisp`
- Test: `src/dds-tests/echo-test.lisp`

**Interfaces:**
- Produces: `dds.cdr:utf8-octet-length` (`(string) → (integer 0)`) — octets the string will occupy,
  excluding the NUL; `cdr-put-string` writing UTF-8.

- [ ] **Step 1: Write the failing test.** Assert exact octets, not round-trips — a round-trip through
  a matching encoder and decoder passes even when both are wrong:

```lisp
(defun* run-utf8-encode-test ()
    (function () t)
  "cdr-put-string emits UTF-8 (RFC 3629), the encoding IDL/XTypes `string` requires. Asserted as
   EXACT OCTETS: a round-trip through our own decoder would pass even if both halves were wrong."
  (flet ((octets-of (s)
           (let* ((buf (dds.core.buffer:make-octet-buffer 64))
                  (c (dds.core.buffer:cursor buf :endianness :little)))
             (dds.cdr:cdr-put-string c s :xcdr2)
             (coerce (subseq (dds.core.buffer:octet-buffer-vec buf) 0
                             (dds.core.buffer:cursor-position c))
                     'list))))
    ;; ASCII must be BYTE-IDENTICAL to the Latin-1 codec: 4-octet length (incl. NUL) + octets + NUL.
    (%check :utf8-ascii (equal (octets-of "AB") '(3 0 0 0 65 66 0)) "ASCII is unchanged")
    ;; U+00E4 is TWO octets in UTF-8 (C3 A4), not the one octet E4 the Latin-1 codec wrote.
    (%check :utf8-2-octet (equal (octets-of (string (code-char #xE4))) '(3 0 0 0 #xC3 #xA4 0))
            "U+00E4 encodes as C3 A4")
    ;; 3-octet (U+20AC EURO SIGN) and 4-octet (U+1F600) forms.
    (%check :utf8-3-octet (equal (octets-of (string (code-char #x20AC)))
                                 '(4 0 0 0 #xE2 #x82 #xAC 0))
            "U+20AC encodes as E2 82 AC")
    (%check :utf8-4-octet (equal (octets-of (string (code-char #x1F600)))
                                 '(5 0 0 0 #xF0 #x9F #x98 #x80 0))
            "U+1F600 encodes as F0 9F 98 80")
    (%check :utf8-length (= (dds.cdr:utf8-octet-length (string (code-char #x20AC))) 3)
            "utf8-octet-length counts octets, not characters"))
  t)
```

- [ ] **Step 2: Run it, watch it fail.** `./scripts/with-sbcl.sh --non-interactive --eval '(asdf:load-system :dds-tests)'` then call the test. Expected: the U+00E4 case signals `cdr-not-implemented`.
- [ ] **Step 3: Implement.** `utf8-octet-length` sums 1/2/3/4 per code point by the RFC 3629 ranges;
  `cdr-put-string` writes the 4-octet length as `(1+ (utf8-octet-length s))` — the prefix now counts
  **octets**, which is what FR-CDR-1 always meant — then the encoded octets, then the NUL.
  **Read the encoding table from RFC 3629 §3, do not write the shift amounts from memory.**
- [ ] **Step 4: Run, watch it pass. Falsify:** emit `char-code` directly for U+00E4 and confirm
  `utf8-2-octet` goes red. Restore.
- [ ] **Step 5: Register `("cdr-utf8-encode" . run-utf8-encode-test)`; both suites.**
- [ ] **Step 6: Commit.**

### Task 2: the decoder, and what it does with malformed input

A decoder over wire bytes is a parser over hostile input. Two properties matter more than the happy
path: it must never read past the buffer extent, and it must never turn corrupt bytes into a string a
caller cannot distinguish from real data.

**Files:**
- Modify: `src/dds-cdr/primitives.lisp` (`cdr-get-string` :103), callers below
- Test: `src/dds-tests/echo-test.lisp`

**Interfaces:**
- Produces: `cdr-get-string` → **`(values string status)`**, status `:malformed-utf8` on invalid input.

**⚠️ This widens a contract with a real ripple.** Enumerate and update every caller:
`src/dds-types/typeobject-cdr.lisp:452,465` · `src/dds-types/typelookup.lisp:322` ·
`src/dds-rtps/discovery.lisp:793,796` · the generated deserializer in `src/dds-gen/dsl.lisp:304`.
A caller that ignores the second value gets `NIL` where it expected a string — which is a type error
in the caller, so **none may be left unchecked**. Discovery's two sites are the important ones: a
malformed topic or type name from a peer must make the endpoint record unusable, not half-parsed.

- [ ] **Step 1: Write the failing test.** Round-trip all four encoding widths; then the refusals: a
  bare continuation octet (`0x80`), an over-long two-octet encoding of `/` (`C0 AF` — the classic
  security bug: an over-long form that decodes to an ASCII character bypasses filters that checked
  the ASCII form), a truncated multi-byte sequence at the very end of the buffer, and a sequence
  claiming a code point above U+10FFFF. Each must return `(values nil :malformed-utf8)` and must not
  read past the extent.
- [ ] **Step 2: Run it, watch it fail.**
- [ ] **Step 3: Implement.** Decode per RFC 3629, **validating**: correct continuation-octet count,
  no over-long forms, no surrogates (U+D800–U+DFFF), maximum U+10FFFF. Size the result string by
  **decoded characters** — a first pass to count, or fill a scratch and copy. Check each continuation
  octet against the remaining extent *before* reading it.
- [ ] **Step 4: Run, watch it pass. Falsify twice:** (a) accept over-long forms and confirm the `C0 AF`
  case goes red; (b) drop the per-octet extent check and confirm the truncated case reads past the
  end. Restore both.
- [ ] **Step 5: Update every caller listed above**, then both suites.
- [ ] **Step 6: `make gate-nocond`** — the ceiling stays **0**. If threading the status through
  discovery proves to need a condition, stop and raise it rather than annotating a new exemption.
- [ ] **Step 7: Commit** — present the message for approval; this changes a public contract.

### Task 3: the generated size estimator under-sizes buffers

`dsl.lisp:316` computes a string member's serialized size as `(+ 5 (length s))` — 4 length + one octet
per character + NUL. Under UTF-8 that is **wrong and unsafe**: a string of multi-byte characters needs
more octets than it has characters, and this number is used to size the buffer the sample is written
into.

**Files:** Modify `src/dds-gen/dsl.lisp:316`; Test: `src/dds-tests/gen-test.lisp`

- [ ] **Step 1: Write the failing test** — a generated type with a string member holding multi-byte
  characters: assert the estimated size is **≥** the octets actually written. Under the old formula
  the estimate is smaller, which is the bug.
- [ ] **Step 2: Run it, watch it fail** — the estimate comes out short.
- [ ] **Step 3: Implement:** `(+ 5 (dds.cdr:utf8-octet-length s))`.
- [ ] **Step 4: Run, watch it pass. Falsify:** restore `length` and confirm it goes red.
- [ ] **Step 5: Both suites + `make corpus`. Commit.**

### Task 4: retire `cdr-not-implemented` — ❌ VOID, the premise was false

**This task must not be done.** It assumed the Latin-1 restriction was the condition's only reason to
exist, on the strength of the annotation at `primitives.lisp:99` saying *"Remove when UTF-8 lands."*
Step 1 falsified that in one grep: the condition has **two live signallers** unrelated to strings —
`cdr.lisp:34` (unknown representation *name*) and `cdr.lisp:181` (unsupported representation *id*) —
and the fuzz suite asserts on it as one of the two controlled outcomes a forged body may produce
(`pbt-test.lisp:536,559,578`).

Consequences, recorded rather than quietly dropped:

- The condition, its export and its `handler-case` clause at `entities.lisp:1415` all **stay**. That
  clause is not dead code: an unsupported representation configured on a writer still reaches it, and
  it is what turns that into `RETCODE_BAD_PARAMETER`.
- The annotation at `primitives.lisp:99` was **misleading** — the condition's string signaller was
  only one of three, so "remove when UTF-8 lands" was never true. It went with the Latin-1 code.
- The condition-surface reduction this task claimed does not exist. The real reduction delivered by
  this change is the opposite of what was planned: the `write-sample` boundary got **wider**, because
  it was only catching one class while promising to catch all.

**Lesson worth keeping: an in-code comment stating what a future change should do is a claim, not a
fact.** This one had been true when written and quietly stopped being true when the condition
acquired other signallers.

### Task 5: corpus, bench, docs

- [ ] **Step 1: `make corpus`.** Every existing vector is ASCII and **must be byte-identical**. A moved
  vector means the ASCII path changed — that is a regression, not a new baseline.
- [ ] **Step 2: Add UTF-8 corpus vectors** — a type with a string member carrying 2-, 3- and 4-octet
  characters, both endiannesses. These are what a foreign peer is checked against.
- [ ] **Step 3: `make mem` before/after into `bench/report/`.** The decoder's allocation shape changed
  (consequence 1 above); report the number whichever way it moved.
- [ ] **Step 4: `make gate-hotpath`, `make gate-types`, `make gate-pal`, `make build`.**
- [ ] **Step 5: Update docs** — the `cdr-put-string`/`cdr-get-string` docstrings (the Latin-1 wording is
  now wrong), `docs/wiki/` CDR page, and a `docs/verification.csv` row recording what was verified,
  what was falsified, and what turned red.
- [ ] **Step 6:** Consider whether this deserves its own ADR. It changes a wire-visible codec and a
  public contract; the argument for one is that a future reader will ask why the length prefix counts
  octets and where the over-long-form refusal came from.
- [ ] **Step 7: Commit** and present the message for approval.

---

## Interop consequence, stated plainly

After this change we emit correct UTF-8 where we previously emitted Latin-1 octets that conformant
peers misdecoded, and we correctly decode UTF-8 that peers were already sending us. Both directions
move from wrong to right, so there is no compatibility window to manage against a conformant peer —
only against a peer that had adapted to our Latin-1 output, and none exists.

**Not covered here:** a live interop leg proving a non-ASCII string survives a round trip through
Connext and Fast DDS. The corpus vectors are the byte-level oracle; the live legs belong with the
next interop pass and are named here so their absence is not mistaken for coverage.
