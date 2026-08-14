# ADR 0117 — Validity is not representability: the second UTF-8 decoder

- **Status:** Accepted
- **Date:** 2026-08-14
- **Requirement:** NFR-SEC-POSTURE (a network-facing parser must not be crashable by wire data), NFR-PORT,
  the operating contract's no-conditions rule; ADR 0064 (this decoder returns a *status*, never a signal);
  Unicode Standard Table 3-7 / RFC 3629 §3
- **Severity:** **remotely-triggerable crash of the durability microservice serve thread**, pre-existing,
  AllegroCL only — and it presents as a **hang**, not an error
- **Found by:** asking, after ADR 0115, where else the same pattern lives
- **Relates to:** ADR 0115 (the same root cause in `CDR-GET-STRING`)

---

## 1. The defect

`%MS-UTF8->STRING` in `src/dds-durability/store-microservice.lisp` validates every byte sequence against
the Unicode Table 3-7 / RFC 3629 §3 well-formed ranges **before** it calls `CODE-CHAR`, and rejects
overlong forms, surrogates, bare continuations and scalars beyond U+10FFFF with a clean `:BAD-UTF8`
status. Its docstring drew the obvious conclusion from that work:

> "…so `CODE-CHAR` is only ever called on a valid Unicode scalar — ANY ill-formed sequence returns
> `(values NIL :BAD-UTF8)` BEFORE `code-char` …, never a `TYPE-ERROR` / out-of-range crash."

**Every clause of that sentence is true, and the conclusion it invites is false.**

⛔ **Well-formedness is a property of the OCTETS. Representability is a property of the IMPLEMENTATION.**
`CODE-CHAR` is specified to return `NIL` for any code that is not a character *in this implementation* —
a condition that has nothing to do with whether the input was valid. **AllegroCL 11.0 has 16-bit
characters** (`CHAR-CODE-LIMIT` = 65536, measured on the CI host). So the **entire 4-byte branch** handed
`VECTOR-PUSH-EXTEND` a `NIL`, which signalled a type error **out of the microservice serve thread**.

The blast radius differs from ADR 0115 and is worse in one respect. There the signal escaped the receive
path. Here it kills the connection handler, so the client is left **waiting for a reply that will never
arrive** — the failure is a **stall, not a diagnostic**, and that is how a single test hung the whole
suite. No input involved is malformed: `F0 9F 98 80` is exactly what a conformant peer sends for U+1F600.

## 2. The decision

`%MS-CHAR` substitutes **U+FFFD REPLACEMENT CHARACTER** for any scalar this implementation cannot hold,
exactly as `CDR-GET-STRING` does (ADR 0115) — one project-wide answer to one project-wide condition:

```lisp
(declaim (inline %ms-char))
(defun* %ms-char (c) (function (t) character) "…" (or c #.(code-char #xFFFD)))
```

Applied at **all four** `CODE-CHAR` call sites, not only the 4-byte branch. The 1-, 2- and 3-byte branches
are unreachable-for-`NIL` only by an argument about ranges that must then be re-derived by every future
reader; pinning the invariant in **one** place costs nothing (the function is inlined, and on a
full-Unicode implementation the `OR` arm is dead code) and removes the re-derivation entirely.

U+FFFD is itself always representable — `#xFFFD` is below AllegroCL's 16-bit limit and below every other
target's — and it is read at compile time so no `CODE-CHAR` call happens per substitution.

### What is NOT claimed

AllegroCL still cannot **represent** a supplementary code point. That is an implementation limit this ADR
cannot repeal; what it changes is that the limit is a **visible substitution instead of a hang**. The
`:BAD-UTF8` status stays reserved for genuinely ill-formed input — a substitution is not a rejection.

⛔ **The substitution is NOT injective, and on an AllegroCL SERVER that is a data-integrity exposure, not
a fidelity nicety.** Two distinct well-formed wire topics decode to **one** store key. Measured on the CI
host's AllegroCL 11.0:

```
LIMIT=65536   A="<U+FFFD>"   B="<U+FFFD>"   EQUAL=T
```

for `F0 9F 98 80` (U+1F600) and `F0 9F 98 81` (U+1F601). Driving the real dispatcher
(`%MS-HANDLE-REQUEST`) with those two topics:

| | SBCL | AllegroCL |
|---|---|---|
| distinct topics stored | 2 | **1 (aliased)** |
| `get-range(A)` | 1 record | **2 records — the other client's data** |
| `replace-topic(A, 0)` / `purge(A)` | B survives | **B destroyed** |

Every dispatch returned `status = NIL`. **Silent, not a rejection.** With a `--backend server` whose inner
store is file- or sqlite-backed, the destruction is durable.

**Reachable only in a mixed-implementation deployment** — full-Unicode clients against an AllegroCL
`durability-service-main --backend server` — because an AllegroCL *client* cannot construct the two names.
Note the same substitution is already committed project-wide for the RTPS path (`CDR-GET-STRING`,
ADR 0115), which decodes `PID_TOPIC_NAME`, so an AllegroCL node already aliases such topics *upstream* of
durability.

**This ADR does not fix that, and does not pretend to.** The alternatives at this call site were: crash the
serve thread and hang the client (the pre-fix state, a remotely-triggerable DoS), false-REJECT well-formed
RFC 3629 input (the worst defect class), or substitute. *"Stay distinct on AllegroCL"* was never on the
menu — with `CHAR-CODE-LIMIT` 65536, **no** `octets → string` decoder on that implementation is injective
over full Unicode.

⛔ **OPEN POLICY QUESTION, owner's call:** injectivity is recoverable only by keying topics on **raw octets
end-to-end**, or by **rejecting** unrepresentable scalars. Both are ADR 0115/0117 policy changes affecting
**both** decoders, and both are larger than this defect. Recorded as an NFR-PORT gap plus an open
data-integrity item until then.

## 3. ⭐ The generalisable lesson

> **A validity check does not license an unchecked constructor.**

The docstring's reasoning was sound and still insufficient, because it answered the wrong question. When
code validates its input and then concludes a downstream primitive cannot fail, the question to ask is:

> **does that primitive's failure mode depend on the INPUT, or on the ENVIRONMENT?**

`CODE-CHAR`'s depends on the environment *only*. No amount of input validation can make it total. The same
shape recurs wherever a "we already checked" comment sits above a partial function — `INTERN` against a
package that may not exist, `FIND-SYMBOL` against a foreign package, an FFI call whose return width is
platform-dependent.

## 4. ⭐ The fixture could not construct its case — the fifth occurrence

`RUN-DURABILITY-MICROSERVICE-FUZZ-TEST` asserted a round trip over

```lisp
(let ((valid "AZ¿ࠀ\U0001F600"))   ; ASCII + 2/3/4-byte scalars
```

⛔ **In ANSI CL a backslash inside a string escapes the next character and nothing more.** There is no
`\U` Unicode escape in a string literal: `\U` is the character `U`. **Measured on SBCL**, that literal is

```
len=13   codes=(65 90 191 2048 85 48 48 48 49 70 54 48 48)   maxcode=2048
```

— thirteen characters whose maximum code point is U+0800. The advertised "4-byte scalar" is the **ASCII
text `U0001F600`**. So the 4-byte branch — the branch where the defect lived and where the fix lands —
**was unexercised on every implementation**, which is precisely why neither was ever covered.

This is the fifth instance of one pattern, after `(string (code-char #x1F600))` → `"NIL"` (ADR 0115), the
`-0.0` literal that reads as `+0.0` on AllegroCL (ADR 0111), and the drain-window sabotage that never
reached the code it sabotaged (ADR 0108):

> **A fixture that cannot construct its case does not fail — it quietly tests something else.**

Fixed the ADR 0115 way. The round-trip literal is now honestly `"AZ¿ࠀ"` (ASCII + 2- and 3-byte scalars),
and a new arm drives the supplementary case **from octets**, because constructing the character is exactly
what the affected implementation cannot do. It asserts the decode does not signal, is not reported
malformed, yields exactly one character, and is **U+1F600 where representable and U+FFFD where not** —
a total assertion with **no skip**, so neither branch can degrade into a silent pass.

## 5. Verification — both arms falsified, on both implementations

Green alone would prove nothing here; the old fixture was green too. Each arm was therefore **sabotaged
and observed to fail**, then restored and re-confirmed byte-identical.

| implementation | `char-code-limit` | decodes `F0 9F 98 80` to | sabotage armed | result |
|---|---|---|---|---|
| SBCL 2.2.9 | 1 114 112 | U+1F600 | b1 term shifted 11 not 12 (→ U+FE00) | **`TEST FAILED [MS-FUZZ-UTF8-SUPP-VALUE]`** |
| AllegroCL 11.0 | 65 536 | U+FFFD, no signal | `%MS-CHAR` substitutes `#\?` | **`TEST FAILED [MS-FUZZ-UTF8-SUPP-VALUE]`** |

⚠️ **The first sabotage attempt was inert and would have recorded a false falsification.** Shifting the
`b0` term (`(ash (logand b0 #x07) 18)` → `17`) changes nothing for this input: the lead byte is `#xF0`, so
`(logand #xF0 #x07)` is **0**, and zero shifted by 17 or 18 is still zero. The test passed under sabotage
and the correct reading was *"the sabotage never reached the assertion"*, not *"the assertion is weak"*.
Re-armed on the `b1` term, which carries U+1F600's high bits, it failed immediately.

> **A sabotage must be shown to change the value under test, or it falsifies nothing.**

Full suite and gates on SBCL with this change and the parked AllegroCL work applied: **646 passed,
0 FAILED, `skipped: 0`**; `gate-build`, `gate-hotpath`, `gate-pal`, `gate-nocond`, `gate-nlx`,
`gate-types`, `gate-drivers` all `rc=0`.
