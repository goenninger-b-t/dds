# ADR 0115 — A valid UTF-8 sequence must not crash the decoder

- **Status:** Accepted
- **Date:** 2026-08-07
- **Requirement:** NFR-SEC-POSTURE (a network-facing parser must not be crashable by wire data), FR-CDR-1,
  NFR-PORT; XTypes 1.3 §7.4.1.1.2 (`String<Char8>` is UTF-8); the operating contract's no-conditions rule
- **Severity:** **remotely-triggerable crash of the receive path**, pre-existing, AllegroCL only
- **Found by:** porting to a third implementation (ADR 0113/0114)

---

## 1. The defect

`CDR-GET-STRING` materialised its result with

```lisp
(setf (char s k) (code-char cp))
```

`CODE-CHAR` is specified to return `NIL` for a code that is not a character in the implementation, and
**AllegroCL 11.0 has 16-bit characters**: `CHAR-CODE-LIMIT` is 65536 and `(code-char #x1F600)` is `NIL`.
Every **supplementary-plane** scalar value — every emoji, all of CJK Extension B, and much else — therefore
made that `SETF` a **type error signalled out of the receive path**.

⛔ **The input is not malformed.** `F0 9F 98 80` is well-formed UTF-8 per RFC 3629 §3 and exactly what a
conformant DDS peer sends for U+1F600. So any peer could crash an AllegroCL subscriber by publishing a
string containing an emoji. That is a denial of service reachable from the network, and it violates two
standing rules at once: NFR-SEC-POSTURE ("a malformed RTPS submessage must never cause OOB access" — and a
*well-formed* one must certainly not crash), and the contract's prohibition on our code signalling at all.

SBCL (`CHAR-CODE-LIMIT` 1114112) and Clasp cannot reach it: `CODE-CHAR` never fails there for a valid
scalar value. **Two implementations agreeing proves nothing about the third.**

## 2. The decision

Substitute **U+FFFD REPLACEMENT CHARACTER** for any scalar value this implementation cannot represent:

```lisp
(setf (char s k) (or (code-char cp) +replacement-character+))
```

- **U+FFFD is the Unicode-standard substitution** for exactly this case, and is itself always
  representable — `#xFFFD` is below AllegroCL's 16-bit limit and below every other target's.
- **It is deliberately not silent.** The application receives `�` and can see it. The two alternatives both
  hide the loss: dropping the sample discards data the peer legitimately sent, and returning a status is
  ineffective because the generated codecs call `CDR-GET-STRING` in a single-value context and ignore it.
- **This is a substitution, not a rejection.** The existing `:MALFORMED-UTF8` status is reserved for input
  that is genuinely ill-formed (overlong forms, bare continuations, surrogates, beyond U+10FFFF); a
  supplementary code point is none of those and must not be conflated with them.
- On SBCL and Clasp the `OR` arm is **unreachable**, so their behaviour is byte-identical.

`+REPLACEMENT-CHARACTER+` is read at compile time so the decoder does not call `CODE-CHAR` per substitution.

### What is NOT claimed

AllegroCL still cannot *represent* a supplementary code point in a `STRING`, so a round trip through an
AllegroCL reader is lossy for that character. That is an implementation limit, not something this ADR can
fix; what it fixes is that the limit is now a **visible substitution instead of a crash**. Recorded as an
NFR-PORT gap.

## 3. ⭐ The same fixture trap, three times in one day

Both existing UTF-8 tests built their case as `(string (code-char #x1F600))`. On AllegroCL that is
`(string NIL)` — the three-character string **`"NIL"`**. So they passed on SBCL while silently asserting the
encoding and decoding of `"NIL"` on the implementation where the bug lived.

This is the third occurrence of one pattern today, after the `-0.0` literal (ADR 0111 — the literal reads as
`+0.0` on AllegroCL) and the drain-window sabotage that could not reach the code it sabotaged (ADR 0108):

> **A fixture that cannot construct its case does not fail — it quietly tests something else.**

Fixed three ways, each deliberate:

1. The **encode** assertion is guarded on `(code-char #x1F600)` being non-`NIL`, and where it is `NIL` the
   guard *itself is asserted* (`char-code-limit < #x1F600`) so the skip cannot become a silent pass.
2. The **decode** assertion expects the scalar value where representable and U+FFFD where not — still an
   `OK-CASE`, because a substitution is not a rejection.
3. A new arm, `RUN-UTF8-SUPPLEMENTARY-DECODE-TEST`, is driven **from octets** rather than from a character —
   because constructing the character is precisely what the affected implementation cannot do, so a
   character-driven fixture could never have run where the bug lived. It asserts the decode does not
   signal, is not reported malformed, yields exactly one character, and is U+1F600 or U+FFFD per
   `CHAR-CODE-LIMIT`.

## 4. Verification

`RUN-UTF8-ENCODE-TEST`, `RUN-UTF8-DECODE-TEST` and `RUN-UTF8-SUPPLEMENTARY-DECODE-TEST` on **both**
implementations available on the CI host:

| | `char-code-limit` | result |
|---|---|---|
| SBCL | 1 114 112 | all three OK — decodes U+1F600 |
| AllegroCL 11.0 | 65 536 | all three OK — decodes U+FFFD, no signal |

Plus the full suite and gates (§ commit).
