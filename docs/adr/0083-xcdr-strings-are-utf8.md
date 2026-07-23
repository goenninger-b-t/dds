# ADR 0083 — XCDR strings are UTF-8, and a malformed sequence is refused rather than repaired

- **Status:** Accepted
- **Date:** 2026-07-23
- **Requirements:** FR-CDR-1 (string wire form), FR-CDR-8 (byte-exactness), FR-IO-1/2 (interop), NFR-SEC-POSTURE
- **Spec:** RFC 3629 §3 (the UTF-8 encoding), RFC 3629 §10 (the security rationale for refusing over-long forms), OMG XTypes 1.3 §7.3.1.2 (`string` is a sequence of UTF-8 characters)
- **Supersedes:** the "Latin-1 for M1, UTF-8 deferred" note in `primitives.lisp` and `docs/wiki/cdr-and-memory.md`
- **Occasioned by:** ADR 0082 §9.0 — `LogEvent` cannot carry a log message in Latin-1 — but the defect is independent of logging and is fixed on its own merits.

## 1. The problem

`cdr-put-string` wrote `char-code` as a single octet and **signalled** `cdr-not-implemented` for any
character above U+00FF; `cdr-get-string` read the octets straight back as character codes. That is
Latin-1, and it was wrong in two directions at once:

- **Every string containing a character above U+00FF was refused outright.** A German or Japanese
  topic name, a file path, a log message — refused, with a Lisp condition.
- **For U+0080..U+00FF we emitted a single octet.** IDL and XTypes define `string` as UTF-8, so a
  conformant peer reads that octet as the start of a multi-byte sequence and finds it malformed. We
  were not "limited to Latin-1"; we were emitting bytes no conformant peer can decode.

Topic and type names go through this same codec in SPDP/SEDP (`discovery.lisp`), so the defect
reached **discovery**, not merely user payloads.

## 2. Decision

**XCDR strings are UTF-8 (RFC 3629 §3).** The 4-octet length prefix counts **octets** — as it always
did; only a one-octet-per-character codec made "octets" and "characters" look interchangeable.
`dds.cdr:utf8-octet-length` is the supported way to measure a string for a bound or a buffer.

**A malformed sequence is REFUSED, not repaired.** `cdr-get-string` returns
`(values string status)`, with `:malformed-utf8` for a bad lead octet, a truncated sequence, a bad
continuation octet, an **over-long** form, a surrogate, or anything above U+10FFFF.

Substituting U+FFFD — the other defensible option, and what many decoders do — was **rejected**: it
hands the caller a string it cannot distinguish from one the peer actually sent. Over-long forms in
particular are a documented attack, not a curiosity: `C0 AF` decodes to `/` written in two octets,
which is how a filter that checked the one-octet form is bypassed (RFC 3629 §10).

**The primary value stays a `string` on the failure path** (`""`), deliberately. Generated
deserializers assign it into a slot declared `string`; returning `NIL` would turn a peer's malformed
octets into a type violation at `(safety 0)`. Callers that must not accept corrupt text check the
status: discovery **leaves a malformed topic or type name unset** — so the endpoint record carries no
name, matches nothing, and is unusable, rather than announcing the empty topic — TypeLookup drops the
request, and TypeObject rides its existing `:unsupported` channel.

**ASCII is byte-identical to before.** UTF-8 is an ASCII superset, so every committed corpus vector
is unchanged (11 vectors, 0 mismatches). That is the property that made this safe to land: a moved
vector would have been a regression, not a new baseline.

## 3. Three defects this exposed, none of them about UTF-8

**(a) The `write-sample` condition boundary was narrower than its own comment.** It read
"NO CONDITION MAY ESCAPE THE PUBLIC API" and then caught exactly one condition class,
`cdr-not-implemented`. An over-long sample signalled `dds.core.buffer:buffer-overflow` straight past
it into the application — *before* this change — and removing the Latin-1 signaller would have left
it catching nothing at all. It now covers the serialization failure classes. An owner-directed,
non-negotiable guarantee had a hole in it that nothing tested.

**(b) The generated `serialized-size` under-sized its buffer.** It computed `4 + (length s) + 1`, one
octet per character. Under UTF-8 a character takes up to four octets, and that number **sizes the
buffer the sample is serialized into** — measured at estimate 13 against 17 octets actually written
for a four-character string. A latent overflow, fixed to use `utf8-octet-length`.

**(c) A test asserted a defect.** `run-no-condition-escapes-api-test` used "a non-Latin-1 string" as
its example of an *unencodable* sample. Once the codec encodes it, a test demanding it still fail
would be demanding the bug back. It now asserts the opposite for that input and re-anchors the
no-unwind property on an input that is still unencodable and always will be.

## 4. A test that passed for the wrong reason

Deleting the decoder's field-extent check left the whole suite **green**. The truncated-sequence case
was being caught by the *continuation-octet* check instead, because the octet after a truncated
sequence is the string's trailing NUL, and `0` is not a valid continuation. The extent check —
the one that stops a decoder reading into the next field — was therefore **unfalsified**, which is
indistinguishable from absent.

The case that fixes it: a length prefix declaring 2 octets while a complete 3-octet sequence follows,
so the third octet **is** a valid continuation. Without the bound the decoder returns `€` for octets
the field never contained; with it, refused. An under-declaring length prefix is also a real hostile
input, not a synthetic one.

## 5. Consequences

- **Both directions move from wrong to right**, so there is no compatibility window against a
  conformant peer — only against a peer that had adapted to our Latin-1 output, and none exists.
- **`cdr-not-implemented` stays.** The plan called for retiring it on the strength of an in-code
  comment saying "remove when UTF-8 lands"; one grep falsified that — it has two live signallers for
  unsupported encapsulation *representations* and the fuzz suite asserts on it. **A comment stating
  what a future change should do is a claim, not a fact**; that one had been true when written and
  quietly stopped being true.
- **No measurable allocation change.** `gate-mem` baseline 1883.1 / 1878.4 against 1878.4 / 1885.1
  with the change — overlapping ranges. An earlier "+27 B" reading was taken against a *remembered*
  number rather than a measured baseline, which is exactly the error this gate's own history warns
  about.
- **⚠️ OPEN — UTF-8 corpus vectors cannot be self-generated.** `scripts/capture-corpus.sh` captures
  vectors from a **live RTI Connext writer**, and `make corpus` only verifies committed ones. A
  vector we produced ourselves would be a second copy of our own encoder and would prove nothing
  about interop. **A live non-ASCII round trip through Connext and Fast DDS is owed**, and 585/585
  does not imply it.
