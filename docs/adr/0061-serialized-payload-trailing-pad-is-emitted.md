# ADR 0061 — The SerializedPayload trailing pad octets are EMITTED, not merely counted

* Status: **Accepted** (2026-07-13)
* Supersedes the "the body is NOT tail-padded" premise in ADR 0015 (FlatData) and in
  `finalize-encapsulation-options`.

## Context

`finalize-encapsulation-options` computed the number of pad octets needed to bring the SerializedPayload body
to a 4-byte boundary and wrote that count into the low two bits of the encapsulation `options` field
(DDS-XTypes 1.3 §7.6.3.1.2) — **but never appended the pad octets themselves**. The FlatData size constant
carried the same premise explicitly: *"the FINAL body is NOT tail-padded — any trailing pad is carried in the
encapsulation OPTIONS field, not as body octets."*

That premise is wrong. §7.6.3.1.2's option bits **count padding that is PRESENT**; a conformant receiver
derives the end of the data as `payload_length - pad`. We were advertising "there are N trailing pad octets"
and then sending a payload that did not contain them, so a conformant receiver read **short by exactly N
octets**.

**Every sample whose serialized body length was not a multiple of 4 was malformed on the wire.** Not only
sequences — any type whose body ends unaligned (a trailing `octet`, a `u8`/`bool`, a short string, …).

## Why it survived so long

Our own reader ignores the option bits (it is driven by the member list), so the stack was **self-consistent**:
`ours <-> ours` echo passed at every payload length, the unit suite passed, and the byte-exact XCDR vector
tests passed — because they were checking our encoder against our decoder and against vectors we had derived
from the same wrong premise. Two tests (`FD-TAIL-SIZE`, `FD-NARROW-SIZE`) *asserted the defect*, and one even
justified it: *"a tail-padded 12 would false-REJECT the engine's own 9-octet payload."*

It was invisible until the bytes met a foreign vendor. Live RTI Connext 7.3.1 interop failed for **every**
payload length with `len mod 4 ∈ {1,2,3}` and passed for every multiple of 4 — a perfectly clean signature.

This is the operating contract's rule, demonstrated at our own expense: **THE WIRE IS THE ORACLE.** A green
unit suite over a self-consistent encoder/decoder pair proves nothing about conformance.

## Decision

1. `finalize-encapsulation-options` **emits** the pad octets (zeros) after setting the option bits, so the
   payload length is always a multiple of 4 and `payload_length - pad` is the true data end.
2. The FlatData payload-size constant `+<type>-FLATDATA-SIZE+` **includes** the pad, and the FlatData wrap
   positions its cursor at the *unpadded* body end so `finalize-encapsulation-options` performs the identical
   patch-and-emit — keeping the 0-copy FlatData payload byte-for-byte identical to the engine's.
3. The two tests that asserted the unpadded sizes are corrected to the conformant values (9 → 12, 10 → 12)
   with the rationale recorded in place.

## Consequences

* **Wire-visible change.** Payloads with a non-4-aligned body grow by 1–3 octets. This is a *conformance fix*:
  the previous bytes were malformed, so there is no interop to preserve. A peer of ours running the old code
  will still parse the new payloads (our reader ignores the trailing pad).
* **Validated on the wire, not just in tests:** live `ours <-> Connext 7.3.1`, 12/12 length classes
  (0,1,2,3,5,7,63,255,256,257,1023,4096) — previously every non-multiple-of-4 failed.
* Suites: 563/563 SBCL, 563/563 Clasp; `gate-hotpath`, `gate-types`, `fuzz` green.
* **Follow-on:** `make corpus` is still a vacuous stub (#21). This defect is exactly what a byte-exact corpus
  generated from `rtiddsgen` output would have caught on day one, and it is now the strongest argument for
  building it.
