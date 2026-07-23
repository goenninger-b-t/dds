# Bounded string LARGE form — cross-DDS interop probe

Answers a log-service Task 1 debt item. NeoDDS's `(:string N)` member with **N > 255** emits
**`TI_STRING8_LARGE` (0x71)** + an LBound `UInt32` in the TypeObject, versus `TI_STRING8_SMALL`
(0x70) + an SBound octet for N ≤ 255. The SMALL form rides the externally-confirmed path (it carries
the SBound field — value 0 — for an unbounded string); the **LARGE form had never been exercised by
a live peer**. `LogEvent` bounds `message` at **1024**, so it takes the LARGE path — this probe
confirms the LARGE TypeObject framing interoperates before Phase B ships `LogEvent`.

## Result

**INTEROPERATES.**

`StringLarge.idl` declares a real IDL `string<1024> text` → `TI_STRING8_LARGE`. `stringlarge_sub.lisp`
declares the matching NeoDDS type with `(:string 1024)` → also `TI_STRING8_LARGE` + LBound UInt32,
same topic/type name `StringLarge`, `@key long id`.

Direction B (Connext writer → our reader): **our reader received 36 samples and decoded the text
correctly** — `text="hello-from-connext-24"` … The lo0 capture carries `PID_TYPE_INFORMATION`
(`0x0075`) and `PID_TYPE_OBJECT_LB` (`0x8021`), so type structure was exchanged, not just the name.
Connext (bound `string<1024>`) matched our `TI_STRING8_LARGE` reader and delivered.

The `0x71` LBound-UInt32 framing is therefore confirmed on a live wire against an independent vendor
that implements the same Table 60 / string-collection encoding — it was only ever derived from the
spec before.

### Boundary — same as the enum probe

This is Connext-**writer** → our-**reader**: our LARGE-form reader tolerates a foreign `string<1024>`
writer. The reciprocal — a **strict foreign reader** evaluating **our** LARGE-form writer — is
direction A (our writer → foreign reader), currently blocked by a pre-existing SEDP-publication
regression. For string bounds this is low risk: Connext coerces differing string bounds via
`ignore_string_bounds` during type matching (see `../connext/common/ShapeType.idl`), so a bound
difference is tolerated where an enum kind difference might not be. The `TI_STRING8_LARGE` *framing*
(the thing that was unexercised) is what this probe confirms, and it is confirmed.

## Run

```sh
export NDDSHOME=/Applications/rti_connext_dds-7.3.1
export CONNEXTDDS_ARCH=arm64Darwin20clang12.0        # ls $NDDSHOME/lib
make                                                 # -> stringlarge_pub
./scripts/with-sbcl.sh --load interop/string-large/stringlarge_sub.lisp &
( cd interop/string-large && ./stringlarge_pub 0 60 )
```

rtiddsgen output and the built binary are git-ignored (clean-room: generated locally, never checked
in).
