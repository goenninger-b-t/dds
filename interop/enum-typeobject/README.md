# Enum TypeObject — cross-DDS interop probe

Answers a log-service Phase B blocker (ADR 0082 §9.0): NeoDDS's `(:enum ...)` member emits
**`TK_INT32`** in the TypeObject, because the serializer cannot yet emit a real
`MinimalEnumeratedType` (`equivalence-hash` takes a `minimal-struct-type` only, so an `EK_MINIMAL`
TypeIdentifier referencing an enum hits `%put-type-identifier`'s no-hash branch). A conformant peer
whose IDL declares an `enum` presents **`TK_ENUM`**. Under strict XTypes type-consistency the two are
structurally different types — the ADR 0009 defect class. **Does a real RTI Connext peer reject or
tolerate the difference, and does the enum value survive?**

The answer decides whether Phase B can ship `LogEvent` with an enum-as-int32, or whether the
`MinimalEnumeratedType` serializer must land first.

## Result

**TOLERATED in the tested direction — with an important boundary.**

`EnumBox.idl` declares a real IDL `enum Kind { KIND_TRACE, KIND_INFO, KIND_ERROR }` → `TK_ENUM`.
`enum_sub.lisp` declares the matching NeoDDS type with the member as `(:enum probe-kind)` →
`TK_INT32`, same topic/type name `EnumBox`, `@key long id`.

Direction B (Connext writer → our reader): **our reader received 59 samples and decoded every value
correctly** — Connext's `0/1/2` became `:TRACE / :INFO / :ERROR`. Connext matched its `TK_ENUM`
writer against our `TK_INT32` reader and delivered; our lenient reader (ADR 0009 — gate, never
hash-reject) accepted the foreign `TK_ENUM` writer.

**And it is real coercion, not a name-only match.** The lo0 capture carries `PID_TYPE_INFORMATION`
(`0x0075`) and `PID_TYPE_OBJECT_LB` (`0x8021`, Connext's compressed complete TypeObject for its
`TK_ENUM` `EnumBox`) — type *structure* was exchanged, not just the type *name*. So Connext had the
enum's structural definition available and, under its default `TypeConsistencyEnforcement =
ALLOW_TYPE_COERCION`, still deemed `TK_ENUM` (writer) assignable to `TK_INT32` (reader) — an enum is
int32-backed, and coercion permits it. This is the meaningful common case.

> The signal is the **sample count**, not `dds.dcps:matched-count` (a participant-level counter that
> does not reflect this reader's `SUBSCRIPTION_MATCHED` here). To receive reliable user DATA a reader
> must be matched to the writer, so 32 decoded samples prove the match end to end.

### The boundary — what this does NOT prove

This is Connext-**writer** → our-**reader**. It proves **our reader tolerates a foreign `TK_ENUM`
writer**. It does **not** prove the reciprocal: a **strict foreign reader** evaluating **our
`TK_INT32` writer**. That reciprocal is exactly where enum-vs-int32 enforcement would bite (a
`TypeConsistencyEnforcement = DISALLOW_TYPE_COERCION` reader), and it is the `LogEvent`-as-writer /
foreign-strict-subscriber case. It is **untested here because that is direction A** (our writer →
foreign reader), which is currently blocked by a pre-existing SEDP-publication regression unrelated
to enums (see the resume note / `interop/appendable` open items). So:

- ✅ **We subscribe to a foreign enum publisher** — works, values correct.
- ⏳ **A strict foreign subscriber reads our enum publisher** — untested (direction-A regression);
  this is the residual risk for `LogEvent` and the reason the `MinimalEnumeratedType` serializer is
  still worth landing.

## Run

```sh
export NDDSHOME=/Applications/rti_connext_dds-7.3.1
export CONNEXTDDS_ARCH=arm64Darwin20clang12.0        # ls $NDDSHOME/lib
make                                                 # -> enum_pub
# our reader:
./scripts/with-sbcl.sh --load interop/enum-typeobject/enum_sub.lisp &
# Connext writer:
( cd interop/enum-typeobject && ./enum_pub 0 60 )
```

rtiddsgen output and the built binary are git-ignored (clean-room: generated locally, never checked
in).
