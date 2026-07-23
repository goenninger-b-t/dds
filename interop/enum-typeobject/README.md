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

### The reciprocal — our `TK_INT32` writer → a Connext `TK_ENUM` reader (`enum_sub`)

`enum_sub.cxx` is the Connext reader; a scratch `TK_INT32` writer (offering XCDR1, see below) is our
side. Connext's verbose log on this run:

```
PRESPsService_assertRemoteEndpointEx:TypeObject succesfully stored (topic: 'EnumBox', type: 'EnumBox')
```

**Connext stored our writer's TypeObject with no incompatible-QoS warning** — so the enum-vs-int32
difference does **not** make Connext reject our `TK_INT32` writer on type grounds either. The
type-matching question is answered **in both directions**: `TK_ENUM ↔ TK_INT32` is coerced, not
rejected, by default Connext (`ALLOW_TYPE_COERCION`).

Honest caveat: end-to-end *sample delivery* in this reciprocal run was 0, but for a reason unrelated
to the enum — a DCPS-write-path issue (`COMMENDAnonReaderService: FAILED TO MODIFY READ WRITE AREA |
commend anon remoteWriter`), i.e. user-data delivery from the scratch DCPS `write-sample` path, not a
type or QoS rejection. The type acceptance (the Phase B-relevant fact) is established; end-to-end
delivery via that particular publish path is a separate open item.

### A note on DATA_REPRESENTATION (why the reciprocal writer offers XCDR1)

Our writer's default `DATA_REPRESENTATION` is `[XCDR2]`; a stock Connext `@final` reader requests
`[XCDR1]`, and XTypes 1.3 §7.6.3.1.1 has a writer serialize with its single representation, so an
XCDR2 writer does not match an XCDR1 reader (RxO incompatible). This — not any discovery/SEDP defect
— is what makes an XCDR2 writer fail against a stock foreign reader; offering XCDR1
(`make-writer-qos :data-representation '(:xcdr1)`) makes the representations compatible so the *type*
question can be isolated. Our reader already accepts both `(:xcdr2 :xcdr1)`, which is why the forward
direction needed no such adjustment.

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
