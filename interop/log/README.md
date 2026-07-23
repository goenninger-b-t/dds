# LogEvent — cross-DDS interop leg

Live proof that the `LogEvent` wire type (ADR 0082 §3, `src/dds-log/event.lisp`, kept in lockstep
with `DdsLog.idl`) interoperates with **RTI Connext 7.3.1**: a Connext `@appendable`
`dds::log::LogEvent` publisher generated from `DdsLog.idl` → our reader, every field decoded.

## Result

**INTEROPERATES (Connext writer → our reader).** Our reader decoded 33 samples, every field correct
across the vendor boundary:

```
host="connext-node" pid=4242 uuid="8b619879-4ffe-4fca-ad01-05b39d987dbc" ip="192.168.2.148"
seq=47 sev=CRIT cat="MEM" ek=EXIT msg="segfault at frame 47"
```

Connext's verbose log stored our reader's type with no incompatibility:
`assertRemoteEndpointEx:TypeObject succesfully stored (topic: 'DdsLog', type: 'dds::log::LogEvent')`.
So the full `LogEvent` feature stack is structurally compatible with a Connext peer: `@appendable`
framing, the two enums (our `TK_INT32` ↔ Connext `TK_ENUM`, coerced), the five bounded strings
(including `message` `string<1024>` = `TI_STRING8_LARGE`), and the source-identity fields.

**It settles the member-naming question empirically.** Our multi-word members carry kebab names in the
TypeObject (`event-kind`, `participant-uuid`, `host-ip`, `elapsed-ns`) while the IDL — and the Connext
peer generated from it — uses underscores (`event_kind`, …). All of them decoded correctly, so
`@appendable` matches members by **member ID / position** (both sides default to `@autoid(SEQUENTIAL)`),
**not by name**. The kebab-vs-underscore gap is therefore cosmetic, confirmed on a live wire — not the
match-blocking defect it appeared to be.

## Two IDL defects this leg caught (that the Lisp round-trip could not)

Generating a Connext peer from `DdsLog.idl` immediately surfaced two bugs in the ADR 0082 §3 IDL that
a self-consistent Lisp round-trip is blind to — the entire reason a live foreign peer is the oracle:

1. **`sequence` is an IDL reserved word.** The field was named `sequence` (per-source monotonic
   counter). `sequence` is the IDL collection keyword, so `rtiddsgen` rejects a member named
   `sequence` outright — a foreign publisher could **never** be generated. Renamed `sequence → seq`
   (matching the existing `tagged-shape` precedent) in the IDL and the Lisp type in lockstep.
2. **The compact module close `}};` does not parse.** `module dds { module log { … }};` fails with
   `mismatched input '}' expecting ';'`; each module must close with its own `};`. Fixed in the IDL
   and the ADR.

## Run

```sh
export NDDSHOME=/Applications/rti_connext_dds-7.3.1
export CONNEXTDDS_ARCH=arm64Darwin20clang12.0        # ls $NDDSHOME/lib
make                                                 # -> log_pub  (rtiddsgen from DdsLog.idl + clang)
./log_pub 0 80                                       # Connext publishes dds::log::LogEvent on "DdsLog"
```

Our reader side is a scratch runner that loads `:dds-log`, binds the registered `log-event`
type-support under topic `DdsLog` / type name `dds::log::LogEvent`, and prints each decoded event. Use
Connext's default transport (do **not** force the loopback-only QoS profile — that config did not
deliver same-host user data in this harness; Connext's default SHMEM/UDP mix does). rtiddsgen output,
the binary, and any copied QoS profile are git-ignored (clean-room).

## Still open

Byte-exact `LogEvent` corpus vectors (both endiannesses, captured from this Connext writer) and the
**Fast DDS** publisher leg. The reciprocal (our LogEvent writer → a Connext reader) rides the
DATA_REPRESENTATION note in `../enum-typeobject/README.md`: our writer would offer XCDR1 for a stock
`@final` reader, but `LogEvent` is `@appendable`, so the reader's requested representation governs.
