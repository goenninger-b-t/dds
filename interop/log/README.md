# LogEvent — cross-DDS interop leg

Live proof that the `LogEvent` wire type (ADR 0082 §3, `src/dds-log/event.lisp`, kept in lockstep
with `DdsLog.idl`) interoperates with **RTI Connext 7.3.1**: a Connext `@appendable`
`dds::log::LogEvent` publisher generated from `DdsLog.idl` → our reader, every field decoded.

## Result

**INTEROPERATES (Connext writer → our reader).** Our reader decoded every field correct across the
vendor boundary — including the source-identity fields and an **IPv6** `host_ip`:

```
host="connext-node" pid=4242 uuid="8b619879-4ffe-4fca-ad01-05b39d987dbc" ip="fe80::ffff:ffff:ffff:1"
appid="gbttctools" seq=4 sev=CRIT cat="MEM" ek=EXIT msg="segfault at frame 4"
```

`app_id` and an IPv6 `host_ip` both survive the round trip; `host_ip` (`string<46>` =
`INET6_ADDRSTRLEN`) carries IPv4 and IPv6 alike.

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

## Both cross-DDS legs + the byte-exact corpus vector — DONE

**Fast DDS leg (`interop/fastdds/log/`).** A Fast DDS 3.6.1 `@appendable dds::log::LogEvent` publisher
(`log_pub.cpp`, fastddsgen from this same canonical `DdsLog.idl`) → our reader (`log_sub.lisp`):
**INTEROPERATES**, 192 samples, every field decoded (host, pid, uuid, IPv6 `host_ip`, app_id, seq,
CRIT, MEM, EXIT). A loopback-pinned Fast DDS peer is reached by unicast SPDP to `127.0.0.1:7410..`.
This leg caught a **third IDL defect** the Connext leg could not: **fastddsgen rejects explicit enum
values** (`SEV_EMERG = 0`) that rtiddsgen accepts — the `Severity` enum is now plain sequential values
(identical wire, both vendors generate). The Connext leg was re-confirmed from the same unified IDL.

**Byte-exact corpus vector (`corpus/xcdr2/logevent-connext.bin`).** Captured OFF THE WIRE from the
Connext writer (`log_capture.lisp`) and round-tripped through our codec — deserialize → re-serialize →
**BYTE-EXACT** (260 octets). This is the ENCODER oracle the decoder-legs cannot give, and the first
`@appendable` byte-exact vector (the perfdata corpus is `@final`). A stock `@appendable` writer sends
our `LogEvent` as **XCDR1 (`0x0001`, no DHEADER, rule 29)** because our reader accepts XCDR1, so the
vector is XCDR1. Verified in the test suite by `run-log-corpus-test` (`make corpus` is perfdata-only).

## Still open

The reciprocal (our LogEvent writer → a foreign reader). It rides the DATA_REPRESENTATION note in
`../enum-typeobject/README.md`: our writer offers XCDR1 for a stock `@final` reader; `LogEvent` is
`@appendable`, so the reader's requested representation governs.
