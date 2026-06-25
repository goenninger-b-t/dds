# DDS-Security Auth 2b-i interop — don't-break-plain check (M7/P6 Slice 2b-i)

**Status: ENVIRONMENT-LIMITED (2026-06-25) — live Connext-Security auth interop DEFERRED to Slice 5**

This directory contains the "don't-break-plain" interop harness for
WP-DDS-SECURITY-AUTH-2BI (Slice 2b-i): verifying that an OUR participant that
advertises `PID_IDENTITY_TOKEN` and the PSM endpoint bits 22/23 in its SPDP does NOT
break a PLAIN (non-security) foreign peer.

ADR 0033 documents the full Slice 2b-i design and the honest interop posture.

---

## What this check asserts

A PLAIN Connext 7.3.1 or Fast DDS 3.6.1 peer:

(a) **Discovers our participant** — the unknown `PID_IDENTITY_TOKEN` (PID 0x1001,
    optional bit set per DDS-Security 1.1 §9.4.1.3) is silently skipped per RTPS 2.5
    §9.6.2.2.2. The plain peer's participant list includes our entry.

(b) **Plain Shapes pub/sub works in both directions** — after discovering our
    participant, plain DATA exchange proceeds normally. The security bits do not alter
    the DATA submessage path (serialized-payload protection requires an explicit
    `crypto-transform`, which is `NIL` by default).

(c) **The plain peer does NOT error on our SPDP** — no parse error, no crash, no
    silent drop of our SPDP message.

---

## Environment status

| Tool | Status |
|---|---|
| RTI Connext 7.3.1 (`rtiddsspy`) | INSTALLED |
| RTI Security Plugins | **NOT INSTALLED** (`libnddssecurity.dylib` absent) |
| Fast DDS 3.6.1 | **NOT AVAILABLE** in this environment |
| tshark | AVAILABLE |

**Live execution limitation:** `rtiddsspy` is a subscribe-only monitor; it does not
publish ShapeType samples. The RTI Shapes Demo (the standard headless-capable plain
Connext tool for ShapeType pub/sub interop) requires a display session and is not
scriptable from this shell. Fast DDS peer tools (`fastdds_shapes_demo`) are not
installed. A fully automated live cross-peer don't-break run is therefore not possible
in this environment without operator involvement.

---

## Portable guard (in CI; always green)

`run-auth-spdp-identity-token-test` in `src/dds-tests/security-auth-test.lisp` (T1 of
WP-DDS-SECURITY-AUTH-2BI) provides the portable structural guard:

- **Arm (b) — DEFAULT-OFF byte-identical:** A participant built WITHOUT
  `:identity-token-octets` produces a serialized SPDP that is byte-identical to the
  non-security baseline — no `PID_IDENTITY_TOKEN`, no PSM bits 22/23. All existing
  cross-DDS interop tests (durability, shapes, keyed FlatData, etc.) run under the
  security build with the identity-token slot NIL and all pass. This is the strongest
  possible evidence: the security build does not regress plain interop on the default
  path.

- **Arm (a) — WITH-token round-trip:** A participant built WITH `:identity-token-octets`
  carries `PID_IDENTITY_TOKEN` and PSM bits 22/23. The serialized SPDP round-trips
  correctly. The RTPS spec requirement means a conformant plain peer MUST skip the
  unknown PID silently (see RTPS spec evidence below).

---

## RTPS spec evidence for the don't-break property

**RTPS 2.5 §9.6.2.2.2 (Unknown PID handling):**
Unknown PIDs with the "optional" bit (bit 14 of the PID) set are silently skipped by
a conformant receiver. `PID_IDENTITY_TOKEN` = 0x1001 has bit 14 set (optional) per
DDS-Security 1.1 §9.4.1.3. A plain Connext or Fast DDS receiver MUST skip it without
error.

**RTPS 2.5 §8.5.3.1 (BuiltinEndpointSet):**
A receiver that does not implement DDS-Security parses `BuiltinEndpointSet` as an
opaque bitmask; unknown bits (22 = ParticipantStatelessWriter, 23 =
ParticipantStatelessReader per DDS-Security 1.1 §7.4.6.1 Table 29) are ignored.

**Corroborating cross-DDS history:**
All existing durability-persistent, durability-keeplast, and durability-coexist-live
harnesses run our participant alongside Connext 7.3.1 readers/writers without issue.
Those harnesses use the security build. The identity-token feature adds one additional
PID to the SPDP only when `:identity-token-octets` is non-NIL.

---

## How to run the live check (when a display session is available)

1. `bash run-dont-break-plain.sh` — runs the portable guard unconditionally; describes
   the live steps.

2. For the live plain Connext check:
   - Start the RTI Shapes Demo (non-security configuration, domain 0).
   - Publish a `Square` topic in the Shapes Demo.
   - Run our Lisp participant (see script for the REPL invocation).
   - Observe: our participant appears in the Shapes Demo's discovery list; both sides
     exchange ShapeType DATA normally.
   - Capture with tshark and confirm no RTPS error frames from the Shapes Demo peer.

3. For the live Fast DDS check (when Fast DDS is available):
   - `fastdds_shapes_demo -n 0` (or equivalent CLI tool) on domain 0.
   - Same assertions: discovery + DATA exchange + no errors.

---

## Deferred items

- **Live Connext-Security AUTHENTICATION interop:** the RTI Security Plugins add-on
  (`libnddssecurity.dylib`) is not installed. A live mutual-auth PKI-DH handshake
  between our stack and Connext's security layer is the **Slice 5 item** (the P6 exit
  gate). See ADR 0033 §"Known limitations / Slice-5 carries" and ADR 0032 §cross-vendor-interop.
