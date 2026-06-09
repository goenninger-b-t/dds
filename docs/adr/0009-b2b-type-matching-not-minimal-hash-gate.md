# ADR 0009 — XTypes type-matching against Connext is name + structural, not a minimal-hash gate

- **Status:** Accepted (2026-06-08)
- **Deciders:** A0 (integrator)
- **Amends:** the M4/FR-TYPE-3 roadmap step "b2b" (`docs/MILESTONES.md`, `docs/verification.csv` FR-TYPE-3)
- **Evidence:** `interop/connext/typeobject-probe` capture vs live RTI Connext 7.3.1 (2026-06-08)

## Context

Step **b2b** of FR-TYPE-3 was specified as *"hash-equality match enforcement"*: gate
SEDP endpoint matching on equality of the EK_MINIMAL `EquivalenceHash` carried in
`PID_TYPE_INFORMATION` (0x0075). Our stack emits 0x0075 with a **provisional** minimal
hash (`typeobject-cdr.lisp`). The operating contract (§4, "the wire is the oracle")
requires confirming that hash against a conformant peer before gating on it, because a
wrong hash would block matching.

The `typeobject-probe` was driven against **live RTI Connext 7.3.1** (arm64 macOS) to
capture the reference bytes. Discovery was forced onto loopback UDPv4 (no SHMEM, no
multicast) via a `USER_QOS_PROFILES.xml`, and the SEDP was decoded with the Wireshark
RTPS dissector (the same oracle as `make wire`). Two facts emerged, both from the wire:

1. **Default Connext 7.3.1 (RTI↔RTI, same host) emits NO `PID_TYPE_INFORMATION`
   (0x0075).** Exhaustive PID enumeration of every SEDP `DATA(w)`/`DATA(r)` shows the
   type is advertised **only** via the vendor parameter **`PID_TYPE_OBJECT_LB`
   (0x8021)** — a **ZLIB-compressed COMPLETE TypeObject** (540 bytes uncompressed). The
   minimal `EquivalenceHash` our stack would match on is **not present on the wire**.
   *(Likely cause: for a small type Connext inlines the complete TypeObject via the
   vendor LB PID and skips the TypeInformation/TypeLookup machinery. Whether Connext
   emits 0x0075 to a foreign-vendor peer, or for a type past its inline-size threshold,
   is the open question — see "Follow-ups".)*

2. **`rtiddsgen` bounds the unbounded `string color` at 255** (`string_255_character`,
   Bound 255), so Connext's `ShapeType` is structurally **not** the unbounded-`color`
   type our `define-dds-type` produces. Our committed reference values (87-byte
   MinimalTypeObject, hash `BF E2 A6 2E D8 11 AC 46 3C 40 C9 7D 30 EE`) describe a
   different type and could not match Connext's regardless of (1).

The decompressed complete TypeObject **did** corroborate our structural model: `@final`
(Flags 0x0001, NESTED/MUTABLE clear), members `color`/`x`/`y`/`shapesize` at sequential
Member Ids 0/1/2/3, `color` carrying the **Key** flag, the three longs as `INT_32_TYPE`.

## Decision

**Type-compatibility matching against Connext is established by type name + structural
assignability — never by minimal-hash equality as a hard gate.** Concretely:

- **Do not** make EK_MINIMAL `EquivalenceHash` equality a precondition for endpoint
  matching. A stock Connext 7.3.1 peer sends no 0x0075, so a hash gate would
  **false-reject every Connext endpoint** — a correctness/interop regression.
- Matching consumes the type information a peer actually provides, in priority order:
  (a) the structural **assignability** check (FR-TYPE-4) over a TypeObject obtained from
  the peer, decompressing and parsing **`PID_TYPE_OBJECT_LB` (0x8021)** when present;
  (b) **TypeLookup** request/reply to fetch a remote TypeObject by TypeIdentifier when
  only 0x0075 hashes are advertised; (c) **type-name** equality + local registration as
  the floor, honouring `TYPE_CONSISTENCY_ENFORCEMENT` (`ignore_*` coercion flags).
- **Minimal-hash equality stays an opportunistic fast-path only** — usable to short-
  circuit assignability **when both peers advertise 0x0075 with a confirmed hash**, never
  as the sole or mandatory criterion.
- Our stack **continues to emit** `PID_TYPE_INFORMATION` (0x0075) (b2a, standard-
  conformant); we additionally **learn to consume** `PID_TYPE_OBJECT_LB` for Connext
  interop. Emitting the vendor LB parameter ourselves is **not** adopted (clean-room +
  it is RTI-proprietary); we only parse it inbound.

b2b ("enforce minimal-hash equality") is therefore **retired as specified** and replaced
by the matching policy above; the provisional minimal-hash serializer remains gated and
unconfirmed (no wire oracle exists for it in this Connext configuration).

## Consequences

- **Positive:** matching works against real Connext (which does not publish the minimal
  hash); aligns with `TYPE_CONSISTENCY_ENFORCEMENT` coercion semantics already modelled
  (FR-TYPE-4); removes a latent interop-breaking gate before it shipped.
- **Cost:** the stack must gain a `PID_TYPE_OBJECT_LB` reader — ZLIB inflate + complete
  TypeObject parse — and (later) the TypeLookup service. The provisional minimal-hash
  serializer is now exercised only by our own round-trip tests, not by Connext interop.
- **No code lands in this ADR.** It records the finding and the redirected plan; the
  reader/TypeLookup work is scheduled separately under FR-TYPE-3.

## Follow-ups

- **Decide b2b viability at all:** capture whether Connext emits `PID_TYPE_INFORMATION`
  (0x0075) to a **foreign-vendor** peer (our non-RTI `square-sub` ↔ Connext
  `shapes-pub`) and/or for a type larger than its inline-TypeObject threshold. If yes,
  the hash fast-path is reachable in real deployments; if no, it is RTI-unreachable.
- **Align the oracle type:** `interop/connext/common/ShapeType.idl` must be made to match
  our generated type exactly for any future byte comparison — either bound our `color` at
  255 to match `rtiddsgen`'s default, or generate Connext with a truly-unbounded string
  (`-unboundedSupport` / explicit bound). The current "keep it UNBOUNDED" note in the
  harness README is wrong and is corrected alongside this ADR.
- **Implement** the `PID_TYPE_OBJECT_LB` inbound reader (ZLIB + complete TypeObject parse)
  and wire it into SEDP match-time assignability.

## Verification

The finding is reproducible: build `interop/connext/typeobject-probe` (needs
`NDDSHOME` + `CONNEXTDDS_ARCH`, run with `DYLD_LIBRARY_PATH=$NDDSHOME/lib/$CONNEXTDDS_ARCH`),
capture loopback UDP while it runs, and decode with
`tshark -r <pcap> --enable-protocol null --enable-protocol ip --enable-protocol udp -V`
(this host's Wireshark profile disables those link/net dissectors). The SEDP `DATA(w)`
shows `PID_TYPE_OBJECT_LB` and no `PID_TYPE_INFORMATION`. See the harness README.
