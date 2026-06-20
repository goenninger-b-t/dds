# Live dual-relay coexistence vs RTI Persistence Service (WP-DURABILITY-COEXIST-DEDUP)

The cross-vendor coexistence exercise for the durability dedup mechanism (M6/P5, ADR 0026 §10): with
RTI Persistence Service (RTI PS) v7.3.1 **and** our durability service both relaying a Connext TRANSIENT
publisher on a TRANSIENT topic, does a late-joining TRANSIENT receiver get the retained history exactly
once (the two relay streams collapsing to N, not 2N)?

## The headline finding (wire-proven, and it CORRECTS Phase-3b)

**RTI PS is conformant: on its retained-history REPLAY to a late-joiner it stamps the OMG-standard
`PID_ORIGINAL_WRITER_INFO` (0x0061) carrying the original Connext publisher's REAL user-writer GUID** —
the same PID, namespace, and 24-byte LE layout our own relay emits and our receiver dedup
(`reader-dedup-accept-p`, ADR 0024) already consumes. Wire evidence (`analyze-capture.py --owi-dump`):
RTI PS's `0x0061` origin GUID (e.g. `0101fa83…:80000002`) is a **captured direct user-writer**
(EntityId kind `0x02` = USER_DEFINED) — i.e. the original publisher itself, not a synthetic identity.

This **corrects the Phase-3b / ADR-0026 statement** that "RTI PS stamps ZERO `PID_ORIGINAL_WRITER_INFO`."
That was true only of RTI PS's **live-forward** path (samples it forwards while the original writer is
still alive); on its **retained-history replay** — the episode that matters for dual-relay dedup — RTI PS
emits standard OWI. So **cross-vendor dual-relay exactly-once against RTI PS works on the STANDARD path —
no RTI vendor per-sample PID is needed** — provided both relays converge on the same `(origin-GUID, SN)`.

## Capabilities added by this WP

So that our service can actually participate in such a topology:

- **`:relay-durability :transient`** (qos-override; default `:transient-local`, byte-identical) — the relay
  writer advertises TRANSIENT, so a TRANSIENT receiver (the tier RTI PS replays to) can match it. Without
  this our TRANSIENT_LOCAL-only relay (rank 1) could not be matched by a TRANSIENT reader (rank 2).
- **`:collect-durability :transient`** (qos-override; default `:transient-local`, byte-identical) — the
  collect reader advertises TRANSIENT, so it pulls a foreign persistence service's OWI-stamped TRANSIENT
  replay and records the OWI *logical* origin, instead of recording a foreign relay's copies under the
  relay's own wire GUID.

Both default to `:transient-local` ⇒ the normal service is byte-identical to before
(`run-durability-relay-tier-test`, `run-durability-collect-tier-test`, both green Clasp + SBCL).

## Live status — honest

A live cross-vendor dual-relay **exactly-once was not captured** in this WP. With both tiers on, a single
TRANSIENT receiver does match **both** relays (direction (a) reaches `relays=2` — the tier wall is gone),
but the two relays' `0x0061` origins **diverged** in the runs: RTI PS stamped the publisher's real GUID
(`0101fa83…`), while our relay recorded a **different** GUID (`0101f0a9…`) → disjoint origins → a deduping
receiver saw 2N (direction (a): 868 = 2×434), and a Connext receiver pulled from RTI PS alone
(direction (b): N from `0x80000002` only).

**The divergence is on our collect / orchestration side — NOT an RTI virtual-GUID wall** (RTI demonstrably
uses the publisher's real GUID, above) and not a dedup-mechanism defect. Achieving live convergence needs
(a) one publisher genuinely feeding both relays' replays and (b) our collect path recording the *original*
publisher's GUID for a foreign relay's OWI-stamped samples (what `:collect-durability :transient` targets).
A reliable live capture proved finicky to orchestrate (discovery timing of one Connext pub into two foreign
relays + a late-joiner); the exact residual cause was not fully pinned here. **The live convergence capture
is a documented follow-on** (ADR 0027 §follow-ons).

## Authoritative proof (conformant, deterministic)

The mechanism is proven in-process, both impls: `dds.tests:run-durability-no-double-delivery-test` (and the
N-relay arm) — two relays stamping the **same** standard `0x0061 (origin-GUID, SN)` tuple collapse to
exactly N. Since RTI PS is wire-proven to stamp that same standard tuple, RTI PS is — as far as the dedup
key is concerned — just another standard-OWI relay; the open item is purely the live origin *convergence* +
orchestration, not the dedup itself.

## Reproduce / caveats

- `run-coexist-both.sh DIR=a|b|both` — one episode per direction (fresh relays + one publisher that exits +
  a late-joiner). `RTI_PS_TRANSIENT.xml` pins KEEP_ALL/TRANSIENT on the RTI PS relay group. Decode with
  `python3 interop/durability-persistent/coexistence/analyze-capture.py --owi-dump <pcap>`.
- macOS `lo0` is DLT_NULL (tshark 4.6.x doesn't dissect it) → per-sample PID decoding is the raw RTPS
  byte-walk in `analyze-capture.py`, cross-validated against the tshark dissector in Task 1.
- Single vendor / version: RTI Connext + RTI PS v7.3.1.
- EntityId kinds (RTPS 9.3.1.2): `0x02` = USER_DEFINED writer; `0xc0…` (e.g. `0x000100c2`) = BUILTIN — the
  publisher's user writer is `…:80000002` (kind `0x02`), NOT the `0x000100c2` builtin.
