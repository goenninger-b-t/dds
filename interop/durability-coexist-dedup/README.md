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

## Live status — CAPTURED (WP-DURABILITY-COEXIST-LIVE, ADR 0028, 2026-06-21)

**Cross-vendor dual-relay exactly-once is now LIVE-CAPTURED in both directions.** The root cause of the
ADR 0027 divergence was identified and fixed: `%collect-loop` was storing the **wire sender GUID** instead
of the OWI **logical origin** GUID. When RTI PS's TRANSIENT replay won the arrival race our relay stored
RTI PS's relay GUID (`0x80000002`), not the publisher's — so the two relays' `0x0061` origins diverged.

**Fix:** per-sample logical-origin capture in `disc-node` (`node-sample-origin-guid`/`node-sample-origin-sn`
accessors; `%record-sample-origin` on `on-data`); `%collect-loop` now re-stamps `store-put` + dedup from
the logical origin. Default/direct path byte-identical (no OWI → effective = wire).

**Capture results (`captures/coexist-dir-{a,b}.pcap`):**

| Direction | Receiver | N | Both relays' OWI origin GUID |
|---|---|---|---|
| dir-a | our-stack reader | **545** | `0101642e5f4294116dd106b480000002` (publisher's real GUID) |
| dir-b | Connext `shapes_sub` | **550** | `01017344014e53c9630ac19e80000002` (publisher's real GUID) |

UNION = N in both directions. Naïve 2-relay sum = 1090 / 1100 respectively. Both relays stamp the
**same** publisher GUID (EntityId kind `0x02`, USER_DEFINED) — no divergence. Both runs converged on the
FIRST attempt. `analyze-capture.py --assert-converged` exits 0 on both captures.

**ADR 0027 §follow-on 1 is RESOLVED** by ADR 0028.

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
