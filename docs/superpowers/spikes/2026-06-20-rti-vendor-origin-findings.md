# Spike findings: RTI Persistence Service per-sample origin encoding on the wire

**Date:** 2026-06-20
**Branch:** wp-durability-coexist-dedup
**WP / Task:** WP-DURABILITY-COEXIST-DEDUP, Task 1 (SPIKE — investigation only, no production code).
**Question (the crux):** Does RTI Persistence Service (RTI PS) carry a **per-sample** origin identity
`(virtualGUID, virtualSN)` on the wire, and if so under which PID, with what byte layout, and is that
identity the original writer's **real** `(GUID, SN)` (the namespace our `PID_ORIGINAL_WRITER_INFO`
dedup already keys on) — Branch A — or a synthetic RTI namespace — Branch B — or is there **no
per-sample SN** at all (FALLBACK)?

---

## Branch: A

> **RTI Persistence Service v7.3.1 carries the per-sample origin under the OMG-standard
> `PID_ORIGINAL_WRITER_INFO (0x0061)` inline-QoS parameter — NOT a vendor 0x80xx PID — and its
> `(GUID, SN)` is the original writer's REAL `(GUID, SN)`, byte-identical in layout to our own
> `encode-original-writer-info`. This is the same PID, the same namespace, and the same byte layout
> our receiver-side dedup (`reader-dedup-accept-p`, ADR 0024) already consumes.**

This **overturns the Phase-3b documented finding** (`interop/durability-persistent/coexistence/README.md`;
ADR 0026 line 282) that "RTI PS stamps `PID_KEY_HASH (0x0070)` + **ZERO** `PID_ORIGINAL_WRITER_INFO`."
That earlier statement was an artifact of *which traffic episode* the Phase-3b capture recorded — see §4.

---

## 1. Method (existing capture first, then a live re-run)

Per controller resolution #2, the existing captures were decoded first; a fresh live run was then
done to independently reproduce the result on this session's wire.

| # | Capture | Scenario |
|---|---|---|
| C1 | `interop/durability-transient/captures/spike-rtips-transient-virtual-guid.pcap` (2026-06-18) | RTI PS relaying retained TRANSIENT history to a **clean late-joiner** (publisher had exited) |
| C2 | `interop/durability-persistent/coexistence/captures/coexistence-transient.pcap` (Phase-3b) | Dual-relay coexistence; the Connext late-joiner was **discovery-flaky** (0 samples in 3 of 4 runs) |
| C3 | `interop/durability-coexist-dedup/spike/captures/rti-ps-replay-owi.pcap` (**this session, 2026-06-20**) | Fresh: RTI PS relaying retained TRANSIENT history to a late-joiner (publisher exited) |
| C4 | `interop/durability-dedup/coexistence/coexistence-run-task8.pcap` (Phase-2) | TRANSIENT_LOCAL topic → RTI PS inert (out of its tier) |

Tooling: RTI Connext 7.3.1 + `rtipersistenceservice` v7.3.1, Connext `shapes_pub`/`shapes_sub`, loopback
(`lo0`, DLT_NULL), domain 0. macOS tshark 4.6.x does not dissect DLT_NULL, so decoding is a **raw RTPS
submessage byte-walk** (`interop/durability-persistent/coexistence/analyze-capture.py`, extended in this
spike with an `--owi-dump` mode). The walk was cross-validated against the tshark RTPS dissector's own
output on C1 (frame 1102, recorded 2026-06-18 — see §3.3).

The RTI PS per-relay byte-walk (`analyze-capture.py`, default mode):

```
# C1 (2026-06-18, clean late-joiner replay):
relay-writer EntityId | DATA | distinct own-SN | distinct OWI-origin | inline-QoS PIDs
  80000002 | 2183 | 2170 | 1085 | 0x0070(PID_KEY_HASH):2183, 0x0061(PID_ORIGINAL_WRITER_INFO):1085

# C2 (Phase-3b coexistence, flaky late-joiner):
  80000002 | 601  | 601  | 0    | 0x0070(PID_KEY_HASH):601
  00000102 | 534  | 534  | 534  | 0x0061(PID_ORIGINAL_WRITER_INFO):534      (OUR relay)

# C3 (this session, fresh replay):
  80000002 | 495  | 495  | 1    | 0x0070(PID_KEY_HASH):495, 0x0061(PID_ORIGINAL_WRITER_INFO):1
```

The same EntityId `0x80000002` (RTI PS relay writer) carries `0x0061` in C1 and C3, and zero in C2 —
the difference is the scenario (§4), not the RTI PS version.

---

## 2. The decoded per-sample origin PID

### 2.1 PID id and layout

RTI PS's per-sample origin carrier is **`PID_ORIGINAL_WRITER_INFO`, parameterId `0x0061`** — an
**OMG-standard RTPS 2.5 PID** in the conformant range `0x0000–0x7FFF` (RTPS 2.5 §8.3.5.4,
`OriginalWriterInfo`; Table 9.12). **It is NOT a vendor PID.** There is **no** RTI vendor `0x80xx`
per-sample origin PID on the relayed DATA — the only two inline-QoS PIDs on RTI PS's relayed DATA are
`0x0061` (origin) and `0x0070` (`PID_KEY_HASH`, 16-byte keyhash). (All distinct PIDs on RTI PS DATA were
enumerated; see §3.2.)

Byte layout of the 24-octet parameter body, **Little-Endian** (matches RTPS 2.5 §8.3.5.4 and our
`encode-original-writer-info`, `src/dds-rtps/message.lisp:782`):

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 12 | `guidPrefix` | original writer's GUID prefix |
| 12 | 4 | `entityId` | original writer's EntityId (incl. kind byte) |
| 16 | 4 | `SequenceNumber.high` | `int32` LE |
| 20 | 4 | `SequenceNumber.low` | `uint32` LE |

(The 4-byte parameter HEADER — `paramId(2 LE) ∥ paramLength(2 LE = 0x0018 = 24)` — precedes this body.)

### 2.2 Captured byte vectors (regression fixtures)

**C1 (2026-06-18), RTI PS `0x80000002`, first 5 relayed-replay samples** — full 24-byte `0x0061` body:

```
origGUID                          origSN  0x0061 body (24B, LE)
010166f28f4f795fa08ecda980000002  1       010166f28f4f795fa08ecda9 80000002 00000000 01000000
010166f28f4f795fa08ecda980000002  2       010166f28f4f795fa08ecda9 80000002 00000000 02000000
010166f28f4f795fa08ecda980000002  3       010166f28f4f795fa08ecda9 80000002 00000000 03000000
010166f28f4f795fa08ecda980000002  4       010166f28f4f795fa08ecda9 80000002 00000000 04000000
010166f28f4f795fa08ecda980000002  5       010166f28f4f795fa08ecda9 80000002 00000000 05000000
```

distinct OWI origins = **1085**, origin SN range **1..1085 contiguous** (= the original publisher's own
sequence numbers).

**C3 (this session, 2026-06-20), RTI PS `0x80000002`** — full 24-byte `0x0061` body:

```
origGUID                          origSN  0x0061 body (24B, LE)
0101cacb014f0b659a231a8f80000002  495     0101cacb014f0b659a231a8f 80000002 00000000 ef010000
```

(`ef010000` LE = `0x000001ef` = 495; the publisher reached SN 495 before being killed and the
late-joiner received that single retained sample, stamped with its real origin SN.)

**Pinned single regression vector (for Task 3's constants file):** the C1 SN=1 value
`010166f28f4f795fa08ecda9800000020000000001000000` decodes to
GUID `010166f28f4f795fa08ecda980000002`, SN `1`.

### 2.3 One full DATA submessage (offset-math proof), C1, RTI PS `0x80000002`

```
endianness = LE,  octetsToInlineQoS = 16,  inlineQoS starts at sub-offset 20
sub body (first 80B):
  0000 1000 00000000 80000002 6601000000000000 7000 1000 30219b4293ba6b3fee6a4fe029813882 01000000 00 ...
  ^extraFlags ^otiq  ^readerId ^writerId ^writerSN          ^PID0070 len16 ^keyhash(16)            ^PID0001(sentinel)
```

DATA layout (RTPS 2.5 §8.3.7.2): `extraFlags(2) ∥ octetsToInlineQoS(2) ∥ readerId(4) ∥ writerId(4) ∥
writerSN(8) ∥ inlineQoS ∥ payload`. inlineQoS begins at `4 + octetsToInlineQoS = 4 + 16 = 20`. The walk's
`iq = 4 + otiq` is therefore correct (confirmed against the dissector and against our own relay's OWI,
which the same walk parses byte-exact). In this particular submessage the inline-QoS order is
`PID_KEY_HASH` then `PID_SENTINEL`; in OWI-carrying submessages the order is `PID_ORIGINAL_WRITER_INFO`,
`PID_KEY_HASH`, `PID_SENTINEL` (frame 1102, §3.3).

---

## 3. Crux answers, with evidence

### 3.1 Is there a per-sample origin `(virtualGUID, virtualSN)` PID? — YES

Under `PID_ORIGINAL_WRITER_INFO (0x0061)`, 24-byte body, carrying `(GUID, SequenceNumber)` per sample.
1085 distinct origin tuples in C1; 1 in C3. The tshark RTPS dissector labels the SN field
`virtualSeqNumber` and the EntityId field `virtualGUIDSuffix` under this PID (§3.3) — i.e. RTI's
"virtual" origin IS the standard `OriginalWriterInfo`.

### 3.2 Is it a vendor 0x80xx PID, or a second per-sample SN carrier? — NO

The complete set of distinct inline-QoS PIDs on RTI PS's relayed DATA (C1, enumerated by raw walk):

```
0x0061 len=24 value=010166f28f4f795fa08ecda9800000020000000001000000   (PID_ORIGINAL_WRITER_INFO)
0x0070 len=16 value=30219b4293ba6b3fee6a4fe029813882                    (PID_KEY_HASH)
```

No `0x80xx` PID on the per-sample DATA. (RTI's vendor `PID_ENTITY_VIRTUAL_GUID (0x8002)` and
`PID_SERVICE_KIND (0x8003)` appear once per relay endpoint in **SEDP discovery**, not per sample — that
was the 2026-06-18 / Task-7 SEDP finding, `docs/superpowers/spikes/2026-06-18-durability-virtual-guid-findings.md`
§3.3. They identify the relay; they are not the per-sample dedup key.) There is **no** second per-sample
sequence-number carrier beyond `0x0061`.

### 3.3 Does `virtualGUID/virtualSN == original writer's real (GUID, SN)`? — YES → Branch A

Three independent confirmations:

1. **Cross-correlation, C1 (positive):** the `analyze-capture.py --owi-dump` cross-check compares each
   relay's OWI origin GUID against the set of GUIDs of writers seen sending *direct* (non-OWI) DATA in
   the same capture. RTI PS's origin GUID `010166f28f4f795fa08ecda980000002` **is** present as a direct
   writer GUID → it is the original Connext publisher's own GUID (the §2 spike publisher GUID was
   `{010166f28f4f795fa08ecda9}:80000002`). And its origin SNs are **1..1085 contiguous** = the
   publisher's own sequence numbering. So `(virtualGUID, virtualSN) = (original writer real GUID,
   original writer real SN)`.

   ```
   origin 010166f28f4f795fa08ecda980000002: also-a-direct-writer-GUID=True
     => Branch A (origin == an original writer real GUID/SN seen in-capture)
   ```

2. **Cross-correlation, C3 (positive, this session):** RTI PS origin GUID
   `0101cacb014f0b659a231a8f80000002` likewise matched a captured direct-writer GUID → Branch A,
   reproduced independently on this session's wire.

   ```
   origin 0101cacb014f0b659a231a8f80000002: also-a-direct-writer-GUID=True
     => Branch A (origin == an original writer real GUID/SN seen in-capture)
   ```

3. **tshark RTPS dissector, C1 frame 1102** (recorded 2026-06-18, `…/2026-06-18-…-findings.md` §3.1):

   ```
   submessageId: DATA (0x15);  writerEntityId: 0x80000002 (RTI PS relay)
   inlineQos: PID_ORIGINAL_WRITER_INFO  parameterLength: 24
       guidPrefix: 010166f28f4f795fa08ecda9      <- original writer's GUID prefix
       virtualGUIDSuffix: 0x80000002             <- original writer's EntityId
       virtualSeqNumber: 1                        <- original writer's SequenceNumber
   ```

   The dissector's own labels confirm the GUID+SN are the original writer's, and that RTI's "virtual"
   identity is carried in the standard `PID_ORIGINAL_WRITER_INFO`.

### 3.4 Does RTI PS's relayed DATA carry the SAME `(GUID, SN)` per sample as the original writer's DATA for the same logical sample? — YES

C1 contains both the original publisher's direct DATA (GUID `010166…80000002`) and RTI PS's relayed DATA
stamped with origin GUID `010166…80000002` + SN 1..1085. The relayed-sample origin tuple equals the
original sample's `(writerGUID, writerSN)` — exactly the cross-relay dedup key. (RTI PS's *own* writerSN
on the relay submessage is unrelated/large, as expected: the relay re-sequences under its own GUID but
preserves the origin in `0x0061`.)

---

## 4. Reconciling with the Phase-3b "ZERO OWI" finding (the discrepancy is resolved)

RTI PS stamps `PID_ORIGINAL_WRITER_INFO` on the **subset** of its DATA that constitutes the
**retained-history REPLAY to a (late-joining) durable reader** — the cross-relay-dedup episode — and
**not** on samples it forwards live while the original writer is still alive. Counts (raw walk, same
EntityId `0x80000002`):

```
C1 (clean late-joiner replay):  total=2183  with-OWI=1085  without-OWI=1098
C2 (Phase-3b, flaky joiner):    total=601   with-OWI=0     without-OWI=601
C3 (this session, replay):      total=495   with-OWI=1     without-OWI=494
```

This is consistent with RTPS semantics: `OriginalWriterInfo` is attached when a Persistence/relay writer
delivers a sample that **did not originate from itself** to a reader as **durable** data. The Phase-3b
coexistence run's Connext late-joiner was discovery-flaky (the Phase-3b README itself records "0 in three
of four runs"); that capture therefore recorded RTI PS's live-forward / collect traffic but **never a
clean replay-to-late-joiner episode**, so it saw zero `0x0061`. It was not wrong about the bytes it
captured — it captured the wrong episode and over-generalized. C1 (taken 2026-06-18) and C3 (taken this
session), both of which contain a genuine RTI-PS-to-late-joiner replay, show `0x0061` unambiguously.

**Corrective note for ADR 0026 / the coexistence README:** the statement "RTI PS stamps … **ZERO**
`PID_ORIGINAL_WRITER_INFO`" is true only of the *live-forward* path and must be qualified — on its
**retained-history replay to a late joiner**, RTI PS v7.3.1 emits standard `PID_ORIGINAL_WRITER_INFO`
carrying the original writer's real `(GUID, SN)`. (This file is the source of the correction; the README
update is the WP follow-on's job, not this spike's.)

---

## 5. Consequence for WP-DURABILITY-COEXIST-DEDUP (Branch A implications)

Because RTI PS uses the **same PID (`0x0061`), the same namespace (original writer's real GUID+SN), and
the same byte layout** as our own relay and our own receiver-side dedup
(`dds.rtps.reliable:reader-dedup-accept-p`, ADR 0024):

- **No vendor-PID decoding is required for cross-vendor dual-relay exactly-once against RTI PS.** Our
  existing standard-OWI dedup already keys on exactly the tuple RTI PS emits on its replay. The premise
  that motivated this WP — "to dedup against RTI-PS samples, a receiver needs a per-sample origin key
  *from RTI's vendor PID*" — does **not** hold for the replay path: the key is the standard
  `PID_ORIGINAL_WRITER_INFO`, which we already parse (`parse-original-writer-info`,
  `src/dds-rtps/message.lisp:800`).
- The previously-planned FALLBACK (recognize the SEDP `PID_ENTITY_VIRTUAL_GUID 0x8002` to synthesize a
  per-sample key) is **not needed for the replay episode** and would only matter if one wanted to dedup
  RTI PS's *live-forward* stream (which carries no per-sample origin at all — but in that scenario the
  original writer is still alive and is itself the authoritative source, so there is nothing for a
  durability relay to add).
- **The remaining task to make the live proof exercisable is a CAPTURE/ORCHESTRATION fix, not a
  protocol fix:** drive the coexistence harness so the Connext late-joiner reliably discovers RTI PS
  *after* the publisher has exited (so RTI PS replays, stamping `0x0061`), with our relay also present
  and also stamping `0x0061`, then assert a single receiver deduplicates the two `0x0061` streams to
  exactly-once. (`run-spike.sh` in this spike reliably produces the RTI-PS-replay-with-OWI episode; the
  Phase-3b coexistence flakiness is the discovery-timing issue to fix.)

**Re-plan guidance for Tasks 3–6 (per the brief's RE-PLAN CHECKPOINT):** Branch A. The constant Task 3
should pin is **not** a new vendor PID — it is the **already-existing** `+pid-original-writer-info+`
(`#x0061`, `src/dds-rtps/message.lisp:777`) with the documented 24-byte LE layout above. There is **no**
RTI `0x80xx` per-sample origin PID to add. The brief's proposed `src/dds-rtps/rti-vendor-origin.lisp`
with `+pid-rti-virtual-guid+` is therefore **unnecessary for the per-sample dedup key** — the spike
recommends Tasks 3–6 be re-scoped from "decode a vendor per-sample PID" to "make the RTI-PS-replay
dual-relay-exactly-once live proof reliable using the standard OWI we already emit/parse" (plus, if the
SEDP `PID_ENTITY_VIRTUAL_GUID` is still wanted as a relay-identity signal, that is the SEDP-level
`+pid-entity-virtual-guid+ #x8002` already constant'd at `src/dds-rtps/message.lisp:750`, NOT a
per-sample carrier).

---

## 6. Documented constant VALUES (for Task 3 — no build change made in this spike)

Per controller resolution #1, this spike makes **no build change** (no
`src/dds-rtps/rti-vendor-origin.lisp`, no `dds-rtps.asd` edit). The pinned values for Task 3 are:

| Symbol (proposed) | Value | Meaning / pin |
|---|---|---|
| (reuse) `+pid-original-writer-info+` | `#x0061` | RTI PS's per-sample origin PID == OMG-standard `PID_ORIGINAL_WRITER_INFO`. Already at `src/dds-rtps/message.lisp:777`. |
| `+rti-origin-owi-len+` | `24` | Body length: guidPrefix(12) ∥ entityId(4) ∥ SN.high(4) ∥ SN.low(4). RTPS 2.5 §8.3.5.4. |
| GUID offset / len | `0` / `16` | bytes 0..15 = original writer GUID (prefix 12 + entityId 4). |
| SN.high offset / len | `16` / `4` | `int32` LE. |
| SN.low offset / len | `20` / `4` | `uint32` LE. |
| Endianness | LE | Per the captured submessage flags (E flag set); confirmed C1 + C3. |
| Regression byte vector (one value) | `010166f28f4f795fa08ecda9800000020000000001000000` | Decodes to GUID `010166f28f4f795fa08ecda980000002`, SN 1 (C1). |

(There is intentionally **no** `+pid-rti-virtual-guid+` per-sample constant: §5 — RTI uses the standard
`0x0061`, not a vendor per-sample PID. If Task 3 wants the SEDP relay-identity PID, it is the existing
`+pid-entity-virtual-guid+ #x8002` at `src/dds-rtps/message.lisp:750`.)

---

## 7. Honest caveats / limits of the evidence

1. **The `--owi-dump` Branch-A cross-check is sufficient, not necessary.** A *positive* result (origin
   GUID == a captured direct-writer GUID) proves Branch A; a *negative* result is **inconclusive** (the
   original writer may simply not be in the capture window — as happens for our own relay in C2, where
   the publisher had exited before tshark started, yielding a spurious "not-a-direct-writer"). The
   Branch A verdict rests on the **positive** cross-checks in C1 **and** C3, plus the dissector labels.
2. **RTI PS emits OWI only on the retained-history replay path** (§4), not on live forwards. A capture
   that does not include a clean replay-to-late-joiner episode will (correctly) show zero `0x0061` —
   this is the trap the Phase-3b run fell into. Any future live proof must guarantee the replay episode.
3. **macOS lo0 / DLT_NULL.** tshark 4.6.x on this host does not dissect DLT_NULL; all per-sample PID
   decoding here is the raw byte-walk (`analyze-capture.py`), which is more precise than the dissector
   for this purpose and was cross-validated against the dissector's frame-1102 output on C1.
4. **Single-vendor / single-version scope.** Findings are for RTI Connext / RTI PS **v7.3.1**. Other
   versions or eProsima persistence were not re-captured here (Fast DDS source independently confirms the
   same `0x0061` id + layout — `…/2026-06-18-…-findings.md` §4/§6, Apache-2.0, read-only).
5. **The fresh C3 capture is thin (1 OWI sample)** because the publisher was killed early; it is a
   *corroboration* of C1's 1085-sample evidence, not a standalone proof. C1 carries the statistical
   weight (1085 contiguous origins).

---

## 8. Clean-room / provenance

- **RTI Connext / RTI PS source, headers, generated code:** NOT read. All behavior observed via live
  `rtipersistenceservice` v7.3.1 on `lo0` and decoded by our own raw RTPS byte-walk. CLEAN.
- **tshark RTPS dissector** used only as an independent cross-check of our byte offsets (frame 1102,
  C1). Output read, not copied.
- **OMG RTPS 2.5:** `PID_ORIGINAL_WRITER_INFO (0x0061)` and `OriginalWriterInfo` defined in §8.3.5.4 and
  Table 9.12; `SequenceNumber` (int32 high + uint32 low) in §8.3.3.4; DATA submessage / octetsToInlineQoS
  in §8.3.7.2. These are the normative pins for the layout in §2.1.
- Recorded in `docs/provenance.md` under the WP-DURABILITY-COEXIST-DEDUP heading.

---

## 9. Summary

| Crux question | Answer | Evidence |
|---|---|---|
| Per-sample origin PID on RTI PS DATA? | **Yes — `PID_ORIGINAL_WRITER_INFO 0x0061`** (standard, not vendor) | C1 (1085), C3 (1), dissector frame 1102 |
| Byte layout | guidPrefix(12) ∥ entityId(4) ∥ SN.high(i32 LE) ∥ SN.low(u32 LE) = 24B | §2.1, raw submessage §2.3 |
| Vendor 0x80xx per-sample PID? | **No** (only `0x0061` + `0x0070`); `0x8002`/`0x8003` are SEDP-only | §3.2 |
| `(virtualGUID,virtualSN)` == original real `(GUID,SN)`? | **Yes** | C1 + C3 positive cross-check, contiguous SNs, dissector labels |
| **Branch** | **A** | §3.3 |
| Constant for Task 3 | **reuse `+pid-original-writer-info+ #x0061`** (no new vendor per-sample PID) | §5, §6 |
| Caveat | RTI PS emits OWI only on retained-history **replay to a late joiner**, not live forwards | §4, §7 |
