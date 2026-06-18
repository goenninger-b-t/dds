# Spike findings: TRANSIENT durability-service virtual-GUID dedup wire format

**Date:** 2026-06-18
**Branch:** wp-durability-service-transient
**Task:** Task 1 of the TRANSIENT durability service plan — investigate what wire
mechanism a foreign persistence service uses to let a late-joining reader deduplicate
durable samples (so a sample relayed by multiple sources is received only once).
**Scope:** investigation only; no production code.

---

## 1. Tooling availability verdict

| Tool | Verdict | Notes |
|---|---|---|
| RTI Connext Persistence Service (`rtipersistenceservice`) | **RUNNABLE HERE** | `$NDDSHOME/bin/rtipersistenceservice` v7.3.1.0; the built-in `default` TRANSIENT config (in `$NDDSHOME/resource/xml/RTI_PERSISTENCE_SERVICE.xml`) runs with `-cfgName default` |
| RTI Connext shapes publisher/subscriber | **RUNNABLE HERE** | The committed `interop/connext/shapes-{pub,sub}` harnesses; TRANSIENT durability configured via a loopback+TRANSIENT QoS XML profile (created for this spike) |
| eProsima Fast DDS persistence plugin | **NOT REQUIRED** | Fast DDS 3.6.1 is installed and runnable (`scripts/with-fastdds.sh`), but its persistence requires SQLite3 (the installed build has `HAVE_SQLITE3` gated) and a custom plugin; not attempted — the RTI capture alone was sufficient to identify the mechanism (and the Fast DDS source code, Apache-2.0, independently confirms the same PID and byte layout; see §4) |

**Live TRANSIENT relay was successfully captured** (RTI PS v7.3.1 relaying to a late-joining Connext
subscriber after the original publisher exited).

---

## 2. Capture procedure

Setup on `lo0`, domain 0, loopback-pinned (UDPv4 only, `allow_interfaces=127.0.0.1`):

```
tshark -i lo0 -f "udp portrange 7400-7700" -w spike-rtips-transient-virtual-guid.pcap
```

1. **Connext shapes publisher** (TRANSIENT, RELIABLE, KEEP_ALL) publishes 80 `Square/GREEN` samples
   at 1/sec for ~17 seconds, then exits.  Original publisher participant GUID:
   `{010166f28f4f795fa08ecda9}:80000002`.
2. **RTI Persistence Service** (`spike-transient` config, in-memory TRANSIENT) runs concurrently,
   subscribes to `Square`, collects all samples.
3. After the publisher exits, a **late-joining Connext shapes subscriber** (TRANSIENT, RELIABLE)
   joins.  The PS re-published 80 samples to it; the subscriber received `#1 color=GREEN x=53 y=52`
   (the original publisher's first pre-exit sample) through to `#80` — confirming TRANSIENT relay.

Capture: `interop/durability-transient/captures/spike-rtips-transient-virtual-guid.pcap` (479 KB).

---

## 3. Identified PID + byte layout + dedup rule

### 3.1 The standard PID: PID_ORIGINAL_WRITER_INFO (0x0061)

**This is NOT a vendor PID.** It is a standard OMG RTPS 2.5 PID in the conformant range
0x0000–0x7FFF. RTI Connext uses this PID in its inline QoS on every DATA submessage it relays
through the Persistence Service.

tshark RTPS dissector output for a single relayed DATA submessage (frame 1102):

```
submessageId: DATA (0x15)
    Flags: 0x07, Data present, Inline QoS, Endianness
    writerEntityId: 0x80000002 (PS relay writer entity)
    writerSeqNumber: 1
    inlineQos:
        PID_ORIGINAL_WRITER_INFO
            parameterId: PID_ORIGINAL_WRITER_INFO (0x0061)
            parameterLength: 24
            guidPrefix: 010166f28f4f795fa08ecda9      ← original writer's GUID prefix (12 B)
            virtualGUIDSuffix: 0x80000002              ← original writer's EntityId (4 B)
            virtualSeqNumber: 1                        ← original writer's SequenceNumber
        PID_KEY_HASH
            parameterId: PID_KEY_HASH (0x0070)
            parameterLength: 16
        PID_SENTINEL
            parameterId: PID_SENTINEL (0x0001)
    serializedData: CDR_LE (0x0001) ...
```

### 3.2 Byte layout (PL_CDR parameter, LE endian)

Raw hex from frame 1102 (offset 0x66 into the RTPS payload):

```
61 00  18 00
01 01 66 f2  8f 4f 79 5f  a0 8e cd a9   ← guidPrefix[0..11] (12 bytes)
80 00 00 02                               ← entityId[0..3]    (4 bytes)
00 00 00 00                               ← SequenceNumber.high (4 bytes)
01 00 00 00                               ← SequenceNumber.low  (4 bytes, LE → SN=1)
```

Structure (Little-Endian):

| Offset | Size | Field | Value in capture |
|---|---|---|---|
| 0 | 2 | `paramId` (LE) | `0x0061` |
| 2 | 2 | `paramLength` (LE) | `0x0018` = 24 |
| 4 | 12 | `guidPrefix` | original writer's 12-byte GUID prefix |
| 16 | 4 | `entityId` | original writer's 4-byte EntityId (incl. kind byte) |
| 20 | 4 | `SequenceNumber.high` | `0x00000000` |
| 24 | 4 | `SequenceNumber.low` (LE) | `0x00000001` = SN 1 |
| 28 | — | (next PID follows, 4B-aligned) | |

Total parameter body = 24 bytes (guidPrefix 12 + entityId 4 + SN 8 = 24). ✓

The `paramId + paramLength` header is 4 bytes; total wire footprint per relayed DATA = 28 bytes
of inline QoS for this PID (plus PID_KEY_HASH + PID_SENTINEL, which are unrelated).

The RTPS spec name for this structure is **`OriginalWriterInfo`** (RTPS 2.5 §8.3.5.4).  The PL
parameter carries `{GUID, SequenceNumber}` identifying the sample as it was numbered by the
original writer — not the relay writer.

### 3.3 SEDP-level PID: PID_ENTITY_VIRTUAL_GUID (0x8002)

Additionally observed in the SEDP PUBLICATION announcement from the PS relay writer's endpoint:

```
PID_ENTITY_VIRTUAL_GUID (0x8002)
    parameterLength: 16
    parameterData: 010166f28f4f795fa08ecda9 80000002   ← original writer GUID (16 bytes)
```

This is the same 16-byte GUID (guidPrefix + entityId) as in the inline-QoS PID_ORIGINAL_WRITER_INFO,
but at SEDP discovery level (not per-sample inline QoS).  It advertises which original GUID this relay
endpoint represents.  The tshark dissector labels it `PID_ENTITY_VIRTUAL_GUID`; Fast DDS source names it
`PID_PERSISTENCE_GUID` (same PID id 0x8002, same layout) in `ParameterTypes.hpp`.

Also observed alongside `PID_ENTITY_VIRTUAL_GUID`:
- `PID_SERVICE_KIND (0x8003)` → value `PERSISTENCE_SERVICE_QOS (0x00000001)`: marks the PS participant
  as a persistence service.
- `PID_EXPECTS_VIRTUAL_HB (0x8009)` → `false` (0x00000000): the subscriber side carries this.
- `PID_ROLE_NAME (0x800a)` → `"PERSISTENCE_SERVICE"` (string PID).

These are RTI vendor PIDs (0x8000+); a conformant receiver that does not understand them MUST ignore
them per RTPS 2.5 §8.3.5.10 (unknown parameters with `V_FLAG` set or `ID < 0x8000` must be forwarded;
others ignored unless recognized).

### 3.4 Dedup rule

The late-joining receiver applies the following rule (observed from captured 1085 relayed DATA messages):

1. For each incoming DATA with `PID_ORIGINAL_WRITER_INFO` inline QoS:
   - Extract `{originalGUID, originalSN}` = `{guidPrefix + entityId, SequenceNumber}` from the PID.
   - Map the relay sender's GUID → `originalGUID` in a per-reader `history_record` map.
   - Track `max_received_SN[originalGUID]` = the highest `originalSN` received from ANY relay for
     this original writer.
   - Accept the sample only if `originalSN > max_received_SN[originalGUID]`; discard otherwise
     (duplicate from a second relay).
2. For DATA without `PID_ORIGINAL_WRITER_INFO` (direct non-relay writer):
   - Standard RTPS SN tracking: track `max_received_SN[writerGUID]` in the normal way.

This is the exact mechanism implemented in Fast DDS's `BaseReader::add_persistence_guid` /
`get_last_notified` / `update_last_notified` (source: `src/cpp/rtps/reader/BaseReader.cpp`
lines 397–490, Apache-2.0, consulted for cross-vendor confirmation; see §6 Clean-room/provenance).

**Edge case:** if both the original writer AND a relay are alive simultaneously and matched to the
same reader, the reader receives the same sample twice — once with `PID_ORIGINAL_WRITER_INFO` (from
the relay) and once without (directly from the original writer).  The dedup map handles this: when
the original writer is matched, its GUID is recorded as mapping to itself
(`persistence_guid_map[guid] = guid`); when the relay is also matched and carries the same
`originalGUID`, both map to the same key in `history_record`, so the max-SN check deduplicates.

---

## 4. Inter-service coordination: observable gap

The capture covers a **single PS instance**.  What was **NOT** observed (and is not observable on
the wire with a single PS instance):

- How two independent PS instances avoid delivering the same sample twice to a late-joiner that
  matches both.
- Whether there is an inter-service coordination protocol beyond the dedup-at-receiver mechanism.

The mechanism is entirely **receiver-side dedup** (based on the `(originalGUID, originalSN)` tuple
carried in inline QoS): no inter-relay coordination protocol is observable.  Any two relays that
carry the same `PID_ORIGINAL_WRITER_INFO` for the same original sample will be deduplicated by the
receiver.  This is the intended design — the standard `OriginalWriterInfo` mechanism is receiver-side
only.

The **open question** (deferred): can a conformant receiver that does not yet understand
`PID_ENTITY_VIRTUAL_GUID (0x8002)` / `PID_SERVICE_KIND (0x8003)` (the RTI vendor SEDP PIDs) still
correctly dedup?  Answer from the spec: YES — `PID_ORIGINAL_WRITER_INFO (0x0061)` is the only
per-sample inline QoS needed for dedup, and it is a standard PID.  The vendor SEDP PIDs are
supplementary (service identification, SEDP-level virtual GUID annotation) and can be safely ignored
by a non-RTI receiver without breaking correctness.

---

## 5. Phase 2 design recommendation

Phase 2 (durability service / TRANSIENT) MUST emit `PID_ORIGINAL_WRITER_INFO (0x0061)` in the
inline QoS of every relayed DATA submessage, carrying the original writer's GUID and original
SequenceNumber.  This is sufficient for conformant cross-vendor dedup (both RTI Connext and
eProsima Fast DDS consume it).

### 5.1 Conformant substrate

The Phase 2 durability service relay writer MUST:

1. **Set the `Q-BIT` (Inline QoS present) flag** in every relayed DATA submessage.
2. **Emit `PID_ORIGINAL_WRITER_INFO (0x0061)`** in the inline QoS parameter list with:
   - `guidPrefix[12]` = original writer's GUID prefix (from the captured `CacheChange`)
   - `entityId[4]` = original writer's EntityId
   - `seqNumber[8]` = original writer's SequenceNumber (high=0, low=SN, LE)
3. **Track the original GUID+SN for each stored `CacheChange`** in the relay's internal history
   (`HistoryCache`), so it can fill in the `PID_ORIGINAL_WRITER_INFO` at relay time.

A `CacheChange` already carries `writerGUID` and `sequenceNumber` — Phase 2 stores them verbatim
at collection time and re-emits them in inline QoS at relay time.

### 5.2 Receiver-side dedup (our TL reader)

Our existing TL reader does not yet dedup by `originalGUID`.  Phase 2 does not require the reader
to change for TRANSIENT_LOCAL (the original writer is always alive; no relay involved).  But once
Phase 2 introduces the relay writer, a reader that matches BOTH the original writer AND the relay
writer for the same topic must dedup.  The Phase 2 plan should add a `%reader-apply-original-writer-info`
step to the DATA receive path that:
- Extracts `PID_ORIGINAL_WRITER_INFO` from inline QoS when present.
- Maintains `max-received-sn[originalGUID]` per matched original GUID.
- Discards a DATA if `originalSN <= max-received-sn[originalGUID]`.

This can be a deferred Phase 2 sub-task (not needed for the Phase 2 relay-writer MVP; only needed
when a Connext/Fast DDS relay AND our direct reader co-exist on the same topic simultaneously).

### 5.3 Vendor PIDs: deferred-with-documented-assumption

Emitting the RTI vendor SEDP PIDs (`PID_ENTITY_VIRTUAL_GUID 0x8002`, `PID_SERVICE_KIND 0x8003`,
`PID_EXPECTS_VIRTUAL_HB 0x8009`, `PID_ROLE_NAME 0x800a`) is NOT required for correctness and is
deferred.  Assumption: a conformant RTI Connext or Fast DDS receiver will correctly dedup using
only `PID_ORIGINAL_WRITER_INFO (0x0061)` in inline QoS, regardless of whether the SEDP-level vendor
PIDs are present.  This assumption is consistent with Fast DDS source code (`WriterProxyData.cpp`
line 976 — the receiver handles `PID_PERSISTENCE_GUID` but the per-sample dedup relies only on
`OriginalWriterInfo`).

---

## 6. Clean-room / provenance

- **RTI Connext source:** NOT read.  Behavior observed via live `rtipersistenceservice` v7.3.1 on
  `lo0`, dissected with tshark RTPS dissector.  CLEAN.
- **eProsima Fast DDS source** (Apache-2.0, `$HOME/gbt Dropbox/gbt/projects/fastdds/src/fastdds/`):
  consulted for cross-vendor confirmation:
  - `include/fastdds/dds/core/policy/ParameterTypes.hpp` line 123: `PID_ORIGINAL_WRITER_INFO = 0x0061`
    and line 171: `PID_PERSISTENCE_GUID = 0x8002`.
  - `src/cpp/rtps/builtin/data/WriterProxyData.cpp` lines 246, 514, 976: serialization /
    deserialization of `PID_PERSISTENCE_GUID`.
  - `src/cpp/rtps/reader/BaseReader.cpp` lines 397–490: `add_persistence_guid` / `get_last_notified`
    / `update_last_notified` — the receiver dedup map implementation.
  - `src/cpp/rtps/messages/submessages/DataMsg.hpp` lines 48–155: `PID_ORIGINAL_WRITER_INFO`
    serialized in inline QoS when `change->write_params.original_writer_info() != unknown()`.
  - No code was copied.  Reading for understanding only, per the operating contract §4
    (Apache-2.0 confirmed; recorded here per NFR-IP and `docs/provenance.md`).
- **OMG RTPS 2.5 spec:** `PID_ORIGINAL_WRITER_INFO` (0x0061) is defined in RTPS 2.5
  §8.3.5.4 (`OriginalWriterInfo` submessage element) and Table 9.12 (PID table).
  `SequenceNumber` is defined in §8.3.3.4 (8-byte: `int32` high + `uint32` low).
- **Capture:** `interop/durability-transient/captures/spike-rtips-transient-virtual-guid.pcap`
  — taken on this host's `lo0`, clean-room observation only.

---

## 7. Summary

| Finding | Value |
|---|---|
| RTI Persistence Service | Runnable (v7.3.1, TRANSIENT in-memory config) |
| Fast DDS persistence | Not run (not required) |
| Per-sample dedup PID | **`PID_ORIGINAL_WRITER_INFO (0x0061)`** — standard OMG RTPS |
| PID layout | `paramId(2B) paramLen(2B=24) guidPrefix(12B) entityId(4B) SN.high(4B) SN.low(4B)` |
| Dedup rule | Receiver: `max_received_SN[originalGUID]`; discard if `originalSN ≤ max` |
| SEDP-level virtual GUID PID | `PID_ENTITY_VIRTUAL_GUID (0x8002)` — RTI vendor PID, SAME as Fast DDS `PID_PERSISTENCE_GUID`; 16-byte GUID value |
| Service identification PIDs | `PID_SERVICE_KIND (0x8003)`, `PID_ROLE_NAME (0x800a)`, `PID_EXPECTS_VIRTUAL_HB (0x8009)` — RTI vendor PIDs |
| Phase 2 action | Emit `PID_ORIGINAL_WRITER_INFO` in inline QoS of every relayed DATA; `PID_ENTITY_VIRTUAL_GUID` in SEDP deferred |
| Receiver dedup | Deferred Phase 2 sub-task (needed when relay + direct writer co-exist) |
