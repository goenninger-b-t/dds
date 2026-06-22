# Spike: PID_KEY_HASH on keyed ShapeType DATA — Connext 7.3.1 + Fast DDS 3.6.1

**Date:** 2026-06-21  
**WP:** WP-DURABILITY-KEEPLAST-COMPACTION (M6/P5, ADR 0026 §10)  
**Spec ref:** RTPS 2.5 §9.6.3.7, §9.6.4.8; DDSI-RTPS-v2.5, Table 9.14 (DATA submessage flags)

---

## Question

Does RTI Connext 7.3.1 (and Fast DDS 3.6.1) include `PID_KEY_HASH` (0x0070, 16-octet inline-QoS body)
on keyed `ShapeType` **data** samples (regular `write()` calls, D-flag=1), not only on
dispose/unregister? If yes, what is the value form and the actual 16-byte value for color=BLUE?

This gates T1 (node-gated capture is feasible iff the wire carries it) and T5 (live per-instance
DoD for the compaction feature).

---

## Method

Two-process Connext pub+sub on loopback (127.0.0.1, UDPv4 only — `connext-loopback-qos.xml`
disables SHMEM and pins to lo0) and Fast DDS pub+sub on loopback (profiles.xml pins to 127.0.0.1).
tshark captures all UDP on lo0 to pcapng. A Python decoder walks every RTPS DATA submessage,
checks inline-QoS presence (Q-flag), and reports PID_KEY_HASH (0x0070) occurrence and value.

**Critical note on transport:** without a matched subscriber on the same interface, Connext sends
ONLY discovery traffic (SPDP/SEDP). User data is sent unicast to the subscriber's advertised
locator. For Connext, if the loopback QoS pins to a non-matching IP (e.g. 192.168.2.148 but the
host is at 192.168.2.142), UDPv4 fails and Connext falls back to SHMEM (which is not captured on
lo0). The definitive captures run both pub and sub with loopback QoS so user DATA flows over lo0.

**Connext entity ID for ShapeType user writer:** `0x80000002` (confirmed from Connext verbose log:
`Create | Local keyed user datawriter (GUID: ...0x80000002) for topic "Square"`). This EntityId
is shared with the ParticipantMessage writer by naming convention in some analyses, but in any
given RTPS stream each GUID + EntityId combination is unique to one endpoint.

**Key captures (authoritative):**
- `interop/durability-keeplast/spike/captures/connext-lo0-pub-sub-final.pcap` — Connext user DATA
- `interop/durability-keeplast/spike/captures/fastdds-pub-sub-matched.pcap` — Fast DDS user DATA

---

## Findings

### Connext 7.3.1

**PID_KEY_HASH: PRESENT on ALL keyed DATA-with-payload (D=1) samples.**

| Metric | Value |
|--------|-------|
| User writer EntityId | `0x80000002` |
| Total DATA from user writer | 767 |
| DATA with D=1 (payload) | 767 |
| DATA with PID_KEY_HASH present | 767 |
| Fraction | 767/767 = 100% |
| PID_KEY_HASH form | MD5 (form 1, RTPS 2.5 §9.6.4.8) |
| Value (hex, 16 bytes) | `cac217c318363f8ef1160eeedef9e886` |
| Inline-QoS Q-flag | 1 on ALL keyed user DATA |
| Status-info present on write() samples | no (correct: regular writes have no status_info) |

The Q-flag is set on every ShapeType write, and PID_KEY_HASH is in every inline-QoS block.

### Fast DDS 3.6.1

**PID_KEY_HASH: PRESENT on ALL keyed DATA-with-payload (D=1) samples.**

| Metric | Value |
|--------|-------|
| User writer EntityId | `0x80000002` |
| Total DATA from user writers | 362 (pub writer) |
| DATA with D=1 (payload) | 362 |
| DATA with PID_KEY_HASH present | 362 |
| Fraction | 362/362 = 100% |
| PID_KEY_HASH form | MD5 (form 1, RTPS 2.5 §9.6.4.8) |
| Value (hex, 16 bytes) | `cac217c318363f8ef1160eeedef9e886` |
| Inline-QoS Q-flag | 1 on ALL keyed user DATA |

Same value, same form as Connext. Both implementations agree.

### Key hash value derivation

The value `cac217c318363f8ef1160eeedef9e886` is verified as:

```
MD5(CDR1_BE(color="BLUE")) = MD5(0x00000005 424c554500) = cac217c318363f8ef1160eeedef9e886
```

Per RTPS 2.5 §9.6.4.8: for an unbounded string key, the maximum key serialized size is unbounded
(> 16 bytes), so form 1 (MD5) is always used regardless of the actual value length. The CDR
serialization of the key uses **big-endian** byte order per the spec: length-prefix (4B BE) +
string bytes + null terminator.

Cross-check: `MD5(CDR1_LE(color="BLUE")) = 03b75ae92943b62dba150b7828cee5ab` — does NOT match,
confirming BE is the correct endianness per spec.

---

## Implications

### T1: node-gated capture feasibility

**FEASIBLE.** The durability service collecting reader receives keyed ShapeType DATA samples
with PID_KEY_HASH inline-QoS on every sample. The service can extract the 16-octet key hash
from the raw RTPS inline-QoS without parsing the CDR payload. Per-instance capture (keying
the durable-store by key hash) is viable purely from the wire.

Implementation note: the store key for KEEP_LAST compaction = `topic_name + "/" + keyhash_hex`.
The key hash is stable (same value for same color string from both Connext and Fast DDS),
so the on-disk partition key is deterministic and cross-vendor consistent.

### T5: live per-instance DoD

**ACHIEVABLE via live wire.** The cross-DDS interop DoD for KEEP_LAST compaction can be
verified live: write N instances (different colors), let the durability service collect,
verify that the store holds exactly one sample per key hash (the latest), and that a
late-joining reader receives the correct current value per instance. Both Connext and Fast
DDS deliver PID_KEY_HASH on every write, so the live per-instance count is verifiable
directly from wire analysis without any application-level instrumentation.

The live DoD test replays the same pattern as the PERSISTENT DoD test
(`interop/durability-persistent/`), extended to verify per-instance KEEP_LAST compaction
(N instances, N key hashes, 1 stored sample per hash after multiple writes to the same key).

---

## Captures

| File | Size | Contents |
|------|------|----------|
| `captures/connext-lo0-pub-sub-final.pcap` | 245 KB | **Authoritative Connext** — lo0 pub+sub matched, 767 user DATA all with PID_KEY_HASH |
| `captures/fastdds-pub-sub-matched.pcap` | 108 KB | **Authoritative Fast DDS** — lo0 pub+sub matched, 362 user DATA all with PID_KEY_HASH |
| `captures/connext-dispose-keyhash.pcap` | 252 KB | Connext SIGTERM run — 847 user DATA with PID_KEY_HASH |
| `captures/connext-keyed.pcap` | 25 KB | Discovery-only (no subscriber — no user DATA) |
| `captures/fastdds-keyed.pcap` | 4.6 KB | Discovery-only (no subscriber) |

---

## Summary (one line per peer)

- **Connext 7.3.1:** PID_KEY_HASH present on 767/767 keyed DATA-with-payload; value = `cac217c318363f8ef1160eeedef9e886` (MD5 form 1, CDR1-BE key encoding of "BLUE")
- **Fast DDS 3.6.1:** PID_KEY_HASH present on 362/362 keyed DATA-with-payload; value = `cac217c318363f8ef1160eeedef9e886` (identical — both implementations agree)
