# Instance lifecycle — dispose / unregister + NOT_ALIVE states — design

**Goal:** Implement the DDS instance lifecycle: `DataWriter::register_instance` /
`dispose` / `unregister_instance`, the wire encoding (a DATA carrying the key + `PID_STATUS_INFO`
inline QoS), and reader-side `instance_state` tracking (`ALIVE` / `NOT_ALIVE_DISPOSED` /
`NOT_ALIVE_NO_WRITERS`) surfaced in `SampleInfo`. A core keyed-topic semantic we mishandle today:
a live Connext/Fast DDS peer disposes instances and we treat the dispose DATA as an opaque sample
with the wrong `instance_state`.

## Current state (from exploration)

- `SampleInfo` (`src/dds-dcps/entities.lisp:121`) already has `instance-state`
  (`:alive | :not-alive-disposed | :not-alive-no-writers`), `disposed-generation-count`,
  `no-writers-generation-count`, `instance-handle` — but `%drain` hardcodes `:alive` (line ~463).
- `CacheChange` (`src/dds-rtps/history.lisp:7`) already has `kind` (`:data | :dispose | :unregister`)
  + `instance-key-hash` — scaffolding present, not wired to DCPS.
- `+pid-key-hash+` 0x0070 exists; **`+pid-status-info+` (0x0071) does NOT**.
- DATA flags E/Q/D/K exist (`message.lisp:442`); **inline-QoS (Q) is parsed-as-skip** — the
  ParameterList in a DATA's inlineQos is not decoded. This is the key prerequisite.
- No writer-side instance registry; no `dispose`/`unregister`/`register_instance` DCPS API.
- Reader `dr-instances` tracks only view-state (NEW/NOT_NEW), not instance-state.

## Spec pinning (verify each from docs/specs before locking)

- **RTPS 2.5 §9.6.3.9** — `StatusInfo_t` = `octet[4]`; flags in the last octet: Disposed (D)=0x01,
  Unregistered (U)=0x02, Filtered (F)=0x04. Carried as inline-QoS parameter **`PID_STATUS_INFO`
  (0x0071)**, length 4.
- **RTPS 2.5 §8.7.4 / §8.7.5** — instance lifecycle + the dispose/unregister CacheChange kinds and
  how they ride a DATA (the writer sends a DATA whose `serializedPayload` is the **key** (K flag,
  D clear) with `PID_STATUS_INFO` in inlineQos; the reader resolves the instance by the key /
  `PID_KEY_HASH`).
- **DDS 1.4 §2.2.2.4.2.x** — `register_instance` / `dispose` / `unregister_instance` semantics
  (`dds_rtf2_dcps.idl` ~1214-1242).
- **DDS 1.4 §2.2.2.5 + dds_rtf2_dcps.idl:312** — `InstanceStateKind` (ALIVE=1, NOT_ALIVE_DISPOSED=2,
  NOT_ALIVE_NO_WRITERS=4) + the generation-count / view-state semantics on receiving a dispose.
- **The wire is the oracle:** S0 byte-validates the dispose/unregister DATA + `PID_STATUS_INFO`
  against a captured **live Connext and/or Fast DDS dispose** (lock a regression vector), exactly as
  the WLP/PID_LIVELINESS legs did — do not finalize the wire form from the spec text alone.

## Staged plan

**S0 — wire codec (the foundation).**
- `+pid-status-info+` 0x0071 + `StatusInfo_t` flag constants (D/U/F), pinned + cited.
- Inline-QoS **ParameterList build + parse** inside the DATA submessage (decode the Q-flag
  ParameterList, currently skipped): extract `PID_STATUS_INFO` + `PID_KEY_HASH`; emit them for a
  dispose/unregister. Bounds-checked (NFR-SEC-POSTURE).
- `write-data` / `parse-data` support the dispose/unregister form: K flag (key payload) + D clear +
  `PID_STATUS_INFO` inlineQos. `parse-data-body` returns the change-kind (`:data`/`:dispose`/
  `:unregister`) + key-hash.
- Locked byte-vector test vs a captured Connext/Fast DDS dispose.

**S1 — writer side.**
- A per-writer **instance registry** (instance-handle → state), keyed by the type-support key-hash.
- DCPS API: `register-instance` (returns a handle), `dispose` (handle | sample), `unregister-instance`
  (handle | sample), wired into `data-writer`. Route through `CacheChange` `:dispose`/`:unregister`
  → the disc/reliable send path emits the dispose/unregister DATA (key + `PID_STATUS_INFO`).
  `write` keeps registering the instance ALIVE.
- `OFFERED_DEADLINE`-style status not in scope; this is lifecycle only.

**S2 — reader side.**
- Decode the inbound dispose/unregister DATA (S0 parser) → resolve the instance by key-hash →
  update the reader's per-instance state → set `SampleInfo.instance_state` +
  `disposed_generation_count` / `no_writers_generation_count` on delivered samples (§2.2.2.5).
- `NOT_ALIVE_NO_WRITERS`: when the last matched writer of an instance unregisters OR all matched
  writers unmatch (tie into the existing on-unmatch hook from the lease-expiry feature), the
  instance goes NO_WRITERS. A dispose → NOT_ALIVE_DISPOSED.
- A dispose/unregister surfaces as a SampleInfo with `valid_data = false` (no sample data) per DDS,
  unless coalesced — follow the spec.

**S3 — live interop (wire-is-oracle).**
- Connext: a Connext shapes/keyed writer disposes an instance → our reader reports
  NOT_ALIVE_DISPOSED; our writer disposes → Connext reports it. Capture + byte-validate.
- Fast DDS: same, the conformant peer. Lock vectors; provenance.

## Wire form — RESOLVED against the Fast DDS oracle (2026-06-12, interop/fastdds/captures/instance-dispose-lo0.pcap)
Fast DDS dispose (frame 91) / unregister (frame 113) on the keyed user writer `0x00000102`:
the dispose/unregister rides a **DATA submessage with flags E+Q only** (`0x03`) — **D clear, K
clear, NO serialized payload**. The instance is identified by **`PID_KEY_HASH`** in the inlineQos,
not a serialized key. InlineQos ParameterList:

```
70 00 10 00  <16-octet keyhash>          PID_KEY_HASH (0x0070) len 16
71 00 04 00  00 00 00 0X                 PID_STATUS_INFO (0x0071) len 4; StatusInfo_t octet[4] BE
01 00 00 00                              PID_SENTINEL (0x0001)
```
`StatusInfo_t` flags in the LAST octet (big-endian octet[4], like the WLP kind): Disposed=0x01,
Unregistered=0x02 (dispose→`00 00 00 01`, unregister→`00 00 00 02`; an unregister of an
already-disposed instance carries both → `00 00 00 03`, observed frame 113). So our codec must:
(S0) emit/parse a DATA with Q-flag inlineQos = PID_KEY_HASH + PID_STATUS_INFO, no D/K payload;
(S1) writer sends this for dispose/unregister with the instance's key-hash; (S2) reader keys the
instance by the inbound PID_KEY_HASH (16-octet handle) → instance_state. A dispose with no prior
register is accepted (readers handle out-of-order).

## Out of scope here — QUEUED as the next features (owner directive 2026-06-12)
These follow this feature, each its own brainstorm→spec→plan→execute cycle:
1. **OWNERSHIP** (SHARED/EXCLUSIVE) + `OWNERSHIP_STRENGTH` — exclusive-writer arbitration on the
   reader (highest-strength alive writer wins per instance; DDS 1.4 §2.2.3.9). PID_OWNERSHIP /
   PID_OWNERSHIP_STRENGTH on the wire (the qos slots already exist).
2. **`autodispose_unregistered_instances`** (WRITER_DATA_LIFECYCLE) — auto-dispose an instance when
   its last writer unregisters (DDS 1.4 §2.2.3.21); builds directly on this feature's unregister path.
3. **`WRITER_DATA_LIFECYCLE`** QoS (the autodispose flag) + **`READER_DATA_LIFECYCLE`**
   (autopurge_nowriter / disposed samples) — the reader-side purge timers for NOT_ALIVE instances
   (DDS 1.4 §2.2.3.22).
4. **Change coalescing** — coalesce multiple instance-state changes / batch the dispose+data paths
   (an optimisation, after the above are correct).
