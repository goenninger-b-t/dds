# OWNERSHIP (SHARED/EXCLUSIVE) + OWNERSHIP_STRENGTH — design

**Goal:** Implement OWNERSHIP QoS: advertise it in SEDP (PID_OWNERSHIP + PID_OWNERSHIP_STRENGTH),
and on an EXCLUSIVE reader deliver samples for an instance only from the highest-strength alive
writer (the owner), with owner takeover when the owner vanishes (DDS 1.4 §2.2.3.9 / §2.2.3.10).

## Current state (from exploration)
- QoS slots EXIST: `qos-ownership` (:shared/:exclusive, default :shared), `qos-ownership-strength`
  (integer, default 0) — `src/dds-qos/qos.lisp:111`.
- RxO EXISTS + correct: `qos-rxo-compatible` requires OWNERSHIP kind EQUALITY (qos.lisp:164;
  strength is writer-only, not RxO-checked). DDS 1.4 §2.2.3.9.
- The S2 instance-lifecycle substrate is READY: per-instance `instance-rec` with a `writers` set
  (matched remote writer EntityIds, entities.lisp:149); `node-sample-writer` (the source writer of a
  sample); the disc `matches` table (writer GUID → endpoint-data.qos); `%on-writer-vanished` /
  `%reader-revive-instance` hooks.
- MISSING: the wire PIDs + SEDP codec; the EXCLUSIVE reader arbitration.

## Wire format (pin from docs/specs; byte-validate vs Fast DDS oracle in S0)
- **PID_OWNERSHIP** (0x001f) = OwnershipQosPolicy `{ kind: long }`, SHARED=0 EXCLUSIVE=1
  (dds_rtf2_dcps.idl OwnershipQosPolicyKind; RTPS 2.5 §9.6.2.2).
- **PID_OWNERSHIP_STRENGTH** (0x0006) = OwnershipStrengthQosPolicy `{ value: long }` (writer only).
- Both u32 LE in the ParameterList, like PID_RELIABILITY/DURABILITY.

## Staged plan

**S0 — wire codec (mechanical, self-contained).**
- `+pid-ownership+` 0x001f + `+pid-ownership-strength+` 0x0006 (message.lisp, cite §9.6.2.2).
- `serialize-endpoint-data`: emit PID_OWNERSHIP (kind 0/1) always; emit PID_OWNERSHIP_STRENGTH only
  for a WRITER (publication) role (strength is writer-only) — needs the role, which the serializer
  must know (check how the role is available; mirror how reliability defaults differ by role in the
  parser). `parse-endpoint-data`: parse both into the endpoint qos (bounds-checked; unknown ignored).
- Byte-validate vs a captured Fast DDS SEDP (a Fast DDS writer with OWNERSHIP=EXCLUSIVE + a strength)
  — lock the vector. Fast DDS shapes_pub gains an env-gated OWNERSHIP/STRENGTH (like WLP_LEASE_MS).
- RxO already enforces kind equality — confirm an EXCLUSIVE-vs-SHARED mismatch now blocks the match
  on the wire (a Fast DDS EXCLUSIVE writer vs our default SHARED reader → no match), and matching
  kinds still match.

**S1 — reader-side EXCLUSIVE arbitration.**
- Per-instance OWNER state: extend `instance-rec` with `owner` (the current owner's writer identity)
  + the owner's strength. The owner = the highest-strength ALIVE writer among the instance's writers.
- **Source-writer identity:** a sample's source must be resolvable to its advertised strength. Today
  `node-sample-writer` returns the writer EntityId (4 octets); the `matches` table is keyed by full
  GUID (16). Two writers on different participants can share EntityId 0x102, so EXCLUSIVE needs the
  FULL source GUID. Extend the engine to record the source GUID (datagram prefix + writer EntityId)
  per sample (sample-writers → GUID), and a helper to fetch a matched writer's
  (ownership-kind, strength) by GUID from `matches`.
- In `%drain-one-sample` (EXCLUSIVE reader only): fetch the source writer's strength; if the instance
  has no owner or the source strength > the owner's strength (or it IS the owner), the source becomes
  the owner and the sample is DELIVERED; if the source strength < the owner's, DROP the sample (do
  NOT deliver, do not enqueue). Tiebreak equal strength deterministically by GUID (higher GUID wins —
  document; DDS leaves it implementation-defined). SHARED readers deliver unconditionally (unchanged).
- **Owner takeover:** when the owner writer unmatches/vanishes (`%on-writer-vanished`) or its
  liveliness is lost or it disposes/unregisters the instance, clear the owner; the next sample from
  the now-highest-strength alive writer reclaims ownership. (v1: recompute lazily on the next sample
  rather than eagerly scanning — simpler + correct; document.)
- Tests: two writers strengths 10 + 20 → an EXCLUSIVE reader delivers only the strength-20 writer's
  samples; the strength-10 writer's samples are dropped; kill/vanish the strength-20 writer → the
  strength-10 writer's samples are then delivered (takeover). A SHARED reader delivers both. RxO: an
  EXCLUSIVE writer vs SHARED reader does not match.

**S2 — live interop (wire-is-oracle).**
- Fast DDS: two Fast DDS EXCLUSIVE writers (strengths) → our EXCLUSIVE reader delivers only the
  owner's; takeover on owner kill. And our EXCLUSIVE writer + strength → Fast DDS EXCLUSIVE reader
  arbitrates. Capture + byte-validate PID_OWNERSHIP(_STRENGTH); provenance.

## Out of scope
OWNERSHIP interaction with DEADLINE/liveliness ownership-loss timing nuances beyond
vanish/dispose; the `ownership` of builtin topics; per-sample coherent-set ownership.
