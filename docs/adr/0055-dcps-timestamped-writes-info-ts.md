# ADR 0055 — Timestamped writes: the INFO_TIMESTAMP wire path and the SampleInfo source_timestamp

Status: Accepted
Date: 2026-07-11
Work package: WP-DCPS-API-COMPLETION Slice S5, task S5.T4 (the timestamped-write tail of the instance/sample-access slice; T1–T3 are ADR-free local-API, shipped `2d975de`)
Relates to: the reader `SampleInfo` (S0, `source-timestamp` slot present but never populated before S5); the discovery Duration_t/Time_t wire codec (`dds.qos:duration-nanosec->wire-fraction`, reused here); the small-DATA send path (`%data-builder`) and the receive dispatch (`%handle-datagram`)

## 1. Context

DDS 1.4 lets an application supply the `source_timestamp` of a write explicitly:
`write_w_timestamp` / `dispose_w_timestamp` / `unregister_instance_w_timestamp` (§2.2.2.4.2.11/.9/.8),
plus the Connext-compatible `writedispose` extension. The reader surfaces it as
`SampleInfo.source_timestamp` (§2.2.2.5.4). On the wire the timestamp rides an **INFO_TIMESTAMP**
submessage (RTPS 2.5 §9.4.5.9 / §8.3.7.9), applied to the DATA submessage(s) that follow it in the
datagram.

Before S5.T4 the stack had the `+submsg-info-ts+` constant and a `SampleInfo.source-timestamp` slot
but **neither emitted nor parsed INFO_TS** — the slot was always NIL and plain writes carried no
timestamp. This is the one S5 task with a wire surface, so it requires cross-vendor interop validation.

## 2. Decision

### 2.1 The wire codec (message.lisp)

`write-info-ts (cursor seconds fraction)` and `parse-info-ts (cursor flags)` implement the INFO_TS
submessage: header (`+submsg-info-ts+` 0x09, E flag, Invalidate clear) + `Time_t{seconds(u32);
fraction(u32)}` where `fraction` is in units of sec/2^32 (§9.3.2.1). The 2^-32 fraction is **not
hardcoded** — it reuses `dds.qos:duration-nanosec->wire-fraction` / `wire-fraction->duration-nanosec`,
the same codec the discovery layer already uses for `Duration_t` (leaseDuration etc.), so the format
is DRY and inherits that path's interop provenance. `parse-info-ts` bounds-checks the 8-octet body
(NFR-SEC-POSTURE) and returns NIL on the Invalidate flag (`+info-ts-flag-invalidate+` 0x02, no body,
clear the current timestamp) or a short body. The internal representation everywhere above the wire is
**nanoseconds** (`sec*1e9 + nsec`), a single integer.

### 2.2 TX — emit INFO_TS only for an explicit timestamp

The DCPS `_w_timestamp` ops thread the timestamp down: `write-sample` gains an optional
`source-timestamp`; `publish-sample` sets it on the returned `cache-change` (the change already had an
unused `source-timestamp` slot, so retransmits carry it too); the dispose/unregister path threads it
through `dispose-instance` / `unregister-instance` → `%dispose-or-unregister` →
`writer-lifecycle-change` → `make-cache-change`. In `%data-builder`, a change whose
`source-timestamp` is **non-zero** emits a 12-octet INFO_TS before its DATA (its packable SIZE grows
by 12); a change with source-timestamp 0 — **every plain write / dispose / unregister** — emits
nothing, so the default wire is **byte-identical** (no corpus / interop regression). This is the
deliberate scope: the stack does not (yet) prefix plain writes with a current-time INFO_TS; that is a
recorded follow-on. `writedispose` is a Connext-compatible extension (not in `dds_rtf2_dcps.idl`),
implemented as write-then-dispose, additive on top of the standard API.

### 2.3 RX — parse INFO_TS whenever present

`%handle-datagram` binds a per-datagram special `*rx-source-timestamp*` (nil) around the submessage
dispatch; the INFO_TS clause sets it (ns); `%deliver-user-sample` reads it and stores it per (GUID, SN)
via `%record-sample-timestamp` in a `sample-timestamps` store that mirrors the existing key-hash store
(purged with the sample). The drain copies it into the delivered `SampleInfo.source_timestamp`. A
dynamic var — not a hook argument — was chosen because the DATA `on-data` hook has many fixed-arity
lambdas (secure-SEDP harness); a per-datagram binding threads the timestamp to the deep store with no
signature churn and no cross-file coupling. **Connext and Fast DDS prefix every user DATA with an
INFO_TS**, so this populates `source_timestamp` on all cross-vendor traffic — not only our own
`_w_timestamp` writes.

## 3. Consequences

- **No default-wire change.** A plain write is byte-identical (source-timestamp 0 → no INFO_TS). The
  only new wire output is an INFO_TS before a `_w_timestamp` write/dispose/unregister's DATA. The only
  new receive behaviour is populating a previously-always-NIL SampleInfo field.
- **Cross-vendor interop validated (2026-07-11).** Our-to-our `write_w_timestamp` → `source_timestamp`
  round-trips within the 2^-32 fraction granularity (test `dcps-timestamped-write`, both impls,
  551/551). Live RX: our reader parses **Connext 7.3.1** and **Fast DDS** INFO_TS correctly — 2026
  wall-clock `source_timestamp`s, incrementing at each peer's publish cadence (interop/deadline harness,
  `make deadline-sub` now prints source_timestamp).
- **Representation.** `source_timestamp` is nanoseconds (a single integer) in `SampleInfo` and on the
  DCPS API (`write_w_timestamp` takes DDS `Time_t` sec/nanosec, converted via `%time->ns`). The
  wire↔nanosecond fraction conversion is lossy below ~0.23 ns (the 2^-32 granularity) — exact for whole
  and half seconds, sub-ns-approximate otherwise; the round-trip test asserts within 1 µs.
- **Follow-ons (recorded):** prefix plain writes with a current-time INFO_TS for full source_timestamp
  coverage (currently only `_w_timestamp` writes carry one); a TX-direction interop capture (our
  `write_w_timestamp` → a Connext/Fast DDS reader's rti/eprosima-reported source timestamp) to complement
  the validated RX direction.

## 4. Alternatives considered

- **Carry source_timestamp in a PID / inline-QoS** (as the plan's shorthand suggested). Rejected: the
  RTPS mechanism for source timestamps is the INFO_TS submessage (§8.3.7.9), which is what Connext /
  Fast DDS emit and what a conformant reader reads; a PID would not interoperate.
- **Thread the timestamp as an `on-data` hook argument** (explicit). Rejected: many fixed-arity hook
  lambdas in the secure-SEDP harness would each need editing, and the deep store (`%deliver-user-sample`)
  has a large signature; the per-datagram dynamic var is minimal and localized.
- **Emit a current-time INFO_TS on every write** (full conformance). Deferred: it changes the byte-exact
  output of every DATA and risks corpus/interop regression; scoping INFO_TS to explicit `_w_timestamp`
  writes keeps the default wire byte-identical while still exercising the full TX+RX path.
