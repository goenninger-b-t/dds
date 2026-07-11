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
by 12); a change with source-timestamp 0 emits nothing.

**Amendment (2026-07-11, closing the §3 follow-on).** A **plain** DCPS `write-sample` / `dispose` /
`unregister` now stamps the **current wall-clock** (`dds.pal:realtime-ns` — a new PAL primitive over
`clock_gettime(CLOCK_REALTIME)`, nanoseconds since the Unix epoch) as its source_timestamp, per DDS 1.4
§2.2.2.4.2.11 (`write` ≡ `write_w_timestamp(now)`). So **every DCPS DATA now carries an INFO_TS** and a
reader always sees a populated `SampleInfo.source_timestamp` — full DDS coverage, matching Connext /
Fast DDS which prefix every DATA with one. This reverses the original "byte-identical default wire"
scope: the DCPS write path is intentionally no longer byte-identical (it gains a 12-octet INFO_TS per
DATA). No corpus regression (the XCDR corpus tests payload serialization, not RTPS framing; the RTPS
byte-exact tests exercise `write-data` directly). No interop regression — validated live (§3). The
low-level `dds.disc:publish-sample` still defaults source-timestamp NIL (no INFO_TS) so the engine
bench / raw disc-API path is unchanged; only the DCPS layer stamps `now`. `writedispose` is a
Connext-compatible extension (not in `dds_rtf2_dcps.idl`), implemented as write-then-dispose, additive.

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

- **DCPS default wire now carries INFO_TS (per the amendment).** Every DCPS write/dispose/unregister
  emits a 12-octet INFO_TS (current wall-clock, or the explicit `_w_timestamp` value); a reader always
  sees a populated `SampleInfo.source_timestamp`. The engine bench / raw `dds.disc:publish-sample` path
  is unchanged (source-timestamp NIL → no INFO_TS). The clock cost is one `clock_gettime` per DCPS
  write on the control-plane wrapper (not the measured engine hot path; gate-hotpath green).
- **Cross-vendor interop validated (2026-07-11).** Our-to-our round-trip: `write_w_timestamp` →
  `source_timestamp` within the 2^-32 fraction granularity, AND a plain write → the reader sees the
  current wall-clock (test `dcps-timestamped-write`, both impls, 551/551). **RX** (validated): our reader
  parses live **Connext 7.3.1** and **Fast DDS** INFO_TS correctly — 2026 wall-clock `source_timestamp`s
  at each peer's publish cadence (`make deadline-sub` prints source_timestamp). **TX** (validated): with
  every DCPS DATA now carrying INFO_TS, **RTI Connext's `rtiddsspy` receives and processes our DCPS
  writer's Square/ShapeType samples** (New data → Modified instance) — Connext accepts our INFO_TS-carrying
  RTPS messages, no regression. (A peer-side *display* of the exact extracted timestamp value was not
  obtained this session — `rtiddsspy`'s output mode does not print source_timestamp and a single-host
  loopback tshark capture did not yield RTPS frames — but the TX byte format is pinned by the symmetric
  codec + the live RX parse of the identical Connext/Fast DDS format.)
- **Representation.** `source_timestamp` is nanoseconds (a single integer) in `SampleInfo` and on the
  DCPS API (`write_w_timestamp` takes DDS `Time_t` sec/nanosec, converted via `%time->ns`); the plain-write
  clock is `dds.pal:realtime-ns` (ns since the Unix epoch, `clock_gettime(CLOCK_REALTIME)`). The
  wire↔nanosecond fraction conversion is lossy below ~0.23 ns (the 2^-32 granularity) — exact for whole
  and half seconds, sub-ns-approximate otherwise; the round-trip test asserts within 1 µs.
- **Follow-ons (recorded):** a direct peer-side capture of the extracted source_timestamp *value* (a
  Connext/Fast DDS tool or tshark RTPS-dissector readout of our INFO_TS on the wire), to complement the
  format-validated TX above.

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
