# WRITER_DATA_LIFECYCLE.autodispose_unregistered_instances — design

**Goal:** Implement the WRITER_DATA_LIFECYCLE QoS `autodispose_unregistered_instances` (DDS 1.4
§2.2.3.21, **default TRUE**): when a writer unregisters an instance and autodispose is TRUE, the
instance is also DISPOSED — so the unregister DATA carries StatusInfo Disposed|Unregistered and the
reader reports NOT_ALIVE_DISPOSED (not NOT_ALIVE_NO_WRITERS).

## Why (conformance gap, oracle-confirmed)
A live Fast DDS clean unregister (no prior dispose) emits StatusInfo `0x03` (Disposed|Unregistered) —
its default autodispose is TRUE (`interop/fastdds/captures/` clean-unregister frame). Our current
unregister emits only Unregistered (`0x02`), so a conformant peer's default behaviour differs from
ours and our reader mis-reports the instance state. This closes that gap.

## Current state
- The instance-lifecycle S0/S1/S2 dispose/unregister path: `+statusinfo-disposed+` 0x01 /
  `+statusinfo-unregistered+` 0x02 exist; `unregister-instance` (disc + DCPS) emits StatusInfo
  Unregistered (0x02); `status-info->kind` maps U-dominates → `:unregister`; the reader
  `%drain-one-lifecycle` (entities.lisp) applies the change by the derived KIND.
- WRITER_DATA_LIFECYCLE QoS slot likely does NOT exist (check qos.lisp).

## Design
**A. QoS.** Add `autodispose-unregistered-instances` (boolean, default T) to the writer qos
(`make-writer-qos` / the qos struct). NOT advertised in SEDP, NOT RxO-checked (a writer-local policy,
DDS 1.4 §2.2.3.21). DataWriter reads it from its qos.

**B. Writer.** `unregister-instance` (DCPS DataWriter + the disc entry) emits StatusInfo:
- autodispose TRUE (default) → `Disposed | Unregistered` (0x03).
- autodispose FALSE → `Unregistered` (0x02) only.
The disc `unregister-instance node key-hash` gains a status-flags / autodispose arg (or the DCPS
layer passes the right StatusInfo). `dispose-instance` is unchanged (Disposed 0x01).

**C. Reader (the subtle part).** `%drain-one-lifecycle` must apply the instance state from the
StatusInfo FLAGS, not only the derived kind, because Disposed dominates for the instance_state:
- Disposed bit set → instance_state NOT_ALIVE_DISPOSED (regardless of the Unregistered bit).
- Unregistered bit set → drop the source writer from the instance's writers-set; if no writers
  remain AND the instance is not disposed → NOT_ALIVE_NO_WRITERS.
- So a `0x03` (D|U) → drop the writer AND set NOT_ALIVE_DISPOSED (disposed dominates, §2.2.2.5.1.3).
The lifecycle record already carries `status-flags` (the S2 5-tuple) — use the flag bits, keep the
existing kind for the writers-set bookkeeping. A pure unregister (0x02, autodispose FALSE) still →
NOT_ALIVE_NO_WRITERS (last writer). A pure dispose (0x01) unchanged.

## Tests
- Writer: `unregister-instance` on a default writer emits StatusInfo 0x03 (D|U); with autodispose
  FALSE emits 0x02. Byte-assert.
- Reader: an inbound D|U lifecycle → instance_state NOT_ALIVE_DISPOSED (not NO_WRITERS); a pure 0x02
  unregister → NO_WRITERS; a pure 0x01 dispose → DISPOSED.
- Regression: the S2 instance-lifecycle tests (dcps-no-writers used a pure unregister → must now
  either use autodispose FALSE to keep testing NO_WRITERS, OR be updated to expect DISPOSED under the
  default — pick the conformant expectation + keep the NO_WRITERS path covered via autodispose FALSE).
- Live: a Fast DDS default unregister → our reader reports NOT_ALIVE_DISPOSED (matching the conformant
  default); our default writer's unregister → Fast DDS reports DISPOSED. (S2-style, optional if quick.)

## Out of scope
DataWriter deletion auto-unregistering all its instances (a separate lifecycle event); the
`autopurge_*` READER_DATA_LIFECYCLE timers (backlog item 3).
