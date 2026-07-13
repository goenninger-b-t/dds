# Fast DDS non-4-aligned leg — and why it does NOT replace the Connext leg

Closes the coverage gap that let ADR 0061 survive: **every type in the Shapes interop legs ends on a 4-byte
member**, so the SerializedPayload trailing pad was never exercised and a real wire defect (the pad counted in
the encapsulation OPTIONS bits but never emitted) went unnoticed by the whole live-interop suite.

`PerfData` (`long id; sequence<octet,65536> data`) lets us sweep the alignment classes — `len mod 4 ∈
{0,1,2,3}` — against an **independent decoder** (`fastcdr`), so the fix is confirmed on a second vendor.

## Run

```sh
# terminal 1 — the Fast DDS subscriber verifies every payload byte (byte i must == i mod 256)
./scripts/with-fastdds.sh bash -c 'cd interop/fastdds/perfdata && ./perf_sub 0 50'
# terminal 2 — publish our bytes at each alignment class, XCDR1 (see the gotcha below)
```

Result (2026-07-13, Fast DDS 3.6.1): **ALL PASS**, 12/12 lengths
(0,1,2,3,5,7,15,63,255,256,257,1023), 5 samples each, every payload byte verified.

**Gotcha — `REP=xcdr1`.** A stock Fast DDS `DataReader` advertises XCDR1. `DATA_REPRESENTATION` is an RxO
policy, so our default XCDR2 writer **silently does not match** it (no error, no incompatible-QoS: just
`matched=0`). Publish as XCDR1 for this leg. That is also useful coverage in itself: the pad rule is
representation-independent (XTypes 1.3 §7.6.3.1.2's clause is universal — its normative example is on
PLAIN_CDR/XCDR1), and this leg exercises it on XCDR1 while `make corpus` exercises it on XCDR2.

## ⚠️ THIS LEG CANNOT CATCH THE DEFECT — Fast DDS is LENIENT, Connext is STRICT

Measured, not assumed. With the ADR 0061 pad emission **reverted**:

| oracle | verdict on the malformed (unpadded) payload |
|---|---|
| **RTI Connext 7.3.1** | **REJECTS** — every `len mod 4 ∈ {1,2,3}` fails, multiples of 4 pass |
| **Fast DDS 3.6.1** | **ACCEPTS** — all 12 lengths still PASS, every byte still correct |
| **`make corpus`** (byte-exact vs Connext's wire bytes) | **FAILS** — exactly the non-4-aligned cases |

Fast DDS reads the members and tolerates the missing trailing pad. So this leg proves our **padded bytes
decode correctly on a second stack** (i.e. the fix did not break Fast DDS) — it does **not** prove the bytes
are *conformant*, and it would not have caught the bug.

**The discriminating oracles are `make corpus` and the live Connext leg. Do not let a green Fast DDS run
stand in for either.** A tolerant receiver is a false reassurance: it is exactly the kind of self-agreement
that hid this defect for months.
