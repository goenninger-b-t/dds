# Liveliness / participant-lease-expiry live test (FR-DCPS S0/S1)

Connext-side run notes for the Writer-Liveliness-Protocol + participant-lease-expiry
feature. Treats RTI Connext 7.3.1 as the interop oracle (public API + wire only; **no RTI
source/headers/`rtiddsgen` output copied** — clean-room, NFR-IP). Not built/run by CI;
requires a local Connext install. Captures + RTI dylibs are git-ignored.

## What this confirms

| Target | How | Status |
|---|---|---|
| Participant-lease expiry prunes a vanished Connext peer, decrementing `SUBSCRIPTION_MATCHED` | `corpus_pub` ↔ `make gated-sub`, kill the publisher, observe `MATCHED 1 -> 0` | ✅ live (2026-06-12) |
| RTI's default participant-liveliness wire artifact | raw `lo0` capture of a lone Connext participant | ⚠️ proprietary `NDDSPING`, **not** standard `ParticipantMessageData` (see below) |
| Standard `ParticipantMessageData` (RTPS §8.4.13) byte-validation against a peer | needs a conformant non-RTI peer | ⛔ deferred to the Fast DDS leg (FR-IO-2) — not on the default RTI-to-RTI wire |

## Participant-lease prune — live PASS (2026-06-12)

Recipe (the proven 2026-06-11 legacy-gate match config, plus a shortened lease):

```sh
export NDDSHOME=/Applications/rti_connext_dds-7.3.1
export CONNEXTDDS_ARCH=arm64Darwin20clang12.0
# RTI dylibs use @loader_path install names and macOS SIP strips DYLD_LIBRARY_PATH, so
# symlink the release dylibs next to the binary (git-ignored):
#   ln -sf $NDDSHOME/lib/$CONNEXTDDS_ARCH/lib{nddscpp2,nddsc,nddscore}.dylib .
# Temporarily shorten the announced participant lease to 12 s (assert 4 s) in
# ../typeobject-corpus/USER_QOS_PROFILES.xml participant_qos/discovery_config so the prune
# is observable in seconds rather than the 100 s default (revert after the run).
( cd ../typeobject-corpus && ./corpus_pub 0 Square C_Shape )     # Connext C_Shape writer
make gated-sub SECONDS=60                                        # our DCPS gated subscriber
# ... once "MATCHED 0 -> 1", kill corpus_pub; within ~lease the sub logs the prune.
```

Observed (our `gated-sub` stdout):

```
; type-gate[Square/C_Shape]: COMPATIBLE — legacy-TypeObject assignability
[gated-sub] MATCHED 0 -> 1 remote endpoint(s) (gate verdict :compatible).
[gated-sub] sample #1: color=BLUE x=50 y=50 shapesize=30
... (26 samples) ...
[gated-sub] MATCHED 1 -> 0 remote endpoint(s) (remote pruned — participant lease expired).
[gated-sub] stopped: received 26 sample(s); matched=0; INCONSISTENT_TOPIC total=0.
```

The `MATCHED 1 -> 0` line is the `%lease-sweep` (RTPS §8.5.3.3.2): the killed Connext
participant stopped refreshing its SPDP, our sweep found it stale past its announced
`leaseDuration`, purged its endpoints/matches, and fired the DCPS unmatch hook that
decrements `SUBSCRIPTION_MATCHED`. `total_count` is untouched (DDS 1.4 §2.2.4.1).

## Finding: RTI uses proprietary `NDDSPING`, not standard `ParticipantMessageData`

A raw `lo0` capture of a lone Connext participant (loopback profile in
`USER_QOS_PROFILES.xml` here) shows its participant-liveliness assertion frames carry the
RTPS magic followed by the literal `NDDSPING`, e.g. frame 1 payload:

```
52 54 50 53 02 05 01 01 4e 44 44 53 50 49 4e 47   RTPS....NDDSPING
```

This is RTI's proprietary participant-liveliness ping, **not** the standard RTPS §8.4.13
`ParticipantMessageData` on `ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_WRITER`
(`0x000200c2`). It mirrors the established TypeObject finding (ADR 0009): default RTI↔RTI
discovery emits the vendor artifact (`PID_TYPE_OBJECT_LB 0x8021`, `NDDSPING`) rather than
the standardized one (`PID_TYPE_INFORMATION 0x0075`, `ParticipantMessageData`). Our stack
implements the **standard** mechanism (the conformant default), which a non-RTI peer
(Fast DDS) exercises — so the live byte-validation of `ParticipantMessageData` belongs to
the Fast DDS leg (FR-IO-2), not this RTI run. RTI still **accepts** the standard
`ParticipantMessageData` (it is spec-mandated), so emitting it toward a Connext peer is safe.

> Tooling note: the bundled `tshark` (Wireshark.app) did not dissect the `lo0` capture in
> this shell (`Protocols in frame:` empty for every frame, sandboxed and un-sandboxed); the
> RTPS/`NDDSPING` identification above is from the raw `capinfos`/hexdump bytes, which are
> unambiguous. Re-dissect in the Wireshark GUI if frame-level detail is needed.
