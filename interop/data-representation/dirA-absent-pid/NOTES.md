# Direction-A absent-PID DATA_REPRESENTATION — live confirmation of the RxO fix (`e3f1803`)

Live wire confirmation, on this host's `lo0` (tshark RTPS dissector under a clean `WIRESHARK_CONFIG_DIR`),
that `parse-endpoint-data` seeding an **absent** `PID_DATA_REPRESENTATION` to the DDS-XTypes 1.3
§7.6.3.1.1 **wire** default `[XCDR1]` (not our `make-*-qos` local default `[XCDR2, XCDR1]`) is correct:
our default `[XCDR2]` writer must **not** match a stock `@final` reader that elides the PID, and must
report it incompatible instead of the pre-fix silent false-match.

## Which peer actually elides the PID? (the wire is the oracle — a prior claim corrected)

The prior `../README.md` stated "both Connext's and Fast DDS's reader elide the default-valued PID — 0
matches of 0x0073 from either peer." **The wire falsifies that for Connext.** Dissecting the archived
`../captures/connext-sedp-lo0.pcap` and `../captures/fastdds-sedp-lo0.pcap`, filtered by vendor id
(RTI = `0x0101`, eProsima = `0x010f`; ours = `0x01ff`):

| peer | reader SEDP subscription (`wrEntityId 0x000004c2`) | `PID_DATA_REPRESENTATION` (0x0073) |
|---|---|---|
| **RTI Connext 7.3.1** | present | **INCLUDED**, explicit `Data Representation Sequence[1] → [0]: XCDR_DATA_REPRESENTATION (0x0)` = `[XCDR1]` (frame 56, vendor `0x0101`) |
| **eProsima Fast DDS 3.6.1** | present (7 announcements) | **OMITTED** — 0 frames carry 0x0073; the reader PID set is DURABILITY/RELIABILITY/TOPIC_NAME/TYPE_NAME/TYPE_INFORMATION/UNICAST_LOCATOR/… with **no** data-representation |

So **Fast DDS is the peer that exercises the absent-PID path**; Connext advertises `[XCDR1]` explicitly
(so the Connext leg gives the correct no-match with or without the fix — the fix does not change it).

## The A/B (same stock @final Fast DDS reader, `create_participant_with_default_profile`)

`run-publisher`'s `[pub] async pre-publish match=YES/NO` is a direct readout of
`disc-node-matched-count`, i.e. `endpoint-match-p → qos-rxo-compatible` (the fixed path). Note
`run-publisher` **publishes regardless of match** ("publishing anyway"), so *samples on the wire* do
**not** distinguish the fix — only the match verdict (and the peer's own RxO) do.

| leg | our writer rep | our `match=` verdict | Fast DDS `received` |
|---|---|---|---|
| **PRE-FIX** (seed reverted to `make-*-qos` local default) `REP=xcdr2` | `[XCDR2]` | **YES — the false match (bug), live** | 0 |
| **POST-FIX** (`e3f1803`) `REP=xcdr2` | `[XCDR2]` | **NO — correct no-match, live** | 0 |
| **POST-FIX** `REP=xcdr1` | `[XCDR1]` | YES | **49 (delivered, correct field values)** |

Pre-fix: absent PID → parsed `[XCDR2, XCDR1]` → `first-of-offered XCDR2 ∈ {XCDR2,XCDR1}` → false
`match=YES`. Post-fix: absent PID → parsed `[XCDR1]` → `XCDR2 ∉ {XCDR1}` → correct `match=NO`.

**The A/B flip itself proves the parsed Fast DDS reader carried NO PID.** An *explicit* `[XCDR1]` (what
Connext sends) parses to `[XCDR1]` under **both** seeds and yields `match=NO` both times (the Connext
leg does exactly this — unchanged by the fix). Only an **absent** PID lets the parse seed change the
verdict, so `match=YES → NO` across the identical setup is a direct consequence of an absent PID. The
*direct* wire proof of that omission is the archived dedicated `../captures/fastdds-sedp-lo0.pcap` (7
subscription announcements, 0 carrying 0x0073); honest caveat — in the fresh A/B captures here Fast
DDS's SEDP subscription did not re-appear on `lo0` UDP (only its SPDP did, as with Connext's same-host
run), so the fresh pcaps evidence the *match behaviour*, and the archived SEDP capture + this flip
argument evidence the *absent PID*. In both
xcdr2 cases Fast DDS received 0 (its own reader RxO rejects `[XCDR2]`), and ACKNACKs=0 — the *only*
thing the fix changes is **our** match decision (matched-count), which is the `OFFERED_INCOMPATIBLE_QOS`
trigger that was silently absent before. `REP=xcdr1` matches and delivers (49/50), proving the fix
discriminates representation correctly rather than over-rejecting.

Captures (this dir): `fastdds-prefix-xcdr2-FALSE-match.pcap`, `fastdds-postfix-xcdr2-no-match.pcap`,
`fastdds-postfix-xcdr1-delivered.pcap`.

## Reproduce

```sh
# stock @final Fast DDS subscriber (default profile, omits the PID), 30 s, in its loopback profile dir:
( cd interop/fastdds/shapes && ../../../scripts/with-fastdds.sh ./shapes_sub 30 ) &
# our writer, :async t so the match verdict prints; REP=xcdr2 -> match=NO, REP=xcdr1 -> match=YES + delivery:
make square-pub REP=xcdr2 TYPE=canonical COUNT=50 RATE=4 HISTORY=keep-all \
  PEERS=127.0.0.1:7410,127.0.0.1:7412,127.0.0.1:7414,127.0.0.1:7416
# (the captured runs invoke run-publisher directly with :async t; matched-count = endpoint-match-p RxO.)
```
