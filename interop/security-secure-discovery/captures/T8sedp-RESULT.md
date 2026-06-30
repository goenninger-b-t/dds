# T8sedp live cross-vendor result — WP-DDS-SECURITY-FASTDDS-INTEROP (M7/P6 Slice 5)

`bash interop/security-secure-discovery/run-fastdds-interop.sh secure <secs>` — our stack ↔ a SECURITY=ON
eProsima Fast DDS peer, both directions, **GOV=secure** (the PROTECTED governance the DoD requires:
discovery_protection_kind=ENCRYPT, rtps_protection_kind=ENCRYPT, metadata/data_protection_kind=ENCRYPT). The
prior PVMS iteration ran GOV=none; this is the first GOV=secure cross-vendor run. Detailed token/decode counts
below are from temporary instrumentation (removed before commit); the committed `ssd-secure-*.log` are the
clean re-run (keyed=T headline).

## Under GOV=secure, cross-vendor keying + the full builtin-secure crypto-token exchange now COMPLETE

| | before | T8sedp (after) |
|---|---|---|
| our side `:keyed` | NIL both | **KEYED both directions** — `ever-keyed=T`, `states=...=KEYED` |
| Fast DDS applies our tokens / keys us | NO — `[SECURITY_CRYPTO] No key material yet` flood | **YES** — flood gone |
| Fast DDS sends its builtin-secure tokens | 3 (phase 1: participant + secure-SPDP 0xff0101 DW/DR) | **all builtin secure**: participant + secure-SPDP 0xff0101 + secure-SEDP pub 0xff0003 + secure-SEDP sub 0xff0004 + secure-PM 0xff0200 (DW+DR each) |
| we decode Fast DDS's secure-builtin traffic | 0 | **131/131 brackets** (inner ids: HEARTBEAT x99, ACKNACK x32) |
| user-endpoint match / protected data | 0 / none | **0 / none** (next blocker) |

## The two reconciled divergences (corroborated CLEAN-ROOM vs Fast DDS; RTI never read)

1. **`:keyed` gate must NOT require the secure-SEDP endpoint tokens (Fast DDS two-phase secure discovery).**
   Fast DDS exchanges the secure-SEDP/PM EntityCryptos in a SECOND phase AFTER the participant secure-match
   (`PDPSimple::assignRemoteEndpoints` notify_secure gated on the secure-SPDP reader matching the remote
   secure-SPDP writer → `EDPSimple::assignRemoteEndpoints` ~819-876), not as a keying precondition. Our gate
   required them → deadlock (Fast DDS sent only the 3 phase-1 tokens). Fixed: gate `:keyed` on the
   ParticipantCrypto alone; the endpoint EntityCryptos install lazily by transformation_key_id on arrival.
2. **DW/DR CryptoToken destination_endpoint_key = matched-remote endpoint GUID (was GUID_unknown).** Fast DDS
   `process_participant_volatile_message_secure` REJECTS a DW/DR token whose destination_endpoint_key ==
   GUID_unknown (SM:1830/1907) and applies it via `*_handles_.find(destination_endpoint_key)` (SM:1924/1848);
   a participant token requires BOTH endpoint keys = GUID_unknown (SM:1739/1745). We sent dest=all-zero → ALL
   our endpoint tokens rejected → phase 2 never triggered. Fixed: `%cm-token-dest-entity-id` (builtin secure
   writer 0xC2↔reader 0xC7; user writer-id↔reader-id) → dest = remote-prefix + complementary-id.

## NEXT blocker (next iteration): secure-builtin RELIABILITY (the brief's hypothesis #1)

Fast DDS's reliable secure-SEDP/SPDP writers send submessage-protected HEARTBEATs (inner id 7) + ACKNACKs
(inner id 6); our `%on-secure-builtin` handles only inner DATA and DROPS HEARTBEAT/ACKNACK (the pre-fix PVMS
bug, now for the secure builtins). So we never ACKNACK-pull Fast DDS's secure-SEDP DiscoveredReaderData →
`matched=0`. Conformant fix: demux + answer the secure-builtin HEARTBEAT/ACKNACK like the PVMS ones (reuse
`%builtin-acknack-values` + the reliable engine) + emit secure HEARTBEATs; plus exchange USER-endpoint tokens
at endpoint-match time with the matched-remote GUID (cross-vendor user ids ≠ symmetric our-to-our ids).
Connext-Security live = Slice-5b exit gate (RTI Security Plugins absent).

Captures: `ssd-secure-{ours2fast,fast2ours}-{ours,fastdds}.log`, `ssd-secure-*.pcapng` (tshark cannot dissect
the macOS lo0 link-layer; diagnosis rests on logs + Fast DDS source + our decoded bytes).
