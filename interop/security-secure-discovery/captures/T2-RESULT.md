# WP-DDS-SECURITY-FASTDDS-INTEROP T2 — live Fast DDS re-run result (GOV=none, 2026-06-29)

Reproduce: `bash interop/security-secure-discovery/run-fastdds-interop.sh none 20`
(after `pkill -9 -f "examples/cpp/security/security"; pkill -f run-secure-interop-peer`).

## Result: the auth handshake ADVANCES — Fast DDS now REPLIES.

| | our auth state | meaning |
|---|---|---|
| T1 (baseline) | `HANDSHAKING` | we send a HandshakeRequest; Fast DDS sends NO processable reply |
| T2 (this run) | `REJECTED` | Fast DDS deserializes + accepts our request, **sends a HandshakeReply**; our peer receives it and rejects it at reply-verification |

Both directions (ours2fast, fast2ours): by §9.3.2.1 GUID ordering our peer (`B9A1E95F…`, participant_ec_b)
is always the requester, Fast DDS (`D1437B8E…`, participant_ec) the replier.

The committed `*-fastdds.log` are from a FINAL CLEAN run (un-instrumented Fast DDS, only the one-line
`Log::SetVerbosity(Warning)` kept): they show **zero** "bad sequence Number" warnings — the four T2 blockers
are cleared and Fast DDS deserializes + accepts our request.

**Correction (per T3 diagnosis):** the log does NOT show `begin_handshake_reply` succeeding — it shows
`[SECURITY Warning] Cannot load certificate -> begin_handshake_reply`. On that VALIDATION_FAILED Fast DDS
sends NOTHING, so it never actually replied; our `REJECTED` was our own side false-rejecting an out-of-role
token, NOT a rejection of a Fast DDS reply. T3 fixes both (c.id = PEM credential; requester drops out-of-role
tokens). See `T3-RESULT.md`.

## Diagnosis — a CHAIN of four silent blockers (each masked the next).

tshark cannot dissect macOS lo0 RTPS, and the Fast DDS example only does `Log::Reset()` (verbosity Error →
every security warning suppressed). Diagnosed by TEMPORARILY instrumenting the Fast DDS peer (Apache-2.0,
clean-room; RTI source never read): `Log::SetVerbosity(Warning)` in the example (KEPT — legitimate
diagnostic config) + DIAG `EPROSIMA_LOG_WARNING`s in `SecurityManager::process_participant_stateless_message`
(REVERTED after diagnosis; lib rebuilt clean). The instrumented run showed, in order:

1. **(pre-fix) `RTPS_MSG_IN: Invalid message received, bad sequence Number`** — our PSM DATA had writerSN 0;
   Fast DDS `MessageReceiver.cpp:814` rejects `sequenceNumber <= 0` at the RTPS layer. → fix: monotonic
   `psm-writer-sn` from 1 (`disc.lisp`, `stateless-message.lisp`). RTPS 2.5 §8.3.5.4/§8.4.2.
2. **(then) silent drop on `source_endpoint_key`** — `SecurityManager.cpp:1506` requires
   `source_endpoint_key == GUID_UNKNOWN` (INFO, compiled out); we set it to our GUID. → fix: GUID_UNKNOWN
   (`auth-manager.lisp %am-send-handshake`). §7.4.4.
3. **(then) `DIAG: Cannot deserialize ParticipantGenericMessage`** — the wire DataHolder `BinaryProperty`
   octet-vector lacked 4-byte alignment padding; Fast DDS `addBinaryPropertySeq(...,add_final_padding=true)`
   + `readOctetVector` (`pos→(pos+3)&~3`) expect it. → fix: pad the wire octet-vector + skip on decode
   (`wire.lisp`). WIRE-ONLY — the §8.7 hash/Sign seq stays unpadded (`add_final_padding=false`).
4. **(innermost) c.pdata stub + non-§9.3.2.1 GUID** — `begin_handshake_reply` reads `c.pdata` as a BE
   ParameterList and validates `PID_PARTICIPANT_GUID`'s first 48 bits == the §9.3.2.1 adjusted GUID. → fix:
   real `%build-c-pdata` (BE ParameterList, PID_PARTICIPANT_GUID + PID_SENTINEL, no encap header) + adjusted
   GUID `%adjust-guid-prefix` (octet-0 bit set + first 47 bits of SHA-256(cert subject), Fast-DDS-corroborated).

After all four, the instrumented Fast DDS log shows:
`DIAG: process_participant_stateless_message ENTER` → `DIAG: PSM deserialized class=dds.sec.auth` →
`DIAG: PSM auth lookup found=1 status=4 srcEP=|GUID UNKNOWN| dstEP=|GUID UNKNOWN|` →
`DIAG: calling on_process_handshake (auth)` — with **no** PKIDH rejection → Fast DDS sends the reply.

OUR-TO-OUR side effect of the §9.3.2.1 GUID: the cert-derived requester/replier election no longer follows
creation order, exposing that the best-effort PSM handshake had NO request retransmission. Fixed conformantly
(re-fire `on-participant-discovered` on SPDP re-announce + requester re-send while `:awaiting-reply` + replier
re-send stored reply on a duplicate request). our-to-our green both impls (377 SBCL + 377 Clasp).

## NEXT blocker (for T3): our peer REJECTS Fast DDS's HandshakeReply.

Our log: `requester: sent HandshakeRequest` → `handshake step rejected`. So `%process-reply`
(`src/dds-security/auth/handshake.lisp`) received Fast DDS's Reply and failed one of its checks: the echoed
hash_c1 / dh1 / challenge1, the peer-cert chain verify, the algo-vs-suite cross-check, the recomputed
**hash_c2** equality, or the **Sign2** signature verification. The most likely cross-vendor divergences are
the hash_c2 recomputation and the Sign2 input concatenation (the BE BinaryPropertySeq order/bytes Fast DDS
signs over). T3 should instrument `%process-reply`'s reject points to isolate which, then reconcile
conformant (corroborate vs Fast DDS `begin_handshake_reply`'s hash_c2 + signature construction, lines
1764-1847).
