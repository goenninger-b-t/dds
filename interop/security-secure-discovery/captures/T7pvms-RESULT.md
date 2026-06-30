# T7-PVMS live cross-vendor result — WP-DDS-SECURITY-FASTDDS-INTEROP (M7/P6 Slice 5)

`bash interop/security-secure-discovery/run-fastdds-interop.sh none <secs>` — our stack ↔ a SECURITY=ON
eProsima Fast DDS v3.6.1 peer, both directions, GOV=none (auth + access-control + crypto-token exchange;
all protection-kinds NONE). Diagnosis used temporary instrumentation of our PVMS send/decode/promote path
(removed before commit); the numbers below are from the instrumented diagnostic runs.

## The PVMS ParticipantCryptoToken exchange now COMPLETES both directions (cross-vendor :keyed)

| | T6 (before) | T7-PVMS (after) |
|---|---|---|
| our side `:keyed` | NIL (no inbound token) | **KEYED both directions** — `states=D1437B8E=KEYED`, `ever-keyed=T` |
| participant-token parse | `class=NIL km=NIL` (false-REJECT) | `class=dds.sec.participant_crypto_tokens km=T`; `try-promote ready=T part-km=T` |
| Fast DDS receives our tokens | racy / no (clear HEARTBEAT dropped) | **YES** — Fast DDS PVMS reader ACKNACK `base=12` (acked our SN 1..11), `resends=0`, no crypto error in its log |
| secure-SEDP / user-endpoint match | 0 | **0** (next blocker) |
| protected data | none | none (next blocker) |

## The two reconciled divergences

1. **KeyMaterial `transformation_kind` AES256_GMAC {0,0,0,3}** — `%parse-km-cdr` accepted only
   `{0x01,0x02,0x04}` and false-REJECTed Fast DDS's ParticipantKeyMaterial (kind `{0,0,0,3}`). The 88-byte
   KeyMaterial was otherwise byte-exact to ours (BE seq-lengths salt=32/key=32, length markers at offsets
   7/47 = 0x20). Fixed: accept all four §9.5.2.1.1 non-NONE kinds. → our side reaches `:keyed`.
2. **PVMS HEARTBEAT/ACKNACK submessage protection** — Fast DDS encrypts them (add_heartbeat/add_acknack →
   encode_writer/reader_submessage) and drops clear submessages on a protected endpoint (MessageReceiver
   was_decoded gate); ours were clear (dropped by Fast DDS → our token never NACK-pulled) and we dropped
   Fast DDS's encrypted ones. Fixed: encrypt our PVMS HEARTBEAT/ACKNACK + demux the decoded inner
   submessage in `%on-volatile-secure`. → Fast DDS pulls + acks all our tokens (base=12) → Fast DDS keys.

## Inner submessage ids observed decoding Fast DDS's PVMS brackets (decode=T cross-vendor)

`7`=HEARTBEAT, `6`=ACKNACK, `9`=INFO_TS, `21`=DATA. The §9.5.3.1 bootstrap KM + §9.5.3.3.4.2 session-key
KDF + nonce are byte-correct cross-vendor (we decode Fast DDS's protected submessages; Fast DDS decodes
ours, symmetric bootstrap KM).

## NEXT blocker (next iteration): user-endpoint SEDP match

After both key, `matched=0` and we receive NO SEDP HEARTBEAT from Fast DDS (`%on-builtin-heartbeat` never
fires) — Fast DDS does not initiate the plain-SEDP/EDP user-endpoint exchange with us post-keying, and its
subscriber never prints "matched". A SEDP-layer issue distinct from the (now-resolved) PVMS crypto-token
exchange. Connext-Security live = Slice-5b exit gate (RTI Security Plugins absent).

Captures: `ssd-none-{ours2fast,fast2ours}-{ours,fastdds}.log`, `ssd-none-*.pcapng` (tshark cannot dissect
the macOS lo0 link-layer; diagnosis rests on logs + Fast DDS source + our decoded bytes).
