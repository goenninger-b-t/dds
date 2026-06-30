# WP-DDS-SECURITY-FASTDDS-INTEROP T4 — live Fast DDS re-run result (GOV=none, 2026-06-29)

Reproduce: `bash interop/security-secure-discovery/run-fastdds-interop.sh none 20`
(after `pkill -9 -f fastdds; pkill -9 -f "examples/cpp/security/security"; pkill -f run-secure-interop-peer`).

## Result: the cross-vendor PKI-DH handshake now COMPLETES. Both directions reach AUTHENTICATED.

| | our side (requester, B9A1E95F…) | Fast DDS (replier, D1437B8E…) |
|---|---|---|
| T3 | `HANDSHAKING` (drops `+Req`) | `Wrong hash_c1` + `Cannot deserialize public key (PKIDH.cpp:858)` → `on_validation_failed` (sends nothing) |
| T4 | `AUTHENTICATED`; `authenticated; driving crypto-token exchange over PVMS` | security log CLEAN — no `Wrong hash_c1`, no `Cannot deserialize public key`, no retry spam (accepted our request, sent Reply) |

Our log (both `ssd-none-ours2fast-ours.log` and `ssd-none-fast2ours-ours.log`):
```
; auth-manager[D1437B8E7A95]: requester: sent HandshakeRequest
; auth-manager[D1437B8E7A95]: authenticated; driving crypto-token exchange over PVMS
[*] discovered=1 matched=0 samples=0 keyed=NIL states=D1437B8E=AUTHENTICATED   (x20)
```
Fast DDS log: only `Subscriber/Publisher running` + `SIGTERM received` — the T3 security errors AND the
`Attempting to add existing reader, updating information` failure-retry spam are GONE.

## What T4 fixed (corroborated, clean-room — Fast DDS Apache-2.0 only; RTI never read).

- **(A) ROLE ELECTION — BENIGN retransmit, no code change.** Fast DDS `validate_remote_identity`
  (`PKIDH.cpp:1293`) elects requester iff `participant_key_ (adjusted, :1238) < remote (announced adjusted)` —
  the SAME §9.3.2.1 GUIDs our `auth-manager.lisp:244` compares. B9… < D1… → we requester, Fast DDS replier
  (AGREE). The `+Req` Fast DDS emits is its FAILURE-RETRY: `SecurityManager.cpp:719-732` resets
  `AUTHENTICATION_FAILED → REQUEST_NOT_SEND` on SPDP re-announce → `begin_handshake_request`. `begin_handshake_
  reply` runs ONLY from `WAITING_REQUEST` (`:862-865`), proving Fast DDS is the replier. The retries existed
  ONLY because our request failed B+C; with B+C fixed, `begin_handshake_reply` succeeds → Fast DDS sends Reply,
  not retry-`+Req`. Dropping `+Req` (T3) is correct and is now moot (none are emitted). Verified: zero
  `dropped out-of-role token` lines in the T4 logs.
- **(B) dh1/dh2 = raw uncompressed EC point** (`0x04||X||Y`, 65 B). Fast DDS `store_dh_public_key`
  `EC_POINT_point2oct(conv_form=uncompressed)` / `generate_dh_peer_key` `o2i_ECPublicKey` (`PKIDH.cpp:737,833`).
  Was SubjectPublicKeyInfo DER → `:858` reject. Fix: `dds.dare:ecdh-gen-keypair` emits the point via
  `EVP_PKEY_get_octet_string_param "pub"`; `ecdh-compute` decode-tolerant (raw point OR SPKI DER).
- **(C) hash_c/Sign BinaryPropertySeq value padding.** Fast DDS `addBinaryPropertySeq(..., add_final_padding=
  false)` 4-pads each octet value EXCEPT the last (`CDRMessage.cpp:1001-1003,602-637`). Was unpadded → `Wrong
  hash_c1`. Fix: `handshake.lisp %build-cdr-binary-property-seq-be` pads value-to-4 for all but the last
  property.

## NEXT blocker (for T5): crypto-token exchange over reliable PVMS → never `:keyed`.

Both peers AUTHENTICATE but neither reaches `:keyed` (`ever-keyed=NIL`, `matched=0`). After
`authenticated; driving crypto-token exchange over PVMS` our log is silent — no remote crypto tokens arrive,
so `%cm-try-promote` never fires. This is the brief's **T5 candidate**: the §8.5.2 crypto-token exchange rides
the reliable ParticipantVolatileMessageSecure (PVMS) builtin endpoint; a reliable Fast DDS peer likely needs
receiver-side HEARTBEAT/ACKNACK pull (and/or the secure-SEDP reliable delivery) that our push+dedup path does
not drive cross-vendor. Diagnose the PVMS reliability handshake (Fast DDS
`builtin/discovery/.../ParticipantVolatileMessageSecure` reader/writer) and add the reliable pull. T6
(metatraffic rtps-wrapping) only applies if the governance sets `rtps_protection ≠ NONE` (GOV=none here).

## our-to-our greenness (binding invariant) — GREEN both impls.

SBCL **377 passed** (deterministic); build clean; gate-hotpath PASS (8 files); gate-types PASS (2027 ftypes);
fuzz PASS; mem 0 bytes/sample. Clasp **377 passed** on a clean run; two prior runs flaked at different
live-socket e2e tests (`SDP-BYTE-EXACT`, then `SDP-SEC-PREFIX-ON-WIRE`) — the known Clasp live-socket
timing-flake (NFR-PORT, re-run-don't-chase), DOWNSTREAM of the handshake; the changed crypto path + the
handshake/keyed e2e tests (`auth-handshake-over-wire`, `auth-manager-handshake`, `secure-discovery-keyed`)
passed every run. Both ECDH + FFDH suites still reach byte-equal SharedSecret.
