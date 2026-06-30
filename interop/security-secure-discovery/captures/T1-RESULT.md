# WP-DDS-SECURITY-FASTDDS-INTEROP T1 — live Fast DDS re-run result (GOV=none, 2026-06-28)

Reproduce: `bash interop/security-secure-discovery/run-fastdds-interop.sh none 25`
(after `pkill -f fastdds; pkill -f 'examples/cpp/security/security'`).

## Result: the auth handshake ADVANCES PAST the IdentityToken.

Before/after of our auth state against the live Fast DDS-Security peer (same EC PKI, domain 0):

| | discovered | auth state | log line |
|---|---|---|---|
| PRE-FIX (HEAD baseline) | 2 (env-contaminated) | `REJECTED` | `auth-manager: remote IdentityToken rejected` |
| POST-FIX (this run) | 1 (clean) | `HANDSHAKING` | `auth-manager: requester: sent HandshakeRequest` |

The §9.3.4 Property propagate-byte drop fixed our DECODE of Fast DDS's real SPDP IdentityToken:
our `validate-remote-identity` now returns `:ok` (was REJECT), the GUID ordering elects us requester,
and we emit a HandshakeRequest. Observed identically in BOTH directions (ours2fast, fast2ours) — by
GUID ordering our participant (`4742016909ECED…`) is always the requester.

The `pkill` cleared the T0 env-contamination (discovered 2 → 1).

## NEXT failure point (for T2): no HandshakeReply is processed → stuck in HANDSHAKING.

We (always the requester) send the HandshakeRequest, but never advance to reply/final → no
SharedSecret → `ever-keyed=NIL`, `peak-matched=0`, `RESULT: FAIL`.

Raw UDP flow (tcpdump; the lo0 NULL/Loopback capture is NOT RTPS-dissectable by tshark in-env):
- ours2fast: us `7420 → fastdds 7410` = 252 pkts (SPDP + repeated best-effort HandshakeRequest);
  us `→ 239.255.0.1:7400` = 51 (SPDP mcast); fastdds `→ us 7420` = 25 pkts (~1/s, periodic SPDP,
  NOT a reply burst).

So Fast DDS discovers us (bidirectional SPDP) but does not send a processable HandshakeReply. T2 must
determine why Fast DDS (the replier) does not reply — either it still rejects OUR SPDP IdentityToken /
HandshakeRequest token at a residual divergence behind the propagate fix (candidates per ADR 0036 §10:
c.pdata is a 4-byte stub vs the real ParticipantBuiltinTopicData; message_class_id; the request token's
binary-property contents/order; session_id/AAD/4-alignment) — pursued with RTPS dissection on a
non-lo0 (e.g. Linux) capture, since tshark cannot dissect the macOS loopback link type here.
