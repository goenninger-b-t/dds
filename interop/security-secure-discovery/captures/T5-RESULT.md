# WP-DDS-SECURITY-FASTDDS-INTEROP T5 — live Fast DDS re-run result (GOV=none, 2026-06-29)

Reproduce: `bash interop/security-secure-discovery/run-fastdds-interop.sh none 15`
(after `pkill -9 -f fastdds; pkill -9 -f "examples/cpp/security/security"; pkill -f run-secure-interop-peer`).

## Result: the cross-vendor handshake now COMPLETES ON FAST DDS — it reaches `participant_authorized`.

| | T4 (before) | T5 (after) |
|---|---|---|
| our side (requester, B9A1E95F…) | `AUTHENTICATED`; sends crypto tokens over PVMS | `AUTHENTICATED`; sends 11 crypto tokens over PVMS (km/writer/locator all resolved) |
| Fast DDS (replier, D1437B8E…) | silently stuck in `WAITING_FINAL` (no security log, no match, sends nothing) | reaches `participant_authorized` BOTH directions; logs `[SECURITY Error] Error validating remote permissions … Cannot read as PKCS7 the permissions file (Permissions.cpp:593)` |

Neither side reaches `:keyed` yet (`ever-keyed=NIL`, `peak-matched=0`) — Fast DDS aborts authorization at the
permissions step, so it never matches PVMS / exchanges its ParticipantCryptoToken. But the advance is real and
reproducible: Fast DDS went from **silently stuck (no log)** to **executing `participant_authorized`** — the
§8.7 handshake Final is now accepted, which is the gate to the entire crypto-token exchange.

## What T5 fixed (corroborated, clean-room — Fast DDS Apache-2.0 only; RTI never read).

**(THE live blocker) §7.4.3 handshake-Final correlation.** Fast DDS
`process_participant_stateless_message` in `WAITING_FINAL`: a Final whose `related_message_identity.source_guid
== GUID_unknown` is treated as a missed-reply and RESENT (`SecurityManager.cpp:1554`); the conformant Final
needs `related.source_guid == its PSM-writer GUID` (`:1582`) and `related.sequence_number ==
expected_sequence_number_` (`:1590`). We hardcoded `related = {unknown, 0}`. Fix: echo the INCOMING message's
`message_identity` into the response's `related_message_identity` (`auth-manager.lisp`
`%am-on-stateless-message` → `%am-drive-handshake` → `%am-send-handshake`). Live: our Final now sends
`related = {D1437B8E..0x000201C3, 1}` = Fast DDS's Reply identity → Fast DDS processes the Final.

**PVMS crypto-token prerequisites (now in place for the exchange once T6 passes authorization):**
- **SPDP BuiltinEndpointSet bits 24/25** advertised iff the PVMS endpoint exists (`disc.lisp`), matching Fast
  DDS `builtin_endpoints()`; Fast DDS `match_builtin_key_exchange_endpoints` gates PVMS matching on them.
  Verified advertised (`builtin-endpoint-set = #x03C0FC3F`).
- **PVMS payload §10.2 PLAIN_CDR_LE encapsulation header** (`volatile-secure.lisp`, reuses `%psm-encapsulate`);
  Fast DDS `process_participant_volatile_message_secure:1700-1718` requires it.
- **Participant token `source_endpoint_key = GUID_unknown`** (`crypto-manager.lisp`); Fast DDS `:1745-1749`
  drops it otherwise (OMG §8.5.2.1).
- **Keyed-gate governance sensitivity** (`crypto-manager.lisp`): under GOV=none (no discovery protection) keying
  needs only the ParticipantCrypto (Fast DDS exchanges it unconditionally; secure-SEDP tokens exist only under
  discovery protection).

## NEXT blocker (for T6): empty `c.perm` → Fast DDS cannot validate our permissions.

Our §8.7 handshake sends an EMPTY `c.perm` (`handshake.lisp:359` placeholder); our own access control uses the
locally-configured permissions + the validated cert subject, so our-to-our never needed it on the wire. Fast
DDS reads the remote permissions credential via `SMIME_read_PKCS7` (`Permissions.cpp:354`) +
`PKCS7_verify(PKCS7_TEXT|PKCS7_NOVERIFY|PKCS7_NOINTERN)` — it requires the **S/MIME multipart** document (its
`.smime`), not our PEM PKCS7. T6 = plumb the local permissions S/MIME document into `c.perm` through the
handshake API + auth-manager. (T6+ then re-exposes the original PVMS candidates — secure-SEDP reliable pull,
rtps-wrapping — once authorization passes and tokens flow.)

## our-to-our greenness (binding invariant) — GREEN both impls.

SBCL **377 passed** (deterministic); build clean; gate-hotpath PASS (8 files); gate-types PASS (2027 ftypes);
fuzz PASS; mem 0.0000 bytes/sample. Clasp: keyed/PVMS/secure-discovery tests all pass deterministically
(`secure-discovery-keyed`, `secure-discovery-protected`, `pvms-reliable-bootstrap`, `pvms-fail-closed`,
`pvms-purge-bound-n2`, `pvms-session-id-on-wire` — all ok); the `SDP-SEC-PREFIX-ON-WIRE` wire-capture e2e
(`secure-discovery-protected-sign`) is the known NFR-PORT Clasp live-socket timing flake (passes in isolation,
e.g. 1/4 and 3/5 across runs; downstream of the handshake, not in any changed path) — re-run, don't chase.
