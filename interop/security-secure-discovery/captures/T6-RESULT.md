# WP-DDS-SECURITY-FASTDDS-INTEROP T6 — live Fast DDS re-run result (GOV=none, 2026-06-29)

Reproduce: `bash interop/security-secure-discovery/run-fastdds-interop.sh none 20`
(after `pkill -9 -f fastdds; pkill -9 -f "examples/cpp/security/security"; pkill -f run-secure-interop-peer`).

## Result: Fast DDS now VALIDATES our permissions — the "Cannot read as PKCS7" reject is GONE.

| | T5 (before) | T6 (after) |
|---|---|---|
| our side | `AUTHENTICATED`; sends crypto tokens over PVMS | `AUTHENTICATED`; drives crypto-token exchange over PVMS (unchanged) |
| Fast DDS permissions | `[SECURITY Error] Error validating remote permissions … Cannot read as PKCS7 the permissions file (Permissions.cpp:593)` | **no `[SECURITY]` error in either log** — permissions VALIDATE; proceeds to secure SEDP matching (`RTPS_WRITER … Attempting to add existing reader`) |
| keyed / matched | `ever-keyed=NIL`, `peak-matched=0` | `ever-keyed=NIL`, `peak-matched=0` (next blocker) |

Both directions symmetric (ours2fast: Fast DDS=subscriber; fast2ours: Fast DDS=publisher): our peer reaches
`AUTHENTICATED`, Fast DDS clears authentication AND permissions validation with no security error. The advance
is real and reproducible: Fast DDS went from **aborting authorization at the permissions step** to **passing
permissions and entering secure endpoint matching** — the gate to the crypto-token exchange.

## What T6 fixed (corroborated, clean-room — Fast DDS Apache-2.0 only; RTI never read).

**(THE live blocker) empty `c.perm`.** Our §8.7 handshake sent an EMPTY `c.perm` (`handshake.lisp:359`
placeholder). Fast DDS `validate_remote_permissions` reads the remote c.perm via `SMIME_read_PKCS7`
(`Permissions.cpp:354`) + `PKCS7_verify(PKCS7_TEXT | PKCS7_NOVERIFY | PKCS7_NOINTERN)` (`:406`) — it requires
the **MIME multipart/signed S/MIME** form (the `.smime`, `openssl smime -sign -text`), NOT the bare-PEM
`-----BEGIN PKCS7-----` opaque form (`-outform PEM -nodetach`) our Slice-3 `cms-verify` consumed. Fast DDS's
c.perm value = the `dds.perm.cert` Property = the RAW configured permissions file content
(`PKIDH.cpp:1352-1364`; `Permissions.cpp:777-797`).

Conformant fix (DDS-Security 1.1 §9.4.1.1; the spec form IS S/MIME, RFC 5751):
- **`dds.dare:cms-verify` decode-tolerant** (`openssl-ffi.lisp`): PEM_read_bio_CMS first (form 1, flags=0,
  byte-identical to before) → on NULL, `SMIME_read_CMS` + `CMS_verify(…, CMS_TEXT)` (form 2). Pure ADDITION;
  isolation-verified both `.p7s` and `.smime` recover the identical 1265-byte XML, garbage → NIL.
- **c.perm plumbed**: configured `:permissions` octets → `%install-auth-manager` → auth-manager-state
  `perm-credential` → optional `perm-octets` of `begin-handshake-request`/`-reply`, emitted as c.perm AND
  folded into hash_c (both ends recompute over the transmitted bytes — hash stays consistent; default empty =
  byte-identical to T5 for auth-only/unit paths). The harness feeds our peer the SHARED `.smime` (grants both
  EC subjects).
- **PSM send buffer sized per-call** (`stateless-message.lisp`): the ~3 KiB c.perm + c.id cert exceeds the
  fixed 2 KiB rx-tx-msg scratch (the receive buffer is already 64 KiB).

## NEXT blocker (for T7 / next iteration): PVMS ParticipantCryptoToken exchange → `:keyed`.

Authentication AND permissions now pass both directions, but neither side reaches `:keyed` (`peak-matched=0`).
Our side is `AUTHENTICATED` and "driving crypto-token exchange over PVMS"; no inbound ParticipantCryptoToken is
observed. This re-exposes the original PVMS candidates the T5-RESULT deferred — the §8.5.2 ParticipantCryptoToken
exchange over reliable PVMS (HEARTBEAT/ACKNACK pull) and/or metatraffic rtps-wrapping — now reachable because
authorization no longer aborts. Fast DDS's repeated `Attempting to add existing reader` indicates it is doing
secure SEDP discovery while waiting on the crypto match.

## our-to-our greenness (binding invariant) — GREEN.

SBCL **377 passed** (deterministic, two full runs, make-rc=0); build clean; gate-hotpath PASS (8 files);
gate-types PASS (2027 ftypes); fuzz PASS (Clasp default LISP, rc=0); mem 0.0000 bytes/sample; corpus stub rc=0.
Clasp: all security/auth/access-control/handshake tests pass deterministically in isolation
(cms-verify-kat, access-permissions-parse, auth-token-corpus, auth-handshake-ecdh/rsa, auth-negatives,
auth-handshake-over-wire, auth-manager-handshake, auth-encrypted-pubsub-keyx, secure-discovery-keyed/protected);
the live-socket wire-capture e2e is the known NFR-PORT Clasp flake — it landed on SDP-BYTE-EXACT
(secure-discovery-origin-auth) in run 1 and SDP-SEC-PREFIX-ON-WIRE (secure-discovery-protected-sign) in run 2
(a moving, non-deterministic failure = flake, not a regression), both pass in isolation (4x and 3x). SBCL ran
all e2e back-to-back deterministically at 377, proving the code is correct.
