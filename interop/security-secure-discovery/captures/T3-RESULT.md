# WP-DDS-SECURITY-FASTDDS-INTEROP T3 — live Fast DDS re-run result (GOV=none, 2026-06-29)

Reproduce: `bash interop/security-secure-discovery/run-fastdds-interop.sh none 20`
(after `pkill -9 -f "examples/cpp/security/security"; pkill -f run-secure-interop-peer`).

## Result: the auth handshake ADVANCES past credential-load.

| | Fast DDS (replier) | our side (requester) |
|---|---|---|
| T2 | `[Warning] Cannot load certificate -> begin_handshake_reply` (sends NOTHING) | false-`REJECTED` |
| T3 | cert loads OK; fails later: `[Error] Cannot deserialize public key (PKIDH.cpp:858) -> on_validation_failed` | `HANDSHAKING` (drops out-of-role tokens) |

By §9.3.2.1 GUID ordering our peer (`B9A1E95F…`, participant_ec_b) is the requester, Fast DDS
(`D1437B8E…`, participant_ec) the replier, in BOTH directions.

## Diagnosis — TWO divergences (the T3 honesty correction).

T2-RESULT claimed `begin_handshake_reply` "succeeds silently (sends the reply)" and our peer rejected that
reply. **Both halves were wrong.** The committed `*-fastdds.log` show `Cannot load certificate` in
`begin_handshake_reply`; on `VALIDATION_FAILED` Fast DDS sends NOTHING (`SecurityManager.cpp:907-953` only
transmits for `VALIDATION_PENDING_HANDSHAKE_MESSAGE`/`OK_WITH_FINAL_MESSAGE`). So:

1. **c.id was DER; Fast DDS needs PEM.** `PKIDH.cpp:198-215 load_certificate` reads `c.id` via
   `PEM_read_bio_X509_AUX`; `:297-310 store_certificate_in_buffer` writes its own `c.id` via
   `PEM_write_bio_X509`. We emitted `x509-to-der`. → Fast DDS could not load our credential → no reply.
   The §8.7 hash_c is computed over the transmitted c.id bytes on both sides; changing c.id from DER to
   PEM changes the hashed bytes, so hash_c1 is NOT guaranteed to match — and the live logs confirm it does
   not: both ssd-none-ours2fast-fastdds.log and ssd-none-fast2ours-fastdds.log show
   `[SECURITY Warning] Wrong hash_c1 -> begin_handshake_reply` (both directions). The hash_c
   BinaryPropertySeq serialization diverges from Fast DDS and is a REAL cross-vendor blocker alongside
   dh1, not an artefact of the cert-load failure. The cert-load failure was blocking T4 but hash_c1 is a
   separate divergence that would block progress even once cert-load succeeds.

2. **Our peer false-rejected an out-of-role token.** The live peer sends us `DDS:Auth:PKI-DH:1.0+Req`
   tokens (from Fast DDS's prefix D1437B8E). Our requester fed them to `%process-reply`, which rejected on
   the class_id mismatch and latched `:rejected` — discarding the genuine Reply if/when it arrives. §8.7.2.4:
   the requester processes ONLY the HandshakeReply.

## Conformant fixes (corroborated, clean-room — Apache-2.0 Fast DDS only; RTI never read).

- **c.id = PEM certificate** (§9.3.2.1 credential form). New `dds.dare:x509-to-pem` (PEM_write_bio_X509) at
  the request + reply emit sites; the hash_c input uses the same PEM bytes. Decode is **tolerant** —
  `dds.dare:x509-load-cert-auto` (PEM then DER) never false-rejects a legacy DER peer.
- **Requester drops out-of-role tokens** — `auth-manager.lisp %am-drive-handshake` drops any non-Reply token
  while `:awaiting-reply` (new `%am-token-class`), symmetric to the replier's duplicate-request guard.

Live confirmation: `Cannot load certificate` is GONE; Fast DDS loads our cert and proceeds to key-agreement;
our peer logs `requester: dropped out-of-role token (class=DDS:Auth:PKI-DH:1.0+Req; awaiting HandshakeReply)`
and stays `HANDSHAKING` (was `REJECTED`).

## NEXT blockers (for T4): TWO independent cross-vendor divergences.

### Blocker 1: dh1/dh2 EC public-key format.

`PKIDH.cpp:761-867 generate_dh_peer_key` deserializes the EC dh key via **`o2i_ECPublicKey`** (raw
uncompressed EC point), called on our `dh1` at `:1706`; we emit dh1/dh2 as **SubjectPublicKeyInfo DER** →
`[Error] Cannot deserialize public key (PKIDH.cpp:858)`. T4 fix = emit the raw uncompressed EC point
(`i2o_ECPublicKey` / `EC_POINT_point2oct`) and parse the peer dh as a raw point (decode-tolerant).

### Blocker 2: hash_c BinaryPropertySeq serialization divergence (live evidence).

Both ssd-none-ours2fast-fastdds.log and ssd-none-fast2ours-fastdds.log show
`[SECURITY Warning] Wrong hash_c1 -> begin_handshake_reply` in both directions. This is independent of
the cert-load failure (fixed in T3); Fast DDS recomputes hash_c1 over the handshake BinaryPropertySeq and
it does NOT match our transmitted value. The T3 claim that "hash_c matches regardless of encoding" was
wrong and is retracted here. Note: dh1 bytes are included in the hashed BinaryPropertySeq (§9.3.2.1
c.id,c.perm,c.pdata,c.dsign_algo,c.kagree_algo — dh1 is NOT in the hash_c1 input set, but fixing the
dh1 encoding changes what goes into the DataHolder BinaryPropertySeq wire layout that Fast DDS parses).
T4 must re-verify hash_c1 agreement after fixing dh1 — do NOT assume fixing dh1 resolves hash_c1.

### T4 watch-item: role-election and the `+Req` token drop.

Fast DDS emits `DDS:Auth:PKI-DH:1.0+Req` tokens which we currently drop (T3 fix: requester discards
out-of-role tokens while `:awaiting-reply`). However, if both sides computed themselves as the requester
— which can happen if Fast DDS uses the §9.3.2.1 cert-derived key for ordering rather than the raw RTPS
prefix we use in `identity.lisp:347`/`auth-manager.lisp:244` — then dropping those `+Req` tokens is
WRONG: we would owe a reply but would never send one, and both sides would be stuck in HANDSHAKING
indefinitely. T4 must determine whether the `+Req` arrival is a role-disagreement (both elected
requester, we should switch to replier) or a retransmit (Fast DDS re-sending its own request), and
handle accordingly.

## our-to-our greenness (binding invariant) — GREEN both impls.

SBCL **377 passed** (deterministic). Clasp **377 passed** on re-run; two transient Clasp failures
(`SDP-SEC-PREFIX-ON-WIRE`, then `SDP-BYTE-EXACT`) were both DOWNSTREAM of the handshake in the single
live-socket e2e test (`%run-secure-discovery-e2e`) — the known Clasp timing-flake; the changed code (the
PSM handshake dispatch) succeeded in every run. gate-hotpath PASS (8 files), gate-types PASS (2025 ftype),
fuzz PASS (Clasp + SBCL), mem 0 bytes/sample.
