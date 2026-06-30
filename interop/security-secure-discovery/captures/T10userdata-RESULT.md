# T10userdata live cross-vendor result — WP-DDS-SECURITY-FASTDDS-INTEROP (M7/P6 Slice 5)

`bash interop/security-secure-discovery/run-fastdds-interop.sh secure 45` — our stack ↔ a SECURITY=ON
eProsima Fast DDS v3.6.1 peer, both directions, **GOV=secure** (discovery_protection=ENCRYPT,
liveliness=SIGN, rtps_protection=ENCRYPT, metadata_protection=ENCRYPT, data_protection=ENCRYPT). This
iteration adds the user-DATA protection tier: (1) Slice-1 serialized-payload AAD reconciled to EMPTY
(Fast-DDS-faithful), (2) KeyMaterial advertised kind GMAC/GCM, (3) user-DATA submessage protection
(metadata_protection, §8.5.1.7-.9). Captures: `ssd-secure-{ours2fast,fast2ours}-{ours,fastdds}.log`
(+ `.pcapng`, gitignored — tshark cannot dissect the macOS lo0 NULL/loopback link layer, ADR 0036; diagnosis
rests on the logs + Fast DDS source + our decoded bytes).

## THE ADVANCE: PROTECTED USER DATA NOW FLOWS ONE DIRECTION (was peak-samples=0 BOTH ways in T9)

| | T9protected (before) | T10userdata (after) |
|---|---|---|
| user-endpoint match | matched=1 both | matched=1 both (unchanged) |
| **fast2ours protected DATA** (Fast DDS pub → OUR sub) | **0** (`peak-samples=0`) | **FLOWS — `peak-samples=89`** (we decode Fast DDS's rtps+metadata+data-protected user DATA) |
| ours2fast protected DATA (OUR pub → Fast DDS sub) | 0 | still 0 (residual below) |
| Fast DDS ours2fast error | `89× Key material not found → decode_datawriter_submessage` + `8× Not valid SecureDataTag → decode_rtps_message` | `217× No key material yet → lookup_reader` + `1× Could not find key material → decode_datareader_submessage` — **the `Not valid SecureDataTag` SRTPS-level rejection is GONE** |

**fast2ours = the DoD direction achieved.** Our subscriber decoded 89 protected `HelloWorld` samples (Fast DDS
sent up to index 92), through the full inbound stack: SRTPS whole-RTPS decode (ParticipantCrypto) → user
SEC_PREFIX bracket decode (the remote user-writer EntityCrypto, `%on-user-secure-submessage`) → re-dispatch →
serialized-payload data_protection decode → user reader. `RESULT: PASS`, `ever-keyed=T`, stable across the
window (88 on the prior in-flight run, 89 on this re-run).

## REMAINING blocker (ours2fast, next iteration): our OUTBOUND user CryptoToken is not APPLIED at Fast DDS

Fast DDS receives our protected user submessages (the SRTPS envelope + the SEC_PREFIX bracket framing are now
ACCEPTED — the T9 `Not valid SecureDataTag → decode_rtps_message` is GONE), but at decode time it has **no
installed EntityCrypto for our user WRITER**:

- `217× [SECURITY_CRYPTO Warning] No key material yet → Function lookup_reader`
- `1× [SECURITY_CRYPTO Warning] Could not find key material → Function decode_datareader_submessage` (our ACKNACK)
- `1× [SECURITY Warning] Cannot decode reader RTPS submessage () → Function decode_rtps_submessage`
- `1× [RTPS_EDP Warning] Incompatible Data Representation QoS → valid_matching` (transient single-shot during
  early discovery; the dominant/persistent error is the crypto `lookup_reader` one — the endpoints DID match,
  our data DID reach Fast DDS's crypto layer)

### Best hypothesis + next conformant step (do NOT chase this iteration — finishing the validated advance)

ASYMMETRY: we install Fast DDS's user-writer EntityCrypto (→ 89 samples decoded), but Fast DDS does not install
OURS. The outbound `DatawriterCryptoToken` (our user-writer's §9.5.2 KeyMaterial, re-sent at endpoint-match via
`cm-on-endpoint-match` over the reliable PVMS, T9) is not being APPLIED by Fast DDS for the data decode —
`lookup_reader` finds the matched local reader but the reader↔our-writer crypto relation has no key material.
Next loop (CLEAN-ROOM vs Fast DDS `process_participant_volatile_message_secure` + `set_remote_writer_crypto`
→ `Handshake/CryptoTransform` reader-handle map; RTI never read): confirm (a) our match-time
DatawriterCryptoToken reaches Fast DDS over the reliable PVMS AND parses (vs being dropped/ignored), (b) the
token's `destination_endpoint_key` resolves to Fast DDS's actual local reader handle (the
`*_handles_.find(dest)` application), (c) the token's KeyMaterial `transformation_kind`/`sender_key_id` match
the SEC_PREFIX our DATA carries (so its `find_key` succeeds once installed). This is purely the OUTBOUND
user-token application — distinct from the inbound path this iteration proves works end-to-end. Connext-Security
live remains the Slice-5b exit gate (RTI Security Plugins absent).

## tshark — environment-limited (unchanged, ADR 0036)

tshark in this environment does not dissect the macOS lo0 NULL/Loopback link layer; the dissector histograms
are empty. Our submessage byte-exactness rests on the in-suite byte-exact corpus + fuzz (green both impls);
the inbound 89-sample decode is itself live cross-vendor proof that Fast DDS's emitted SRTPS+metadata+data wire
is what our decoders expect and vice-versa for the framing.

## our-to-our (binding invariant) — GREEN both impls

- **SBCL**: `make test-sbcl` = **378 passed** (deterministic); the new `user-submessage-protection` test +
  `security-encrypted-pubsub`/`-fragmented` (data-protection with the empty-AAD change) +
  secure-sedp/pvms/crypto-manager + the four secure-discovery e2es all ok.
- **Clasp** (`GC_DONT_GC=1 make test-clasp`): **378 passed, full suite, no abort** this run (including
  `user-submessage-protection ... ok`, all secure e2es, `governance-protection-kind ... ok`). A stale cached
  `perftest.fasl` caused a one-off FASL-loader `FLOATING-POINT-INVALID-OPERATION` on the first attempt; clearing
  the hofvarpnir main-tree Clasp FASL cache and rebuilding fixed it (not a code regression — `perftest.lisp` is
  untouched by this WP).
- `gate-hotpath(8)` / `gate-types(2047)` / `corpus`(M1 stub, rc 0) / `fuzz`(SBCL; submessage+rtps-message+
  origin-auth+payload arms) / `mem`(SBCL, 0.0000 bytes/sample) PASS.

## Security self-checks — all PASS (see the WP report for the full trace)

- (a) Empty-AAD integrity substitution: kind tamper → `find_key` reject (tested, arm d); key_id tamper →
  `find_key` reject; session_id/iv_suffix tamper → nonce/session-key change → GCM auth fail. All reject
  (no silent accept). Coverage note: only kind is directly byte-tampered in `security-test.lisp`;
  key_id/session_id/iv_suffix rejection is analytical + exercised by the find_key (key_id) and tag-tamper (GCM)
  arms.
- (b) User-submessage receive fail-closed: an undecryptable/forged/truncated bracket → `decode-datawriter-
  submessage` NIL → no synthetic dispatch, no plaintext. `rtps-unwrapped=t` is set ONLY post-AEAD (two call
  sites), never on unauthenticated data → no rtps_protection-enforcement bypass.
- (c) Nonce-safety: DATA+HEARTBEAT draw distinct monotonic iv_suffix from the user-WRITER KM counter; ACKNACK
  from the user-READER KM counter; the DATA payload's data_protection encode shares the SAME writer-KM singleton
  counter (no two-instances-same-master-key) → no (key, nonce) reuse.
