# T11reverse live cross-vendor result — WP-DDS-SECURITY-FASTDDS-INTEROP (M7/P6 Slice 5)

`bash interop/security-secure-discovery/run-fastdds-interop.sh secure 45` — our stack <-> a SECURITY=ON
eProsima Fast DDS v3.6.1 peer, both directions, **GOV=secure** (discovery_protection=ENCRYPT, liveliness=SIGN,
rtps_protection=ENCRYPT, metadata_protection=ENCRYPT, data_protection=ENCRYPT). This iteration closes the
REVERSE direction (ours2fast) — the FINAL functional blocker. Captures:
`ssd-secure-{ours2fast,fast2ours}-{ours,fastdds}.log` (+ `.pcapng`, gitignored — tshark cannot dissect the
macOS lo0 NULL/loopback link layer, ADR 0036; diagnosis rests on the Fast DDS verbose logs + clean-room Fast
DDS source + our decoded bytes).

## THE DoD: PROTECTED USER DATA NOW FLOWS **BOTH DIRECTIONS**

| | T10userdata (before) | T11reverse (after) |
|---|---|---|
| user-endpoint match | matched=1 both | matched=1 both |
| **fast2ours** protected DATA (Fast DDS pub -> OUR sub) | FLOWS `peak-samples=89` | FLOWS `peak-samples=88` |
| **ours2fast** protected DATA (OUR pub -> Fast DDS sub) | **0** (peak-samples=0) | **FLOWS — Fast DDS RECEIVED 8/8** (`'Hello world from Lisp' index 0..7 RECEIVED`) |

**Both directions PASS.** ours2fast: Fast DDS's subscriber decoded our full inbound stack (SRTPS whole-RTPS
decode -> user SEC_PREFIX metadata bracket decode -> re-dispatch -> data_protection serialized-payload decode ->
its user reader) for all 8 samples. fast2ours: our subscriber decoded 88 of Fast DDS's protected samples.

## THE TWO DIVERGENCES (diagnosed in dependency order; each diagnosed -> conformant fix -> re-run)

### 1. data-representation QoS — Fast DDS rejected our writer at MATCH (upstream of all crypto)
Fast DDS logged `1x [RTPS_EDP Warning] Incompatible Data Representation QoS -> valid_matching` and its
subscriber NEVER matched our publisher. Our interop writer offered XCDR2 only (`make-writer-qos` default);
Fast DDS's `@extensibility(APPENDABLE)` HelloWorld reader runs the default `DataReaderQos` = empty
DATA_REPRESENTATION = XCDR1, and `EDP::checkDataRepresentationQos` makes an XCDR2 writer vs an XCDR1/empty
reader INCOMPATIBLE (XTypes 1.3 Table 7.57). So Fast DDS rejected our writer BEFORE any crypto — the user
writer never matched, its DatawriterCryptoToken stayed pending. fast2ours matched because our READER accepts
`(:xcdr2 :xcdr1)`. The persistent `No key material yet -> lookup_reader` warnings were BENIGN builtin noise,
present IDENTICALLY in the working fast2ours direction (the T10 hypothesis that Fast DDS dropped our user token
was wrong). **Fix:** the interop peer's user writer offers XCDR1 (PLAIN_CDR) — the same symmetric resolution
already recorded for WP-FLATDATA-XCDR-TRANSCODE. Harness-only; no core/wire change.

### 2. data_protection SecureDataTag 4-byte alignment — Fast DDS could not decode the user payload
With the match fixed, Fast DDS reached the payload decode and failed:
`[SECURITY_CRYPTO Error] Error in fastcdr trying to deserialize SecureDataTag length -> decode_serialized_payload`.
Fast DDS `serialize_SecureDataTag` aligns the `receiver_specific_macs` length to 4 (relative to the
SecuredPayload start, AFTER the common_mac): `header(20) || ct_len(u32 BE) || ciphertext(N) || common_mac(16)
|| <pad to 4> || rsm_count(u32 BE)` — a SecuredPayload is always 4-aligned. Our serializer omitted the pad, so
for a non-4-aligned N (our 34-octet XCDR1 payload) Fast DDS read `rsm_count` 2 octets past the buffer end.
fast2ours worked only because Fast DDS's 'Hello world' payload is N=24 (already 4-aligned). **Fix:**
`(align cursor 4)` the rsm_count in `serialize-crypto-footer`/`parse-crypto-footer` +
`serialize-secured-payload`/`parse-secured-payload`, exactly as Fast DDS. Provable NO-OP for the
submessage/whole-RTPS brackets (already 4-aligned) and the existing secured-payload corpus (4-octet ciphertext)
-> corpus byte-exact, unchanged.

## ours2fast Fast DDS log (after) — the decode errors are GONE
- `8x Message: 'Hello world from Lisp' with index '0'..'7' RECEIVED`
- The T10 `Error in fastcdr trying to deserialize SecureDataTag length` + `Error decoding encoded payload` are
  ABSENT.
- Residual warnings are the benign builtin noise also present in fast2ours: `128x No key material yet ->
  lookup_reader`, `3x -> preprocess_secure_submsg`, `1x Could not find key material -> decode_datareader_submessage`
  (an early ACKNACK), `1x Cannot decode reader RTPS submessage`, `1x transport interfaceWhiteList` (cosmetic).

## our-to-our (binding invariant) — GREEN both impls
- **SBCL**: `make test-sbcl` = **380 passed** (deterministic; incl. the updated `user-submessage-data-protection`
  + secured-payload/submessage/crypto-header/rtps-message corpora byte-exact + the four secure-discovery e2es).
- **Clasp**: `make test-clasp` = **380 passed** (full suite, clean this run). The documented NFR-PORT
  live-socket/threading flake is intermittent and WANDERS between tests/runs (it hit two earlier full-suite
  runs on unrelated FlatData/Shapes tests, cleared by re-run + a FASL-cache clear — not chased, memory: Clasp
  threading gap); the secure suite also passes in isolation (all 11 secure e2e + PVMS + data-protection +
  secure-SEDP + crypto-manager).
- gate-hotpath(8) / gate-types(2048) / corpus(M1 stub) / fuzz (submessage + rtps-message arms exercise the new
  pad-skip bounds check) / mem(0.0000 bytes/sample) PASS.

## Carry
- Connext-Security live remains the **Slice-5b** exit gate (RTI Security Plugins absent on this host).
- tshark lo0 dissection environment-limited (ADR 0036); the both-directions live decode is itself the
  cross-vendor wire proof.
