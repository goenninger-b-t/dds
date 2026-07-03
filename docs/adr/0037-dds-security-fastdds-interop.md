# ADR 0037 — Live Fast DDS-Security cross-vendor interop: the §8.7 auth → keyed → secure-SEDP → protected-data reconciliation campaign (Slice 5, Fast-DDS half)

- **Status:** Accepted (M7/P6; WP-DDS-SECURITY-FASTDDS-INTEROP, 2026-06-30)
- **Relates to:** ADR 0036 (Slice 4 — secure discovery our-to-our; this campaign closes its numbered
  Slice-5 carries against a live peer); ADR 0035 (Slice 3 — AccessControl; the Permissions document this
  campaign plumbs into `c.perm`); ADR 0034 (Slice 2b-ii + 2c — the auth manager + KxKey + crypto-token
  exchange driven cross-vendor here); ADR 0033 (Slice 2b-i — the PSM `DataHolder`/`ParticipantGenericMessage`
  wire codec whose `propagate`-byte carry this campaign resolves; **re-opened + closed by T1**); ADR 0032
  (Slice 2a — the §8.7.2.4 PKI-DH handshake completed cross-vendor here); ADR 0031 (Slice 1 — the
  serialized-payload codec; **two shipped crypto-wire changes land as ADR-0031 addenda**: the empty-AAD
  reconcile [T10] and the SecureDataTag `rsm_count` 4-align [T11]); ADR 0025 (DARE — the `dds-dare` OpenSSL
  FFI: AES-256-GCM / HMAC-SHA256 / GMAC / ECDH / CMS); NFR-SEC-POSTURE (bounds-checked fail-closed parsers,
  fuzzed; a **false REJECT is the worst defect class**); NFR-PORT (Clasp + SBCL both validate, Clasp first;
  no reader conditionals outside `dds-pal/`); the operating contract §4 (clean-room — Fast DDS read for
  understanding, **RTI Connext never read**).
- **Standards:** OMG DDS-Security 1.1 §7.2.x (`Property_t` / `BinaryProperty_t` / `DataHolder` /
  `ParticipantGenericMessage`); §7.4.3 / §7.4.4 (the PSM `ParticipantStatelessMessage` + the handshake
  message-identity correlation); §8.5.1.7–.9 / §8.5.1.10–.12 (the submessage + whole-RTPS crypto transforms);
  §8.5.2.x (the CryptoKeyExchange + `*_crypto_tokens` endpoint-key semantics); §8.7.2.4 (the PKI-DH handshake
  + role election); §9.3.2.1 (the adjusted participant GUID + `c.pdata`); §9.3.4 (the `Property`/`BinaryProperty`
  CDR serialization — the `propagate` byte); §9.4.1.1 (the S/MIME-signed Permissions/Governance document, RFC
  5652 CMS + RFC 5751 S/MIME); §9.5.2.1.1 Table 70 (the `KeyMaterial_AES_GCM_GMAC` `transformation_kind`s
  incl. AES256-GMAC `{0,0,0,3}`); §9.5.3.3.3 (the SecureDataTag); §9.5.3.3.4.4 (`encode_serialized_data`);
  RTPS 2.5 §8.3.5.4 / §8.4.2 (the writer sequence number); §10.2 (the CDR encapsulation header); OMG
  DDS-XTypes 1.3 Table 7.57 (the data-representation `valid_matching` rule). Every value is dual-corroborated
  against eProsima Fast DDS (Apache-2.0, read for understanding, `docs/provenance.md`) and Eclipse Cyclone DDS
  (EPL) where applicable; the OMG IDL `dds_security_plugins_spis.idl` (DDS-SECURITY/20170901) is the normative
  artifact for the `propagate` resolution. **No RTI Connext source, headers, or generated code was ever read.**

---

## Context

ADR 0036 (Slice 4) delivered secure discovery **end-to-end our-to-our** — submessage + whole-RTPS protection,
origin authentication, reliable `ParticipantVolatileMessageSecure` (PVMS), the Governance protection-kind
model, the secure builtin endpoints — and reached, **cross-vendor against a live SECURITY=ON eProsima Fast DDS
v3.6.1 peer**, only *bidirectional SPDP discovery + four config/wire fixes*. The §8.7 handshake **rejected at
the remote IdentityToken**, blocked by the `propagate`-byte divergence, so none of the keyed tiers were
exercised cross-vendor. ADR 0036 was explicit: *"Do NOT interpret this slice as cross-vendor secure discovery
verified."* It enumerated eleven numbered Slice-5 carries.

Slice 5 is the **P6 exit gate**. It is a **reconciliation campaign, not a feature build**: the deliverable is
behavioral — make a real Fast DDS-Security peer and ours complete the **full secure path both directions**
(plain SPDP → §8.7 PKI-DH auth → SharedSecret → crypto-token exchange `:keyed` → secure-SEDP endpoint match →
protected user data, byte-exact) — and the work is **discovery-driven**: T0 confirmed only the `propagate`
blocker; each subsequent divergence was revealed by the live peer, fixed conformant, corroborated clean-room,
and re-run to surface the next. The owner split the exit gate: **this ADR records the Fast-DDS half** (live RTI
Connext-Security is **Slice 5b**, deferred because the licensed RTI Security Plugins / `libnddssecurity*` are
not installed on this host).

This ADR documents the **WP-DDS-SECURITY-FASTDDS-INTEROP** work package as built, from the controller's
commit-by-commit ledger (T0 `9dea5d0` … T11 `b74fb54` on `wp-dds-security-fastdds-interop`).

---

## The campaign shape

A **live-peer-driven reconciliation loop**, twelve increments (T0 spike → T11), each its own commit + two-stage
review, holding the **our-to-our-green invariant** (both impls, byte-exact corpus regenerated with each
conformant wire change, fuzz, gate-hotpath, gate-types, mem) after every step:

1. **T0 — spike.** Confirm the Fast DDS-Security peer (v3.6.1, `-DSECURITY=ON`), the live harness
   (`interop/security-secure-discovery/run-fastdds-interop.sh`; tcpdump — tshark cannot dissect macOS `lo0`),
   the live baseline (SPDP works; auth rejects at the remote IdentityToken), and **pin the `propagate`-byte
   resolution** four-way (OMG IDL + Fast DDS + Cyclone).
2. **T1 — the one fully-specifiable fix.** Drop the `propagate` byte slice-wide; regenerate the entire token
   corpus.
3. **T2…T11 — the discovery loop.** Run the live peer → diagnose the next REJECT/mismatch (capture + logs) →
   fix it conformant (corroborate OMG + Fast DDS + Cyclone; shim-on-top only for a genuine vendor-vs-spec
   divergence) → regenerate any affected corpus → confirm our-to-our green both impls → re-run. Each iteration
   unblocked the next; the candidate backlog from ADR 0036 was the *likely* order, the live peer the authority.

**Decode-tolerance posture.** Where a divergence admitted a self-describing both-forms decode (the dh1/dh2
EC-point-vs-SPKI form, the CMS PEM-vs-S/MIME container), we **accept both** so a spec-literal peer is never
false-REJECTed. Where it did not (the trailing 4-octet `propagate` field is not self-describing and collides
with the next field), we emit the conformant form and **fail closed** on the legacy form, flagging "verify
Connext at 5b". A false REJECT is the worst defect class (the operating contract).

---

## The divergences (the as-built sequence, each conformant + corroborated)

Every row was found by the live peer, fixed on the OMG-conformant path, corroborated clean-room against Fast
DDS (and Cyclone / the OMG IDL where applicable), kept our-to-our byte-exact on both impls, and re-run live.
**RTI Connext source was never read.**

| # | Divergence (live symptom) | Conformant resolution | Citation | Commit |
|---|---|---|---|---|
| 1 | §9.3.4 `Property`/`BinaryProperty` `propagate` byte — our codec emitted a 4-octet `propagate` per property; Fast DDS does not → every cross-vendor token misaligned → auth REJECTs at the remote IdentityToken | Serialize `name`+`value` only; omit `propagate=false` from the seq; `propagate` is a *local* include-filter. Decode the conformant form; no tolerance shim (trailing field not self-describing → fail closed) | OMG IDL `dds_security_plugins_spis.idl` §9.3.4; Fast DDS `Property.hpp:174-191`, `CDRMessage.cpp:828-929`, `PKIDH.cpp:1396-1410`; Cyclone `dds_security_serialize.c` | T0 `9dea5d0` (pin) → T1 `3d07bd4` |
| 2 | PSM `writerSN`=0 → RTPS "bad sequenceNumber" reject | Monotonic `psm-writer-sn` from 1 | RTPS 2.5 §8.3.5.4 / §8.4.2 | T2 `b6a1448` |
| 3 | PSM `source_endpoint_key`=our-GUID → SecurityManager drops the message | Emit `GUID_UNKNOWN` (auth message leaves endpoint keys unknown) | §7.4.4 | T2 `b6a1448` |
| 4 | wire `DataHolder` `BinaryProperty` octet-vector not 4-aligned → `readDataHolderSeq` misaligns | Pad on encode + skip on decode (the *wire* DataHolder only; the §8.7 hash/Sign seq stays unpadded) | Fast DDS `CDRMessage.cpp` `addBinaryPropertySeq(add_final_padding=true)` + `readOctetVector` | T2 `b6a1448` |
| 5 | `c.pdata` 4-byte stub + non-conformant participant GUID → `begin_handshake_reply` rejects | §9.3.2.1 adjusted GUID = SHA-256(cert subject) (`X509_NAME_digest`), carried in a real BE ParameterList `c.pdata` | §9.3.2.1 | T2 `b6a1448` |
| 6 | `c.id` credential as DER → "Cannot load certificate" | Emit the certificate as **PEM**, not DER (Fast DDS `load_certificate`); requester drops out-of-role tokens | Fast DDS `PKIDH` `load_certificate` | T3 `3a31a5e` |
| 7 | dh1/dh2 as SubjectPublicKeyInfo DER → "Cannot deserialize public key" | Emit the **raw uncompressed EC point** `0x04‖X‖Y`; decode-tolerant (raw point OR SPKI DER → RFC 5903 KAT stays green) | Fast DDS `store_dh_public_key` `EC_POINT_point2oct` / `o2i_ECPublicKey` (`PKIDH.cpp:737,833,858`) | T4 `5f3b6ab` |
| 8 | "Wrong hash_c1" — our `hash_c`/Sign `BinaryPropertySeq` padded every octet value | Pad each octet value **except the last** (`add_final_padding=false`) | Fast DDS `addBinaryPropertySeq(...,false)` + `addOctetVector` (`CDRMessage.cpp:1001-1003,602-637`); hash is BIGEND (`PKIDH.cpp:1398`) | T4 `5f3b6ab` |
| 9 | Role election + duplicate Request retransmits (watch-item) | **No code change** — Fast DDS elects requester iff adjusted GUID < remote, the same §9.3.2.1 compare we use (we agree); +Req are Fast DDS failure-retries | §8.7.2.4; Fast DDS `validate_remote_identity` (`PKIDH.cpp:1293`) | T4 `5f3b6ab` / T3-review `b2a38cc` |
| 10 | §7.4.3 handshake Final ignored — our Final hardcoded `related_message_identity={GUID_unknown,0}` → Fast DDS treats it as a missed reply, never authorizes | Echo the incoming `message_identity` as the response's `related_message_identity` (`related.source_guid`==its PSM-writer GUID, `related.sequence_number`==expected) | §7.4.3; Fast DDS `process_participant_stateless_message:1554/1582/1590` | T5 `6776454` |
| 11 | PVMS crypto-token prerequisites | SPDP `BuiltinEndpointSet` bits 24/25; PVMS SerializedPayload §10.2 PLAIN_CDR_LE encapsulation; participant crypto-token `source_endpoint_key`=`GUID_unknown`; governance-sensitive keyed-gate | §10.2; §8.5.2.1; Fast DDS `SecurityManager.cpp:1700-1718,1745` | T5 `6776454` |
| 12 | Empty `c.perm` → Fast DDS "Cannot read as PKCS7 the permissions file" → permissions validation aborts | Plumb the configured S/MIME-signed Permissions document verbatim into `c.perm` (folded into `hash_c`); `cms-verify` decode-tolerant: `PEM_read_bio_CMS` first, else `SMIME_read_CMS` + `CMS_verify(CMS_TEXT)` | §9.4.1.1; RFC 5652 + RFC 5751; Fast DDS `Permissions.cpp:354,406,777-797`, `PKIDH.cpp:1352-1364` | T6 `6a622f9` |
| 13 | PVMS ParticipantKeyMaterial `transformation_kind`=AES256-GMAC `{0,0,0,3}` false-REJECTed (`%parse-km-cdr` accepted-kind set omitted 0x03) | Accept all four non-NONE `transformation_kind`s | §9.5.2.1.1 Table 70; Fast DDS `AESGCMGMAC_KeyFactory` `c_transfrom_kind_aes256_gmac` | T7-PVMS `5bfafe3` |
| 14 | PVMS HEARTBEAT/ACKNACK sent clear → Fast DDS drops them on a protected endpoint (and we dropped its encrypted ones) → our token never NACK-pulled | Submessage-ENCRYPT-protect the PVMS HEARTBEAT (`encode-datawriter-submessage`) + ACKNACK (`encode-datareader-submessage`) under the bootstrap KM + per-role `session_id`; demux the decoded inner DATA/HEARTBEAT/ACKNACK | Fast DDS `RTPSMessageGroup add_heartbeat/add_acknack` → `encode_writer/reader_submessage`; `MessageReceiver` `was_decoded \|\| !is_submessage_protected` | T7-PVMS `5bfafe3` |
| 15 | Under GOV=secure, requiring the secure-SEDP/PM EntityCryptos before `:keyed` deadlocked the two-phase peer | Gate `:keyed` on the **ParticipantCrypto alone**; the endpoint EntityCryptos install lazily by `transformation_key_id` (Fast DDS exchanges them in phase two, after the participant secure-match) | §8.5.2; Fast DDS `PDPSimple::assignRemoteEndpoints notify_secure` → `EDPSimple` | T8-SEDP `918167b` |
| 16 | DW/DR CryptoToken `destination_endpoint_key`=`GUID_unknown` → Fast DDS rejects, applies-by-`find(dest)` fails → phase two never triggers | DW/DR token `destination_endpoint_key` = the **matched-remote complementary endpoint GUID** (builtin 0xC2↔0xC7; user writer-id↔reader-id); a participant token still uses both keys=`GUID_unknown` | §8.5.2; Fast DDS `SecurityManager.cpp:1739/1745/1830/1907/1924/1848` | T8-SEDP `918167b` |
| 17 | After keying, secure builtin endpoints are RELIABLE — Fast DDS HEARTBEATs (inner id 7) + expects ACKNACK (id 6); `%on-secure-builtin` dropped them → no secure-SEDP delivery → user endpoints never match | Demux the recovered inner submessage by id: DATA records its SN + routes; HEARTBEAT → range + submessage-PROTECTED ACKNACK (`encode-datareader-submessage`); ACKNACK → resend NACKed secure-SEDP DATA; emit NON-FINAL secure-SEDP HEARTBEATs so a reliable reader NACK-pulls | §8.5.2; the M2 reliable engine; the §9.3.2 secure-builtin EntityId pair 0xC2→0xC7 | T9 `eff2ae0` |
| 18 | User DW/DR CryptoToken keyed on an auth-time symmetric guess, not the real matched endpoint | Re-exchange the USER DW/DR CryptoToken at endpoint-MATCH (`cm-on-endpoint-match` via `%on-disc-match`) with `destination_endpoint_key`=the real matched-remote endpoint GUID; gated on the remote being keyed; idempotent our-to-our | §8.5.2 | T9 `eff2ae0` |
| 19 | INCOMPATIBLE QOS keyed:1 vs keyed:0 — our interop HelloWorld endpoints were keyed | Declare the interop HelloWorld endpoints NO_KEY (`:keyed nil`, harness-only) to match Fast DDS's NO_KEY example | DDS 1.4 RxO key-matching; Fast DDS HelloWorld example | T9 `eff2ae0` |
| 20 | Protected user DATA needs a submessage tier — Fast DDS "Not a valid SecureDataTag" / "Key material not found" on our plain user DATA | Wrap the user DATA submessage with SEC_PREFIX **metadata_protection** under the per-endpoint EntityCrypto | §8.5.1.7-.9 | T10 `3e92d08` |
| 21 | **(SHIPPED Slice-1 crypto-wire change)** the serialized-payload AEAD AAD = the 20-byte SecureDataHeader; Fast DDS uses **empty** AAD → data_protection cannot interoperate | AAD = **EMPTY** across all three tiers (the single shared `+empty-octets+`); header integrity preserved via `find_key` (kind/key_id) + the KDF/nonce (session_id/iv_suffix). GCM tag value changes → corpus re-pinned | §9.5.3.3.4.4; Fast DDS `serialize_SecureDataBody` ENCRYPT branch (no prior AAD `EVP_EncryptUpdate`) — **see the ADR-0031 empty-AAD addendum** | T10 `3e92d08` |
| 22 | KeyMaterial advertised kind vs wire CryptoHeader kind — a SIGN endpoint advertising a GCM KeyMaterial is "Key material not found" | The advertised `transformation_kind` MUST equal the wire CryptoHeader kind (Fast DDS `find_key` matches on kind AND `sender_key_id`) | §9.5.2; Fast DDS `AESGCMGMAC_Transform::find_key` | T10 `3e92d08` |
| 23 | rtps_protection enforcement + a non-4-aligned recovered submessage silently dropped | Enforce-gate a bare (non-SRTPS-wrapped) user metadata_protection bracket under a required `rtps_protection` (builtin exempt); move the 4-align pad into the SEC_BODY `CryptoContent` container (not the plaintext) so the recovered submessage reflects its TRUE length; + tamper-coverage arms + a NONE-tier short-circuit | §8.5.1.10-.12; Fast DDS `serialize_SecureDataBody` (submessage=true) — **see the ADR-0031 SEC_BODY 4-align addendum** | T10-review `4d27178` |
| 24 | data-representation QoS — our interop user WRITER offered XCDR2 only; Fast DDS's `@extensibility(APPENDABLE)` HelloWorld DataReader defaults to XCDR1 → INCOMPATIBLE at match → the writer never matches, so its token is never applied | The interop peer's writer offers XCDR1 (PLAIN_CDR); harness-only, our XCDR2 default is per-spec and unchanged | DDS-XTypes 1.3 Table 7.57 `valid_matching`; Fast DDS `EDP::checkDataRepresentationQos` (the same resolution as M5 WP-FLATDATA-XCDR-TRANSCODE) | T11 `b74fb54` |
| 25 | **(SHIPPED Slice-1 crypto-wire change)** the SecureDataTag `receiver_specific_macs_count` not 4-aligned → Fast DDS "Error in fastcdr trying to deserialize SecureDataTag length" for a non-4-aligned ciphertext | 4-align the rsm_count to the SecuredPayload start (`serialize/parse-crypto-footer` + `serialize/parse-secured-payload`); pad = `(-N) mod 4`; byte-identical for the 4-aligned shipped corpus | §9.5.3.3.3; Fast DDS `serialize_SecureDataTag` — **see the ADR-0031 SecureDataTag-align addendum** | T11 `b74fb54` |

The two **SHIPPED crypto-wire changes** (#21 empty-AAD, #25 SecureDataTag 4-align) altered the wire behavior of
the *landed* Slice-1 codec and are each recorded as an **ADR-0031 addendum** (the third change, #23's SEC_BODY
4-align on the submessage/SRTPS tiers, is the second ADR-0031 addendum); the corpus was re-pinned for #21 (the
GCM tag value changed) and unchanged for #25 (4-aligned vectors are pad-free).

---

## The green cross-vendor run (the DoD)

Live, both directions, vs the SECURITY=ON eProsima Fast DDS v3.6.1 peer, under the **protected governance**
(`GOV=secure`: `discovery_protection` / `rtps_protection` / `metadata_protection` / `data_protection` = ENCRYPT),
sharing the reused Identity-CA / Permissions-CA / Governance
(`bash interop/security-secure-discovery/run-fastdds-interop.sh secure`):

- **ours2fast** (our publisher → Fast DDS subscriber): Fast DDS **RECEIVED 8/8** of our ENCRYPT-protected
  `HelloWorld` samples (`'Hello world from Lisp' index 0..7 RECEIVED`).
- **fast2ours** (Fast DDS publisher → our subscriber): we **decoded 88** of Fast DDS's ENCRYPT-protected
  samples.

Both directions traverse the **full stack**: plain SPDP bootstrap → §8.7 PKI-DH authentication → SharedSecret →
permissions validation → PVMS ParticipantCryptoToken exchange → `:keyed` → reliable secure-SEDP endpoint match →
SRTPS `rtps_protection` + SEC_PREFIX `metadata_protection` + serialized-payload `data_protection` (all ENCRYPT)
on the matched, authenticated, permissioned user endpoints.

**Captures (committed):** `interop/security-secure-discovery/captures/ssd-secure-ours2fast.{pcapng,…-ours.log,…-fastdds.log}`
and `…/ssd-secure-fast2ours.{pcapng,…-ours.log,…-fastdds.log}`, plus the per-task `T*-RESULT.md` and the
`CAPSTONE-RESULT.md`. tshark cannot dissect the macOS `lo0` NULL/Loopback link-layer (ADR 0036); `tcpdump -r`
confirms well-formed RTPS, and the **live cross-vendor decode in both directions is itself the wire proof**
(Fast DDS's plugins parse our protected frames and vice-versa); secure-submessage byte-exactness additionally
rests on the in-suite byte-exact corpus (regenerated green every step).

**This is Fast-DDS-validated, NOT Connext-validated.** Live RTI Connext-Security secure discovery is **Slice 5b**
— the licensed RTI Security Plugins (`libnddssecurity*`) are not installed on this host. No statement in this ADR
asserts Connext interop.

---

## Honest posture

- **Achieved (this WP):** live cross-vendor DDS-Security interop vs a real Fast DDS-Security peer — the full
  `SPDP → §8.7 auth → SharedSecret → crypto-token :keyed → secure-SEDP match → protected user data` path, **both
  directions, protected user data exchanged** (ours2fast 8/8 + fast2ours 88) under the protected governance. This
  is the **Fast-DDS half of the P6 exit gate**.
- **Not achieved (deferred):** live RTI Connext-Security (Slice 5b — plugins absent). The Fast-DDS-shaped fixes
  (decode-tolerance where the form is self-describing; the `propagate` conformant-only emit) are flagged for
  Connext re-verification at 5b.
- **Our-to-our invariant held throughout:** both impls green after every step; the byte-exact corpus regenerated
  with each conformant wire change; never a weakened test.

---

## Residual carries (recorded, NOT fixed here — none blocks the Fast-DDS exit gate)

1. **§9.3.2 0xC2→0xC7 secure-builtin EntityId pairing is computed in three places** (the secure-SEDP
   writer↔reader complement is open-coded in `crypto-manager` / `volatile-secure` / `secure-sedp`).
   Package-ownership-justified today (`dds-disc` must not import `dds-dcps`; each site is in its own package);
   a shared `dds.rtps` helper would DRY it. Benign — the three derivations agree.
2. **No dedicated our-to-our test counts secure-builtin ACKNACKs on the wire.** The T9 reliability
   handlers (`%on-secure-builtin-heartbeat`/`-acknack`, `%send-secure-builtin-heartbeats`) are proven
   non-vacuous only via the e2e secure-discovery test + the live Fast DDS NACK-pull. A unit test asserting an
   ACKNACK count on the secure-builtin wire (the M2-reliable pattern) would make the reliability path
   independently regression-proof without the live peer.
3. **The SIGN-tier inter-submessage alignment + GMAC AAD byte-span (the ADR-0036 T12 carry).** The headline
   `GOV=secure` governance is ENCRYPT on every tier, so the SIGN GMAC AAD span and the SIGN 4-octet
   re-alignment were **not exercised** by the live peer. Reconcile + verify if a SIGN-tier governance is run
   (and at Connext 5b).
4. **Live RTI Connext-Security secure discovery (Slice 5b) — the remaining half of the P6 exit gate.** Requires
   the licensed RTI Security Plugins (not installed). The Fast DDS-Security harness + run scripts are in place.
5. **The ADR-0036 hardening carries not forced by the live peer:** zero-alloc into-buffer AEAD on the data
   path (~2.2 KB/datagram residual; `make mem` does not cover the dds-disc rtps path); per-topic
   `metadata_protection` applied selectively to user endpoints; `pvms-bootstrap-kms` pruning on peer-loss;
   `%dn-normalize` RFC2253 escaped/quoted/multi-valued edge cases; KeyMaterial GC-heap → foreign/static
   hardening (ADR 0034); builtin-endpoint share-vs-own-key vs Connext; Zero-Copy × `rtps_protection` SHMEM
   cleartext; the `%on-secure-builtin` inner-writerId cross-check (defense-in-depth). None is on the Fast-DDS
   exit-gate path; each is a follow-on.

---

## Residual-carry status reconciliation vs Connext (WP-SLICE5B-FOLLOWONS B3, 2026-07-03)

Slice 5b (ADR 0040) reconciled the live-Connext half of the P6 exit gate; several carries above were resolved by
it or by subsequent hardening WPs. Status of each Fast-DDS-era carry against the current tree:

| Carry | Status vs Connext | Evidence |
|---|---|---|
| **1 — 0xC2→0xC7 pairing computed in three places (DRY)** | **OPEN — vendor-agnostic, NOT a Connext divergence** | Still open-coded in `dds-disc/volatile-secure.lisp`, `dds-disc/secure-sedp.lisp`, `dds-dcps/crypto-manager.lisp`. A code-quality DRY refactor, not an interop reconciliation; the three derivations agree, and a shared helper would have to sit below both packages (`dds-disc` must not import `dds-dcps`), so it is a deliberate follow-on, not a quick close. The live Connext GOV=secure interop exercised all three sites correctly (protected metatraffic both directions). |
| **2 — no dedicated our-to-our test counts secure-builtin ACKNACKs** | **OPEN — vendor-agnostic test-hardening** | The secure-builtin reliable NACK-pull is now driven by TWO live cross-vendor peers (Fast DDS AND Connext: the Slice-5b reverse direction needed reliable secure-SEDP under GOV=secure) plus the e2e our-to-our test, but a dedicated unit test asserting an ACKNACK COUNT on the secure-builtin wire is still a follow-on. Not Connext-specific. |
| **3 — SIGN-tier inter-submessage alignment + GMAC AAD byte-span** | **OPEN vs Connext (live gate was all-ENCRYPT); our-to-our COVERED** | ADR 0040 divergence #7 set the `governance-sign` `rtps_protection` ENCRYPT→SIGN and updated its OUR-TO-OUR test (`run-secure-discovery-protected-sign-test` — the topic inside a SIGN SRTPS_PREFIX bracket). The LIVE Connext DoD gate ran all-ENCRYPT (GOV=secure), so the SIGN GMAC AAD span was NOT exercised LIVE vs Connext. Already tracked in ADR 0040 carry #5. |
| **4 — live RTI Connext-Security secure discovery (Slice 5b)** | **RESOLVED** | ADR 0040 (WP-DDS-SECURITY-CONNEXT-INTEROP, LANDED 2026-07-02): protected user DATA both directions ours↔live RTI Connext 7.3.1 (GOV=secure, all-ENCRYPT); the §8.7.2.3 AuthRequestMessageToken sub-protocol + §7.4.3.3 monotonic PSM seq unblocked the full-participant handshake. **The P6 exit gate is COMPLETE (both halves).** B1 (this WP) additionally live-covers GOV=none reverse (ADR 0040 carry #1 resolved). |
| **5a — zero-alloc into-buffer AEAD on the data path** | **RESOLVED (send path) — mem-covered** | ADR 0038/0039 (WP-DDS-SECURITY-ZEROALLOC-AEAD) landed the zero-alloc submessage `metadata_protection` + whole-RTPS `rtps_protection` tiers; `make mem` now COVERS the dds-disc path with the secured SEND arms at 0.0000 B/sample (`meta-send`/`rtps-send`/`rtps-recv` delta 0.0000). The `meta-recv` loan-wrapper residual (~176 B) remains a documented follow-on. |
| **5b — KeyMaterial GC-heap → foreign/static** | **PARTIALLY RESOLVED** | Commit `6beb08b` (WP-SECURITY-KEYMATERIAL-HARDEN) moved the KeyMaterial MASTER secrets to foreign/static memory + zeroize-on-teardown (ADR-0034 Carry-4 resolved for the master slots). Non-master/session slots remain a follow-on. |
| **5c — Zero-Copy × `rtps_protection` SHMEM cleartext** | **RESOLVED** | Commit `0308996` (WP-SECURITY-ZC-SHMEM-CLEARTEXT): no cleartext user payload in SHMEM for a secured writer (ADR-0036 Carry-10 resolved). |
| **5d — builtin-endpoint share-vs-own-key vs Connext** | **VALIDATED by the Slice-5b live interop** | Protected metatraffic (SRTPS + secure-SEDP + secure-PM) flowed both directions ours↔Connext under GOV=secure, so our builtin-endpoint keying interoperates with Connext. The residual benign `DecryptFinal` on participant-metatraffic EntityId `0x000001C1` is ADR 0040 carry #4 (not a keying mismatch). |
| **5e — per-topic `metadata_protection` selective / `pvms-bootstrap-kms` peer-loss pruning / `%dn-normalize` RFC2253 edges / `%on-secure-builtin` inner-writerId cross-check** | **OPEN — hardening follow-ons, not forced by any live peer** | None is on the P6 exit-gate path; each is a defense-in-depth / resource-cleanup / edge-case follow-on (tracked in ADR 0040 carry #5). |

**Net:** carries 4, 5c RESOLVED; 5a, 5b, 5d substantially resolved/validated by Slice 5b + the zero-alloc/keymaterial WPs; carries 1, 2, 3, 5e remain OPEN follow-ons (none Connext-blocking, none on the exit-gate path). No new large reconciliation was needed vs Connext.

---

## §M7 roadmap update

| Slice | Description | Status |
|---|---|---|
| 1 | Crypto plugin: AES256-GCM `SecuredPayload` (ADR 0031) | LANDED |
| 2a | Authentication: §8.7.2.4 PKI-DH → SharedSecret (ADR 0032) | LANDED |
| 2b-i | PSM IdentityToken + `DataHolder`/envelope codec (ADR 0033) | LANDED |
| 2b-ii + 2c | Auth manager + KxKey + crypto-token exchange (ADR 0034) | LANDED |
| 3 | AccessControl (§8.4 / §9.4) (ADR 0035) | LANDED |
| 4 | Secure discovery our-to-our (§7.3.7 / §8.5) (ADR 0036) | LANDED |
| **5 (this ADR)** | **Live Fast DDS-Security cross-vendor `auth → keyed → secure-SEDP → protected data`, both directions = the Fast-DDS half of the P6 exit gate** | **LANDED (Fast-DDS-validated)** |
| 5b | Live RTI Connext-Security secure discovery — the remaining half of the P6 exit gate (RTI Security Plugins gated) | pending |

---

## Consequences

- **NFR-SEC-POSTURE:** every reconciled parser stays bounds-checked + fail-closed (the `propagate` legacy form,
  the dh1/dh2 / CMS decode-tolerant paths, the SecureDataTag pad-skip, the secure-builtin inner-submessage
  demux all fail closed; the SecureDataTag pad-skip `check-room`s the 1–3 RX pad octets, which are consumed and
  never enter the AEAD AAD). No false-REJECT: a spec-literal peer is accepted wherever the form is
  self-describing.
- **Clean-room / IP:** Fast DDS (Apache-2.0) + Cyclone (EPL) + the OMG IDL read for understanding and
  provenance-logged (`docs/provenance.md`, T0–T11); **RTI Connext never read.**
- **FR-SEC-2:** no hand-rolled crypto — AES-256-GCM / HMAC-SHA256 / GMAC / ECDH / CMS via `dds-dare` (OpenSSL).
- **NFR-PORT:** no reader conditionals outside `dds-pal/`; Clasp + SBCL both validate, Clasp first. The known
  NFR-PORT Clasp full-suite live-socket/threading flake (`[SDP-SEC-PREFIX-ON-WIRE]` / `[SDP-BYTE-EXACT]`) wanders
  between runs and is SBCL-clean — re-run, do not chase.
- **Default-OFF / false-REJECT guard:** security-OFF and the no-governance / all-NONE paths stay byte-identical;
  the shipped Slice-1 4-aligned corpus is unchanged by the SecureDataTag fix.
- **Gates (final sweep, both impls, Clasp first):** `make build` PASS; `make test-clasp` / `make test-sbcl`
  **381** (380 + the new `run-security-secured-payload-pad-corpus-test` offline golden); `make corpus` PASS;
  `make fuzz` PASS; `make gate-hotpath` PASS; `make gate-types` PASS; `make mem` 0.0000. `make bench` is **N/A**
  (no hot-path change this slice — the secure data path is control-plane / off the measured CDR hot path).
  Full numbers in `.superpowers/sdd/task-T7capstone-report.md`.

---

## References

- Design spec: `docs/superpowers/specs/2026-06-28-dds-security-fastdds-interop-design.md`
- Plan: `docs/superpowers/plans/2026-06-28-dds-security-fastdds-interop.md`
- T0 spike: `docs/superpowers/spikes/2026-06-28-dds-security-fastdds-interop.md`
- `src/dds-security/auth/{wire,identity,handshake,keyexchange}.lisp` — the §9.3.4 Property codec + the handshake-token / c.id / dh / hash_c / c.perm / KeyMaterial reconciliations
- `src/dds-disc/{volatile-secure,secure-sedp,disc,dataplane}.lisp` — PVMS protection, the secure-SEDP reliability demux/pull, the rtps_protection enforce-gate, the secure-builtin EntityId pairing
- `src/dds-dcps/{auth-manager,crypto-manager,entities,access-control}.lisp` — the §7.4.3 Final correlation, the two-phase keyed-gate, the DW/DR token destination-endpoint-key, the user-token-at-match
- `src/dds-security/crypto/{crypto-header,submessage}.lisp` + `src/dds-security/crypto.lisp` — the empty-AAD reconcile + the SEC_BODY / SecureDataTag 4-align
- `src/dds-tests/security-test.lisp` — `run-security-secured-payload-pad-corpus-test` (the offline padded-SecuredPayload golden); `src/dds-tests/secure-interop.lisp` — `run-secure-interop-peer` (the live harness peer)
- `interop/security-secure-discovery/` — the Fast DDS-Security peer build/run + the reproducible cross-vendor run + `captures/` (the `ssd-secure-*` both-directions captures + `CAPSTONE-RESULT.md`)
- `docs/provenance.md` — every Fast DDS / Cyclone / OMG-IDL source consulted across T0–T11
- `docs/adr/0031-dds-security-crypto.md` — the two shipped crypto-wire addenda (empty-AAD; SecureDataTag 4-align) + the SEC_BODY 4-align addendum
- ADR 0036 — Slice 4 (secure discovery our-to-our; the numbered Slice-5 carries this campaign closes)
- ADR 0032 / 0033 / 0034 / 0035 — Slices 2a / 2b-i / 2b-ii+2c / 3
