# Spike — DDS-Security Secure Discovery (M7 / P6, Slice 4) — T0

> WP: `WP-DDS-SECURITY-SECURE-DISCOVERY` · Task T0 (foundational spike). Pins every wire constant the
> 13 follow-on tasks import, builds the governance/permissions fixtures, locates the Fast DDS-Security
> peer, confirms the RTI Security Plugins are absent, and records provenance. Design:
> `docs/superpowers/specs/2026-06-27-dds-security-secure-discovery-design.md` (§5/§6/§9).

## 0. Outcome

- Constants module `src/dds-security/crypto/constants.lisp` created + registered in `dds-security.asd`;
  the 8 secure builtin EntityIds co-located with the existing builtin EntityIds in
  `src/dds-rtps/discovery.lisp`. **Loads clean on Clasp and SBCL** (Clasp first).
- Governance (3 variants) + permissions fixtures authored under `interop/security-secure-discovery/pki/`,
  signed by the **reused** Slice-3 Permissions CA, **openssl-verified** (`cms` and `smime`).
- Fast DDS-Security peer **located** (source + toolchain present); the built library is currently
  `SECURITY=OFF` — exact `-DSECURITY=ON` rebuild recipe recorded (§4). RTI Security Plugins **absent**,
  check recorded (§5).
- Provenance updated with every Fast DDS source file consulted (`docs/provenance.md`).

## 1. Clean-room method + an honesty note

Every value is pinned from its OMG DDS-Security 1.1 / DDSI-RTPS 2.5 §-clause and **dual-corroborated**:
(a) read directly from the **Fast DDS** Apache-2.0 source (reading only, no code copied; files logged in
`docs/provenance.md`); (b) cross-checked against the vendor-neutral **Wireshark/tshark 4.6.6** RTPS
dissector (installed at `/Applications/Wireshark.app/Contents/MacOS/tshark` — the same version prior
slices used) and public docs. RTI Connext source is never read.

**Spec-PDF gap (finding).** `docs/specs/` holds the RTPS 2.5, DDS 1.4 DCPS, and XTypes 1.3 PDFs but **not**
the DDS-Security 1.1 PDF. The §-clause numbers below are carried from the design + brief + the four prior
in-repo security spikes (written from the spec); the *values* are corroborated by the Fast DDS direct
reads (an independent conformant implementation) + the dissector. Recommend the owner add the
DDS-Security 1.1 PDF to `docs/specs/` so later tasks can cite the clause text directly. Confidence in the
pinned values: **high** (two independent corroborations agree); confidence in exact clause sub-numbers:
**moderate** (carried, not read from an in-repo PDF).

## 2. Pinned values

### 2.1 Secure builtin EntityIds — `src/dds-rtps/discovery.lisp` (pkg `dds.rtps.discovery`)

Co-located with the existing builtin EntityIds (SPDP/SEDP/PSM/PVMS) for DRY; exported from the discovery
package. OMG clause §7.4.5 (consistent with the in-repo PVMS cite). Corroboration: Fast DDS
`include/fastdds/rtps/common/EntityId_t.hpp` lines 55-64 (`#if HAVE_SECURITY`); tshark RTPS dissector
`ENTITYID_*_SECURE_*`.

| Constant | Value | Fast DDS macro (EntityId_t.hpp) |
|---|---|---|
| `+entityid-sedp-pub-secure-writer+` | `0xff0003c2` | `ENTITYID_SEDP_BUILTIN_PUBLICATIONS_SECURE_WRITER` |
| `+entityid-sedp-pub-secure-reader+` | `0xff0003c7` | `..._PUBLICATIONS_SECURE_READER` |
| `+entityid-sedp-sub-secure-writer+` | `0xff0004c2` | `..._SUBSCRIPTIONS_SECURE_WRITER` |
| `+entityid-sedp-sub-secure-reader+` | `0xff0004c7` | `..._SUBSCRIPTIONS_SECURE_READER` |
| `+entityid-participant-message-secure-writer+` | `0xff0200c2` | `ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_SECURE_WRITER` |
| `+entityid-participant-message-secure-reader+` | `0xff0200c7` | `..._PARTICIPANT_MESSAGE_SECURE_READER` |
| `+entityid-spdp-secure-writer+` | `0xff0101c2` | `ENTITYID_SPDP_RELIABLE_BUILTIN_PARTICIPANT_SECURE_WRITER` |
| `+entityid-spdp-secure-reader+` | `0xff0101c7` | `..._PARTICIPANT_SECURE_READER` |

All eight match the design §5.4 expectation exactly. (PVMS `0xff0202c3/c4` + PSM `0x000201c3/c4` were
already in `discovery.lisp`; the §7.4.6.1 BuiltinEndpointSet bits 16-27 likewise — now exported.)

### 2.2 Secure RTPS SubmessageKind octets — `src/dds-security/crypto/constants.lisp` (pkg `dds.security`)

OMG clause §7.3.7 (DDS-Security extends the DDSI-RTPS 2.5 SubmessageKind set). Corroboration: Fast DDS
`src/cpp/rtps/security/cryptography/CryptoTypes.h` lines 31-41; tshark dissector `SUBMESSAGE_SEC_*`.

| Constant | Value | Fast DDS (CryptoTypes.h) |
|---|---|---|
| `+submessage-sec-body+` | `0x30` | `_SecureBodySubmessage_` |
| `+submessage-sec-prefix+` | `0x31` | `_SEC_PREFIX_` |
| `+submessage-sec-postfix+` | `0x32` | `_SEC_POSTFIX_` |
| `+submessage-srtps-prefix+` | `0x33` | `_SRTPS_PREFIX_` |
| `+submessage-srtps-postfix+` | `0x34` | `_SRTPS_POSTFIX_` |

Placement: same 1-octet submessageId space as the `dds.rtps` `+submsg-*+` family (`message.lisp`), but
pinned in the crypto plugin (the codec's primary consumer) so the codec does not pull a
`dds-security -> dds-rtps` dependency, preserving the deliberate `dds-security.asd` separation.

### 2.3 KDF labels

| Constant | Value | Home | Clause / corroboration |
|---|---|---|---|
| `+kdf-label-session-receiver-key+` (**new**) | `"SessionReceiverKey"` | `crypto/constants.lisp` | §9.5.3.3.4.3; Fast DDS `AESGCMGMAC_Transform.cpp:1481` (`const char receiver_seq[] = "SessionReceiverKey"`) |
| `+session-key-id-string+` (**reused**) | `"SessionKey"` | `crypto.lisp` (Slice 1) | §9.5.3.3.4.2; Fast DDS `AESGCMGMAC_Transform.cpp:1480` (`const char seq[] = "SessionKey"`) |
| `+session-key-counter-string+` (**reused**) | `"0001"` | `crypto.lisp` (Slice 1) | §9.5.3.3.4.2 Table 70 |

The receiver-specific session key (origin-auth) is
`HMAC-SHA256(master_receiver_specific_key, "SessionReceiverKey" || master_salt || session_id || "0001")`.
The session-key label is reused, **not** re-pinned (DRY) — see §3.

### 2.4 Crypto-token `message_class_id`s — **already pinned (reused, not duplicated)**

`src/dds-security/auth/keyexchange.lisp` already pins all three, corroborated against Fast DDS
`CryptoTypes.h` lines 27-29 (`GMCLASSID_SECURITY_*_CRYPTO_TOKENS`):

| Existing constant | Value |
|---|---|
| `+gm-participant-crypto-tokens+` | `"dds.sec.participant_crypto_tokens"` |
| `+gm-datawriter-crypto-tokens+` | `"dds.sec.datawriter_crypto_tokens"` |
| `+gm-datareader-crypto-tokens+` | `"dds.sec.datareader_crypto_tokens"` |

The brief's suggested names (`+crypto-token-class-participant+` …) would have been new symbols holding the
identical literals — a DRY violation. **Decision: reuse the `+gm-*-crypto-tokens+` constants.** Later tasks
import those. `crypto/constants.lisp` cross-references them in its header so the module remains the
documented index. (Also reused, not re-pinned: `+crypto-token-class-id+` `"DDS:Crypto:AES_GCM_GMAC"` and
`+crypto-token-keymat-prop+` `"dds.cryp.keymat"`.)

### 2.5 Governance ProtectionKind enum + on-wire encoding — `crypto/constants.lisp`

OMG clause §9.4.1.2 / Annex B `dds_governance.xsd`. Corroboration: Fast DDS
`src/cpp/security/accesscontrol/GovernanceParser.cpp` lines 48-52 (the `ProtectionKind*_str` table) and
lines 35-46 (the element names).

- `+protection-kinds+` = `(:none :sign :encrypt :sign-with-origin-auth :encrypt-with-origin-auth)`
  (ProtectionKind, 5 values — domain-rule kinds: discovery / liveliness / rtps).
- `+basic-protection-kinds+` = `(:none :sign :encrypt)` (BasicProtectionKind, 3 values — per-topic
  metadata / data kinds; no origin-auth).
- `+protection-kind-xsd-strings+` = the keyword↔XSD-token alist:

| Keyword | XSD on-wire token (GovernanceParser.cpp) |
|---|---|
| `:none` | `NONE` |
| `:sign` | `SIGN` |
| `:encrypt` | `ENCRYPT` |
| `:sign-with-origin-auth` | `SIGN_WITH_ORIGIN_AUTHENTICATION` |
| `:encrypt-with-origin-auth` | `ENCRYPT_WITH_ORIGIN_AUTHENTICATION` |

The "on-wire encoding" of a ProtectionKind is the XSD enumeration token carried in the signed Governance
XML; there is no separate RTPS-wire enum (the local plugin maps the token to the protection it applies).
Governance element names confirmed: `discovery_protection_kind`, `liveliness_protection_kind`,
`rtps_protection_kind`, per-topic `enable_discovery_protection` / `enable_liveliness_protection`,
`metadata_protection_kind`, `data_protection_kind` — all match the design §7.1.

### 2.6 KeyMaterial receiver fields — **no struct change needed (confirmed)**

`key-material` (`src/dds-security/key-material.lisp:23`) already carries `receiver-specific-key-id` +
`master-receiver-specific-key` (added in Auth-KEYX T3, §9.5.2 Table 65). Origin authentication
(T3) populates them; **no struct change is required** — confirmed by inspection.

## 3. DRY / placement decisions (stated for the report)

1. **Secure builtin EntityIds → `discovery.lisp`** (not `crypto/constants.lisp`): kept with the existing
   PSM/PVMS/SEDP builtin EntityIds; consumed by the dds-dcps wiring layer (which already depends on
   dds-rtps). Exported from `dds.rtps.discovery` (the pre-existing PVMS pair + §7.4.6.1 bits 16-27 +
   `+pid-permissions-token+`, which the slice needs, were exported alongside).
2. **Secure submessage kinds → `crypto/constants.lisp`** (not `message.lisp`): kept in the codec's
   package to avoid a `dds-security -> dds-rtps` dependency.
3. **Token `message_class_id`s reused** from `keyexchange.lisp` (`+gm-*-crypto-tokens+`), not re-pinned.
4. **Session-key KDF label reused** (`+session-key-id-string+`), not aliased; only the *new*
   `+kdf-label-session-receiver-key+` is pinned. (Brief's `+kdf-label-session-key+` intentionally not
   created — it would be a second name for one literal.)
5. **ASDF**: new module `crypto-plugin` with `:pathname "crypto"` (the ASDF name avoids clashing with the
   existing `(:file "crypto")` sibling); `crypto/constants.lisp` is its first file. T1+ append
   `crypto-header.lisp` / `submessage.lisp` / `rtps-message.lisp` to this module.

## 4. Fast DDS-Security peer (T12 live oracle)

**Located.** Source + toolchain present; a security-enabled build is **not yet** built.

- Source tree: `/Users/frgo/gbt Dropbox/gbt/projects/fastdds/src/fastdds` (security sources under
  `src/cpp/security/` and `src/cpp/rtps/security/`).
- Built library: `/Users/frgo/gbt Dropbox/gbt/projects/fastdds/install/lib/libfastdds.3.6.1.0.dylib`
  — but `CMakeCache.txt` has **`SECURITY:BOOL=OFF`** and `COMPILE_EXAMPLES:BOOL=OFF`. No `SECURITY=ON`
  cache exists anywhere under the tree.
- Prerequisites present: OpenSSL **3.6.2** (`/opt/homebrew/opt/openssl@3`, found by the existing cache),
  Fast CDR 2.3.5 + foonathan_memory 0.7.4 (in `install/lib/`), cmake 4.3.3, system `cc`/`c++`. So a
  headless rebuild is feasible in this environment (Fast DDS is a library + headless CLI examples; no GUI).
- The T12 peer source: `examples/cpp/security/` (a headless HelloWorld secure pub/sub with `CLIParser.hpp`
  + a `certs/` dir).

**Rebuild recipe (headless, security ON):**
```
cd "/Users/frgo/gbt Dropbox/gbt/projects/fastdds/src/fastdds/build"
cmake .. -DSECURITY=ON -DCOMPILE_EXAMPLES=ON -DCMAKE_BUILD_TYPE=Release \
         -DOPENSSL_ROOT_DIR=/opt/homebrew/opt/openssl@3
cmake --build . --target install -j
# headless secure peer then under build/examples/cpp/security/ (run pub/sub with its --security CLI args).
```
T0 does **not** run interop (deferred to T12 per the design); it confirms the peer is buildable here and
records how to invoke it.

## 5. RTI Connext Security Plugins — ABSENT (check recorded)

RTI Connext itself is installed at `/Applications/rti_connext_dds-7.3.1/`. The **Security Plugins** are a
separate add-on and are **not installed**:
- `/Applications/rti_connext_dds-7.3.1/lib/arm64Darwin20clang12.0/` contains 116 libs (ndds*, rtirouting*,
  …) but **no `libnddssecurity*`** and nothing matching `*security*`.
Therefore live Connext-Security interop is out of scope this slice (Slice-5 P6 exit gate, per the design
§2/§12). Connext is verified statically: OMG clause + tshark RTPS-security dissector + byte-exact corpus.

## 6. Fixtures — `interop/security-secure-discovery/`

Generated by `gen-test-fixtures.sh`, which **reuses** the Slice-3 Permissions CA
(`../security-access-control/pki/perm-ca-{cert,key}.pem`) and the Slice-2 Identity CA
(`../security-auth/pki/ca/ca-cert.pem`) — it does not regenerate them. Signed with
`openssl smime -sign -outform PEM -nodetach -md sha256` (DDS-Security 1.1 §9.4.1.1: embedded/opaque CMS).

| Fixture | discovery / liveliness / rtps | per-topic enable + metadata/data |
|---|---|---|
| `governance-secure.{xml,p7s}` | `ENCRYPT` / `SIGN` / `ENCRYPT` | enable=true; metadata=ENCRYPT, data=ENCRYPT |
| `governance-origin-auth.{xml,p7s}` | `ENCRYPT_WITH_ORIGIN_AUTHENTICATION` / `SIGN_WITH_ORIGIN_AUTHENTICATION` / `ENCRYPT_WITH_ORIGIN_AUTHENTICATION` | enable=true; metadata=ENCRYPT, data=ENCRYPT |
| `governance-none.{xml,p7s}` | `NONE` / `NONE` / `NONE` | enable=false; metadata=NONE, data=NONE (security-OFF byte-identical baseline) |
| `permissions.{xml,p7s}` | — | 4 subjects (EC/ECB/RSA/RSAB), allow Square pub+sub, deny Circle, default DENY |

**Verification (independent of the generator):**
- `openssl cms -verify -CAfile perm-ca-cert.pem -no-CAfile -no-CApath -no-CAstore` → all four recover content.
- `openssl smime -verify -in governance-origin-auth.p7s -CAfile perm-ca-cert.pem` → `Verification successful`,
  recovered XML carries the two `*_WITH_ORIGIN_AUTHENTICATION` tokens intact.
- Signer cert = `CN=TestPermissionsCA` (the reused CA; no new CA created).

## 7. Open points / carries

- **KEYX per-writer KM migration (design §6.4).** Auth-KEYX currently carries the per-writer KeyMaterial
  under `+gm-participant-crypto-tokens+`. The conformant home for a per-DataWriter KM is
  `+gm-datawriter-crypto-tokens+`. T0 confirms both class_ids are pinned; the actual migration (and moving
  KEYX's tests) is its own increment in T8, not done here.
- **Builtin-endpoint share-vs-own-key** (design §6.6) — resolved against the live Fast DDS peer at T12;
  any Connext divergence is a Slice-5 item.
- **DDS-Security 1.1 PDF not in `docs/specs/`** (§1) — recommend adding it.
- Live secure-capture tshark confirmation of the submessage kinds + secure EntityIds is folded into T12
  (the live Fast DDS-Security run) — T0 corroborated against the installed dissector's known constants +
  Fast DDS source, not a fresh secure capture.

## 8. Load verification

```
# Clasp (first): ./scripts/with-clasp.sh + ql:quickload :dds-rtps :dds-security
CLASP-LOAD-OK  srtps-postfix=0x34  sedp-pub-secure-w=0xFF0003C2  recv-key-label="SessionReceiverKey"
               protection-kinds=(:none :sign :encrypt :sign-with-origin-auth :encrypt-with-origin-auth)
# SBCL: ./scripts/with-sbcl.sh + ql:quickload :dds-rtps :dds-security
SBCL-LOAD-OK   sec-body=0x30 sec-prefix=0x31 srtps-prefix=0x33  spdp-secure-r=0xFF0101C7
               pm-secure-w=0xFF0200C2  sedp-sub-secure-w=0xFF0004C2  basic-pk=(:none :sign :encrypt)
               xsd-enc="ENCRYPT_WITH_ORIGIN_AUTHENTICATION"
```
Both impls load clean, no warnings-as-errors.
