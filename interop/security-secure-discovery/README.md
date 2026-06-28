# interop/security-secure-discovery — fixtures + cross-vendor peer notes (M7/P6 Slice 4)

Test fixtures and interop notes for `WP-DDS-SECURITY-SECURE-DISCOVERY` (DDS-Security 1.1 secure
discovery: submessage protection, whole-RTPS-message protection, origin-auth, reliable PVMS, governance
protection-kinds, secure builtin endpoints). Spike:
`docs/superpowers/spikes/2026-06-27-dds-security-secure-discovery.md`.

## PKI / governance / permissions fixtures (`pki/`)

Generated and self-verified by `gen-test-fixtures.sh`. The script **reuses** the existing test CAs
(it never regenerates them):

- **Permissions CA** — `../security-access-control/pki/perm-ca-{cert,key}.pem` (EC P-256). Signs the
  governance + permissions documents.
- **Identity CA** — `../security-auth/pki/ca/ca-cert.pem` (EC P-256). Issued the participant identity
  certs whose DNs are the permissions-grant subjects (`TestParticipant{EC,ECB,RSA,RSAB}`).

Run the prerequisite generators once if the CAs are missing:
`bash ../security-access-control/gen-test-permissions.sh` and `bash ../security-auth/gen-test-pki.sh`.

Regenerate the secure-discovery fixtures:
```
bash interop/security-secure-discovery/gen-test-fixtures.sh
```

Artifacts (XML plaintext + `.p7s` CMS/S-MIME PEM signed, embedded/opaque, sha256 — DDS-Security 1.1
§9.4.1.1):

| File | Governance protection kinds (discovery / liveliness / rtps) |
|---|---|
| `governance-secure.{xml,p7s}` | ENCRYPT / SIGN / ENCRYPT; per-topic `enable_discovery_protection=true`, metadata=ENCRYPT, data=ENCRYPT |
| `governance-origin-auth.{xml,p7s}` | ENCRYPT_WITH_ORIGIN_AUTHENTICATION / SIGN_WITH_ORIGIN_AUTHENTICATION / ENCRYPT_WITH_ORIGIN_AUTHENTICATION |
| `governance-none.{xml,p7s}` | NONE / NONE / NONE — the security-OFF byte-identical baseline (false-REJECT guard) |
| `permissions.{xml,p7s}` | 4 subjects: allow `Square` pub+sub on domain 0, deny `Circle`, default DENY |

The throwaway test keys are committed intentionally; they are **not** production credentials.

Verify any artifact (no system trust store):
```
openssl cms  -verify -in pki/governance-secure.p7s -inform PEM \
  -CAfile ../security-access-control/pki/perm-ca-cert.pem -no-CAfile -no-CApath -no-CAstore
openssl smime -verify -in pki/governance-origin-auth.p7s -inform PEM \
  -CAfile ../security-access-control/pki/perm-ca-cert.pem
```

## Cross-vendor peers

### Fast DDS-Security (live oracle — T12)

eProsima Fast DDS source + toolchain are present at
`/Users/frgo/gbt Dropbox/gbt/projects/fastdds`. The built library is currently `SECURITY=OFF`. Build a
headless security-enabled peer (OpenSSL 3.6.2, Fast CDR, foonathan_memory, cmake all present):
```
cd "/Users/frgo/gbt Dropbox/gbt/projects/fastdds/src/fastdds/build"
cmake .. -DSECURITY=ON -DCOMPILE_EXAMPLES=ON -DCMAKE_BUILD_TYPE=Release \
         -DOPENSSL_ROOT_DIR=/opt/homebrew/opt/openssl@3
cmake --build . --target install -j
```
The headless secure HelloWorld pub/sub example (`examples/cpp/security/`, with `CLIParser.hpp` + `certs/`)
is the T12 cross-vendor secure-discovery peer. T0 does not run interop.

### RTI Connext-Security (static only — Slice 5)

RTI Connext 7.3.1 is installed (`/Applications/rti_connext_dds-7.3.1/`) but the **Security Plugins are
absent** (no `libnddssecurity*` in `lib/arm64Darwin20clang12.0/`). Connext-Security is verified statically
this slice (OMG clause + tshark 4.6.6 RTPS-security dissector + byte-exact corpus); live Connext-Security
interop is the Slice-5 P6 exit gate.

## T12 — LIVE Fast DDS-Security cross-vendor secure-discovery result (2026-06-28)

A **SECURITY=ON** eProsima Fast DDS v3.6.1 peer was built (`docs/provenance.md`; spike §4 recipe) and run
live against our stack over UDP loopback sharing this repo's reused Identity-CA / Permissions-CA / Governance.

**Harness.** `run-fastdds-interop.sh [GOV] [SECS]` stands up the Fast DDS `security` example
(`examples/cpp/security`, topic `HelloWorldTopic`/`HelloWorld`) + our `dds.tests:run-secure-interop-peer`
(`src/dds-tests/secure-interop.lisp`) on domain 0, both directions, with tshark capture.
`fastdds/gen-fastdds-fixtures.sh` emits the Fast DDS-format fixtures; `fastdds/secure_profile.xml` points
Fast DDS at our PKI via `${SSD_*}` env expansion. NOT run by CI (external toolchain).

**Result: build + discovery achieved cross-vendor; the §8.7 auth handshake is REJECTED at the remote
IdentityToken** (both directions: our peer `discovered=2`, auth state `REJECTED`, `keyed=NIL`; Fast DDS
initialises fully with our PKI). Captures: `captures/ssd-none-{ours2fast,fast2ours}.pcapng` + `*-ours.log`.

### Divergences found + fixed conformant (verified our-to-our: SBCL 377 / Clasp 377, all gates green)

1. **PSM SerializedPayload encapsulation header** (a brief candidate). Our ParticipantStatelessMessage sent
   the §7.4.4 envelope with NO 4-octet CDR encapsulation header; a conformant peer prepends/strips the
   RTPS 2.5 §10.2 `00 01 00 00` (Fast DDS `SecurityManager.cpp:933-938`). Fixed symmetric in
   `src/dds-disc/stateless-message.lisp` (`%psm-encapsulate` + strip-on-receive).
2. **Governance XML structure.** Our fixture+parser used a non-conformant `<dds><policies><domain_access_rules>`
   wrapper; the OMG schema + Fast DDS (`GovernanceParser.cpp:73-135`) require `<domain_access_rules>` as a
   DIRECT child of `<dds>`. Fixed conformant in `gen-test-fixtures.sh`; parser made tolerant of both
   (`access-control/governance.lisp`, no false-REJECT).
3. **Subject-name DN serialization.** We matched the cert subject (OpenSSL oneline `/CN=.../O=.../C=DE`) by
   `string=`; Fast DDS uses RFC2253 (`Permissions.cpp:632`). Added the serialization-insensitive `%dn-equal`
   + `permissions-grant-for` (`access-control/permissions.lisp`), routed all three subject-match sites through
   it, and emit RFC2253 in `permissions-hello.xml`.
4. **Permissions/governance S/MIME container.** Fast DDS needs multipart/signed with `Content-Type: text/plain`
   (`PKCS7_TEXT`, `Permissions.cpp:408`), not PEM PKCS7. `gen-fastdds-fixtures.sh` emits the MIME form.
   Plus a loopback-reachability `:port` on `create-participant` + Fast DDS `initialPeersList` (macOS multi-NIC).

### PRIMARY RESIDUAL — the handshake blocker (Slice-5 / dedicated WP)

**5. Token `Property`/`BinaryProperty` `propagate` byte on the wire.** Fast DDS serialises a Token property as
`{name,value}` only (`CDRMessage.cpp:828-906`); `propagate` is a local include-filter, never on the wire. Our
entire DDS-Security token codec (`auth/identity.lisp` `%cdr-property-le`, `auth/wire.lisp`
`%cdr-binary-property-le`, `auth/handshake.lisp` `%cdr-binary-property-be` + their parsers) writes/reads a
spurious 4-octet `propagate` field per property — misaligning EVERY cross-vendor token (IdentityToken,
HandshakeRequest/Reply/Final, CryptoTokens, PermissionsToken). This is why the handshake rejects at the remote
IdentityToken. The spec-conformant fix (drop the propagate field across the codec) is slice-wide — it also
requires regenerating the entire DDS-Security token byte-exact corpus (currently pinned WITH the propagate
byte, i.e. never validated against a real peer) — so it is its own WP, not landed under T12.

### Candidate divergences NOT YET REACHED (behind #5; carried to Slice 5)

session_id base derivation (T8), metatraffic rtps-wrapping (T10), SIGN GMAC AAD byte-span (T2), SIGN
4-alignment (T4), PSM payload encapsulation for the §8.7 PSM (the auth-2b-i carry — addressed by fix #1 above),
reliable pull for secure-SEDP/PVMS (T7/T9). All sit AFTER the auth handshake, which #5 blocks — they cannot be
exercised live until #5 lands. Verified statically this slice (byte-exact secure-submessage corpus in the test
suite: `run-security-{submessage,crypto-header,rtps-message}-corpus-test`).

### Static verification note

The vendor-neutral tshark RTPS-security dissector could NOT validate the captures in this environment: tshark
here does not dissect the macOS lo0 `NULL/Loopback` link-layer (IP/UDP shows empty; tcpdump confirms the
traffic is well-formed RTPS on lo0). Our secure-submessage byte-exactness is therefore carried by the in-suite
byte-exact corpus, not a live dissector pass. Live Connext-Security stays the Slice-5 P6 exit gate.
