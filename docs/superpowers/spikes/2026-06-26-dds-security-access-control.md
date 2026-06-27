# Spike: DDS-Security 1.1 AccessControl — Governance/Permissions XSD + CMS format + XML lib + fixtures
**Date:** 2026-06-26
**WP:** WP-DDS-SECURITY-ACCESS-CONTROL T0
**Status:** DONE

---

## Purpose

Pin every format constant and library choice that T1–T5 depend on, from the OMG DDS-Security 1.1
specification + OpenSSL headers + live smoke-loads. Confirms the design holds or flags re-planning.

---

## Step 1 — Governance + Permissions XSD element set

**Source:** OMG DDS-Security 1.1 formal/19-04-03 §9.4.1.2.3 (Governance), §9.4.1.3.2 (Permissions),
Annex B (dds_governance.xsd, dds_permissions.xsd).
XSD schema location: `https://www.omg.org/spec/DDS-Security/20190401/dds_{governance,permissions}.xsd`.

### Governance document (`dds_governance.xsd`)

Path to the slice-scope elements (§9.4.1.2.3 Tables 30–34, Annex B.1):

```
<dds>
  <policies>
    <domain_access_rules>
      <domain_rule>
        <domains> <id>N</id> | <id_range><min>N</min><max>M</max></id_range> </domains>

        <!-- §9.4.1.2.3 Table 30 — domain-level access controls -->
        <allow_unauthenticated_participants>false|true</allow_unauthenticated_participants>
        <enable_join_access_control>false|true</enable_join_access_control>

        <!-- §9.4.1.2.3 Table 31 — protection kinds (NONE for this slice) -->
        <discovery_protection_kind>NONE|SIGN|ENCRYPT|SIGN_WITH_ORIGIN_AUTHENTICATION|ENCRYPT_WITH_ORIGIN_AUTHENTICATION</discovery_protection_kind>
        <liveliness_protection_kind>... (same enum)</liveliness_protection_kind>
        <rtps_protection_kind>... (same enum)</rtps_protection_kind>

        <!-- §9.4.1.2.3 Table 32 — per-topic rules -->
        <topic_access_rules>
          <topic_rule>
            <topic_expression>*</topic_expression>   <!-- POSIX fnmatch pattern -->
            <enable_discovery_protection>false|true</enable_discovery_protection>
            <enable_liveliness_protection>false|true</enable_liveliness_protection>
            <enable_read_access_control>false|true</enable_read_access_control>
            <enable_write_access_control>false|true</enable_write_access_control>
            <metadata_protection_kind>NONE|SIGN|ENCRYPT|...</metadata_protection_kind>
            <data_protection_kind>NONE|SIGN|ENCRYPT|...</data_protection_kind>
          </topic_rule>
        </topic_access_rules>
      </domain_rule>
    </domain_access_rules>
  </policies>
</dds>
```

**Slice-scope subset** (T1–T5 must enforce):
- `allow_unauthenticated_participants` — if false: participants without a valid auth token MUST be rejected at check_create_participant (§9.4.1.2.3 Table 30).
- `enable_join_access_control` — if true: the `check_create_participant` check is active for the domain (§9.4.1.2.3 Table 30).
- `topic_rule/enable_read_access_control` — if true: `check_create_datareader` AND `check_remote_datawriter` enforce topic-level permissions for subscribe (§9.4.1.2.3 Table 32).
- `topic_rule/enable_write_access_control` — if true: `check_create_datawriter` AND `check_remote_datareader` enforce topic-level permissions for publish (§9.4.1.2.3 Table 32).
- `topic_rule/topic_expression` — POSIX fnmatch glob matching the topic name; first matching rule wins (§9.4.1.2.3 §9.4.1.2.4 "Rules are evaluated in order; the first matching rule applies.").

### Permissions document (`dds_permissions.xsd`)

Path to the slice-scope elements (§9.4.1.3.2 Tables 35–41, Annex B.2):

```
<dds>
  <permissions>
    <grant name="friendly-name">
      <!-- §9.4.1.3.2.3 — DN matching the identity cert Subject -->
      <subject_name>/CN=Foo/O=Bar/C=XX</subject_name>

      <!-- §9.4.1.3.2.4 — ISO 8601 date-time -->
      <validity>
        <not_before>2026-01-01T00:00:00</not_before>
        <not_after>2036-01-01T00:00:00</not_after>
      </validity>

      <!-- §9.4.1.3.2.5 — allow_rule: allows matching pub/sub -->
      <allow_rule>
        <domains><id>0</id></domains>
        <publish>
          <topics><topic>Square</topic></topics>   <!-- fnmatch, §9.4.1.3.2.7 -->
          <!-- optional: <partitions><partition>*</partition></partitions> -->
        </publish>
        <subscribe>
          <topics><topic>Square</topic></topics>
        </subscribe>
      </allow_rule>

      <!-- §9.4.1.3.2.6 — deny_rule: denies matching pub/sub -->
      <deny_rule>
        <domains><id>0</id></domains>
        <publish><topics><topic>Circle</topic></topics></publish>
        <subscribe><topics><topic>Circle</topic></topics></subscribe>
      </deny_rule>

      <!-- §9.4.1.3.2.9 — fallback if no rule matches -->
      <default>DENY</default>   <!-- ALLOW|DENY -->
    </grant>
  </permissions>
</dds>
```

**Wildcard rule** (§9.4.1.3.2.7, §9.4.1.2.4): topic names use POSIX `fnmatch(3)` patterns:
`*` matches any string (incl. empty, not crossing `/`), `?` matches any single char, `[...]` is a
character class. The matching library function is `fnmatch(pattern, topic_name, 0)` (no flags).
A bare `*` matches every topic name.

**subject_name format** (§9.4.1.3.2.3): the spec says "the printable string representation of the
distinguished name components." Our implementation uses `X509_NAME_oneline` (OpenSSL slash-separated:
`/CN=.../O=.../C=...`), matching what `dds.dare:x509-subject-name` returns. Cross-vendor interop
(Slice 5) may require RFC 2253 format — flagged NEEDS-VERIFICATION.

**Rule evaluation order** (§9.4.1.3.2.10): allow_rule and deny_rule entries are evaluated in
document order; the first matching rule (by domain + topic + operation) determines the outcome.
If no rule matches, `<default>` applies. For our fixtures: allow Square, deny Circle, default DENY.

---

## Step 2 — S/MIME-CMS signing format

**Source:** OMG DDS-Security 1.1 §9.4.1.1 "Signing the Governance Document and Permissions Document";
OpenSSL 3.6.2 headers `/opt/homebrew/opt/openssl@3/include/openssl/cms.h` (lines cited below).

### §9.4.1.1 wire-level requirements (pinned)

- Format: CMS RFC 5652 SignedData, wrapped in S/MIME (RFC 5751).
- Digest algorithm: SHA-256 (§9.4.1.1 mandates SHA-256 minimum).
- Content embedding: **opaque (non-detached)** — the plaintext XML is embedded inside the
  CMS SignedData `encapContentInfo.eContent` field, NOT supplied as a separate detached stream.
- On-disk PEM headers: **`-----BEGIN PKCS7-----`** / **`-----END PKCS7-----`**
  (§9.4.1.1 explicit; produced by `openssl smime -sign -outform PEM`).

### Sign invocation (reproducible test fixture)

```bash
openssl smime -sign \
  -signer perm-ca-cert.pem \
  -inkey  perm-ca-key.pem \
  -in     document.xml \
  -out    document.p7s \
  -outform PEM \
  -nodetach \
  -md sha256
```

- `-nodetach` = opaque signing (embedded content, required by DDS-Security).
- Output begins `-----BEGIN PKCS7-----`, ends `-----END PKCS7-----`.
- The signer cert is embedded in the signed message (no `-nocerts`): `SMIME_read_CMS`
  finds it automatically; chain validates against the Permissions CA store.

### Verify invocation (test round-trip)

```bash
openssl smime -verify \
  -in document.p7s \
  -inform PEM \
  -CAfile perm-ca-cert.pem \
  -no-CAfile -no-CApath -no-CAstore
```

### C API — pinned signatures (OpenSSL 3.6.2 cms.h)

```c
/* cms.h line 226 — parse PEM S/MIME wrapper, return CMS_ContentInfo + optional content BIO */
CMS_ContentInfo *SMIME_read_CMS(BIO *bio, BIO **bcont);
/* bcont: NULL for opaque signing (content embedded), non-NULL for detached.
   For our fixtures: bcont = NULL after call (embedded content). */

/* cms.h lines 276-277 — verify SignedData; returns 1 on success, 0 on failure */
int CMS_verify(CMS_ContentInfo *cms,
               STACK_OF(X509) *certs,  /* NULL: use certs embedded in message */
               X509_STORE *store,      /* Permissions CA trust store */
               BIO *dcont,             /* detached data BIO (NULL for embedded) */
               BIO *out,               /* BIO to write recovered plaintext into */
               unsigned int flags);    /* 0 = full verify: chain + content + attr sigs */

/* cms.h line 283 — extract signer certs after successful verify */
STACK_OF(X509) *CMS_get0_signers(CMS_ContentInfo *cms);
```

**Flag constants** (cms.h lines 180–200, OpenSSL 3.6.2):
- `CMS_NO_CONTENT_VERIFY 0x4` — skip content sig check (do NOT set).
- `CMS_NO_ATTR_VERIFY 0x8` — skip signed-attribute sig check (do NOT set).
- `CMS_NOINTERN 0x10` — do not search the message for signer cert (optional; not set = look in message first).
- `CMS_NO_SIGNER_CERT_VERIFY 0x20` = `CMS_NOVERIFY` — skip chain verify (do NOT set; we DO chain verify).
- `CMS_NOCRL 0x2000` — ignore CRLs (set if no CRL distribution; our test fixtures have no CRL).

**Binding call sequence for `dds.dare:cms-verify`**:
1. `BIO_new_mem_buf(pem_bytes, pem_len)` — load signed doc into a mem BIO.
2. `SMIME_read_CMS(bio_in, &bcont)` — parse PEM PKCS7 → `CMS_ContentInfo*`; `bcont = NULL` for embedded.
3. `BIO_new(BIO_s_mem())` — create output BIO for recovered content.
4. `CMS_verify(cms, NULL, ca_store, bcont, bio_out, 0)` — full verify; 1 = success.
5. `BIO_get_mem_data(bio_out, &buf)` → recovered XML octets.
6. Cleanup: `BIO_free(bio_in)`, `BIO_free(bio_out)`, `CMS_ContentInfo_free(cms)`.
7. On any failure at steps 2–5: return nil (fail-closed, no partial content).

**Correction to design doc §2:** The design doc listed `d2i_CMS_ContentInfo` as the parse call.
`d2i_CMS_ContentInfo` parses raw DER. Our signed documents are PEM S/MIME (`BEGIN PKCS7`);
the correct parse call is `SMIME_read_CMS`. The design doc should be updated in T1.

---

## Step 3 — XML library (confirmed working on BOTH Clasp and SBCL)

### Smoke-load results

**SBCL (sbcl --noinform):**
```
$ scripts/with-sbcl.sh \
    --eval '(ql:quickload :xmls :silent t)' \
    --eval '(format t "xmls loaded~%")' \
    --eval '(let ((tree (xmls:parse "<foo bar=\"baz\"><child>text</child></foo>")))
             (format t "parse OK: ~s~%" tree))' \
    --eval '(uiop:quit 0)'
xmls loaded
parse OK: #S(XMLS:NODE :NAME "foo" :NS NIL :ATTRS (("bar" "baz"))
             :CHILDREN (#S(XMLS:NODE :NAME "child" :NS NIL :ATTRS NIL :CHILDREN ("text"))))
```

**Clasp (clasp-boehmprecise-2.7.0-892-g7eb263ba3):**
```
$ scripts/with-clasp.sh \
    --eval '(ql:quickload :xmls :silent t)' \
    --eval '(format t "xmls loaded~%")' \
    --eval '(let ((tree (xmls:parse "<foo bar=\"baz\"><child>text</child></foo>")))
             (format t "parse OK: ~s~%" tree))' \
    --eval '(uiop:quit 0)'
Starting clasp-boehmprecise-2.7.0-892-g7eb263ba3 from base image
xmls loaded
parse OK: #S(XMLS:NODE :NAME "foo" :NS NIL :ATTRS (("bar" "baz"))
             :CHILDREN (#S(XMLS:NODE :NAME "child" :NS NIL :ATTRS NIL :CHILDREN ("text"))))
```

Both `cxml` (20250622-git) and `xmls` (3.3.0) load cleanly on both implementations.

### Decision: pin `xmls`

| Library | Clasp | SBCL | Transitive deps | Quicklisp dist |
|---------|-------|------|-----------------|----------------|
| `cxml`  | OK    | OK   | closure-common, trivial-gray-streams, babel, trivial-features (4 systems) | 20250622-git |
| `xmls`  | OK    | OK   | none (zero) | 3.3.0 |

`xmls` selected: zero transitive dependencies (simpler SBOM, simpler security surface), single .lisp
file, pure Common Lisp, no foreign code, passes the Clasp+SBCL-both-validate directive identically.
`cxml` works but adds 4 transitive systems for no functional gain (we need element-tree access, not
full DOM or validation).

`xmls` tree structure: `(XMLS:NODE :NAME string :NS string-or-nil :ATTRS alist :CHILDREN list)`.
Element children are NODE structs; text-node children are strings.

SBOM entry for `xmls` (to add in `sbom.spdx.json`):

```
spdxId: SPDXRef-xmls
name: xmls
version: 3.3.0
supplier: Organization: Shannon Spires (xmls)
downloadLocation: https://github.com/rpgoldman/xmls
licenseConcluded: MIT
relationship: SPDXRef-dds-security DYNAMIC_LINK SPDXRef-xmls
```

---

## Step 4 — Signed test fixtures

**Location:** `interop/security-access-control/pki/`
**Generator script:** `interop/security-access-control/gen-test-permissions.sh` (reproducible, idempotent)

**Files generated:**
| File | Description |
|------|-------------|
| `perm-ca-cert.pem` | Throwaway Permissions CA (EC P-256, self-signed, CN=TestPermissionsCA, 10yr) |
| `perm-ca-key.pem` | Permissions CA private key (throwaway test key, committed intentionally) |
| `governance.xml` | Governance document (plaintext): domain 0, unauthenticated=false, join-AC=true, topic_rule `*` enable read+write AC, all protection kinds NONE |
| `governance.p7s` | governance.xml signed by Permissions CA (PEM PKCS7, embedded, SHA-256) |
| `permissions.xml` | Permissions document (plaintext): 4 grants (TestParticipantEC, TestParticipantECB, TestParticipantRSA, TestParticipantRSAB); allow Square pub+sub; deny Circle pub+sub; default DENY |
| `permissions.p7s` | permissions.xml signed by Permissions CA (PEM PKCS7, embedded, SHA-256) |

**Subject names in permissions.xml** match `dds.dare:x509-subject-name` (OpenSSL `X509_NAME_oneline`
format) read from `interop/security-auth/pki`:
- `/CN=TestParticipantEC/O=DDS-Test/C=DE`
- `/CN=TestParticipantECB/O=DDS-Test/C=DE`
- `/CN=TestParticipantRSA/O=DDS-Test/C=DE`
- `/CN=TestParticipantRSAB/O=DDS-Test/C=DE`

**Self-verification output (run of gen-test-permissions.sh):**
```
Generated Permissions CA: .../pki/perm-ca-cert.pem
Generated .../pki/governance.xml
Generated .../pki/permissions.xml
Signed  .../pki/governance.p7s
Signed  .../pki/permissions.p7s
Verified governance.p7s: 1364 chars of recovered content
Verified permissions.p7s: 3192 chars of recovered content
All fixtures generated and self-verified in .../pki/
```

**Tamper detection verified:**
A CMS byte-flip in governance.p7s causes:
```
Verification failure
PKCS7 routines:PKCS7_signatureVerify:digest failure
PKCS7 routines:PKCS7_verify:signature failure
```

---

## Step 5 — Assumption confirmations + NEEDS-VERIFICATION

### Confirmed assumptions

1. **Manager-in-dcps:** The AccessControl manager (`dp-access-state`, `%install-access-control`,
   `%participant-permissions-gate`) lives in `src/dds-dcps/access-control.lisp`, parallel to
   `src/dds-dcps/auth-manager.lisp`. Confirmed by design doc §3/§4 and inspection of
   `src/dds-dcps/auth-manager.lisp` (the `dp-auth-state` + `%install-auth-manager` pattern).

2. **permissions-gate mirrors auth-gate:** A `permissions-gate` slot is added to `dds-disc/disc.lisp`
   parallel to the existing `auth-gate` slot. NIL → `:compatible` (default-OFF). The gate is called
   as the third sequential check at `%match-remote-endpoint`, after auth-gate returns `:compatible`.
   Confirmed by design doc §4 Modified items and the existing `%consult-auth-gate` in disc.lisp.

3. **Three check points** (DDS-Security 1.1 §8.4 `AccessControl` plugin interface):
   - `check_create_participant` — at `create-participant` in `src/dds-dcps/entities.lisp`, before the
     participant joins (Governance `enable_join_access_control` + `allow_unauthenticated_participants`).
   - `check_create_datawriter` / `check_create_datareader` — at `create-datawriter`/`create-datareader`
     in entities.lisp, before `add-local-writer`/`add-local-reader` (Governance `enable_write/read_AC`
     + Permissions `publish`/`subscribe` grant for local subject on the topic).
   - `check_remote_datawriter` / `check_remote_datareader` — at `%match-remote-endpoint` in
     disc.lisp, after auth-gate `:compatible` (remote Permissions keyed by the authenticated cert
     subject name from the `auth-remote` record).

4. **Default-OFF gate semantics:** `(when (null (dp-permissions-gate p)) (return :compatible))` at
   the gate — identical to the auth-gate. A participant without governance/permissions configured
   is byte-identical to current behaviour (no access-control overhead on the default path).

### NEEDS-VERIFICATION (LOW-RISK, flag for Slice 5)

1. **subject_name format for cross-vendor interop (LOW).** Our implementation will use OpenSSL
   `X509_NAME_oneline` format (`/CN=.../O=.../C=...`) in permissions.xml. DDS-Security 1.1
   §9.4.1.3.2.3 says "printable string representation" without mandating slash vs RFC 2253 format.
   RTI Connext and Fast DDS typically use RFC 2253 (e.g., `CN=Foo,O=Bar,C=XX`). The our-to-our
   comparison is safe because both sides use `x509-subject-name`. For Slice-5 cross-vendor
   interop: may need to normalize both to RFC 2253 at comparison time, OR accept both formats in
   the permissions parser. DEFERRED to ADR 0035 Slice-5 track.

2. **d2i_CMS_ContentInfo vs SMIME_read_CMS (CORRECTION).** The design doc §2 specifies
   `d2i_CMS_ContentInfo` as the parse call. This is wrong for PEM S/MIME input — it parses raw DER
   only. The correct call for `BEGIN PKCS7` PEM is `SMIME_read_CMS`. The T1 FFI binding should
   use `SMIME_read_CMS`. Design doc to be corrected at T1.

3. **xmls vs cxml (LOW).** The design doc §2 says "cxml if it loads clean on Clasp." cxml DOES
   load clean on Clasp but adds 4 transitive systems. We select xmls (zero deps) instead. The
   narrow `parse-governance` / `parse-permissions` interface isolates the choice (swap is a 1-file
   change). Risk: none for our-to-our.

4. **Validity date enforcement (deferred).** Our fixtures set `not_before=2026-01-01` /
   `not_after=2036-01-01`. Date checking is confirmed deferred per design doc §6.
   The fixtures will be valid through 2036.

5. **Topic wildcard fnmatch(3) on Clasp.** POSIX `fnmatch` is available via CFFI (glibc/libSystem).
   Alternatively, a pure-Lisp glob matcher (7 lines) avoids the FFI dependency for control-plane
   use. Decision deferred to T3 (the allow/deny matcher) — either approach is fine; note here.

---

## Pinned constants summary

| Constant | Value | Source |
|----------|-------|--------|
| Governance XSD schema location | `https://www.omg.org/spec/DDS-Security/20190401/dds_governance.xsd` | §9.4.1.2.3 Annex B.1 |
| Permissions XSD schema location | `https://www.omg.org/spec/DDS-Security/20190401/dds_permissions.xsd` | §9.4.1.3.2 Annex B.2 |
| CMS signed-data digest algorithm | SHA-256 | §9.4.1.1 |
| On-disk PEM headers | `-----BEGIN PKCS7-----` / `-----END PKCS7-----` | §9.4.1.1 |
| Content embedding | opaque (non-detached, `-nodetach`) | §9.4.1.1 |
| Parse call (PEM input) | `SMIME_read_CMS` (cms.h line 226, OpenSSL 3.6.2) | cms.h |
| Verify call | `CMS_verify(..., flags=0)` (cms.h lines 276-277, OpenSSL 3.6.2) | cms.h |
| flags=0 meaning | full verify: chain + content + attr signatures | cms.h lines 180-200 |
| `CMS_NO_CONTENT_VERIFY` | `0x4` (do NOT set) | cms.h line 182 |
| `CMS_NOINTERN` | `0x10` (optional) | cms.h line 185 |
| `CMS_NO_SIGNER_CERT_VERIFY` = `CMS_NOVERIFY` | `0x20` (do NOT set) | cms.h lines 186-187 |
| XML library | `xmls` 3.3.0 (zero deps, MIT) | Quicklisp 2026-01-01 |
| subject_name encoding (our-to-our) | OpenSSL `X509_NAME_oneline` slash format | `x509-subject-name` in dds-dare |
| Wildcard rule | POSIX fnmatch(3) | DDS-Security 1.1 §9.4.1.3.2.7 |
| Default rule element | `<default>ALLOW\|DENY</default>` | DDS-Security 1.1 §9.4.1.3.2.9 |
