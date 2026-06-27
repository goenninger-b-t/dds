# WP-DDS-SECURITY-ACCESS-CONTROL — design (M7/P6 Slice 3)

**Status:** DESIGN — approved 2026-06-26, pending spec review.
**Milestone:** M7 / P6 — DDS-Security 1.1. Slice 3 of the 5-slice roadmap (ADR 0031 §9): AccessControl ("DDS:Access:Permissions" builtin plugin, §9.4).
**Prior:** Slice 1 = crypto-payload (ADR 0031); Slice 2 = Authentication (2a ADR 0032, 2b-i ADR 0033, 2b-ii+2c ADR 0034 — the secure participant end-to-end).
**ADR (at the capstone):** 0035.

---

## 1. Goal (the vertical slice)

Deliver **AccessControl end-to-end, our-to-our**: a security-enabled participant loads + **CMS-verifies** its signed **Governance** + **Permissions** documents (signed by a Permissions CA), parses them, and **enforces allow/deny** at the three DDS-Security check points — participant creation, local DataWriter/DataReader creation, and remote endpoint matching (the permissions-gate composed with the Slice-2 auth-gate). Demonstrated end-to-end: a participant whose Permissions **deny** a topic is refused; one whose Permissions **allow** it matches and communicates.

This composes on top of Slice 2: authentication establishes *who* a remote is (its validated cert subject name); AccessControl decides *what* it is allowed to do.

**Non-goals (deferred — §5):** partition-expression matching; validity-date (not_before/not_after) enforcement; the Governance protection-kinds→crypto wiring (metadata/RTPS/submessage protection); the full Governance/Permissions XSD breadth; live RTI Connext-Security interop (Slice 5 = the P6 exit gate).

---

## 2. Approved decisions

1. **Scope:** one vertical slice — validate the signed documents AND enforce allow/deny at all three points, demonstrated end-to-end (a denied topic is refused, an allowed one matches). Core checks; the fancier knobs are documented carries.
2. **XML parsing:** add an XML library dependency, pinned in T0 to one that loads cleanly on **both** Clasp and SBCL (cxml if it loads clean on Clasp; otherwise a lighter self-contained pure-Lisp parser), behind a narrow `parse-governance` / `parse-permissions` interface so the AccessControl logic does not depend on the choice. Justify the new dependency in `docs/provenance.md` + the SBOM.
3. **Signed-document handling:** add a `dds.dare:cms-verify` FFI binding (`d2i_CMS_ContentInfo` + `CMS_verify` + `CMS_get0_signers`) — OpenSSL parses the S/MIME/CMS structure and validates the signer chain against the Permissions CA store, returning the verified content bytes. Conformant + robust; preferred over composing a manual PKCS#7 parse from the raw signature primitives.

---

## 3. Architecture

Mirror the Slice-2 split. **Document validation + the data model** live in `dds-security` (`access-control/`, no `dds-disc` dependency). The **manager** lives in `dds-dcps` (`access-control.lisp`), parallel to `auth-manager.lisp`: `%install-access-control` holds per-participant Permissions state (`dp-access-state`) and installs a **permissions-gate** (composed as a third sequential gate after the auth-gate at `%match-remote-endpoint`) plus the `check_create_*` hooks. `dds-disc` stays crypto/policy-free — it gains one `permissions-gate` slot (exactly like `auth-gate`, T4 of Slice 2). The new `cms-verify` lives in `dds-dare`.

Layering: `dds-security/access-control` depends only on `dds-dare` + the new XML lib (acyclic). The manager in `dds-dcps` sits above both `dds-security` and `dds-disc`, like the auth manager.

---

## 4. Components

### New
- **`src/dds-dare/` — `cms-verify`** (+ FFI `d2i_CMS_ContentInfo` / `CMS_verify` / `CMS_get0_signers`): `(cms-verify smime-or-der ca-store) -> (or verified-content-octets null)`; fail-closed (nil on any verify failure); handle lifecycle via the established dds-dare pattern.
- **`src/dds-security/access-control/parser.lisp`** — `parse-governance (octets) -> governance` and `parse-permissions (octets) -> permissions` (XML → the data model, via the pinned XML lib; bounds-checked; fail-closed).
- **`src/dds-security/access-control/governance.lisp`** + **`permissions.lisp`** — the data model (`governance`: per-domain + per-topic rules — `enable_read_access_control`, `enable_write_access_control`, `allow_unauthenticated_participants`; `permissions`: the subject name + the grants → allow/deny rules → publish/subscribe topic sets) + the **allow/deny matcher** (`permissions-allow-publish-p` / `permissions-allow-subscribe-p (permissions topic-name) -> boolean`, topic-name wildcards per the XSD).
- **`src/dds-security/access-control/plugin.lisp`** — `validate-local-permissions (perm-ca-octets governance-smime permissions-smime local-subject) -> (or access-handle null)` (CMS-verify both vs the Permissions CA, parse, bind grants to the local subject; nil/reject on any failure); `validate-remote-permissions (access-handle remote-permissions-smime remote-subject) -> (or remote-perms null)`; the `check-create-participant` / `check-create-datawriter` / `check-create-datareader` / `check-remote-datawriter` / `check-remote-datareader` predicates.
- **`src/dds-dcps/access-control.lisp`** — `dp-access-state` (slot on `domain-participant`, like `dp-auth-state`); `%install-access-control (p access-handle) -> domain-participant`; `%participant-permissions-gate (p node remote local) -> (member :compatible :incompatible :pending)`.

### Modified
- **`src/dds-disc/disc.lisp`** — add a `permissions-gate` slot + `%consult-permissions-gate` (NIL gate → `:compatible`, like `%consult-auth-gate`); compose at `%match-remote-endpoint` as the third sequential gate, AFTER the auth-gate returns `:compatible` (same `:incompatible`/`:pending`/`t` ladder; `:incompatible` = access-denied, no INCONSISTENT_TOPIC). Crypto/policy-free.
- **`src/dds-dcps/entities.lisp`** — `check_create_participant` at `create-participant` (gate the participant on its Governance/Permissions before it joins); `check_create_datawriter` / `check_create_datareader` in `create-datawriter` / `create-datareader` (before `add-local-writer` / `add-local-reader`) — deny → signal/refuse the endpoint.

---

## 5. Data flow / enforcement

1. A participant is configured with its **Permissions CA** cert + the signed **Governance** + signed **Permissions** documents. `validate-local-permissions` CMS-verifies both against the Permissions CA, parses them, and binds the grants to the local cert **subject name** (`x509-subject-name (identity-handle-cert …)`). `%install-access-control` stores the result in `dp-access-state`.
2. **check_create_participant:** is this participant allowed in the domain (per Governance / its grant)? Deny → the participant does not join (fail-closed).
3. **check_create_datawriter / datareader:** does the local Permissions grant allow publish / subscribe on this topic (matcher with topic wildcards)? + the Governance `enable_write/read_access_control` toggles. Deny → the endpoint is refused.
4. **At matching** (`%match-remote-endpoint`, after the auth-gate `:compatible`): **check_remote_datawriter / datareader** — does the *remote's* Permissions (keyed by its **VALIDATED handshake-certificate** subject name — `auth-remote-validated-subject`, the `x509-subject-name` of the §8.7 chain-verified peer cert surfaced at `:authenticated` per §8.7.2.5, **never** the self-asserted SPDP IdentityToken `cert-sn`) allow the topic? Not yet authenticated → `:pending`; allowed → `:compatible`; denied / no permissions → `:incompatible` (refuse, no INCONSISTENT_TOPIC).
5. Compose: **type-gate → auth-gate → permissions-gate**. All three must pass for a match.

---

## 6. Scope (YAGNI)

**In:** topic-level allow/deny (publish/subscribe grants, topic-name wildcards); Governance `enable_read_access_control` / `enable_write_access_control`; `allow_unauthenticated_participants`; CMS signature + Permissions-CA validation of both documents; the three check points composed with the auth-gate; default-OFF byte-identical.

**Deferred carries (ADR 0035):** partition-expression matching; validity-date (not_before/not_after) enforcement; the Governance protection-kinds→crypto wiring (metadata/RTPS/submessage protection — itself a Slice-2 carry); the full XSD breadth (e.g. the `<criterias>` fnmatch nuances beyond topic+partition); live RTI Connext-Security AccessControl interop = Slice 5.

---

## 7. Error handling / default-OFF

Fail-closed everywhere: a bad CMS signature, an unverifiable Permissions CA, a malformed document, missing or denied permissions → reject (no participant / no endpoint / no match) — **no permissive fallback**. **Default-OFF:** a participant with no governance/permissions configured leaves AccessControl inactive (the `permissions-gate` slot NIL → `:compatible`; no `check_create_*`), byte-identical to today and `mem 0.0000` on the default path (like the Slice-2 auth-gate NIL default). The post-CMS-verify XML bytes are bounds-checked and fuzzed anyway (defense-in-depth, even though the signature gates them).

---

## 8. Constraints (global, copied into the plan)

- OMG DDS-Security 1.1 §9.4 conformance is non-negotiable; the only allowed deviation is interop behavior added on top, never replacing. False-REJECT is the worst class.
- Never hardcode a wire/format constant from memory — pin the Governance/Permissions XSD element set, the S/MIME-CMS signing format, and the XML lib from the spec clause + the OpenSSL/XSD reference (T0 spike); cite the clause.
- No hand-rolled crypto (FR-SEC-2): CMS verification + signature checks via `dds-dare`/OpenSSL only.
- The new XML dependency: justify it (`docs/provenance.md` + SBOM); it must load on BOTH Clasp and SBCL (the Clasp+SBCL-both-validate directive); control-plane only (never on the hot path).
- `defun*` on every function, `defstruct*` on every struct, full `ftype` on every function.
- No reader conditionals outside `dds-pal/`.
- Both impls validate, Clasp first, identically.
- Every parser bounds-checked + fail-closed even at `(safety 0)`; resource caps.
- Default (no-permissions) path byte-identical + `mem 0.0000`.
- Docs in lockstep (docstrings + `docs/wiki/security.md` + README + `docs/verification.csv`) at the capstone; SBOM auto-regenerated.
- No AI-assistant attribution in any repo file except the agent-config file; cite "the operating contract".

---

## 9. Honest interop posture (our-to-our this slice)

Achieved: our-to-our — two security-enabled participants with signed Governance + Permissions authenticate, then their endpoints match **only** when both the auth-gate AND the permissions-gate allow; a participant denied a topic is refused; an allowed one communicates.

**Slice-5 cross-vendor carries (ADR 0035):** live RTI Connext-Security AccessControl interop (the RTI Security Plugins are not installed); the deferred §6 knobs (partition matching, validity dates, protection-kinds→crypto); any S/MIME-CMS framing nuances vs a real peer's signed documents.

Default-OFF: a participant without governance/permissions is byte-identical to today; a security-enabled participant strictly refuses access-denied peers (conformant).

---

## 10. Testing / DoD (spike-first, both impls Clasp-first)

- **T0 spike:** pin the Governance/Permissions XSD element set (DDS-Security 1.1 Annex) + the S/MIME-CMS signing format; pin the XML lib (confirm it loads on Clasp AND SBCL — substitute a lighter parser if cxml does not load clean on Clasp); generate the signed test fixtures — a Permissions CA + `governance.xml` + `permissions.xml` (`openssl smime -sign -outform PEM`) with allow/deny rules referencing the existing test cert subjects (`interop/security-auth/pki`). Confirm assumptions or re-plan.
- **Unit:** `cms-verify` (an openssl-`cms -sign`-generated signed doc verifies against the Permissions CA; a tampered doc → nil); parse-governance / parse-permissions (round-trip the fixture XML → the data model); the allow/deny matcher (topic wildcards, publish vs subscribe, allow vs deny). Each non-vacuous.
- **Integration (headline, our-to-our):** a participant whose Permissions **allow** a topic authenticates + matches + communicates; a participant whose Permissions **deny** that topic is **refused** at matching — **non-vacuous** (an allowed control on the same topic matches; the denied one does not). The local `check_create_datawriter/datareader` denies an endpoint the local Permissions forbid.
- **Fuzz:** the XML parser + `cms-verify` decode path (safety 0), defense-in-depth.
- **Gates:** build / test-clasp / test-sbcl / gate-hotpath / gate-types / mem 0.0000 (default path) / fuzz — green both impls.
- **Cross-DDS (directive):** the live secured cross-vendor AccessControl run is Slice 5 (plugins not installed); the our-to-our allow/deny + the default-OFF don't-break-plain stand here; a harness is provided for the owner's full env.

---

## 11. References

- OMG DDS-Security 1.1: §8.4 (the AccessControl plugin operations), §9.4 ("DDS:Access:Permissions" builtin plugin — the Governance + Permissions document formats + the S/MIME signing), the Annex XSDs.
- Recon (this repo): `src/dds-dare/openssl-ffi.lisp` (`x509-verify-chain`, `x509-subject-name`, `x509-public-key`) + `primitives.lisp` (ecdsa/rsa-pss verify); `src/dds-security/auth/identity.lisp` (`identity-handle-cert`, `%parse-remote-token-strings`); `src/dds-dcps/auth-manager.lisp` (`%install-auth-manager`, `dp-auth-state`, `auth-remote`); `src/dds-disc/disc.lisp` (`%match-remote-endpoint`, `%consult-auth-gate`); `src/dds-dcps/entities.lisp` (`create-participant` / `create-datawriter` / `create-datareader`).
- Prior: ADR 0031–0034.
