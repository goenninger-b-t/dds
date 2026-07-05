# ADR 0035 — DDS-Security AccessControl: governance/permissions CMS-verify + topic-level enforcement (Slice 3)

- **Status:** Accepted (M7/P6; WP-DDS-SECURITY-ACCESS-CONTROL, 2026-06-26)
- **Relates to:** ADR 0034 (Slice 2b-ii + 2c — the auth manager + key exchange; the
  `%participant-auth-gate` this slice composes after); ADR 0033 (Slice 2b-i — PSM wire
  transport); ADR 0032 (Slice 2a — PKI-DH handshake + SharedSecret); ADR 0031 (Slice 1 —
  `crypto-transform` slot; the serialized-payload protection layer); ADR 0025 (DARE — the
  `dds-dare` OpenSSL FFI extended here for `cms-verify` + the existing `x509-load-ca`/
  `x509-ca-free` + `x509-subject-name`); FR-SEC-2 (no hand-rolled crypto); NFR-SEC-POSTURE
  (bounds-checked parsers, fail-closed, fuzzed); NFR-MEM (off the measured CDR hot path).
- **Standards:** OMG DDS-Security 1.1 §8.4 (the AccessControl plugin operations —
  `validate_local_permissions`, `validate_remote_permissions`, `check_create_participant`,
  `check_create_datawriter`, `check_create_datareader`, `check_remote_datawriter`,
  `check_remote_datareader`); §9.4 ("DDS:Access:Permissions" builtin plugin — the Governance +
  Permissions XML document formats, the S/MIME CMS signing, the XSD element set); §9.4.1.2.3
  Table 30–32 (the Governance toggle semantics); §9.4.1.3.2 (the Permissions grant model, the
  first-match-wins rule evaluator, the topic-expression wildcard); §7.3 (the strict
  authenticated-only posture enforced by the auth-gate upstream). The T0 spike
  (`docs/superpowers/spikes/2026-06-26-dds-security-access-control.md`) is the primary
  format/wire reference for this ADR.

---

## Context

ADR 0034 (Slice 2b-ii + 2c) delivered the complete secure-participant vertical slice: every
security-enabled participant discovers its peers, authenticates via the §8.7.2.4 PKI-DH
handshake, derives the §9.5.3 KxKey, exchanges §9.5.2 KxKey-encrypted per-writer KeyMaterial,
gates endpoint matching strictly on authentication (§7.3 `allow_unauthenticated=FALSE`), and
publishes/receives with AES256-GCM encrypted payloads using the exchanged keys.

What was missing: authentication establishes *who* a remote is (its validated cert subject name
is now provably known at `auth-remote` `:keyed`), but there was no policy layer deciding *what*
it is allowed to do.  A security-enabled participant could authenticate any peer and match on any
topic regardless of policy.  AccessControl (DDS-Security 1.1 §8.4 / §9.4) is the policy layer.

This ADR documents the **WP-DDS-SECURITY-ACCESS-CONTROL** work package: Slice 3 of the five-slice
M7/P6 roadmap.

---

## Goal

Deliver **AccessControl end-to-end, our-to-our**: a security-enabled participant loads and
**CMS-verifies** its signed **Governance** + **Permissions** documents (signed by a Permissions
CA), parses them, and enforces **allow/deny** at the three DDS-Security §8.4 check points —
participant creation (`check_create_participant`), local DataWriter/DataReader creation
(`check_create_datawriter` / `check_create_datareader`), and remote endpoint matching
(`check_remote_datawriter` / `check_remote_datareader` — the permissions-gate composed after the
auth-gate at `%match-remote-endpoint`).

Demonstrated end-to-end: a participant whose Permissions **deny** a topic is refused at matching
(the permissions-gate returns `:incompatible`); one whose Permissions **allow** it matches and
communicates byte-exact plaintext.

This is a single vertical slice through every layer: CMS verify + XML parse → data model →
allow/deny matcher → local check points → permissions-gate → endpoint match / refuse.

---

## Approved decisions

Three design decisions were approved before implementation (design spec §2):

### Decision 1 — Full end-to-end vertical slice

Validate the signed documents AND enforce allow/deny at all three §8.4 check points, demonstrated
end-to-end (a denied topic is refused, an allowed one matches and communicates).  A validator that
verifies signatures but never gates anything is a horizontal layer, not a vertical slice.

### Decision 2 — XML library: `xmls` 3.3.0 (MIT, pure-Lisp)

The Governance and Permissions documents are §9.4.1 XML.  The library choice was pinned in the
T0 spike after testing both `cxml` and `xmls` on both Clasp and SBCL: `cxml` required C
extensions unavailable on Clasp at this configuration; `xmls` 3.3.0 (MIT; Shannon Spires /
rpgoldman) is a pure-Lisp SAX/DOM parser that loads cleanly on both implementations with zero
transitive C dependencies.  The `xmls:parse` + `xmls:node` + `xmls:node-children` + `xmls:node-name`
interface is narrow and abstracted behind internal helpers (`%ac-node-child`, `%ac-node-text`,
`%ac-node-children-named`, `%ac-node-bool`, `%ac-node-text-req`) so the access-control logic
is implementation-independent of the XML library.  `xmls` is justified in `docs/provenance.md`
and reflected in `sbom.spdx.json` (SPDXRef-xmls).

### Decision 3 — CMS signature verification via `dds.dare:cms-verify` (OpenSSL FFI)

DDS-Security 1.1 §9.4.1.1 specifies that signed documents are opaque **CMS SignedData**
(`-----BEGIN PKCS7-----` PEM wrapper).  Rather than composing a manual PKCS#7 parse from
the raw primitives already in `dds-dare`, a new `cms-verify (smime-octets ca-store) ->
(or octets null)` binding was added to `dds-dare/openssl-ffi.lisp`:

- `PEM_read_bio_CMS` (OpenSSL pem.h) parses the `-----BEGIN PKCS7-----` PEM wrapper into a
  `CMS_ContentInfo*`.
- `CMS_verify` (OpenSSL cms.h, flags=0) performs the full chain + content + attribute
  verification against the Permissions CA `X509_STORE*`.
- `BIO_ctrl / BIO_CTRL_INFO=3` recovers the verified plaintext bytes from the output mem-BIO.

`cms-verify` is fail-closed (NIL on any failure), conforms to FR-SEC-2 (no hand-rolled crypto),
and reuses the existing `x509-load-ca` / `x509-ca-free` handle lifecycle.  The `x509-load-ca`
function builds the `X509_STORE*` from the PEM-encoded Permissions CA octets; the store is
retained in the `access-handle` and freed via `free-access-handle` (a `dds-dare` call).

---

## Architecture

### Layering

The split mirrors the Slice-2 auth split exactly:

- **Document validation + data model** live in `dds-security` (`access-control/`: `parser.lisp`,
  `governance.lisp`, `permissions.lisp`, `plugin.lisp`).  No `dds-disc` dependency.  Depends
  only on `dds-dare` + `xmls`.
- **The manager** lives in `dds-dcps` (`access-control.lisp`), parallel to `auth-manager.lisp`:
  `%install-access-control` holds per-participant `dp-access-state` and installs the
  `permissions-gate` on the disc-node.
- **`dds-disc`** stays crypto/policy-free.  It gains one `permissions-gate` slot (exactly like
  `auth-gate`), and `%consult-permissions-gate` composes as the **third** sequential gate after
  the auth-gate at `%match-remote-endpoint`.

Dependency direction: `dds-security/access-control` → `dds-dare` + `xmls` (acyclic); `dds-dcps`
→ `dds-security` + `dds-disc` (the established layer); `dds-disc` has no upward dependency.

### Module layout

| File | Responsibility |
|---|---|
| `src/dds-dare/openssl-ffi.lisp` | `cms-verify` (T1): `PEM_read_bio_CMS` + `CMS_verify` + `BIO_ctrl` |
| `src/dds-security/access-control/parser.lisp` | XML primitives (`%ac-node-*`) + `%topic-match-p` (fnmatch subset) + grant-rule parse helpers |
| `src/dds-security/access-control/governance.lisp` | `governance` defstruct + `parse-governance` + `governance-topic-rule` |
| `src/dds-security/access-control/permissions.lisp` | `permissions` defstruct + `parse-permissions` + `%permissions-match-p` + `permissions-allow-publish-p` / `-subscribe-p` |
| `src/dds-security/access-control/plugin.lisp` | `access-handle` defstruct; `validate-local-permissions` / `validate-remote-permissions`; `check-create-participant` / `-datawriter` / `-datareader` / `check-remote-datawriter` / `-datareader`; `free-access-handle` |
| `src/dds-dcps/access-control.lisp` | `%participant-permissions-gate`; `%install-access-control`; plumbing into `dp-access-state` + disc-node `permissions-gate` slot |

### The `access-handle` and the shared-document model

`access-handle` (T3, `plugin.lisp`) is the per-participant AccessControl state.  It owns:

- `governance` — the parsed Governance struct (first `domain_rule`).
- `permissions` — the LOCAL subject's parsed grant (the `<grant>` whose `<subject_name>` matches
  the local participant's cert subject name).
- `grants` — the FULL list of all parsed `<grant>` entries (one per `<grant>` element in the
  Permissions document, XSD `grant+`, in document order).
- `ca-store` — the Permissions CA `X509_STORE*` (foreign pointer; owned; freed in
  `free-access-handle`).
- `subject` — the local cert subject name (string; used for local grant selection).

The **shared-document model** (our-to-our this slice): every participant is configured with the
SAME multi-grant Permissions document.  To check a REMOTE participant, the permissions-gate
selects the remote's grant from the access-handle's FULL `grants` list by the remote's
**VALIDATED handshake-certificate** subject name.  The subject is the `auth-remote-validated-subject`
field — the `x509-subject-name` of the §8.7 chain-verified peer certificate, surfaced from the
`handshake-handle` `peer-subject` slot at `:authenticated` (§8.7.2.5), **NOT** the self-asserted SPDP
IdentityToken.  Because the remote proved possession of the private key for *that* certificate AND the
subject is read from the validated certificate (never from a field the remote sets freely), the
authorization subject cannot be forged.  *(Authorizing on the self-asserted IdentityToken `cert-sn` —
the original behaviour — was a privilege-escalation hole: any Identity-CA-issued peer could advertise a
privileged `cert-sn` it does not hold the key for, complete the handshake with its real cert, and be
authorized on the privileged grant.  Fixed by surfacing the validated peer subject from the handshake
and authorizing on it; the §8.7.2.5 consistency check additionally rejects the handshake when the
validated subject and the advertised `cert-sn` disagree.)*

This surfaces the validated peer subject from the §8.7 handshake (the new `handshake-handle`
`peer-subject` slot + `auth-remote-validated-subject`).  The conformant per-participant
`c.perm`-in-handshake Permissions exchange (each peer sends its own independently-signed
Permissions document, which the peer CMS-verifies) is a **documented Slice-5 carry** (see
§Honest interop posture, Carry 1).

### §9.4.1.2.3 Table 32 — Governance toggle semantics at `%match-remote-endpoint`

The Governance `enable_read_access_control` and `enable_write_access_control` toggles control
WHICH direction of remote endpoint checking applies at the local participant.  Per Table 32:

| Governance toggle | Check applied |
|---|---|
| `enable_read_access_control = TRUE` | `check_remote_datawriter` (the local read path vets the remote publisher) |
| `enable_write_access_control = TRUE` | `check_remote_datareader` (the local write path vets the remote subscriber) |

`%remote-writer-p (endpoint-data)` (in `dds-dcps`) reads the EntityId kind byte (octet 15 of
the GUID) to decide which remote check applies — a remote writer (kind `0x02`) triggers
`check-remote-datawriter`, a remote reader (kind `0x07`) triggers `check-remote-datareader`.

### First-match-wins rule evaluator

`%permissions-match-p (perms operation topic-name)` iterates the ordered `rules` list of a
`permissions` struct (T2, `permissions.lisp`).  For each rule `(action . (op . topic-exprs))`:
if `op` matches the requested operation AND `some` of `topic-exprs` matches `topic-name` via
`%topic-match-p`, the rule fires and returns `(eq action :allow)`.  If no rule fires, the
`permissions-default` field (`(member :allow :deny)`) decides (per §9.4.1.3.2.10).

`%topic-match-p (expr topic-name)` is a pure-Lisp full-string POSIX fnmatch(3) matcher
(§9.4.1.3.2.7, no `FNM_PATHNAME`): `*` matches zero or more chars, `?` matches exactly one,
and `[...]` bracket classes match one char from a set (`!`/`^` negation, `[]...]` literal-`]`,
first/last `-` literal, `c1-c2` inclusive char-code range, unterminated `[` is a literal `[`).

### The permissions-gate verdict ladder

`%participant-permissions-gate` (the third sequential gate at `%match-remote-endpoint`,
OUTSIDE the node lock, receiver thread) returns:

| Condition | Verdict |
|---|---|
| `dp-access-state` NIL (AC OFF) | `:compatible` — unchanged plain path |
| `dp-auth-state` NIL (AC needs auth; auth not configured — misconfig) | `:pending` — fail-closed park |
| auth-remote absent / not `:keyed` (auth in flight) | `:pending` — parked; resumed on `:keyed` by existing auth path |
| remote VALIDATED subject absent (no chain-verified handshake-cert subject, §8.7.2.5) | `:incompatible` — cannot authorize → deny |
| remote subject has no grant in the shared Permissions | `:incompatible` — no permissions → deny |
| remote grant denies the topic (direction-aware per Table 32) | `:incompatible` — access denied |
| remote grant allows the topic | `:compatible` |

The `:pending` case when auth is in flight is important: the permissions-gate shares the park /
`resume-parked-matches` path with the auth-gate.  When the auth path reaches `:keyed` it calls
`resume-parked-matches`, which re-invokes the full gate chain (type → auth → permissions) for
all parked matches.  The permissions-gate does NOT need its own resume trigger.

---

## Data flow / the three check points

1. A participant is configured with Permissions CA cert octets + signed Governance + signed
   Permissions.  `validate-local-permissions` CMS-verifies both against the Permissions CA,
   parses them, selects the local grant by subject name, and returns an `access-handle`.
   `%install-access-control (p access-handle)` stores it in `dp-access-state` and wires the
   permissions-gate closure on the disc-node.
2. **`check_create_participant`** (`check-create-participant (ah)`, §8.4.2.3): is the Governance
   `enable_join_access_control` flag set?  If yes, is the local `permissions` bound?
   Deny → the participant does not join (fail-closed; the Slice-2 auth-gate already enforces
   `allow_unauthenticated_participants=FALSE` upstream — see Carry 6).
3. **`check_create_datawriter`** (`check-create-datawriter (ah topic)`, §8.4.2.4): is
   `enable_write_access_control` (Governance, Table 32) set?  If yes, does the local Permissions
   allow publish on `topic` (first-match-wins)?  Deny → the endpoint is refused before being
   added to the local disc-node.
4. **`check_create_datareader`** (`check-create-datareader (ah topic)`, §8.4.2.5): same for
   `enable_read_access_control` / subscribe check.
5. **At matching** (`%match-remote-endpoint`, after the auth-gate returns `:compatible`):
   `%consult-permissions-gate` → `%participant-permissions-gate` → `check-remote-datawriter`
   or `check-remote-datareader` for the remote endpoint's topic, using the remote's VALIDATED
   handshake-certificate subject (`auth-remote-validated-subject`, §8.7.2.5 — the `x509-subject-name`
   of the chain-verified peer cert, never the self-asserted IdentityToken) from the `auth-remote`
   record at `:keyed`.
6. Gate composition: **type-gate → auth-gate → permissions-gate**.  All three must return
   `:compatible` for a match to proceed.

---

## KAT note (CMS-verify)

CMS signature verification is entirely within OpenSSL (`PEM_read_bio_CMS` + `CMS_verify`).
The OpenSSL 3.6.2 implementation is covered by NIST CAVP test vectors.  Our test verifies:
(a) the signed governance.p7s fixture (generated with `openssl smime -sign -outform PEM`) verifies
against the Permissions CA → returns the XML bytes; (b) a tampered document (one byte flipped in the
signed content) → NIL (fail-closed).  This is the structural correctness test; the
cryptographic correctness of the underlying primitives is inherited from the OpenSSL KATs
(ADR 0025).

---

## Honest interop posture and Slice-5 carries

**Achieved this slice (our-to-our):** two security-enabled participants configured with the
shared signed Governance + shared signed Permissions document authenticate (via the Slice-2
auth path), then their endpoints match **only** when the auth-gate AND the permissions-gate
both allow.  A participant whose Permissions deny a topic is refused at matching (the
permissions-gate returns `:incompatible`, non-vacuous: the control participant with an allowed
topic matches and communicates byte-exact plaintext).  `check_create_datawriter` / `check_create_datareader`
enforce local Permissions at endpoint creation (`run-access-control-local-deny-test`).

**Do NOT interpret this ADR as "cross-vendor AccessControl interop verified."**

The following items are explicitly deferred to Slice 5:

### Carry 1 — Conformant per-participant `c.perm`-in-handshake Permissions exchange

DDS-Security 1.1 §8.7.2.4 / §9.4.1 specifies that each participant includes its own signed
Permissions document (`c.perm`) in the handshake token.  The peer CMS-verifies it against the
Permissions CA it already trusts, confirming the remote holds a valid Permissions document from
the same authority.  This mechanism is distinct from (and additive to) the shared-document model.

Our slice uses the **shared-document model** (all participants hold the same multi-grant
Permissions doc; the gate selects the remote's grant by its validated handshake-cert subject).  This
is our-to-our self-consistent.  The conformant `c.perm` exchange is a **Slice-5 carry** that
also enables cross-vendor AccessControl interop (a Connext peer may require it to accept our
permission claim).

### Carry 2 — Signed-document format: bare-PEM-PKCS7 vs MIME-wrapped S/MIME

Our test fixtures (`governance.p7s`, `permissions.p7s`) are generated by `openssl smime -sign
-outform PEM`, producing a bare `-----BEGIN PKCS7-----` / `-----END PKCS7-----` PEM block.
`PEM_read_bio_CMS` reads this format directly.

A cross-vendor peer (e.g. RTI Connext) may emit the document as a MIME-wrapped S/MIME multipart
message (`Content-Type: application/pkcs7-mime; smime-type=signed-data ...`).  OpenSSL's
`SMIME_read_CMS` would handle that format.  Whether Connext uses the bare PEM or MIME-wrapped
format is **unverified** (the RTI Security Plugins are not installed; the P6 exit gate).
`PEM_read_bio_CMS` is the conformant choice for the `-----BEGIN PKCS7-----` format (§9.4.1.1).

### Carry 3 — Subject-name normalization: RFC 2253 vs OpenSSL slash format

The Permissions document `<subject_name>` element uses the **OpenSSL slash-delimited** format
(e.g. `/CN=TestParticipantEC/O=DDS-Test/C=DE`), matching the output of `openssl x509 -subject`.
`x509-subject-name` (via OpenSSL `X509_get_subject_name` + `X509_NAME_oneline`) returns the
slash format.  Our matcher uses `string=`.

A cross-vendor peer may use RFC 2253 (comma-delimited, reversed RDN order; e.g.
`C=DE,O=DDS-Test,CN=TestParticipantEC`).  Subject-name normalization across formats is a
**Slice-5 carry**.  The canonical comparison function (per §9.4.1.3.2.2) is not specified by
the OMG standard itself and varies across implementations.

### Carry 4 — Deferred §6 knobs

| Item | Deferred to |
|---|---|
| Partition-expression matching (`<partitions>` element, §9.4.1.3.2.8) | Slice-5 |
| Validity-date enforcement (`<not_before>` / `<not_after>`, §9.4.1.3.2.5) | Slice-5 |
| Governance `protection_kind` → crypto wiring (metadata/RTPS/submessage protection, §9.4.1.2.3 Table 31) | Later slice (also a Slice-2c carry) |
| The full XSD breadth (e.g. multi-`<domain_rule>` + `<criteria>` nesting, §9.4.1.2) | Slice-5 |

These are strictly additive: the current implementation enforces the subset it covers correctly
(fail-closed on missing/denied permissions) and the deferred items do not invalidate the
achieved checks.

### Carry 5 — `%topic-match-p` glob: `[...]` bracket classes — RESOLVED (WP-SECURITY-GLOB-BRACKET-CLASSES)

`%topic-match-p` now implements full POSIX fnmatch(3) `[...]` bracket classes on top of the
existing `*`/`?` subset (§9.4.1.3.2.7 references the full fnmatch(3) pattern language; no
`FNM_PATHNAME` — topic names have no path separators, so `*` still matches everything).
Semantics chosen (POSIX fnmatch(3), disambiguated and pinned in the `%bracket-class-match`
docstring):

- `[abc]` matches any one listed char; `[a-z]` is an inclusive char-code range (`a`, `z`
  boundaries included; an inverted range `hi<lo` matches nothing — safe).
- **Negation:** `[!...]` (POSIX-canonical) negates. `[^...]` is also honoured as the
  widely-supported (glibc/BSD/musl) synonym — the brief's test matrix requires `[^abc]` to
  negate, so treating `^` as a literal member would be a false reading; both `!` and `^` as
  the first class char negate.
- **Literal `]`:** a `]` immediately after `[` or `[!`/`[^` is a literal member, not the
  terminator (`[]abc]` = set `{ ] a b c }`).
- **Literal `-`:** a `-` first or last in the class (`[-a]`, `[a-]`) is a literal `-`.
- **Unterminated `[`:** no closing `]` before end-of-pattern → the `[` is a **literal `[`**
  (POSIX unmatched-`[` rule); `[]` (degenerate empty class) is therefore an unterminated `[`
  followed by a literal `]`, i.e. it matches the literal string `[]`.

Every pattern index is bounds-checked against the pattern length before access (no OOB even at
`(safety 0)`); a malformed/unterminated class fails **safe** — a deterministic no-match or the
literal-`[` reading, never a crash, unbounded loop, or spurious match that could false-ACCEPT.
`*`/`?`/literal behaviour is byte-for-byte unchanged (`run-access-glob-test` prior cases stay
green). Covered by extended `run-access-glob-test` + a permissions-level
`run-access-glob-permissions-test` (a grant with a bracket-class `topic_expression` allows the
matching topic and denies a non-matching one through `permissions-allow-{publish,subscribe}-p`).

Two conformance boundaries (both non-security, documented for completeness): (i) `^` as a
negation synonym follows glibc/BSD/musl (every real fnmatch, incl. Connext-on-Linux) rather
than strict POSIX.1 (which reads a leading `^` as a literal member) — no administrator authors
a leading `^` intending a literal caret, and this side only ever matches a superset relative to
a strict-POSIX-only peer, never a subset of an authored ALLOW; (ii) backslash escaping
(`FNM_NOESCAPE`-off) is not modelled — `\` is a literal char in and out of a class — which is a
non-path for DDS topic identifiers (no `\` in a topic name/expression). Neither affects the
bounded/fail-safe/no-false-ACCEPT guarantee above.

### Carry 6 — `allow_unauthenticated_participants` enforced upstream by the auth-gate

`governance-allow-unauthenticated` is parsed and stored.  However, enforcement at the
AccessControl layer is redundant: the Slice-2 auth-gate (`%participant-auth-gate`) already
enforces `allow_unauthenticated_participants=FALSE` as the unconditional conformant default
(ADR 0034 §Decision 2), refusing any unauthenticated participant before the permissions-gate
is ever consulted.  The AC layer's separate `enable_join_access_control` toggle
(`check-create-participant`) gates the JOIN itself (whether the participant may join the domain
at all, independent of authentication), which is distinct.

### Carry 7 — Live RTI Connext-Security AccessControl interop (the P6 exit gate — Slice 5)

A live AccessControl check against a running RTI Connext-Security stack has NOT been
performed.  It requires the licensed Security Plugins add-on (`rti_connext_dds_secure_plugins`
/ `libnddssecurity.dylib`), which is not installed in this environment.

**This is the P6 exit gate.**

---

## Tests

| Test | What it proves | Added in |
|---|---|---|
| `run-access-cms-verify-test` | `cms-verify`: signed fixture → XML bytes; tampered doc → NIL; wrong CA → NIL (fail-closed, non-vacuous) | T1 |
| `run-access-governance-parse-test` | `parse-governance`: fixture → governance struct; `allow_unauthenticated=NIL`; `enable_join_ac=T`; topic-rules non-empty + correct; `governance-topic-rule` for `"Square"` → `(T T)`; malformed inputs → NIL | T2 |
| `run-access-permissions-parse-test` | `parse-permissions`: fixture → 4 grants; EC grant fields (subject-name, not-before, not-after, default=`:deny`, rules count); allow rule contains `"Square"`; deny rule contains `"Circle"`; malformed inputs → NIL | T2 |
| `run-access-matcher-test` | `permissions-allow-publish-p` / `-subscribe-p`: Square allowed, Circle denied, Triangle → default DENY | T2 |
| `run-access-glob-test` | `%topic-match-p`: `*`, `?`, literal, prefix*, *suffix, infix, empty pattern/string, `[...]` bracket classes (`[abc]`, `[a-z]` range + boundaries, `[!abc]`/`[^abc]` negation, `[]abc]` literal-`]`, `[-a]`/`[a-]` literal-`-`, unterminated `[` → literal, `Shape[0-9]*` mixed) | T2 (bracket classes: WP-SECURITY-GLOB-BRACKET-CLASSES) |
| `run-access-glob-permissions-test` | permissions-level bracket class: a grant with a `[...]` `topic_expression` allows the matching topic and denies non-matching / wrong-length topics via `permissions-allow-{publish,subscribe}-p` (no false-ACCEPT / false-REJECT) | WP-SECURITY-GLOB-BRACKET-CLASSES |
| `run-access-ac-fuzz-test` | 2000 adversarial blobs × 2 parsers (`parse-governance` / `parse-permissions`) × normal + `(safety 0)` = 8000 calls; all NIL-or-valid, 0 crashes | T2 |
| `run-access-plugin-test` | `validate-local-permissions` (signed fixtures → access-handle; wrong CA → NIL; tampered governance → NIL); `check-create-participant` / `check-create-datawriter` / `check-create-datareader` / `check-remote-datawriter` / `check-remote-datareader` (AC-on + allow, AC-on + deny, AC-off via Governance toggle) | T3 |
| `run-access-manager-test` | `%participant-permissions-gate` unit test (DARE-free, unsigned XML): AC-off → `:compatible`; auth-off → `:pending`; no auth-remote → `:pending`; auth not `:keyed` → `:pending`; no grant → `:incompatible`; deny → `:incompatible`; allow → `:compatible`; **privilege-escalation exploit (final-review fix): a `:keyed` remote whose self-asserted SPDP token claims the granted `/CN=TestParticipantEC` but whose VALIDATED handshake-cert subject is the un-granted `/CN=Eve` → `:incompatible` (the gate authorizes on `auth-remote-validated-subject`, never the token)** | T5 |
| `run-access-control-allow-deny-test` | Full e2e (real signed fixtures, real participants, real wire): ALLOW pair (`"Square"`, domains 85) authenticates + matches + communicates byte-exact; DENY pair (`"Circle"`, domain 86) authenticates (`:keyed`) but does NOT match (permissions-gate `:incompatible`); NON-VACUOUS: `sq-b matched-count >= 1` AND `ci-b matched-count = 0`; the ONLY difference is the topic name | T6 |
| `run-access-control-local-deny-test` | `check_create_datawriter` / `check_create_datareader` refuse a local endpoint the local Permissions deny (domain 87; EC participant; write-AC=T + publish-deny-triangle → `nil` from `check-create-datawriter`); NON-VACUOUS: an allowed topic (`"Square"`) is not refused | T6 |
| `run-access-control-default-off-test` | A participant with NO governance/permissions configured: `dp-access-state=NIL` → permissions-gate returns `:compatible` → byte-identical to the pre-security plain path | T6 |

Clasp 349 + SBCL 349.  All gates green at T7 (gate sweep results in §Consequences).

---

## §M7 roadmap update

| Slice | Description | Status |
|---|---|---|
| 1 | Crypto plugin: AES256-GCM `SecuredPayload` + session-key KDF (ADR 0031) | LANDED |
| 2a | Authentication plugin: PKI identity + §8.7.2.4 PKI-DH handshake → SharedSecret, both §9.3 suites, our-to-our (ADR 0032) | LANDED |
| 2b-i | Wire transport: SPDP IdentityToken + PSM endpoints + DataHolder/envelope codec + our-to-our handshake over UDP (ADR 0033) | LANDED |
| 2b-ii + 2c | Auth manager: on-discovery trigger + auth-remote state machine + strict endpoint gate + KxKey KDF + per-writer KeyMaterial exchange + exchanged-key resolver (ADR 0034) | LANDED |
| **3 (this ADR)** | AccessControl plugin (§8.8): governance/permissions XML, CMS-verify, topic-level enforcement | **LANDED** |
| 4 | Secure discovery: SPDP/SEDP participant/endpoint authentication | pending |
| 5 | Connext-Security live interop (P6 exit gate; RTI Security Plugins required) | pending |

---

## Consequences

- **NFR-MEM:** `make mem` stays **0.0000** bytes/sample.  The AccessControl path is
  control-plane and off the measured CDR hot path.  The `%consult-permissions-gate` call in
  `%match-remote-endpoint` adds one nil-check on the default (no-AC) path; byte-identical.
- **NFR-SEC-POSTURE:** `parse-governance` and `parse-permissions` are `handler-bind`-wrapped
  (any XML parse error → NIL, fail-closed) and the XML bytes are already CMS-verified before
  they reach the parser (defense-in-depth).  `run-access-ac-fuzz-test` proves no OOB, crash,
  or non-NIL result on 8000 adversarial calls at `(safety 0)`.
- **FR-SEC-2:** no hand-rolled crypto.  CMS verification = OpenSSL `PEM_read_bio_CMS` +
  `CMS_verify` via `dds.dare:cms-verify`; CA store = `dds.dare:x509-load-ca` /
  `dds.dare:x509-ca-free` (ADR 0025).
- **NFR-PORT:** no reader conditionals in `src/dds-security/access-control/` or
  `src/dds-dcps/access-control.lisp`.  `gate-hotpath(8)` unaffected.
- **Default-OFF:** a participant without governance/permissions has `dp-access-state=NIL` and
  the permissions-gate returns `:compatible` unconditionally — byte-identical to the pre-Slice-3
  path with no overhead beyond one NIL check.
- **Gates (T7 gate sweep):** `build` PASS; `test-clasp` 349 PASS (Clasp first); `test-sbcl`
  349 PASS; `gate-hotpath(8)` PASS; `gate-types(1806)` PASS; `mem(0.0000)` PASS; `fuzz` PASS.
  First Clasp run had a pre-existing `keyed-flatdata-copy-behavior` flake (KFDC-A2-ONE) unrelated
  to this WP; second run passed.

---

## References

- T0 spike: `docs/superpowers/spikes/2026-06-26-dds-security-access-control.md`
- Design spec: `docs/superpowers/specs/2026-06-26-dds-security-access-control-design.md`
- `src/dds-dare/openssl-ffi.lisp` — `cms-verify` (T1)
- `src/dds-security/access-control/parser.lisp` — XML helpers + `%topic-match-p` + grant-rule helpers
- `src/dds-security/access-control/governance.lisp` — `governance` defstruct + `parse-governance` + `governance-topic-rule`
- `src/dds-security/access-control/permissions.lisp` — `permissions` defstruct + `parse-permissions` + allow/deny matcher
- `src/dds-security/access-control/plugin.lisp` — `access-handle` + all §8.4 check predicates
- `src/dds-dcps/access-control.lisp` — `%participant-permissions-gate` + `%install-access-control`
- `src/dds-dcps/entities.lisp` — `dp-access-state` slot; `check-create-participant` / `check-create-datawriter` / `check-create-datareader` calls
- `src/dds-disc/disc.lisp` — `permissions-gate` slot + `%consult-permissions-gate` (third gate in `%match-remote-endpoint`)
- `src/dds-tests/security-access-control-test.lisp` — all WP-DDS-SECURITY-ACCESS-CONTROL test functions
- `interop/security-access-control/README.md` — our-to-our e2e harness + environment-limited Connext-Security AccessControl deferral (Slice 5)
- `docs/provenance.md` — `xmls` 3.3.0 dependency justification
- ADR 0034 — Slice 2b-ii + 2c (the auth manager this slice composes after)
- ADR 0033 — Slice 2b-i (PSM wire transport)
- ADR 0032 — Slice 2a (PKI-DH handshake)
- ADR 0031 — Slice 1 (the `crypto-transform` slot)
- ADR 0025 — DARE (the `dds-dare` OpenSSL FFI extended for `cms-verify`)
