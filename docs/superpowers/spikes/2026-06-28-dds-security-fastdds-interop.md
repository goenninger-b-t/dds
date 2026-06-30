# Spike — DDS-Security Live Fast-DDS Cross-Vendor Interop (M7 / P6, Slice 5) — T0

> WP: `WP-DDS-SECURITY-FASTDDS-INTEROP` · Task T0 (foundational spike). Re-establishes the live Fast
> DDS-Security peer + harness, reproduces the live cross-vendor baseline (the current failure point), and
> **pins the §9.3.4 `Property`/`BinaryProperty` `propagate`-byte resolution** that T1 consumes. No code
> changes (the fix is T1). Design: `docs/superpowers/specs/2026-06-28-dds-security-fastdds-interop-design.md`;
> plan: `docs/superpowers/plans/2026-06-28-dds-security-fastdds-interop.md`.

## 0. Outcome

- **Fast DDS-Security peer: BUILT + RUNS.** The Slice-4 T12 `SECURITY=ON` build of eProsima Fast DDS
  v3.6.1 persists (`CMakeCache.txt`: `SECURITY:BOOL=ON`, `COMPILE_EXAMPLES:BOOL=ON`, `Release`); the
  headless `security` example binary runs clean (`--help` exit 0) and drives the live harness. No rebuild
  was needed (§2).
- **Live baseline reproduced, both directions.** ours↔Fast DDS over UDP loopback (domain 0, the reused
  Identity-CA / Permissions-CA / Governance): **SPDP discovery works** (`discovered=2`); the §8.7 auth
  handshake **REJECTs at the remote IdentityToken** (`remote IdentityToken rejected`, `matched=0`,
  `keyed=NIL`, `RESULT: FAIL`). Fresh logs under `interop/security-secure-discovery/captures/`; 2683
  well-formed RTPS UDP packets confirmed via `tcpdump -r` (§3).
- **`propagate`-byte resolution PINNED, four-way corroborated.** The conformant §9.3.4 serialization is
  **`name`+`value` only — no `propagate` field on the wire**; `propagate` is a *local* include/exclude
  filter. EMIT the conformant form at all three codec sites; **genuine decode-tolerance is NOT cleanly
  implementable** (the trailing 4-octet field is not self-describing) → match the conformant form on decode
  too and flag "verify Connext at 5b" (§4, §5).
- Provenance updated with every Fast DDS / Cyclone / OMG source consulted (`docs/provenance.md`).

## 1. Clean-room method + the spec-PDF gap

The wire form is pinned from **independent conformant implementations and the OMG IDL**, never from memory:
- **OMG** — the normative machine-readable IDL `dds_security_plugins_spis.idl` (DDS-SECURITY/20170901),
  fetched from omg.org (§4.1).
- **Fast DDS** (Apache-2.0) — read-only, every file logged in `docs/provenance.md` (§4.2).
- **Cyclone DDS** (EPL-2.0/EDL) — read-only via the public `dds_security_serialize.c` on GitHub (§4.3).
- **RTI Connext source is never read** (operating contract §4 clean-room). Connext is the Slice-5b gate.

**Spec-PDF gap (carried from the Slice-4 spike).** `docs/specs/` holds RTPS 2.5, DDS 1.4 DCPS, and XTypes
1.3 PDFs but **not** the DDS-Security 1.1 PDF. The §-clause numbers (§7.2.x `Property_t`, §9.3.4
`DataHolder`) are carried from the design/brief; the *normative artifact* used here is the OMG **IDL** (an
OMG-published file, not memory) plus the two implementations. Confidence in the pinned wire form: **high**
(OMG IDL + two independent implementations agree). Recommend the owner add the DDS-Security 1.1 PDF to
`docs/specs/` (re-stated from the Slice-4 spike §1).

## 2. Step 1 — Fast DDS-Security peer (BUILT + RUNS)

The Slice-4 T12 build is intact; **no rebuild was required this session.**

- Binary: `/Users/frgo/gbt Dropbox/gbt/projects/fastdds/src/fastdds/build/examples/cpp/security/security`
  (built 2026-06-28). `./security --help` exits 0 with the expected publisher/subscriber usage.
- Cache: `…/build/CMakeCache.txt` → `SECURITY:BOOL=ON`, `COMPILE_EXAMPLES:BOOL=ON`,
  `CMAKE_BUILD_TYPE=Release`. Libs present: `libfastdds.3.6.1.0.dylib`, `libfastcdr.2.3.5.dylib`,
  `libfoonathan_memory-0.7.4.dylib` (under `…/fastdds/install/lib/`); OpenSSL 3.x at
  `/opt/homebrew/opt/openssl@3`.
- **Rebuild recipe (only if it regresses)** — unchanged from the Slice-4 spike §4 / interop README:
  ```
  cd "/Users/frgo/gbt Dropbox/gbt/projects/fastdds/src/fastdds/build"
  cmake .. -DSECURITY=ON -DCOMPILE_EXAMPLES=ON -DCMAKE_BUILD_TYPE=Release \
           -DOPENSSL_ROOT_DIR=/opt/homebrew/opt/openssl@3
  cmake --build . --target install -j
  ```
- The Fast DDS build tree is **external** (kept out of the repo, per the operating contract).

## 3. Step 2 — live baseline (SPDP ok; auth REJECT at the IdentityToken)

Run: `bash interop/security-secure-discovery/run-fastdds-interop.sh none 22` (GOV=none isolates
auth+access-control; both directions; the Fast DDS `security` example ⇄ our
`dds.tests:run-secure-interop-peer`, topic `HelloWorldTopic`/`HelloWorld`, domain 0).

| Direction | ours role | result |
|---|---|---|
| `ours2fast` | publisher | `discovered=2 matched=0 keyed=NIL RESULT: FAIL` — `; auth-manager[D1437B8E7A95]: remote IdentityToken rejected` |
| `fast2ours` | subscriber | `discovered=2 matched=0 keyed=NIL RESULT: FAIL` — `; auth-manager[D1437B8E7A95]: remote IdentityToken rejected` |

- **SPDP discovery works** cross-vendor in both directions (`discovered=2` — our participant sees the Fast
  DDS participant); the §8.7 PKI-DH handshake **never advances** because our peer rejects the *remote*
  IdentityToken (and, symmetrically, Fast DDS rejects ours — neither side matches, `keyed=NIL`).
- **Wire confirmation:** `tcpdump -r captures/ssd-none-ours2fast.pcapng` → 2683 well-formed RTPS UDP
  packets on the domain-0 port range (7413–7425), all `127.0.0.1` loopback. (tshark cannot dissect the
  macOS `lo0` NULL/Loopback link layer — the harness's tshark dissector histogram is empty; this is the
  known Slice-4 limitation, so byte-exactness rests on the in-suite corpus and `tcpdump`.)
- **Recorded** (committed): `captures/ssd-none-{ours2fast,fast2ours}-ours.log` (the authoritative reject
  evidence) + `…-fastdds.log`. The `.pcapng` captures are **gitignored** (large + undissectable on lo0,
  reproducible via the harness) — the established Slice-4 convention.
- **Environmental note (honest):** the `fastdds.log` for `ours2fast` shows `RECEIVED` lines with large
  indices (e.g. 39860) — those are from a *leaked/external* Fast DDS publisher on the host, **not** our
  peer (our peer sent 0 samples). The authoritative baseline is our peer's `discovered=2 / REJECTED /
  keyed=NIL`, not the Fast DDS subscriber's stray receives.

## 4. Step 3 — the PINNED `propagate`-byte resolution (four-way corroborated)

**Root cause (from Slice-4 T12 / ADR 0036).** Our DDS-Security token codec serializes a 4-octet
`propagate` field (`01 00 00 00` = `propagate=true` byte + 3 pad) after **every** `Property` /
`BinaryProperty`. A conformant peer does **not** put `propagate` on the wire and never reads it — so every
`Property`/`BinaryProperty` after the first is **misaligned by 4 bytes**, corrupting every DataHolder
(IdentityToken first, then the §8.7 handshake tokens and the §9.5 crypto tokens). This is why the live
baseline rejects at the *remote IdentityToken* (the first token exchanged).

### 4.1 OMG IDL — `dds_security_plugins_spis.idl` (DDS-SECURITY/20170901)

```idl
struct Property_t        { string name;  string value;     boolean propagate; };
struct BinaryProperty_t  { string name;  OctetSeq value;    boolean propagate; };
typedef sequence< Property_t >        PropertySeq;
typedef sequence< BinaryProperty_t >  BinaryPropertySeq;
struct DataHolder {
    string             class_id;
    @optional  PropertySeq        properties;
    @optional  BinaryPropertySeq  binary_properties;
};
```

**The subtle tension that caused the bug:** `propagate` is a **plain `boolean` with no `@non-serialized`
annotation**, so a strict IDL-literal CDR codec (what ours did) *would* emit it (1 byte + alignment) — a
defensible reading. But the spec **text** + both interoperable implementations treat `propagate` as a
*local* flag ("intended for local use by plugins" — whether the property is included when the seq is
serialized), **never serialized**. The interoperable wire form follows the text, not the literal IDL.
`DataHolder.properties`/`binary_properties` are `@optional` → empty seq encodes as `count=0` (already
handled by our codec, T0 spike §10.5 carry).

### 4.2 Fast DDS (Apache-2.0) — three independent confirmations

| Source | Finding |
|---|---|
| `include/fastdds/rtps/common/Property.hpp:174-191` `PropertyHelper::serialized_size` | `if (propagate()) { size += name; size += value; } else return 0;` — only `name`+`value` count toward serialized size; **no byte for `propagate`**; a `propagate=false` property contributes **0** bytes. |
| `include/fastdds/rtps/common/BinaryProperty.hpp:172-189` `BinaryPropertyHelper::serialized_size` | identical pattern (octet-seq value, no `+1` NUL). |
| `src/cpp/rtps/messages/CDRMessage.cpp:828-847` `addProperty` / `867-887` `addBinaryProperty` | writes `add_string(name)` + `add_string`/`addOctetVector(value)` **only**, guarded by `if (propagate())`. No `propagate` written. |
| `…CDRMessage.cpp:889-906` `readBinaryProperty` | reads `name`+`value`, then **`binary_property.propagate(true);`** — `propagate` is *set locally to true on read*, **never read from the wire**. (Definitive.) |
| `…CDRMessage.cpp:908-929` `addPropertySeq` | the serialized seq **count** = `number_to_serialize` = count of `propagate==true` properties only (`propagate=false` dropped from count **and** body). |
| `src/cpp/security/authentication/PKIDH.cpp:1396-1400` (hash_c1/c2) | the handshake challenge hash is `SHA256` over `addBinaryPropertySeq(&msg, …, /*add_final_padding=*/false)` with **`msg.msg_endian = BIGEND`** — i.e. the same no-`propagate` serialization, **Big-Endian**. |

### 4.3 Cyclone DDS (EPL-2.0) — corroboration

`src/security/core/src/dds_security_serialize.c` (GitHub `eclipse-cyclonedds/cyclonedds`):
`DDS_Security_Serialize_Property` writes `Serialize_string(name)` + `Serialize_string(value)` only;
`DDS_Security_Serialize_BinaryProperty` writes `name` + `Serialize_OctetSeq(value)` only — **no
`propagate` field** in either. (Cyclone serializes the seq as presented by the caller; Fast DDS filters
`propagate=false` at serialize time. Both omit the `propagate` field on the wire — the load-bearing fact.)

### 4.4 The pinned resolution (what T1 consumes)

**EMIT form (conformant):** serialize each *propagated* `Property`/`BinaryProperty` as `name`+`value` only;
omit `propagate=false` properties from the seq (so the seq `count` = number of propagated properties). Our
codec sets `propagate=true` for **all** properties, so for us the `count` is **unchanged** — the fix is
purely **dropping the trailing 4-octet `propagate`+pad** at each emit site (and the matching skip at each
decode site).

**DECODE posture — match conformant, NO tolerance shim (decided):** genuine decode-tolerance is **not
cleanly implementable**. The trailing 4-octet `propagate` field is **not self-describing** and collides
structurally with the very next field: after a property's `name`+`value`, the next u32 is *either* the next
property's `name`-length *or* the `BinaryPropertySeq` count — and a `propagate` of `01 00 00 00` is
indistinguishable from `name-len=1` (empty-string name) or `count=1`. Disambiguation would require an
ambiguous backtracking parse over network data, violating the fail-closed/deterministic parser posture
(NFR-SEC-POSTURE). **Decision:** decode the conformant form **only** (`name`+`value`), and **flag "verify
Connext at 5b"**: if a live Connext capture ever shows `propagate` on the wire (contrary to the shared OMG
PSM convention + both corroborating implementations — *not expected*), add targeted handling then. A
new-form decoder fed old-form bytes fails *closed* (safe), so there is no security regression — only the
inability to interoperate with a (non-conformant) `propagate`-emitting peer, of which none is known.

## 5. What T1 changes (the exact codec surface)

Three EMIT sites + three DECODE sites + the corpus. `keyexchange.lisp` needs **no direct change** — it
builds crypto-token DataHolders via the shared `handshake-token->dataholder` → `%build-dataholder-le` →
`%cdr-binary-property-le`, so fixing `wire.lisp` covers it (its corpus must still be re-derived).

| File | Site | Change |
|---|---|---|
| `src/dds-security/auth/wire.lisp` | `%cdr-binary-property-le` (`:25-32`) | drop the `#(1 0 0 0)` pad → `name`+`value` only (LE wire DataHolder; covers IdentityToken bin-props, handshake tokens, **and** keyexchange crypto-tokens) |
| `…/wire.lisp` | `%dh-scan-extent` (`:121-138`) | remove both `(incf pos 4)` propagate skips (PropertySeq + BinaryPropertySeq loops) |
| `…/wire.lisp` | `dataholder->handshake-token` (`:165-188`) | remove both propagate skips |
| `src/dds-security/auth/identity.lisp` | `%cdr-property-le` (`:59-65`) | drop the `#(1 0 0 0)` → `name`+`value` only (LE IdentityToken Property) |
| `…/identity.lisp` | `read-cdr-property` (`:239-245`) | remove the `(incf pos 4)` propagate skip |
| `src/dds-security/auth/handshake.lisp` | `%cdr-binary-property-be` (`:54-59`) | drop the `#(1 0 0 0)` → `name`+`value` only (**BE** hash_c1/c2 + signature input) |
| `src/dds-tests/security-auth-test.lisp` | `+ec-identity-token-vector+` + every hard-coded token vector | regenerate: drop the `1 0 0 0 ; propagate+pad` per property (the IdentityToken: 240 → **224** bytes = 240 − 4 props × 4) + the keymat-blob test offsets (`:2705-2710`) |

**T1 de-risking intelligence (from §4.2 PKIDH.cpp:1398):** the handshake hash input is **Big-Endian** and
uses `add_final_padding=false` — so our `handshake.lisp` **BE** endianness is *already correct*. Dropping
the `propagate` byte alone aligns the hash input with Fast DDS; **no endianness change is needed** in the
challenge-hash path. (One byte-exactness item for T1 to verify when regenerating the corpus: the
`BinaryProperty` octet-seq value's trailing-pad — Fast DDS `addOctetVector(..., add_final_padding=false)`
for the hash; confirm our `%cdr-octet-seq-be`/`-le` `u32(len)+bytes` no-pad form matches for the wire
DataHolder too. The our-to-our byte-exact corpus + the live re-run will catch any residual.)

## 6. Open points / carries (for T1+ and the discovery loop)

- **The propagate fix unblocks the IdentityToken; the next live REJECT is unknown** until T1 lands and the
  peer is re-run. The ADR-0036 candidate backlog (session_id base, SIGN GMAC AAD span, SIGN 4-alignment,
  secure-SEDP/PVMS reliable pull, metatraffic rtps-wrapping) are the *likely* next divergences — each is
  corroborated-conditional (fix only what the live peer exhibits; T2–T6).
- **`add_final_padding` for the wire DataHolder `BinaryProperty` value** — verify in T1 against Fast DDS's
  security-manager serialization call site (the hash path uses `false`; confirm the wire path) so the
  regenerated corpus is byte-exact (§5 note).
- **Connext decode-tolerance** — carried to **5b**: if Connext emits `propagate` on the wire (not expected
  per the OMG PSM + Fast DDS + Cyclone), add targeted decode handling then.
- **DDS-Security 1.1 PDF not in `docs/specs/`** (§1) — recommend the owner add it.
- **`.pcapng` captures are gitignored** (reproduce via the harness); only the `.log` files are committed.
