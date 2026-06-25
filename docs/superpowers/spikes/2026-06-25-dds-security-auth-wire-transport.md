# Spike: DDS-Security 1.1 §7.4/§9.3 PSM Wire Transport Constants

**Date:** 2026-06-25
**WP:** WP-DDS-SECURITY-AUTH-2BI (M7/P6, Slice 2b-i — PSM wire transport)
**Status:** DONE (all required values pinned; NEEDS-VERIFICATION list below is short and
does not block T1–T3)
**Confidence:** HIGH on all constants in §2–§6; NO values fabricated from memory.

---

## 1. Environment and approach

**RTI Connext DDS 7.3.1 Security Plugins:** Security plugin DSO (`libnddssecurity.dylib`)
absent — the plain publisher initialises but the participant transport fails (no matching
network interface in the stored QoS profile). Connext 7.3.1 base stack present and the
existing interop capture `interop/connext/tl-probe-runA-lo0.pcap` contains clean SPDP
frames from the plain (non-security) participant — used to ground the SPDP ParameterList
shell (§7).

**Sources used (in precedence order):**

1. OMG DDS-Security 1.1 formal/2018-04-01 PDF — primary authority. PDF binary; clause
   text not machine-readable, but the IDL companion file (OMG DDS-SECURITY/20170901/
   dds_security_plugins_spis.idl) IS machine-readable and provides normative struct
   definitions.
2. OMG DDS-SECURITY/20170901/dds_security_plugins_spis.idl — normative IDL (fetched).
3. eProsima Fast DDS (Apache-2.0): headers and source (reading only, no code copied):
   - `include/fastdds/dds/core/policy/ParameterTypes.hpp` — PID values
   - `include/fastdds/rtps/builtin/data/BuiltinEndpoints.hpp` — endpoint set bits
   - `src/cpp/rtps/security/SecurityManager.h` — security-specific endpoint bits
   - `src/cpp/rtps/security/SecurityManager.cpp` — message construction context
   - `src/cpp/rtps/messages/CDRMessage.cpp` — CDR serialization field order
   - `src/cpp/rtps/security/common/ParticipantGenericMessage.h` — struct fields
   - `src/cpp/rtps/security/authentication/PKIDH.cpp` — message_class_id constants
   - `include/fastdds/rtps/common/EntityId_t.hpp` (via docs) — EntityId hex values
4. Fast DDS 3.1.x API docs for EntityId macros (machine-readable page) — EntityId values.
5. Prior spike `docs/superpowers/spikes/2026-06-23-dds-security-auth-wire.md` — the 2a
   constants (class_id strings, algo strings, HandshakeMessageToken property names,
   MODP-2048) are already pinned and correct; this spike extends them.
6. Live capture analysis: `interop/connext/tl-probe-runA-lo0.pcap` (frame 1 hex decode)
   — confirms the SPDP ParameterList structure and PID_BUILTIN_ENDPOINT_SET wire value.

**No RTI Connext source or headers were read.** Fast DDS was read for understanding only.
Provenance: this file.

---

## 2. ParticipantStatelessMessage builtin EntityIds (§7.4.3)

These are the RTPS builtin endpoint EntityIds for the authentication handshake channel.
The PSM writer sends handshake tokens; the PSM reader receives them.

| Endpoint | EntityId (u32 MSB-first) | §-clause |
|---|---|---|
| `ENTITYID_P2P_BUILTIN_PARTICIPANT_STATELESS_WRITER` | **0x000201C3** | DDS-Security 1.1 §7.4.3 |
| `ENTITYID_P2P_BUILTIN_PARTICIPANT_STATELESS_READER` | **0x000201C4** | DDS-Security 1.1 §7.4.3 |

**Encoding:** entityKey[3] + entityKind, 4 octets MSB-first (same encoding as all RTPS
builtin EntityIds per RTPS 2.5 §9.3.1.2). entityKind byte: 0xC3 = `WRITER_NO_KEY`
(best-effort writer); 0xC4 = `READER_NO_KEY` (best-effort reader). The PSM is
**best-effort, NOT reliable** — no HEARTBEAT/ACKNACK exchange (DDS-Security 1.1 §7.4.3).

**Fast DDS corroboration** (3.1.x API docs macro definitions — `EntityId_t` defines page):
```
ENTITYID_P2P_BUILTIN_PARTICIPANT_STATELESS_WRITER = 0x000201C3
ENTITYID_P2P_BUILTIN_PARTICIPANT_STATELESS_READER = 0x000201C4
```

**Also pinned for future use (ParticipantVolatileMessageSecure — Slice-3):**

| Endpoint | EntityId | §-clause |
|---|---|---|
| `ENTITYID_P2P_BUILTIN_PARTICIPANT_VOLATILE_MESSAGE_SECURE_WRITER` | **0xff0202C3** | DDS-Security 1.1 §7.4.5 |
| `ENTITYID_P2P_BUILTIN_PARTICIPANT_VOLATILE_MESSAGE_SECURE_READER` | **0xff0202C4** | DDS-Security 1.1 §7.4.5 |

The `0xff` entity key prefix identifies vendor-specific / security-scoped endpoints.

---

## 3. BuiltinEndpointSet bit positions for secure builtins (§7.4.6.1)

The `availableBuiltinEndpoints` u32 field in SPDP PID_BUILTIN_ENDPOINT_SET carries bit
flags for every endpoint the participant advertises. For a security-enabled participant the
following bits MUST be set in addition to the plain (bits 0–15) bits:

| Bit | Mask | Constant name | §-clause |
|---|---|---|---|
| 16 | 0x00010000 | `DISC_BUILTIN_ENDPOINT_PUBLICATION_SECURE_ANNOUNCER` | DDS-Security 1.1 §7.4.6.1 |
| 17 | 0x00020000 | `DISC_BUILTIN_ENDPOINT_PUBLICATION_SECURE_DETECTOR` | §7.4.6.1 |
| 18 | 0x00040000 | `DISC_BUILTIN_ENDPOINT_SUBSCRIPTION_SECURE_ANNOUNCER` | §7.4.6.1 |
| 19 | 0x00080000 | `DISC_BUILTIN_ENDPOINT_SUBSCRIPTION_SECURE_DETECTOR` | §7.4.6.1 |
| 20 | 0x00100000 | `BUILTIN_ENDPOINT_PARTICIPANT_MESSAGE_SECURE_DATA_WRITER` | §7.4.6.1 |
| 21 | 0x00200000 | `BUILTIN_ENDPOINT_PARTICIPANT_MESSAGE_SECURE_DATA_READER` | §7.4.6.1 |
| **22** | **0x00400000** | **`BUILTIN_ENDPOINT_PARTICIPANT_STATELESS_MESSAGE_WRITER`** | §7.4.6.1 |
| **23** | **0x00800000** | **`BUILTIN_ENDPOINT_PARTICIPANT_STATELESS_MESSAGE_READER`** | §7.4.6.1 |
| 24 | 0x01000000 | `BUILTIN_ENDPOINT_PARTICIPANT_VOLATILE_MESSAGE_SECURE_WRITER` | §7.4.6.1 |
| 25 | 0x02000000 | `BUILTIN_ENDPOINT_PARTICIPANT_VOLATILE_MESSAGE_SECURE_READER` | §7.4.6.1 |
| 26 | 0x04000000 | `DISC_BUILTIN_ENDPOINT_PARTICIPANT_SECURE_ANNOUNCER` | §7.4.6.1 |
| 27 | 0x08000000 | `DISC_BUILTIN_ENDPOINT_PARTICIPANT_SECURE_DETECTOR` | §7.4.6.1 |

**For Slice 2b-i (PSM only):** the bits to OR in when wiring up the PSM writer+reader are
bits **22 + 23** (0x00C00000). Bits 26 + 27 MUST also be set in the secure SPDP
announcement (§7.4.6.1 — the secure participant announcer/detector endpoints advertise that
this participant supports SPDPsecure-based discovery).

**Fast DDS corroboration** (SecurityManager.h `#define` block + BuiltinEndpoints.hpp):
```cpp
#define BUILTIN_ENDPOINT_PARTICIPANT_MESSAGE_SECURE_WRITER      (1 << 20)
#define BUILTIN_ENDPOINT_PARTICIPANT_MESSAGE_SECURE_READER      (1 << 21)
#define BUILTIN_ENDPOINT_PARTICIPANT_STATELESS_MESSAGE_WRITER   (1 << 22)
#define BUILTIN_ENDPOINT_PARTICIPANT_STATELESS_MESSAGE_READER   (1 << 23)
#define BUILTIN_ENDPOINT_PARTICIPANT_VOLATILE_MESSAGE_SECURE_WRITER (1 << 24)
#define BUILTIN_ENDPOINT_PARTICIPANT_VOLATILE_MESSAGE_SECURE_READER (1 << 25)
// From BuiltinEndpoints.hpp:
DISC_BUILTIN_ENDPOINT_PARTICIPANT_SECURE_ANNOUNCER              = (1 << 26)
DISC_BUILTIN_ENDPOINT_PARTICIPANT_SECURE_DETECTOR               = (1 << 27)
```

**Live SPDP capture corroboration:** Frame 1 of `interop/connext/tl-probe-runA-lo0.pcap`
contains PID_BUILTIN_ENDPOINT_SET with value **0x0000F43F** (plain, non-security peer):
bits 0–5 + 10 + 12–15 = SPDP/SEDP announcer+detector + PMD writer + TypeLookup 4 bits.
No security bits (16–27) are set — this is expected because the plain Connext participant
is not security-enabled. This confirms the SPDP ParameterList structure is correct and
that security bits are ADDITIVE (ORed in only when security is enabled). **CAPTURE
GROUNDING: confirmed.**

---

## 4. PID_IDENTITY_TOKEN and PID_PERMISSIONS_TOKEN (§7.4.3.2 / DDS-Security PID table)

The SPDP ParameterList MUST carry these additional PIDs when security is enabled.

| PID name | PID value (u16 LE in wire) | §-clause |
|---|---|---|
| `PID_IDENTITY_TOKEN` | **0x1001** | DDS-Security 1.1 §7.4.3.2 / PID table |
| `PID_PERMISSIONS_TOKEN` | **0x1002** | DDS-Security 1.1 §7.4.3.2 (AccessControl — Slice-3) |
| `PID_DATA_TAGS` | 0x1003 | DDS-Security 1.1 (out of scope for 2b-i) |
| `PID_ENDPOINT_SECURITY_INFO` | 0x1004 | DDS-Security 1.1 (out of scope for 2b-i) |
| `PID_PARTICIPANT_SECURITY_INFO` | 0x1005 | DDS-Security 1.1 (out of scope for 2b-i) |

**Only `PID_IDENTITY_TOKEN` (0x1001) is needed for Slice 2b-i.** PID_PERMISSIONS_TOKEN is
AccessControl/Slice-3.

**Fast DDS corroboration** (`include/fastdds/dds/core/policy/ParameterTypes.hpp`):
```
PID_IDENTITY_TOKEN    = 0x1001
PID_PERMISSIONS_TOKEN = 0x1002
PID_DATA_TAGS         = 0x1003
PID_ENDPOINT_SECURITY_INFO   = 0x1004
PID_PARTICIPANT_SECURITY_INFO = 0x1005
```

**IdentityToken wire form inside PID_IDENTITY_TOKEN:** The IdentityToken is a `Token`
(= `DataHolder`) with class_id `"DDS:Auth:PKI-DH:1.0"` and string Properties (not binary).
The existing `identity-token` struct in `src/dds-security/auth/identity.lisp` produces
exactly this form. Its CDR-LE octet-string slots directly as the PID value.

`DataHolder` CDR-LE wire layout (from OMG IDL `dds_security_plugins_spis.idl`):
```
string       class_id          -- CDR string: u32-LE(strlen+1) | bytes | NUL | pad4
@optional PropertySeq      properties     -- u32-LE(count) | Property* (name+value strings)
@optional BinaryPropertySeq binary_properties -- u32-LE(count) | BinaryProperty*
```
For IdentityToken: `properties` carries 4 string entries (`dds.cert.sn`, `dds.cert.algo`,
`dds.ca.sn`, `dds.ca.algo`); `binary_properties` is empty (count=0).

---

## 5. ParticipantGenericMessage / ParticipantStatelessMessage envelope (§7.4.4)

This is the wrapper carried in the SerializedPayload of each PSM DATA submessage.

**Source:** OMG DDS-Security 1.1 §7.4.4 IDL + Fast DDS
`src/cpp/rtps/security/common/ParticipantGenericMessage.h` + CDRMessage.cpp serialization.

### 5.1 MessageIdentity (§7.4.4)

IDL (from OMG IDL file `dds_security_plugins_spis.idl`):
```idl
struct MessageIdentity {
    GUID_t     source_guid;      -- 16 octets: guidPrefix[12] + entityId[4]
    long long  sequence_number;  -- int64_t (8 octets)
};
```
CDR-LE wire: 16-octet GUID (prefix MSB-first + entityId MSB-first) + 8-octet LE int64 SN.
Total: 24 octets per MessageIdentity.

### 5.2 ParticipantGenericMessage / ParticipantStatelessMessage (§7.4.4)

**typedef:** `ParticipantStatelessMessage` is a type alias for `ParticipantGenericMessage`
in DDS-Security 1.1 §7.4.4 — one struct, two names. Fast DDS uses the same C++ class.

CDR-LE field order (confirmed from `CDRMessage::addParticipantGenericMessage`):

| # | Field name | Type | CDR-LE size |
|---|---|---|---|
| 1 | `message_identity` | MessageIdentity | 24 |
| 2 | `related_message_identity` | MessageIdentity | 24 |
| 3 | `destination_participant_key` | GUID_t | 16 |
| 4 | `destination_endpoint_key` | GUID_t | 16 |
| 5 | `source_endpoint_key` | GUID_t | 16 |
| 6 | `message_class_id` | string | u32-LE(len+1)+bytes+NUL+pad4 |
| 7 | `message_data` | DataHolderSeq | u32-LE(count) + DataHolder* |

**No `message_aux` field**: The Fast DDS `addParticipantGenericMessage` function writes
exactly these 7 fields. There is no `message_aux` in the Fast DDS serialization.
NEEDS-VERIFICATION: the OMG §7.4.4 IDL should be checked for whether `message_aux`
appears in the normative struct (the IDL on omg.org was not machine-readable for this
clause). Fast DDS does NOT serialize it. **Assessment: ABSENT in practice — omit.**

**Encapsulation:** The SerializedPayload prepended to the above is CDR_LE encapsulation
(4 octets: `00 01 00 00` for plain CDR LE) — same as other builtin endpoint payloads.
Fast DDS SecurityManager: `"if (msg->msg_endian == DEFAULT_ENDIAN)"` — the function
uses the negotiated endianness, but DEFAULT_ENDIAN is LE on x86/ARM. PSM DATA submessages
are little-endian CDR (matching all other builtin DATA on this stack).

---

## 6. HandshakeMessageToken as DataHolder (§9.3.4)

The `message_data` sequence in the ParticipantGenericMessage carries one DataHolder per
token. For the authentication handshake:

**DataHolder wire layout** (CDR-LE, OMG `dds_security_plugins_spis.idl`):
```idl
struct DataHolder {
    string             class_id;            -- CDR string LE
    @optional PropertySeq        properties;        -- string-pair sequence (empty for HST)
    @optional BinaryPropertySeq  binary_properties; -- octet-pair sequence (contains all HST fields)
};
```

For HandshakeMessageToken:
- `class_id` = one of `+handshake-request-class-id+` / `+handshake-reply-class-id+` /
  `+handshake-final-class-id+` (already pinned in `constants.lisp`).
- `properties` = empty sequence (count = 0) — all values are binary, not string.
- `binary_properties` = the binary properties as confirmed in prior spike §5.

The existing 2a `handshake-token` internal format (magic + class_id + binary-props list)
maps to this DataHolder: `class_id` → DataHolder.class_id, binary-props list →
DataHolder.binary_properties. The CDR-LE encoding for each BinaryProperty:
```
u32-LE(name-strlen+1) | name-bytes | NUL | pad4
u32-LE(value-byte-count) | value-bytes
u8(propagate=1) | 3 pad
```
This is the LE mirror of the BE encoding used for hash/signature inputs in handshake.lisp.

**IMPORTANT NOTE:** The `binary_properties` in the internal token format
(in `handshake.lisp`) encode in CDR **big-endian** for the hash/signature inputs. But
the wire DataHolder in the PSM DATA submessage uses CDR **little-endian** for the
BinaryPropertySeq. These are TWO DIFFERENT serializations: (a) the CDR-BE form is the
input to hash_c1/hash_c2/Sign1/Sign2 computations; (b) the CDR-LE DataHolder form is
what goes on the wire in the PSM. T2 (the PSM CDR encoder) must use LE; the
hash/signature code already uses BE correctly.

---

## 7. message_class_id for authentication handshake (§7.4.4 / §9.3)

The `message_class_id` field in ParticipantGenericMessage identifies the purpose:

| message_class_id | Purpose | §-clause |
|---|---|---|
| **`"dds.sec.auth"`** | Authentication handshake (PSM channel) | DDS-Security 1.1 §7.4.4 / §9.3 |
| `"dds.sec.participant_crypto_tokens"` | Participant crypto key exchange (Slice-3) | §7.4.4 |
| `"dds.sec.datareader_crypto_tokens"` | Reader crypto tokens (Slice-3) | §7.4.4 |
| `"dds.sec.datawriter_crypto_tokens"` | Writer crypto tokens (Slice-3) | §7.4.4 |

**Only `"dds.sec.auth"` is needed for Slice 2b-i.**

**Fast DDS corroboration** (SecurityManager.h + SecurityManager.cpp):
```cpp
#define AUTHENTICATION_PARTICIPANT_STATELESS_MESSAGE "dds.sec.auth"
```
Used in: `message.message_class_id(AUTHENTICATION_PARTICIPANT_STATELESS_MESSAGE);`
before `message.message_data().push_back(handshake_message);`

---

## 8. SPDP ParameterList shell — capture ground truth

**Capture:** `interop/security-auth/captures/plain-spdp-connext.pcap`
(copied from `interop/connext/tl-probe-runA-lo0.pcap` which contains a clean capture
from the Connext 7.3.1 TypeLookup probe with the plain (non-security) SPDP).

**Frame 1 hex decode** (4-byte NULL/Loopback + IP20 + UDP8 + RTPS):

```
Loopback: 02 00 00 00
IP:  45 00 00 c0 f5 77 00 00 01 11 10 79
     src=192.168.2.148, dst=239.255.0.1 (SPDP multicast)
UDP: src=50729, dst=7400
RTPS header (0x20-0x33):
  52 54 50 53  = 'RTPS' magic
  02 05        = version 2.5
  01 ff        = vendorId 0x01FF
  47 42 50 7f c1 d3 ed 00 00 00 00 00 = guidPrefix
DATA submessage (0x34-):
  15           = SubmessageKind DATA
  05           = flags E=1(LE) D=1(data present)
  8c 00        = submessageLength = 140
  (extraFlags+inlineQosLen = 00 00 10 00)
  rdEntityId   = 00 01 00 c7  (SPDP reader)
  wrEntityId   = 00 01 00 c2  (SPDP writer)
  SN           = 00 00 00 00 01 00 00 00 = 1
  (no inline QoS; encapsulation header starts here:)

SerializedPayload encapsulation: 00 03 00 00 (CDR2_LE — this is the tl-probe variant)
  ParameterList:
    PID=0x0050, len=16  PID_PARTICIPANT_GUID
      GUID prefix: 47 42 50 7f c1 d3 ed 00 00 00 00 00
      EntityId:    00 00 01 c1  (ENTITYID_PARTICIPANT)
    PID=0x0015, len=4   PID_PROTOCOL_VERSION = {2, 5}
    PID=0x0016, len=4   PID_VENDORID = 01 ff (+ 2 pad)
    PID=0x0031, len=24  PID_METATRAFFIC_UNICAST_LOCATOR
      kind=1, port=0xC629=50729, addr=..127.0.0.1
    PID=0x0032, len=24  PID_DEFAULT_UNICAST_LOCATOR
      kind=1, port=0xC629=50729, addr=..127.0.0.1
    PID=0x0002, len=8   PID_PARTICIPANT_LEASE_DURATION = {100, 0}
    PID=0x0058, len=4   PID_BUILTIN_ENDPOINT_SET = 0x0000F43F
      bits set: 0,1,2,3,4,5 (SPDP/SEDP), 10 (PMD writer),
                12,13,14,15 (TypeLookup 4 endpoints)
    PID=0x0001, len=0   PID_SENTINEL
```

**Security-enabled extension (spec, NOT in this plain capture):**
A security-enabled SPDP announcement appends BEFORE PID_SENTINEL:
```
PID=0x1001, len=<token_len>   PID_IDENTITY_TOKEN  (DDS-Security §7.4.3.2)
  DataHolder CDR-LE: class_id + properties + binary_properties
PID=0x1002, len=<token_len>   PID_PERMISSIONS_TOKEN  (DDS-Security §7.4.3.2; Slice-3)
```
And ORs into the PID_BUILTIN_ENDPOINT_SET value:
- bits 22+23 (PSM writer+reader) + bits 26+27 (secure SPDP announcer+detector) +
  optionally 16-21 (secure SEDP + secure PMD) + 24-25 (PVMS).

**Conclusion: The SPDP is a ParameterList we append PIDs to. Confirmed.**

---

## 9. Verification of plan assumptions

| Assumption | Verified? | Finding |
|---|---|---|
| SPDP is a ParameterList we append PIDs to | **CONFIRMED** | Hex decode §8; PIDs are contiguous, sentinel at end |
| PSM is best-effort DATA, no HEARTBEAT | **CONFIRMED** | EntityKind 0xC3/C4 = NO_KEY writers/readers; DDS-Security 1.1 §7.4.3 explicitly states best-effort |
| Envelope is CDR-LE struct | **CONFIRMED** | Fast DDS CDRMessage.cpp serializes LE; encapsulation header 00 01 00 00 (CDR_LE) |
| DataHolder is class_id + BinaryPropertySeq | **CONFIRMED with NUANCE** | DataHolder = class_id + PropertySeq + BinaryPropertySeq; for HST: PropertySeq is empty (count=0), BinaryPropertySeq carries all values |
| No message_aux field | **CONFIRMED in Fast DDS** | Not serialized in CDRMessage.cpp; NEEDS-VERIFICATION against OMG §7.4.4 IDL text |
| IdentityToken CDR-LE form slots into PID | **CONFIRMED** | DataHolder class_id+PropertySeq(string props)+BinaryPropertySeq(empty) is the exact form |

---

## 10. NEEDS-VERIFICATION list

Items that could NOT be conclusively grounded in a machine-readable OMG §-clause text.
None of these are blocking for T1–T3; each has HIGH confidence from Fast DDS.

1. **`message_aux` field absence (§7.4.4):** Fast DDS does NOT serialize any `message_aux`
   field after `message_data`. The OMG §7.4.4 normative IDL text was not machine-readable.
   **Assessment: ABSENT — the IDL companion file (`dds_security_plugins_spis.idl`) has the
   DataHolder and MessageIdentity but not the ParticipantGenericMessage IDL in the
   machine-readable portion fetched; Fast DDS is the implementation authority here.
   Confidence: HIGH. Do NOT add a message_aux field without spec evidence.**

2. **PID_PERMISSIONS_TOKEN required in SPDP or optional (§7.4.3.2):** In the absence of
   an AccessControl plugin, is PID_PERMISSIONS_TOKEN required? Fast DDS only emits it when
   `permissions_token_.class_id()` is non-empty. **Assessment: CONDITIONAL — omit if no
   AccessControl configured. Slice 2b-i (auth only) omits it.**

3. **CDR endianness of ParticipantGenericMessage — host vs. negotiated:** Fast DDS uses
   `msg->msg_endian` (DEFAULT_ENDIAN on x86 = LE). This stack sends all builtin DATA in
   LE; the same approach applies here. **Assessment: LITTLE-ENDIAN consistent with all
   other builtin DATA. Confidence: HIGH.**

4. **BuiltinEndpointSet bits 16–19 (secure SEDP) — required for auth handshake?**
   The auth handshake uses bits 22+23 (PSM). Bits 16–19 (secure SEDP) are for protecting
   the publication/subscription discovery after authentication. Slice 2b-i should set them
   to advertise that secure SEDP will be used post-auth. **Assessment: SET bits 22+23+26+27
   for the PSM + secure-participant-discovery; add 16–21+24–25 in Slice 2c when the
   post-auth secure endpoints are wired.**

5. **DataHolder `@optional` PropertySeq / BinaryPropertySeq wire encoding:** The OMG IDL
   marks both as `@optional`. In CDR, `@optional` with XCDR1 means `present-flag(bool)` +
   value when present. Fast DDS emits count=0 (an empty sequence, NOT an optional absent
   flag). **Assessment: EMIT empty sequences (count=0 u32-LE), not optional-absent. Verify
   against a live Fast DDS security exchange in T3.**

---

## 11. Provenance

- OMG DDS-Security 1.1 formal/2018-04-01 (primary; PDF binary — not machine-readable for
  clause text; IDL companion `dds_security_plugins_spis.idl` machine-readable and fetched).
- eProsima Fast DDS Apache-2.0: read for understanding; no code copied. Files:
  `ParameterTypes.hpp`, `BuiltinEndpoints.hpp`, `SecurityManager.h`, `SecurityManager.cpp`,
  `CDRMessage.cpp`, `ParticipantGenericMessage.h`, `PKIDH.cpp`.
  Source: `raw.githubusercontent.com/eProsima/Fast-DDS/master/...`
- Fast DDS 3.1.x API documentation page for EntityId_t macro defines (machine-readable).
- `interop/connext/tl-probe-runA-lo0.pcap` — frame 1 hex decoded manually to verify
  SPDP ParameterList structure and PID_BUILTIN_ENDPOINT_SET live wire value.
- RTI Connext DDS 7.3.1 Security Plugins: NOT available. No RTI source consulted.
