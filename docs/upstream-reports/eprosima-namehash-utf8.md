# `get_string_from_name_hash` emits non-UTF-8 member names (the `std::hex` is a no-op on `uint8_t`)

- **Component:** XTypes dynamic types — `DynamicTypeBuilderFactoryImpl`
- **Fast DDS version:** 3.6.1 (git tag `v3.6.1`, commit `4e81e8b`; `package.xml` `<version>3.6.1</version>`, `CMakeLists.txt` `project(fastdds VERSION "3.6.1.0")`)
- **Platform observed:** Any platform (`uint8_t` == `unsigned char` everywhere); reproducible by inspection
- **Severity:** Correctness — produces malformed (non-UTF-8) member names; breaks downstream UTF-8 consumers such as `json_serialize`
- **Status:** Confirmed present on v3.6.1 by source inspection and a live symptom (`type_error.316` from the JSON serializer). Re-verified 2026-07-09: the defective body is byte-identical on both the pinned `v3.6.1` (`4e81e8b`) and current `master` (`<iomanip>` still absent), so it is not fixed upstream.

## Summary

`DynamicTypeBuilderFactoryImpl::get_string_from_name_hash` builds a printable member name from a 4-octet XTypes `NameHash` (used when a type is reconstructed from a **MINIMAL** `TypeObject`, which carries only the hash of each member name, not the name itself). The implementation intends to hex-encode the four bytes — it sets `std::hex` on the stream — but because a `NameHash` element is a `uint8_t` (i.e. `unsigned char`), the stream inserts each byte **as a character, not as a hexadecimal number**. `std::hex` has no effect on the character insertion overloads, so it is dead code.

The result is a string composed of the four **raw hash bytes** interpreted as characters. Since a `NameHash` is the truncation of a hash (SHA-256 / MD5 depending on context), its bytes are arbitrary: any byte `> 0x7F` (e.g. `0xDD`, `0xFF`) is not valid UTF-8, and a `0x00` byte embeds a NUL. The synthesized member name is therefore frequently a malformed, non-UTF-8 string. Downstream code that requires valid UTF-8 — notably Fast DDS's own `json_serialize` — then fails or produces mojibake.

## Root cause

**File:** `src/cpp/fastdds/xtypes/dynamic_types/DynamicTypeBuilderFactoryImpl.cpp` (lines ~1626–1637).

```cpp
// src/cpp/fastdds/xtypes/dynamic_types/DynamicTypeBuilderFactoryImpl.cpp  (Fast DDS v3.6.1)
std::string DynamicTypeBuilderFactoryImpl::get_string_from_name_hash(
        const xtypes::NameHash& name)
{
    std::stringstream ss;
    ss << std::hex;
    ss << name[0];
    for (size_t i {1}; i < name.size(); ++i)
    {
        ss << "." << name[i];
    }
    return ss.str();
}
```

`NameHash` is a 4-byte array of `uint8_t` (`include/fastdds/dds/xtypes/type_representation/detail/dds_xtypes_typeobject.hpp:130`, from IDL `typedef octet NameHash[4]`):

```cpp
typedef std::array<uint8_t, 4> NameHash;
```

The defect is a C++ streaming subtlety:

- `uint8_t` is an alias for `unsigned char` on all mainstream platforms.
- `std::basic_ostream::operator<<` has dedicated overloads for `char`, `signed char`, and `unsigned char` that write **one character** (the raw byte), independent of the stream's numeric base.
- The `std::hex` manipulator only affects the **integer** insertion overloads (`int`, `long`, …). It does nothing for the character overloads.

So `ss << std::hex << name[0]` writes the raw byte `name[0]` as a character; the `std::hex` is inert. The intended output (e.g. `"70.dd.a5.df"` for a hash `{0x70, 0xDD, 0xA5, 0xDF}`) is never produced; instead the function returns the four raw bytes separated by `.` — here `0x70` (`'p'`), `.`, `0xDD`, `.`, `0xA5`, `.`, `0xDF` — a string containing the non-UTF-8 bytes `0xDD 0xA5 0xDF`.

Corroborating evidence that hex-encoding was intended but never actually performed: the translation unit does **not** include `<iomanip>` and contains no `std::setw` / `std::setfill` / `static_cast<unsigned>` — the ingredients required to stream a `uint8_t` as two hex digits. The lone `ss << std::hex;` is the only trace of the intent, and it is a no-op.

## Impact

`get_string_from_name_hash` is the fallback that synthesizes a member **name** whenever only the name hash is available on the wire — i.e. for any type reconstructed from a MINIMAL `TypeObject`. It is called from many member kinds in the same file:

- structure/aggregate members (lines ~686, ~812)
- annotation parameters (line ~546)
- enumeration literals (line ~1218)
- bitmask bitflags (line ~1289)
- bitset bitfields (line ~900)
- verbatim/annotation parameter names (line ~1476)

Every such member ends up with a name that may contain non-UTF-8 bytes. The concrete downstream failures:

- **JSON serialization throws.** Fast DDS's `json_serialize` (`fastdds/dds/xtypes/utils.hpp`) requires valid UTF-8 for object keys / string values. A member name carrying bytes like `0xDD`/`0xFF` makes it raise `type_error.316` on every sample. We root-caused a live per-sample `json_serialize` `type_error.316` to exactly this: raw `NameHash` `uint8_t` bytes streamed through the `char` `operator<<` overload, yielding non-UTF-8 member names from a MINIMAL `TypeObject`. (Sample data deserialization itself is unaffected — the problem is confined to string/UTF-8 consumers of the synthesized name.)
- **Logging / tooling mojibake.** Any place that logs or renders the member name (error messages, IDL regeneration, monitoring) shows corrupted text; NUL bytes truncate C-string consumers.

## Steps to reproduce

1. Cause Fast DDS to reconstruct a `DynamicType` from a **MINIMAL** `TypeObject` whose member `NameHash` contains at least one byte `> 0x7F` — this is the normal case, since a `NameHash` is a hash truncation and roughly half of all bytes are `≥ 0x80`. For example a member whose name hashes to `{0x70, 0xDD, 0xA5, 0xDF}`.
2. Inspect the resulting `MemberDescriptor::name()` — it contains the raw bytes `0x70 0x2E 0xDD 0x2E 0xA5 0x2E 0xDF`, which is not valid UTF-8 (bytes `0xDD`, `0xA5`, `0xDF` are ill-formed here).
3. Call `json_serialize` on a sample of that type (or otherwise route the name through a UTF-8-requiring consumer). It raises `type_error.316`.

## Expected vs actual

- **Expected:** A `NameHash` is opaque bytes and must be rendered as an unambiguous, always-valid-ASCII representation — e.g. hex-encoded (`"70.dd.a5.df"` or `"70dda5df"`). The result must always be valid UTF-8.
- **Actual:** The four raw bytes are inserted as characters (the `std::hex` is ignored), producing a frequently non-UTF-8, non-printable string.

## Suggested fix

Cast each element to an unsigned integer type before insertion so the numeric hex formatting actually applies, and zero-pad to two digits. Add `#include <iomanip>`:

```cpp
#include <iomanip>
// ...
std::string DynamicTypeBuilderFactoryImpl::get_string_from_name_hash(
        const xtypes::NameHash& name)
{
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    ss << std::setw(2) << static_cast<unsigned>(name[0]);
    for (size_t i {1}; i < name.size(); ++i)
    {
        ss << "." << std::setw(2) << static_cast<unsigned>(name[i]);
    }
    return ss.str();
}
```

This yields a stable, always-valid-UTF-8 name such as `"70.dd.a5.df"`. (The exact separator/format is a cosmetic choice; the essential fix is to treat the hash as opaque bytes and hex-encode via an integer cast rather than inserting `uint8_t` as characters.) Consider factoring this into a small shared hash-to-hex helper if other call sites render `NameHash`/`EquivalenceHash` values.
