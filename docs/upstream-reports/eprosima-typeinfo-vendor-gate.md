# SEDP vendor gate silently drops the standard `PID_TYPE_INFORMATION` (0x0075) from non-eProsima peers

- **Component:** Discovery (SEDP) / ProxyData parameter-list deserialization
- **Fast DDS version:** 3.6.1 (git tag `v3.6.1`, commit `4e81e8b`; `package.xml` `<version>3.6.1</version>`, `CMakeLists.txt` `project(fastdds VERSION "3.6.1.0")`)
- **Platform observed:** Linux/macOS, built from source; reproducible by inspection on any platform
- **Severity:** Interoperability defect — breaks standard cross-vendor XTypes type discovery
- **Status:** Confirmed reproducible on v3.6.1 by source inspection and a live cross-vendor capture. Re-verified 2026-07-09: the vendor-gate block is byte-identical on both the pinned `v3.6.1` (`4e81e8b`) and current `master` (`WriterProxyData.cpp` + `ReaderProxyData.cpp`), so it is not fixed upstream.

## Summary

When Fast DDS deserializes a remote endpoint's SEDP announcement (`DiscoveredWriterData` / `DiscoveredReaderData`), the handler for `PID_TYPE_INFORMATION` (parameter id `0x0075`) is guarded by a vendor check that **only accepts eProsima** as the announcing vendor. Any endpoint whose resolved `vendorId` is not eProsima's (`01 0f`) has its `PID_TYPE_INFORMATION` parameter **silently ignored**.

`PID_TYPE_INFORMATION` is a **standard OMG DDS-XTypes 1.3 parameter**, not an eProsima extension. Gating it by `vendorId` means a fully conformant non-eProsima peer that advertises its `TypeInformation` in SEDP — exactly as the specification prescribes — has that information discarded. As a consequence Fast DDS never triggers its TypeLookup client for that remote endpoint, and complete-type discovery / `DynamicType` reconstruction / XTypes type-compatibility all fail cross-vendor, even though the peer did everything correctly.

## Root cause

**File:** `src/cpp/rtps/builtin/data/WriterProxyData.cpp`, in `WriterProxyData::read_from_cdr_message(...)` (lines ~1074–1096). The identical block exists in `src/cpp/rtps/builtin/data/ReaderProxyData.cpp` (lines ~1076–1098).

```cpp
// src/cpp/rtps/builtin/data/WriterProxyData.cpp  (Fast DDS v3.6.1)
case fastdds::dds::PID_TYPE_INFORMATION:
{
    VendorId_t local_vendor_id = source_vendor_id;
    if (c_VendorId_Unknown == local_vendor_id)
    {
        local_vendor_id = ((c_VendorId_Unknown == vendor_id) ? c_VendorId_eProsima : vendor_id);
    }

    // Ignore this PID when coming from other vendors
    if (c_VendorId_eProsima != local_vendor_id)
    {
        EPROSIMA_LOG_INFO(RTPS_PROXY_DATA,
                "Ignoring PID" << pid << " from vendor " << local_vendor_id);
        return true;
    }

    if (!dds::QosPoliciesSerializer<dds::xtypes::TypeInformationParameter>::
            read_from_cdr_message(type_information, msg, plength))
    {
        return false;
    }
    break;
}
```

The gating condition is `c_VendorId_eProsima != local_vendor_id`: if the resolved vendor is anything other than eProsima, the handler returns early and the parameter's payload is never parsed into `type_information`. `return true` means "continue parsing the rest of the parameter list", so the drop is silent — there is no warning, and no configuration option disables it.

How `local_vendor_id` resolves (same file, lines ~770–792): `read_from_cdr_message` receives `source_vendor_id`; a local `vendor_id` is initialized to it and then overwritten if the parameter list itself carries `PID_VENDORID` (0x0016):

```cpp
bool WriterProxyData::read_from_cdr_message(CDRMessage_t* msg, fastdds::rtps::VendorId_t source_vendor_id)
{
    auto param_process = [this, source_vendor_id](CDRMessage_t* msg, const ParameterId_t& pid, uint16_t plength)
        {
            VendorId_t vendor_id = source_vendor_id;
            switch (pid)
            {
                case fastdds::dds::PID_VENDORID:
                {
                    ParameterVendorId_t p(pid, plength);
                    if (!dds::ParameterSerializer<ParameterVendorId_t>::read_from_cdr_message(p, msg, plength)) { return false; }
                    vendor_id = p.vendorId;
                    break;
                }
                // ...
```

The vendor constants are (`include/fastdds/rtps/common/VendorId_t.hpp:34-37`):

```cpp
const VendorId_t c_VendorId_Unknown     = {0x00, 0x00};
const VendorId_t c_VendorId_eProsima    = {0x01, 0x0F};
// ...
const VendorId_t c_VendorId_rti_connext = {0x01, 0x01};
```

So for any real non-eProsima peer (RTI Connext `01 01`, Cyclone DDS, OpenDDS, or any other conformant vendor) `local_vendor_id` resolves to that foreign vendor and the standard `PID_TYPE_INFORMATION` is dropped.

## Why this is incorrect (the PID is standard, not vendor-specific)

`PID_TYPE_INFORMATION = 0x0075` is defined by **OMG DDS-XTypes 1.3** (formal/2020-02-04) as a standard, optional member of the extended built-in topic data used in endpoint discovery. It lives in the **OMG standard parameter-id range** (`< 0x8000`), not the vendor-specific range. For reference, the standard IDL for the discovery built-in topic data assigns it as:

```idl
// DDS-XTypes 1.3, Publication/Subscription/Topic BuiltinTopicData
@id(0x0075) @optional XTypes::TypeInformation type_information;
```

Fast DDS's own parameter-id enumeration reflects the standard-vs-vendor split (`include/fastdds/dds/core/policy/ParameterTypes.hpp`):

```cpp
PID_TYPE_INFORMATION      = 0x0075,   // standard OMG range (< 0x8000)
// ...
PID_PRODUCT_VERSION       = 0x8000,   // vendor-specific range begins here
PID_DISABLE_POSITIVE_ACKS = 0x8005,   // vendor-specific
```

Per OMG DDSI-RTPS 2.5, the parameter-id range `0x8000`–`0xFFFF` is reserved for vendor-specific parameters; the range below `0x8000` is standardized by OMG and must be interpreted uniformly regardless of the announcing vendor. Vendor-gating a **standard** PID is therefore a category error.

This is underscored by the neighboring case in the same switch, `PID_DISABLE_POSITIVE_ACKS` (a genuinely vendor-specific PID at `0x8005`), which is vendor-gated but at least whitelists **both** eProsima and RTI Connext:

```cpp
// Ignore custom PID when coming from other vendors except RTI Connext
if ((c_VendorId_eProsima != local_vendor_id) &&
        (fastdds::rtps::c_VendorId_rti_connext != local_vendor_id))
{
    // ...ignore...
    return true;
}
```

The vendor gate is thus applied deliberately and knowingly to vendor-specific PIDs — but it was mistakenly extended to the standard `0x0075` and narrowed to eProsima-only.

## Impact

A conformant non-eProsima DDS implementation that publishes XTypes `TypeInformation` in its SEDP announcements (the standard mechanism for propagating type identifiers so peers can fetch full `TypeObject`s via the TypeLookup service) is treated by Fast DDS as if it had advertised no type information at all:

- Fast DDS stores no `TypeInformation` for the remote endpoint, so it never initiates `getTypeDependencies` / `getTypes` against that peer. Cross-vendor **complete-type discovery and `DynamicType` reconstruction do not happen**.
- XTypes **type-assignability / type-compatibility** checks that rely on the remote `TypeInformation` cannot run cross-vendor.
- The failure is silent (an `INFO`-level "Ignoring PID..." log at most), so it presents as an unexplained absence of remote type information rather than an error, which is difficult to diagnose from the outside.

Data-sample delivery can still succeed when endpoints match purely by topic-name and type-name equality, which is why the defect is easy to miss; but any feature that depends on the discovered `TypeInformation` is broken for every non-eProsima peer.

## Steps to reproduce

1. Run a **non-eProsima** DDS participant (any vendor, or a minimal RTPS peer) that creates a DataWriter and includes a standard `PID_TYPE_INFORMATION` (0x0075) parameter carrying a valid XTypes `TypeInformation` in its SEDP `DiscoveredWriterData`. Ensure its announced `vendorId` (via `PID_VENDORID` and/or the participant's vendor) is **not** `01 0f`.
2. Run a Fast DDS 3.6.1 participant with a matching DataReader on the same topic/type.
3. Capture SEDP on the wire (Wireshark/tshark RTPS dissector) and confirm the writer announcement contains `PID_TYPE_INFORMATION` (0x0075) with a well-formed value.
4. Observe on the Fast DDS side that the remote endpoint's `type_information` is empty and that no TypeLookup request (`getTypeDependencies`/`getTypes`) is issued toward the peer. With `INFO` logging enabled you will see `Ignoring PID... from vendor ...`.

### Observed live (our cross-vendor interop)

We encountered this while validating interop between Fast DDS 3.6.1 and an independent (non-eProsima) DDS/RTPS implementation:

- Stock Fast DDS 3.6.1: our writer's SEDP carries a well-formed 92-octet `PID_TYPE_INFORMATION` (0x0075) value; Fast DDS's TypeLookup client never fires (the parameter is dropped by the gate).
- As a **local diagnostic only**, neutralizing the gate with a one-line change (`if (false && c_VendorId_eProsima != local_vendor_id)`) in `WriterProxyData.cpp`/`ReaderProxyData.cpp` made Fast DDS's client consume the same value (`assigned=1`) and proceed to issue `getTypeDependencies` — confirming the gate is the sole cause. The stock behavior was then restored and re-verified.

## Expected vs actual

- **Expected:** `PID_TYPE_INFORMATION` (0x0075), being a standard OMG DDS-XTypes parameter, is parsed regardless of the announcing `vendorId`.
- **Actual:** It is parsed only when the resolved `vendorId` equals eProsima's `01 0f`; for every other vendor it is silently discarded.

## Suggested fix

Do not vendor-gate a standard OMG parameter. In both `WriterProxyData::read_from_cdr_message` and `ReaderProxyData::read_from_cdr_message`, remove the vendor check from the `PID_TYPE_INFORMATION` case and parse the value unconditionally:

```cpp
case fastdds::dds::PID_TYPE_INFORMATION:
{
    if (!dds::QosPoliciesSerializer<dds::xtypes::TypeInformationParameter>::
            read_from_cdr_message(type_information, msg, plength))
    {
        return false;
    }
    break;
}
```

Reserve vendor gating for genuinely eProsima-proprietary parameters in the vendor-specific `0x8000`–`0xFFFF` range. If some historical interop concern motivated the gate, consider making it opt-in rather than the unconditional default, so standard cross-vendor XTypes discovery works out of the box.
