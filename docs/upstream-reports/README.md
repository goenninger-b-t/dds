# Upstream bug reports

Prepared, submittable bug reports for defects found in third-party DDS implementations
while validating cross-vendor interoperability. These are drafted here for review; the
outward submission to the upstream project is a manual action taken by the maintainer.

## eProsima Fast DDS

Tested against **Fast DDS v3.6.1** (git tag `v3.6.1`, commit `4e81e8b`). Submission target:
<https://github.com/eProsima/Fast-DDS/issues>.

| Report | Area | Summary | Status |
| --- | --- | --- | --- |
| [`eprosima-typeinfo-vendor-gate.md`](eprosima-typeinfo-vendor-gate.md) | Discovery / SEDP ProxyData | SEDP vendor gate silently drops the **standard** `PID_TYPE_INFORMATION` (0x0075) from non-eProsima peers (`WriterProxyData.cpp` / `ReaderProxyData.cpp`), breaking cross-vendor XTypes type discovery | Prepared; re-verified 2026-07-09 present on v3.6.1 + master — awaiting maintainer submission |
| [`eprosima-namehash-utf8.md`](eprosima-namehash-utf8.md) | XTypes dynamic types | `get_string_from_name_hash` streams `NameHash` `uint8_t` bytes as characters (the `std::hex` is a no-op), yielding non-UTF-8 member names that break `json_serialize` (`type_error.316`) | Prepared; re-verified 2026-07-09 present on v3.6.1 + master — awaiting maintainer submission |

Both defects were confirmed reproducible on v3.6.1 by source inspection and observed live
during interop testing. Each report notes that the maintainers should verify the defect is
still present on the latest `master` before triage. Both were originally documented, with
frame- and line-level evidence, in
[`docs/adr/0012-fastdds-peer-fr-io-2.md`](../adr/0012-fastdds-peer-fr-io-2.md) and
[`docs/provenance.md`](../provenance.md); the supporting captures live under
`interop/fastdds/captures/`.
