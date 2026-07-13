// Byte-exact XCDR corpus GENERATOR (FR-CDR-8, make corpus).
//
// Emits RTI Connext's own SerializedPayload bytes for a set of known PerfData samples, one .bin per
// case, plus a manifest. Our codec must reproduce these byte-for-byte — Connext is the reference
// encoder, so the corpus is an ORACLE EXTERNAL TO THIS PROJECT rather than a recording of our own
// output. Clean-room: public Connext Modern C++ API only (rti::topic::to_cdr_buffer); no RTI source or
// rtiddsgen output is copied into the repo — only the resulting BYTES, which are the OMG-specified wire
// encoding, not RTI's code.
//
// The sequence<octet> lengths are chosen to sweep the 4-byte alignment classes (len mod 4 = 0,1,2,3),
// because that is exactly the dimension our whole live-interop suite was blind to: every Shapes type ends
// on a 4-byte member, so the SerializedPayload trailing pad was never exercised and a real conformance
// defect (pad counted in the OPTIONS bits but never emitted — ADR 0061) survived a green 563-test suite,
// a byte-exact vector suite, and two tests that actively asserted it.
//
//   ./dump_vectors <out-dir>

#include <cstdio>
#include <cstdint>
#include <string>
#include <vector>
#include <fstream>
#include <rti/topic/cdr.hpp>
#include "PerfData.hpp"

namespace {

// The payload byte at index i, fixed by rule so the Lisp side can regenerate it without shipping the data.
uint8_t payload_byte(size_t i) { return static_cast<uint8_t>(i & 0xff); }

bool dump_case(const std::string& dir, int32_t id, size_t len, std::ostream& manifest)
{
    PerfData s;
    s.id(id);
    std::vector<uint8_t> data(len);
    for (size_t i = 0; i < len; ++i) data[i] = payload_byte(i);
    s.data(data);

    // XCDR2 (the representation our writers offer by default).
    std::vector<char> buf;
    rti::topic::to_cdr_buffer(buf, s, dds::core::policy::DataRepresentation::xcdr2());

    char name[128];
    std::snprintf(name, sizeof(name), "perfdata-id%d-len%zu.bin", id, len);
    const std::string path = dir + "/" + name;

    std::ofstream out(path, std::ios::binary);
    if (!out) { std::fprintf(stderr, "cannot write %s\n", path.c_str()); return false; }
    out.write(buf.data(), static_cast<std::streamsize>(buf.size()));
    out.close();

    // manifest: name id len payload-len(bytes of the serialized payload)
    manifest << name << " " << id << " " << len << " " << buf.size() << "\n";
    std::printf("  %-28s id=%-3d len=%-6zu payload=%zu octets (len mod 4 = %zu)\n",
                name, id, len, buf.size(), len % 4);
    return true;
}

}  // namespace

int main(int argc, char* argv[])
{
    const std::string dir = (argc > 1) ? argv[1] : ".";
    std::ofstream manifest(dir + "/manifest.txt");
    if (!manifest) { std::fprintf(stderr, "cannot write manifest in %s\n", dir.c_str()); return 1; }
    manifest << "# name id seq-len payload-octets   (RTI Connext 7.3.1, XCDR2, PerfData)\n";

    std::printf("XCDR corpus (RTI Connext 7.3.1 is the reference encoder), XCDR2:\n");

    // Sweep the alignment classes: a sequence<octet> of length L leaves the body 4-aligned only when
    // (4 + L) mod 4 == 0, i.e. L mod 4 == 0. 1/2/3/5/7/255 are precisely the cases that were malformed.
    const size_t lens[] = {0, 1, 2, 3, 4, 5, 7, 8, 15, 16, 63, 64, 255, 256, 257, 1023, 1024};
    bool ok = true;
    for (size_t len : lens) ok = dump_case(dir, 1, len, manifest) && ok;
    // a couple of non-1 keys, to pin the key member's encoding too
    ok = dump_case(dir, 0, 3, manifest) && ok;
    ok = dump_case(dir, -7, 5, manifest) && ok;
    ok = dump_case(dir, 2147483647, 6, manifest) && ok;

    manifest.close();
    return ok ? 0 : 1;
}
