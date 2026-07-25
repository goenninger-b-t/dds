// mutable_pub — publish ONE deterministic @mutable sample repeatedly so the exact PL_CDR2
// SerializedPayload RTI Connext puts ON THE WIRE can be captured as a byte-exact reference vector
// (FR-CDR-8, ADR 0086).
//
// THE ORACLE IS THE WIRE, not a local CDR buffer. This deliberately does NOT call
// rti::topic::to_cdr_buffer: that returns a buffer which is neither padded to 4 nor carries the
// OPTIONS pad bits, and a corpus built from it once certified bytes that were provably malformed on
// the wire (ADR 0061 — a 1-octet sequence gave 13 unpadded octets there and 16 with options=0x0003
// on the wire). The vector is captured off our own receive path, exactly as scripts/capture-corpus.sh
// does for the FINAL type.
//
// What this is FOR: the length code a writer picks for a variable-width member is unfixed by the spec
// (XTypes 1.3 §7.4.3.4.2), so `label` and `vals` are the two members where Connext may legitimately
// differ from us — LC=5/LC=6 reusing NEXTINT as the member's own leading length, versus the LC=4 this
// stack emits. Whatever this publishes is what the vector says, and the vector wins.
//
// Usage: ./mutable_pub [domain=0]

#include <iostream>
#include <thread>
#include <chrono>
#include <cstdlib>

#include <dds/dds.hpp>
#include "MutableData.hpp"

int main(int argc, char **argv)
{
    const int domain = (argc > 1) ? std::atoi(argv[1]) : 0;

    dds::domain::DomainParticipant dp(domain);
    dds::topic::Topic<MutableData> topic(dp, "MutableCorpus");

    dds::pub::Publisher pub(dp);
    dds::pub::qos::DataWriterQos wqos = pub.default_datawriter_qos();
    wqos << dds::core::policy::Reliability::Reliable();
    dds::pub::DataWriter<MutableData> writer(pub, topic, wqos);

    MutableData sample;
    sample.a(1);
    sample.b(2);
    sample.label("hello");
    sample.t_ns(3);
    sample.vals(std::vector<int32_t>{7, 8, 9});

    std::cout
        << "[mut] publishing fixed MutableData{a=1,b=2,label=\"hello\",t_ns=3,vals=[7,8,9]}"
        << " on domain " << domain << "\n"
        << "[mut] extensibility=@mutable -> encapsulation PL_CDR2_LE 0x000b (XTypes 1.3 Table 60)\n"
        << "[mut] capture it off a receive path; do NOT use to_cdr_buffer (see the header comment).\n"
        << "[mut] the open question this answers: which LENGTH CODE Connext picks for `label` (string)\n"
        << "[mut]   and `vals` (sequence<long>) -- LC=4, or LC=5/6 reusing NEXTINT. Ctrl-C to stop.\n";

    for (;;) {
        writer.write(sample);
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
    return 0;
}
