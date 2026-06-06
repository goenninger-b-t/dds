// typeobject_probe — put a Connext ShapeType on the wire so its SEDP announcement (carrying
// PID_TYPE_INFORMATION with the EquivalenceHash-based TypeIdentifier) can be captured and
// compared against THIS stack's provisional serializer output. The captured 14-byte hash is
// the oracle for src/dds-types/typeobject-cdr.lisp.
//
// It creates a matched ShapeType writer + reader (two participants, one process) so discovery
// definitely happens, prints the type name + our expected hash, and idles for tshark.
//
// Authoritative extraction (uses the same RTPS dissector as this repo's `make wire`):
//   tshark -i lo  -O rtps -V | grep -A60 'PID_TYPE_INFORMATION'      # Linux loopback
//   tshark -i lo0 -O rtps -V | grep -A60 'PID_TYPE_INFORMATION'      # macOS loopback
//   ...or run RTI's `rtiddsspy -printSample` against this process.

#include <iostream>
#include <thread>
#include <chrono>
#include <cstdlib>

#include <dds/dds.hpp>
#include "ShapeType.hpp"

int main(int argc, char **argv)
{
    const int domain = (argc > 1) ? std::atoi(argv[1]) : 0;

    dds::domain::DomainParticipant dp1(domain);
    dds::domain::DomainParticipant dp2(domain);
    dds::topic::Topic<ShapeType> t1(dp1, "Square");
    dds::topic::Topic<ShapeType> t2(dp2, "Square");

    dds::pub::qos::DataWriterQos wqos = dds::pub::Publisher(dp1).default_datawriter_qos();
    wqos << dds::core::policy::Reliability::Reliable();
    dds::pub::DataWriter<ShapeType> writer(dds::pub::Publisher(dp1), t1, wqos);

    dds::sub::qos::DataReaderQos rqos = dds::sub::Subscriber(dp2).default_datareader_qos();
    rqos << dds::core::policy::Reliability::Reliable();
    dds::sub::DataReader<ShapeType> reader(dds::sub::Subscriber(dp2), t2, rqos);

    std::cout
        << "[probe] ShapeType type_name='" << t1.type_name() << "' on domain " << domain << "\n"
        << "[probe] this stack's PROVISIONAL EquivalenceHash for ShapeType:\n"
        << "[probe]   BF E2 A6 2E D8 11 AC 46 3C 40 C9 7D 30 EE   (TypeObject = 87 bytes, no encap header)\n"
        << "[probe] capture Connext's SEDP to read its hash + compare:\n"
        << "[probe]   tshark -i lo -O rtps -V | grep -A60 'PID_TYPE_INFORMATION'   (lo0 on macOS)\n"
        << "[probe] idling so discovery stays on the wire; Ctrl-C to stop.\n";

    // Keep one sample flowing so a late tshark/rtiddsspy still sees DATA + discovery.
    ShapeType sample;
    sample.color("BLUE");
    sample.x(50); sample.y(50); sample.shapesize(30);
    for (;;) {
        writer.write(sample);
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    return 0;
}
