// cdr_capture — publish ONE deterministic ShapeType sample repeatedly so the exact XCDR
// SerializedPayload can be captured with tshark, giving a byte-exact reference vector for
// FR-CDR-8. A co-located reader prints the decoded fields to confirm the round-trip.
//   sample = { color="RED", x=1, y=2, shapesize=3 }
// Usage: ./cdr_capture [domain=0]

#include <iostream>
#include <thread>
#include <chrono>
#include <cstdlib>

#include <dds/dds.hpp>
#include "ShapeType.hpp"

int main(int argc, char **argv)
{
    const int domain = (argc > 1) ? std::atoi(argv[1]) : 0;

    dds::domain::DomainParticipant dp(domain);
    dds::topic::Topic<ShapeType> topic(dp, "Square");

    dds::pub::Publisher pub(dp);
    dds::pub::qos::DataWriterQos wqos = pub.default_datawriter_qos();
    wqos << dds::core::policy::Reliability::Reliable();
    dds::pub::DataWriter<ShapeType> writer(pub, topic, wqos);

    dds::sub::Subscriber sub(dp);
    dds::sub::qos::DataReaderQos rqos = sub.default_datareader_qos();
    rqos << dds::core::policy::Reliability::Reliable();
    dds::sub::DataReader<ShapeType> reader(sub, topic, rqos);

    ShapeType sample;
    sample.color("RED");
    sample.x(1);
    sample.y(2);
    sample.shapesize(3);

    std::cout
        << "[cdr] publishing fixed ShapeType{color=RED,x=1,y=2,shapesize=3} on domain " << domain << "\n"
        << "[cdr] capture the SerializedPayload:  tshark -i lo -O rtps -V | grep -A20 serializedData\n"
        << "[cdr] expected XCDR body (after the 4-byte encapsulation header):\n"
        << "[cdr]   04 00 00 00 52 45 44 00 01 00 00 00 02 00 00 00 03 00 00 00\n"
        << "[cdr]   (len=4 'RED\\0' | x=1 | y=2 | shapesize=3) -- matches this stack's XCDR2 body.\n"
        << "[cdr] Connext may use encap id CDR_LE (00 01) vs our CDR2_LE (00 07); the BODY is\n"
        << "[cdr]   identical for this final 32-bit/string type. Ctrl-C to stop.\n";

    for (;;) {
        writer.write(sample);
        dds::sub::LoanedSamples<ShapeType> samples = reader.take();
        for (const auto &s : samples) {
            if (!s.info().valid()) continue;
            const ShapeType &d = s.data();
            std::cout << "[cdr] round-trip: color=" << d.color() << " x=" << d.x()
                      << " y=" << d.y() << " size=" << d.shapesize() << "\n";
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
    return 0;
}
