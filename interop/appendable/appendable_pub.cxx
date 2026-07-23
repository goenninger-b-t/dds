// appendable_pub — Connext publishes an animated Square as an @appendable ShapeType on
// topic "Square". Interop Leg 1 (cross-DDS half), OUT direction: run this and verify NeoDDS
// receives it via  make square-sub TYPE=appendable.
//
// The point: a real Connext writer of an @appendable type puts D_CDR2_LE 0x0009 + a DHEADER on the
// wire (XTypes 1.3 Table 60 + rule (30)). Our self-leg confirmed OUR writer does; this proves an
// independent vendor agrees, and that our reader accepts a foreign appendable sample.
//
// Usage: ./appendable_pub [domain=0] [color=BLUE] [shapesize=30]
// Env:   SHAPESIZE overrides the shapesize; CONNEXT_VERBOSE=1 surfaces discovery/match on stderr.

#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <cstdlib>

#include <dds/dds.hpp>
#include <rti/config/Logger.hpp>
#include "AppendableShape.hpp"

int main(int argc, char **argv)
{
    if (std::getenv("CONNEXT_VERBOSE"))
        rti::config::Logger::instance().verbosity(rti::config::Verbosity::STATUS_ALL);

    const int   domain    = (argc > 1) ? std::atoi(argv[1]) : 0;
    const std::string color = (argc > 2) ? argv[2] : "BLUE";
    const char* szenv     = std::getenv("SHAPESIZE");
    const int   shapesize = szenv ? std::atoi(szenv) : ((argc > 3) ? std::atoi(argv[3]) : 30);

    dds::domain::DomainParticipant participant(domain);
    dds::topic::Topic<ShapeType> topic(participant, "Square");

    dds::pub::Publisher publisher(participant);
    dds::pub::qos::DataWriterQos qos = publisher.default_datawriter_qos();
    qos << dds::core::policy::Reliability::Reliable();
    dds::pub::DataWriter<ShapeType> writer(publisher, topic, qos);

    std::cout << "[connext-pub] Square/" << topic.type_name() << " (@appendable) color=" << color
              << " size=" << shapesize << " domain=" << domain
              << " (reliable). Ctrl-C to stop.\n";

    ShapeType sample;
    sample.color(color);
    sample.shapesize(shapesize);
    int x = 50, y = 50, dx = 3, dy = 2;
    for (;;) {
        x += dx; y += dy;
        if (x >= 240 || x <= 10) dx = -dx;
        if (y >= 260 || y <= 10) dy = -dy;
        sample.x(x);
        sample.y(y);
        writer.write(sample);
        std::this_thread::sleep_for(std::chrono::milliseconds(33)); // ~30 Hz
    }
    return 0;
}
