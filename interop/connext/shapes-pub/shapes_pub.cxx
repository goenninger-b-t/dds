// shapes_pub — Connext publishes an animated Square (ShapeType) on topic "Square".
// Interop OUT-direction oracle: run this and verify this stack receives it via
//   make square-sub          (or a DCPS DataReader on Square/ShapeType).
// Also interoperates with RTI rtishapesdemo (the bounded-vs-unbounded string color
// difference is absorbed by type coercion; see ../common/ShapeType.idl).
//
// Usage: ./shapes_pub [domain=0] [color=BLUE] [shapesize=30]

#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <cstdlib>

#include <dds/dds.hpp>
#include "ShapeType.hpp"

int main(int argc, char **argv)
{
    const int   domain    = (argc > 1) ? std::atoi(argv[1]) : 0;
    const std::string color = (argc > 2) ? argv[2] : "BLUE";
    const int   shapesize = (argc > 3) ? std::atoi(argv[3]) : 30;

    dds::domain::DomainParticipant participant(domain);
    dds::topic::Topic<ShapeType> topic(participant, "Square");

    dds::pub::Publisher publisher(participant);
    dds::pub::qos::DataWriterQos qos = publisher.default_datawriter_qos();
    qos << dds::core::policy::Reliability::Reliable();
    dds::pub::DataWriter<ShapeType> writer(publisher, topic, qos);

    std::cout << "[connext-pub] Square/" << topic.type_name() << " color=" << color
              << " domain=" << domain << " (reliable). Ctrl-C to stop.\n";

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
