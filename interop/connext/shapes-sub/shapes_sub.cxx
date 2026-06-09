// shapes_sub — Connext subscribes to Square (ShapeType) and prints received samples.
// Interop IN-direction oracle: run this and publish from this stack via
//   make square-pub          (or a DCPS DataWriter on Square/ShapeType).
// A received, correctly-decoded sample proves this stack's XCDR payload + RTPS reliable
// data plane are wire-correct for Connext (FR-IO-1, FR-CDR-8).
//
// Usage: ./shapes_sub [domain=0] [seconds=0]   (seconds 0 = run forever)

#include <iostream>
#include <thread>
#include <chrono>
#include <cstdlib>

#include <dds/dds.hpp>
#include <rti/config/Logger.hpp>
#include "ShapeType.hpp"

int main(int argc, char **argv)
{
    if (std::getenv("CONNEXT_VERBOSE"))
        rti::config::Logger::instance().verbosity(rti::config::Verbosity::STATUS_ALL);

    const int domain  = (argc > 1) ? std::atoi(argv[1]) : 0;
    const int seconds = (argc > 2) ? std::atoi(argv[2]) : 0;

    dds::domain::DomainParticipant participant(domain);
    dds::topic::Topic<ShapeType> topic(participant, "Square");

    dds::sub::Subscriber subscriber(participant);
    dds::sub::qos::DataReaderQos qos = subscriber.default_datareader_qos();
    qos << dds::core::policy::Reliability::Reliable();
    dds::sub::DataReader<ShapeType> reader(subscriber, topic, qos);

    std::cout << "[connext-sub] Square/" << topic.type_name() << " domain=" << domain
              << " (reliable). Ctrl-C to stop.\n";

    const auto start = std::chrono::steady_clock::now();
    long count = 0;
    for (;;) {
        dds::sub::LoanedSamples<ShapeType> samples = reader.take();
        for (const auto &s : samples) {
            if (!s.info().valid()) continue;
            const ShapeType &d = s.data();
            std::cout << "[connext-sub] #" << ++count << " color=" << d.color()
                      << " x=" << d.x() << " y=" << d.y()
                      << " size=" << d.shapesize() << "\n";
        }
        if (seconds > 0 &&
            std::chrono::steady_clock::now() - start > std::chrono::seconds(seconds)) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    std::cout << "[connext-sub] received " << count << " sample(s).\n";
    return 0;
}
