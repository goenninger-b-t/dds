// large_pub — Connext publishes LargeData on topic "LargeData" (DATA_FRAG oracle).
// The QoS profile caps the UDPv4 message_size_max at 1400, so a multi-KB payload is
// fragmented by Connext into DATA_FRAG submessages; run with large_sub and capture lo0.
// Payload octet i = (i*7) mod 256, matching this stack's run-large-publisher pattern.
//
// Usage: ./large_pub [domain=0] [size=8000] [count=0]   (count 0 = run forever)

#include <iostream>
#include <thread>
#include <chrono>
#include <cstdlib>
#include <cstdint>

#include <dds/dds.hpp>
#include <rti/config/Logger.hpp>
#include "LargeData.hpp"

int main(int argc, char **argv)
{
    // Set CONNEXT_VERBOSE=1 to surface Connext's discovery/match decisions on stderr.
    if (std::getenv("CONNEXT_VERBOSE"))
        rti::config::Logger::instance().verbosity(rti::config::Verbosity::STATUS_ALL);

    const int domain = (argc > 1) ? std::atoi(argv[1]) : 0;
    const int size   = (argc > 2) ? std::atoi(argv[2]) : 8000;
    const int count  = (argc > 3) ? std::atoi(argv[3]) : 0;
    if (size <= 0) { // reject atoi garbage / negative payload sizes
        std::cerr << "usage: " << argv[0] << " [domain=0] [size=8000] [count=0]; size must be > 0\n";
        return 1;
    }

    dds::domain::DomainParticipant participant(domain);
    dds::topic::Topic<LargeData> topic(participant, "LargeData");

    dds::pub::Publisher publisher(participant);
    dds::pub::qos::DataWriterQos qos = publisher.default_datawriter_qos();
    qos << dds::core::policy::Reliability::Reliable();
    dds::pub::DataWriter<LargeData> writer(publisher, topic, qos);

    // Wait for a matched subscription so the first samples are not written into the void.
    for (int waited_ms = 0; dds::pub::matched_subscriptions(writer).empty(); waited_ms += 100) {
        if (waited_ms >= 30000) {
            std::cout << "[connext-large-pub] no matched subscription after 30 s; writing anyway.\n";
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    std::cout << "[connext-large-pub] LargeData domain=" << domain << " size=" << size
              << " (reliable, message_size_max=1400 => DATA_FRAG). Ctrl-C to stop.\n";

    LargeData sample;
    sample.payload().resize(size);
    for (int i = 0; i < size; ++i)
        sample.payload()[static_cast<size_t>(i)] = static_cast<uint8_t>((i * 7) & 0xff);

    int n = 0;
    for (;;) {
        sample.id(++n);
        writer.write(sample);
        if (n % 10 == 0)
            std::cout << "[connext-large-pub] sent " << n << " samples; size=" << size << "\n";
        if (count > 0 && n >= count) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(200)); // 5 Hz
    }
    // Async publish mode queues samples; flush before teardown or the last one is lost.
    try {
        writer.wait_for_acknowledgments(dds::core::Duration(5));
    } catch (const std::exception &e) {
        std::cout << "[connext-large-pub] wait_for_acknowledgments: " << e.what() << "\n";
    }
    std::cout << "[connext-large-pub] done; sent " << n << " sample(s).\n";
    return 0;
}
