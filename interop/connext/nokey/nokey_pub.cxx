// nokey_pub — Connext publishes a keyless NoKeyData sample on topic "NoKeyTopic".
// No-key endpoint-kinds OUT direction: run this and verify this stack receives it via
//   make nokey-sub
// The keyless IDL makes Connext register a NO_KEY DataWriter (RTPS 2.5 §9.3.1.2 kind
// 0x03). The 3-arg Topic constructor pins the registered type name to "nokey-data"
// so it is byte-identical to this stack's registered type-name (discovery matches on
// topic name + type name).
//
// Usage: ./nokey_pub [domain=0] [count=0]   (count 0 = run forever)

#include <iostream>
#include <thread>
#include <chrono>
#include <cstdlib>

#include <dds/dds.hpp>
#include <rti/config/Logger.hpp>
#include "NoKeyData.hpp"

int main(int argc, char **argv)
{
    if (std::getenv("CONNEXT_VERBOSE"))
        rti::config::Logger::instance().verbosity(rti::config::Verbosity::STATUS_ALL);

    const int domain = (argc > 1) ? std::atoi(argv[1]) : 0;
    const int count  = (argc > 2) ? std::atoi(argv[2]) : 0;

    dds::domain::DomainParticipant participant(domain);
    dds::topic::Topic<NoKeyData> topic(participant, "NoKeyTopic", "nokey-data");

    dds::pub::Publisher publisher(participant);
    dds::pub::qos::DataWriterQos qos = publisher.default_datawriter_qos();
    qos << dds::core::policy::Reliability::Reliable();
    dds::pub::DataWriter<NoKeyData> writer(publisher, topic, qos);

    std::cout << "[connext-nokey-pub] NoKeyTopic/" << topic.type_name()
              << " domain=" << domain << " (NO_KEY, reliable). Ctrl-C to stop.\n";

    NoKeyData sample;
    int n = 0;
    for (;;) {
        ++n;
        sample.a(n);
        sample.b(n * 10);
        writer.write(sample);
        std::cout << "[connext-nokey-pub] sent #" << n << " a=" << n << " b=" << (n * 10) << "\n";
        if (count > 0 && n >= count) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(200)); // 5 Hz
    }
    std::cout << "[connext-nokey-pub] sent " << n << " sample(s).\n";
    return 0;
}
