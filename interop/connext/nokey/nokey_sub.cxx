// nokey_sub — Connext subscribes to keyless NoKeyData on topic "NoKeyTopic".
// No-key endpoint-kinds IN direction: run this and publish from this stack via
//   make nokey-pub
// The keyless IDL makes Connext register a NO_KEY DataReader (RTPS 2.5 §9.3.1.2 kind
// 0x04). The 3-arg Topic constructor pins the registered type name to "nokey-data"
// so it is byte-identical to this stack's registered type-name.
//
// Usage: ./nokey_sub [domain=0] [seconds=0]   (seconds 0 = run forever)

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

    const int domain  = (argc > 1) ? std::atoi(argv[1]) : 0;
    const int seconds = (argc > 2) ? std::atoi(argv[2]) : 0;

    dds::domain::DomainParticipant participant(domain);
    dds::topic::Topic<NoKeyData> topic(participant, "NoKeyTopic", "nokey-data");

    dds::sub::Subscriber subscriber(participant);
    dds::sub::qos::DataReaderQos qos = subscriber.default_datareader_qos();
    qos << dds::core::policy::Reliability::Reliable();
    dds::sub::DataReader<NoKeyData> reader(subscriber, topic, qos);

    std::cout << "[connext-nokey-sub] NoKeyTopic/" << topic.type_name()
              << " domain=" << domain << " (NO_KEY, reliable). Ctrl-C to stop.\n";

    const auto start = std::chrono::steady_clock::now();
    long count = 0;
    for (;;) {
        dds::sub::LoanedSamples<NoKeyData> samples = reader.take();
        for (const auto &s : samples) {
            if (!s.info().valid()) continue;
            const NoKeyData &d = s.data();
            std::cout << "[connext-nokey-sub] #" << ++count
                      << " a=" << d.a() << " b=" << d.b() << "\n";
        }
        if (seconds > 0 &&
            std::chrono::steady_clock::now() - start > std::chrono::seconds(seconds)) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    std::cout << "[connext-nokey-sub] received " << count << " sample(s).\n";
    return 0;
}
