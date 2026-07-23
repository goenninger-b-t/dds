// Connext subscribes to EnumBox (a real IDL enum member -> TK_ENUM) on topic "EnumBox", for the
// enum TypeObject interop probe RECIPROCAL: our enum-box WRITER (TK_INT32) -> this Connext READER
// (TK_ENUM). This is the direction that matters for LogEvent-as-publisher: does a strict foreign
// reader accept our TK_INT32 writer? Run our writer with enum_writer.lisp.
// Usage: ./enum_sub [domain=0] [seconds=0]   (0 = run until Ctrl-C)
// Env:   CONNEXT_VERBOSE=1 surfaces discovery/match/incompatible decisions on stderr.

#include <iostream>
#include <thread>
#include <chrono>
#include <cstdlib>

#include <dds/dds.hpp>
#include <rti/config/Logger.hpp>
#include "EnumBox.hpp"

int main(int argc, char **argv)
{
    if (std::getenv("CONNEXT_VERBOSE"))
        rti::config::Logger::instance().verbosity(rti::config::Verbosity::STATUS_ALL);

    const int domain  = (argc > 1) ? std::atoi(argv[1]) : 0;
    const int seconds = (argc > 2) ? std::atoi(argv[2]) : 0;

    dds::domain::DomainParticipant participant(domain);
    dds::topic::Topic<EnumBox> topic(participant, "EnumBox");

    dds::sub::Subscriber subscriber(participant);
    dds::sub::qos::DataReaderQos qos = subscriber.default_datareader_qos();
    qos << dds::core::policy::Reliability::Reliable();
    dds::sub::DataReader<EnumBox> reader(subscriber, topic, qos);

    std::cout << "[connext-enum-sub] EnumBox/" << topic.type_name()
              << " (Kind enum -> TK_ENUM) domain=" << domain << " (reliable). Ctrl-C to stop.\n";

    const auto start = std::chrono::steady_clock::now();
    long count = 0;
    for (;;) {
        dds::sub::LoanedSamples<EnumBox> samples = reader.take();
        for (const auto &s : samples) {
            if (!s.info().valid()) continue;
            const EnumBox &d = s.data();
            std::cout << "[connext-enum-sub] #" << ++count << " id=" << d.id()
                      << " kind=" << static_cast<int>(d.kind()) << "\n";
        }
        if (seconds > 0 &&
            std::chrono::steady_clock::now() - start > std::chrono::seconds(seconds))
            break;
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    std::cout << "[connext-enum-sub] received " << count << " sample(s).\n";
    return 0;
}
