// Connext publishes StringLarge (a real IDL string<1024> -> TI_STRING8_LARGE) on topic
// "StringLarge", for the bounded-string LARGE-form interop probe. Run NeoDDS's scratch subscriber
// (whose (:string 1024) member also emits TI_STRING8_LARGE) and observe match + value.
// Usage: ./stringlarge_pub [domain=0] [count=0]   (0 = forever, ~10/s)
// Env:   CONNEXT_VERBOSE=1 surfaces discovery/match/incompatible-type decisions on stderr.

#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <cstdlib>

#include <dds/dds.hpp>
#include <rti/config/Logger.hpp>
#include "StringLarge.hpp"

int main(int argc, char **argv)
{
    if (std::getenv("CONNEXT_VERBOSE"))
        rti::config::Logger::instance().verbosity(rti::config::Verbosity::STATUS_ALL);

    const int  domain = (argc > 1) ? std::atoi(argv[1]) : 0;
    const long count  = (argc > 2) ? std::atol(argv[2]) : 0;

    dds::domain::DomainParticipant participant(domain);
    dds::topic::Topic<StringLarge> topic(participant, "StringLarge");

    dds::pub::Publisher publisher(participant);
    dds::pub::qos::DataWriterQos qos = publisher.default_datawriter_qos();
    qos << dds::core::policy::Reliability::Reliable();
    dds::pub::DataWriter<StringLarge> writer(publisher, topic, qos);

    std::cout << "[connext-strlarge-pub] StringLarge/" << topic.type_name()
              << " (string<1024> -> TI_STRING8_LARGE) domain=" << domain << " (reliable). Ctrl-C.\n";

    StringLarge sample;
    sample.id(1);
    long sent = 0;
    for (long i = 0; count == 0 || i < count; ++i)
    {
        // A short value on a bounded<1024> member: the BOUND (type) is what differs, not the payload.
        sample.text(std::string("hello-from-connext-") + std::to_string(i));
        writer.write(sample);
        std::cout << "[connext-strlarge-pub] sent " << ++sent << " text=" << sample.text() << "\n";
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return 0;
}
