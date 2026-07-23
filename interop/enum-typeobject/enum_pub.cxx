// Connext publishes EnumBox (a real IDL enum member -> TK_ENUM) on topic "EnumBox", for the enum
// TypeObject interop probe. Run NeoDDS's scratch enum subscriber (TK_INT32 for the same member) and
// observe whether Connext matches (tolerates) or refuses (enforces).
// Usage: ./enum_pub [domain=0] [count=0]   (0 = forever, ~10/s)
// Env:   CONNEXT_VERBOSE=1 surfaces discovery/match/incompatible-type decisions on stderr.

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

    const int  domain = (argc > 1) ? std::atoi(argv[1]) : 0;
    const long count  = (argc > 2) ? std::atol(argv[2]) : 0;

    dds::domain::DomainParticipant participant(domain);
    dds::topic::Topic<EnumBox> topic(participant, "EnumBox");

    dds::pub::Publisher publisher(participant);
    dds::pub::qos::DataWriterQos qos = publisher.default_datawriter_qos();
    qos << dds::core::policy::Reliability::Reliable();
    dds::pub::DataWriter<EnumBox> writer(publisher, topic, qos);

    std::cout << "[connext-enum-pub] EnumBox/" << topic.type_name()
              << " (Kind enum -> TK_ENUM) domain=" << domain << " (reliable). Ctrl-C to stop.\n";

    EnumBox sample;
    sample.id(1);
    const Kind kinds[3] = { Kind::KIND_TRACE, Kind::KIND_INFO, Kind::KIND_ERROR };
    long sent = 0;
    for (long i = 0; count == 0 || i < count; ++i)
    {
        sample.kind(kinds[i % 3]);
        writer.write(sample);
        std::cout << "[connext-enum-pub] sent " << ++sent << " kind=" << static_cast<int>(sample.kind()) << "\n";
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return 0;
}
