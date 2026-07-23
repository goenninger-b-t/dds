// Connext publishes dds::log::LogEvent (generated from DdsLog.idl) on topic "DdsLog", for the
// LogEvent interop leg: a foreign @appendable publisher -> our reader. Proves the LogEvent type
// matches and decodes across the vendor boundary, and empirically settles whether @appendable
// members correspond by ID/position (our kebab member names vs the IDL's underscore names would
// then NOT matter) or by name (they would).
// Usage: ./log_pub [domain=0] [count=0]   (0 = forever, ~10/s)
// Env:   CONNEXT_VERBOSE=1 surfaces discovery/match/incompatible decisions on stderr.

#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <cstdlib>

#include <dds/dds.hpp>
#include <rti/config/Logger.hpp>
#include "DdsLog.hpp"

int main(int argc, char **argv)
{
    if (std::getenv("CONNEXT_VERBOSE"))
        rti::config::Logger::instance().verbosity(rti::config::Verbosity::STATUS_ALL);

    const int  domain = (argc > 1) ? std::atoi(argv[1]) : 0;
    const long count  = (argc > 2) ? std::atol(argv[2]) : 0;

    dds::domain::DomainParticipant participant(domain);
    dds::topic::Topic<dds::log::LogEvent> topic(participant, "DdsLog");

    dds::pub::Publisher publisher(participant);
    dds::pub::qos::DataWriterQos qos = publisher.default_datawriter_qos();
    qos << dds::core::policy::Reliability::Reliable();
    dds::pub::DataWriter<dds::log::LogEvent> writer(publisher, topic, qos);

    std::cout << "[connext-log-pub] DdsLog/" << topic.type_name()
              << " (@appendable LogEvent) domain=" << domain << " (reliable). Ctrl-C to stop.\n";

    dds::log::LogEvent sample;
    sample.host("connext-node");
    sample.process(4242);
    sample.participant_uuid("8b619879-4ffe-4fca-ad01-05b39d987dbc");
    sample.host_ip("192.168.2.148");
    sample.thread(7);
    sample.timestamp(1700000000000000000LL);
    sample.severity(dds::log::Severity::SEV_CRIT);
    sample.category("MEM");
    sample.function("gbt_tc_core_mem_init()");
    sample.file("gbttctools/src/src.c");
    sample.line(1234);
    sample.event_kind(dds::log::EventKind::EV_EXIT);
    sample.elapsed_ns(12000);
    sample.truncated(false);

    long sent = 0;
    for (long i = 0; count == 0 || i < count; ++i)
    {
        sample.seq(static_cast<uint64_t>(i));
        sample.message(std::string("segfault at frame ") + std::to_string(i));
        writer.write(sample);
        std::cout << "[connext-log-pub] sent " << ++sent << " seq=" << i << "\n";
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return 0;
}
