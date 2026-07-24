// Fast DDS peer publisher for the LogEvent cross-DDS interop leg (ADR 0082 §3, FR-IO-2 cross-DDS half):
// RELIABLE @appendable dds::log::LogEvent on topic "DdsLog". A second independent vendor's appendable
// writer -> our reader (interop/log/log_sub.lisp), the cross-DDS oracle alongside the Connext leg.
// Usage: log_pub [domain] [count]   (count 0 = forever, ~10 samples/s). Reads profiles.xml from cwd.
// fastddsgen output goes in gen/ (git-ignored, clean-room).
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <string>
#include <thread>

#include <fastdds/dds/domain/DomainParticipant.hpp>
#include <fastdds/dds/domain/DomainParticipantFactory.hpp>
#include <fastdds/dds/publisher/DataWriter.hpp>
#include <fastdds/dds/publisher/DataWriterListener.hpp>
#include <fastdds/dds/publisher/Publisher.hpp>
#include <fastdds/dds/topic/Topic.hpp>
#include <fastdds/dds/topic/TypeSupport.hpp>

#include "gen/DdsLogPubSubTypes.hpp"
#include "participant_guard.hpp"

using namespace eprosima::fastdds::dds;

class MatchListener : public DataWriterListener
{
public:
    void on_publication_matched(DataWriter*, const PublicationMatchedStatus& info) override
    {
        std::cout << "[fastdds-log-pub] matched change: " << info.current_count_change
                  << " total: " << info.current_count << std::endl;
    }
};

int main(int argc, char** argv)
{
    const long count = (argc > 2) ? std::atol(argv[2]) : 0;   // argv[1]=domain (profiles.xml), argv[2]=count

    auto* factory = DomainParticipantFactory::get_instance();
    if (RETCODE_OK != factory->load_XML_profiles_file("profiles.xml"))
    {
        std::cerr << "[fastdds-log-pub] cannot load profiles.xml (run from interop/fastdds/log)" << std::endl;
        return 1;
    }
    DomainParticipant* participant =
        factory->create_participant_with_default_profile(nullptr, StatusMask::none());
    if (participant == nullptr) { std::cerr << "[fastdds-log-pub] participant creation failed\n"; return 1; }
    ParticipantGuard guard{participant};

    TypeSupport type(new dds::log::LogEventPubSubType());
    type.register_type(participant);

    Topic* topic = participant->create_topic("DdsLog", type.get_type_name(), TOPIC_QOS_DEFAULT);
    Publisher* publisher = participant->create_publisher(PUBLISHER_QOS_DEFAULT, nullptr);
    if (topic == nullptr || publisher == nullptr) { std::cerr << "[fastdds-log-pub] topic/publisher failed\n"; return 1; }

    DataWriterQos wqos = DATAWRITER_QOS_DEFAULT;
    wqos.reliability().kind = RELIABLE_RELIABILITY_QOS;
    MatchListener listener;
    DataWriter* writer = publisher->create_datawriter(topic, wqos, &listener, StatusMask::all());
    if (writer == nullptr) { std::cerr << "[fastdds-log-pub] writer creation failed\n"; return 1; }

    dds::log::LogEvent sample;
    sample.host("fastdds-node");
    sample.process(4242);
    sample.participant_uuid("8b619879-4ffe-4fca-ad01-05b39d987dbc");
    sample.host_ip("fe80::ffff:ffff:ffff:1");             // IPv6, as the Connext leg
    sample.app_id("gbttctools");
    sample.thread(7);
    sample.timestamp(1753349333645329000LL);
    sample.severity(dds::log::Severity::SEV_CRIT);
    sample.category("MEM");
    sample.function("gbt_tc_core_mem_init");
    sample.file("gbttctools/src/src.c");
    sample.line(1234);
    sample.event_kind(dds::log::EventKind::EV_EXIT);
    sample.elapsed_ns(12000);
    sample.truncated(false);
    long sent = 0;
    for (long i = 0; count == 0 || i < count; ++i)
    {
        sample.seq(i);
        sample.message(std::string("segfault at frame ") + std::to_string(i));
        if (RETCODE_OK == writer->write(&sample))
        {
            ++sent;
            std::cout << "[fastdds-log-pub] sent " << sent << " seq=" << i << std::endl;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    std::cout << "[fastdds-log-pub] done, sent " << sent << std::endl;
    return 0;
}
