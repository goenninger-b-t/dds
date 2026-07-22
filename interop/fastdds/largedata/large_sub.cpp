// Fast DDS peer subscriber for the LargeData (DATA_FRAG) interop leg — ADR 0079.
//
// WHY THIS EXISTS. Fragmentation was tested against RTI Connext only. Fast DDS is the LENIENT peer, so a
// green Fast DDS leg proves strictly less than a green Connext leg — but a MISSING leg proves nothing at
// all, and "our emitted datagram size interoperates" is a claim about the second vendor too. Shapes samples
// sit far below any MTU, so no Shapes leg can exercise DATA_FRAG.
//
// Usage: large_sub [seconds]   (0 = forever). Reads profiles.xml from the cwd.
// Verifies the payload octet-by-octet against the harness pattern (i*7) mod 256, exactly as the Connext
// peer does — a reassembly that silently mis-orders or drops a fragment must FAIL, not merely arrive.
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <string>
#include <thread>

#include <fastdds/dds/domain/DomainParticipant.hpp>
#include <fastdds/dds/domain/DomainParticipantFactory.hpp>
#include <fastdds/dds/subscriber/DataReader.hpp>
#include <fastdds/dds/subscriber/DataReaderListener.hpp>
#include <fastdds/dds/subscriber/SampleInfo.hpp>
#include <fastdds/dds/subscriber/Subscriber.hpp>
#include <fastdds/dds/topic/Topic.hpp>
#include <fastdds/dds/topic/TypeSupport.hpp>

#include "gen/LargeDataPubSubTypes.hpp"
#include "participant_guard.hpp"

using namespace eprosima::fastdds::dds;

class LargeListener : public DataReaderListener
{
public:
    std::atomic<long> received{0};

    void on_subscription_matched(DataReader*, const SubscriptionMatchedStatus& info) override
    {
        std::cout << "[fastdds-large-sub] matched change: " << info.current_count_change
                  << " total: " << info.current_count << std::endl;
    }

    void on_data_available(DataReader* reader) override
    {
        LargeData sample;
        SampleInfo info;
        while (RETCODE_OK == reader->take_next_sample(&sample, &info))
        {
            if (!info.valid_data)
            {
                std::cout << "[fastdds-large-sub] INSTANCE_STATE " << info.instance_state << std::endl;
                continue;
            }
            const auto& pv = sample.payload();
            long bad = -1;
            for (size_t i = 0; i < pv.size(); ++i)
            {
                if (pv[i] != static_cast<uint8_t>((i * 7) & 0xff)) { bad = static_cast<long>(i); break; }
            }
            const long n = ++received;
            std::cout << "[fastdds-large-sub] #" << n << " id=" << sample.id()
                      << " payload-len=" << pv.size()
                      << " pattern=" << (bad < 0 ? std::string("OK") : ("BAD@" + std::to_string(bad)))
                      << std::endl;
        }
    }
};

int main(int argc, char** argv)
{
    const long seconds = (argc > 1) ? std::atol(argv[1]) : 0;

    auto* factory = DomainParticipantFactory::get_instance();
    if (RETCODE_OK != factory->load_XML_profiles_file("profiles.xml"))
    {
        std::cerr << "[fastdds-large-sub] cannot load profiles.xml (run from interop/fastdds/largedata)"
                  << std::endl;
        return 1;
    }
    DomainParticipant* participant =
        factory->create_participant_with_default_profile(nullptr, StatusMask::none());
    if (participant == nullptr)
    {
        std::cerr << "[fastdds-large-sub] participant creation failed" << std::endl;
        return 1;
    }
    ParticipantGuard guard{participant};

    TypeSupport type(new LargeDataPubSubType());
    type.register_type(participant);

    Topic* topic = participant->create_topic("LargeData", type.get_type_name(), TOPIC_QOS_DEFAULT);
    Subscriber* subscriber = participant->create_subscriber(SUBSCRIBER_QOS_DEFAULT, nullptr);
    if (topic == nullptr || subscriber == nullptr)
    {
        std::cerr << "[fastdds-large-sub] topic/subscriber creation failed" << std::endl;
        return 1;
    }

    DataReaderQos rqos = DATAREADER_QOS_DEFAULT;
    rqos.reliability().kind = RELIABLE_RELIABILITY_QOS;
    LargeListener listener;
    DataReader* reader = subscriber->create_datareader(topic, rqos, &listener, StatusMask::all());
    if (reader == nullptr)
    {
        std::cerr << "[fastdds-large-sub] datareader creation failed" << std::endl;
        return 1;
    }

    std::cout << "[fastdds-large-sub] LargeData (reliable). "
              << (seconds > 0 ? ("Running " + std::to_string(seconds) + " s.") : std::string("Ctrl-C to stop."))
              << std::endl;

    if (seconds == 0)
    {
        while (true) { std::this_thread::sleep_for(std::chrono::seconds(1)); }
    }
    std::this_thread::sleep_for(std::chrono::seconds(seconds));
    // Exit NORMALLY so the fully-buffered stdout is flushed — a peer killed mid-run leaves an empty log and
    // its leg scores zero however many samples it received (see scripts/gate-interop.sh wait_peer).
    std::cout << "[fastdds-large-sub] done, received " << listener.received.load() << std::endl;
    return 0;
}
