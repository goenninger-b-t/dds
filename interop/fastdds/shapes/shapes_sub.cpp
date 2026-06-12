// FR-IO-2 Fast DDS peer subscriber: RELIABLE ShapeType on topic "Square".
// Usage: shapes_sub [seconds]   (0 = forever)
// Reads profiles.xml from the cwd (UDPv4-only, TypeLookup client+server).
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

#include "gen/ShapeTypePubSubTypes.hpp"
#include "participant_guard.hpp"

using namespace eprosima::fastdds::dds;

class ShapeListener : public DataReaderListener
{
public:
    std::atomic<long> received{0};

    void on_subscription_matched(DataReader*, const SubscriptionMatchedStatus& info) override
    {
        std::cout << "[shapes_sub] matched change: " << info.current_count_change
                  << " total: " << info.current_count << std::endl;
    }

    // Reverse-WLP proof: fires when a matched writer's liveliness changes (our ParticipantMessageData asserts -> alive; assertions stop -> not_alive).
    void on_liveliness_changed(DataReader*, const LivelinessChangedStatus& status) override
    {
        std::cout << "[shapes_sub] LIVELINESS_CHANGED alive=" << status.alive_count
                  << " (" << status.alive_count_change << ") not_alive=" << status.not_alive_count
                  << " (" << status.not_alive_count_change << ")" << std::endl;
    }

    void on_data_available(DataReader* reader) override
    {
        ShapeType sample;
        SampleInfo info;
        while (RETCODE_OK == reader->take_next_sample(&sample, &info))
        {
            if (info.valid_data)
            {
                const long n = ++received;
                std::cout << "[shapes_sub] " << n << ": color=" << sample.color()
                          << " x=" << sample.x() << " y=" << sample.y()
                          << " size=" << sample.shapesize() << std::endl;
            }
        }
    }
};

int main(int argc, char** argv)
{
    const long seconds = (argc > 1) ? std::atol(argv[1]) : 0;

    auto* factory = DomainParticipantFactory::get_instance();
    if (RETCODE_OK != factory->load_XML_profiles_file("profiles.xml"))
    {
        std::cerr << "[shapes_sub] cannot load profiles.xml (run from interop/fastdds/shapes)"
                  << std::endl;
        return 1;
    }
    DomainParticipant* participant =
        factory->create_participant_with_default_profile(nullptr, StatusMask::none());
    if (participant == nullptr)
    {
        std::cerr << "[shapes_sub] participant creation failed" << std::endl;
        return 1;
    }
    ParticipantGuard guard{participant};

    TypeSupport type(new ShapeTypePubSubType());
    type.register_type(participant);

    Topic* topic = participant->create_topic("Square", type.get_type_name(), TOPIC_QOS_DEFAULT);
    Subscriber* subscriber = participant->create_subscriber(SUBSCRIBER_QOS_DEFAULT, nullptr);
    if (topic == nullptr || subscriber == nullptr)
    {
        std::cerr << "[shapes_sub] topic/subscriber creation failed" << std::endl;
        return 1;
    }

    DataReaderQos rqos = DATAREADER_QOS_DEFAULT;
    rqos.reliability().kind = RELIABLE_RELIABILITY_QOS;
    // SUB_LIVELINESS_LEASE_MS (off by default) requests a finite-lease LIVELINESS so this reader RxO-matches + TRACKS a remote writer's liveliness; SUB_LIVELINESS_KIND selects automatic (default) or manual_by_participant.
    if (const char* lease_ms = std::getenv("SUB_LIVELINESS_LEASE_MS"))
    {
        const long ms = std::atol(lease_ms);
        const char* k = std::getenv("SUB_LIVELINESS_KIND");
        rqos.liveliness().kind = (k && std::string(k) == "manual_by_participant")
            ? MANUAL_BY_PARTICIPANT_LIVELINESS_QOS : AUTOMATIC_LIVELINESS_QOS;
        rqos.liveliness().lease_duration = Duration_t(static_cast<int32_t>(ms / 1000), static_cast<uint32_t>((ms % 1000) * 1000000));
    }
    ShapeListener listener;
    DataReader* reader = subscriber->create_datareader(topic, rqos, &listener, StatusMask::all());
    if (reader == nullptr)
    {
        std::cerr << "[shapes_sub] reader creation failed" << std::endl;
        return 1;
    }

    if (seconds == 0)
    {
        for (;;)
        {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
    std::this_thread::sleep_for(std::chrono::seconds(seconds));
    std::cout << "[shapes_sub] done, received " << listener.received.load() << std::endl;
    return 0;
}
