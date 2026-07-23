// Fast DDS peer publisher for interop Leg 1 (cross-DDS half): RELIABLE @appendable ShapeType on
// topic "Square". A second independent vendor's appendable writer -> our reader, the cross-DDS
// oracle alongside the Connext leg. Run our side with  make square-sub TYPE=appendable.
// Usage: appendable_pub [color] [count]   (count 0 = forever, ~10 samples/s)
// Reads profiles.xml from the cwd (UDPv4-only). fastddsgen output goes in gen/.
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

#include "gen/AppendableShapePubSubTypes.hpp"
#include "participant_guard.hpp"

using namespace eprosima::fastdds::dds;

class MatchListener : public DataWriterListener
{
public:
    void on_publication_matched(DataWriter*, const PublicationMatchedStatus& info) override
    {
        std::cout << "[fastdds-pub] matched change: " << info.current_count_change
                  << " total: " << info.current_count << std::endl;
    }
};

int main(int argc, char** argv)
{
    const char* color = (argc > 1) ? argv[1] : "GREEN";
    const long count = (argc > 2) ? std::atol(argv[2]) : 0;

    auto* factory = DomainParticipantFactory::get_instance();
    if (RETCODE_OK != factory->load_XML_profiles_file("profiles.xml"))
    {
        std::cerr << "[fastdds-pub] cannot load profiles.xml (run from interop/fastdds/appendable)"
                  << std::endl;
        return 1;
    }
    DomainParticipant* participant =
        factory->create_participant_with_default_profile(nullptr, StatusMask::none());
    if (participant == nullptr)
    {
        std::cerr << "[fastdds-pub] participant creation failed" << std::endl;
        return 1;
    }
    ParticipantGuard guard{participant};

    TypeSupport type(new ShapeTypePubSubType());
    type.register_type(participant);

    Topic* topic = participant->create_topic("Square", type.get_type_name(), TOPIC_QOS_DEFAULT);
    Publisher* publisher = participant->create_publisher(PUBLISHER_QOS_DEFAULT, nullptr);
    if (topic == nullptr || publisher == nullptr)
    {
        std::cerr << "[fastdds-pub] topic/publisher creation failed" << std::endl;
        return 1;
    }

    DataWriterQos wqos = DATAWRITER_QOS_DEFAULT;
    wqos.reliability().kind = RELIABLE_RELIABILITY_QOS;
    MatchListener listener;
    DataWriter* writer = publisher->create_datawriter(topic, wqos, &listener, StatusMask::all());
    if (writer == nullptr)
    {
        std::cerr << "[fastdds-pub] writer creation failed" << std::endl;
        return 1;
    }

    ShapeType sample;
    sample.color(color);
    sample.shapesize(std::getenv("SHAPESIZE") ? std::atoi(std::getenv("SHAPESIZE")) : 30);
    long sent = 0;
    for (long i = 0; count == 0 || i < count; ++i)
    {
        sample.x(50 + (i % 100));
        sample.y(50 + ((i * 7) % 100));
        if (RETCODE_OK == writer->write(&sample))
        {
            ++sent;
            std::cout << "[fastdds-pub] sent " << sent << " x=" << sample.x()
                      << " y=" << sample.y() << std::endl;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    std::cout << "[fastdds-pub] done, sent " << sent << std::endl;
    return 0;
}
