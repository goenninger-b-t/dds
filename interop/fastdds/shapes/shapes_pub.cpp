// FR-IO-2 Fast DDS peer publisher: RELIABLE ShapeType on topic "Square".
// Usage: shapes_pub [color] [count]   (count 0 = forever, ~10 samples/s)
// Reads profiles.xml from the cwd (UDPv4-only, TypeLookup client+server).
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

#include "gen/ShapeTypePubSubTypes.hpp"
#include "participant_guard.hpp"

using namespace eprosima::fastdds::dds;

class MatchListener : public DataWriterListener
{
public:
    void on_publication_matched(DataWriter*, const PublicationMatchedStatus& info) override
    {
        std::cout << "[shapes_pub] matched change: " << info.current_count_change
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
        std::cerr << "[shapes_pub] cannot load profiles.xml (run from interop/fastdds/shapes)"
                  << std::endl;
        return 1;
    }
    DomainParticipant* participant =
        factory->create_participant_with_default_profile(nullptr, StatusMask::none());
    if (participant == nullptr)
    {
        std::cerr << "[shapes_pub] participant creation failed" << std::endl;
        return 1;
    }
    ParticipantGuard guard{participant};

    TypeSupport type(new ShapeTypePubSubType());
    type.register_type(participant);

    Topic* topic = participant->create_topic("Square", type.get_type_name(), TOPIC_QOS_DEFAULT);
    Publisher* publisher = participant->create_publisher(PUBLISHER_QOS_DEFAULT, nullptr);
    if (topic == nullptr || publisher == nullptr)
    {
        std::cerr << "[shapes_pub] topic/publisher creation failed" << std::endl;
        return 1;
    }

    DataWriterQos wqos = DATAWRITER_QOS_DEFAULT;
    wqos.reliability().kind = RELIABLE_RELIABILITY_QOS;
    // DURABILITY=transient_local (off by default = VOLATILE) makes the writer RETAIN+REPLAY its history to a late-joining reader; KEEP_ALL so ALL pre-join samples are retained (WP-DURABILITY-TRANSIENT-LOCAL interop, DDS 1.4 §2.2.3.4).
    if (const char* dur = std::getenv("DURABILITY"))
    {
        if (std::string(dur) == "transient_local" || std::string(dur) == "transient-local")
        {
            wqos.durability().kind = TRANSIENT_LOCAL_DURABILITY_QOS;
            wqos.history().kind = KEEP_ALL_HISTORY_QOS;
        }
    }
    // WLP_LEASE_MS (off by default) gives the writer a finite-lease AUTOMATIC LIVELINESS so the participant emits standard ParticipantMessageData (RTPS 8.4.13) for the interop WLP byte-validation leg.
    if (const char* wlp_ms = std::getenv("WLP_LEASE_MS"))
    {
        const long ms = std::atol(wlp_ms);
        const long ap = ms / 3;
        wqos.liveliness().kind = AUTOMATIC_LIVELINESS_QOS;
        wqos.liveliness().lease_duration = Duration_t(static_cast<int32_t>(ms / 1000), static_cast<uint32_t>((ms % 1000) * 1000000));
        wqos.liveliness().announcement_period = Duration_t(static_cast<int32_t>(ap / 1000), static_cast<uint32_t>((ap % 1000) * 1000000));
    }
    // OWNERSHIP_STRENGTH env (off by default): make the writer EXCLUSIVE with that strength (instance-ownership interop oracle).
    if (const char* os = std::getenv("OWNERSHIP_STRENGTH"))
    {
        wqos.ownership().kind = EXCLUSIVE_OWNERSHIP_QOS;
        wqos.ownership_strength().value = std::atol(os);
    }
    MatchListener listener;
    DataWriter* writer = publisher->create_datawriter(topic, wqos, &listener, StatusMask::all());
    if (writer == nullptr)
    {
        std::cerr << "[shapes_pub] writer creation failed" << std::endl;
        return 1;
    }

    ShapeType sample;
    sample.color(color);
    sample.shapesize(std::getenv("SHAPESIZE") ? std::atoi(std::getenv("SHAPESIZE")) : 30);   // distinguish two writers of one instance (ownership interop)
    long sent = 0;
    for (long i = 0; count == 0 || i < count; ++i)
    {
        sample.x(50 + (i % 100));
        sample.y(50 + ((i * 7) % 100));
        if (RETCODE_OK == writer->write(&sample))
        {
            ++sent;
            std::cout << "[shapes_pub] sent " << sent << " x=" << sample.x()
                      << " y=" << sample.y() << std::endl;
        }
        // DISPOSE_AFTER / UNREGISTER_AFTER (off by default): emit a dispose / unregister of the instance, then stop writing it and hold the participant alive so the reliable lifecycle DATA is delivered (instance-lifecycle interop).
        const char* d = std::getenv("DISPOSE_AFTER");
        const char* u = std::getenv("UNREGISTER_AFTER");
        if (d && sent == std::atol(d)) { writer->dispose(&sample, HANDLE_NIL); std::cout << "[shapes_pub] DISPOSED after " << sent << std::endl; }
        if (u && sent == std::atol(u)) { writer->unregister_instance(&sample, HANDLE_NIL); std::cout << "[shapes_pub] UNREGISTERED after " << sent << std::endl; }
        if ((d && sent == std::atol(d)) || (u && sent == std::atol(u)))
        {
            std::this_thread::sleep_for(std::chrono::seconds(8));   // let the reliable dispose/unregister reach matched readers
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    std::cout << "[shapes_pub] done, sent " << sent << std::endl;
    return 0;
}
