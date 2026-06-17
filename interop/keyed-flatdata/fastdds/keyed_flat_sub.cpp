// WP-KEYED-FLATDATA Fast DDS peer subscriber (FR-PF-4, RTPS 2.5 §9.6.4.8): RELIABLE + KEEP_ALL keyed
// KeyedFlat on topic "KeyedFlat". Usage: keyed_flat_sub [seconds]   (0 = forever)
// Reads profiles.xml from the cwd (UDPv4-only). The @key on `id` makes Fast DDS register a WITH_KEY
// DataReader and assign each sample to a per-key instance via its keyhash (RTPS 2.5 §9.6.4.8). For each
// sample this prints the 16-octet instance handle hex so it can be compared, octet-for-octet, with this
// stack's per-key keyhash (the cross-impl conformance crux). An invalid-data sample is an instance-state
// change (a dispose-by-key from the peer, carrying PID_KEY_HASH inline-QoS).
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <set>
#include <sstream>
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

#include "gen/KeyedFlatPubSubTypes.hpp"
#include "participant_guard.hpp"

using namespace eprosima::fastdds::dds;

static std::string handle_hex(const InstanceHandle_t& h)
{
    // InstanceHandle_t wraps the 16-octet keyhash (RTPS 2.5 §9.6.4.8); render it as hex so it can be
    // compared octet-for-octet with this stack's per-key keyhash.
    std::ostringstream os;
    for (int i = 0; i < 16; ++i)
        os << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(h.value[i]);
    return os.str();
}

class KeyedFlatListener : public DataReaderListener
{
public:
    std::atomic<long> received{0};
    std::set<std::string> instances;

    void on_subscription_matched(DataReader*, const SubscriptionMatchedStatus& info) override
    {
        std::cout << "[keyed_flat_sub] matched change: " << info.current_count_change
                  << " total: " << info.current_count << std::endl;
    }

    void on_data_available(DataReader* reader) override
    {
        KeyedFlat sample;
        SampleInfo info;
        while (RETCODE_OK == reader->take_next_sample(&sample, &info))
        {
            const std::string hx = handle_hex(info.instance_handle);
            instances.insert(hx);
            if (info.valid_data)
            {
                const long n = ++received;
                std::cout << "[keyed_flat_sub] #" << n << " id=" << sample.id()
                          << " x=" << sample.x() << " y=" << sample.y()
                          << " instance(keyhash)=" << hx << std::endl;
            }
            else
            {
                std::cout << "[keyed_flat_sub] INSTANCE_STATE " << info.instance_state
                          << " instance(keyhash)=" << hx << " (dispose-by-key from peer)\n";
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
        std::cerr << "[keyed_flat_sub] cannot load profiles.xml (run from interop/keyed-flatdata/fastdds)"
                  << std::endl;
        return 1;
    }
    DomainParticipant* participant =
        factory->create_participant_with_default_profile(nullptr, StatusMask::none());
    if (participant == nullptr) { std::cerr << "[keyed_flat_sub] participant creation failed\n"; return 1; }
    ParticipantGuard guard{participant};

    // Register under the type name "keyed-flat" (NOT the IDL name "KeyedFlat") so it is byte-identical
    // to this stack's registered type-name; discovery matches on topic name + type name.
    TypeSupport type(new KeyedFlatPubSubType());
    type.register_type(participant, "keyed-flat");

    Topic* topic = participant->create_topic("KeyedFlat", "keyed-flat", TOPIC_QOS_DEFAULT);
    Subscriber* subscriber = participant->create_subscriber(SUBSCRIBER_QOS_DEFAULT, nullptr);
    if (topic == nullptr || subscriber == nullptr)
    { std::cerr << "[keyed_flat_sub] topic/subscriber creation failed\n"; return 1; }

    DataReaderQos rqos = DATAREADER_QOS_DEFAULT;
    rqos.reliability().kind = RELIABLE_RELIABILITY_QOS;
    rqos.history().kind = KEEP_ALL_HISTORY_QOS;
    KeyedFlatListener listener;
    DataReader* reader = subscriber->create_datareader(topic, rqos, &listener, StatusMask::all());
    if (reader == nullptr) { std::cerr << "[keyed_flat_sub] reader creation failed\n"; return 1; }

    std::cout << "[keyed_flat_sub] KeyedFlat/keyed-flat"
              << " (WITH_KEY, reliable). Ctrl-C to stop.\n";

    if (seconds == 0)
        for (;;) std::this_thread::sleep_for(std::chrono::seconds(1));
    std::this_thread::sleep_for(std::chrono::seconds(seconds));
    std::cout << "[keyed_flat_sub] done, received " << listener.received.load() << " sample(s) in "
              << listener.instances.size() << " distinct instance(s).\n";
    return 0;
}
