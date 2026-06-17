// WP-KEYED-FLATDATA Fast DDS peer publisher (FR-PF-4, RTPS 2.5 §9.6.4.8): RELIABLE + KEEP_ALL keyed
// KeyedFlat on topic "KeyedFlat". Usage: keyed_flat_pub [count] [keys]   (count 0 = forever, ~5/s)
// Env: DISPOSE_AFTER=N  dispose EACH key once N samples per key have been sent (dispose-by-key).
// Reads profiles.xml from the cwd (UDPv4-only). The @key on `id` makes Fast DDS register a WITH_KEY
// DataWriter and compute the per-key instance keyhash (RTPS 2.5 §9.6.4.8) from the i32 id.
//
// XCDR2 (PLAIN_CDR2) data representation is requested EXPLICITLY: this stack's FlatData type is an XCDR2
// type, so a conformant XTypes peer must publish XCDR2 (DDS-XTypes 1.3 §7.6.3.1.1) for this stack's
// XCDR2-only FlatData reader to accept the payload on the COPY/UDP path. (Absent the hint a peer may
// default to XCDR1; the same-host data-sharing/SHMEM ZC loan path is out of scope for wire interop.)
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <thread>
#include <vector>

#include <fastdds/dds/core/policy/QosPolicies.hpp>
#include <fastdds/dds/domain/DomainParticipant.hpp>
#include <fastdds/dds/domain/DomainParticipantFactory.hpp>
#include <fastdds/dds/publisher/DataWriter.hpp>
#include <fastdds/dds/publisher/DataWriterListener.hpp>
#include <fastdds/dds/publisher/Publisher.hpp>
#include <fastdds/dds/topic/Topic.hpp>
#include <fastdds/dds/topic/TypeSupport.hpp>

#include "gen/KeyedFlatPubSubTypes.hpp"
#include "participant_guard.hpp"

using namespace eprosima::fastdds::dds;

class MatchListener : public DataWriterListener
{
public:
    void on_publication_matched(DataWriter*, const PublicationMatchedStatus& info) override
    {
        std::cout << "[keyed_flat_pub] matched change: " << info.current_count_change
                  << " total: " << info.current_count << std::endl;
    }
};

int main(int argc, char** argv)
{
    const long count = (argc > 1) ? std::atol(argv[1]) : 0;
    const int keys = (argc > 2) ? std::atoi(argv[2]) : 3;
    const long dispose_after = std::getenv("DISPOSE_AFTER") ? std::atol(std::getenv("DISPOSE_AFTER")) : 0;

    auto* factory = DomainParticipantFactory::get_instance();
    if (RETCODE_OK != factory->load_XML_profiles_file("profiles.xml"))
    {
        std::cerr << "[keyed_flat_pub] cannot load profiles.xml (run from interop/keyed-flatdata/fastdds)"
                  << std::endl;
        return 1;
    }
    DomainParticipant* participant =
        factory->create_participant_with_default_profile(nullptr, StatusMask::none());
    if (participant == nullptr) { std::cerr << "[keyed_flat_pub] participant creation failed\n"; return 1; }
    ParticipantGuard guard{participant};

    // Register under the type name "keyed-flat" (NOT the IDL name "KeyedFlat") so it is byte-identical
    // to this stack's registered type-name; discovery matches on topic name + type name.
    TypeSupport type(new KeyedFlatPubSubType());
    type.register_type(participant, "keyed-flat");

    Topic* topic = participant->create_topic("KeyedFlat", "keyed-flat", TOPIC_QOS_DEFAULT);
    Publisher* publisher = participant->create_publisher(PUBLISHER_QOS_DEFAULT, nullptr);
    if (topic == nullptr || publisher == nullptr)
    { std::cerr << "[keyed_flat_pub] topic/publisher creation failed\n"; return 1; }

    DataWriterQos wqos = DATAWRITER_QOS_DEFAULT;
    wqos.reliability().kind = RELIABLE_RELIABILITY_QOS;
    wqos.history().kind = KEEP_ALL_HISTORY_QOS;
    wqos.representation().m_value.clear();
    wqos.representation().m_value.push_back(XCDR2_DATA_REPRESENTATION);   // XCDR2 (PLAIN_CDR2), DDS-XTypes 1.3 §7.6.3.1.1
    MatchListener listener;
    DataWriter* writer = publisher->create_datawriter(topic, wqos, &listener, StatusMask::all());
    if (writer == nullptr) { std::cerr << "[keyed_flat_pub] writer creation failed\n"; return 1; }

    std::cout << "[keyed_flat_pub] KeyedFlat/keyed-flat"
              << " (WITH_KEY, reliable, XCDR2, " << keys << " key(s)). Ctrl-C to stop.\n";

    std::vector<bool> disposed(keys, false);
    long n = 0;
    for (;;)
    {
        ++n;
        const int id = static_cast<int>(n % keys);
        KeyedFlat sample;
        sample.id(id);
        sample.x(50 + static_cast<int>(n % 100));
        sample.y(50 + static_cast<int>((n * 7) % 100));
        if (RETCODE_OK == writer->write(&sample) && n % keys == 0)
            std::cout << "[keyed_flat_pub] sent #" << n << " id=" << id
                      << " x=" << sample.x() << " y=" << sample.y() << std::endl;
        // dispose-by-key: once each key has reached DISPOSE_AFTER, dispose it once
        if (dispose_after > 0 && n >= dispose_after * keys && !disposed[id])
        {
            writer->dispose(&sample, HANDLE_NIL);
            disposed[id] = true;
            std::cout << "[keyed_flat_pub] DISPOSED key id=" << id
                      << " (dispose DATA carries PID_KEY_HASH inline-QoS)\n";
        }
        if (count > 0 && n >= count) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(200)); // 5 Hz
    }
    std::this_thread::sleep_for(std::chrono::seconds(2));   // let reliable dispose DATA reach matched readers
    std::cout << "[keyed_flat_pub] done, sent " << n << std::endl;
    return 0;
}
