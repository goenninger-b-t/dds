// Fast DDS peer publisher for the MUTABLE encoding question (ADR 0086 §A2/§A5).
//
// RTI Connext answered one half of it and not the other: it sends @mutable as PL_CDR (XCDR1), so the
// committed vector pins the parameter-list framing of rules (23)-(25) and says NOTHING about rules
// (21)-(22). That leaves the ONE part of the MUTABLE encoding the spec leaves to the writer entirely
// unpinned against any external encoder: the LENGTH CODE for a variable-width member. Codes 5-7 rewind
// the stream so NEXTINT doubles as the member's own leading length, saving 4 octets; we emit LC=4.
// Both are conformant, so only a peer that actually emits PL_CDR2 can say what a second implementation
// chooses — and whether our decoder reads its choice correctly.
//
// This is that peer, IF Fast DDS emits PL_CDR2 here. Whether it does is the experiment; a NEGATIVE
// result (it also sends PL_CDR, or refuses the type) is a real answer and is recorded as one, not
// quietly dropped.
//
// Usage: ./mutable_pub [count]   (0 = forever, ~10 samples/s). Reads profiles.xml from the cwd.
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <thread>
#include <vector>

#include <fastdds/dds/domain/DomainParticipant.hpp>
#include <fastdds/dds/domain/DomainParticipantFactory.hpp>
#include <fastdds/dds/publisher/DataWriter.hpp>
#include <fastdds/dds/publisher/DataWriterListener.hpp>
#include <fastdds/dds/publisher/Publisher.hpp>
#include <fastdds/dds/topic/Topic.hpp>
#include <fastdds/dds/topic/TypeSupport.hpp>

#include "gen/MutableDataPubSubTypes.hpp"
#include "participant_guard.hpp"

using namespace eprosima::fastdds::dds;

class MatchListener : public DataWriterListener
{
public:
    void on_publication_matched(DataWriter*, const PublicationMatchedStatus& info) override
    {
        std::cout << "[fastdds-mut-pub] matched change: " << info.current_count_change
                  << " total: " << info.current_count << std::endl;
    }
};

int main(int argc, char** argv)
{
    const long count = (argc > 1) ? std::atol(argv[1]) : 0;

    auto* factory = DomainParticipantFactory::get_instance();
    if (RETCODE_OK != factory->load_XML_profiles_file("profiles.xml"))
    {
        std::cerr << "[fastdds-mut-pub] cannot load profiles.xml (run from interop/fastdds/mutable)"
                  << std::endl;
        return 1;
    }
    DomainParticipant* participant =
        factory->create_participant_with_default_profile(nullptr, StatusMask::none());
    if (participant == nullptr)
    {
        std::cerr << "[fastdds-mut-pub] participant creation failed" << std::endl;
        return 1;
    }
    ParticipantGuard guard{participant};

    TypeSupport type(new MutableDataPubSubType());
    type.register_type(participant);

    Topic* topic = participant->create_topic("MutableCorpus", type.get_type_name(), TOPIC_QOS_DEFAULT);
    Publisher* publisher = participant->create_publisher(PUBLISHER_QOS_DEFAULT, nullptr);
    if (topic == nullptr || publisher == nullptr)
    {
        std::cerr << "[fastdds-mut-pub] topic/publisher creation failed" << std::endl;
        return 1;
    }

    DataWriterQos wqos = DATAWRITER_QOS_DEFAULT;
    wqos.reliability().kind = RELIABLE_RELIABILITY_QOS;
    MatchListener listener;
    DataWriter* writer = publisher->create_datawriter(topic, wqos, &listener, StatusMask::all());
    if (writer == nullptr)
    {
        std::cerr << "[fastdds-mut-pub] writer creation failed" << std::endl;
        return 1;
    }

    // THE SAME fixed sample the Connext peer publishes and %corpus-mutable-sample builds, so the two
    // vendors' payloads for one identical sample can be compared octet for octet.
    MutableData sample;
    sample.a(1);
    sample.b(2);
    sample.label("hello");
    sample.t_ns(3);
    sample.vals(std::vector<int32_t>{7, 8, 9});

    long sent = 0;
    for (long i = 0; count == 0 || i < count; ++i)
    {
        if (RETCODE_OK == writer->write(&sample))
        {
            ++sent;
            std::cout << "[fastdds-mut-pub] sent " << sent << std::endl;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    std::cout << "[fastdds-mut-pub] done, sent " << sent << std::endl;
    return 0;
}
