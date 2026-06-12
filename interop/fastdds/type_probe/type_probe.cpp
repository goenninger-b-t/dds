// FR-IO-2 S4 leg B: type-blind Fast DDS subscriber that resolves topic "Square"'s
// type SOLELY via the peer's TypeLookup server (XTypes 1.3 7.6.3.3) and a remotely
// built DynamicType. Deliberately does NOT link/include any generated ShapeType
// code: the local registry must miss, forcing Fast DDS's builtin TypeLookup client
// (getTypeDependencies + getTypes) toward the discovered writer's participant.
// Usage: type_probe [seconds]   (default 30; 0 = forever)
// Reads profiles.xml from the cwd (UDPv4-only, fastdds.type_propagation enabled).
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>

#include <fastdds/dds/domain/DomainParticipant.hpp>
#include <fastdds/dds/log/Log.hpp>
#include <fastdds/dds/domain/DomainParticipantFactory.hpp>
#include <fastdds/dds/domain/DomainParticipantListener.hpp>
#include <fastdds/dds/subscriber/DataReader.hpp>
#include <fastdds/dds/subscriber/SampleInfo.hpp>
#include <fastdds/dds/subscriber/Subscriber.hpp>
#include <fastdds/dds/topic/Topic.hpp>
#include <fastdds/dds/topic/TypeSupport.hpp>
#include <fastdds/dds/xtypes/dynamic_types/DynamicData.hpp>
#include <fastdds/dds/xtypes/dynamic_types/DynamicDataFactory.hpp>
#include <fastdds/dds/xtypes/dynamic_types/DynamicPubSubType.hpp>
#include <fastdds/dds/xtypes/dynamic_types/DynamicType.hpp>
#include <fastdds/dds/xtypes/dynamic_types/DynamicTypeBuilder.hpp>
#include <fastdds/dds/xtypes/dynamic_types/DynamicTypeBuilderFactory.hpp>
#include <fastdds/dds/xtypes/type_representation/TypeObject.hpp>
#include <fastdds/dds/xtypes/utils.hpp>

#include "participant_guard.hpp"

using namespace eprosima::fastdds::dds;

class TypeProbe : public DomainParticipantListener
{
public:
    std::atomic<long> received{0};

    explicit TypeProbe(
            const std::string& topic_name)
        : topic_name_(topic_name)
    {
    }

    void on_participant_discovery(
            DomainParticipant* /*participant*/,
            eprosima::fastdds::rtps::ParticipantDiscoveryStatus /*reason*/,
            const ParticipantBuiltinTopicData& info,
            bool& should_be_ignored) override
    {
        should_be_ignored = false;
        std::cout << "[type_probe] participant discovery event: " << info.guid << std::endl;
    }

    // Fast DDS defers this callback for an unknown remote type until its own
    // TypeLookup client has resolved it against the peer's TypeLookup server.
    void on_data_writer_discovery(
            DomainParticipant* /*participant*/,
            eprosima::fastdds::rtps::WriterDiscoveryStatus /*reason*/,
            const PublicationBuiltinTopicData& info,
            bool& should_be_ignored) override
    {
        should_be_ignored = false;
        std::lock_guard<std::mutex> lck(mtx_);
        if ((type_discovered_.empty()) && (topic_name_ == info.topic_name.to_string()))
        {
            std::cout << "[type_probe] writer discovered: topic=" << info.topic_name
                      << " type=" << info.type_name
                      << " type_information.assigned=" << info.type_information.assigned()
                      << std::endl;
            remote_type_information_ = info.type_information.type_information;
            auto type_id_complete = remote_type_information_.complete().typeid_with_size().type_id();
            auto type_id_minimal = remote_type_information_.minimal().typeid_with_size().type_id();
            auto& registry = DomainParticipantFactory::get_instance()->type_object_registry();
            if ((RETCODE_OK != registry.get_type_object(type_id_complete, remote_type_object_)) &&
                    (RETCODE_OK != registry.get_type_object(type_id_minimal, remote_type_object_)))
            {
                std::cout << "[type_probe] discovered type NOT in registry (resolution failed)"
                          << std::endl;
                return;
            }
            type_discovered_ = info.type_name.to_string();
            std::cout << "[type_probe] type resolved via remote TypeObject: "
                      << type_discovered_ << std::endl;
            cv_.notify_one();
        }
    }

    void on_subscription_matched(
            DataReader* /*reader*/,
            const SubscriptionMatchedStatus& info) override
    {
        std::cout << "[type_probe] matched change: " << info.current_count_change
                  << " total: " << info.current_count << std::endl;
    }

    void on_data_available(
            DataReader* reader) override
    {
        SampleInfo info;
        while (RETCODE_OK == reader->take_next_sample(&sample_, &info))
        {
            if (info.valid_data)
            {
                const long n = ++received;
                std::stringstream json;
                if (RETCODE_OK == json_serialize(sample_, DynamicDataJsonFormat::EPROSIMA, json))
                {
                    std::cout << "[type_probe] " << n << ": " << json.str() << std::endl;
                }
                else
                {
                    std::cout << "[type_probe] " << n << ": (json_serialize failed)" << std::endl;
                }
            }
        }
    }

    bool wait_for_type(
            long seconds)
    {
        std::unique_lock<std::mutex> lck(mtx_);
        if (seconds == 0)
        {
            cv_.wait(lck, [&] { return !type_discovered_.empty(); });
            return true;
        }
        return cv_.wait_for(lck, std::chrono::seconds(seconds),
                       [&] { return !type_discovered_.empty(); });
    }

    // Builds the reader stack from nothing but the remotely resolved TypeObject.
    bool create_entities(
            DomainParticipant* participant)
    {
        DynamicTypeBuilder::_ref_type builder =
                DynamicTypeBuilderFactory::get_instance()->create_type_w_type_object(remote_type_object_);
        if (!builder)
        {
            std::cerr << "[type_probe] create_type_w_type_object failed" << std::endl;
            return false;
        }
        remote_type_ = builder->build();
        if (!remote_type_)
        {
            std::cerr << "[type_probe] DynamicType build failed" << std::endl;
            return false;
        }
        // The two-arg ctor skips re-registering the TypeObject: required when the
        // remote TypeInformation carries only the minimal TypeIdentifier (our peer).
        TypeSupport type(new DynamicPubSubType(remote_type_, remote_type_information_));
        if (RETCODE_OK != type.register_type(participant, type_discovered_))
        {
            std::cerr << "[type_probe] register_type failed" << std::endl;
            return false;
        }
        sample_ = DynamicDataFactory::get_instance()->create_data(remote_type_);
        if (!sample_)
        {
            std::cerr << "[type_probe] create_data failed" << std::endl;
            return false;
        }
        Topic* topic = participant->create_topic(topic_name_, type_discovered_, TOPIC_QOS_DEFAULT);
        Subscriber* subscriber = participant->create_subscriber(SUBSCRIBER_QOS_DEFAULT, nullptr);
        if (topic == nullptr || subscriber == nullptr)
        {
            std::cerr << "[type_probe] topic/subscriber creation failed" << std::endl;
            return false;
        }
        DataReaderQos rqos = DATAREADER_QOS_DEFAULT;
        rqos.reliability().kind = RELIABLE_RELIABILITY_QOS;
        DataReader* reader = subscriber->create_datareader(topic, rqos, nullptr, StatusMask::all());
        if (reader == nullptr)
        {
            std::cerr << "[type_probe] reader creation failed" << std::endl;
            return false;
        }
        std::cout << "[type_probe] RELIABLE reader created on topic " << topic_name_
                  << " with the remotely resolved type" << std::endl;
        return true;
    }

private:
    const std::string topic_name_;
    std::string type_discovered_;
    xtypes::TypeInformation remote_type_information_;
    xtypes::TypeObject remote_type_object_;
    DynamicType::_ref_type remote_type_;
    DynamicData::_ref_type sample_;
    std::mutex mtx_;
    std::condition_variable cv_;
};

int main(int argc, char** argv)
{
    const long seconds = (argc > 1) ? std::atol(argv[1]) : 30;

    // surface Fast DDS drop reasons (default verbosity logs errors only)
    Log::SetVerbosity(Log::Kind::Warning);

    auto* factory = DomainParticipantFactory::get_instance();
    if (RETCODE_OK != factory->load_XML_profiles_file("profiles.xml"))
    {
        std::cerr << "[type_probe] cannot load profiles.xml (run from interop/fastdds/type_probe)"
                  << std::endl;
        return 1;
    }

    TypeProbe probe("Square");
    StatusMask mask = StatusMask::data_available();
    mask << StatusMask::subscription_matched();
    DomainParticipant* participant =
            factory->create_participant_with_default_profile(&probe, mask);
    if (participant == nullptr)
    {
        std::cerr << "[type_probe] participant creation failed" << std::endl;
        return 1;
    }
    ParticipantGuard guard{participant};

    const auto t0 = std::chrono::steady_clock::now();
    if (!probe.wait_for_type(seconds))
    {
        std::cerr << "[type_probe] FAIL: no type resolved within " << seconds << " s" << std::endl;
        Log::Flush();
        return 1;
    }
    if (!probe.create_entities(participant))
    {
        return 1;
    }

    if (seconds == 0)
    {
        for (;;)
        {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
    const auto deadline = t0 + std::chrono::seconds(seconds);
    while (std::chrono::steady_clock::now() < deadline)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
    std::cout << "[type_probe] done, received " << probe.received.load() << std::endl;
    return 0;
}
