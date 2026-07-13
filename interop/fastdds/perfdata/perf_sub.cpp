// Fast DDS SUBSCRIBER for the non-4-aligned corpus leg (FR-IO-2, ADR 0061, task #28).
//
// WHY THIS EXISTS. Every type in the Shapes interop legs ends on a 4-byte member, so the SerializedPayload
// TRAILING PAD was never exercised and a real wire defect (pad counted in the encapsulation OPTIONS bits but
// never emitted — ADR 0061) survived our entire live-interop suite. PerfData's sequence<octet> lets us sweep
// the alignment classes (len mod 4 = 0,1,2,3) against an INDEPENDENT decoder (fastcdr), so the fix is proven
// against a SECOND vendor and not only RTI Connext.
//
// Verifies the payload BYTE FOR BYTE (byte i must equal i mod 256) — a mis-decoded pad shows up as a wrong
// length or wrong bytes, not merely as a missing sample.
//
//   ./perf_sub [domain] [seconds]

#include <cstdio>
#include <cstdint>
#include <map>
#include <thread>
#include <chrono>
#include <fastdds/dds/domain/DomainParticipantFactory.hpp>
#include <fastdds/dds/domain/DomainParticipant.hpp>
#include <fastdds/dds/subscriber/Subscriber.hpp>
#include <fastdds/dds/subscriber/DataReader.hpp>
#include <fastdds/dds/subscriber/DataReaderListener.hpp>
#include <fastdds/dds/subscriber/qos/DataReaderQos.hpp>
#include <fastdds/dds/topic/TypeSupport.hpp>
#include "gen/PerfDataPubSubTypes.hpp"

using namespace eprosima::fastdds::dds;

namespace {

struct Stats { int ok = 0; int bad = 0; };
std::map<size_t, Stats> g_by_len;   // sequence length -> pass/fail counts

class Listener : public DataReaderListener {
public:
    void on_data_available(DataReader* reader) override
    {
        PerfData s;
        SampleInfo info;
        while (reader->take_next_sample(&s, &info) == eprosima::fastdds::dds::RETCODE_OK) {
            if (!info.valid_data) continue;
            const size_t len = s.data().size();
            bool good = true;
            for (size_t i = 0; i < len; ++i)
                if (s.data()[i] != static_cast<uint8_t>(i & 0xff)) { good = false; break; }
            if (good) ++g_by_len[len].ok; else ++g_by_len[len].bad;
        }
    }
    void on_subscription_matched(DataReader*, const SubscriptionMatchedStatus& st) override
    {
        std::printf("[fastdds perf_sub] matched=%d\n", st.current_count);
        std::fflush(stdout);
    }
};

}  // namespace

int main(int argc, char* argv[])
{
    const int domain  = (argc > 1) ? std::atoi(argv[1]) : 0;
    const int seconds = (argc > 2) ? std::atoi(argv[2]) : 60;

    DomainParticipantQos pqos;
    pqos.name("fastdds_perf_sub");
    DomainParticipant* p =
        DomainParticipantFactory::get_instance()->create_participant(domain, pqos);
    if (!p) { std::fprintf(stderr, "cannot create participant\n"); return 1; }

    TypeSupport type(new PerfDataPubSubType());
    type.register_type(p);

    Topic* topic = p->create_topic("PerfPing", "PerfData", TOPIC_QOS_DEFAULT);
    Subscriber* sub = p->create_subscriber(SUBSCRIBER_QOS_DEFAULT);

    DataReaderQos rqos;
    rqos.reliability().kind = RELIABLE_RELIABILITY_QOS;
    rqos.history().kind = KEEP_ALL_HISTORY_QOS;

    Listener listener;
    sub->create_datareader(topic, rqos, &listener);

    std::printf("[fastdds perf_sub] PerfPing/PerfData domain=%d, %d s\n", domain, seconds);
    std::fflush(stdout);
    std::this_thread::sleep_for(std::chrono::seconds(seconds));

    std::printf("\n[fastdds perf_sub] RESULTS (payload byte i must == i mod 256):\n");
    int total_bad = 0;
    for (const auto& kv : g_by_len) {
        const size_t len = kv.first;
        std::printf("  len=%-6zu (mod4=%zu)  ok=%-4d bad=%-4d  %s\n",
                    len, len % 4, kv.second.ok, kv.second.bad,
                    kv.second.bad == 0 && kv.second.ok > 0 ? "PASS" : "FAIL");
        total_bad += kv.second.bad;
    }
    std::printf("[fastdds perf_sub] %s\n", total_bad == 0 && !g_by_len.empty() ? "ALL PASS" : "FAILURES");
    DomainParticipantFactory::get_instance()->delete_participant(p);
    return (total_bad == 0 && !g_by_len.empty()) ? 0 : 1;
}
