// Connext PINGER for the cross-stack parity harness (WP-CONFORMANCE-AND-PARITY WP-1).
//
// Writes ONE PerfPing sample, waits for the echo on PerfPong, records the RTT; one-way := RTT/2.
// Single in-flight — no pipelining, which is what makes this a LATENCY number and not a
// throughput number in disguise. Identical in every measurable respect to our Lisp pinger
// (dds.bench:run-echo-pinger): same topics, same type, same QoS, same wait strategy (a
// listener + condvar, not a poll), same clock (steady_clock ~ monotonic-ns), same percentile
// rule (nearest-rank on the ascending sorted vector), same warmup discipline.
//
// Connext<->Connext is THE REFERENCE the NFR-PERF ratios are taken against; ours<->Connext
// additionally proves interop under load. Clean-room: public Connext Modern C++ API only.
//
//   ./perf_pinger [domain] [samples] [payload_bytes] [warmup]

#include <iostream>
#include <vector>
#include <algorithm>
#include <numeric>
#include <chrono>
#include <mutex>
#include <condition_variable>
#include <cstdint>
#include <thread>

#include <dds/domain/DomainParticipant.hpp>
#include <dds/topic/Topic.hpp>
#include <dds/pub/ddspub.hpp>
#include <dds/sub/ddssub.hpp>

#include "PerfData.hpp"

namespace {

std::mutex g_m;
std::condition_variable g_cv;
bool g_got = false;
std::chrono::steady_clock::time_point g_recv;

class PongListener : public dds::sub::NoOpDataReaderListener<PerfData> {
public:
    void on_data_available(dds::sub::DataReader<PerfData>& reader) override {
        dds::sub::LoanedSamples<PerfData> samples = reader.take();
        for (const auto& s : samples) {
            if (!s.info().valid()) continue;
            {
                std::lock_guard<std::mutex> lk(g_m);
                g_recv = std::chrono::steady_clock::now();
                g_got = true;
            }
            g_cv.notify_one();
        }
    }
};

// Nearest-rank quantile on an ascending vector — the SAME rule as the Lisp %pct, so the two
// stacks' percentiles are computed identically and the ratio is not an artifact of the stat.
int64_t pct(const std::vector<int64_t>& sorted, double frac) {
    size_t i = static_cast<size_t>(frac * sorted.size());
    if (i >= sorted.size()) i = sorted.size() - 1;
    return sorted[i];
}

}  // namespace

int main(int argc, char* argv[])
{
    const int domain  = (argc > 1) ? std::atoi(argv[1]) : 0;
    const int samples = (argc > 2) ? std::atoi(argv[2]) : 10000;
    const int payload = (argc > 3) ? std::atoi(argv[3]) : 256;
    const int warmup  = (argc > 4) ? std::atoi(argv[4]) : 1000;

    dds::domain::DomainParticipant participant(domain);
    dds::topic::Topic<PerfData> ping(participant, "PerfPing");
    dds::topic::Topic<PerfData> pong(participant, "PerfPong");

    dds::pub::qos::DataWriterQos wqos = dds::pub::Publisher(participant).default_datawriter_qos();
    wqos << dds::core::policy::Reliability::Reliable()
         << dds::core::policy::History::KeepAll()
         << dds::core::policy::Durability::Volatile();
    // XCDR2 on BOTH sides: our writer OFFERS XCDR2 by default, and DATA_REPRESENTATION is an RxO
    // policy — a stock Connext reader advertises XCDR1 only and would silently NOT match.
    wqos << dds::core::policy::DataRepresentation(
                std::vector<dds::core::policy::DataRepresentationId>{
                    dds::core::policy::DataRepresentation::xcdr2()});

    dds::sub::qos::DataReaderQos rqos = dds::sub::Subscriber(participant).default_datareader_qos();
    rqos << dds::core::policy::Reliability::Reliable()
         << dds::core::policy::History::KeepAll()
         << dds::core::policy::Durability::Volatile();
    rqos << dds::core::policy::DataRepresentation(
                std::vector<dds::core::policy::DataRepresentationId>{
                    dds::core::policy::DataRepresentation::xcdr2()});

    dds::pub::Publisher publisher(participant);
    dds::sub::Subscriber subscriber(participant);
    dds::pub::DataWriter<PerfData> writer(publisher, ping, wqos);
    PongListener listener;
    dds::sub::DataReader<PerfData> reader(subscriber, pong, rqos);
    reader.listener(&listener, dds::core::status::StatusMask::data_available());

    // Wait for BOTH endpoints to match the responder's before a single measurement is taken —
    // a bench that reports the numbers of a run that never talked to anyone is worse than none.
    for (int i = 0; i < 300; ++i) {
        if (writer.publication_matched_status().current_count() > 0 &&
            reader.subscription_matched_status().current_count() > 0) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    if (writer.publication_matched_status().current_count() == 0 ||
        reader.subscription_matched_status().current_count() == 0) {
        std::cerr << "[connext-pinger] peer did not match within 30s — is the responder up?\n";
        return 1;
    }

    PerfData sample;
    sample.id(1);
    std::vector<uint8_t> data(static_cast<size_t>(payload));
    for (size_t i = 0; i < data.size(); ++i) data[i] = static_cast<uint8_t>(i & 0xff);
    sample.data(data);

    auto one = [&]() -> int64_t {
        {
            std::lock_guard<std::mutex> lk(g_m);
            g_got = false;
        }
        auto t0 = std::chrono::steady_clock::now();
        writer.write(sample);
        std::unique_lock<std::mutex> lk(g_m);
        if (!g_cv.wait_for(lk, std::chrono::seconds(5), [] { return g_got; })) {
            std::cerr << "[connext-pinger] no echo within 5s (peer died / reliable stall?)\n";
            std::exit(2);
        }
        return std::chrono::duration_cast<std::chrono::nanoseconds>(g_recv - t0).count();
    };

    for (int i = 0; i < warmup; ++i) one();

    std::vector<int64_t> oneway;
    oneway.reserve(static_cast<size_t>(samples));
    for (int i = 0; i < samples; ++i) oneway.push_back(one() / 2);   // one-way := RTT/2

    std::sort(oneway.begin(), oneway.end());
    const int64_t mean = std::accumulate(oneway.begin(), oneway.end(), int64_t(0)) / oneway.size();

    std::cout << "| " << "connext   " << " | " << payload
              << " | p50=" << pct(oneway, 0.50)
              << " | p99=" << pct(oneway, 0.99)
              << " | p99.99=" << pct(oneway, 0.9999)
              << " | max=" << oneway.back()
              << " | min=" << oneway.front()
              << " | mean=" << mean
              << "   (one-way ns, " << samples << " samples)\n" << std::flush;
    return 0;
}
