// liveliness_pub — a Connext ShapeType writer with MANUAL_BY_TOPIC liveliness and a finite lease that
// asserts for a while and then STOPS ASSERTING while staying discovered, so a peer must observe the
// writer go ALIVE -> NOT_ALIVE (DDS 1.4 §2.2.3.11 LIVELINESS, §2.2.4.1 LIVELINESS_CHANGED).
//
// MANUAL_BY_TOPIC, not AUTOMATIC, and that is the whole design. Under AUTOMATIC the infrastructure
// asserts liveliness for you as long as the process is alive, so the ONLY way to make a writer go
// not-alive is to kill it — and a killed writer also disappears from discovery, which is a DIFFERENT
// event (unmatch) that a reader would report through PUBLICATION/SUBSCRIPTION_MATCHED instead. The
// interesting case, and the one no other leg in this gate can produce, is a writer that is still
// DISCOVERED and still MATCHED going NOT_ALIVE purely because its lease expired.
//
// Usage: ./liveliness_pub [domain] [lease_ms] [assert_seconds] [total_seconds]
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <thread>

#include <dds/dds.hpp>
#include "ShapeType.hpp"

class MatchCount : public dds::pub::NoOpDataWriterListener<ShapeType>
{
public:
    void on_publication_matched(dds::pub::DataWriter<ShapeType>&,
                                const dds::core::status::PublicationMatchedStatus& st) override
    { matched = st.current_count(); }
    std::atomic<int> matched{0};
};

int main(int argc, char **argv)
{
    const int domain   = (argc > 1) ? std::atoi(argv[1]) : 0;
    const int lease_ms = (argc > 2) ? std::atoi(argv[2]) : 2000;
    const int assert_s = (argc > 3) ? std::atoi(argv[3]) : 8;
    const int total_s  = (argc > 4) ? std::atoi(argv[4]) : 30;

    dds::domain::DomainParticipant dp(domain);
    dds::topic::Topic<ShapeType> topic(dp, "Square");
    dds::pub::Publisher pub(dp);

    dds::pub::qos::DataWriterQos wqos = pub.default_datawriter_qos();
    wqos << dds::core::policy::Reliability::Reliable()
         << dds::core::policy::Liveliness::ManualByTopic(
                dds::core::Duration::from_millisecs(lease_ms));
    MatchCount listener;
    dds::pub::DataWriter<ShapeType> writer(
        pub, topic, wqos, &listener, dds::core::status::StatusMask::publication_matched());

    std::cout << "[connext-liveliness-pub] Square/ShapeType domain=" << domain
              << " MANUAL_BY_TOPIC lease=" << lease_ms << "ms; asserting for " << assert_s
              << "s then STOPPING while staying discovered\n";
    std::cout.flush();

    const auto end = std::chrono::steady_clock::now() + std::chrono::seconds(total_s);
    for (int w = 0; w < 300 && listener.matched.load() == 0
                    && std::chrono::steady_clock::now() < end; ++w)
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    std::cout << "[connext-liveliness-pub] matched=" << listener.matched.load() << "\n";
    std::cout.flush();

    ShapeType s;
    s.color("BLUE");
    s.shapesize(30);
    s.x(1);
    s.y(1);

    // Assert well inside the lease. A write is itself an assertion under MANUAL_BY_TOPIC.
    const auto stop_asserting = std::chrono::steady_clock::now() + std::chrono::seconds(assert_s);
    while (std::chrono::steady_clock::now() < stop_asserting) {
        writer.write(s);
        std::this_thread::sleep_for(std::chrono::milliseconds(lease_ms / 3));
    }
    std::cout << "[connext-liveliness-pub] STOPPED ASSERTING — the peer must now see ALIVE -> NOT_ALIVE\n";
    std::cout.flush();

    // Stay alive and DISCOVERED. Exiting would unmatch, which is a different event entirely.
    while (std::chrono::steady_clock::now() < end)
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    std::cout << "[connext-liveliness-pub] exiting\n";
    std::cout.flush();
    return 0;
}
