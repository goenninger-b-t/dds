// deadline_pub — a Connext ShapeType writer that publishes at a steady rate, then DELIBERATELY STOPS,
// so a peer's REQUESTED_DEADLINE_MISSED must start climbing (DDS 1.4 §2.2.3.7, FR-DCPS-3/FR-QOS-1).
//
// WHY A PEER THAT STOPS. A deadline test where the writer keeps writing proves only that samples
// arrive — the deadline machinery is never exercised, because nothing ever misses. The interesting
// assertion is the ABSENCE of a sample within the period, and the only way a cross-vendor leg can make
// that happen is a foreign writer that goes quiet on purpose while the reader stays up.
//
// OFFERED <= REQUESTED is the RxO rule (§2.2.3.7): this writer OFFERS the period given on the command
// line, and the peer requests something >= it, so they match and the peer's clock is what decides.
//
// Publishes @final ShapeType on "Square" — the same type the Shapes legs use, so no new IDL.
// Usage: ./deadline_pub [domain] [offered_deadline_ms] [samples_before_going_quiet] [total_seconds]
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <thread>
#include <atomic>

#include <dds/dds.hpp>
#include "ShapeType.hpp"

// Publishing must not start before a reader has MATCHED. This writer is VOLATILE with the default
// KEEP_LAST history, so anything written before the match is simply gone — the peer would report zero
// samples and zero deadline misses, which reads exactly like a broken deadline implementation. That is
// not a subtlety of this test; it is the ordinary late-joiner rule, and the harness has to respect it.
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
    const int domain      = (argc > 1) ? std::atoi(argv[1]) : 0;
    const int deadline_ms = (argc > 2) ? std::atoi(argv[2]) : 1000;
    const int before_quiet= (argc > 3) ? std::atoi(argv[3]) : 8;
    const int seconds     = (argc > 4) ? std::atoi(argv[4]) : 25;

    dds::domain::DomainParticipant dp(domain);
    dds::topic::Topic<ShapeType> topic(dp, "Square");
    dds::pub::Publisher pub(dp);

    dds::pub::qos::DataWriterQos wqos = pub.default_datawriter_qos();
    wqos << dds::core::policy::Reliability::Reliable()
         << dds::core::policy::Deadline(dds::core::Duration::from_millisecs(deadline_ms));
    MatchCount listener;
    dds::pub::DataWriter<ShapeType> writer(
        pub, topic, wqos, &listener,
        dds::core::status::StatusMask::publication_matched());

    std::cout << "[connext-deadline-pub] Square/ShapeType domain=" << domain
              << " offered-deadline=" << deadline_ms << "ms; will send " << before_quiet
              << " sample(s) then GO QUIET for the rest of " << seconds << "s\n";
    std::cout.flush();

    ShapeType s;
    s.color("BLUE");
    s.shapesize(30);

    const auto end = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);

    // Wait for a reader before the first write (see MatchCount). Bounded, so a leg with no peer at all
    // still terminates and fails on sample count rather than hanging.
    for (int w = 0; w < 300 && listener.matched.load() == 0
                    && std::chrono::steady_clock::now() < end; ++w)
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    std::cout << "[connext-deadline-pub] matched=" << listener.matched.load()
              << " — starting the active phase\n";
    std::cout.flush();

    for (int i = 0; i < before_quiet; ++i) {
        s.x(50 + i);
        s.y(60 + i);
        writer.write(s);
        std::cout << "[connext-deadline-pub] sent #" << (i + 1) << "\n";
        std::cout.flush();
        // Comfortably inside the offered period so nothing misses while we are still writing.
        std::this_thread::sleep_for(std::chrono::milliseconds(deadline_ms / 2));
    }
    std::cout << "[connext-deadline-pub] GOING QUIET — the peer's REQUESTED_DEADLINE_MISSED must now climb\n";
    std::cout.flush();

    // Stay alive and MATCHED. Exiting here would unmatch the endpoint, and an unmatched reader has no
    // deadline to miss — the status would never fire and the leg would prove nothing.
    while (std::chrono::steady_clock::now() < end)
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

    std::cout << "[connext-deadline-pub] done\n";
    std::cout.flush();
    return 0;
}
