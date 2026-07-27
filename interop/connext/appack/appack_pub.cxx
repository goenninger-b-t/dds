// appack_pub — a Connext ShapeType writer configured for APPLICATION acknowledgment, so that the
// APP_ACK / APP_ACK_CONF exchange appears on the wire and can be captured (ADR 0090).
//
// WHY THIS EXISTS. Application acknowledgment has NO OMG clause — an exhaustive search of RTPS 2.5 and
// the DCPS IDL finds nothing (ADR 0090 §1). There is therefore no specification to implement from and
// no vector to check against: the only oracle is the wire. This peer, its subscriber twin, and a tshark
// capture ARE the specification we get.
//
// The QoS lives entirely in USER_QOS_PROFILES.xml (loopback-only transport + acknowledgment_kind), so
// this program calls no vendor-extension API and nothing about the C++ binding has to be assumed. It
// publishes plain @final ShapeType on "Square" — the same type every other leg uses, so no new IDL.
//
// Usage: ./appack_pub [domain] [samples] [seconds]
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <thread>

#include <dds/dds.hpp>
#include "ShapeType.hpp"

// Nothing may be written before a reader has MATCHED. The writer is KEEP_ALL/RELIABLE here, so an
// early sample is not lost — but it would be acknowledged before the capture starts, and an APP_ACK
// that happened off-camera is exactly the thing this peer exists to record.
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
    const int domain  = (argc > 1) ? std::atoi(argv[1]) : 0;
    const int samples = (argc > 2) ? std::atoi(argv[2]) : 5;
    const int seconds = (argc > 3) ? std::atoi(argv[3]) : 25;

    dds::domain::DomainParticipant dp(domain);
    dds::topic::Topic<ShapeType> topic(dp, "Square");
    dds::pub::Publisher pub(dp);

    MatchCount listener;
    dds::pub::DataWriter<ShapeType> writer(
        pub, topic, pub.default_datawriter_qos(), &listener,
        dds::core::status::StatusMask::publication_matched());

    std::cout << "[connext-appack-pub] Square/ShapeType domain=" << domain
              << " samples=" << samples
              << " (acknowledgment_kind from USER_QOS_PROFILES.xml)\n";
    std::cout.flush();

    // wait for the match, then let discovery settle so the capture is data-plane, not SEDP
    for (int i = 0; i < 200 && listener.matched.load() == 0; ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    if (listener.matched.load() == 0) {
        std::cout << "[connext-appack-pub] NEVER MATCHED — nothing was captured\n";
        return 1;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    ShapeType s;
    s.color("BLUE");
    for (int i = 0; i < samples; ++i) {
        s.x(10 + i); s.y(20 + i); s.shapesize(30);
        writer.write(s);
        std::cout << "[connext-appack-pub] wrote x=" << s.x() << "\n";
        std::cout.flush();
        std::this_thread::sleep_for(std::chrono::milliseconds(400));
    }

    // Stay up: the APP_ACK for the last sample, and its APP_ACK_CONF, arrive after the final write.
    // Exiting here would truncate exactly the exchange being captured.
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
    while (std::chrono::steady_clock::now() < deadline)
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

    std::cout << "[connext-appack-pub] done\n";
    return 0;
}
