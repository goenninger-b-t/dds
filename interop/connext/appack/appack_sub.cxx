// appack_sub — the subscriber twin of appack_pub (ADR 0090).
//
// Under APPLICATION_AUTO acknowledgment a sample becomes acknowledged when the subscribing application
// ACCESSES it — so the ordinary take() loop below IS the acknowledgment, and no vendor-extension API
// call is needed to provoke APP_ACK onto the wire. That is the whole reason this capture uses AUTO
// rather than EXPLICIT: it keeps the peer free of any assumption about the C++ binding, so the only
// thing under test is the wire.
//
// Usage: ./appack_sub [domain] [seconds]
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <thread>

#include <dds/dds.hpp>
#include "ShapeType.hpp"

int main(int argc, char **argv)
{
    const int domain  = (argc > 1) ? std::atoi(argv[1]) : 0;
    const int seconds = (argc > 2) ? std::atoi(argv[2]) : 25;

    dds::domain::DomainParticipant dp(domain);
    dds::topic::Topic<ShapeType> topic(dp, "Square");
    dds::sub::Subscriber sub(dp);
    dds::sub::DataReader<ShapeType> reader(sub, topic, sub.default_datareader_qos());

    std::cout << "[connext-appack-sub] Square/ShapeType domain=" << domain
              << " (acknowledgment_kind from USER_QOS_PROFILES.xml)\n";
    std::cout.flush();

    int received = 0;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
    while (std::chrono::steady_clock::now() < deadline) {
        // take() is the access that acknowledges under APPLICATION_AUTO. The samples are consumed
        // here rather than merely counted so the acknowledgment is unambiguous.
        dds::sub::LoanedSamples<ShapeType> ss = reader.take();
        for (const auto& s : ss) {
            if (s.info().valid()) {
                ++received;
                std::cout << "[connext-appack-sub] took x=" << s.data().x()
                          << " (total " << received << ")\n";
                std::cout.flush();
            }
        }
        // The loan is returned when `ss` goes out of scope at the end of this iteration; under
        // APPLICATION_AUTO with loaned samples that return is what completes the acknowledgment.
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    std::cout << "[connext-appack-sub] RESULT: took " << received << " sample(s)\n";
    return 0;
}
