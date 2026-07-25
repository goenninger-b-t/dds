// durable_pub — a Connext TRANSIENT_LOCAL + KEEP_ALL ShapeType writer that publishes its whole batch
// BEFORE any reader exists, then stays alive, so a LATE-JOINING peer must still receive every sample
// out of the writer's durable history (DDS 1.4 §2.2.3.4, FR-QOS-1; RTPS late-joiner replay).
//
// THE POINT IS THE ORDERING. Every other leg in this gate has the reader up first, so a writer with no
// history at all would pass them. Here the samples are gone from the wire by the time the reader
// appears: the only way it can see them is if the writer REPLAYS its history on match, which is the
// entire content of TRANSIENT_LOCAL. A VOLATILE writer scores zero here, which is the discrimination
// the leg exists for.
//
// It publishes with a settled delay AND keeps publishing nothing afterwards — deliberately. If it kept
// writing, a reader that got only live samples would look identical to one that got history.
//
// Usage: ./durable_pub [domain] [count] [seconds]
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <thread>

#include <dds/dds.hpp>
#include "ShapeType.hpp"

int main(int argc, char **argv)
{
    const int domain  = (argc > 1) ? std::atoi(argv[1]) : 0;
    const int count   = (argc > 2) ? std::atoi(argv[2]) : 10;
    const int seconds = (argc > 3) ? std::atoi(argv[3]) : 30;

    dds::domain::DomainParticipant dp(domain);
    dds::topic::Topic<ShapeType> topic(dp, "Square");
    dds::pub::Publisher pub(dp);

    dds::pub::qos::DataWriterQos wqos = pub.default_datawriter_qos();
    wqos << dds::core::policy::Reliability::Reliable()
         << dds::core::policy::Durability::TransientLocal()
         << dds::core::policy::History::KeepAll();
    dds::pub::DataWriter<ShapeType> writer(pub, topic, wqos);

    std::cout << "[connext-durable-pub] Square/ShapeType domain=" << domain
              << " TRANSIENT_LOCAL + KEEP_ALL; writing " << count
              << " sample(s) NOW, before any reader exists\n";
    std::cout.flush();

    ShapeType s;
    s.color("BLUE");
    s.shapesize(30);
    for (int i = 0; i < count; ++i) {
        s.x(10 + i);
        s.y(20 + i);
        writer.write(s);
        std::cout << "[connext-durable-pub] wrote #" << (i + 1) << " x=" << s.x() << "\n";
    }
    std::cout << "[connext-durable-pub] DONE WRITING — everything further a peer sees is REPLAYED HISTORY\n";
    std::cout.flush();

    // Stay alive so a late joiner can discover, match, and be replayed to. Nothing more is written.
    const auto end = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
    while (std::chrono::steady_clock::now() < end)
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    std::cout << "[connext-durable-pub] exiting\n";
    std::cout.flush();
    return 0;
}
