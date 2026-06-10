// large_sub — Connext subscribes to LargeData and prints id + payload length per sample.
// A received full-length payload proves Connext reassembled the DATA_FRAGs forced by the
// message_size_max=1400 QoS; the (i*7) mod 256 pattern is verified octet-by-octet.
//
// Usage: ./large_sub [domain=0] [seconds=0]   (seconds 0 = run forever)

#include <iostream>
#include <thread>
#include <chrono>
#include <cstdlib>
#include <cstdint>

#include <dds/dds.hpp>
#include <rti/config/Logger.hpp>
#include "LargeData.hpp"

static bool pattern_ok(const std::vector<uint8_t> &p)
{
    for (size_t i = 0; i < p.size(); ++i)
        if (p[i] != static_cast<uint8_t>((i * 7) & 0xff)) return false;
    return true;
}

int main(int argc, char **argv)
{
    if (std::getenv("CONNEXT_VERBOSE"))
        rti::config::Logger::instance().verbosity(rti::config::Verbosity::STATUS_ALL);

    const int domain  = (argc > 1) ? std::atoi(argv[1]) : 0;
    const int seconds = (argc > 2) ? std::atoi(argv[2]) : 0;

    dds::domain::DomainParticipant participant(domain);
    dds::topic::Topic<LargeData> topic(participant, "LargeData");

    dds::sub::Subscriber subscriber(participant);
    dds::sub::qos::DataReaderQos qos = subscriber.default_datareader_qos();
    qos << dds::core::policy::Reliability::Reliable();
    dds::sub::DataReader<LargeData> reader(subscriber, topic, qos);

    std::cout << "[connext-large-sub] LargeData domain=" << domain
              << " (reliable). Ctrl-C to stop.\n";

    const auto start = std::chrono::steady_clock::now();
    long count = 0;
    for (;;) {
        dds::sub::LoanedSamples<LargeData> samples = reader.take();
        for (const auto &s : samples) {
            if (!s.info().valid()) continue;
            const LargeData &d = s.data();
            std::cout << "[connext-large-sub] #" << ++count << " id=" << d.id()
                      << " payload-len=" << d.payload().size()
                      << " pattern=" << (pattern_ok(d.payload()) ? "OK" : "BAD") << "\n";
        }
        if (seconds > 0 &&
            std::chrono::steady_clock::now() - start > std::chrono::seconds(seconds)) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    std::cout << "[connext-large-sub] received " << count << " sample(s).\n";
    return 0;
}
