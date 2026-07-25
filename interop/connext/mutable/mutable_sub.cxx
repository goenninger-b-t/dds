// mutable_sub — subscribe MutableData and print every received sample, so a live leg can assert that
// RTI Connext ACCEPTED and DECODED a @mutable sample this stack wrote (FR-IO, ADR 0086).
//
// This is the direction that matters and the one a captured vector cannot prove. The corpus proves our
// ENCODER reproduces Connext's octets; it says nothing about whether Connext's own reader accepts what
// we put on the wire — type gate, encapsulation id, member headers and all. Only Connext's DataReader
// delivering the sample proves that, and Connext is the STRICT oracle: it rejects payloads Fast DDS
// accepts (ADR 0061).
//
// It EXITS NORMALLY after <seconds>. It must: a killed process never flushes its stdout buffer, so the
// leg's log would read empty even though every sample arrived.
//
// Usage: ./mutable_sub [domain=0] [seconds=20]

#include <iostream>
#include <thread>
#include <chrono>
#include <cstdlib>

#include <dds/dds.hpp>
#include <rti/config/Logger.hpp>
#include "MutableData.hpp"

int main(int argc, char **argv)
{
    const int domain  = (argc > 1) ? std::atoi(argv[1]) : 0;
    const int seconds = (argc > 2) ? std::atoi(argv[2]) : 20;

    // MUT_SUB_VERBOSE=1 raises RTI's logger so it REPORTS WHY it declined to match a remote writer.
    // A reader that rejects a publication on type grounds is otherwise completely silent — it simply
    // never matches, which on this leg is indistinguishable from "the peer never wrote". Diagnosing
    // that by guessing costs far more than one env var.
    if (const char *v = std::getenv("MUT_SUB_VERBOSE")) {
        if (v[0] == '1')
            rti::config::Logger::instance().verbosity(rti::config::Verbosity::STATUS_ALL);
    }

    dds::domain::DomainParticipant dp(domain);
    dds::topic::Topic<MutableData> topic(dp, "MutableCorpus");

    dds::sub::Subscriber sub(dp);
    dds::sub::qos::DataReaderQos rqos = sub.default_datareader_qos();
    rqos << dds::core::policy::Reliability::Reliable();
    dds::sub::DataReader<MutableData> reader(sub, topic, rqos);

    std::cout << "[mut-sub] MutableCorpus/MutableData on domain " << domain
              << " for " << seconds << "s\n";
    std::cout.flush();

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
    long n = 0;
    while (std::chrono::steady_clock::now() < deadline) {
        dds::sub::LoanedSamples<MutableData> samples = reader.take();
        for (const auto &s : samples) {
            if (!s.info().valid()) continue;
            const MutableData &d = s.data();
            // Every member is printed so the leg asserts VALUES, not merely a sample count: a decode
            // that silently defaulted a member would otherwise pass.
            std::cout << "[mut-sub] a=" << d.a() << " b=" << d.b()
                      << " label=" << d.label() << " t_ns=" << d.t_ns()
                      << " vals=" << d.vals().size();
            for (size_t i = 0; i < d.vals().size(); ++i) std::cout << " " << d.vals()[i];
            std::cout << "\n";
            ++n;
        }
        std::cout.flush();
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    std::cout << "[mut-sub] received " << n << " sample(s)\n";
    std::cout.flush();
    return 0;
}
