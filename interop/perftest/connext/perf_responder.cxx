// Connext RESPONDER for the cross-stack parity harness (WP-CONFORMANCE-AND-PARITY WP-1).
//
// Subscribes PerfPing, echoes every sample VERBATIM on PerfPong. Interchangeable with our
// dds.bench:run-echo-responder and with the Fast DDS responder: same topics, same type, same
// QoS, same wait strategy (a listener, not a poll loop). That interchangeability is the whole
// point — hold the PINGER constant and swap the RESPONDER, and the difference is the stack.
//
// Clean-room: written against the public Connext Modern C++ API from the RTI documentation.
// No RTI source, headers or rtiddsgen output is copied into this repo (the generated type
// support is produced locally at build time and is git-ignored). NFR-IP.
//
// QoS is pinned to match the Lisp side exactly:
//   RELIABLE, KEEP_ALL, VOLATILE, and a reader/writer data_representation of XCDR2 —
//   because our writer OFFERS XCDR2 by default and DATA_REPRESENTATION is an RxO policy
//   (a stock Connext reader advertises XCDR1 only and would silently not match).
//
//   ./perf_responder [domain] [seconds]

#include <iostream>
#include <thread>
#include <chrono>
#include <atomic>
#include <vector>

#include <dds/domain/DomainParticipant.hpp>
#include <dds/topic/Topic.hpp>
#include <dds/pub/ddspub.hpp>
#include <dds/sub/ddssub.hpp>
#include <rti/config/Logger.hpp>

#include "PerfData.hpp"

namespace {

std::atomic<long> g_echoed(0);

// Echo listener: on data, take everything and republish it verbatim. A LISTENER (not a poll
// loop) so the wait strategy matches the other stacks' — a busy-poll on one side and a
// listener on the other would measure the poll interval, not the stack.
class EchoListener : public dds::sub::NoOpDataReaderListener<PerfData> {
public:
    explicit EchoListener(dds::pub::DataWriter<PerfData>& w) : writer_(w) {}

    void on_data_available(dds::sub::DataReader<PerfData>& reader) override {
        dds::sub::LoanedSamples<PerfData> samples = reader.take();
        for (const auto& s : samples) {
            if (s.info().valid()) {
                writer_.write(s.data());
                ++g_echoed;
            }
        }
    }

private:
    dds::pub::DataWriter<PerfData>& writer_;
};

}  // namespace

int main(int argc, char* argv[])
{
    const int domain  = (argc > 1) ? std::atoi(argv[1]) : 0;
    const int seconds = (argc > 2) ? std::atoi(argv[2]) : 60;

    if (std::getenv("CONNEXT_VERBOSE"))
        rti::config::Logger::instance().verbosity(rti::config::Verbosity::STATUS_ALL);

    dds::domain::DomainParticipant participant(domain);

    dds::topic::Topic<PerfData> ping(participant, "PerfPing");
    dds::topic::Topic<PerfData> pong(participant, "PerfPong");

    // Match the Lisp side's QoS exactly (see the header comment).
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

    dds::pub::DataWriter<PerfData> writer(publisher, pong, wqos);
    EchoListener listener(writer);
    dds::sub::DataReader<PerfData> reader(subscriber, ping, rqos);
    reader.listener(&listener, dds::core::status::StatusMask::data_available());

    std::cout << "[connext-responder] PerfPing -> PerfPong, domain=" << domain
              << ", running " << seconds << "s.\n" << std::flush;

    std::this_thread::sleep_for(std::chrono::seconds(seconds));

    reader.listener(nullptr, dds::core::status::StatusMask::none());
    std::cout << "[connext-responder] echoed " << g_echoed.load() << " sample(s).\n" << std::flush;
    return 0;
}
