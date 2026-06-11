// corpus_pub — put a Connext corpus type on the wire so its SEDP announcement (carrying
// RTI's proprietary legacy TypeObject, the inflated PID_TYPE_OBJECT_LB / 0x8021) can be
// captured by this stack's `make corpus-capture` subscriber and reverse-engineered.
//
// It follows the typeobject_probe pattern: a matched writer + reader (two participants in
// one process) so SEDP definitely fires, then idles writing one sample so a late capturer
// still sees DATA + discovery. Topic and type name are selectable by argv so the ONE binary
// serves every corpus type:
//
//   ./corpus_pub <domain> <topic> <typename>     (e.g. ./corpus_pub 0 Square C_Shape)
//
// For THIS task only C_Shape exists in Corpus.idl; the argv dispatch is built so later tasks
// add types to Corpus.idl, extend the dispatch below, and rebuild — no new binary needed.
//
// Clean-room: this app mirrors our own ../typeobject-probe app; rtiddsgen output stays
// git-ignored and is never committed, and no RTI source is read to decode anything.

#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <cstdlib>

#include <dds/dds.hpp>
#include <rti/config/Logger.hpp>
#include "Corpus.hpp"

// Drive one corpus type: matched writer+reader on <topic>, idle writing one sample.
template <typename T>
static int run_corpus(int domain, const std::string &topic, const std::string &typname,
                      const T &sample)
{
    dds::domain::DomainParticipant dp1(domain);
    dds::domain::DomainParticipant dp2(domain);
    dds::topic::Topic<T> t1(dp1, topic);
    dds::topic::Topic<T> t2(dp2, topic);

    dds::pub::qos::DataWriterQos wqos = dds::pub::Publisher(dp1).default_datawriter_qos();
    wqos << dds::core::policy::Reliability::Reliable();
    dds::pub::DataWriter<T> writer(dds::pub::Publisher(dp1), t1, wqos);

    dds::sub::qos::DataReaderQos rqos = dds::sub::Subscriber(dp2).default_datareader_qos();
    rqos << dds::core::policy::Reliability::Reliable();
    dds::sub::DataReader<T> reader(dds::sub::Subscriber(dp2), t2, rqos);

    std::cout
        << "[corpus-pub] topic='" << topic << "' type_name='" << t1.type_name()
        << "' (requested '" << typname << "') on domain " << domain << "\n"
        << "[corpus-pub] idling so SEDP (legacy TypeObject) stays on the wire; Ctrl-C to stop.\n";

    T s = sample;
    for (;;) {
        writer.write(s);
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    return 0;
}

int main(int argc, char **argv)
{
    // Set CONNEXT_VERBOSE=1 to surface Connext's discovery/match decisions on stderr.
    if (std::getenv("CONNEXT_VERBOSE"))
        rti::config::Logger::instance().verbosity(rti::config::Verbosity::STATUS_ALL);

    const int domain        = (argc > 1) ? std::atoi(argv[1]) : 0;
    const std::string topic = (argc > 2) ? argv[2] : "Square";
    const std::string type  = (argc > 3) ? argv[3] : "C_Shape";

    if (type == "C_Shape") {
        C_Shape sample;
        sample.color("BLUE");
        sample.x(50); sample.y(50); sample.shapesize(30);
        return run_corpus<C_Shape>(domain, topic, type, sample);
    }

    std::cerr << "usage: " << argv[0] << " <domain> <topic> <typename>\n"
              << "  unknown typename '" << type << "'; this build knows: C_Shape\n"
              << "  (later corpus tasks add types to Corpus.idl + a dispatch arm here)\n";
    return 1;
}
