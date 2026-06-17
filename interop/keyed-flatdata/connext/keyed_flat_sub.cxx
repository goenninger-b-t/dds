// keyed_flat_sub — Connext subscribes to keyed KeyedFlat on topic "KeyedFlat".
// WP-KEYED-FLATDATA cross-DDS interop IN direction (this stack -> Connext): publish from this
// stack via
//   make keyed-flat-pub
// and verify Connext groups our keyed FlatData samples into the CORRECT per-key instances
// (proving our keyhash matches Connext's). The @key on `id` makes Connext register a WITH_KEY
// DataReader (RTPS 2.5 §9.3.1.2 kind 0x07) and assign each sample to a per-key instance via
// its keyhash (RTPS 2.5 §9.6.4.8). For each sample this prints the 16-octet instance handle
// hex so it can be compared, octet-for-octet, with this stack's per-key keyhash. The 3-arg
// Topic constructor pins the registered type name to "keyed-flat".
//
// Usage: ./keyed_flat_sub [domain=0] [seconds=0]   (seconds 0 = run forever)

#include <iostream>
#include <iomanip>
#include <thread>
#include <chrono>
#include <cstdlib>
#include <set>
#include <string>

#include <dds/dds.hpp>
#include <rti/config/Logger.hpp>
#include "KeyedFlat.hpp"

static std::string handle_hex(const dds::core::InstanceHandle &h)
{
    // h->native() is a DDS_InstanceHandle_t; .keyHash.value is RTICdrOctet[16] (the 16-octet
    // keyhash, RTPS 2.5 §9.6.4.8). Render it as hex so it can be compared octet-for-octet with
    // this stack's per-key keyhash.
    const unsigned char *bytes = h->native().keyHash.value;
    std::ostringstream os;
    for (int i = 0; i < 16; ++i)
        os << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(bytes[i]);
    return os.str();
}

int main(int argc, char **argv)
{
    if (std::getenv("CONNEXT_VERBOSE"))
        rti::config::Logger::instance().verbosity(rti::config::Verbosity::STATUS_ALL);

    const int domain  = (argc > 1) ? std::atoi(argv[1]) : 0;
    const int seconds = (argc > 2) ? std::atoi(argv[2]) : 0;

    dds::domain::DomainParticipant participant(domain);
    dds::topic::Topic<KeyedFlat> topic(participant, "KeyedFlat", "keyed-flat");

    dds::sub::Subscriber subscriber(participant);
    dds::sub::qos::DataReaderQos qos = subscriber.default_datareader_qos();
    qos << dds::core::policy::Reliability::Reliable()
        << dds::core::policy::History::KeepAll();
    dds::sub::DataReader<KeyedFlat> reader(subscriber, topic, qos);

    std::cout << "[connext-kflat-sub] KeyedFlat/" << topic.type_name()
              << " domain=" << domain << " (WITH_KEY 0x07, reliable). Ctrl-C to stop.\n";

    const auto start = std::chrono::steady_clock::now();
    long count = 0;
    std::set<std::string> instances;
    for (;;) {
        dds::sub::LoanedSamples<KeyedFlat> samples = reader.take();
        for (const auto &s : samples) {
            const std::string hx = handle_hex(s.info().instance_handle());
            instances.insert(hx);
            if (s.info().valid()) {
                const KeyedFlat &d = s.data();
                std::cout << "[connext-kflat-sub] #" << ++count << " id=" << d.id()
                          << " x=" << d.x() << " y=" << d.y()
                          << " instance(keyhash)=" << hx << "\n";
            } else {
                std::cout << "[connext-kflat-sub] INSTANCE_STATE change instance(keyhash)=" << hx
                          << " (dispose-by-key from peer)\n";
            }
        }
        if (seconds > 0 &&
            std::chrono::steady_clock::now() - start > std::chrono::seconds(seconds)) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    std::cout << "[connext-kflat-sub] received " << count << " sample(s) in "
              << instances.size() << " distinct instance(s).\n";
    return 0;
}
