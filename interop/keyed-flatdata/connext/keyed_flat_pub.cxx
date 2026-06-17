// keyed_flat_pub — Connext publishes keyed KeyedFlat samples on topic "KeyedFlat".
// WP-KEYED-FLATDATA cross-DDS interop OUT direction (Connext -> this stack): run this and
// verify this stack's keyed FlatData subscriber groups the samples into the CORRECT per-key
// instances via
//   make keyed-flat-sub
// The @key on `id` makes Connext register a WITH_KEY DataWriter (RTPS 2.5 §9.3.1.2 kind 0x02)
// and compute the per-key instance keyhash (RTPS 2.5 §9.6.4.8) from the i32 id; alive DATA
// carries the key in the XCDR payload (no PID_KEY_HASH), a dispose DATA carries PID_KEY_HASH.
// The 3-arg Topic constructor pins the registered type name to "keyed-flat" so it is
// byte-identical to this stack's registered type-name (discovery matches on topic + type name).
//
// Usage: ./keyed_flat_pub [domain=0] [count=0] [keys=3]   (count 0 = run forever)
// Env: DISPOSE_AFTER=N  dispose EACH key once N samples per key have been sent, then keep
//      publishing the survivors (proves dispose-by-key crosses the wire).

#include <iostream>
#include <thread>
#include <chrono>
#include <cstdlib>
#include <vector>

#include <dds/dds.hpp>
#include <rti/config/Logger.hpp>
#include "KeyedFlat.hpp"

int main(int argc, char **argv)
{
    if (std::getenv("CONNEXT_VERBOSE"))
        rti::config::Logger::instance().verbosity(rti::config::Verbosity::STATUS_ALL);

    const int domain = (argc > 1) ? std::atoi(argv[1]) : 0;
    const int count  = (argc > 2) ? std::atoi(argv[2]) : 0;
    const int keys   = (argc > 3) ? std::atoi(argv[3]) : 3;
    const long dispose_after = std::getenv("DISPOSE_AFTER") ? std::atol(std::getenv("DISPOSE_AFTER")) : 0;

    dds::domain::DomainParticipant participant(domain);
    dds::topic::Topic<KeyedFlat> topic(participant, "KeyedFlat", "keyed-flat");

    dds::pub::Publisher publisher(participant);
    dds::pub::qos::DataWriterQos qos = publisher.default_datawriter_qos();
    // XCDR2 (PLAIN_CDR2) data representation: this stack's FlatData type is an XCDR2 type, so a
    // conformant XTypes peer must publish XCDR2 (DDS-XTypes 1.3 §7.6.3.1.1 — absent this hint Connext
    // defaults to XCDR1 for backward compat, which our XCDR2-only FlatData reader does not accept).
    dds::core::policy::DataRepresentation xcdr2;
    xcdr2.value().push_back(DDS_XCDR2_DATA_REPRESENTATION);
    qos << dds::core::policy::Reliability::Reliable()
        << dds::core::policy::History::KeepAll()
        << xcdr2;
    dds::pub::DataWriter<KeyedFlat> writer(publisher, topic, qos);

    std::cout << "[connext-kflat-pub] KeyedFlat/" << topic.type_name()
              << " domain=" << domain << " (WITH_KEY 0x02, reliable, " << keys
              << " key(s)). Ctrl-C to stop.\n";

    std::vector<bool> disposed(keys, false);
    int n = 0;
    for (;;) {
        ++n;
        const int id = n % keys;
        KeyedFlat sample;
        sample.id(id);
        sample.x(50 + (n % 100));
        sample.y(50 + ((n * 7) % 100));
        writer.write(sample);
        if (n % keys == 0)
            std::cout << "[connext-kflat-pub] sent #" << n << " id=" << id
                      << " x=" << sample.x() << " y=" << sample.y() << "\n";
        // dispose-by-key: once each key has reached DISPOSE_AFTER, dispose it once
        if (dispose_after > 0 && n >= dispose_after * keys && !disposed[id]) {
            writer.dispose_instance(writer.lookup_instance(sample));
            disposed[id] = true;
            std::cout << "[connext-kflat-pub] DISPOSED key id=" << id
                      << " (dispose DATA carries PID_KEY_HASH inline-QoS)\n";
        }
        if (count > 0 && n >= count) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(200)); // 5 Hz
    }
    // hold the participant briefly so reliable dispose DATA reaches matched readers
    std::this_thread::sleep_for(std::chrono::seconds(2));
    std::cout << "[connext-kflat-pub] sent " << n << " sample(s).\n";
    return 0;
}
