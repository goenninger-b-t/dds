// hello_secure_pub — M7/P6 Slice 5b reverse-direction peer: a DDS-Security-secured RTI
// Connext PUBLISHER of OUR HelloWorld type, so the clean-room Lisp stack (subscriber) can
// decode Connext's GOV=secure AEAD-protected user DATA (the mirror of Phase 4, where
// Connext decoded ours). External rtiddsgen interop peer; NOT part of the clean-room stack
// (docs/provenance.md). Security config comes from the named QoS profile in
// ./USER_QOS_PROFILES.xml (OursConnextInterop::secure = all-ENCRYPT discovery+rtps+data),
// which shares our reused Identity-CA / Permissions-CA / governance / S/MIME permissions.
//
// Usage: ./hello_secure_pub [domain=0] [profile=OursConnextInterop::secure] [count=0] [msg]
//   count 0 = publish forever (2 Hz) until the harness kills it (covers the ~40 s the Lisp
//   subscriber takes to load, authenticate, key, and secure-SEDP match before it can decode).

#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <cstdlib>

#include <dds/dds.hpp>
#include <rti/config/Logger.hpp>
#include "HelloWorld.hpp"

int main(int argc, char **argv)
{
    // CONNEXT_VERBOSE=1 surfaces the security plugin's auth/keying/match decisions on stderr.
    if (std::getenv("CONNEXT_VERBOSE"))
        rti::config::Logger::instance().verbosity(rti::config::Verbosity::STATUS_ALL);

    const int         domain  = (argc > 1) ? std::atoi(argv[1]) : 0;
    const std::string profile = (argc > 2) ? argv[2] : "OursConnextInterop::secure";
    const int         count   = (argc > 3) ? std::atoi(argv[3]) : 0;
    const std::string message = (argc > 4) ? argv[4] : "Hello world from Connext";

    // The security-bearing participant QoS: QosProvider::Default() auto-loads
    // ./USER_QOS_PROFILES.xml (run cwd), whose profile carries the dds.sec.* identity /
    // governance / permissions properties that drive the DDS-Security 1.1 path.
    dds::core::QosProvider qos_provider = dds::core::QosProvider::Default();
    dds::domain::DomainParticipant participant(
        domain, qos_provider.participant_qos(profile));

    // 3-arg Topic pins the registered type name to "HelloWorld" so discovery matches ours
    // (matches on topic name + type name; the Lisp peer registers type "HelloWorld").
    dds::topic::Topic<HelloWorld> topic(participant, "HelloWorldTopic", "HelloWorld");

    dds::pub::Publisher publisher(participant);
    dds::pub::qos::DataWriterQos qos = publisher.default_datawriter_qos();
    qos << dds::core::policy::Reliability::Reliable();
    dds::pub::DataWriter<HelloWorld> writer(publisher, topic, qos);

    std::cout << "[connext-hello-pub] HelloWorldTopic/" << topic.type_name()
              << " profile=" << profile << " domain=" << domain
              << " (NO_KEY, reliable, secured). publishing.\n";
    std::cout.flush();

    HelloWorld sample;
    unsigned int n = 0;
    for (;;) {
        sample.index(n);
        sample.message(message);
        writer.write(sample);
        std::cout << "[connext-hello-pub] sent index=" << n
                  << " message=\"" << message << "\"\n";
        std::cout.flush();
        ++n;
        if (count > 0 && static_cast<int>(n) >= count) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(500)); // 2 Hz
    }
    std::cout << "[connext-hello-pub] sent " << n << " sample(s).\n";
    return 0;
}
