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

    if (type == "C_Shape2") {
        C_Shape2 sample;
        sample.colour("BLUE");
        sample.x(50); sample.y(50); sample.shapesize(30);
        return run_corpus<C_Shape2>(domain, topic, type, sample);
    }

    if (type == "C_Shape3") {
        C_Shape3 sample;
        sample.color("BLUE");
        sample.x(50); sample.y(50); sample.shapesize(30); sample.w(7);
        return run_corpus<C_Shape3>(domain, topic, type, sample);
    }

    if (type == "C_Shape4") {
        C_Shape4 sample;
        sample.color("BLUE");
        sample.x(50); sample.y(50); sample.shapesize(30);
        return run_corpus<C_Shape4>(domain, topic, type, sample);
    }

    // Task 2.2 primitive-kind differentials: each retypes member x to one primitive.
    if (type == "C_ShapeP_short") {
        C_ShapeP_short sample;
        sample.color("BLUE"); sample.x(7); sample.y(50); sample.shapesize(30);
        return run_corpus<C_ShapeP_short>(domain, topic, type, sample);
    }
    if (type == "C_ShapeP_ushort") {
        C_ShapeP_ushort sample;
        sample.color("BLUE"); sample.x(7); sample.y(50); sample.shapesize(30);
        return run_corpus<C_ShapeP_ushort>(domain, topic, type, sample);
    }
    if (type == "C_ShapeP_ulong") {
        C_ShapeP_ulong sample;
        sample.color("BLUE"); sample.x(7); sample.y(50); sample.shapesize(30);
        return run_corpus<C_ShapeP_ulong>(domain, topic, type, sample);
    }
    if (type == "C_ShapeP_longlong") {
        C_ShapeP_longlong sample;
        sample.color("BLUE"); sample.x(7); sample.y(50); sample.shapesize(30);
        return run_corpus<C_ShapeP_longlong>(domain, topic, type, sample);
    }
    if (type == "C_ShapeP_ulonglong") {
        C_ShapeP_ulonglong sample;
        sample.color("BLUE"); sample.x(7); sample.y(50); sample.shapesize(30);
        return run_corpus<C_ShapeP_ulonglong>(domain, topic, type, sample);
    }
    if (type == "C_ShapeP_octet") {
        C_ShapeP_octet sample;
        sample.color("BLUE"); sample.x(7); sample.y(50); sample.shapesize(30);
        return run_corpus<C_ShapeP_octet>(domain, topic, type, sample);
    }
    if (type == "C_ShapeP_float") {
        C_ShapeP_float sample;
        sample.color("BLUE"); sample.x(7.0f); sample.y(50); sample.shapesize(30);
        return run_corpus<C_ShapeP_float>(domain, topic, type, sample);
    }
    if (type == "C_ShapeP_double") {
        C_ShapeP_double sample;
        sample.color("BLUE"); sample.x(7.0); sample.y(50); sample.shapesize(30);
        return run_corpus<C_ShapeP_double>(domain, topic, type, sample);
    }
    if (type == "C_ShapeP_boolean") {
        C_ShapeP_boolean sample;
        sample.color("BLUE"); sample.x(true); sample.y(50); sample.shapesize(30);
        return run_corpus<C_ShapeP_boolean>(domain, topic, type, sample);
    }
    if (type == "C_ShapeP_char") {
        C_ShapeP_char sample;
        sample.color("BLUE"); sample.x('Q'); sample.y(50); sample.shapesize(30);
        return run_corpus<C_ShapeP_char>(domain, topic, type, sample);
    }

    // Task 2.3 string-bound + @key-flag differentials.
    if (type == "C_ShapeS32") {
        C_ShapeS32 sample;
        sample.color("BLUE"); sample.x(50); sample.y(50); sample.shapesize(30);
        return run_corpus<C_ShapeS32>(domain, topic, type, sample);
    }
    if (type == "C_ShapeS300") {
        C_ShapeS300 sample;
        sample.color("BLUE"); sample.x(50); sample.y(50); sample.shapesize(30);
        return run_corpus<C_ShapeS300>(domain, topic, type, sample);
    }
    if (type == "C_ShapeNoKey") {
        C_ShapeNoKey sample;
        sample.color("BLUE"); sample.x(50); sample.y(50); sample.shapesize(30);
        return run_corpus<C_ShapeNoKey>(domain, topic, type, sample);
    }
    if (type == "C_ShapeAppend") {
        C_ShapeAppend sample;
        sample.color("BLUE"); sample.x(50); sample.y(50); sample.shapesize(30);
        return run_corpus<C_ShapeAppend>(domain, topic, type, sample);
    }
    if (type == "C_ShapeMutable") {
        C_ShapeMutable sample;
        sample.color("BLUE"); sample.x(50); sample.y(50); sample.shapesize(30);
        return run_corpus<C_ShapeMutable>(domain, topic, type, sample);
    }

    // Task 3.1 sequence-member differentials.
    if (type == "C_Seq") {
        C_Seq sample;
        sample.id(7); sample.payload().resize(3);
        return run_corpus<C_Seq>(domain, topic, type, sample);
    }
    if (type == "C_SeqL") {
        C_SeqL sample;
        sample.id(7); sample.payload().resize(3);
        return run_corpus<C_SeqL>(domain, topic, type, sample);
    }
    if (type == "C_SeqL100") {
        C_SeqL100 sample;
        sample.id(7); sample.payload().resize(3);
        return run_corpus<C_SeqL100>(domain, topic, type, sample);
    }

    // Task 3.2 nested-struct differentials.
    if (type == "C_Nested") {
        C_Nested sample;
        sample.id(7); sample.inner().a(1); sample.inner().b(2);
        return run_corpus<C_Nested>(domain, topic, type, sample);
    }
    if (type == "C_Nested2") {
        C_Nested2 sample;
        sample.id(7);
        sample.inner().a(1); sample.inner().b(2);
        sample.inner2().a(3); sample.inner2().b(4);
        return run_corpus<C_Nested2>(domain, topic, type, sample);
    }

    // Task 4.1 enum-member differential.
    if (type == "C_Enum") {
        C_Enum sample;
        sample.id(7); sample.e(SomeEnum::GREEN);
        return run_corpus<C_Enum>(domain, topic, type, sample);
    }

    // Task 4.2 union/array/bitmask degrading-tier differentials.
    if (type == "C_Union") {
        C_Union sample;
        sample.id(7);
        SomeUnion u; u.a(42);
        sample.u(u);
        return run_corpus<C_Union>(domain, topic, type, sample);
    }
    if (type == "C_Array") {
        C_Array sample;
        sample.id(7);
        sample.arr()[0] = 1; sample.arr()[1] = 2; sample.arr()[2] = 3; sample.arr()[3] = 4;
        return run_corpus<C_Array>(domain, topic, type, sample);
    }
    // C_Bitmask: NOT capturable — rtiddsgen 4.3.1 rejects the `bitmask` keyword. Gap in provenance.

    std::cerr << "usage: " << argv[0] << " <domain> <topic> <typename>\n"
              << "  unknown typename '" << type << "'; this build knows: C_Shape, C_Shape2, C_Shape3, C_Shape4,\n"
              << "  C_ShapeP_{short,ushort,ulong,longlong,ulonglong,octet,float,double,boolean,char},\n"
              << "  C_ShapeS32, C_ShapeS300, C_ShapeNoKey, C_ShapeAppend, C_ShapeMutable,\n"
              << "  C_Seq, C_SeqL, C_SeqL100, C_Nested, C_Nested2, C_Enum, C_Union, C_Array\n"
              << "  (C_Bitmask not capturable: rtiddsgen 4.3.1 rejects `bitmask` keyword)\n";
    return 1;
}
