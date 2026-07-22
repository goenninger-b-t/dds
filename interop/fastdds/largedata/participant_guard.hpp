// Tears the participant down on every exit path (a missing BYE leaves the
// peer with a stale endpoint match until its lease expires).
#ifndef INTEROP_FASTDDS_PARTICIPANT_GUARD_HPP
#define INTEROP_FASTDDS_PARTICIPANT_GUARD_HPP

#include <fastdds/dds/domain/DomainParticipant.hpp>
#include <fastdds/dds/domain/DomainParticipantFactory.hpp>

struct ParticipantGuard
{
    eprosima::fastdds::dds::DomainParticipant* p;
    ~ParticipantGuard()
    {
        if (p != nullptr)
        {
            p->delete_contained_entities();
            eprosima::fastdds::dds::DomainParticipantFactory::get_instance()->delete_participant(p);
        }
    }
};

#endif
