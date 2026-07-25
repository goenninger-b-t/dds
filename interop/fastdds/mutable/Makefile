# Fast DDS MUTABLE harness (ADR 0086: does a SECOND vendor emit PL_CDR2 for @mutable?). Needs FASTDDS_PREFIX + FASTDDSGEN
# (use scripts/with-fastdds.sh).  make gen  then  make mutable_pub.
# fastddsgen output (gen/) is git-ignored — clean-room, generated locally.
CXX      ?= clang++
CXXFLAGS ?= -std=c++17 -O2 -Wall
INC       = -I"$(FASTDDS_PREFIX)/include" -Igen
LIBS      = -L"$(FASTDDS_PREFIX)/lib" -lfastdds -lfastcdr \
            -Wl,-rpath,"$(FASTDDS_PREFIX)/lib"
GEN_SRCS  = $(wildcard gen/*.cxx)
HDRS      = $(wildcard gen/*.hpp) participant_guard.hpp

all: mutable_pub

gen: MutableData.idl
	mkdir -p gen && "$(FASTDDSGEN)" -replace -d gen MutableData.idl

mutable_pub: mutable_pub.cpp $(GEN_SRCS) $(HDRS)
	$(CXX) $(CXXFLAGS) $(INC) -o $@ mutable_pub.cpp $(GEN_SRCS) $(LIBS)

clean:
	rm -f mutable_pub
