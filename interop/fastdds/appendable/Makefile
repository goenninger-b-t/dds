# Fast DDS appendable harness (interop Leg 1, cross-DDS half). Needs FASTDDS_PREFIX + FASTDDSGEN
# (use scripts/with-fastdds.sh).  make gen  then  make appendable_pub.
# fastddsgen output (gen/) is git-ignored — clean-room, generated locally.
CXX      ?= clang++
CXXFLAGS ?= -std=c++17 -O2 -Wall
INC       = -I"$(FASTDDS_PREFIX)/include" -Igen
LIBS      = -L"$(FASTDDS_PREFIX)/lib" -lfastdds -lfastcdr \
            -Wl,-rpath,"$(FASTDDS_PREFIX)/lib"
GEN_SRCS  = $(wildcard gen/*.cxx)
HDRS      = $(wildcard gen/*.hpp) participant_guard.hpp

all: appendable_pub

gen: AppendableShape.idl
	mkdir -p gen && "$(FASTDDSGEN)" -replace -d gen AppendableShape.idl

appendable_pub: appendable_pub.cpp $(GEN_SRCS) $(HDRS)
	$(CXX) $(CXXFLAGS) $(INC) -o $@ appendable_pub.cpp $(GEN_SRCS) $(LIBS)

clean:
	rm -f appendable_pub
