# Fast DDS LargeData (DATA_FRAG) harness. Needs FASTDDS_PREFIX (use scripts/with-fastdds.sh).
# Regenerate types with: "$(FASTDDSGEN)" -replace -d gen LargeData.idl
CXX      ?= clang++
CXXFLAGS ?= -std=c++17 -O2 -Wall
INC       = -I"$(FASTDDS_PREFIX)/include" -Igen
LIBS      = -L"$(FASTDDS_PREFIX)/lib" -lfastdds -lfastcdr \
            -Wl,-rpath,"$(FASTDDS_PREFIX)/lib"
GEN_SRCS  = $(wildcard gen/*.cxx)
HDRS      = $(wildcard gen/*.hpp) participant_guard.hpp

all: large_sub

large_sub: large_sub.cpp $(GEN_SRCS) $(HDRS)
	$(CXX) $(CXXFLAGS) $(INC) -o $@ large_sub.cpp $(GEN_SRCS) $(LIBS)

clean:
	rm -f large_sub
