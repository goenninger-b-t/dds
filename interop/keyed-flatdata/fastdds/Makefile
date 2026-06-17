# WP-KEYED-FLATDATA Fast DDS interop apps (FR-PF-4). Needs FASTDDS_PREFIX (use scripts/with-fastdds.sh).
# Mirrors interop/fastdds/shapes/Makefile. The gen/ type support is fastddsgen output committed
# verbatim (Apache-2.0; see ../README.md + docs/provenance.md). Regenerate after an IDL change with:
#   ../../../scripts/with-fastdds.sh bash -c '"$FASTDDSGEN" -replace -d gen ../KeyedFlat.idl'
CXX      ?= clang++
CXXFLAGS ?= -std=c++17 -O2 -Wall
INC       = -I"$(FASTDDS_PREFIX)/include" -Igen
LIBS      = -L"$(FASTDDS_PREFIX)/lib" -lfastdds -lfastcdr \
            -Wl,-rpath,"$(FASTDDS_PREFIX)/lib"
GEN_SRCS  = $(wildcard gen/*.cxx)
HDRS      = $(wildcard gen/*.hpp) participant_guard.hpp

all: keyed_flat_pub keyed_flat_sub

keyed_flat_pub: keyed_flat_pub.cpp $(GEN_SRCS) $(HDRS)
	$(CXX) $(CXXFLAGS) $(INC) -o $@ keyed_flat_pub.cpp $(GEN_SRCS) $(LIBS)

keyed_flat_sub: keyed_flat_sub.cpp $(GEN_SRCS) $(HDRS)
	$(CXX) $(CXXFLAGS) $(INC) -o $@ keyed_flat_sub.cpp $(GEN_SRCS) $(LIBS)

clean:
	rm -f keyed_flat_pub keyed_flat_sub
