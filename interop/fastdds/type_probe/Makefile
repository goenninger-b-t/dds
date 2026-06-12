# Fast DDS type-blind TypeLookup probe (S4 leg B). Needs FASTDDS_PREFIX (use
# scripts/with-fastdds.sh). Unlike shapes/, this app ships its OWN profiles.xml
# (loopback-only whitelist - see the comment there for the firewall rationale).
CXX      ?= clang++
CXXFLAGS ?= -std=c++17 -O2 -Wall
INC       = -I"$(FASTDDS_PREFIX)/include" -I../shapes
LIBS      = -L"$(FASTDDS_PREFIX)/lib" -lfastdds -lfastcdr \
            -Wl,-rpath,"$(FASTDDS_PREFIX)/lib"
HDRS      = ../shapes/participant_guard.hpp

all: type_probe

type_probe: type_probe.cpp $(HDRS)
	$(CXX) $(CXXFLAGS) $(INC) -o $@ type_probe.cpp $(LIBS)

clean:
	rm -f type_probe
