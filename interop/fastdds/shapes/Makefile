# Fast DDS shapes harness. Needs FASTDDS_PREFIX (use scripts/with-fastdds.sh).
CXX      ?= clang++
CXXFLAGS ?= -std=c++17 -O2 -Wall
INC       = -I"$(FASTDDS_PREFIX)/include" -Igen
LIBS      = -L"$(FASTDDS_PREFIX)/lib" -lfastdds -lfastcdr \
            -Wl,-rpath,"$(FASTDDS_PREFIX)/lib"
GEN_SRCS  = $(wildcard gen/*.cxx)
HDRS      = $(wildcard gen/*.hpp) participant_guard.hpp

all: shapes_pub shapes_sub

shapes_pub: shapes_pub.cpp $(GEN_SRCS) $(HDRS)
	$(CXX) $(CXXFLAGS) $(INC) -o $@ shapes_pub.cpp $(GEN_SRCS) $(LIBS)

shapes_sub: shapes_sub.cpp $(GEN_SRCS) $(HDRS)
	$(CXX) $(CXXFLAGS) $(INC) -o $@ shapes_sub.cpp $(GEN_SRCS) $(LIBS)

clean:
	rm -f shapes_pub shapes_sub
