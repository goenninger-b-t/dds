# Fast DDS non-4-aligned interop leg (ADR 0061 / task #28). Needs FASTDDS_PREFIX (scripts/with-fastdds.sh).
CXX      ?= clang++
CXXFLAGS ?= -std=c++17 -O2 -Wall
INC       = -I"$(FASTDDS_PREFIX)/include" -Igen
LIBS      = -L"$(FASTDDS_PREFIX)/lib" -lfastdds -lfastcdr \
            -Wl,-rpath,"$(FASTDDS_PREFIX)/lib"
GEN_SRCS  = $(wildcard gen/*.cxx)

all: perf_sub

gen: PerfData.idl
	mkdir -p gen && "$(FASTDDSGEN)" -replace -d gen PerfData.idl

perf_sub: perf_sub.cpp $(GEN_SRCS)
	$(CXX) $(CXXFLAGS) $(INC) -o $@ perf_sub.cpp $(GEN_SRCS) $(LIBS)

clean:
	rm -f perf_sub && rm -rf gen
