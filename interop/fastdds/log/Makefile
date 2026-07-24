# Fast DDS LogEvent harness (ADR 0082 §3, FR-IO-2 cross-DDS leg). Needs FASTDDS_PREFIX + FASTDDSGEN
# (use scripts/with-fastdds.sh).  make gen  then  make log_pub.
# fastddsgen output (gen/) is git-ignored — clean-room, generated locally.
CXX      ?= clang++
CXXFLAGS ?= -std=c++17 -O2 -Wall
INC       = -I"$(FASTDDS_PREFIX)/include" -Igen
LIBS      = -L"$(FASTDDS_PREFIX)/lib" -lfastdds -lfastcdr \
            -Wl,-rpath,"$(FASTDDS_PREFIX)/lib"
GEN_SRCS  = $(wildcard gen/*.cxx)
HDRS      = $(wildcard gen/*.hpp) participant_guard.hpp

all: log_pub

# The IDL is the ONE canonical interop/log/DdsLog.idl (kept in lockstep with the Lisp type) — no copy.
gen: ../../log/DdsLog.idl
	mkdir -p gen && "$(FASTDDSGEN)" -replace -d gen ../../log/DdsLog.idl

log_pub: log_pub.cpp $(GEN_SRCS) $(HDRS)
	$(CXX) $(CXXFLAGS) $(INC) -o $@ log_pub.cpp $(GEN_SRCS) $(LIBS)

clean:
	rm -f log_pub
