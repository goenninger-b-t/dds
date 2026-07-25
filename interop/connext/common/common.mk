# Shared build rules for the RTI Connext test harness (RTI 7.x, Modern C++ / C++11).
# Each app's Makefile sets APP (or APPS for several binaries) + COMMON and includes this
# file; IDL and RTIDDSGEN_FLAGS are overridable (default: the shared ShapeType).
#
# Required:
#   NDDSHOME         RTI Connext install dir
#   CONNEXTDDS_ARCH  target arch (e.g. x64Linux4gcc7.3.0, x64Darwin20clang12.0; `ls $NDDSHOME/lib`)
# Optional:
#   RTI_BUILD        release (default) | debug
#
# Mirrors the variables RTI's own rtiddsgen-generated makefiles use. rtiddsgen codegen is
# platform-independent (only the C++ build needs the arch), so the generated type support
# is portable; the generated files are git-ignored (clean-room: never checked in).

ifndef NDDSHOME
$(error NDDSHOME is not set -- point it at your RTI Connext install)
endif
ifndef CONNEXTDDS_ARCH
$(error CONNEXTDDS_ARCH is not set -- e.g. x64Linux4gcc7.3.0 or x64Darwin20clang12.0; run `ls $(NDDSHOME)/lib`)
endif

RTI_BUILD ?= release
RTIDDSGEN := $(NDDSHOME)/bin/rtiddsgen
RTIDDSGEN_FLAGS ?=
IDL       ?= $(COMMON)/ShapeType.idl
IDL_BASE  := $(basename $(notdir $(IDL)))
APPS      ?= $(APP)
UNAME_S   := $(shell uname -s)

CXX      ?= c++
CXXFLAGS += -std=c++11 -m64 -Wall -O2
CPPFLAGS += -I. -I$(NDDSHOME)/include -I$(NDDSHOME)/include/ndds \
            -I$(NDDSHOME)/include/ndds/hpp -DNDDS_USER_DLL_EXPORT

LIBDIR := $(NDDSHOME)/lib/$(CONNEXTDDS_ARCH)

# Modern C++ (C++11) API libs; debug builds use the 'd'-suffixed variants. If your install
# names them differently, `ls $(LIBDIR)` and adjust RTILIBS.
ifeq ($(RTI_BUILD),debug)
  RTILIBS  := -lnddscpp2d -lnddscd -lnddscored
  CXXFLAGS += -g -O0
else
  RTILIBS  := -lnddscpp2 -lnddsc -lnddscore
endif

ifeq ($(UNAME_S),Darwin)
  CPPFLAGS += -DRTI_DARWIN -DRTI_UNIX
  SYSLIBS  := -ldl -lm -lpthread
  LDFLAGS  += -Wl,-rpath,$(LIBDIR)
else
  CPPFLAGS += -DRTI_LINUX -DRTI_UNIX
  SYSLIBS  := -ldl -lm -lpthread -lrt
  LDFLAGS  += -Wl,-rpath,$(LIBDIR)
endif

LDLIBS += -L$(LIBDIR) $(RTILIBS) $(SYSLIBS)

# rtiddsgen output for the app's IDL (one run via a sentinel; files git-ignored).
GEN_SRCS := $(IDL_BASE).cxx $(IDL_BASE)Plugin.cxx
GEN_HDRS := $(IDL_BASE).hpp $(IDL_BASE)Plugin.hpp
GEN_OBJS := $(GEN_SRCS:.cxx=.o)
OBJS     := $(addsuffix .o,$(APPS)) $(GEN_OBJS)

.PHONY: all clean generate
all: $(APPS)

generate: .gen.stamp
.gen.stamp: $(IDL)
	$(RTIDDSGEN) -language C++11 -replace $(RTIDDSGEN_FLAGS) -d . $(IDL)
	@touch $@

$(GEN_SRCS) $(GEN_HDRS): .gen.stamp

%.o: %.cxx $(GEN_HDRS)
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -c -o $@ $<

# The RTI libraries are installed with an @loader_path install name, which DYLD_LIBRARY_PATH CANNOT
# satisfy — the loader resolves @loader_path relative to the BINARY, not to the search path. Every peer
# therefore needs the libs symlinked beside it, and doing that by hand is how peers end up built but
# unrunnable: interop/connext/nokey/ had a working pub AND sub that died with "Library not loaded"
# the moment anything tried to run them, which is a large part of why they were never gated. Linking
# them here fixes every peer at once and keeps fixing new ones. The symlinks are git-ignored.
RTILINKS := libnddscpp2 libnddsc libnddscore
$(APPS): %: %.o $(GEN_OBJS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)
ifeq ($(UNAME_S),Darwin)
	@for l in $(RTILINKS); do ln -sf "$(LIBDIR)/$$l.dylib" "$$l.dylib"; done
endif

clean:
	rm -f $(APPS) $(OBJS) .gen.stamp $(GEN_SRCS) $(GEN_HDRS) \
	      $(IDL_BASE)*.hpp $(IDL_BASE)*.cxx *.o *.dylib
