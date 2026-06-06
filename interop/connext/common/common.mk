# Shared build rules for the RTI Connext test harness (RTI 7.x, Modern C++ / C++11).
# Each app's Makefile sets APP + COMMON and includes this file.
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
IDL       := $(COMMON)/ShapeType.idl
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

# rtiddsgen output for the shared IDL (one run via a sentinel; files git-ignored).
GEN_SRCS := ShapeType.cxx ShapeTypePlugin.cxx
GEN_HDRS := ShapeType.hpp ShapeTypePlugin.hpp
OBJS     := $(APP).o $(GEN_SRCS:.cxx=.o)

.PHONY: all clean generate
all: $(APP)

generate: .gen.stamp
.gen.stamp: $(IDL)
	$(RTIDDSGEN) -language C++11 -replace -d . $(IDL)
	@touch $@

$(GEN_SRCS) $(GEN_HDRS): .gen.stamp

$(APP).o: $(APP).cxx $(GEN_HDRS)
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -c -o $@ $<

%.o: %.cxx $(GEN_HDRS)
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -c -o $@ $<

$(APP): $(OBJS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

clean:
	rm -f $(APP) $(OBJS) .gen.stamp $(GEN_SRCS) $(GEN_HDRS) \
	      ShapeType*.hpp ShapeType*.cxx *.o
