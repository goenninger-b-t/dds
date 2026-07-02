# M7/P6 Slice 5b — the reverse-direction Connext secured PUBLISHER (external interop peer).
# Reuses the shared RTI build rules (Modern C++11, -lnddscpp2 -lnddsc -lnddscore). rtiddsgen
# codegen is platform-independent; the generated type support is git-ignored (clean-room:
# never checked in — see ../connext/common/common.mk and docs/provenance.md).
#
# Requires NDDSHOME + CONNEXTDDS_ARCH (see the run script for the arm64Darwin values).
#   make            build hello_secure_pub
#   make clean      remove the binary + generated type support + objects

APP    := hello_secure_pub
COMMON := ../connext/common
IDL    := HelloWorld.idl
include $(COMMON)/common.mk
