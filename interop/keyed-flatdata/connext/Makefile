# WP-KEYED-FLATDATA Connext interop apps (RTI Connext 7.x). Reuses the shared Connext
# build rules (../../connext/common/common.mk) with the keyed-flatdata IDL one level up.
# Requires NDDSHOME + CONNEXTDDS_ARCH (see ../README.md). Clean-room: our IDL,
# rtiddsgen output produced at build time and git-ignored.
APPS   := keyed_flat_pub keyed_flat_sub
COMMON := ../../connext/common
IDL    := ../KeyedFlat.idl
include $(COMMON)/common.mk
