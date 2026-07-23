# Connext apps for interop Leg 1 (cross-DDS half): an @appendable AppendableShape pub + sub.
# Reuses the shared Connext build rules; the ONLY difference from the @final ShapeType harness is
# the IDL (AppendableShape.idl, @appendable), which is exactly the variable under test.
#
#   export NDDSHOME=/Applications/rti_connext_dds-7.3.1
#   export CONNEXTDDS_ARCH=arm64Darwin20clang12.0     # ls $NDDSHOME/lib
#   make                                              # -> appendable_pub appendable_sub
APPS   := appendable_pub appendable_sub
COMMON := ../connext/common
IDL    := ./AppendableShape.idl
include $(COMMON)/common.mk
