# Connext app for the enum-TypeObject interop probe. Reuses the shared Connext build rules; the IDL
# (EnumBox.idl, a real enum member) is the variable under test.
#   export NDDSHOME=/Applications/rti_connext_dds-7.3.1
#   export CONNEXTDDS_ARCH=arm64Darwin20clang12.0     # ls $NDDSHOME/lib
#   make                                              # -> enum_pub
APPS   := enum_pub
COMMON := ../connext/common
IDL    := ./EnumBox.idl
include $(COMMON)/common.mk
