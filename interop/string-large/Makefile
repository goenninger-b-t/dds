# Connext app for the bounded-string LARGE-form interop probe. Reuses the shared Connext build rules;
# the IDL (StringLarge.idl, a string<1024> member) is the variable under test.
#   export NDDSHOME=/Applications/rti_connext_dds-7.3.1
#   export CONNEXTDDS_ARCH=arm64Darwin20clang12.0     # ls $NDDSHOME/lib
#   make                                              # -> stringlarge_pub
APPS   := stringlarge_pub
COMMON := ../connext/common
IDL    := ./StringLarge.idl
include $(COMMON)/common.mk
