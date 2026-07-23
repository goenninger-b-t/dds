# Connext app for the LogEvent interop leg. Reuses the shared Connext build rules; the IDL
# (DdsLog.idl — the logging service wire type, ADR 0082 §3) is what a foreign publisher is generated
# from and is kept in lockstep with src/dds-log/event.lisp.
#   export NDDSHOME=/Applications/rti_connext_dds-7.3.1
#   export CONNEXTDDS_ARCH=arm64Darwin20clang12.0     # ls $NDDSHOME/lib
#   make                                              # -> log_pub
APPS   := log_pub
COMMON := ../connext/common
IDL    := ./DdsLog.idl
include $(COMMON)/common.mk
