# Build every Connext harness app (each lives in its own subdir with its own Makefile).
# Requires NDDSHOME + CONNEXTDDS_ARCH (see README.md).

APPS := typeobject-probe shapes-pub shapes-sub cdr-capture

.PHONY: all clean $(APPS)

all: $(APPS)

$(APPS):
	$(MAKE) -C $@

clean:
	@for d in $(APPS); do $(MAKE) -C $$d clean; done
