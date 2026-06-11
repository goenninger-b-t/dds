# Build every Fast DDS harness app (each lives in its own subdir with its own Makefile).
# Requires FASTDDS_PREFIX — run via scripts/with-fastdds.sh (see README.md).

APPS := shapes

.PHONY: all clean $(APPS)

all: $(APPS)

$(APPS):
	$(MAKE) -C $@

clean:
	@for d in $(APPS); do $(MAKE) -C $$d clean; done
