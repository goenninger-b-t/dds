# M0 quality gates (the operating contract §6). Landed targets: Clasp + SBCL. Allegro later.
# Live gates this milestone: build, test, gate-hotpath. The rest are M1+ stubs.
#
# Bare `build`/`test` use $(LISP) (default Clasp); override with LISP=... or use
# the per-impl / -all variants. `make all` runs both landed impls.

CLASP := ./scripts/with-clasp.sh
SBCL  := ./scripts/with-sbcl.sh
LISP  ?= $(CLASP)

.PHONY: all build test build-clasp build-sbcl test-clasp test-sbcl \
        build-all test-all gate-hotpath gate-types corpus fuzz wire interop \
        square-pub square-sub square-spy large-pub large-sub gated-sub corpus-capture \
        nokey-pub nokey-sub \
        fastdds-pub fastdds-sub fastdds-tl-probe fastdds-type-probe bench bench-shmem bench-zerocopy shmem-xproc zc-xproc mem sbom hooks clean

DOMAIN   ?= 0
COLOR    ?= BLUE
ADVERTISE ?= 127.0.0.1
TYPE     ?= tagged
SIZE     ?= 8000
DROP     ?=
TOPIC    ?= Square
SECONDS  ?= 20
TYPENAME  ?= C_Shape
LOCALTYPE ?= shape-type
COUNT    ?= 0
LATSAMPLES  ?= 10000
THRUSAMPLES ?= 20000
PEERS    ?=
LIVELINESS ?=
LEASE    ?=
OWNERSHIP ?=
# Optional writer LIVELINESS QoS for square-pub; empty -> current default behaviour.
LIVELINESS_ARGS := $(if $(LIVELINESS),:liveliness :$(LIVELINESS),)$(if $(LEASE), :liveliness-lease-seconds $(LEASE),)
# Optional WP-BATCH / WP-ASYNC for square-pub: BATCH=N (>1 batches), ASYNC=t (decoupled sender thread).
BATCH    ?= 1
PERF_ARGS := :batch $(BATCH)$(if $(ASYNC), :async t,)
# Optional reader OWNERSHIP QoS for gated-sub (shared|exclusive); empty -> :shared default.
OWNERSHIP_ARGS := $(if $(OWNERSHIP),:ownership :$(OWNERSHIP),)

all: build-all test-all gate-hotpath gate-types mem

# EU CRA / BSI TR-03183-2 SBOM (SPDX 3.0.1 JSON-LD). Regenerate sbom.spdx.json.
sbom:
	python3 scripts/generate-sbom.py

# Activate the git hooks (regenerate+stage the SBOM before every commit).
hooks:
	git config core.hooksPath scripts/git-hooks
	@echo "hooks active (core.hooksPath=scripts/git-hooks): SBOM regenerated before each commit."

build:
	$(LISP) --eval '(ql:quickload :dds :silent t)' --eval '(uiop:quit 0)'

test:
	$(LISP) --eval '(ql:quickload :dds-tests :silent t)' \
	        --eval '(handler-case (progn (asdf:test-system :dds-tests) (uiop:quit 0)) (error (e) (format t "~&~a~%" e) (uiop:quit 1)))'

build-clasp: ; $(MAKE) build LISP=$(CLASP)
build-sbcl:  ; $(MAKE) build LISP=$(SBCL)
test-clasp:  ; $(MAKE) test  LISP=$(CLASP)
test-sbcl:   ; $(MAKE) test  LISP=$(SBCL)
build-all: build-clasp build-sbcl
test-all:  test-clasp test-sbcl

gate-hotpath:
	./scripts/gate-hotpath.sh

gate-types: ; ./scripts/gate-types.sh

corpus:
	@echo "corpus: byte-exact XCDR vectors — not yet implemented (M1, FR-CDR-8)"

fuzz:
	$(LISP) --eval '(ql:quickload :dds-tests :silent t)' \
	        --eval '(handler-case (progn (dds.tests:run-pbt-tests) (uiop:quit 0)) (error (e) (format t "~&~a~%" e) (uiop:quit 1)))'

wire:
	./scripts/wire-check.sh

# Standalone Shapes interop participants (docs/interop-shapes.md). Run forever;
# Ctrl-C to stop. Override DOMAIN=.. COLOR=.. ; LISP=$(SBCL) used (CFFI multicast).
square-pub:
	$(SBCL) --eval '(asdf:load-system :dds-shapes)' \
	        --eval '(uiop:symbol-call :dds.shapes :run-publisher :domain $(DOMAIN) :color "$(COLOR)" :advertise-address "$(ADVERTISE)" :type :$(TYPE) :count $(COUNT) :peers "$(PEERS)" $(LIVELINESS_ARGS) $(PERF_ARGS))' \
	        --eval '(uiop:quit 0)'

square-sub:
	$(SBCL) --eval '(asdf:load-system :dds-shapes)' \
	        --eval '(uiop:symbol-call :dds.shapes :run-subscriber :domain $(DOMAIN) :advertise-address "$(ADVERTISE)" :type :$(TYPE))' \
	        --eval '(uiop:quit 0)'

# Discovery diagnostic: print each discovered participant's locators + resolved dest.
square-spy:
	$(SBCL) --eval '(asdf:load-system :dds-shapes)' \
	        --eval '(uiop:symbol-call :dds.shapes :run-spy :domain $(DOMAIN) :advertise-address "$(ADVERTISE)")' \
	        --eval '(uiop:quit 0)'

# LargeData DATA_FRAG harness; SIZE=payload octets, DROP=3 injects fragment loss for NACK_FRAG recovery
large-pub:
	$(SBCL) --eval '(asdf:load-system :dds-shapes)' \
	        --eval '(uiop:symbol-call :dds.shapes :run-large-publisher :domain $(DOMAIN) :size $(SIZE) :advertise-address "$(ADVERTISE)" :drop-fragments (quote ($(DROP))))' \
	        --eval '(uiop:quit 0)'

large-sub:
	$(SBCL) --eval '(asdf:load-system :dds-shapes)' \
	        --eval '(uiop:symbol-call :dds.shapes :run-large-subscriber :domain $(DOMAIN) :advertise-address "$(ADVERTISE)")' \
	        --eval '(uiop:quit 0)'

# DCPS-level gated live subscriber (FR-TYPE-4, ADR 0010 live DoD): the type-gate fires on a
# stock Connext peer's PID_TYPE_OBJECT_LB. LOCALTYPE=shape-type (compatible) | shape-mismatch.
gated-sub:
	$(SBCL) --eval '(asdf:load-system :dds-shapes)' \
	        --eval '(uiop:symbol-call :dds.shapes :run-gated-subscriber :domain $(DOMAIN) :topic "$(TOPIC)" :type-name "$(TYPENAME)" :local-type "$(LOCALTYPE)" :seconds $(SECONDS) :advertise-address "$(ADVERTISE)" $(OWNERSHIP_ARGS))' \
	        --eval '(uiop:quit 0)'

# Clean-room legacy-TypeObject capture: dump a peer's PID_TYPE_OBJECT_LB as a Lisp byte vector.
corpus-capture:
	$(SBCL) --eval '(asdf:load-system :dds-shapes)' \
	        --eval '(uiop:symbol-call :dds.shapes :run-corpus-capture-subscriber :domain $(DOMAIN) :topic "$(TOPIC)" :type "$(TYPE)" :seconds $(SECONDS))' \
	        --eval '(uiop:quit 0)'

# No-key endpoint-kinds live harness (keyed/no-key feature). The DCPS path threads the
# topic type's keyed-ness (NIL) so the endpoints come up NO_KEY (writer 0x03 / reader 0x04).
nokey-pub:
	$(SBCL) --eval '(asdf:load-system :dds-shapes)' \
	        --eval '(uiop:symbol-call :dds.shapes :run-nokey-publisher :domain $(DOMAIN) :count $(COUNT) :advertise-address "$(ADVERTISE)" :peers "$(PEERS)")' \
	        --eval '(uiop:quit 0)'

nokey-sub:
	$(SBCL) --eval '(asdf:load-system :dds-shapes)' \
	        --eval '(uiop:symbol-call :dds.shapes :run-nokey-subscriber :domain $(DOMAIN) :seconds $(SECONDS) :advertise-address "$(ADVERTISE)" :peers "$(PEERS)")' \
	        --eval '(uiop:quit 0)'

# Fast DDS interop peers (interop/fastdds/README.md). FASTDDS_PREFIX via with-fastdds.sh;
# the apps read profiles.xml from their cwd. COUNT=0 / SECONDS=0 = run forever.
fastdds-pub:
	./scripts/with-fastdds.sh bash -c 'cd interop/fastdds/shapes && ./shapes_pub $(COLOR) $(COUNT)'

fastdds-sub:
	./scripts/with-fastdds.sh bash -c 'cd interop/fastdds/shapes && ./shapes_sub $(SECONDS)'

# TypeLookup live leg B (FR-IO-2 S4): the type-blind Fast DDS probe resolves OUR
# publisher's type via OUR TypeLookup server, builds a DynamicType, and receives samples.
fastdds-type-probe:
	./scripts/with-fastdds.sh bash -c 'cd interop/fastdds/type_probe && ./type_probe $(SECONDS)'

# TypeLookup live leg A (FR-IO-2 S4): our getTypes client queries a peer's TypeLookup
# server (e.g. `make fastdds-pub`) for its SEDP-announced EK_MINIMAL hash. PASS/FAIL on stdout.
fastdds-tl-probe:
	$(SBCL) --eval '(asdf:load-system :dds-shapes)' \
	        --eval '(uiop:symbol-call :dds.shapes :run-typelookup-probe :domain $(DOMAIN) :seconds $(SECONDS) :advertise-address "$(ADVERTISE)")' \
	        --eval '(uiop:quit 0)'

interop: wire
	@echo "interop: 'wire' validates our output vs the tshark RTPS dissector."
	@echo "interop: bidirectional Connext interop pending a Connext install (M2, FR-IO)."

bench:
	$(SBCL) --eval '(ql:quickload :dds-bench :silent t)' \
	        --eval '(uiop:symbol-call :dds.bench :run-bench :latency-samples $(LATSAMPLES) :throughput-samples $(THRUSAMPLES))' \
	        --eval '(uiop:quit 0)'

bench-shmem:
	$(SBCL) --eval '(ql:quickload :dds-bench :silent t)' \
	        --eval '(uiop:symbol-call :dds.bench :run-bench-shmem :latency-samples $(LATSAMPLES) :throughput-samples $(THRUSAMPLES))' \
	        --eval '(uiop:quit 0)'

# WP-ZEROCOPY (FR-PF-3): large-sample ZC vs SHMEM vs UDP comparison (default sizes 4/16/64 KiB,
# above *zerocopy-min-payload-bytes*). Each ZEROCOPY run asserts disc-node-zc-sends advanced (a
# 16-byte reference crossed, not the payload). NOT cleared for ship — pending counsel (R6).
bench-zerocopy:
	$(SBCL) --eval '(ql:quickload :dds-bench :silent t)' \
	        --eval '(uiop:symbol-call :dds.bench :run-bench-zerocopy)' \
	        --eval '(uiop:quit 0)'

# WP-SHMEM Task F1 (FR-XPORT-2): REAL two-OS-process cross-process SHMEM round-trip.
# Two SEPARATE SBCL processes discover over loopback UDP (:peers, no multicast) and the
# pub routes user DATA over SHARED MEMORY; PASS iff the sub received the samples AND the
# pub's shmem-sends > 0. SBCL only — SHMEM is on for SBCL; Clasp/macOS would use UDP.
shmem-xproc:
	./scripts/shmem-roundtrip.sh

# WP-ZEROCOPY Phase E2 (FR-PF-3): REAL two-OS-process cross-process Zero-Copy round-trip.
# Two SEPARATE SBCL processes discover over loopback UDP (:peers, no multicast) and the pub
# stores each LARGE LargeData sample in its SHMEM pool, sending only a 16-byte reference; the
# sub resolves it CROSS-PROCESS + verifies byte-exact. PASS iff the sub received >= threshold
# AND the pub's zc-sends > 0. SBCL only. NOT cleared for ship — pending counsel (R6); ADR 0014.
zc-xproc:
	./scripts/zerocopy-roundtrip.sh

mem:
	$(SBCL) --eval '(ql:quickload :dds-tests :silent t)' \
	        --eval '(handler-case (progn (dds.tests:run-mem-test) (uiop:quit 0)) (error (e) (format t "~&~a~%" e) (uiop:quit 1)))'

clean:
	find . -name '*.fasl' -o -name '*.fasp' -o -name '*.faso' -o -name '*.fasc' | xargs -r rm -f
