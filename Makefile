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
        square-pub square-sub square-spy large-pub large-sub bench mem sbom hooks clean

DOMAIN   ?= 0
COLOR    ?= BLUE
ADVERTISE ?= 127.0.0.1
TYPE     ?= tagged
SIZE     ?= 8000

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
	        --eval '(uiop:symbol-call :dds.shapes :run-publisher :domain $(DOMAIN) :color "$(COLOR)" :advertise-address "$(ADVERTISE)" :type :$(TYPE))' \
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

# LargeData pub/sub harness (DATA_FRAG interop testing). SIZE overrides payload octets.
large-pub:
	$(SBCL) --eval '(asdf:load-system :dds-shapes)' \
	        --eval '(uiop:symbol-call :dds.shapes :run-large-publisher :domain $(DOMAIN) :size $(SIZE) :advertise-address "$(ADVERTISE)")' \
	        --eval '(uiop:quit 0)'

large-sub:
	$(SBCL) --eval '(asdf:load-system :dds-shapes)' \
	        --eval '(uiop:symbol-call :dds.shapes :run-large-subscriber :domain $(DOMAIN) :advertise-address "$(ADVERTISE)")' \
	        --eval '(uiop:quit 0)'

interop: wire
	@echo "interop: 'wire' validates our output vs the tshark RTPS dissector."
	@echo "interop: bidirectional Connext interop pending a Connext install (M2, FR-IO)."

bench:
	@echo "bench: perftest-equivalent harness — not yet implemented (M5, NFR-PERF)"

mem:
	$(SBCL) --eval '(ql:quickload :dds-tests :silent t)' \
	        --eval '(handler-case (progn (dds.tests:run-mem-test) (uiop:quit 0)) (error (e) (format t "~&~a~%" e) (uiop:quit 1)))'

clean:
	find . -name '*.fasl' -o -name '*.fasp' -o -name '*.faso' -o -name '*.fasc' | xargs -r rm -f
