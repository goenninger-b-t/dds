# M0 quality gates (CLAUDE.md §6). Landed targets: Clasp + SBCL. Allegro later.
# Live gates this milestone: build, test, gate-hotpath. The rest are M1+ stubs.
#
# Bare `build`/`test` use $(LISP) (default Clasp); override with LISP=... or use
# the per-impl / -all variants. `make all` runs both landed impls.

CLASP := ./scripts/with-clasp.sh
SBCL  := ./scripts/with-sbcl.sh
LISP  ?= $(CLASP)

.PHONY: all build test build-clasp build-sbcl test-clasp test-sbcl \
        build-all test-all gate-hotpath gate-types corpus fuzz interop bench mem clean

all: build-all test-all gate-hotpath gate-types mem

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
	@echo "fuzz: CDR/RTPS parser fuzzing — not yet implemented (M1+, NFR-SEC-POSTURE)"

interop:
	@echo "interop: Connext + tshark — not yet implemented (M2, FR-IO)"

bench:
	@echo "bench: perftest-equivalent harness — not yet implemented (M5, NFR-PERF)"

mem:
	$(SBCL) --eval '(ql:quickload :dds-tests :silent t)' \
	        --eval '(handler-case (progn (dds.tests:run-mem-test) (uiop:quit 0)) (error (e) (format t "~&~a~%" e) (uiop:quit 1)))'

clean:
	find . -name '*.fasl' -o -name '*.fasp' -o -name '*.faso' -o -name '*.fasc' | xargs -r rm -f
