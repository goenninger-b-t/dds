# M0 quality gates (the operating contract §6). Landed targets: Clasp + SBCL + AllegroCL.
# Live gates this milestone: build, test, gate-hotpath. The rest are M1+ stubs.
#
# Bare `build`/`test` use $(LISP) (default Clasp); override with LISP=... or use
# the per-impl / -all variants. `make all` runs all three landed impls, and each launcher exits 127 when
# its binary is absent — deliberately, so a run cannot report success without validating that impl. The
# per-impl targets (`make test-sbcl`) are the escape hatch on a machine lacking one (AllegroCL is
# commercially licensed; the Mac has no alisp and 192.168.2.180 has no Clasp).

CLASP := ./scripts/with-clasp.sh
SBCL  := ./scripts/with-sbcl.sh
# ADR 0004's tracked follow-up, closed 2026-08-07. The launcher translates --eval to AllegroCL's -e, so
# every target below keeps ONE spelling (ADR 0116 does the same for CHILD processes).
ALLEGRO := ./scripts/with-allegro.sh
LISP  ?= $(CLASP)

.PHONY: all build test build-clasp build-sbcl build-allegro test-clasp test-sbcl test-allegro gate-build gate-mem gate-pal gate-nocond gate-drivers \
        build-all test-all gate-hotpath gate-types corpus fuzz wire interop \
        square-pub square-sub square-spy large-pub large-sub gated-sub corpus-capture \
        nokey-pub nokey-sub keyed-flat-pub keyed-flat-sub \
        fastdds-pub fastdds-sub fastdds-tl-probe fastdds-type-probe fastdds-keyed-flat-pub fastdds-keyed-flat-sub bench bench-shmem bench-zerocopy bench-flatdata bench-flatdata-zc-loan bench-flatdata-loan-write bench-zc-loan-lockfree bench-multi-dest-zc bench-async-flow bench-flow-edf-priority bench-keeplast bench-rtps-message bench-rtps-message-clasp bench-rtps-protection shmem-xproc zc-xproc mem sbom hooks clean \
        gate-arena gate-nlx test-linux linux-run linux-shell linux-image linux-clean-cache

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
DEADLINE_MS ?= 1500
ANNOUNCE_MS ?= 1000
LEASE_SECONDS ?= 100
KEYS     ?= 3
DISPOSE_AFTER ?= 0
LATSAMPLES  ?= 10000
THRUSAMPLES ?= 20000
KLSAMPLES   ?= 1000000
KLINSTANCES ?= 100
KLDEPTH     ?= 2
RTPSITERS   ?= 100000
RTPSSIZE    ?= 256
PEERS    ?=
LIVELINESS ?=
LEASE    ?=
OWNERSHIP ?=
# Optional writer LIVELINESS QoS for square-pub; empty -> current default behaviour.
LIVELINESS_ARGS := $(if $(LIVELINESS),:liveliness :$(LIVELINESS),)$(if $(LEASE), :liveliness-lease-seconds $(LEASE),)
# Optional WP-BATCH / WP-ASYNC for square-pub: BATCH=N (>1 batches), ASYNC=t (decoupled sender thread).
BATCH    ?= 1
PERF_ARGS := :batch $(BATCH)$(if $(ASYNC), :async t,)
# WP-SENDER-ERROR-RESILIENCE square-pub fault injection: FAULT=k@j arms a k-shot synthetic emit
# fault after the j-th publish (k = fault-count before the @, j = fault-after after it); empty = inert.
FAULT    ?=
FAULT_ARGS := $(if $(FAULT), :fault-count $(word 1,$(subst @, ,$(FAULT))) :fault-after $(word 2,$(subst @, ,$(FAULT))),)
# Optional fixed metatraffic port for square-pub (PORT>0): bind+advertise a reachable loopback locator
# so a foreign peer can reply to our unicast SPDP; 0 (default) = ephemeral (multicast discovery).
PORT     ?= 0
# Optional writer HISTORY for square-pub: HISTORY=keep-all retains-until-acked (needed for full reliable
# repair of a dropped/un-acked sample); empty -> keep-last (the spec generic default, depth 1).
HISTORY  ?=
HISTORY_ARGS := $(if $(HISTORY),:history-kind :$(HISTORY),)
# WP-DATA-REPRESENTATION square-pub OFFERED representation: REP=xcdr1 makes the writer advertise+send XCDR1
# (PLAIN_CDR_LE 0x0001) for a peer whose reader accepts [XCDR1]; empty/xcdr2 -> the default (0x0007, identical wire).
REP      ?=
REP_ARGS := $(if $(REP),:data-representation :$(REP),)
# WP-DURABILITY-TRANSIENT-LOCAL square-pub/square-sub DURABILITY QoS: DURABILITY=transient-local makes the
# (always-reliable) writer RETAIN+REPLAY its history to a late-joining reader / the reader REQUEST that
# pre-join history (DDS 1.4 §2.2.3.4); empty/volatile -> the default (no retention, byte-identical wire).
DURABILITY ?=
DURABILITY_ARGS := $(if $(DURABILITY),:durability :$(DURABILITY),)
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

# ASDF, NOT ql:quickload. quickload wraps the whole load in ql-impl-util:call-with-quiet-compilation,
# which does (handler-bind ((warning #'muffle-warning)) ...) — so compile-file's failure-p never reaches
# ASDF and NO compile WARNING can ever fail these gates. That is the exact opposite of the operating
# contract §6 ("fail on any warning promoted to error"), and it green-lit a wrong-arg-count call
# (%count-matching, 4 args vs a 2-arg declaim) for two days: `make test` reported 563/563 while
# `asdf:load-system :dds-dcps` could not compile the tree at all. asdf:load-system honors
# *compile-file-failure-behaviour* (:error), builds the Quicklisp-provided dependencies on demand
# exactly as before, and FAILS on a full WARNING in our own code. Proven to fail: scripts/gate-build.sh.
build:
	$(LISP) --eval '(asdf:load-system :dds)' --eval '(uiop:quit 0)'

test:
	$(LISP) --eval '(asdf:load-system :dds-tests)' \
	        --eval '(handler-case (progn (asdf:test-system :dds-tests) (uiop:quit 0)) (error (e) (format t "~&~a~%" e) (uiop:quit 1)))'

build-clasp:   ; $(MAKE) build LISP=$(CLASP)
build-sbcl:    ; $(MAKE) build LISP=$(SBCL)
build-allegro: ; $(MAKE) build LISP=$(ALLEGRO)
test-clasp:    ; $(MAKE) test  LISP=$(CLASP)
test-sbcl:     ; $(MAKE) test  LISP=$(SBCL)
test-allegro:  ; $(MAKE) test  LISP=$(ALLEGRO)
build-all: build-clasp build-sbcl build-allegro
test-all:  test-clasp test-sbcl test-allegro

gate-hotpath:
	./scripts/gate-hotpath.sh

gate-types: ; ./scripts/gate-types.sh

# No reader conditionals outside dds-pal/ (contract §10, NFR-PORT). The contract claimed "CI lint enforces
# this" — no such lint existed, and there was no CI to run it in. This is that lint; it falsifies itself.
gate-pal: ; ./scripts/gate-pal.sh

# Owner directive 2026-07-14 (NON-NEGOTIABLE): no Lisp conditions in the hot path; every condition handled
# at latest at the toplevel DDS API. Annotation lint + asserts the receiver boundary handlers still exist.
gate-nocond: ; ./scripts/gate-nocond.sh

# ADR 0098: a non-local exit must not cross a lock from inside a condition handler — the handler
# closure loses dynamic extent and is heap-allocated on EVERY call. A FORM WALKER, not a grep:
# no single construct is the defect, only the nesting, which a regex cannot see.
gate-nlx: ; ./scripts/gate-nlx.sh

# Every interop driver that creates a DCPS DataWriter must be able to OFFER a data representation.
# DATA_REPRESENTATION is an RxO policy and a stock foreign reader advertises XCDR1 only, so a driver
# stuck on the XCDR2 default silently will not match it — matched=0, no error. Three drivers were
# found with this omission before the lint existed.
gate-drivers: ; ./scripts/gate-drivers.sh

# The REAL build gate (operating contract §6): clean-cache rebuild + a falsification self-test.
# `build` above is the incremental convenience load; THIS is the one that can actually fail.
gate-build: ; ./scripts/gate-build.sh $(LISP)

# NFR-MEM ALLOCATION RATCHET (ADR 0062). `mem` above measures the CODEC in isolation (~0 B/iter) — a real
# assertion, but NOT the per-sample budget it is credited with, which is why it stayed green while the live
# DCPS path allocated ~3.9 KB/sample. gate-mem measures the END-TO-END path and ratchets it DOWN toward 0.
# Fails on regression AND on an un-lowered ceiling after an improvement. SBCL only (bytes-consed is 0 on Clasp).
gate-mem: ; ./scripts/gate-mem.sh

# FR-PF-7 STATIC-MEMORY PROPERTY (ADR 0095). Asserts what `make mem` was credited with and does not check:
# that ONE process arena sized by *static-arena-bytes* actually bounds hot-path static memory, that a live
# participant charges it, that a create/delete cycle RETURNS the charge (option (a) — the leak this design
# exists to prevent), and that high-water < budget. FALSIFIES ITSELF on every run before asserting anything.
gate-arena: ; ./scripts/gate-arena.sh

# THE CI PLATFORM, REACHABLE FROM THE DEV BOX. macOS/arm64 cannot see a whole class of defect this
# stack has: uninitialized memory that only shows on the wire, a stack that only deadlocks under Linux
# thread scheduling, a discovery window only wide enough there (ADR 0096). Every one was found by Linux
# and none by macOS, and the only way to reach Linux used to be a push. Needs Docker; ~90 s for one
# focused test, ~7 min for the suite (amd64 runs emulated on Apple silicon). The launcher encodes the
# five traps that each cost a wasted run — see scripts/linux-repro.sh.
#   make test-linux                                 the whole suite on Linux x86_64
#   make linux-run FORM='(dds.tests::run-x-test)'   one form, loaded and run in ONE process
#   make linux-shell / linux-image / linux-clean-cache
test-linux:   ; ./scripts/linux-repro.sh
linux-run:    ; ./scripts/linux-repro.sh --eval '(handler-case (progn $(FORM) (format t "~&LINUX: ok~%") (uiop:quit 0)) (error (e) (format t "~&LINUX: FAILED ~a~%" e) (uiop:quit 1)))'
linux-shell:  ; ./scripts/linux-repro.sh --shell
linux-image:  ; ./scripts/linux-repro.sh --build-only
linux-clean-cache: ; docker volume rm -f neodds-linux-fasl-cache

# FR-CDR-8: our codec MUST reproduce, byte for byte, the SerializedPayloads RTI Connext puts ON THE WIRE.
# The vectors in corpus/xcdr2/ are captured from a live Connext writer (scripts/capture-corpus.sh); this
# target only VERIFIES them, so it needs no Connext install and runs anywhere.
corpus:
	$(LISP) --eval '(asdf:load-system :dds-bench)' \
	        --eval '(uiop:quit (if (zerop (dds.bench:corpus-verify)) 0 1))'

fuzz:
	$(LISP) --eval '(asdf:load-system :dds-tests)' \
	        --eval '(handler-case (progn (dds.tests:run-pbt-tests) (uiop:quit 0)) (error (e) (format t "~&~a~%" e) (uiop:quit 1)))'

wire:
	./scripts/wire-check.sh

# Standalone Shapes interop participants (docs/interop-shapes.md). Run forever;
# Ctrl-C to stop. Override DOMAIN=.. COLOR=.. ; LISP=$(SBCL) used (CFFI multicast).
square-pub:
	$(SBCL) --eval '(asdf:load-system :dds-shapes)' \
	        --eval '(uiop:symbol-call :dds.shapes :run-publisher :domain $(DOMAIN) :color "$(COLOR)" :advertise-address "$(ADVERTISE)" :type :$(TYPE) :count $(COUNT) :peers "$(PEERS)" :port $(PORT) $(LIVELINESS_ARGS) $(PERF_ARGS) $(FAULT_ARGS) $(HISTORY_ARGS) $(REP_ARGS) $(DURABILITY_ARGS))' \
	        --eval '(uiop:quit 0)'

# SECONDS bounds the run (default 20; SECONDS=0 runs until Ctrl-C, run-subscriber's :seconds 0
# contract). Previously omitted, so the target silently ran forever and a backgrounded subscriber
# outlived its capture, holding the DDS sockets and hanging the next suite.
square-sub:
	$(SBCL) --eval '(asdf:load-system :dds-shapes)' \
	        --eval '(uiop:symbol-call :dds.shapes :run-subscriber :domain $(DOMAIN) :seconds $(SECONDS) :advertise-address "$(ADVERTISE)" :type :$(TYPE) :peers "$(PEERS)" :port $(PORT) $(DURABILITY_ARGS))' \
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

# WP-DCPS-API-COMPLETION S4 live DEADLINE interop (DDS 1.4 §2.2.3.7; interop/deadline). DEADLINE_MS sets
# the offered (pub) / requested (sub) period; COUNT = samples before the pub stops. The peer is the stock
# Connext/Fast DDS shapes_sub (for deadline-pub) or a finite-offered-deadline shapes_pub (for deadline-sub).
deadline-pub:
	$(SBCL) --eval '(asdf:load-system :dds-shapes)' \
	        --eval '(uiop:symbol-call :dds.shapes :run-deadline-publisher :domain $(DOMAIN) :deadline-ms $(DEADLINE_MS) :count $(COUNT) :seconds $(SECONDS) :advertise-address "$(ADVERTISE)")' \
	        --eval '(uiop:quit 0)'

deadline-sub:
	$(SBCL) --eval '(asdf:load-system :dds-shapes)' \
	        --eval '(uiop:symbol-call :dds.shapes :run-deadline-subscriber :domain $(DOMAIN) :deadline-ms $(DEADLINE_MS) :seconds $(SECONDS) :advertise-address "$(ADVERTISE)")' \
	        --eval '(uiop:quit 0)'

# WP-DCPS-API-COMPLETION S7 live AUTONOMOUS-DISCOVERY interop (ADR 0056; interop/autodiscovery). The same
# DCPS runners in AUTONOMOUS mode: the loop calls NO spin — a background announcer thread drives SPDP/SEDP
# on the ANNOUNCE_MS cadence and announces a LEASE_SECONDS leaseDuration. DEADLINE_MS=0 = no finite
# deadline, so the stock Connext/Fast DDS shapes peer matches with no QoS tweak.
autodisc-pub:
	$(SBCL) --eval '(asdf:load-system :dds-shapes)' \
	        --eval '(uiop:symbol-call :dds.shapes :run-deadline-publisher :domain $(DOMAIN) :deadline-ms 0 :count $(COUNT) :seconds $(SECONDS) :advertise-address "$(ADVERTISE)" :peers "$(PEERS)" :autonomous t :announce-ms $(ANNOUNCE_MS) :lease-seconds $(LEASE_SECONDS) $(REP_ARGS))' \
	        --eval '(uiop:quit 0)'

autodisc-sub:
	$(SBCL) --eval '(asdf:load-system :dds-shapes)' \
	        --eval '(uiop:symbol-call :dds.shapes :run-deadline-subscriber :domain $(DOMAIN) :deadline-ms 0 :seconds $(SECONDS) :advertise-address "$(ADVERTISE)" :peers "$(PEERS)" :autonomous t :announce-ms $(ANNOUNCE_MS) :lease-seconds $(LEASE_SECONDS))' \
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

# WP-KEYED-FLATDATA cross-DDS interop live harness (FR-PF-4, RTPS 2.5 §9.6.4.8; interop/keyed-flatdata).
# DCPS COPY/UDP path (NO ZeroCopy) of the keyed FlatData type keyed-flat (i32 @key id; i32 x; i32 y); the
# foreign peers are interop/keyed-flatdata/{connext,fastdds}. KEYS=N keys, DISPOSE_AFTER=N dispose-by-key.
keyed-flat-pub:
	$(SBCL) --eval '(asdf:load-system :dds-shapes)' \
	        --eval '(uiop:symbol-call :dds.shapes :run-keyed-flat-publisher :domain $(DOMAIN) :count $(COUNT) :keys $(KEYS) :dispose-after $(DISPOSE_AFTER) :advertise-address "$(ADVERTISE)" :peers "$(PEERS)")' \
	        --eval '(uiop:quit 0)'

keyed-flat-sub:
	$(SBCL) --eval '(asdf:load-system :dds-shapes)' \
	        --eval '(uiop:symbol-call :dds.shapes :run-keyed-flat-subscriber :domain $(DOMAIN) :seconds $(SECONDS) :advertise-address "$(ADVERTISE)" :peers "$(PEERS)")' \
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

# WP-KEYED-FLATDATA Fast DDS interop peers (interop/keyed-flatdata/fastdds; FR-PF-4). FASTDDS_PREFIX via
# with-fastdds.sh; the apps read profiles.xml from their cwd. Owner-run leg. KEYS=N keys, COUNT=0/SECONDS=0
# = forever; DISPOSE_AFTER=N (env) on the pub disposes each key by key (dispose DATA carries PID_KEY_HASH).
fastdds-keyed-flat-pub:
	./scripts/with-fastdds.sh bash -c 'cd interop/keyed-flatdata/fastdds && ./keyed_flat_pub $(COUNT) $(KEYS)'

fastdds-keyed-flat-sub:
	./scripts/with-fastdds.sh bash -c 'cd interop/keyed-flatdata/fastdds && ./keyed_flat_sub $(SECONDS)'

# LIVE cross-vendor interop (FR-IO). Was a STUB: it ran `wire` and ECHOED "pending a Connext install"
# while Connext 7.3.1 was installed and passing — asserting nothing, unable to fail, since M0.
# A gate that cannot run must not report success: gate-interop.sh FAILS on a missing vendor unless
# excused via INTEROP_ALLOW_MISSING=connext|fastdds|both.
interop: wire
	./scripts/gate-interop.sh

# ⚠️ `bench` IS A REPORT, NOT A GATE. It prints latency/throughput and exits 0 whatever the numbers say —
# it has NO pass/fail criterion and CANNOT go red, despite the operating contract §6 listing it among the
# quality gates. Do not treat a green `make bench` as evidence of anything.
# The gate that DOES enforce performance is `make gate-mem`: an end-to-end allocation RATCHET against
# bench/mem-ceiling.txt (fails on a regression AND on an un-banked improvement). Allocation is what owns the
# latency tail (the ~10 ms p99.99 is a GC pause in the PEER — ADR 0062), so that is the number under guard.
# A latency ratchet is NOT viable on this hardware: the box measures 16-32 us for identical code.
bench:
	$(SBCL) --eval '(asdf:load-system :dds-bench)' \
	        --eval '(uiop:symbol-call :dds.bench :run-bench :latency-samples $(LATSAMPLES) :throughput-samples $(THRUSAMPLES))' \
	        --eval '(uiop:quit 0)'

bench-shmem:
	$(SBCL) --eval '(asdf:load-system :dds-bench)' \
	        --eval '(uiop:symbol-call :dds.bench :run-bench-shmem :latency-samples $(LATSAMPLES) :throughput-samples $(THRUSAMPLES))' \
	        --eval '(uiop:quit 0)'

# WP-ZEROCOPY (FR-PF-3): large-sample ZC vs SHMEM vs UDP comparison (default sizes 4/16/64 KiB,
# above *zerocopy-min-payload-bytes*). Each ZEROCOPY run asserts disc-node-zc-sends advanced (a
# 16-byte reference crossed, not the payload). NOT cleared for ship — pending counsel (R6).
bench-zerocopy:
	$(SBCL) --eval '(asdf:load-system :dds-bench)' \
	        --eval '(uiop:symbol-call :dds.bench :run-bench-zerocopy)' \
	        --eval '(uiop:quit 0)'

# WP-FLATDATA Phase E1a (FR-PF-4, NFR-PERF-7, FR-LANG-7): HONEST ser/deser/accessor cost of a FINAL
# fixed-size FlatData type vs the classic per-field codec, plus the FlatData-over-ZC RX (safe single
# copy out of SHMEM, ~830x less than WP-ZEROCOPY-v1 — NOT literal-0-copy). Lives in dds-tests (needs
# the dds-gen FlatData type); writes bench/report/2026-06-14-wp-flatdata.md. NOT cleared for ship (R6).
bench-flatdata:
	$(SBCL) --eval '(asdf:load-system :dds-tests)' \
	        --eval '(handler-case (progn (uiop:symbol-call :dds.tests :run-bench-flatdata :file "bench/report/2026-06-14-wp-flatdata.md") (uiop:quit 0)) (error (e) (format t "~&~a~%" e) (uiop:quit 1)))'

# WP-FLATDATA-ZC-LOAN Phase F2 (FR-PF-3/4, NFR-PERF-7, FR-LANG-7): the literal-0-copy RX headline — the RX GC
# bytes/sample PROGRESSION (literal-0-copy loan via take-loaned/return-loan -> FlatData+ZC v1 single-copy ->
# WP-ZEROCOPY-v1 sink), plus the HONEST loan/return per-sample overhead (the loan API adds the explicit
# acquire/release calls + the app's return obligation — no "0-cost" claim). Lives in dds-tests (needs the
# dds-gen FlatData type); writes bench/report/2026-06-16-wp-flatdata-zc-loan.md. SBCL only (ZC, ADR 0013).
# NOT cleared for ship — pending counsel (R6); see ADR 0017.
bench-flatdata-zc-loan:
	$(SBCL) --eval '(asdf:load-system :dds-tests)' \
	        --eval '(handler-case (progn (uiop:symbol-call :dds.tests :run-bench-flatdata-zc-loan :file "bench/report/2026-06-16-wp-flatdata-zc-loan.md") (uiop:quit 0)) (error (e) (format t "~&~a~%" e) (uiop:quit 1)))'

# WP-FLATDATA-LOAN-WRITE (FR-PF-4, FR-LANG-7): the 0-copy TX headline — the writer writes a FlatData sample
# straight into the SHMEM pool slot via the SAP-mode Offset setters, eliminating BOTH intra-host TX copies
# (app->payload fd-ser + payload->slot %zc-loan) the shipped ZC-TX path pays. BASELINE (two copies) vs LOAN-WRITE
# (zero copies), GC bytes/sample + ns/sample. Writes bench/report/2026-07-03-wp-flatdata-loan-write.md. SBCL only
# (ZC + foreign-SAP writes, ADR 0013). NOT cleared for ship — pending counsel (R6); see ADR 0042.
bench-flatdata-loan-write:
	$(SBCL) --eval '(asdf:load-system :dds-tests)' \
	        --eval '(handler-case (progn (uiop:symbol-call :dds.tests :run-bench-flatdata-loan-write :file "bench/report/2026-07-03-wp-flatdata-loan-write.md") (uiop:quit 0)) (error (e) (format t "~&~a~%" e) (uiop:quit 1)))'

# WP-ZC-LOAN-LOCKFREE Phase C (FR-PF-3/4, NFR-PERF-7, FR-LANG-7): the lock-free 0-alloc loaned RX headline —
# the loaned RX GC bytes/sample now LITERAL 0 (the lock-free %zc-acquire-for-read + cas-sap-u32 %zc-release),
# the full progression 65552 -> 79 -> 31 -> 0, plus the HONEST writer tradeoff (the O(1) freelist-pop became an
# O(slots) refcount==0 scan — benched at several pool sizes; no "0-cost" claim — the reader RX is the win, the
# writer pays a small bounded scan). Lives in dds-tests (needs the dds-gen FlatData type); writes
# bench/report/2026-06-16-wp-zc-loan-lockfree.md. SBCL only (ZC + foreign-SAP atomics, ADR 0013).
# NOT cleared for ship — pending counsel (R6); see ADR 0018.
bench-zc-loan-lockfree:
	$(SBCL) --eval '(asdf:load-system :dds-tests)' \
	        --eval '(handler-case (progn (uiop:symbol-call :dds.tests :run-bench-zc-loan-lockfree :file "bench/report/2026-06-16-wp-zc-loan-lockfree.md") (uiop:quit 0)) (error (e) (format t "~&~a~%" e) (uiop:quit 1)))'

# WP-ZC-MULTI-DEST-REFCOUNT (FR-PF-4, FR-LANG-7; R6, ADR 0047): one shared Zero-Copy slot across N co-resident
# ZC destinations — slots + app->slot copies drop from N to 1 at fan-out. SBCL only (Clasp SHMEM pass-skips).
bench-multi-dest-zc:
	$(SBCL) --eval '(asdf:load-system :dds-tests)' \
	        --eval '(handler-case (progn (uiop:symbol-call :dds.tests :run-bench-multi-dest-zc :file "bench/report/2026-07-05-wp-zc-multi-dest.md") (uiop:quit 0)) (error (e) (format t "~&~a~%" e) (uiop:quit 1)))'

# WP-ASYNC-FLOW Phase F1 (FR-PF-2, FR-LANG-7): HONEST rate-shaping report — achieved-vs-configured rate,
# single-writer paced vs the enable-async UNPACED baseline (pacing ADDS latency by design — no 0-cost claim),
# multi-writer AGGREGATE rate shaped to R (not 2R) + per-datagram RR, and DATA_FRAG fragment cadence (the
# FR-PF-2 headline). Standard DDS, NOT R6 (ADR 0016). Writes bench/report/2026-06-15-wp-async-flow.md. SBCL
# only (real threads + timing; Clasp pass-skips — the flow tests' known Clasp condvar SIGSEGV, NFR-PORT).
bench-async-flow:
	$(SBCL) --eval '(asdf:load-system :dds-tests)' \
	        --eval '(handler-case (progn (uiop:symbol-call :dds.tests :run-bench-async-flow :file "bench/report/2026-06-15-wp-async-flow.md") (uiop:quit 0)) (error (e) (format t "~&~a~%" e) (uiop:quit 1)))'

# WP-FLOW-EDF-PRIORITY (ADR 0016; FR-QOS-1, FR-LANG-7): deterministic ordering-quality report for the :edf +
# :priority scheduling policies vs round-robin — EDF deadline-miss count for mixed LATENCY_BUDGET streams, and
# :priority high-priority service share + the low-priority aging starvation bound. Oracle = a discrete-event
# sim over the SHIPPED %flow-policy-* selectors (injected clock). Standard DDS, NOT R6 (ADR 0016). Writes
# bench/report/2026-07-04-wp-flow-edf-priority.md. SBCL (bench convention; the sim is threadless/impl-agnostic).
bench-flow-edf-priority:
	$(SBCL) --eval '(asdf:load-system :dds-tests)' \
	        --eval '(handler-case (progn (uiop:symbol-call :dds.tests :run-bench-flow-edf-priority :file "bench/report/2026-07-04-wp-flow-edf-priority.md") (uiop:quit 0)) (error (e) (format t "~&~a~%" e) (uiop:quit 1)))'

# WP-KEEPLAST Task E1 (DDS 1.4 §2.2.3.18, FR-LANG-7): HONEST writer-side cost of per-instance
# KEEP_LAST. Drives dds.rtps.history:hc-add-change directly so the KEEP_LAST-vs-KEEP_ALL delta
# isolates the per-instance index + evict (not the transport path). Writer throughput + GC
# bytes/sample for KEEP_ALL/KEEP_LAST x keyed/unkeyed + the keyhash-derivation line; SBCL is the
# record (Clasp bytes-consed=0, NFR-PORT gap). Writes bench/report/2026-06-16-wp-keeplast.md.
bench-keeplast:
	$(SBCL) --eval '(asdf:load-system :dds-bench)' \
	        --eval '(with-open-file (s "bench/report/2026-06-16-wp-keeplast.md" :direction :output :if-exists :supersede :if-does-not-exist :create) (uiop:symbol-call :dds.bench :run-keeplast-bench :samples $(KLSAMPLES) :instances $(KLINSTANCES) :depth $(KLDEPTH) :stream s))' \
	        --eval '(uiop:quit 0)'

# WP-DDS-SECURITY-SECURE-DISCOVERY T4 (§8.5.1.10-.12): whole-RTPS-message protection (SRTPS) encode+decode
# micro-bench of a representative datagram submessage stream (SIGN + ENCRYPT); ns/op + GC bytes/op. T4
# BASELINE (T10 re-measures the integrated path). SBCL is the record (Clasp bytes-consed=0, NFR-PORT).
# Writes bench/report/2026-06-27-wp-secure-discovery-t4.md.
bench-rtps-message:
	$(SBCL) --eval '(asdf:load-system :dds-tests)' \
	        --eval '(with-open-file (s "bench/report/2026-06-27-wp-secure-discovery-t4.md" :direction :output :if-exists :supersede :if-does-not-exist :create) (uiop:symbol-call :dds.tests :run-rtps-message-bench :iters $(RTPSITERS) :size $(RTPSSIZE) :stream s))' \
	        --eval '(uiop:quit 0)'

bench-rtps-message-clasp:
	$(CLASP) --eval '(asdf:load-system :dds-tests)' \
	         --eval '(with-open-file (s "bench/report/2026-06-27-wp-secure-discovery-t4-clasp.md" :direction :output :if-exists :supersede :if-does-not-exist :create) (uiop:symbol-call :dds.tests :run-rtps-message-bench :iters $(RTPSITERS) :size $(RTPSSIZE) :stream s))' \
	         --eval '(uiop:quit 0)'

bench-rtps-protection:
	$(SBCL) --eval '(asdf:load-system :dds-tests)' \
	        --eval '(with-open-file (s "bench/report/2026-06-28-wp-secure-discovery-t10.md" :direction :output :if-exists :supersede :if-does-not-exist :create) (uiop:symbol-call :dds.tests :run-rtps-protection-bench :iters $(RTPSITERS) :size $(RTPSSIZE) :stream s))' \
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
	$(SBCL) --eval '(asdf:load-system :dds-tests)' \
	        --eval '(handler-case (progn (dds.tests:run-mem-test) (uiop:quit 0)) (error (e) (format t "~&~a~%" e) (uiop:quit 1)))'

clean:
	find . -name '*.fasl' -o -name '*.fasp' -o -name '*.faso' -o -name '*.fasc' | xargs -r rm -f
