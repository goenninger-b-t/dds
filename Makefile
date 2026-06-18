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
        nokey-pub nokey-sub keyed-flat-pub keyed-flat-sub \
        fastdds-pub fastdds-sub fastdds-tl-probe fastdds-type-probe fastdds-keyed-flat-pub fastdds-keyed-flat-sub bench bench-shmem bench-zerocopy bench-flatdata bench-flatdata-zc-loan bench-zc-loan-lockfree bench-async-flow bench-keeplast shmem-xproc zc-xproc mem sbom hooks clean

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
KEYS     ?= 3
DISPOSE_AFTER ?= 0
LATSAMPLES  ?= 10000
THRUSAMPLES ?= 20000
KLSAMPLES   ?= 1000000
KLINSTANCES ?= 100
KLDEPTH     ?= 2
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
	        --eval '(uiop:symbol-call :dds.shapes :run-publisher :domain $(DOMAIN) :color "$(COLOR)" :advertise-address "$(ADVERTISE)" :type :$(TYPE) :count $(COUNT) :peers "$(PEERS)" :port $(PORT) $(LIVELINESS_ARGS) $(PERF_ARGS) $(FAULT_ARGS) $(HISTORY_ARGS) $(REP_ARGS) $(DURABILITY_ARGS))' \
	        --eval '(uiop:quit 0)'

square-sub:
	$(SBCL) --eval '(asdf:load-system :dds-shapes)' \
	        --eval '(uiop:symbol-call :dds.shapes :run-subscriber :domain $(DOMAIN) :advertise-address "$(ADVERTISE)" :type :$(TYPE) :peers "$(PEERS)" :port $(PORT) $(DURABILITY_ARGS))' \
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

# WP-FLATDATA Phase E1a (FR-PF-4, NFR-PERF-7, FR-LANG-7): HONEST ser/deser/accessor cost of a FINAL
# fixed-size FlatData type vs the classic per-field codec, plus the FlatData-over-ZC RX (safe single
# copy out of SHMEM, ~830x less than WP-ZEROCOPY-v1 — NOT literal-0-copy). Lives in dds-tests (needs
# the dds-gen FlatData type); writes bench/report/2026-06-14-wp-flatdata.md. NOT cleared for ship (R6).
bench-flatdata:
	$(SBCL) --eval '(ql:quickload :dds-tests :silent t)' \
	        --eval '(handler-case (progn (uiop:symbol-call :dds.tests :run-bench-flatdata :file "bench/report/2026-06-14-wp-flatdata.md") (uiop:quit 0)) (error (e) (format t "~&~a~%" e) (uiop:quit 1)))'

# WP-FLATDATA-ZC-LOAN Phase F2 (FR-PF-3/4, NFR-PERF-7, FR-LANG-7): the literal-0-copy RX headline — the RX GC
# bytes/sample PROGRESSION (literal-0-copy loan via take-loaned/return-loan -> FlatData+ZC v1 single-copy ->
# WP-ZEROCOPY-v1 sink), plus the HONEST loan/return per-sample overhead (the loan API adds the explicit
# acquire/release calls + the app's return obligation — no "0-cost" claim). Lives in dds-tests (needs the
# dds-gen FlatData type); writes bench/report/2026-06-16-wp-flatdata-zc-loan.md. SBCL only (ZC, ADR 0013).
# NOT cleared for ship — pending counsel (R6); see ADR 0017.
bench-flatdata-zc-loan:
	$(SBCL) --eval '(ql:quickload :dds-tests :silent t)' \
	        --eval '(handler-case (progn (uiop:symbol-call :dds.tests :run-bench-flatdata-zc-loan :file "bench/report/2026-06-16-wp-flatdata-zc-loan.md") (uiop:quit 0)) (error (e) (format t "~&~a~%" e) (uiop:quit 1)))'

# WP-ZC-LOAN-LOCKFREE Phase C (FR-PF-3/4, NFR-PERF-7, FR-LANG-7): the lock-free 0-alloc loaned RX headline —
# the loaned RX GC bytes/sample now LITERAL 0 (the lock-free %zc-acquire-for-read + cas-sap-u32 %zc-release),
# the full progression 65552 -> 79 -> 31 -> 0, plus the HONEST writer tradeoff (the O(1) freelist-pop became an
# O(slots) refcount==0 scan — benched at several pool sizes; no "0-cost" claim — the reader RX is the win, the
# writer pays a small bounded scan). Lives in dds-tests (needs the dds-gen FlatData type); writes
# bench/report/2026-06-16-wp-zc-loan-lockfree.md. SBCL only (ZC + foreign-SAP atomics, ADR 0013).
# NOT cleared for ship — pending counsel (R6); see ADR 0018.
bench-zc-loan-lockfree:
	$(SBCL) --eval '(ql:quickload :dds-tests :silent t)' \
	        --eval '(handler-case (progn (uiop:symbol-call :dds.tests :run-bench-zc-loan-lockfree :file "bench/report/2026-06-16-wp-zc-loan-lockfree.md") (uiop:quit 0)) (error (e) (format t "~&~a~%" e) (uiop:quit 1)))'

# WP-ASYNC-FLOW Phase F1 (FR-PF-2, FR-LANG-7): HONEST rate-shaping report — achieved-vs-configured rate,
# single-writer paced vs the enable-async UNPACED baseline (pacing ADDS latency by design — no 0-cost claim),
# multi-writer AGGREGATE rate shaped to R (not 2R) + per-datagram RR, and DATA_FRAG fragment cadence (the
# FR-PF-2 headline). Standard DDS, NOT R6 (ADR 0016). Writes bench/report/2026-06-15-wp-async-flow.md. SBCL
# only (real threads + timing; Clasp pass-skips — the flow tests' known Clasp condvar SIGSEGV, NFR-PORT).
bench-async-flow:
	$(SBCL) --eval '(ql:quickload :dds-tests :silent t)' \
	        --eval '(handler-case (progn (uiop:symbol-call :dds.tests :run-bench-async-flow :file "bench/report/2026-06-15-wp-async-flow.md") (uiop:quit 0)) (error (e) (format t "~&~a~%" e) (uiop:quit 1)))'

# WP-KEEPLAST Task E1 (DDS 1.4 §2.2.3.18, FR-LANG-7): HONEST writer-side cost of per-instance
# KEEP_LAST. Drives dds.rtps.history:hc-add-change directly so the KEEP_LAST-vs-KEEP_ALL delta
# isolates the per-instance index + evict (not the transport path). Writer throughput + GC
# bytes/sample for KEEP_ALL/KEEP_LAST x keyed/unkeyed + the keyhash-derivation line; SBCL is the
# record (Clasp bytes-consed=0, NFR-PORT gap). Writes bench/report/2026-06-16-wp-keeplast.md.
bench-keeplast:
	$(SBCL) --eval '(ql:quickload :dds-bench :silent t)' \
	        --eval '(with-open-file (s "bench/report/2026-06-16-wp-keeplast.md" :direction :output :if-exists :supersede :if-does-not-exist :create) (uiop:symbol-call :dds.bench :run-keeplast-bench :samples $(KLSAMPLES) :instances $(KLINSTANCES) :depth $(KLDEPTH) :stream s))' \
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
