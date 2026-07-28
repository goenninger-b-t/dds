# Getting started

## Prerequisites

- **SBCL** and/or **Clasp** (64-bit), with **Quicklisp** installed. AllegroCL is a planned
  target but not yet wired in.
- The `Makefile` drives per-implementation builds via `scripts/with-sbcl.sh` and
  `scripts/with-clasp.sh` (they load Quicklisp and point ASDF at the repo).

## Build & test

```sh
make build         # load all systems (default LISP = Clasp; override LISP=./scripts/with-sbcl.sh)
make test          # run the unit/integration suite once
make build-all     # build on both landed impls (Clasp + SBCL)
make test-all      # test on both
make gate-build    # THE build gate: clean-cache rebuild + a falsification self-test (see below)
make gate-types    # every defun has a single-line ftype declaim (FR-LANG-8)
make gate-pal      # no reader conditionals outside dds-pal/ (contract §10, NFR-PORT)
make gate-hotpath  # no CLOS dispatch (NFR-CLOS) + no UNJUSTIFIED allocation (NFR-MEM) in hot-path files
make mem           # CODEC-only: 0 bytes/sample serialize + deserialize (NFR-PERF-8) — see the caveat below
make gate-mem      # NFR-MEM RATCHET: END-TO-END bytes/sample, must not regress (ADR 0062). SBCL only.
make wire          # validate emitted RTPS against the tshark RTPS dissector (FR-TOOL-3)
make interop       # LIVE cross-vendor interop: Connext 7.3.1 + Fast DDS (FR-IO)
```

### `make mem` vs `make gate-mem` — read this before trusting either

`make mem` measures the **codec in isolation** (serialize / deserialize / AEAD) and reports ~0 bytes per
iteration. That is a real assertion and it would fail if the codec regressed — but it measures **no
workload**, so it is *not* the per-sample budget it is often credited with. It stayed green while the live
DCPS path allocated ~3.9 KB per sample.

`make gate-mem` measures the **end-to-end DCPS path** — `write-sample` → engine → transport → receiver
thread → `take-samples` — which is the number NFR-MEM constrains and the one that drives the peer's GC
pause (the ~10 ms latency tail is a GC *in the peer*, fed by exactly this garbage; ADR 0062).

NFR-MEM's target is **zero**, and we are not there. A gate that failed at "anything above zero" would be
permanently red and therefore ignored, so `gate-mem` is a **ratchet** against `bench/mem-ceiling.txt`:

- measured **above** the ceiling → **FAIL** (allocation regressed);
- measured **well below** it → **FAIL**, telling you to *lower the ceiling and commit it*;
- otherwise → pass, while printing how far above zero we still are.

Failing on an *improvement* is deliberate: a ceiling that is never lowered drifts away from reality and
quietly stops constraining anything — the same slow death as a gate that cannot fail. The ratchet only
moves down, and the ceiling file is the record of how far NFR-MEM has actually got.

**Two arms since ADR 0093**, because there are now two honest workloads — each with its own ceiling on the
arch's row, and each measured in its **own process on its own domain**:

```
gate-mem: COPY   allocation = 1057.3 bytes/sample (ceiling 1090, NFR-MEM target 0)
gate-mem: RETURN allocation = 848.0 bytes/sample (ceiling 880, NFR-MEM target 0)
gate-mem: PASS — no regression. Returning the loan saves 209.3 B/sample; still 848 above the target of ZERO.
```

- **COPY** — the application takes samples and drops them. The legacy arm, unchanged, so every historical
  ceiling row stays comparable.
- **RETURN** — the application `return-loan`s each taken sample, honouring the [ADR 0093](../adr/0093-the-copy-path-becomes-a-loan.md)
  loan contract so the reader can recycle its delivery wrappers. **This is the only arm in which the
  recycling is visible at all**; measuring only COPY would leave that win unratcheted and free to regress
  silently.

An arch whose RETURN ceiling is `-` in `bench/mem-ceiling.txt` (not yet measured there) is still measured
and **reported, with the row to paste in** — it is simply not gated, so an unmeasured arch prints the
number it needs instead of going red. ⚠️ **Never fill a `-` from the other arch's number:** the two diverge
materially and unpredictably, and a predicted value has already been 58 B wrong once.

⚠️ **Each arm runs in its own process on its own domain, and that is load-bearing.** Two arms sharing an
image and a domain *discover each other*, so the second pays for the first's participants and reads high —
measured during ADR 0093 as a 1000 B phantom "regression" that was diagnosed as a code defect before the
harness was suspected. It is the same rule as the standing order that concurrently running tests must use
different DDS domain IDs.

### CI runs the gates now — and it did not before

Until `.github/workflows/gates.yml`, the **only** workflow in this repo was `publish-wiki.yml`. **No build,
no tests, no gates ran automatically on any push.** Every check happened only when a human remembered to run
it locally — which is how `main` went two days without compiling from a clean cache while `make test`
reported 563/563.

The operating contract asserted CI enforcement that did not exist ("the **CI** hotpath-purity-gate enforces
this"; "no reader conditionals outside `dds-pal/` — **CI lint** enforces this"). Both claims were false; the
lint had never been written. `gates.yml` and `make gate-pal` make them true.

**What CI does NOT cover — stated loudly, never silently skipped:**

- **Clasp.** It is a source build, impractical on a hosted runner. The standing rule is that **Clasp AND
  SBCL must both validate**, so this stays a **human step**:
  `make test-clasp && make gate-build LISP=./scripts/with-clasp.sh`.
- **Interop.** Needs licensed RTI Connext + a Fast DDS build. Human step: `make interop`.

### ⚠️ `make bench` is a REPORT, not a gate

It prints latency/throughput and **exits 0 whatever the numbers say** — no pass/fail criterion, so it cannot
go red, despite §6 listing it among the quality gates. **A green `make bench` is not evidence of anything.**

The gate that actually enforces performance is **`make gate-mem`** — an end-to-end allocation *ratchet*.
Allocation is what owns the latency tail (the ~10 ms p99.99 is a GC pause in the *peer*; ADR 0062), so that
is the number under guard. A latency ratchet is not viable on this hardware: the box measures 16–32 µs for
identical code.

### `make gate-build` — and why `make build` alone is not enough

`build` and `test` are *incremental*: ASDF skips any file whose fasl is newer than its source. That makes
them fast, but it also means **they can pass on a tree that does not compile** — a stale fasl cache will
happily satisfy a load whose sources no longer build. That is not theoretical: it let a wrong-arity call
sit in `main` for two days while `make test` reported 563/563.

`make gate-build` is the gate that can actually fail. It (1) **clears the fasl cache** and rebuilds from
scratch, and (2) **falsifies itself** first — it compiles a synthetic system containing a deliberate
wrong-arity call and aborts if the build machinery *fails to reject it*. A gate never proven able to fail
proves nothing, so the gate proves it on every run. Run it on both impls before calling work done:

```sh
make gate-build LISP=./scripts/with-clasp.sh
make gate-build LISP=./scripts/with-sbcl.sh
```

**The fasl cache is private to this project.** Every Lisp entry point (`scripts/with-sbcl.sh`,
`scripts/with-clasp.sh`, `scripts/gate-build.sh`) sources `scripts/lisp-cache-env.sh`, which sets
`XDG_CACHE_HOME` to `~/.cache/hofvarpnir` unless you have already exported one. This matters because
ASDF's default puts every project's fasls in one shared `~/.cache/common-lisp` keyed only by
implementation+version — so `gate-build`'s `rm -rf` would delete the fasls of any *other* project's Lisp
running at the same time, mid-run, surfacing as a failure in a project you were not even touching. A
private root also makes the clean-cache guarantee **stronger** than the wipe: nothing else writes there,
so what the gate clears is all there was. The cache lives outside the repo deliberately — this tree sits
in a synced folder, and a churning build cache must never be synced.

### `make gate-hotpath` — CLOS purity *and* allocation purity

It enforces two things over the designated hot-path files: no CLOS dispatch (NFR-CLOS), and **no
unjustified heap allocation** (NFR-MEM). The second check is new: the gate used to scan for CLOS only,
which is how `message.lisp` sat in the certified-clean list while `parse-header` allocated a 12-octet
guidPrefix on *every* inbound datagram.

Allocation is enforced by **annotation, not prohibition** — a hot-path file may allocate, but every
allocating form must say why:

```lisp
(make-array 12 :element-type '(unsigned-byte 8))   ; HOTPATH-ALLOC(COLD): teardown only, not per sample
```

Classes: `LOAD-TIME`, `COLD`, `ERROR-PATH`, `TEST`, and `TRACKED` (a **real** per-sample allocation, known
NFR-MEM debt, being driven to zero under ADR 0062). An **unmarked** allocating form fails the build — that
is the regression guard. The gate **prints the outstanding `TRACKED` set on every run**, so the remaining
debt is enumerated in the open rather than hiding in a profile nobody reruns. Like `gate-build`, it
falsifies itself on every run.

> **Never load our systems with `ql:quickload`.** It wraps the load in
> `ql-impl-util:call-with-quiet-compilation`, i.e. `(handler-bind ((warning #'muffle-warning)) ...)`, so
> `compile-file`'s `failure-p` never reaches ASDF and **no compile warning can fail the build**. Use
> `asdf:load-system`, which honours `*compile-file-failure-behaviour*`. Quicklisp is still what provides
> the dependencies — it just must not be what *gates* our code.

From a REPL:

```lisp
(ql:quickload :dds)        ; the control-plane stack
;; or a narrower system:
(ql:quickload :dds-cdr)    ; just the codec
(asdf:test-system :dds-tests)   ; run the suite
```

## Publish / subscribe in 4 steps

This is the DCPS happy path (adapted from `run-dcps-entity-test` in
`src/dds-tests/integration-test.lisp`). See [DCPS](dcps.md) for the full API.

```lisp
(ql:quickload :dds)

;; 1. Define a topic type. define-dds-type emits a defstruct + monomorphic XCDR codecs +
;;    key-hash + the XTypes TypeObject + a registered type-support, all named after the type.
(dds.gen:define-dds-type sensor (:extensibility :final)
  (id    :i32 :key t)     ; @key  -> participates in the instance key-hash
  (temp  :i32)
  (label :string))

;; 2. Two participants on domain 0; a writer and a reader on the same topic + type.
(let* ((ts  (dds.types:find-type-support "sensor"))
       (p1  (dds.dcps:create-participant :domain 0))
       (p2  (dds.dcps:create-participant :domain 0))
       (tw  (dds.dcps:create-topic p1 "Sensors" "sensor" ts))
       (tr  (dds.dcps:create-topic p2 "Sensors" "sensor" ts))
       (dw  (dds.dcps:create-datawriter (dds.dcps:create-publisher  p1) tw))
       (dr  (dds.dcps:create-datareader (dds.dcps:create-subscriber p2) tr)))
  (unwind-protect
       (progn
         ;; 3. Drive discovery until the endpoints match (caller-driven `spin` in v1).
         (loop repeat 150
               until (and (plusp (dds.dcps:matched-count p1))
                          (plusp (dds.dcps:matched-count p2)))
               do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))

         ;; 4. Write a sample; take it on the reader.
         (dds.dcps:write-sample dw (make-sensor :id 1 :temp 21 :label "rack-A"))
         (let ((got nil))
           (loop repeat 150 until got
                 do (let ((s (dds.dcps:take-samples dr)))
                      (when s (setf got (dds.dcps:cached-sample-data (first s)))))
                    (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
           (format t "~&reader got: id=~d temp=~d label=~s~%"
                   (sensor-id got) (sensor-temp got) (sensor-label got))))
    (dds.dcps:delete-participant p1)
    (dds.dcps:delete-participant p2)))
```

### What just happened

- `define-dds-type` registered a `type-support` (a `defstruct` of functions — the manual
  vtable) under the name `"sensor"`; `find-type-support` retrieves it. See
  [Type system](type-system.md).
- `create-topic` binds a topic name + type name to that `type-support`.
- Discovery (SPDP then SEDP) runs over UDP loopback; `matched-count` reflects RxO-compatible
  endpoint matches. See [Discovery](discovery.md) and [QoS](qos.md).
- `write-sample` serializes through the generated XCDR2 codec; the reliable RTPS data plane
  delivers it; `take-samples` returns `cached-sample` objects whose `cached-sample-data` is
  your `sensor` struct. See [DCPS](dcps.md) and the [RTPS engine](rtps-engine.md).

## Talk to RTI Connext / other DDS Shapes

```sh
make square-pub COLOR=BLUE     # publish ShapeType (interop with rtishapesdemo / our square-sub)
make square-sub                # subscribe
make square-spy                # discovery diagnostic
```

See [Interop](interop.md) for the Connext oracle/interop harness under `interop/connext/`.
