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
make gate-hotpath  # no CLOS dispatch / per-sample allocation in hot-path files (NFR-CLOS)
make mem           # measured 0 bytes/sample serialize + deserialize (NFR-PERF-8)
make wire          # validate emitted RTPS against the tshark RTPS dissector (FR-TOOL-3)
```

### `make gate-build` — and why `make build` alone is not enough

`build` and `test` are *incremental*: ASDF skips any file whose fasl is newer than its source. That makes
them fast, but it also means **they can pass on a tree that does not compile** — a stale
`~/.cache/common-lisp` will happily satisfy a load whose sources no longer build. That is not theoretical:
it let a wrong-arity call sit in `main` for two days while `make test` reported 563/563.

`make gate-build` is the gate that can actually fail. It (1) **clears the fasl cache** and rebuilds from
scratch, and (2) **falsifies itself** first — it compiles a synthetic system containing a deliberate
wrong-arity call and aborts if the build machinery *fails to reject it*. A gate never proven able to fail
proves nothing, so the gate proves it on every run. Run it on both impls before calling work done:

```sh
make gate-build LISP=./scripts/with-clasp.sh
make gate-build LISP=./scripts/with-sbcl.sh
```

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
