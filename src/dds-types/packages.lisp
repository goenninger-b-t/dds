;;;; L3 — Type system runtime. The type-support record is the manual vtable the
;;;; engine funcalls per sample (IMPLEMENTATION-PLAN §7.3): a plain defstruct of
;;;; function objects, zero type-cache probes. The registry MAY be CLOS; this M0
;;;; uses a hash-table.

(defpackage #:net.goenninger.dds.types
  (:nicknames #:dds.types)
  (:use #:common-lisp)
  (:documentation
   "Per-type type-support vtable + registry (IMPLEMENTATION-PLAN §7.3). Engine
    hot-path code sees only a type-support and funcalls its slots; it never sees
    the concrete sample type.")
  (:export #:type-support #:make-type-support #:type-support-p
           #:type-support-name #:type-support-type-name
           #:type-support-extensibility
           #:type-support-serialize #:type-support-deserialize
           #:type-support-serialized-size #:type-support-key-hash
           #:type-support-typeobject #:type-support-typeidentifier
           #:type-support-sample-pool-alloc #:type-support-sample-pool-free
           #:type-support-flatdata-offset #:type-support-flatdata-builder
           #:type-support-data-representation-mask
           #:register-type #:find-type-support #:registered-type-names))
