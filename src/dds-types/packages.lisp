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
           #:type-support-data-representation-mask #:type-support-field-accessors
           #:register-type #:find-type-support #:registered-type-names
           #:sample-pool #:make-sample-pool #:sample-pool-acquire #:sample-pool-release
           ;; XTypes structural TypeIdentifier / TypeObject model (FR-TYPE-2)
           #:type-identifier #:type-identifier-p #:type-identifier-kind
           #:type-identifier-bound #:type-identifier-element #:type-identifier-hash
           #:primitive-type-identifier #:sequence-type-identifier #:hash-type-identifier
           #:type-identifier= #:type-identifier-referenced
           #:member-name-hash
           #:minimal-struct-member #:make-struct-member
           #:minimal-struct-member-name #:minimal-struct-member-id
           #:minimal-struct-member-type-identifier #:minimal-struct-member-key-p
           #:minimal-struct-member-optional-p #:minimal-struct-member-must-understand-p
           #:minimal-struct-member-name-hash
           #:minimal-struct-type #:make-minimal-struct-type
           #:minimal-struct-type-name #:minimal-struct-type-extensibility
           #:minimal-struct-type-members
           ;; XTypes type assignability + TYPE_CONSISTENCY_ENFORCEMENT (FR-TYPE-4)
           #:assignability-options #:make-assignability-options
           #:assignability-options-ignore-sequence-bounds
           #:assignability-options-ignore-string-bounds
           #:assignability-options-ignore-member-names
           #:assignability-options-prevent-type-widening
           #:default-assignability-options
           #:ti-assignable-from #:strongly-assignable-from #:struct-assignable-from
           #:ti-equivalent-p #:struct-equivalent-p #:enforce-type-consistency
           ;; XCDR2 MinimalTypeObject serializer + EquivalenceHash (FR-TYPE-2/5)
           #:minimal-type-object-octets #:equivalence-hash
           ;; TypeInformation codec for PID_TYPE_INFORMATION (FR-TYPE-3 foundation)
           #:serialize-type-information #:deserialize-type-information-hash
           ;; Inbound RTI PID_TYPE_OBJECT_LB inflate + fingerprint (ADR 0009)
           #:inflate-type-object-lb #:*max-type-object-bytes*
           #:+type-object-lb-compression-zlib+
           #:type-object-strings #:type-object-mentions-all-p
           #:+tk-boolean+ #:+tk-byte+ #:+tk-int16+ #:+tk-int32+ #:+tk-int64+
           #:+tk-uint16+ #:+tk-uint32+ #:+tk-uint64+ #:+tk-string8+
           #:+tk-structure+ #:+tk-sequence+ #:+ek-minimal+ #:+ek-complete+
           #:+ti-string8-small+ #:+ti-plain-sequence-small+))
