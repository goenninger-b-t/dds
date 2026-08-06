;;;; L3 — Type system runtime. The type-support record is the manual vtable the
;;;; engine funcalls per sample (IMPLEMENTATION-PLAN §7.3): a plain defstruct of
;;;; function objects, zero type-cache probes. The registry MAY be CLOS; this M0
;;;; uses a hash-table.

(defpackage #:net.goenninger.dds.types
  (:nicknames #:dds.types)
  (:use #:common-lisp #:net.goenninger.dds.lang)
  (:documentation
   "Per-type type-support vtable + registry (IMPLEMENTATION-PLAN §7.3). Engine
    hot-path code sees only a type-support and funcalls its slots; it never sees
    the concrete sample type.")
  (:export #:type-support #:make-type-support #:type-support-p
           #:type-support-name #:type-support-type-name
           #:type-support-extensibility #:type-support-keyed-p
           #:type-support-serialize #:type-support-deserialize
           #:type-support-serialized-size #:type-support-key-hash
           #:type-support-typeobject #:type-support-typeidentifier
           #:type-support-deserialize-into #:type-support-copy-into
           #:type-support-sample-pool-alloc #:type-support-sample-pool-free
           #:type-support-flatdata-offset #:type-support-flatdata-builder #:type-support-flatdata-ctor
           #:type-support-data-representation-mask #:type-support-field-accessors
           ;; WP-FLATDATA fixed-size layout (FR-PF-4, ADR 0015; R6)
           #:flatdata-layout #:make-flatdata-layout #:flatdata-layout-p
           #:flatdata-layout-size #:flatdata-layout-encap-offset #:flatdata-layout-fields
           ;; WP-FLATDATA-ZC-LOAN read-in-place SHMEM-slot view (FR-PF-3/4, ADR 0017; R6)
           #:flatdata-view #:make-flatdata-view #:flatdata-view-p
           #:flatdata-view-slot-sap #:flatdata-view-base-offset #:flatdata-view-len
           #:flatdata-view-pool-sap #:flatdata-view-slot-index #:flatdata-view-generation
           #:register-type #:find-type-support #:registered-type-names
           #:sample-pool #:make-sample-pool #:sample-pool-acquire #:sample-pool-release
           ;; XTypes structural TypeIdentifier / TypeObject model (FR-TYPE-2)
           #:type-identifier #:type-identifier-p #:type-identifier-kind
           #:type-identifier-bound #:type-identifier-element #:type-identifier-hash
           #:primitive-type-identifier #:string8-type-identifier
           #:sequence-type-identifier #:array-type-identifier #:hash-type-identifier
           #:type-identifier= #:type-identifier-referenced
           #:member-name-hash
           #:minimal-struct-member #:make-struct-member #:minimal-struct-member-p
           #:minimal-struct-member-name #:minimal-struct-member-id
           #:minimal-struct-member-type-identifier #:minimal-struct-member-key-p
           #:minimal-struct-member-optional-p #:minimal-struct-member-must-understand-p
           #:minimal-struct-member-name-hash
           #:minimal-struct-type #:make-minimal-struct-type #:minimal-struct-type-p
           #:minimal-struct-type-name #:minimal-struct-type-extensibility
           #:minimal-struct-type-members
           ;; Enumerated type model (FR-TYPE-4 S0)
           #:enum-literal #:make-enum-literal #:enum-literal-value #:enum-literal-name-hash
           #:minimal-enumerated-type #:minimal-enumerated-type-p #:make-minimal-enumerated-type
           #:minimal-enumerated-type-literals #:minimal-enumerated-type-bit-bound
           #:enumerated-type-identifier
           ;; Union type model (FR-TYPE-4 S2)
           #:union-member #:make-union-member #:union-member-labels
           #:union-member-type-identifier #:union-member-name-hash #:union-member-default-p
           #:minimal-union-type #:minimal-union-type-p #:make-minimal-union-type
           #:minimal-union-type-discriminator #:minimal-union-type-members
           #:union-type-identifier
           ;; XTypes type assignability + TYPE_CONSISTENCY_ENFORCEMENT (FR-TYPE-4)
           #:assignability-options #:make-assignability-options
           #:assignability-options-ignore-sequence-bounds
           #:assignability-options-ignore-string-bounds
           #:assignability-options-ignore-member-names
           #:assignability-options-prevent-type-widening
           #:assignability-options-ignore-key-bounds
           #:default-assignability-options
           #:ti-assignable-from #:strongly-assignable-from #:struct-assignable-from
           #:ti-primitive-p #:ti-array-p
           #:enum-assignable-from
           #:union-assignable-from
           #:member-names-agree-p
           #:ti-equivalent-p #:struct-equivalent-p #:enforce-type-consistency
           ;; XCDR2 MinimalTypeObject serializer + EquivalenceHash (FR-TYPE-2/5)
           #:minimal-type-object-octets #:equivalence-hash
           ;; MinimalTypeObject deserializer, the serializer's inverse (FR-TYPE-2/3)
           #:parse-minimal-type-object
           ;; CompleteTypeObject -> MINIMAL reconstruction (XTypes 1.3 §7.6.3.3.4.2, FR-IO-2 S4)
           #:complete-to-minimal-type-object
           ;; TypeInformation codec for PID_TYPE_INFORMATION (FR-TYPE-3 foundation)
           #:serialize-type-information #:deserialize-type-information-hash
           ;; Built-in TypeLookup service request/reply codecs (XTypes 1.3 §7.6.3.3, FR-TYPE-3)
           #:serialize-type-lookup-request #:parse-type-lookup-request
           #:serialize-type-lookup-reply #:parse-type-lookup-reply
           #:+tl-gettypes-hash+ #:+tl-getdeps-hash+
           ;; TypeLookup hash index + pure server core (XTypes 1.3 §7.6.3.3.4, FR-TYPE-3)
           #:find-type-support-by-hash #:type-lookup-respond
           #:*max-typelookup-request-ids*
           ;; Inbound RTI PID_TYPE_OBJECT_LB inflate + fingerprint (ADR 0009)
           #:inflate-type-object-lb #:*max-type-object-bytes*
           #:+type-object-lb-compression-zlib+
           #:type-object-strings #:type-object-mentions-all-p
           #:type-support-fingerprint-names #:assess-type-object-lb
           ;; Legacy-TypeObject structural TLV tokenizer (ADR 0009, NFR-SEC-POSTURE)
           #:tokenize-legacy-type-object
           ;; Legacy-TypeObject semantic interpreter — struct skeleton (ADR 0009)
           #:parse-legacy-type-object
           #:lto-node #:lto-node-p #:lto-node-tag #:lto-node-code
           #:lto-node-value-start #:lto-node-value-end #:lto-node-children #:lto-node-name
           #:*lto-max-depth* #:*lto-max-elements* #:*lto-max-string-bytes*
           #:*lto-max-type-depth*
           #:+tk-boolean+ #:+tk-byte+ #:+tk-int8+ #:+tk-uint8+
           #:+tk-int16+ #:+tk-int32+ #:+tk-int64+
           #:+tk-uint16+ #:+tk-uint32+ #:+tk-uint64+ #:+tk-string8+
           #:+tk-float32+ #:+tk-float64+ #:+tk-char8+
           #:+tk-structure+ #:+tk-sequence+ #:+ek-minimal+ #:+ek-complete+
           #:+ti-string8-small+ #:+ti-string8-large+ #:+ti-plain-sequence-small+
           #:+ti-plain-array-small+ #:+ti-plain-array-large+))
