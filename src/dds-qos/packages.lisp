;;;; L3 — QoS value model + RxO matching (M3/P2, FR-QOS). Foundational: depends only
;;;; on dds-core so BOTH the discovery matcher (dds.rtps.discovery / dds.disc) and the
;;;; DCPS entities (dds.dcps) can use it. Control-plane value structs (copy-by-value,
;;;; FR-QOS-3). RxO per DDS 1.4 §2.2.3 (now in docs/specs: dds-1_4-dcps.pdf).

(defpackage #:net.goenninger.dds.qos
  (:nicknames #:dds.qos)
  (:use #:common-lisp #:net.goenninger.dds.lang)
  (:documentation
   "DDS 1.4 QoS policies + Requested/Offered (RxO) compatibility (FR-QOS-1/2).
    qos-rxo-compatible returns the incompatible-policy list that drives
    OFFERED/REQUESTED_INCOMPATIBLE_QOS and blocks endpoint matching.")
  (:export #:qos-duration #:make-qos-duration #:qos-duration-sec #:qos-duration-nanosec
           #:+duration-zero+ #:+duration-infinite+ #:duration<=
           #:duration-nanosec->wire-fraction #:wire-fraction->duration-nanosec
           #:qos #:make-qos #:make-writer-qos #:make-reader-qos #:copy-qos
           #:qos-reliability #:qos-durability #:qos-deadline #:qos-latency-budget
           #:qos-ownership #:qos-ownership-strength #:qos-transport-priority
           #:qos-liveliness #:qos-liveliness-lease #:liveliness-rank
           #:qos-destination-order #:qos-presentation-scope
           #:qos-presentation-coherent #:qos-presentation-ordered
           #:qos-data-representation #:qos-partition
           #:qos-autodispose-unregistered-instances
           #:qos-autopurge-nowriter-samples-delay #:qos-autopurge-disposed-samples-delay
           #:qos-history-kind #:qos-history-depth #:qos-lifespan
           #:qos-resource-max-samples #:qos-resource-max-instances
           #:qos-resource-max-samples-per-instance
           #:qos-type-consistency
           ;; TYPE_CONSISTENCY_ENFORCEMENT policy (XTypes, reader-only; FR-TYPE-4)
           #:type-consistency-enforcement #:make-type-consistency-enforcement
           #:copy-type-consistency-enforcement
           #:type-consistency-enforcement-kind
           #:type-consistency-enforcement-ignore-sequence-bounds
           #:type-consistency-enforcement-ignore-string-bounds
           #:type-consistency-enforcement-ignore-member-names
           #:type-consistency-enforcement-prevent-type-widening
           #:type-consistency-enforcement-force-type-validation
           #:qos-rxo-compatible #:partition-match-p
           #:run-qos-rxo-test #:run-data-representation-rxo-test))
