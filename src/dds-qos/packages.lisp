;;;; L3 — QoS value model + RxO matching (M3/P2, FR-QOS). Foundational: depends only
;;;; on dds-core so BOTH the discovery matcher (dds.rtps.discovery / dds.disc) and the
;;;; DCPS entities (dds.dcps) can use it. Control-plane value structs (copy-by-value,
;;;; FR-QOS-3). RxO per DDS 1.4 §2.2.3 (now in docs/specs: dds-1_4-dcps.pdf).

(defpackage #:net.goenninger.dds.qos
  (:nicknames #:dds.qos)
  (:use #:common-lisp)
  (:documentation
   "DDS 1.4 QoS policies + Requested/Offered (RxO) compatibility (FR-QOS-1/2).
    qos-rxo-compatible returns the incompatible-policy list that drives
    OFFERED/REQUESTED_INCOMPATIBLE_QOS and blocks endpoint matching.")
  (:export #:qos-duration #:make-qos-duration #:qos-duration-sec #:qos-duration-nanosec
           #:+duration-zero+ #:+duration-infinite+ #:duration<=
           #:qos #:make-qos #:make-writer-qos #:make-reader-qos #:copy-qos
           #:qos-reliability #:qos-durability #:qos-deadline #:qos-latency-budget
           #:qos-ownership #:qos-ownership-strength
           #:qos-liveliness #:qos-liveliness-lease
           #:qos-destination-order #:qos-presentation-scope
           #:qos-presentation-coherent #:qos-presentation-ordered
           #:qos-data-representation #:qos-partition
           #:qos-history-kind #:qos-history-depth #:qos-lifespan
           #:qos-rxo-compatible #:partition-match-p
           #:run-qos-rxo-test))
