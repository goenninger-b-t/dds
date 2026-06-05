;;;; L6 — DCPS QoS module (M3/P2, FR-QOS). The DDS 1.4 QoS policy set + RxO
;;;; matching. Control-plane: value structs (defstruct is cleanest for the
;;;; copy-by-value semantics QoS requires, FR-QOS-3); the DCPS *entities* that
;;;; follow will be CLOS. RxO rules per DDS 1.4 §2.2.3 (the DCPS spec is not yet in
;;;; docs/specs — flagged for addition; the RxO compatibility table is standard and
;;;; cited inline, not a memorized wire constant).

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
