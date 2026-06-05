;;;; L3 — QoS value model + RxO matching (M3/P2). Foundational so the discovery
;;;; matcher and the DCPS entities share one QoS/RxO implementation.
(defsystem "dds-qos"
  :description "DDS.QOS — DDS 1.4 QoS policy set + Requested/Offered matching."
  :depends-on ("dds-core")
  :pathname "src/dds-qos"
  :serial t
  :components ((:file "packages")
               (:file "qos"))
  :in-order-to ((test-op (test-op "dds-tests"))))
