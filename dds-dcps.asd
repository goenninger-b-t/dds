;;;; L6 — DCPS (the DDS 1.4 entity + QoS layer over the RTPS engine). M3/P2. This
;;;; is CONTROL-PLANE: CLOS is the preferred default (FR-LANG-0 / FR-DCPS-1); the
;;;; hot-path purity rules do not apply here. First increment: the QoS policy model
;;;; + Requested/Offered (RxO) matching (FR-QOS-1/2).
(defsystem "dds-dcps"
  :description "DDS.DCPS — DDS 1.4 entities + QoS (P2)."
  :depends-on ("dds-pal" "dds-core" "dds-cdr" "dds-qos" "dds-types" "dds-rtps" "dds-disc" "dds-security")
  :pathname "src/dds-dcps"
  :serial t
  :components ((:file "packages")
               (:file "statuses")
               (:file "qos-validate")
               (:file "listeners")
               (:file "entities")
               (:file "deadline")
               (:file "type-gate")
               (:file "auth-manager")
               (:file "crypto-manager")
               (:file "access-control")
               (:file "conditions")
               (:file "filter")
               (:file "builtin"))
  :in-order-to ((test-op (test-op "dds-tests"))))
