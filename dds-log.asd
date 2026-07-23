;;;; Distributed logging service (ADR 0082, FR-LOG). This slice: the LogEvent wire type.
(defsystem "dds-log"
  :description "DDS.LOG — the distributed logging service (ADR 0082). Slice: the LogEvent wire type."
  :depends-on ("dds-core" "dds-pal" "dds-qos" "dds-types" "dds-gen" "dds-disc" "dds-dcps")
  :pathname "src/dds-log"
  :serial t
  :components ((:file "packages")
               (:file "event"))
  :in-order-to ((test-op (test-op "dds-tests"))))
