;;;; L9 — the embedded TRANSIENT durability/persistence service (ADR 0021 slice 2).
(defsystem "dds-durability"
  :description "DDS.DURABILITY — embedded TRANSIENT durability service: collect, store, replay to late-joiners."
  :depends-on ("dds-core" "dds-pal" "dds-qos" "dds-types" "dds-disc" "dds-dcps" "dds-dare" "sqlite")
  :pathname "src/dds-durability"
  :serial t
  :components ((:file "packages")
               (:file "store")
               (:file "store-file")
               (:file "store-sqlite")
               (:file "spec")
               (:file "service")
               (:file "store-encrypted")
               (:file "runner")
               (:file "supervisor")
               (:file "main"))
  :in-order-to ((test-op (test-op "dds-tests"))))
