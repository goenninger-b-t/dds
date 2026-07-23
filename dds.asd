;;;; Umbrella system: loads every landed M0 layer (L0–L4 + transport).
(defsystem "dds"
  :description "NeoDDS — Common Lisp DDS/RTPS stack (XCDR-based, Connext-class core)."
  :depends-on ("dds-pal" "dds-core" "dds-cdr" "dds-qos" "dds-types" "dds-gen" "dds-rtps" "dds-xport" "dds-disc" "dds-dcps" "dds-durability" "dds-dare" "dds-security")
  :in-order-to ((test-op (test-op "dds-tests"))))
