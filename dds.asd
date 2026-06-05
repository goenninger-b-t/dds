;;;; Umbrella system: loads every landed M0 layer (L0–L4 + transport).
(defsystem "dds"
  :description "Common Lisp DDS/RTPS stack (XCDR-based, Connext-class core) — M0 skeleton."
  :depends-on ("dds-pal" "dds-core" "dds-cdr" "dds-types" "dds-gen" "dds-rtps" "dds-xport" "dds-disc" "dds-dcps")
  :in-order-to ((test-op (test-op "dds-tests"))))
