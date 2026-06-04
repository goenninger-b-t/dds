;;;; L2 — CDR codec (XCDR1 + XCDR2).
(defsystem "dds-cdr"
  :description "DDS.CDR — XCDR1/XCDR2 codec substrate, encapsulation, alignment, endianness."
  :depends-on ("dds-core")
  :pathname "src/dds-cdr"
  :serial t
  :components ((:file "packages")
               (:file "cdr")
               (:file "primitives"))
  :in-order-to ((test-op (test-op "dds-tests"))))
