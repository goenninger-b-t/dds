;;;; L3 — Type compiler: s-expr DSL -> defstruct + monomorphic codecs + type-support.
(defsystem "dds-gen"
  :description "DDS.GEN — define-dds-type: the s-expr type compiler (FR-TOOL-1)."
  :depends-on ("dds-cdr" "dds-types")
  :pathname "src/dds-gen"
  :serial t
  :components ((:file "packages")
               (:file "runtime")
               (:file "dsl"))
  :in-order-to ((test-op (test-op "dds-tests"))))
