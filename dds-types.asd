;;;; L3 — Type system runtime (type-support vtable + registry).
(defsystem "dds-types"
  :description "DDS.TYPES — type-support manual vtable + type registry."
  :depends-on ("dds-cdr")
  :pathname "src/dds-types"
  :serial t
  :components ((:file "packages")
               (:file "type-support")
               (:file "xtypes")
               (:file "assignability")
               (:file "typeobject-cdr"))
  :in-order-to ((test-op (test-op "dds-tests"))))
