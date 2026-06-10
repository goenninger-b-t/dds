;;;; L3 — Type system runtime (type-support vtable + registry).
(defsystem "dds-types"
  :description "DDS.TYPES — type-support manual vtable + type registry."
  :depends-on ("dds-cdr" "chipz")
  :pathname "src/dds-types"
  :serial t
  :components ((:file "packages")
               (:file "type-support")
               (:file "xtypes")
               (:file "assignability")
               (:file "typeobject-cdr")
               (:file "typelookup")
               (:file "type-object-lb"))
  :in-order-to ((test-op (test-op "dds-tests"))))
