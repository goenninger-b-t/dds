;;;; Shapes interop harness — a standalone Square/ShapeType publisher and
;;;; subscriber built on the participant data plane (dds-disc) + the generated-type
;;;; codec (dds-gen). Run as two processes (or against RTI rtishapesdemo / Fast DDS
;;;; / Cyclone Shapes) over multicast discovery. This is the front half of the M2
;;;; interop gate: my shapes on the wire, watchable in a foreign Shapes tool.
(defsystem "dds-shapes"
  :description "DDS.SHAPES — standalone Square/ShapeType pub/sub for interop."
  :depends-on ("dds-core" "dds-cdr" "dds-gen" "dds-disc" "dds-qos" "dds-types" "dds-dcps")
  :pathname "src/dds-shapes"
  :serial t
  :components ((:file "packages")
               (:file "shapes")))
