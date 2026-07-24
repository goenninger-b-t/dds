;;;; Distributed logging service (ADR 0082, FR-LOG). Slices landed: the LogEvent wire type, the text +
;;;; JSON formatters, and the emit path (logger) + file sink + collector (the thin end-to-end pipeline).
(defsystem "dds-log"
  :description "DDS.LOG — the distributed logging service (ADR 0082): LogEvent wire type, formatters, and
                the logger -> DDS -> collector -> sink pipeline."
  :depends-on ("dds-core" "dds-pal" "dds-cdr" "dds-qos" "dds-types" "dds-gen" "dds-disc" "dds-dcps")
  :pathname "src/dds-log"
  :serial t
  :components ((:file "packages")
               (:file "event")
               (:file "formatter")
               (:file "emit")
               (:file "sink")
               (:file "collector")
               (:file "macros")
               (:file "service")
               (:file "runner")
               (:file "supervisor"))
  :in-order-to ((test-op (test-op "dds-tests"))))
