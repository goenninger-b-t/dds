;;;; Cross-cutting M0 test system. `asdf:test-system :dds-tests` runs run-all-tests.
(defsystem "dds-tests"
  :description "M0 unit/integration tests across the landed systems."
  :depends-on ("dds-core" "dds-cdr" "dds-qos" "dds-types" "dds-gen" "dds-rtps" "dds-xport" "dds-disc" "dds-dcps")
  :pathname "src/dds-tests"
  :serial t
  :components ((:file "packages")
               (:file "echo-test")
               (:file "gen-test")
               (:file "rtps-test")
               (:file "pbt-test")
               (:file "udp-test")
               (:file "xtypes-test")
               (:file "integration-test"))
  :perform (test-op (o c)
             (declare (ignore o c))
             (uiop:symbol-call '#:dds.tests '#:run-all-tests)))
