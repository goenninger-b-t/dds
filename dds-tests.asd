;;;; Cross-cutting M0 test system. `asdf:test-system :dds-tests` runs run-all-tests.
(defsystem "dds-tests"
  :description "M0 unit/integration tests across the landed systems."
  :depends-on ("dds-core" "dds-cdr" "dds-qos" "dds-types" "dds-gen" "dds-rtps" "dds-xport" "dds-disc" "dds-dcps" "dds-bench" "dds-durability" "dds-dare" "dds-security" "dds-log")
  :pathname "src/dds-tests"
  :serial t
  :components ((:file "packages")
               (:file "test-support")
               (:file "echo-test")
               (:file "gen-test")
               (:file "rtps-test")
               (:file "pbt-test")
               (:file "udp-test")
               (:file "xtypes-test")
               (:file "integration-test")
               (:file "legacy-typeobject-test")
               (:file "durability-test")
               (:file "dare-test")
               (:file "security-test")
               (:file "security-auth-test")
               (:file "security-access-control-test")
               (:file "secure-interop")
               (:file "log-test")
               (:file "log-pipeline-test"))
  :perform (test-op (o c)
             (declare (ignore o c))
             (uiop:symbol-call '#:dds.tests '#:run-all-tests)))
