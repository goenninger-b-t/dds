(defpackage #:net.goenninger.dds.tests
  (:nicknames #:dds.tests)
  (:use #:common-lisp #:net.goenninger.dds.lang)
  (:documentation
   "M0 test harness. run-all-tests is invoked by (asdf:test-system :dds-tests)
    and signals on any failure so the build gate goes red.")
  (:export #:run-all-tests #:run-echo-test #:run-mem-test #:run-pbt-tests
           #:run-bench-flatdata #:run-bench-flatdata-zc-loan #:run-bench-zc-loan-lockfree
           #:run-bench-async-flow #:test-failure #:run-durability-store-test
           #:run-durability-spec-test #:run-durability-collect-test
           #:run-durability-transient-test #:run-durability-runner-test
           #:run-durability-supervisor-test #:run-durability-runner-lifecycle-test
           #:run-durability-config-test #:run-durability-process-smoke-test
           #:run-durability-writer-rep-test))
