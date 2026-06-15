(defpackage #:net.goenninger.dds.tests
  (:nicknames #:dds.tests)
  (:use #:common-lisp #:net.goenninger.dds.lang)
  (:documentation
   "M0 test harness. run-all-tests is invoked by (asdf:test-system :dds-tests)
    and signals on any failure so the build gate goes red.")
  (:export #:run-all-tests #:run-echo-test #:run-mem-test #:run-pbt-tests
           #:run-bench-flatdata #:test-failure))
