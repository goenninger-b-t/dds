(defpackage #:net.goenninger.dds.tests
  (:nicknames #:dds.tests)
  (:use #:common-lisp #:net.goenninger.dds.lang)
  (:documentation
   "M0 test harness. run-all-tests is invoked by (asdf:test-system :dds-tests)
    and signals on any failure so the build gate goes red.")
  (:export #:run-all-tests #:run-echo-test #:run-mem-test #:run-pbt-tests
           #:run-pal-signal-handler-test
           #:run-bench-flatdata #:run-bench-flatdata-zc-loan #:run-bench-zc-loan-lockfree
           #:run-bench-async-flow #:test-failure #:run-durability-store-test
           #:run-durability-spec-test #:run-durability-collect-test
           #:run-durability-transient-test #:run-durability-runner-test
           #:run-durability-supervisor-test #:run-durability-runner-lifecycle-test
           #:run-durability-config-test #:run-durability-process-smoke-test
           #:run-durability-writer-rep-test
           #:run-original-writer-info-vector-test
           #:run-data-inline-qos-emit-test
           #:run-relay-emit-test
           #:run-original-writer-dedup-test
           #:run-dedup-cap-test
           #:run-vendor-sedp-pid-test
           #:run-durability-no-double-delivery-test
           #:run-durability-multi-relay-dedup-test
           #:run-durability-multitopic-test
           #:run-durability-dispose-replay-test
           #:run-dare-sha384-hkdf-kat-test
           #:run-dare-aes-gcm-kat-test
           #:run-dare-ml-kem-kat-test
           #:run-dare-envelope-test
           #:run-dare-key-provider-test
           #:run-dare-encrypted-store-test
           #:run-dare-encrypted-store-lifecycle-test
           #:run-dare-service-transparency-test
           #:run-dare-envelope-v2-test
           #:run-durability-file-store-test
           #:run-durability-file-recovery-test
           #:run-dare-persistent-store-test
           #:run-durability-persistent-service-test
           #:run-durability-compaction-test
           #:run-durability-seed-backpressure-test
           #:run-durability-seen-prune-test
           #:run-durability-dynamic-topic-test
           #:run-durability-relay-tier-test
           #:run-durability-collect-tier-test
           #:run-durability-origin-accessor-test
           #:run-durability-collect-origin-convergence-test
           #:run-durability-data-keyhash-capture-test
           #:run-durability-collect-keyhash-store-test
           #:run-durability-keeplast-memory-test
           #:run-durability-keeplast-compaction-test
           #:run-durability-keeplast-cross-restart-test
           #:run-durability-keeplast-service-spec-policy-test
           #:run-durability-graceful-teardown-order-test))
