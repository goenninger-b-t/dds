(defpackage #:net.goenninger.dds.tests
  (:nicknames #:dds.tests)
  (:use #:common-lisp #:net.goenninger.dds.lang)
  (:documentation
   "M0 test harness. run-all-tests is invoked by (asdf:test-system :dds-tests)
    and signals on any failure so the build gate goes red.")
  (:export #:*test-domain* #:test-domain #:test-domain-from-env
           #:run-all-tests #:run-echo-test #:run-mem-test #:run-mem-test-secure #:run-pbt-tests
           #:run-pal-signal-handler-test
           #:run-bench-flatdata #:run-bench-flatdata-zc-loan #:run-bench-zc-loan-lockfree
           #:run-bench-flatdata-loan-write #:run-bench-multi-dest-zc
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
           #:run-dare-image-restart-reresolve-test
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
           #:run-durability-sqlite-load-test
           #:run-durability-sqlite-store-test
           #:run-durability-sqlite-dare-test
           #:run-durability-sqlite-service-test
           #:run-durability-compaction-test
           #:run-durability-seed-backpressure-test
           #:run-durability-seen-prune-test
           #:run-durability-fsync-directory-test
           #:run-durability-frame-version-test
           #:run-durability-mac-chain-test
           #:run-durability-store-dir-perms-test
           #:run-durability-process-persistent-refuse-test
           #:run-durability-origins-cap-test
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
           #:run-durability-graceful-teardown-order-test
           #:run-security-secured-payload-corpus-test
           #:run-security-secured-payload-pad-corpus-test
           #:run-security-keymaterial-harden-test
           #:run-security-payload-roundtrip-test
           #:run-security-payload-into-test
           #:run-security-gmac-payload-test
           #:run-security-payload-fuzz-test
           #:run-security-encrypted-pubsub-test
           #:run-security-encrypted-fragmented-test
           #:run-security-crypto-header-corpus-test
           #:run-security-submessage-corpus-test
           #:run-security-origin-auth-test
           #:run-security-rtps-message-corpus-test
           #:run-security-secured-region-into-test
           #:run-security-crypto-manager-test
           #:run-rtps-message-bench
           #:run-rtps-protection-bench
           #:run-auth-identity-test
           #:run-auth-sha256-kat
           #:run-auth-ecdsa-kat
           #:run-auth-handshake-ecdh-test
           #:run-auth-rsa-pss-kat
           #:run-auth-ffdh-kat
           #:run-auth-suite-selection-test
           #:run-auth-handshake-rsa-test
           #:run-auth-negatives-test
           #:run-auth-challenge-binding-test
           #:run-auth-forged-request-hardening-test
           #:run-auth-token-corpus-test
           #:run-auth-token-fuzz-test
           #:run-auth-spdp-identity-token-test
           #:run-auth-wire-codec-test
           #:run-auth-wire-fuzz-test
           #:run-auth-handshake-over-wire-test
           #:run-cms-verify-kat
           #:run-access-plugin-validate-test
           #:run-access-manager-test
           #:run-governance-protection-kind-test
           #:run-secure-interop-peer))
