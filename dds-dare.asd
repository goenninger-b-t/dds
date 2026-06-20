;;;; CNSA-2.0 Data-At-Rest Encryption layer (pure crypto; no DDS wire deps).
(defsystem "dds-dare"
  :description "DDS.DARE — CNSA-2.0 Data-At-Rest Encryption (AES-256-GCM + ML-KEM-1024 + SHA-384) over OpenSSL >= 3.5."
  :depends-on ("dds-lang" "dds-pal" "dds-core" "cffi")
  :pathname "src/dds-dare"
  :serial t
  :components ((:file "packages") (:file "openssl-ffi") (:file "primitives") (:file "envelope") (:file "key-provider"))
  :in-order-to ((test-op (test-op "dds-tests"))))
