;;;; DDS-Security cryptographic plugin — Slice 1: serialized-payload protection (DDS-Security 1.1 §9.5.3.3).
(defsystem "dds-security"
  :description "DDS.SECURITY — DDS-Security 1.1 Cryptographic plugin (Slice 1): AES256-GCM SecuredPayload wire + HMAC-SHA256 session-key KDF over DDS.DARE/OpenSSL."
  :depends-on ("dds-lang" "dds-pal" "dds-core" "dds-dare" "cffi")
  :pathname "src/dds-security"
  :serial t
  :components ((:file "packages") (:file "crypto") (:file "key-material") (:file "transform"))
  :in-order-to ((test-op (test-op "dds-tests"))))
