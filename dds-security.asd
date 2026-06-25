;;;; DDS-Security cryptographic plugin — Slice 1: serialized-payload protection (§9.5.3.3)
;;;; + Slice 2a Auth wire constants: §8.7/§9.3 PKI-DH HandshakeMessageToken property names and
;;;; algorithm identifier strings.
(defsystem "dds-security"
  :description "DDS.SECURITY — DDS-Security 1.1 plugin (Slice 1 SecuredPayload + Slice 2a Auth wire constants): AES256-GCM SecuredPayload wire + HMAC-SHA256 session-key KDF + §8.7/§9.3 PKI-DH constants over DDS.DARE/OpenSSL."
  :depends-on ("dds-lang" "dds-pal" "dds-core" "dds-dare" "cffi")
  :pathname "src/dds-security"
  :serial t
  :components ((:file "packages")
               (:file "crypto")
               (:file "key-material")
               (:file "transform")
               (:module "auth"
                :serial t
                :components ((:file "constants")
                             (:file "identity")
                             (:file "suites")
                             (:file "handshake")
                             (:file "wire"))))
  :in-order-to ((test-op (test-op "dds-tests"))))
