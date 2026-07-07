(defpackage #:net.goenninger.dds.dare
  (:nicknames #:dds.dare)
  (:use #:common-lisp #:net.goenninger.dds.lang)
  (:documentation
   "DDS.DARE — CNSA-2.0 Data-At-Rest Encryption over OpenSSL >= 3.5 libcrypto.
    Provides: dare-available-p, sha-384, hkdf-sha384 (Task 1);
    AES-256-GCM encrypt/decrypt (Task 2); ML-KEM-1024 wrap/unwrap (Task 3);
    KEM-DEM envelope seal-payload/open-payload + make-record-aad (Task 4);
    pluggable key-provider vtable + file-based ML-KEM-1024 provider (Task 5).")
  (:export
   #:dare-available-p
   #:dare-unavailable
   #:dare-unavailable-reason
   #:sha-384
   #:hmac-sha256
   #:hkdf-sha384
   #:aes-256-gcm-seal
   #:aes-256-gcm-open
   #:aes-256-gcm-seal-into
   #:aes-256-gcm-open-into
   #:ml-kem-1024-keygen
   #:ml-kem-1024-encapsulate
   #:ml-kem-1024-decapsulate
   ;; Task 4: KEM-DEM envelope (v1)
   #:derive-dek
   ;; WP-DURABILITY-MAC-LOG-CHAIN (ADR 0045): cross-restart-stable log-MAC key derivation
   #:derive-log-mac-key
   ;; WP-DURABILITY-METADATA-CONF-3c (ADR 0025 §10 item 3): cross-restart-stable at-rest metadata key
   #:derive-meta-key
   ;; WP-DURABILITY-EPOCHS-MAC (ADR 0045 §7.2): cross-restart-stable epochs.dat MAC key (3rd anchor sibling)
   #:derive-epochs-mac-key
   #:seal-payload
   #:open-payload
   #:make-record-aad
   ;; Task 2 (WP-DURABILITY-PERSISTENT): envelope v2 — epoch-aware, ADR 0025 §5
   #:seal-payload-v2
   #:open-payload-v2
   #:+envelope-version-v2+
   #:+envelope-epoch-len+
   #:+envelope-v2-header-len+
   ;; Task 5: pluggable key-provider vtable + file-based provider
   #:key-provider
   #:key-provider-recipient-public-key
   #:key-provider-decapsulate
   #:key-provider-open
   #:key-provider-close
   #:make-file-key-provider
   ;; WP-DURABILITY-HARDENING-BATCH (ADR 0026 §10.12): 0700 dir enforce/verify, shared K + store dir D
   #:enforce-directory-perms-0700
   #:assert-directory-perms-0700
   ;; Task 6b: foreign-backed secret-material lifetime (design spec §6)
   #:free-secret-octets
   #:octets->secret
   ;; X.509 / EVP_PKEY primitives (WP-DDS-SECURITY-AUTH-2A T1)
   #:x509-load-cert
   #:x509-free
   #:x509-load-ca
   #:x509-ca-free
   #:x509-verify-chain
   #:x509-public-key
   #:x509-subject-name
   #:x509-subject-name-sha256
   #:pkey-load-private
   #:pkey-free
   #:pkey-kind
   ;; internal helper exported for tests
   #:%ascii
   ;; WP-DDS-SECURITY-AUTH-2A T2: ECDH/ECDSA/SHA-256/DER-export
   #:sha-256
   #:ecdh-gen-keypair
   #:ecdh-compute
   #:ecdsa-sign
   #:ecdsa-verify
   #:x509-to-der
   #:x509-to-pem
   #:x509-load-cert-der
   #:x509-load-cert-auto
   #:random-bytes
   ;; T2-fix: raw P-256 key import for KATs (EVP_PKEY_fromdata, OpenSSL 3.6.2)
   #:ec-p256-import-private
   #:ec-p256-import-public
   ;; T3: FFDH MODP-2048 + RSA-PSS-SHA256 (DDS-Security 1.1 §9.3 DH+MODP-2048-256 suite)
   #:ffdh-gen-keypair
   #:ffdh-compute
   #:rsa-pss-sign
   #:rsa-pss-verify
   ;; T1 (WP-DDS-SECURITY-ACCESS-CONTROL): CMS S/MIME verification (§9.4.1.1 Permissions CA)
   #:cms-verify))
