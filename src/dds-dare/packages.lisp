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
   #:hkdf-sha384
   #:aes-256-gcm-seal
   #:aes-256-gcm-open
   #:ml-kem-1024-keygen
   #:ml-kem-1024-encapsulate
   #:ml-kem-1024-decapsulate
   ;; Task 4: KEM-DEM envelope
   #:derive-dek
   #:seal-payload
   #:open-payload
   #:make-record-aad
   ;; Task 5: pluggable key-provider vtable + file-based provider
   #:key-provider
   #:key-provider-recipient-public-key
   #:key-provider-decapsulate
   #:key-provider-open
   #:key-provider-close
   #:make-file-key-provider
   ;; Task 6b: foreign-backed secret-material lifetime (design spec §6)
   #:free-secret-octets
   ;; internal helper exported for tests
   #:%ascii))
