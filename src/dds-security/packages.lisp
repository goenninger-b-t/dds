(defpackage #:net.goenninger.dds.security
  (:nicknames #:dds.security)
  (:use #:common-lisp #:net.goenninger.dds.lang)
  (:documentation
   "DDS.SECURITY — DDS-Security 1.1 Cryptographic plugin, Slice 1 (serialized-payload protection,
    §9.5.3.3). Provides the AES256-GCM SecuredPayload wire (de)serializer
    (serialize-secured-payload / parse-secured-payload), the §9.5.3.3.4.2 HMAC-SHA256 session-key
    KDF (derive-session-key), and the pinned transformation_kind constant. Crypto primitives are
    reused from DDS.DARE (OpenSSL >= 3.5); no hand-rolled crypto, no copied wire constants
    (every field cited from the §9.5.3.3 spec clause + the T0 spike doc).")
  (:export
   #:+transformation-kind-aes256-gcm+
   #:secured-payload-malformed
   #:secured-payload-malformed-reason
   #:serialize-secured-payload
   #:parse-secured-payload
   #:derive-session-key
   ;; KeyMaterial struct + constructor (§9.5.2 Table 65)
   #:key-material
   #:make-key-material
   #:key-material-transformation-kind
   #:key-material-master-salt
   #:key-material-sender-key-id
   #:key-material-master-sender-key
   #:key-material-iv-counter
   #:key-material-iv-counter-lock
   #:make-test-key-material
   ;; Transform ops (§9.5.3.3.4.4/4.5)
   #:encode-serialized-payload
   #:decode-serialized-payload))
