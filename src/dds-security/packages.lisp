(defpackage #:net.goenninger.dds.security
  (:nicknames #:dds.security)
  (:use #:common-lisp #:net.goenninger.dds.lang)
  (:documentation
   "DDS.SECURITY — DDS-Security 1.1 Cryptographic plugin, Slice 1 (serialized-payload protection,
    §9.5.3.3) + Slice 2a Auth (§8.7 Authentication plugin T1: PKI identity load/validate +
    IdentityToken). Crypto primitives reused from DDS.DARE (OpenSSL >= 3.5); no hand-rolled
    crypto, no copied wire constants (every field cited from the §-clause + spike docs).")
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
   #:decode-serialized-payload
   ;; Auth T1: PKI identity (§8.7 / §9.3) — DDS-Security 1.1 Authentication plugin
   #:+test-pki-root+
   #:identity-handle
   #:identity-handle-p
   #:identity-handle-cert
   #:identity-handle-pkey
   #:identity-handle-ca-store
   #:identity-handle-token-octets
   #:identity-handle-guid
   #:validate-local-identity
   #:identity-token
   #:validate-remote-identity
   #:free-identity-handle
   ;; Auth T2: handshake state machine + ECDH-P256 suite (WP-DDS-SECURITY-AUTH-2A T2)
   #:auth-suite
   #:auth-suite-p
   #:auth-suite-kagree-algo-str
   #:auth-suite-dsign-algo-str
   #:+suite-ecdh+
   ;; Auth T3: FFDH-2048 + RSA-PSS suite + §9.3.2 selection (WP-DDS-SECURITY-AUTH-2A T3)
   #:+suite-ffdh+
   #:select-auth-suite
   #:handshake-token
   #:handshake-token-p
   #:handshake-handle
   #:handshake-handle-p
   #:handshake-handle-state
   #:handshake-handle-shared-secret
   #:shared-secret-handle
   #:shared-secret-handle-p
   #:begin-handshake-request
   #:begin-handshake-reply
   #:process-handshake
   #:handshake-shared-secret
   #:shared-secret-bytes
   #:free-shared-secret-handle
   #:free-handshake-handle))
